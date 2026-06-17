/**
 * E2E tests for LCOM-002: Chat Product Links
 *
 * Section 110: Chat Product Link API (6 tests)
 * Section 111: Chat History with Product Links (3 tests)
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const API = "http://localhost:8000";
const TS = Date.now();

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string;
    value: string;
    domain: string;
    path: string;
    httpOnly: boolean;
    secure: boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

// ── Section 110: Chat Product Link API ────────────────────────────────────

test.describe("Section 110 - Chat Product Link API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let liveSessionId: string;
  let draftSessionId: string;
  let profileId: string;
  let catalogCategoryId: string;
  let catalogItemId: string;
  let catalogItemId2: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, "root");

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    // Create broadcast profile
    const profResp = await apiPost(rootPage, "root", "/broadcast/profiles", {
      name: `chat-link-profile-${TS}`,
      region: "us-east-1",
      rendition_preset: "720p",
    });
    expect(profResp.status()).toBe(201);
    profileId = (await profResp.json()).id;

    // Create live session
    const sessResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(sessResp.status()).toBe(201);
    liveSessionId = (await sessResp.json()).id;

    const startResp = await apiPost(rootPage, "root", `/broadcast/sessions/${liveSessionId}/start`, {
      reason: "e2e-chat-link-test",
    });
    expect(startResp.status()).toBe(202);

    // Create draft session
    const draftResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(draftResp.status()).toBe(201);
    draftSessionId = (await draftResp.json()).id;

    // Create catalog category + items
    const catResp = await apiPost(rootPage, "root", "/ui/catalog/categories", {
      name: `chat-link-cat-${TS}`,
    });
    expect(catResp.status()).toBe(200);
    catalogCategoryId = (await catResp.json()).category_id;

    const item1Resp = await apiPost(rootPage, "root", `/ui/catalog/categories/${catalogCategoryId}/items`, {
      name: `Chat Link Widget ${TS}`,
      price_cents: 1999,
      currency: "USD",
      description: "Widget for chat link testing",
    });
    expect(item1Resp.status()).toBe(200);
    catalogItemId = (await item1Resp.json()).item_id;

    const item2Resp = await apiPost(rootPage, "root", `/ui/catalog/categories/${catalogCategoryId}/items`, {
      name: `Chat Link Gadget ${TS}`,
      price_cents: 3499,
      currency: "USD",
      description: "Gadget for chat link testing",
    });
    expect(item2Resp.status()).toBe(200);
    catalogItemId2 = (await item2Resp.json()).item_id;

    // Add item1 to shelf
    const shelfResp = await apiPost(rootPage, "root", `/broadcast/sessions/${liveSessionId}/products`, {
      item_id: catalogItemId,
      category_id: catalogCategoryId,
      display_order: 0,
    });
    expect(shelfResp.status()).toBe(201);
  });

  test("110.1 Broadcaster can share product link in chat", async () => {
    const resp = await apiPost(rootPage, "root", `/broadcast/sessions/${liveSessionId}/chat/product`, {
      item_id: catalogItemId,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.kind).toBe("product_link");
    expect(data.product_link).toBeTruthy();
    expect(data.product_link.item_id).toBe(catalogItemId);
    expect(data.product_link.name).toContain("Chat Link Widget");
    expect(data.product_link.price_cents).toBe(1999);
    expect(data.message_id).toMatch(/^cm_/);
  });

  test("110.2 Viewer cannot share product link", async () => {
    const resp = await apiPost(alicePage, "alice", `/broadcast/sessions/${liveSessionId}/chat/product`, {
      item_id: catalogItemId,
    });
    expect(resp.status()).toBe(403);
  });

  test("110.3 Cannot share product not on shelf", async () => {
    const resp = await apiPost(rootPage, "root", `/broadcast/sessions/${liveSessionId}/chat/product`, {
      item_id: catalogItemId2,
    });
    expect(resp.status()).toBe(404);
  });

  test("110.4 Cannot share product in non-live session", async () => {
    const resp = await apiPost(rootPage, "root", `/broadcast/sessions/${draftSessionId}/chat/product`, {
      item_id: catalogItemId,
    });
    expect(resp.status()).toBe(403);
  });

  test("110.5 Rate limit on product link sharing", async () => {
    // First share should succeed (or be after the cooldown from 110.1)
    await new Promise((r) => setTimeout(r, 5500));
    const resp1 = await apiPost(rootPage, "root", `/broadcast/sessions/${liveSessionId}/chat/product`, {
      item_id: catalogItemId,
    });
    expect(resp1.status()).toBe(201);

    // Immediate second share should be rate limited
    const resp2 = await apiPost(rootPage, "root", `/broadcast/sessions/${liveSessionId}/chat/product`, {
      item_id: catalogItemId,
    });
    expect(resp2.status()).toBe(429);
  });

  test("110.6 Product link appears in chat history", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${liveSessionId}/chat`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const productMsgs = data.messages.filter((m: any) => m.kind === "product_link");
    expect(productMsgs.length).toBeGreaterThanOrEqual(1);
    const msg = productMsgs[productMsgs.length - 1];
    expect(msg.product_link).toBeTruthy();
    expect(msg.product_link.item_id).toBe(catalogItemId);
  });

  // ── 111: Mixed Chat History (within same describe to reuse state) ────

  test("111.1 Text messages have kind=text", async () => {
    const resp = await apiPost(rootPage, "root", `/broadcast/sessions/${liveSessionId}/chat`, {
      text: `Plain text ${TS}`,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.kind).toBe("text");
    expect(data.product_link).toBeNull();
  });

  test("111.2 History contains both text and product_link messages", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${liveSessionId}/chat`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const kinds = new Set(data.messages.map((m: any) => m.kind));
    expect(kinds.has("text")).toBe(true);
    expect(kinds.has("product_link")).toBe(true);
  });

  test("111.3 Product link message has denormalized product data", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${liveSessionId}/chat`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const productMsg = data.messages.find((m: any) => m.kind === "product_link");
    expect(productMsg).toBeTruthy();
    expect(productMsg.product_link.name).toBeTruthy();
    expect(typeof productMsg.product_link.price_cents).toBe("number");
    expect(productMsg.product_link.currency).toBe("USD");
    expect(productMsg.product_link.category_id).toBe(catalogCategoryId);
  });
});
