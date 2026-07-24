import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const TS = Date.now();

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
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

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  const qs = params ? "?" + new URLSearchParams(params).toString() : "";
  return page.request.get(`${API}${path}${qs}`);
}

async function apiDelete(page: Page, identity: string, path: string) {
  const s = getSessions()[identity];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await injectAuth(page, identity);
  return page;
}

const ALICE_ID = "alice";

// ---------------------------------------------------------------------------
// Section 79: Bulk Catalog Operations
// ---------------------------------------------------------------------------
test.describe("79 · Bulk Operations — Catalog bulk-delete and bulk-update", () => {
  let alicePage: Page;
  let categoryId: string;
  const testItemIds: string[] = [];

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);

    // Create a category for bulk test items
    categoryId = `bulkcat_${TS}`;
    const catResp = await apiPost(alicePage, ALICE_ID, "/ui/catalog/categories", {
      category_id: categoryId,
      name: `Bulk Test Category ${TS}`,
      description: "Category for bulk operation tests",
    });
    expect(catResp.status()).toBe(200);

    // Create 3 catalog items in the category
    for (let i = 0; i < 3; i++) {
      const resp = await apiPost(
        alicePage, ALICE_ID,
        `/ui/catalog/categories/${categoryId}/items`,
        {
          name: `bulk_item_${TS}_${i}`,
          description: `Bulk test item ${i}`,
          price_cents: 100 * (i + 1),
          currency: "USD",
        },
      );
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      testItemIds.push(body.item_id);
    }
  });

  test.afterAll(async () => {
    await alicePage?.context().close();
  });

  test("79.1 POST bulk-delete catalog items removes them", async () => {
    const idsToDelete = [testItemIds[0]];
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/catalog/items/bulk-delete", {
      item_ids: idsToDelete,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.succeeded).toBe(1);
    expect(body.failed).toBe(0);
    expect(body.results).toHaveLength(1);
    expect(body.results[0].ok).toBe(true);
  });

  test("79.2 POST bulk-delete with empty array returns 422", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/catalog/items/bulk-delete", {
      item_ids: [],
    });
    expect(resp.status()).toBe(422);
  });

  test("79.3 POST bulk-update changes field on multiple items", async () => {
    const idsToUpdate = testItemIds.slice(1); // items 1 and 2
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/catalog/items/bulk-update", {
      item_ids: idsToUpdate,
      updates: { description: `Updated bulk ${TS}` },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.succeeded).toBe(2);
    expect(body.failed).toBe(0);
  });

  test("79.4 POST bulk-update with invalid fields returns 422", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/catalog/items/bulk-update", {
      item_ids: [testItemIds[1]],
      updates: { price_cents: 999 }, // price_cents is not in allowed_fields
    });
    expect(resp.status()).toBe(422);
  });

  test("79.5 POST bulk-delete with non-existent ID reports not_found", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/catalog/items/bulk-delete", {
      item_ids: ["nonexistent_item_id_xyz"],
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.succeeded).toBe(0);
    expect(body.failed).toBe(1);
    expect(body.results[0].error).toBe("not_found");
  });
});

// ---------------------------------------------------------------------------
// Section 80: Bulk Post Operations
// ---------------------------------------------------------------------------
test.describe("80 · Bulk Operations — Post bulk-delete and bulk-archive", () => {
  let alicePage: Page;
  const testPostIds: string[] = [];

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);

    // Create 3 posts for bulk operation testing
    for (let i = 0; i < 3; i++) {
      const resp = await apiPost(alicePage, ALICE_ID, "/posts", {
        body: `Bulk test post ${TS}_${i}`,
      });
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      testPostIds.push(body.post_id);
    }
  });

  test.afterAll(async () => {
    await alicePage?.context().close();
  });

  test("80.1 POST bulk-delete posts removes them", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/posts/bulk-delete", {
      post_ids: [testPostIds[0]],
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.succeeded).toBe(1);
    expect(body.failed).toBe(0);
    expect(body.results[0].ok).toBe(true);
  });

  test("80.2 POST bulk-archive posts sets archived status", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/posts/bulk-archive", {
      post_ids: [testPostIds[1]],
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.succeeded).toBe(1);
    expect(body.failed).toBe(0);
    expect(body.results[0].ok).toBe(true);
  });

  test("80.3 POST bulk-delete with empty array returns 422", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/posts/bulk-delete", {
      post_ids: [],
    });
    expect(resp.status()).toBe(422);
  });

  test("80.4 POST bulk-archive with empty array returns 422", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/posts/bulk-archive", {
      post_ids: [],
    });
    expect(resp.status()).toBe(422);
  });

  test("80.5 POST bulk-delete with non-existent ID reports not_found", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/posts/bulk-delete", {
      post_ids: ["post_nonexistent_xyz"],
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.succeeded).toBe(0);
    expect(body.failed).toBe(1);
    expect(body.results[0].error).toBe("not_found");
  });
});
