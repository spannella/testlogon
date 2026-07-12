import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

/* ------------------------------------------------------------------ */
/*  GAP-0289 + GAP-0290 — Live-commerce product link in broadcast chat */
/*                                                                     */
/*  GAP-0289: ProductLinkCard renders kind="product_link" messages.    */
/*  GAP-0290: ShelfProductPicker lets the broadcaster share a shelf    */
/*            product into chat via the "Share Product" button.        */
/* ------------------------------------------------------------------ */

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

/** Full auth injection for UI tests (cookies + localStorage auth store). */
async function injectAuthForUI(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

/* ------------------------------------------------------------------ */
/*  Shared setup — live session with one shelf product                 */
/* ------------------------------------------------------------------ */

let liveSessionId: string;
let emptySessionId: string;
let shelfItemId: string;

async function setupSessions(browser: import("@playwright/test").Browser) {
  const setupCtx = await browser.newContext();
  const setupPage = await setupCtx.newPage();
  await injectAuth(setupPage, "root");

  const profResp = await apiPost(setupPage, "root", "/broadcast/profiles", {
    name: `prodlink-profile-${TS}`,
    region: "us-east-1",
    rendition_preset: "720p",
  });
  const profileId = (await profResp.json()).id;

  // Live session with a product on the shelf
  const sessResp = await apiPost(setupPage, "root", "/broadcast/sessions", {
    profile_id: profileId,
  });
  liveSessionId = (await sessResp.json()).id;
  await apiPost(setupPage, "root", `/broadcast/sessions/${liveSessionId}/start`, {
    reason: "e2e-product-link",
  });

  const catResp = await apiPost(setupPage, "root", "/ui/catalog/categories", {
    name: `prodlink-cat-${TS}`,
  });
  const categoryId = (await catResp.json()).category_id;

  const itemResp = await apiPost(
    setupPage,
    "root",
    `/ui/catalog/categories/${categoryId}/items`,
    {
      name: `Shareable Widget ${TS}`,
      price_cents: 3499,
      currency: "USD",
      description: "A widget to share in chat",
    },
  );
  shelfItemId = (await itemResp.json()).item_id;

  await apiPost(setupPage, "root", `/broadcast/sessions/${liveSessionId}/products`, {
    item_id: shelfItemId,
    category_id: categoryId,
    display_order: 0,
  });

  // A second live session with an EMPTY shelf
  const emptyResp = await apiPost(setupPage, "root", "/broadcast/sessions", {
    profile_id: profileId,
  });
  emptySessionId = (await emptyResp.json()).id;
  await apiPost(setupPage, "root", `/broadcast/sessions/${emptySessionId}/start`, {
    reason: "e2e-product-link-empty",
  });

  await setupCtx.close();
}

/* ------------------------------------------------------------------ */
/*  Section 110 - ProductLinkCard rendering (GAP-0289)                  */
/* ------------------------------------------------------------------ */

test.describe("Section 110 - ProductLinkCard (GAP-0289)", () => {
  let viewerPage: Page;

  test.beforeAll(async ({ browser }) => {
    await setupSessions(browser);

    const ctx = await browser.newContext();
    viewerPage = await ctx.newPage();
    await injectAuthForUI(viewerPage, "alice");
  });

  test.afterAll(async () => {
    await viewerPage.context().close();
  });

  test("110.1 product link message renders ProductLinkCard for viewer", async ({ browser }) => {
    await viewerPage.goto(`http://localhost:3000/live/${liveSessionId}`);
    await expect(viewerPage.locator('[data-testid="broadcast-chat"]')).toBeVisible({
      timeout: 10_000,
    });

    // Broadcaster shares the product via the backend endpoint.
    const broadCtx = await browser.newContext();
    const broadPage = await broadCtx.newPage();
    await injectAuth(broadPage, "root");
    const shareResp = await apiPost(
      broadPage,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat/product`,
      { item_id: shelfItemId },
    );
    expect(shareResp.status()).toBe(201);
    const shared = await shareResp.json();
    expect(shared.kind).toBe("product_link");
    await broadCtx.close();

    // Card appears (SSE listener wired in GAP-0289).
    await expect(viewerPage.getByTestId("product-link-card")).toBeVisible({
      timeout: 8_000,
    });
    await expect(viewerPage.getByTestId("product-link-name")).toContainText(
      "Shareable Widget",
    );
    await expect(viewerPage.getByTestId("product-link-price")).toContainText("34.99");
    await expect(viewerPage.getByTestId("product-link-buy-btn")).toBeVisible();
  });

  test("110.2 product link card persists across reload (history fetch)", async () => {
    await viewerPage.reload();
    await expect(viewerPage.getByTestId("product-link-card").first()).toBeVisible({
      timeout: 10_000,
    });
  });
});

/* ------------------------------------------------------------------ */
/*  Section 111 - ShelfProductPicker dialog (GAP-0290)                  */
/* ------------------------------------------------------------------ */

test.describe("Section 111 - ShelfProductPicker (GAP-0290)", () => {
  let broadPage: Page;

  test.beforeAll(async ({ browser }) => {
    // On a retry, Playwright may spawn a fresh worker where Section 110's
    // beforeAll (which calls setupSessions) never ran, leaving the module-level
    // liveSessionId/shelfItemId undefined. Re-run setup when that happens.
    if (!liveSessionId || !shelfItemId) {
      await setupSessions(browser);
    }

    const ctx = await browser.newContext();
    broadPage = await ctx.newPage();
    await injectAuthForUI(broadPage, "root");
  });

  test.afterAll(async () => {
    await broadPage.context().close();
  });

  test("111.1 broadcaster sees Share Product button in toolbar", async () => {
    await broadPage.goto(`http://localhost:3000/live/${liveSessionId}`);
    await expect(broadPage.locator('[data-testid="broadcaster-toggles"]')).toBeVisible({
      timeout: 10_000,
    });
    await expect(broadPage.getByTestId("toggle-product-share")).toBeVisible();
  });

  test("111.2 clicking Share Product opens the picker with the shelf product", async () => {
    await broadPage.getByTestId("toggle-product-share").click();
    await expect(broadPage.getByTestId("shelf-product-picker")).toBeVisible();
    await expect(broadPage.getByTestId("shelf-product-list")).toBeVisible();
    await expect(broadPage.getByTestId(`shelf-product-${shelfItemId}`)).toBeVisible();
  });

  test("111.3 selecting a product and sharing posts the link and closes the dialog", async () => {
    await broadPage.getByTestId(`shelf-product-${shelfItemId}`).click();
    const shareBtn = broadPage.getByTestId("shelf-share-btn");
    await expect(shareBtn).toBeEnabled();

    // The backend rate-limits product-link shares to 1 per 5s per session+user
    // (BROADCAST_PRODUCT_LINK_RATE_LIMITED). Section 110 shares the same product
    // into the same session, so wait out the window before the UI share to avoid
    // a 429 that would leave the share mutation rejected and the dialog open.
    await broadPage.waitForTimeout(5_500);
    await shareBtn.click();

    // Dialog closes after a successful share.
    await expect(broadPage.getByTestId("shelf-product-picker")).not.toBeVisible({
      timeout: 5_000,
    });

    // Product card appears in the broadcaster's own chat (requires GAP-0289).
    await expect(broadPage.getByTestId("product-link-card").first()).toBeVisible({
      timeout: 8_000,
    });
  });

  test("111.4 empty shelf shows the informational message", async () => {
    await broadPage.goto(`http://localhost:3000/live/${emptySessionId}`);
    await expect(broadPage.getByTestId("toggle-product-share")).toBeVisible({
      timeout: 10_000,
    });
    await broadPage.getByTestId("toggle-product-share").click();
    await expect(broadPage.getByTestId("shelf-empty")).toBeVisible();
  });

  test("111.5 viewers do not see the Share Product button", async ({ browser }) => {
    const ctx = await browser.newContext();
    const viewer = await ctx.newPage();
    await injectAuthForUI(viewer, "alice");
    await viewer.goto(`http://localhost:3000/live/${liveSessionId}`);
    await expect(viewer.locator('[data-testid="broadcast-chat"]')).toBeVisible({
      timeout: 10_000,
    });
    await expect(viewer.getByTestId("toggle-product-share")).toHaveCount(0);
    await ctx.close();
  });
});
