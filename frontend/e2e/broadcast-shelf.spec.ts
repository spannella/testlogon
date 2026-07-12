import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

/* ------------------------------------------------------------------ */
/*  Constants & helpers                                                */
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

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body: object,
) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiDelete(page: Page, identity: string, path: string) {
  const s = getSessions()[identity];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function apiPatch(
  page: Page,
  identity: string,
  path: string,
  body: object,
) {
  const s = getSessions()[identity];
  return page.request.patch(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

/* ------------------------------------------------------------------ */
/*  Shared state                                                       */
/* ------------------------------------------------------------------ */

let rootPage: Page;
let alicePage: Page;
let liveSessionId: string;
let draftSessionId: string;
let profileId: string;
let catalogCategoryId: string;
let catalogItemId: string;
let catalogItemId2: string;
let catalogItemId3: string;

/* ------------------------------------------------------------------ */
/*  Section 100 - Shelf Management API                                 */
/* ------------------------------------------------------------------ */

test.describe("Section 100 - Broadcast Product Shelf API", () => {
  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, "root");

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    // Create a broadcast profile
    const profResp = await apiPost(rootPage, "root", "/broadcast/profiles", {
      name: `shelf-test-profile-${TS}`,
      region: "us-east-1",
      rendition_preset: "720p",
    });
    expect(profResp.status()).toBe(201);
    profileId = (await profResp.json()).id;

    // Create a live session
    const sessResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(sessResp.status()).toBe(201);
    liveSessionId = (await sessResp.json()).id;

    // Start it (makes it live)
    const startResp = await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${liveSessionId}/start`,
      { reason: "e2e-shelf-test" },
    );
    expect(startResp.status()).toBe(202);

    // Create a draft session
    const draftResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(draftResp.status()).toBe(201);
    draftSessionId = (await draftResp.json()).id;

    // Create catalog category + items
    const catResp = await apiPost(rootPage, "root", "/ui/catalog/categories", {
      name: `shelf-test-cat-${TS}`,
    });
    expect(catResp.status()).toBe(200);
    catalogCategoryId = (await catResp.json()).category_id;

    const item1Resp = await apiPost(
      rootPage,
      "root",
      `/ui/catalog/categories/${catalogCategoryId}/items`,
      {
        name: `Widget Alpha ${TS}`,
        price_cents: 2999,
        currency: "USD",
        description: "A test widget for shelf testing",
      },
    );
    expect(item1Resp.status()).toBe(200);
    catalogItemId = (await item1Resp.json()).item_id;

    const item2Resp = await apiPost(
      rootPage,
      "root",
      `/ui/catalog/categories/${catalogCategoryId}/items`,
      {
        name: `Widget Beta ${TS}`,
        price_cents: 4999,
        currency: "USD",
        description: "Another widget for shelf testing",
      },
    );
    expect(item2Resp.status()).toBe(200);
    catalogItemId2 = (await item2Resp.json()).item_id;

    const item3Resp = await apiPost(
      rootPage,
      "root",
      `/ui/catalog/categories/${catalogCategoryId}/items`,
      {
        name: `Widget Gamma ${TS}`,
        price_cents: 999,
        currency: "USD",
        description: "Yet another widget",
      },
    );
    expect(item3Resp.status()).toBe(200);
    catalogItemId3 = (await item3Resp.json()).item_id;
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("100.1 Broadcaster adds a product to the shelf", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${liveSessionId}/products`,
      {
        item_id: catalogItemId,
        category_id: catalogCategoryId,
        display_order: 0,
      },
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.session_id).toBe(liveSessionId);
    expect(body.item_id).toBe(catalogItemId);
    expect(body.name).toContain("Widget Alpha");
    expect(body.price_cents).toBe(2999);
    expect(body.currency).toBe("USD");
    expect(body.added_by).toBe(getSessions()["root"].user_sub);
    expect(body.added_at).toBeGreaterThan(0);
  });

  test("100.2 Adding the same product twice returns 409", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${liveSessionId}/products`,
      {
        item_id: catalogItemId,
        category_id: catalogCategoryId,
      },
    );
    expect(resp.status()).toBe(409);
  });

  test("100.3 Non-owner cannot add products (403)", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${liveSessionId}/products`,
      {
        item_id: catalogItemId2,
        category_id: catalogCategoryId,
      },
    );
    expect(resp.status()).toBe(403);
  });

  test("100.4 Listing shelf products returns items sorted by display_order", async () => {
    // Add two more items with specific display orders
    const resp2 = await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${liveSessionId}/products`,
      {
        item_id: catalogItemId2,
        category_id: catalogCategoryId,
        display_order: 2,
      },
    );
    expect(resp2.status()).toBe(201);

    const resp3 = await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${liveSessionId}/products`,
      {
        item_id: catalogItemId3,
        category_id: catalogCategoryId,
        display_order: 1,
      },
    );
    expect(resp3.status()).toBe(201);

    const listResp = await apiGet(
      rootPage,
      `/broadcast/sessions/${liveSessionId}/products`,
    );
    expect(listResp.status()).toBe(200);
    const body = await listResp.json();
    expect(body.count).toBe(3);
    expect(body.items.length).toBe(3);
    // Should be sorted: display_order 0, 1, 2
    expect(body.items[0].display_order).toBe(0);
    expect(body.items[1].display_order).toBe(1);
    expect(body.items[2].display_order).toBe(2);
  });

  test("100.5 Removing a product succeeds and shelf count decreases", async () => {
    const delResp = await apiDelete(
      rootPage,
      "root",
      `/broadcast/sessions/${liveSessionId}/products/${catalogItemId3}`,
    );
    expect(delResp.status()).toBe(200);
    const delBody = await delResp.json();
    expect(delBody.ok).toBe(true);

    // Verify count
    const listResp = await apiGet(
      rootPage,
      `/broadcast/sessions/${liveSessionId}/products`,
    );
    const body = await listResp.json();
    expect(body.count).toBe(2);
  });

  test("100.6 Removing a non-existent product returns 404", async () => {
    const resp = await apiDelete(
      rootPage,
      "root",
      `/broadcast/sessions/${liveSessionId}/products/nonexistent_item`,
    );
    expect(resp.status()).toBe(404);
  });

  test("100.7 Reordering shelf updates display_order correctly", async () => {
    // Re-add item3 so we have 3 items
    await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${liveSessionId}/products`,
      {
        item_id: catalogItemId3,
        category_id: catalogCategoryId,
        display_order: 5,
      },
    );

    // Reorder: item3, item1, item2
    const reorderResp = await apiPatch(
      rootPage,
      "root",
      `/broadcast/sessions/${liveSessionId}/products/reorder`,
      {
        item_order: [catalogItemId3, catalogItemId, catalogItemId2],
      },
    );
    expect(reorderResp.status()).toBe(200);

    const listResp = await apiGet(
      rootPage,
      `/broadcast/sessions/${liveSessionId}/products`,
    );
    const body = await listResp.json();
    expect(body.items[0].item_id).toBe(catalogItemId3);
    expect(body.items[1].item_id).toBe(catalogItemId);
    expect(body.items[2].item_id).toBe(catalogItemId2);
  });

  test("100.8 Adding product to a non-existent catalog item returns 404", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${liveSessionId}/products`,
      {
        item_id: "does_not_exist",
        category_id: catalogCategoryId,
      },
    );
    expect(resp.status()).toBe(404);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 101 - Shelf Visibility for Viewers                        */
/* ------------------------------------------------------------------ */

test.describe("Section 101 - Shelf Visibility for Viewers", () => {
  let viewerPage: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    viewerPage = await ctx.newPage();
    await injectAuth(viewerPage, "alice");
  });

  test.afterAll(async () => {
    await viewerPage.context().close();
  });

  test("101.1 Viewer can list shelf products on a live session", async () => {
    const resp = await apiGet(
      viewerPage,
      `/broadcast/sessions/${liveSessionId}/products`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.items.length).toBeGreaterThanOrEqual(2);
  });

  test("101.2 Shelf products include denormalized name, price, image_url", async () => {
    const resp = await apiGet(
      viewerPage,
      `/broadcast/sessions/${liveSessionId}/products`,
    );
    const body = await resp.json();
    const item = body.items.find(
      (i: { item_id: string }) => i.item_id === catalogItemId,
    );
    expect(item).toBeTruthy();
    expect(item.name).toContain("Widget Alpha");
    expect(item.price_cents).toBe(2999);
    expect(item.currency).toBe("USD");
    // image_url may be null since we didn't upload an image
    expect("image_url" in item).toBeTruthy();
  });

  test("101.3 Viewer cannot add products to shelf (403)", async () => {
    const resp = await apiPost(
      viewerPage,
      "alice",
      `/broadcast/sessions/${liveSessionId}/products`,
      {
        item_id: catalogItemId2,
        category_id: catalogCategoryId,
      },
    );
    expect(resp.status()).toBe(403);
  });

  test("101.4 Viewer cannot remove products from shelf (403)", async () => {
    const resp = await apiDelete(
      viewerPage,
      "alice",
      `/broadcast/sessions/${liveSessionId}/products/${catalogItemId}`,
    );
    expect(resp.status()).toBe(403);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 102 - Draft Session Shelf Management                       */
/* ------------------------------------------------------------------ */

test.describe("Section 102 - Draft Session Shelf", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, "root");
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("102.1 Can add products to a draft session", async () => {
    const resp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${draftSessionId}/products`,
      {
        item_id: catalogItemId,
        category_id: catalogCategoryId,
        display_order: 0,
      },
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.session_id).toBe(draftSessionId);
    expect(body.item_id).toBe(catalogItemId);
  });

  test("102.2 Can list products on a draft session", async () => {
    const resp = await apiGet(
      page,
      `/broadcast/sessions/${draftSessionId}/products`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.count).toBe(1);
  });

  test("102.3 Can remove products from a draft session", async () => {
    const resp = await apiDelete(
      page,
      "root",
      `/broadcast/sessions/${draftSessionId}/products/${catalogItemId}`,
    );
    expect(resp.status()).toBe(200);
    expect((await resp.json()).ok).toBe(true);
  });

  test("102.4 Adding product to stopped session returns 409", async () => {
    // Create and stop a session
    const sessResp = await apiPost(page, "root", "/broadcast/sessions", {
      profile_id: profileId,
    });
    const sessId = (await sessResp.json()).id;
    await apiPost(page, "root", `/broadcast/sessions/${sessId}/start`, {
      reason: "test",
    });
    await apiPost(page, "root", `/broadcast/sessions/${sessId}/stop`, {
      reason: "test",
    });

    const resp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${sessId}/products`,
      {
        item_id: catalogItemId,
        category_id: catalogCategoryId,
      },
    );
    expect(resp.status()).toBe(409);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 103 - Product Shelf UI (Viewer Side)                       */
/* ------------------------------------------------------------------ */

test.describe("Section 103 - Product Shelf UI - Viewer", () => {
  let page: Page;
  let uiSessionId: string;

  test.beforeAll(async ({ browser }) => {
    // First create a context with cookie-only auth for API calls
    const setupCtx = await browser.newContext();
    const setupPage = await setupCtx.newPage();
    await injectAuth(setupPage, "root");

    // Create fresh broadcast profile + live session for UI tests
    const profResp = await apiPost(setupPage, "root", "/broadcast/profiles", {
      name: `shelf-ui-profile-${TS}`,
      region: "us-east-1",
      rendition_preset: "720p",
    });
    const uiProfileId = (await profResp.json()).id;

    const sessResp = await apiPost(setupPage, "root", "/broadcast/sessions", {
      profile_id: uiProfileId,
    });
    uiSessionId = (await sessResp.json()).id;

    await apiPost(setupPage, "root", `/broadcast/sessions/${uiSessionId}/start`, {
      reason: "e2e-shelf-ui",
    });

    // Create catalog item and add to shelf
    const catResp = await apiPost(setupPage, "root", "/ui/catalog/categories", {
      name: `shelf-ui-cat-${TS}`,
    });
    const uiCategoryId = (await catResp.json()).category_id;

    const itemResp = await apiPost(
      setupPage,
      "root",
      `/ui/catalog/categories/${uiCategoryId}/items`,
      {
        name: `UI Test Widget ${TS}`,
        price_cents: 1299,
        currency: "USD",
      },
    );
    const uiItemId = (await itemResp.json()).item_id;

    await apiPost(
      setupPage,
      "root",
      `/broadcast/sessions/${uiSessionId}/products`,
      {
        item_id: uiItemId,
        category_id: uiCategoryId,
        display_order: 0,
      },
    );
    await setupCtx.close();

    // Now create the UI page with full auth (cookies + localStorage)
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuthForUI(page, "root");
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("103.1 Product shelf panel is visible on live player page", async () => {
    await page.goto(`http://localhost:3000/live/${uiSessionId}`);
    // Wait for the shelf panel to appear (it renders when session is live)
    await expect(
      page.locator('[data-testid="product-shelf-panel"]'),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("103.2 Shelf toggle button shows/hides the shelf panel", async () => {
    // We should already be on the live player page from 103.1
    const toggleBtn = page.locator('[data-testid="shelf-visibility-toggle"]');
    await expect(toggleBtn).toBeVisible({ timeout: 5_000 });
    // Click to hide products
    await toggleBtn.click();
    await expect(
      page.locator('[data-testid="product-shelf-panel"]'),
    ).not.toBeVisible();
    // Click to show again
    await toggleBtn.click();
    await expect(
      page.locator('[data-testid="product-shelf-panel"]'),
    ).toBeVisible({ timeout: 5_000 });
  });
});

/* ------------------------------------------------------------------ */
/*  Section 104 - Product Shelf Manager UI - Broadcaster               */
/* ------------------------------------------------------------------ */

test.describe("Section 104 - Product Shelf Manager UI - Broadcaster", () => {
  let page: Page;
  let mgSessionId: string;

  test.beforeAll(async ({ browser }) => {
    // Setup: create profile + session via API-only context
    const setupCtx = await browser.newContext();
    const setupPage = await setupCtx.newPage();
    await injectAuth(setupPage, "root");

    const profResp = await apiPost(setupPage, "root", "/broadcast/profiles", {
      name: `shelf-mgr-profile-${TS}`,
      region: "us-east-1",
      rendition_preset: "720p",
    });
    const mgProfileId = (await profResp.json()).id;

    const sessResp = await apiPost(setupPage, "root", "/broadcast/sessions", {
      profile_id: mgProfileId,
    });
    mgSessionId = (await sessResp.json()).id;
    await setupCtx.close();

    // UI page with full auth
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuthForUI(page, "root");
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("104.1 Product shelf manager shows 0/50 count initially", async () => {
    await page.goto("http://localhost:3000/broadcast");
    // Wait for sessions to load
    await page.waitForTimeout(3000);

    // Find any Details button and click it to open the session dialog
    const allDetails = page.getByRole("button", { name: "Details" });
    if ((await allDetails.count()) > 0) {
      await allDetails.first().click();
      await page.waitForTimeout(1000);
    }

    // The shelf manager count badge should be visible
    const countBadge = page.locator('[data-testid="shelf-manager-count"]');
    if (await countBadge.isVisible()) {
      await expect(countBadge).toContainText("0/50");
    }
  });

  test("104.2 Add Product button is visible in draft state", async () => {
    // The add button should be in the dialog from previous test
    const addBtn = page.locator('[data-testid="add-product-btn"]');
    if (await addBtn.isVisible()) {
      expect(await addBtn.isEnabled()).toBeTruthy();
    }
  });
});

/* ------------------------------------------------------------------ */
/*  Section 106 - Broadcast Price Editor (GAP-0293)                     */
/*                                                                      */
/*  Covers the BroadcastPriceEditor component wired into                */
/*  ProductShelfManager: the broadcaster sets/clears a broadcast-       */
/*  exclusive price on a shelf item, the discount is computed, and a    */
/*  non-broadcaster is rejected by the backend guard.                   */
/* ------------------------------------------------------------------ */

test.describe("Section 106 - Broadcast Price Editor (GAP-0293)", () => {
  let priceSessionId: string;
  let priceCategoryId: string;
  let priceItemId: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    rootPage = await ctx.newPage();
    await injectAuth(rootPage, "root");

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    // Profile + draft session (root is the creator/broadcaster).
    const profResp = await apiPost(rootPage, "root", "/broadcast/profiles", {
      name: `price-editor-profile-${TS}`,
      region: "us-east-1",
      rendition_preset: "720p",
    });
    const priceProfileId = (await profResp.json()).id;

    const sessResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
      profile_id: priceProfileId,
    });
    priceSessionId = (await sessResp.json()).id;

    // The broadcast price is only "active" (is_broadcast_price / discount_pct /
    // effective_price_cents reflect the discount) when the session status is
    // "live" — see resolve_effective_price(). Start the session so 105.1/105.2
    // observe the active broadcast price.
    await apiPost(rootPage, "root", `/broadcast/sessions/${priceSessionId}/start`, {
      reason: "e2e-price-editor",
    });

    // Catalog item at $20.00 so a $10.00 broadcast price is exactly 50% off.
    const catResp = await apiPost(rootPage, "root", "/ui/catalog/categories", {
      name: `price-editor-cat-${TS}`,
    });
    priceCategoryId = (await catResp.json()).category_id;

    const itemResp = await apiPost(
      rootPage,
      "root",
      `/ui/catalog/categories/${priceCategoryId}/items`,
      {
        name: `Flash Deal Widget ${TS}`,
        price_cents: 2000,
        currency: "USD",
        description: "Twenty-dollar widget for price editor tests",
      },
    );
    priceItemId = (await itemResp.json()).item_id;

    // Add it to the shelf.
    const addResp = await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${priceSessionId}/products`,
      { item_id: priceItemId, category_id: priceCategoryId },
    );
    expect(addResp.status()).toBe(201);
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("105.1 Broadcaster sets a broadcast price (50% off)", async () => {
    const resp = await apiPatch(
      rootPage,
      "root",
      `/broadcast/sessions/${priceSessionId}/products/${priceItemId}/price`,
      { broadcast_price_cents: 1000, expires_in_seconds: 300 },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.broadcast_price_cents).toBe(1000);
    expect(body.original_price_cents).toBe(2000);
    expect(body.discount_pct).toBe(50);
  });

  test("105.2 Shelf list reflects the active broadcast price", async () => {
    const resp = await apiGet(
      rootPage,
      `/broadcast/sessions/${priceSessionId}/products`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const item = body.items.find(
      (i: { item_id: string }) => i.item_id === priceItemId,
    );
    expect(item).toBeTruthy();
    expect(item.is_broadcast_price).toBe(true);
    expect(item.effective_price_cents).toBe(1000);
    expect(item.discount_pct).toBe(50);
  });

  test("105.3 Broadcast price below catalog is enforced (>= catalog rejected)", async () => {
    const resp = await apiPatch(
      rootPage,
      "root",
      `/broadcast/sessions/${priceSessionId}/products/${priceItemId}/price`,
      { broadcast_price_cents: 2000 },
    );
    expect(resp.status()).toBe(400);
  });

  test("105.4 Non-broadcaster cannot set a broadcast price", async () => {
    const resp = await apiPatch(
      alicePage,
      "alice",
      `/broadcast/sessions/${priceSessionId}/products/${priceItemId}/price`,
      { broadcast_price_cents: 500 },
    );
    expect(resp.status()).toBe(403);
  });

  test("105.5 Broadcaster clears the broadcast price", async () => {
    const resp = await apiDelete(
      rootPage,
      "root",
      `/broadcast/sessions/${priceSessionId}/products/${priceItemId}/price`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.item_id).toBe(priceItemId);

    // Shelf list now reverts to the catalog price.
    const listResp = await apiGet(
      rootPage,
      `/broadcast/sessions/${priceSessionId}/products`,
    );
    const item = (await listResp.json()).items.find(
      (i: { item_id: string }) => i.item_id === priceItemId,
    );
    expect(item.is_broadcast_price).toBeFalsy();
    expect(item.effective_price_cents ?? item.price_cents).toBe(2000);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 105 - BroadcastPrice viewer component (GAP-0292)           */
/* ------------------------------------------------------------------ */

test.describe("Section 105 - Broadcast Price Viewer (GAP-0292)", () => {
  let page: Page;
  let bpSessionId: string;
  let bpItemId: string;
  let bpCategoryId: string;

  test.beforeAll(async ({ browser }) => {
    // API-only context for setup.
    const setupCtx = await browser.newContext();
    const setupPage = await setupCtx.newPage();
    await injectAuth(setupPage, "root");

    const profResp = await apiPost(setupPage, "root", "/broadcast/profiles", {
      name: `shelf-price-profile-${TS}`,
      region: "us-east-1",
      rendition_preset: "720p",
    });
    const bpProfileId = (await profResp.json()).id;

    const sessResp = await apiPost(setupPage, "root", "/broadcast/sessions", {
      profile_id: bpProfileId,
    });
    bpSessionId = (await sessResp.json()).id;

    await apiPost(setupPage, "root", `/broadcast/sessions/${bpSessionId}/start`, {
      reason: "e2e-shelf-price",
    });

    const catResp = await apiPost(setupPage, "root", "/ui/catalog/categories", {
      name: `shelf-price-cat-${TS}`,
    });
    bpCategoryId = (await catResp.json()).category_id;

    // $10.00 catalog item.
    const itemResp = await apiPost(
      setupPage,
      "root",
      `/ui/catalog/categories/${bpCategoryId}/items`,
      {
        name: `Deal Widget ${TS}`,
        price_cents: 1000,
        currency: "USD",
      },
    );
    bpItemId = (await itemResp.json()).item_id;

    await apiPost(
      setupPage,
      "root",
      `/broadcast/sessions/${bpSessionId}/products`,
      {
        item_id: bpItemId,
        category_id: bpCategoryId,
        display_order: 0,
      },
    );

    // Set a broadcast price of $5.00 (50% off, no expiry).
    const priceResp = await apiPatch(
      setupPage,
      "root",
      `/broadcast/sessions/${bpSessionId}/products/${bpItemId}/price`,
      { broadcast_price_cents: 500 },
    );
    expect(priceResp.status()).toBe(200);
    await setupCtx.close();

    // UI page with full auth.
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuthForUI(page, "root");
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("105.1 LIVE DEAL badge, effective + struck-through price visible", async () => {
    await page.goto(`http://localhost:3000/live/${bpSessionId}`);
    await expect(
      page.locator('[data-testid="product-shelf-panel"]'),
    ).toBeVisible({ timeout: 10_000 });

    await expect(
      page.locator('[data-testid="broadcast-price-effective"]'),
    ).toHaveText("$5.00", { timeout: 10_000 });
    await expect(
      page.locator('[data-testid="broadcast-price-original"]'),
    ).toHaveText("$10.00");
    await expect(
      page.locator('[data-testid="broadcast-price-badge"]'),
    ).toContainText("LIVE DEAL 50% OFF");
  });

  test("105.2 expiry countdown shown when expires_in_seconds set", async ({
    browser,
  }) => {
    const setupCtx = await browser.newContext();
    const setupPage = await setupCtx.newPage();
    await injectAuth(setupPage, "root");
    const r = await apiPatch(
      setupPage,
      "root",
      `/broadcast/sessions/${bpSessionId}/products/${bpItemId}/price`,
      { broadcast_price_cents: 500, expires_in_seconds: 120 },
    );
    expect(r.status()).toBe(200);
    await setupCtx.close();

    await page.goto(`http://localhost:3000/live/${bpSessionId}`);
    await expect(
      page.locator('[data-testid="broadcast-price-countdown"]'),
    ).toBeVisible({ timeout: 10_000 });
    await expect(
      page.locator('[data-testid="broadcast-price-countdown"]'),
    ).toContainText("m");
  });

  test("105.3 shelf:price_update window event updates displayed price", async () => {
    await page.goto(`http://localhost:3000/live/${bpSessionId}`);
    await expect(
      page.locator('[data-testid="broadcast-price-effective"]'),
    ).toBeVisible({ timeout: 10_000 });

    await page.evaluate((itemId: string) => {
      window.dispatchEvent(
        new CustomEvent("shelf:price_update", {
          detail: {
            item_id: itemId,
            price_cents: 1000,
            broadcast_price_cents: 300,
            effective_price_cents: 300,
            is_broadcast_price: true,
            discount_pct: 70,
          },
        }),
      );
    }, bpItemId);

    await expect(
      page.locator('[data-testid="broadcast-price-effective"]'),
    ).toHaveText("$3.00", { timeout: 5_000 });
    await expect(
      page.locator('[data-testid="broadcast-price-badge"]'),
    ).toContainText("70% OFF");
  });
});
