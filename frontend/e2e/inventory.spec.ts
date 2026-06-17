/**
 * E2E tests for SHOP-001: Inventory Management.
 *
 * Sections:
 *   1 — Stock CRUD API (6 tests)
 *   2 — Stock Validation API (4 tests)
 *   3 — Stock in Purchase Flow (4 tests)
 *   4 — ItemEditor UI (4 tests)
 *   5 — Product Detail UI (3 tests)
 *
 * Auth:
 *   Catalog API → session cookies + x-csrf-token header (require_ui_session)
 *
 * Test users (from e2e_session_setup.py):
 *   Alice   (e2e_alice@test.local) — catalog owner
 *   Bob     (e2e_bob@test.local)   — buyer / non-owner
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const TS       = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name:     string;
    value:    string;
    domain:   string;
    path:     string;
    httpOnly: boolean;
    secure:   boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires:  number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function newIdentityPage(browser: Browser, userId: string): Promise<Page> {
  const page = await browser.newPage();
  await injectAuth(page, userId);
  return page;
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function catPost(page: Page, userId: string, path: string, body: object) {
  const session = getSessions()[userId];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function catGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function catPatch(page: Page, userId: string, path: string, body: object) {
  const session = getSessions()[userId];
  return page.request.patch(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function catDelete(page: Page, userId: string, path: string) {
  const session = getSessions()[userId];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function catPurchase(page: Page, userId: string, cartId: string) {
  const session = getSessions()[userId];
  return page.request.post(`${API}/ui/shoppingcart/carts/${cartId}/purchase`, {
    data: {},
    headers: {
      "x-csrf-token": session.csrf_token,
      "X-Idempotency-Key": `idem_${Date.now()}_${Math.random().toString(36).slice(2)}`,
    },
  });
}

// ─── Shared state ─────────────────────────────────────────────────────────────

const CAT_NAME = `inv_cat_${TS}`;
let categoryId = "";
let stockedItemId = "";
let unlimitedItemId = "";
let oosItemId = "";

// =============================================================================
// Section 1 — Stock CRUD API
// =============================================================================

test.describe("1 — Stock CRUD API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);

    // Create a test category
    const catResp = await catPost(alicePage, ALICE_ID, "/ui/catalog/categories", {
      name: CAT_NAME,
    });
    expect(catResp.status()).toBe(200);
    const catBody = await catResp.json();
    categoryId = catBody.category_id;
  });

  test.afterAll(async () => {
    // Cleanup: delete category + items
    if (categoryId) {
      await catDelete(alicePage, ALICE_ID, `/ui/catalog/categories/${categoryId}?cascade=true`);
    }
    await alicePage.close();
  });

  test("1.1 Create item with stock_count returns stock fields", async () => {
    const resp = await catPost(alicePage, ALICE_ID, `/ui/catalog/categories/${categoryId}/items`, {
      name: `Stocked Item ${TS}`,
      price_cents: 1999,
      stock_count: 50,
      low_stock_threshold: 10,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    stockedItemId = body.item_id;
    expect(body.stock_count).toBe(50);
    expect(body.stock_status).toBe("in_stock");
    expect(body.low_stock_threshold).toBe(10);
    expect(body.stock_updated_at).toBeTruthy();
  });

  test("1.2 Create item without stock_count returns unlimited", async () => {
    const resp = await catPost(alicePage, ALICE_ID, `/ui/catalog/categories/${categoryId}/items`, {
      name: `Unlimited Item ${TS}`,
      price_cents: 999,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    unlimitedItemId = body.item_id;
    expect(body.stock_count).toBeNull();
    expect(body.stock_status).toBe("unlimited");
  });

  test("1.3 Adjust stock with positive delta (restock)", async () => {
    const resp = await catPatch(alicePage, ALICE_ID, `/ui/catalog/items/${stockedItemId}/stock`, {
      delta: 20,
      reason: "Restock",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.stock_count).toBe(70);
    expect(body.stock_status).toBe("in_stock");
  });

  test("1.4 Adjust stock with negative delta (sold)", async () => {
    const resp = await catPatch(alicePage, ALICE_ID, `/ui/catalog/items/${stockedItemId}/stock`, {
      delta: -5,
      reason: "Sold at event",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.stock_count).toBe(65);
  });

  test("1.5 Adjust stock to zero → out_of_stock", async () => {
    // First set stock to a known value
    await catPatch(alicePage, ALICE_ID, `/ui/catalog/items/${stockedItemId}/stock`, {
      absolute: 5,
    });
    // Then decrement to zero
    const resp = await catPatch(alicePage, ALICE_ID, `/ui/catalog/items/${stockedItemId}/stock`, {
      delta: -5,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.stock_count).toBe(0);
    expect(body.stock_status).toBe("out_of_stock");
  });

  test("1.6 Adjust stock below zero returns 409", async () => {
    // Stock is already at 0 from previous test
    const resp = await catPatch(alicePage, ALICE_ID, `/ui/catalog/items/${stockedItemId}/stock`, {
      delta: -1,
    });
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail).toContain("Insufficient stock");
  });
});

// =============================================================================
// Section 2 — Stock Validation API
// =============================================================================

test.describe("2 — Stock Validation API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let testItemId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
    bobPage = await newIdentityPage(browser, BOB_ID);

    // Create category + item
    const catResp = await catPost(alicePage, ALICE_ID, "/ui/catalog/categories", {
      name: `val_cat_${TS}`,
    });
    const catBody = await catResp.json();
    const catId = catBody.category_id;

    const itemResp = await catPost(alicePage, ALICE_ID, `/ui/catalog/categories/${catId}/items`, {
      name: `Val Item ${TS}`,
      price_cents: 500,
      stock_count: 10,
    });
    const itemBody = await itemResp.json();
    testItemId = itemBody.item_id;
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("2.1 Both delta and absolute returns 422", async () => {
    const resp = await catPatch(alicePage, ALICE_ID, `/ui/catalog/items/${testItemId}/stock`, {
      delta: 5,
      absolute: 10,
    });
    expect(resp.status()).toBe(422);
  });

  test("2.2 Neither delta nor absolute returns 422", async () => {
    const resp = await catPatch(alicePage, ALICE_ID, `/ui/catalog/items/${testItemId}/stock`, {
      reason: "just a reason",
    });
    expect(resp.status()).toBe(422);
  });

  test("2.3 Non-owner cannot adjust stock → 403", async () => {
    const resp = await catPatch(bobPage, BOB_ID, `/ui/catalog/items/${testItemId}/stock`, {
      delta: 5,
    });
    expect(resp.status()).toBe(403);
  });

  test("2.4 Absolute with negative value returns 422", async () => {
    const resp = await catPatch(alicePage, ALICE_ID, `/ui/catalog/items/${testItemId}/stock`, {
      absolute: -1,
    });
    expect(resp.status()).toBe(422);
  });
});

// =============================================================================
// Section 3 — Stock in Purchase Flow
// =============================================================================

test.describe("3 — Stock in Purchase Flow", () => {
  let alicePage: Page;
  let bobPage: Page;
  let purchaseCatId = "";
  let purchaseItemId = "";
  let purchaseUnlimitedItemId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
    bobPage = await newIdentityPage(browser, BOB_ID);

    // Create category
    const catResp = await catPost(alicePage, ALICE_ID, "/ui/catalog/categories", {
      name: `purch_cat_${TS}`,
    });
    const catBody = await catResp.json();
    purchaseCatId = catBody.category_id;

    // Create item with stock = 2
    const itemResp = await catPost(alicePage, ALICE_ID, `/ui/catalog/categories/${purchaseCatId}/items`, {
      name: `Purchase Item ${TS}`,
      price_cents: 100,
      stock_count: 2,
      low_stock_threshold: 1,
    });
    const itemBody = await itemResp.json();
    purchaseItemId = itemBody.item_id;

    // Create unlimited item
    const unlResp = await catPost(alicePage, ALICE_ID, `/ui/catalog/categories/${purchaseCatId}/items`, {
      name: `Unlimited Purchase Item ${TS}`,
      price_cents: 50,
    });
    const unlBody = await unlResp.json();
    purchaseUnlimitedItemId = unlBody.item_id;
  });

  test.afterAll(async () => {
    if (purchaseCatId) {
      await catDelete(alicePage, ALICE_ID, `/ui/catalog/categories/${purchaseCatId}?cascade=true`);
    }
    await alicePage.close();
    await bobPage.close();
  });

  test("3.1 Purchase decrements stock", async () => {
    // Bob creates a cart and adds the stocked item
    const cartResp = await catPost(bobPage, BOB_ID, "/ui/shoppingcart/carts", {});
    expect(cartResp.status()).toBe(200);
    const cartBody = await cartResp.json();
    const cartId = cartBody.cart_id;

    // Add stocked item (quantity=1)
    const addResp = await catPost(bobPage, BOB_ID, `/ui/shoppingcart/carts/${cartId}/items`, {
      sku: `catalog:${purchaseItemId}`,
      name: `Purchase Item ${TS}`,
      quantity: 1,
      unit_price_cents: 100,
      category_id: purchaseCatId,
      item_id: purchaseItemId,
    });
    expect(addResp.status()).toBe(200);

    // Purchase cart
    const purchResp = await catPurchase(bobPage, BOB_ID, cartId);
    expect(purchResp.status()).toBe(200);

    // Verify stock decremented (was 2, now should be 1)
    const listResp = await catGet(alicePage, `/ui/catalog/categories/${purchaseCatId}/items`);
    expect(listResp.status()).toBe(200);
    const listBody = await listResp.json();
    const item = listBody.items.find((i: { item_id: string }) => i.item_id === purchaseItemId);
    expect(item).toBeTruthy();
    expect(item.stock_count).toBe(1);
    expect(item.stock_status).toBe("low_stock");
  });

  test("3.2 Purchase out-of-stock item fails with 409", async () => {
    // Set stock to 0
    await catPatch(alicePage, ALICE_ID, `/ui/catalog/items/${purchaseItemId}/stock`, {
      absolute: 0,
    });

    // Bob creates a cart and adds the OOS item
    const cartResp = await catPost(bobPage, BOB_ID, "/ui/shoppingcart/carts", {});
    const cartBody = await cartResp.json();
    const cartId = cartBody.cart_id;

    const addResp = await catPost(bobPage, BOB_ID, `/ui/shoppingcart/carts/${cartId}/items`, {
      sku: `catalog:${purchaseItemId}`,
      name: `Purchase Item ${TS}`,
      quantity: 1,
      unit_price_cents: 100,
      category_id: purchaseCatId,
      item_id: purchaseItemId,
    });
    expect(addResp.status()).toBe(200);

    // Purchase should fail
    const purchResp = await catPurchase(bobPage, BOB_ID, cartId);
    expect(purchResp.status()).toBe(409);
    const body = await purchResp.json();
    expect(body.detail.toLowerCase()).toContain("out of stock");
  });

  test("3.3 Purchase unlimited item succeeds", async () => {
    const cartResp = await catPost(bobPage, BOB_ID, "/ui/shoppingcart/carts", {});
    const cartBody = await cartResp.json();
    const cartId = cartBody.cart_id;

    const addResp = await catPost(bobPage, BOB_ID, `/ui/shoppingcart/carts/${cartId}/items`, {
      sku: `catalog:${purchaseUnlimitedItemId}`,
      name: `Unlimited Purchase Item ${TS}`,
      quantity: 3,
      unit_price_cents: 50,
      category_id: purchaseCatId,
      item_id: purchaseUnlimitedItemId,
    });
    expect(addResp.status()).toBe(200);

    const purchResp = await catPurchase(bobPage, BOB_ID, cartId);
    expect(purchResp.status()).toBe(200);
  });

  test("3.4 Multi-item cart: one OOS blocks entire purchase + rollback", async () => {
    // Restock the stocked item to 1
    await catPatch(alicePage, ALICE_ID, `/ui/catalog/items/${purchaseItemId}/stock`, {
      absolute: 1,
    });

    // Create cart with stocked item (qty=2, but only 1 in stock) and unlimited item
    const cartResp = await catPost(bobPage, BOB_ID, "/ui/shoppingcart/carts", {});
    const cartBody = await cartResp.json();
    const cartId = cartBody.cart_id;

    // Add unlimited item first
    await catPost(bobPage, BOB_ID, `/ui/shoppingcart/carts/${cartId}/items`, {
      sku: `catalog:${purchaseUnlimitedItemId}`,
      name: `Unlimited Purchase Item ${TS}`,
      quantity: 1,
      unit_price_cents: 50,
      category_id: purchaseCatId,
      item_id: purchaseUnlimitedItemId,
    });

    // Add stocked item with qty=2 (more than available)
    await catPost(bobPage, BOB_ID, `/ui/shoppingcart/carts/${cartId}/items`, {
      sku: `catalog:${purchaseItemId}`,
      name: `Purchase Item ${TS}`,
      quantity: 2,
      unit_price_cents: 100,
      category_id: purchaseCatId,
      item_id: purchaseItemId,
    });

    // Purchase should fail
    const purchResp = await catPurchase(bobPage, BOB_ID, cartId);
    expect(purchResp.status()).toBe(409);

    // Verify stock was NOT permanently decremented (still 1 after rollback)
    const listResp = await catGet(alicePage, `/ui/catalog/categories/${purchaseCatId}/items`);
    const listBody = await listResp.json();
    const item = listBody.items.find((i: { item_id: string }) => i.item_id === purchaseItemId);
    expect(item.stock_count).toBe(1);
  });
});

// =============================================================================
// Section 4 — ItemEditor UI
// =============================================================================

test.describe("4 — ItemEditor UI", () => {
  let alicePage: Page;
  let uiCatId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);

    // Create a category and an item with stock for the UI tests
    const catResp = await catPost(alicePage, ALICE_ID, "/ui/catalog/categories", {
      name: `ui_cat_${TS}`,
    });
    const catBody = await catResp.json();
    uiCatId = catBody.category_id;

    // Create an item with stock
    await catPost(alicePage, ALICE_ID, `/ui/catalog/categories/${uiCatId}/items`, {
      name: `UI Stock Item ${TS}`,
      price_cents: 2500,
      stock_count: 42,
      low_stock_threshold: 8,
    });

    // Create an out-of-stock item
    await catPost(alicePage, ALICE_ID, `/ui/catalog/categories/${uiCatId}/items`, {
      name: `UI OOS Item ${TS}`,
      price_cents: 500,
      stock_count: 0,
    });
  });

  test.afterAll(async () => {
    if (uiCatId) {
      await catDelete(alicePage, ALICE_ID, `/ui/catalog/categories/${uiCatId}?cascade=true`);
    }
    await alicePage.close();
  });

  test("4.1 Stock input visible in create dialog", async () => {
    await alicePage.goto(`${BASE}/shop`, { waitUntil: "domcontentloaded" });
    // Wait for page to load, then click "Manage" tab
    await expect(alicePage.getByRole("tab", { name: "Manage" })).toBeVisible({ timeout: 10_000 });
    await alicePage.getByRole("tab", { name: "Manage" }).click();
    // Select our test category
    await alicePage.getByRole("button", { name: `ui_cat_${TS}` }).click();
    // Wait for items to load
    await alicePage.waitForTimeout(500);
    // Click "Add Item" button
    await alicePage.getByRole("button", { name: "Add Item" }).click();
    // Verify stock input is visible
    await expect(alicePage.locator("#item-stock")).toBeVisible();
    await expect(alicePage.locator("#item-threshold")).toBeVisible();
    // Close dialog
    await alicePage.getByRole("button", { name: "Cancel" }).click();
  });

  test("4.2 Stock value pre-filled in edit dialog", async () => {
    await alicePage.goto(`${BASE}/shop`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByRole("tab", { name: "Manage" })).toBeVisible({ timeout: 10_000 });
    await alicePage.getByRole("tab", { name: "Manage" }).click();
    await alicePage.getByRole("button", { name: `ui_cat_${TS}` }).click();
    await alicePage.waitForTimeout(500);

    // Find the stocked item card and click its edit button
    const stockCard = alicePage.locator("p.truncate").filter({ hasText: `UI Stock Item ${TS}` }).first();
    await expect(stockCard).toBeVisible();
    // Navigate from p.truncate up to the justify-between flex container (3 levels up)
    // which contains both the text area and the edit/delete buttons
    const cardRow = stockCard.locator("../../..");
    await cardRow.locator("button").first().click();

    // Verify stock input is pre-filled with 42
    await expect(alicePage.locator("#item-stock")).toHaveValue("42");
    await expect(alicePage.locator("#item-threshold")).toHaveValue("8");

    // Close dialog
    await alicePage.getByRole("button", { name: "Cancel" }).click();
  });

  test("4.3 In-stock badge visible in admin table", async () => {
    await alicePage.goto(`${BASE}/shop`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByRole("tab", { name: "Manage" })).toBeVisible({ timeout: 10_000 });
    await alicePage.getByRole("tab", { name: "Manage" }).click();
    await alicePage.getByRole("button", { name: `ui_cat_${TS}` }).click();
    await alicePage.waitForTimeout(500);

    // Look for "In Stock" badge
    const inStockBadge = alicePage.locator("[data-testid='stock-badge']").filter({ hasText: /In Stock/ });
    await expect(inStockBadge.first()).toBeVisible();
  });

  test("4.4 Out-of-stock badge visible in admin table", async () => {
    await alicePage.goto(`${BASE}/shop`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByRole("tab", { name: "Manage" })).toBeVisible({ timeout: 10_000 });
    await alicePage.getByRole("tab", { name: "Manage" }).click();
    await alicePage.getByRole("button", { name: `ui_cat_${TS}` }).click();
    await alicePage.waitForTimeout(500);

    const oosBadge = alicePage.locator("[data-testid='stock-badge']").filter({ hasText: /Out of Stock/ });
    await expect(oosBadge.first()).toBeVisible();
  });
});

// =============================================================================
// Section 5 — Product Detail UI
// =============================================================================

test.describe("5 — Product Detail UI", () => {
  let alicePage: Page;
  let detailCatId = "";
  let inStockItemId = "";
  let lowStockItemId = "";
  let oosDetailItemId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);

    // Create category
    const catResp = await catPost(alicePage, ALICE_ID, "/ui/catalog/categories", {
      name: `detail_cat_${TS}`,
    });
    const catBody = await catResp.json();
    detailCatId = catBody.category_id;

    // In-stock item
    const isResp = await catPost(alicePage, ALICE_ID, `/ui/catalog/categories/${detailCatId}/items`, {
      name: `Detail In Stock ${TS}`,
      price_cents: 3000,
      stock_count: 100,
      low_stock_threshold: 5,
    });
    inStockItemId = (await isResp.json()).item_id;

    // Low-stock item
    const lsResp = await catPost(alicePage, ALICE_ID, `/ui/catalog/categories/${detailCatId}/items`, {
      name: `Detail Low Stock ${TS}`,
      price_cents: 2000,
      stock_count: 3,
      low_stock_threshold: 5,
    });
    lowStockItemId = (await lsResp.json()).item_id;

    // Out-of-stock item
    const oosResp = await catPost(alicePage, ALICE_ID, `/ui/catalog/categories/${detailCatId}/items`, {
      name: `Detail OOS ${TS}`,
      price_cents: 1000,
      stock_count: 0,
      low_stock_threshold: 5,
    });
    oosDetailItemId = (await oosResp.json()).item_id;
  });

  test.afterAll(async () => {
    if (detailCatId) {
      await catDelete(alicePage, ALICE_ID, `/ui/catalog/categories/${detailCatId}?cascade=true`);
    }
    await alicePage.close();
  });

  test("5.1 Low-stock item shows 'Only N left' badge", async () => {
    await alicePage.goto(`${BASE}/shop/${detailCatId}/${lowStockItemId}`, { waitUntil: "domcontentloaded" });
    // Wait for item name to appear (data loaded)
    await expect(alicePage.getByRole("heading", { level: 1 })).toBeVisible({ timeout: 10_000 });
    const badge = alicePage.locator("[data-testid='stock-badge']").filter({ hasText: /Only 3 left/ });
    await expect(badge).toBeVisible();
  });

  test("5.2 Out-of-stock item shows badge + disabled Add to Cart", async () => {
    await alicePage.goto(`${BASE}/shop/${detailCatId}/${oosDetailItemId}`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByRole("heading", { level: 1 })).toBeVisible({ timeout: 10_000 });
    const badge = alicePage.locator("[data-testid='stock-badge']").filter({ hasText: /Out of Stock/ });
    await expect(badge).toBeVisible();
    // "Add to Cart" / "Out of Stock" button should be disabled
    const cartBtn = alicePage.getByRole("button", { name: /Out of Stock/i });
    await expect(cartBtn).toBeDisabled();
  });

  test("5.3 In-stock item has no stock badge and enabled Add to Cart", async () => {
    await alicePage.goto(`${BASE}/shop/${detailCatId}/${inStockItemId}`, { waitUntil: "domcontentloaded" });
    // Wait for the Add to Cart button to appear (data loaded)
    const cartBtn = alicePage.getByRole("button", { name: /Add to Cart/i });
    await expect(cartBtn).toBeVisible({ timeout: 10_000 });
    // No stock badge should be shown for in-stock items
    const badges = alicePage.locator("[data-testid='stock-badge']");
    await expect(badges).toHaveCount(0);
    await expect(cartBtn).toBeEnabled();
  });
});
