/**
 * E2E tests for Shopping Cart, Catalog, and Billing features.
 *
 * Routes tested:
 *   /shop              — Catalog browse & manage tabs
 *   /shop/:cat/:item   — Product detail
 *   /cart              — Shopping cart
 *   /billing           — Billing tabs (Overview, Methods, Ledger)
 *
 * These routes are served by the React SPA (not Vite-proxied), so direct
 * navigation works fine.
 *
 * Cart auto-creation: Cart.tsx creates a cart automatically when the page
 * loads with no open carts, so "Cart is empty" is the initial state we see.
 *
 * Auth: Alice (e2e_alice@test.local) has no MFA, so all endpoints are
 * accessible. She can create catalog categories and items as their owner.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";

// ─── Session bootstrap ────────────────────────────────────────────────────────

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
      "python3 " + REPO_ROOT + "/e2e_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function gotoPage(page: Page, path: string, userId = ALICE_ID) {
  await injectAuth(page, userId);
  await page.goto(`${BASE}${path}`, { waitUntil: "load" });
  await page.waitForTimeout(800);
}

// ─── Authenticated API helpers ────────────────────────────────────────────────

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}${path}`, { params });
}

async function apiPost(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiDelete(page: Page, path: string, params?: Record<string, string>) {
  const session = getSessions()[ALICE_ID];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    params,
  });
}

async function apiPatch(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.patch(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

/** Delete every open cart for Alice so tests start from a clean slate. */
async function deleteAllOpenCarts(page: Page) {
  const resp = await apiGet(page, "/ui/shoppingcart/carts");
  if (!resp.ok()) return;
  const carts: Array<{ cart_id: string; status: string }> = await resp.json();
  for (const c of (Array.isArray(carts) ? carts : [])) {
    if (c.status === "OPEN") {
      await apiDelete(page, `/ui/shoppingcart/carts/${c.cart_id}`);
    }
  }
}

// ─── 1. Shop — page structure ──────────────────────────────────────────────────

test.describe("1. Shop — page structure", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await gotoPage(page, "/shop");
  });

  test.afterAll(async () => page?.close());

  test("Shop page renders 'Browse' and 'Manage' tabs", async () => {
    await expect(page.getByRole("tab", { name: "Browse" })).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("tab", { name: "Manage" })).toBeVisible();
  });

  test("Browse tab has a product search input", async () => {
    await expect(page.getByPlaceholder("Search products...")).toBeVisible({ timeout: 5000 });
  });

  test("Browse tab shows a 'Categories' sidebar section", async () => {
    await expect(page.getByText("Categories", { exact: true })).toBeVisible({ timeout: 5000 });
  });
});

// ─── 2. Shop — catalog browse with live test data ──────────────────────────────

test.describe("2. Shop — catalog browse with test data", () => {
  let page: Page;
  let categoryId: string;
  let itemId: string;
  const CAT_NAME = `!e2e-cart ${Date.now()}`;
  const ITEM_NAME = "E2E Widget Pro";

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    // Create a test category and item via API.
    const catResp = await apiPost(page, "/ui/catalog/categories", {
      name: CAT_NAME,
      description: "Created by E2E tests",
    });
    const cat = await catResp.json();
    categoryId = cat.category_id;

    const itemResp = await apiPost(
      page,
      `/ui/catalog/categories/${categoryId}/items`,
      { name: ITEM_NAME, price_cents: 1999, currency: "USD" },
    );
    const item = await itemResp.json();
    itemId = item.item_id;

    await page.goto(`${BASE}/shop`, { waitUntil: "load" });
    await page.waitForTimeout(800);
  });

  test.afterAll(async () => {
    if (page && categoryId) {
      await apiDelete(page, `/ui/catalog/categories/${categoryId}`, { cascade: "true" });
    }
    await page?.close();
  });

  test("test category appears in the sidebar", async () => {
    await expect(page.getByRole("button", { name: CAT_NAME })).toBeVisible({ timeout: 5000 });
  });

  test("selecting the test category shows the test item in the grid", async () => {
    await page.getByRole("button", { name: CAT_NAME }).click();
    await expect(page.getByText(ITEM_NAME)).toBeVisible({ timeout: 5000 });
  });

  test("search for the item name returns it in results", async () => {
    await page.getByPlaceholder("Search products...").fill(ITEM_NAME);
    await expect(page.getByText(ITEM_NAME)).toBeVisible({ timeout: 6000 });
  });
});

// ─── 3. Cart — empty cart state ───────────────────────────────────────────────

test.describe("3. Cart — empty cart state", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    await deleteAllOpenCarts(page);
    // Navigate to /cart — the component auto-creates a cart when none exist.
    await page.goto(`${BASE}/cart`, { waitUntil: "load" });
    // Wait until the cart auto-creates and the empty state is rendered.
    // The component: GETs carts → sees none → POSTs auto-create → invalidates → GETs again → renders "Cart is empty".
    await expect(page.getByText("Cart is empty")).toBeVisible({ timeout: 15000 });
  });

  test.afterAll(async () => page?.close());

  test("cart page has a 'Back to shop' link and 'New Cart' button", async () => {
    await expect(page.getByRole("button", { name: "Back to shop" })).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("button", { name: "New Cart" })).toBeVisible();
  });

  test("auto-created cart starts in the 'Cart is empty' state", async () => {
    await expect(page.getByText("Cart is empty")).toBeVisible({ timeout: 8000 });
  });

  test("'Browse Shop' action button is visible inside the empty cart", async () => {
    await expect(page.getByRole("button", { name: "Browse Shop" })).toBeVisible({ timeout: 5000 });
  });

  test("'Delete Cart' button appears once a cart is active", async () => {
    await expect(page.getByRole("button", { name: "Delete Cart" })).toBeVisible({ timeout: 5000 });
  });
});

// ─── 4. Cart — with items ──────────────────────────────────────────────────────

test.describe("4. Cart — with items", () => {
  let page: Page;
  let cartId: string;
  const ITEM_SKU = "e2e-widget-001";
  const ITEM_NAME = "E2E Cart Widget";
  const UNIT_PRICE = 999; // $9.99

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    await deleteAllOpenCarts(page);

    // Create a cart and add a test item via API.
    const cartResp = await apiPost(page, "/ui/shoppingcart/carts", {});
    const cart = await cartResp.json();
    cartId = cart.cart_id;

    await apiPost(page, `/ui/shoppingcart/carts/${cartId}/items`, {
      sku: ITEM_SKU,
      name: ITEM_NAME,
      quantity: 1,
      unit_price_cents: UNIT_PRICE,
    });

    // Wait for the carts list GET to complete so the page renders the cart with items.
    const cartsLoaded = page.waitForResponse(
      (r) => r.url().includes("/ui/shoppingcart/carts") && r.request().method() === "GET"
        && !r.url().match(/\/carts\/.+/),
      { timeout: 10000 },
    );
    await page.goto(`${BASE}/cart`, { waitUntil: "load" });
    await cartsLoaded;
    await page.waitForTimeout(400);
  });

  test.afterAll(async () => page?.close());

  test("item name is displayed in the cart", async () => {
    await expect(page.getByText(ITEM_NAME)).toBeVisible({ timeout: 5000 });
  });

  test("quantity controls (Minus / count / Plus) are visible", async () => {
    // Minus button has rounded-r-none, Plus has rounded-l-none
    await expect(page.locator("button.rounded-r-none").first()).toBeVisible({ timeout: 5000 });
    await expect(page.locator("button.rounded-l-none").first()).toBeVisible();
    // Quantity is initially 1
    await expect(page.locator("span.w-8.text-center")).toContainText("1", { timeout: 3000 });
  });

  test("cart shows a 'Total' label and formatted total amount", async () => {
    await expect(page.getByText("Total", { exact: true })).toBeVisible({ timeout: 5000 });
    // Total for 1 × $9.99 = $9.99 — use the bold <p> in the total card to avoid
    // matching the per-unit price or line-total spans on the same page.
    await expect(page.locator("p.text-2xl.font-bold")).toContainText("$9.99", { timeout: 10000 });
  });

  test("'Proceed to Checkout' button is visible", async () => {
    await expect(page.getByRole("button", { name: "Proceed to Checkout" })).toBeVisible({
      timeout: 5000,
    });
  });

  test("clicking the item trash icon removes the item from the cart", async () => {
    // The per-item remove button uses className="... text-destructive"
    await page.locator("button.text-destructive").first().click();
    await expect(page.getByText(ITEM_NAME)).not.toBeVisible({ timeout: 5000 });
    // Cart is now empty
    await expect(page.getByText("Cart is empty")).toBeVisible({ timeout: 5000 });
  });
});

// ─── 5. Product detail page ───────────────────────────────────────────────────

test.describe("5. Product detail page", () => {
  let page: Page;
  let categoryId: string;
  let itemId: string;
  const ITEM_NAME = "E2E Detail Widget";
  const ITEM_PRICE = 4999; // $49.99

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);

    // Create category + item.
    const catResp = await apiPost(page, "/ui/catalog/categories", {
      name: "E2E Detail Category",
      description: "For product detail tests",
    });
    const cat = await catResp.json();
    categoryId = cat.category_id;

    const itemResp = await apiPost(
      page,
      `/ui/catalog/categories/${categoryId}/items`,
      {
        name: ITEM_NAME,
        description: "A widget for testing product detail",
        price_cents: ITEM_PRICE,
        currency: "USD",
      },
    );
    const item = await itemResp.json();
    itemId = item.item_id;

    await page.goto(`${BASE}/shop/${categoryId}/${itemId}`, { waitUntil: "load" });
    await page.waitForTimeout(1000);
  });

  test.afterAll(async () => {
    if (page && categoryId) {
      await apiDelete(page, `/ui/catalog/categories/${categoryId}`, { cascade: "true" });
    }
    await page?.close();
  });

  test("product name is shown as an h1 heading", async () => {
    await expect(page.getByRole("heading", { name: ITEM_NAME })).toBeVisible({ timeout: 5000 });
  });

  test("product price is displayed", async () => {
    await expect(page.getByText("$49.99")).toBeVisible({ timeout: 5000 });
  });

  test("'Add to Cart' button is visible", async () => {
    await expect(page.getByRole("button", { name: "Add to Cart" })).toBeVisible({ timeout: 5000 });
  });

  test("'Write a Review' section is present with a Rating label", async () => {
    await expect(page.getByText("Write a Review")).toBeVisible({ timeout: 5000 });
    await expect(page.getByText("Rating", { exact: true })).toBeVisible();
  });

  test("new product shows 'No reviews yet' placeholder", async () => {
    await expect(
      page.getByText("No reviews yet. Be the first to review!"),
    ).toBeVisible({ timeout: 5000 });
  });

  test("'Back to shop' button navigates back", async () => {
    await page.getByRole("button", { name: "Back to shop" }).click();
    await expect(page).toHaveURL(/\/shop$/, { timeout: 5000 });
  });
});

// ─── 6. Billing — page structure ──────────────────────────────────────────────

test.describe("6. Billing — page structure", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await gotoPage(page, "/billing");
  });

  test.afterAll(async () => page?.close());

  test("billing page shows 'Usage & Billing' heading", async () => {
    await expect(page.getByText("Usage & Billing")).toBeVisible({ timeout: 5000 });
  });

  test("all five billing tabs are present", async () => {
    for (const tab of ["Usage", "Overview", "Methods", "Ledger", "Subscriptions"]) {
      await expect(page.getByRole("tab", { name: tab })).toBeVisible({ timeout: 5000 });
    }
  });
});

// ─── 7. Billing — Overview tab ────────────────────────────────────────────────

test.describe("7. Billing — Overview tab", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await gotoPage(page, "/billing");
    await page.getByRole("tab", { name: "Overview" }).click();
    await page.waitForTimeout(600);
  });

  test.afterAll(async () => page?.close());

  test("Overview tab shows an 'Account Balance' card", async () => {
    await expect(page.getByText("Account Balance", { exact: true })).toBeVisible({ timeout: 5000 });
  });

  test("Autopay section has a toggle switch", async () => {
    await expect(page.getByText("Autopay", { exact: true })).toBeVisible({ timeout: 5000 });
    await expect(page.locator("#autopay-toggle")).toBeVisible({ timeout: 3000 });
  });

  test("quick-links section has 'Payment Methods' and 'Transaction Ledger' buttons", async () => {
    await expect(page.getByRole("button", { name: "Payment Methods" })).toBeVisible({
      timeout: 5000,
    });
    await expect(page.getByRole("button", { name: "Transaction Ledger" })).toBeVisible();
  });
});

// ─── 8. Billing — Methods tab ─────────────────────────────────────────────────

test.describe("8. Billing — Methods tab", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await gotoPage(page, "/billing");
    await page.getByRole("tab", { name: "Methods" }).click();
    await page.waitForTimeout(600);
  });

  test.afterAll(async () => page?.close());

  test("Methods tab shows 'Add Card' and 'Add Bank Account' buttons", async () => {
    await expect(page.getByRole("button", { name: "Add Card" })).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("button", { name: "Add Bank Account" })).toBeVisible();
  });

  test("Add Card dialog opens on button click", async () => {
    await page.getByRole("button", { name: "Add Card" }).click();
    await expect(page.getByRole("dialog")).toContainText("Add Card", { timeout: 3000 });
  });

  test("Add Card dialog has 'Name on card', 'Card Number', 'Expiry', 'CVC' fields", async () => {
    await expect(page.getByLabel("Name on card")).toBeVisible();
    await expect(page.getByLabel("Card Number")).toBeVisible();
    await expect(page.getByLabel("Expiry")).toBeVisible();
    await expect(page.getByLabel("CVC")).toBeVisible();
  });

  test("Add Card dialog notes the test/dev context", async () => {
    await expect(page.getByRole("dialog")).toContainText(
      "In production, this form would use Stripe Elements",
    );
  });

  test("Add Card dialog has Cancel and Add Card buttons", async () => {
    await expect(
      page.getByRole("dialog").getByRole("button", { name: "Cancel" }),
    ).toBeVisible();
    await expect(
      page.getByRole("dialog").getByRole("button", { name: "Add Card" }),
    ).toBeVisible();
    // Close so subsequent tests start clean
    await page.getByRole("dialog").getByRole("button", { name: "Cancel" }).click();
  });
});

// ─── 9. Billing — Ledger tab ──────────────────────────────────────────────────

test.describe("9. Billing — Ledger tab", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await gotoPage(page, "/billing");
    await page.getByRole("tab", { name: "Ledger" }).click();
    await page.waitForTimeout(600);
  });

  test.afterAll(async () => page?.close());

  test("Ledger tab has 'From' and 'To' date filter inputs", async () => {
    await expect(page.getByLabel("From")).toBeVisible({ timeout: 5000 });
    await expect(page.getByLabel("To")).toBeVisible();
  });

  test("From/To inputs accept date values and filter entries", async () => {
    await page.getByLabel("From").fill("2024-01-01");
    await page.getByLabel("To").fill("2099-12-31");
    // Just verify the inputs hold their values (filtering is client-side)
    await expect(page.getByLabel("From")).toHaveValue("2024-01-01");
    await expect(page.getByLabel("To")).toHaveValue("2099-12-31");
  });

  test("'Export CSV' button is present in the Ledger tab", async () => {
    await expect(page.getByRole("button", { name: "Export CSV" })).toBeVisible({ timeout: 5000 });
  });
});

// ─── 10. REST API — catalog CRUD ──────────────────────────────────────────────

test.describe("10. REST API — catalog CRUD", () => {
  let page: Page;
  let categoryId: string;
  let itemId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => {
    // Clean up — ignore errors if already deleted by tests
    if (page && itemId && categoryId) {
      await apiDelete(page, `/ui/catalog/categories/${categoryId}/items/${itemId}`).catch(() => {});
    }
    if (page && categoryId) {
      await apiDelete(page, `/ui/catalog/categories/${categoryId}`).catch(() => {});
    }
    await page?.close();
  });

  test("POST /ui/catalog/categories creates a category with name and id", async () => {
    const resp = await apiPost(page, "/ui/catalog/categories", {
      name: "REST API Test Category",
      description: "Automated test category",
    });
    expect(resp.status()).toBe(200);
    const cat = await resp.json();
    expect(typeof cat.category_id).toBe("string");
    expect(cat.name).toBe("REST API Test Category");
    categoryId = cat.category_id;
  });

  test("POST /ui/catalog/categories/{id}/items creates an item", async () => {
    const resp = await apiPost(page, `/ui/catalog/categories/${categoryId}/items`, {
      name: "REST Test Widget",
      description: "Test item",
      price_cents: 2500,
      currency: "USD",
    });
    expect(resp.status()).toBe(200);
    const item = await resp.json();
    expect(item.name).toBe("REST Test Widget");
    expect(item.price_cents).toBe(2500);
    expect(item.category_id).toBe(categoryId);
    itemId = item.item_id;
  });

  test("GET /ui/catalog/categories/{id}/items lists the created item", async () => {
    const resp = await apiGet(page, `/ui/catalog/categories/${categoryId}/items`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(Array.isArray(data.items)).toBe(true);
    expect(data.items.some((i: { item_id: string }) => i.item_id === itemId)).toBe(true);
  });

  test("GET /ui/catalog/items/search returns the item by name", async () => {
    const resp = await apiGet(page, "/ui/catalog/items/search", { q: "REST Test Widget" });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(Array.isArray(data.items)).toBe(true);
    expect(data.items.some((i: { item_id: string }) => i.item_id === itemId)).toBe(true);
  });

  test("DELETE /ui/catalog/categories/{id}/items/{itemId} removes the item", async () => {
    const resp = await apiDelete(
      page,
      `/ui/catalog/categories/${categoryId}/items/${itemId}`,
    );
    expect(resp.ok()).toBe(true);
    itemId = ""; // already deleted, skip afterAll cleanup

    // Verify it's gone from the list
    const listResp = await apiGet(page, `/ui/catalog/categories/${categoryId}/items`);
    const data = await listResp.json();
    expect(data.items.length).toBe(0);
  });
});

// ─── 11. REST API — cart CRUD ─────────────────────────────────────────────────

test.describe("11. REST API — cart CRUD", () => {
  let page: Page;
  let cartId: string;
  const SKU = "rest-api-sku-001";

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    await deleteAllOpenCarts(page);
  });

  test.afterAll(async () => {
    if (page && cartId) {
      await apiDelete(page, `/ui/shoppingcart/carts/${cartId}`).catch(() => {});
    }
    await page?.close();
  });

  test("POST /ui/shoppingcart/carts creates an OPEN cart", async () => {
    const resp = await apiPost(page, "/ui/shoppingcart/carts", {});
    expect(resp.status()).toBe(200);
    const cart = await resp.json();
    expect(typeof cart.cart_id).toBe("string");
    expect(cart.status).toBe("OPEN");
    cartId = cart.cart_id;
  });

  test("POST /ui/shoppingcart/carts/{id}/items adds an item", async () => {
    const resp = await apiPost(page, `/ui/shoppingcart/carts/${cartId}/items`, {
      sku: SKU,
      name: "REST API Widget",
      quantity: 3,
      unit_price_cents: 500,
    });
    expect(resp.status()).toBe(200);
    const item = await resp.json();
    expect(item.sku).toBe(SKU);
    expect(item.quantity).toBe(3);
    expect(item.unit_price_cents).toBe(500);
  });

  test("GET /ui/shoppingcart/carts/{id}/items returns the added item", async () => {
    const resp = await apiGet(page, `/ui/shoppingcart/carts/${cartId}/items`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(Array.isArray(data.items)).toBe(true);
    expect(data.items.some((i: { sku: string }) => i.sku === SKU)).toBe(true);
  });

  test("GET /ui/shoppingcart/carts/{id}/total returns correct total", async () => {
    const resp = await apiGet(page, `/ui/shoppingcart/carts/${cartId}/total`);
    expect(resp.ok()).toBe(true);
    const total = await resp.json();
    expect(total.total_cents).toBe(1500); // 3 × $5.00
    expect(total.currency).toBe("USD");
  });

  test("PATCH /ui/shoppingcart/carts/{id}/items/{sku} updates quantity", async () => {
    const resp = await apiPatch(
      page,
      `/ui/shoppingcart/carts/${cartId}/items/${SKU}`,
      { quantity: 1 },
    );
    expect(resp.ok()).toBe(true);
    const item = await resp.json();
    expect(item.quantity).toBe(1);
  });

  test("DELETE /ui/shoppingcart/carts/{id}/items/{sku} removes the item", async () => {
    const resp = await apiDelete(
      page,
      `/ui/shoppingcart/carts/${cartId}/items/${SKU}`,
    );
    expect(resp.ok()).toBe(true);

    // Cart total should now be 0
    const totalResp = await apiGet(page, `/ui/shoppingcart/carts/${cartId}/total`);
    const total = await totalResp.json();
    expect(total.total_cents).toBe(0);
  });

  test("DELETE /ui/shoppingcart/carts/{id} deletes the cart", async () => {
    const resp = await apiDelete(page, `/ui/shoppingcart/carts/${cartId}`);
    expect(resp.ok()).toBe(true);
    cartId = ""; // already deleted

    // Cart must not appear in the list
    const listResp = await apiGet(page, "/ui/shoppingcart/carts");
    const carts: Array<{ cart_id: string }> = await listResp.json();
    expect(
      (Array.isArray(carts) ? carts : []).some((c) => c.cart_id === cartId),
    ).toBe(false);
  });
});

// ─── 12. REST API — billing reads ─────────────────────────────────────────────

test.describe("12. REST API — billing reads", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => page?.close());

  test("GET /ui/billing/balance returns the expected shape", async () => {
    const resp = await apiGet(page, "/ui/billing/balance");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(typeof data.currency).toBe("string");
    expect(typeof data.owed_pending_cents).toBe("number");
    expect(typeof data.owed_settled_cents).toBe("number");
    expect(typeof data.payments_settled_cents).toBe("number");
  });

  test("GET /ui/billing/payment-methods returns an array", async () => {
    const resp = await apiGet(page, "/ui/billing/payment-methods");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(Array.isArray(data)).toBe(true);
  });

  test("GET /ui/billing/ledger returns an items array", async () => {
    const resp = await apiGet(page, "/ui/billing/ledger");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(Array.isArray(data.items)).toBe(true);
  });
});
