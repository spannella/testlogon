/**
 * E2E tests for Checkout Promo Code Integration (SHOP-002).
 *
 * Sections:
 *   1 -- Promo Validation API (5 tests)
 *   2 -- Checkout with Promo (5 tests)
 *   3 -- Checkout UI (3 tests)
 *
 * Auth: Cookie-based session for Alice (e2e_alice@test.local) with CSRF.
 * Alice acts as both seller (creates promo codes) and buyer (purchases cart).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
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
    _sessions = loadSessions();
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

// ─── API helpers (cookie session + CSRF) ──────────────────────────────────────

async function apiPost(
  page: Page,
  userId: string,
  path: string,
  body?: object,
  extraHeaders?: Record<string, string>,
) {
  const session = getSessions()[userId];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": session.csrf_token, ...extraHeaders },
  });
}

async function apiGet(
  page: Page,
  path: string,
  params?: Record<string, string>,
) {
  const url = params
    ? `${API}${path}?${new URLSearchParams(params).toString()}`
    : `${API}${path}`;
  return page.request.get(url);
}

async function apiDelete(
  page: Page,
  userId: string,
  path: string,
) {
  const session = getSessions()[userId];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 1: Promo Validation API (5 tests)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 1: Promo Validation API", () => {
  let alicePage: Page;

  // Promo code strings
  const VALID_CODE     = `E2EPROMO${TS}`;
  const EXPIRED_CODE   = `E2EEXP${TS}`;
  const MAXED_CODE     = `E2EMAX${TS}`;
  const FIXED_CODE     = `E2EFIX${TS}`;

  let validCodeId: string;
  let expiredCodeId: string;
  let maxedCodeId: string;
  let fixedCodeId: string;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);

    // Create a valid 20% discount code for shop
    const r1 = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes", {
      code: VALID_CODE,
      discount_type: "percentage",
      discount_value: 20,
      applies_to: ["shop"],
      max_uses: 0,
      max_uses_per_user: 10,
    });
    expect(r1.ok()).toBe(true);
    validCodeId = ((await r1.json()) as { code_id: string }).code_id;

    // Create an expired code
    const r2 = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes", {
      code: EXPIRED_CODE,
      discount_type: "percentage",
      discount_value: 10,
      applies_to: ["shop"],
      expires_at: Math.floor(Date.now() / 1000) + 86400, // future to create
    });
    expect(r2.ok()).toBe(true);
    const expData = (await r2.json()) as { code_id: string };
    expiredCodeId = expData.code_id;
    // Now deactivate it to simulate "expired" behavior
    const r2b = await apiPost(alicePage, ALICE_ID, `/ui/promo-codes/${expiredCodeId}`, {});
    // Actually, let's patch it to set active=false to simulate expired
    const r2c = await alicePage.request.patch(`${API}/ui/promo-codes/${expiredCodeId}`, {
      data: { active: false },
      headers: { "x-csrf-token": getSessions()[ALICE_ID].csrf_token },
    });
    expect(r2c.ok()).toBe(true);

    // Create a code with max_uses=1 (will be maxed after one redeem)
    const r3 = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes", {
      code: MAXED_CODE,
      discount_type: "percentage",
      discount_value: 15,
      applies_to: ["shop"],
      max_uses: 1,
      max_uses_per_user: 10,
    });
    expect(r3.ok()).toBe(true);
    maxedCodeId = ((await r3.json()) as { code_id: string }).code_id;

    // Redeem it once so it's maxed out
    const r3b = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes/redeem", {
      code_id: maxedCodeId,
      original_price_cents: 1000,
      final_price_cents: 850,
      checkout_type: "shop",
    });
    expect(r3b.ok()).toBe(true);

    // Create a fixed-amount code ($100 off -- will cap at cart total)
    const r4 = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes", {
      code: FIXED_CODE,
      discount_type: "fixed_amount",
      discount_value: 10000,  // $100
      applies_to: ["shop"],
      max_uses: 0,
      max_uses_per_user: 10,
    });
    expect(r4.ok()).toBe(true);
    fixedCodeId = ((await r4.json()) as { code_id: string }).code_id;
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("1.1 Valid percentage code returns discount", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes/validate", {
      code: VALID_CODE,
      checkout_type: "shop",
      item_price_cents: 5000,
      creator_user_id: ALICE_ID,
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.valid).toBe(true);
    expect(data.discount_type).toBe("percentage");
    expect(data.discount_cents).toBe(1000); // 20% of 5000
    expect(data.final_price_cents).toBe(4000);
    expect(data.code_id).toBe(validCodeId);
  });

  test("1.2 Deactivated code returns invalid with message", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes/validate", {
      code: EXPIRED_CODE,
      checkout_type: "shop",
      item_price_cents: 5000,
      creator_user_id: ALICE_ID,
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.valid).toBe(false);
    expect(data.message).toBeTruthy();
  });

  test("1.3 Code with wrong checkout_type returns invalid", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes/validate", {
      code: VALID_CODE,
      checkout_type: "subscription",
      item_price_cents: 5000,
      creator_user_id: ALICE_ID,
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.valid).toBe(false);
    expect(data.message).toContain("checkout type");
  });

  test("1.4 Code at max uses returns invalid", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes/validate", {
      code: MAXED_CODE,
      checkout_type: "shop",
      item_price_cents: 5000,
      creator_user_id: ALICE_ID,
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.valid).toBe(false);
    expect(data.message).toContain("fully redeemed");
  });

  test("1.5 Fixed amount code caps discount at cart total", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes/validate", {
      code: FIXED_CODE,
      checkout_type: "shop",
      item_price_cents: 5000, // $50 cart, $100 code
      creator_user_id: ALICE_ID,
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.valid).toBe(true);
    expect(data.discount_cents).toBe(5000); // capped at cart total
    expect(data.final_price_cents).toBe(0);
  });
});


// ─────────────────────────────────────────────────────────────────────────────
// Section 2: Checkout with Promo (5 tests)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 2: Checkout with Promo", () => {
  let alicePage: Page;

  const PROMO_CODE = `E2ECHK${TS}`;
  let promoCodeId: string;
  let cartId: string;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);

    // Create a 25% discount promo code for shop
    const r1 = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes", {
      code: PROMO_CODE,
      discount_type: "percentage",
      discount_value: 25,
      applies_to: ["shop"],
      max_uses: 0,
      max_uses_per_user: 10,
    });
    expect(r1.ok()).toBe(true);
    promoCodeId = ((await r1.json()) as { code_id: string }).code_id;

    // Create a cart and add items
    const cartResp = await apiPost(alicePage, ALICE_ID, "/ui/shoppingcart/carts");
    expect(cartResp.ok()).toBe(true);
    cartId = ((await cartResp.json()) as { cart_id: string }).cart_id;

    // Add an item: $50 widget
    const itemResp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/shoppingcart/carts/${cartId}/items`,
      {
        sku: `promo-widget-${TS}`,
        name: `Promo Widget ${TS}`,
        quantity: 2,
        unit_price_cents: 2500,
      },
    );
    expect(itemResp.ok()).toBe(true);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("2.1 Apply valid code shows discount in validation", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes/validate", {
      code: PROMO_CODE,
      checkout_type: "shop",
      item_price_cents: 5000, // 2 x 2500
      creator_user_id: ALICE_ID,
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.valid).toBe(true);
    expect(data.discount_cents).toBe(1250); // 25% of 5000
    expect(data.final_price_cents).toBe(3750);
  });

  test("2.2 Apply invalid code returns error", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes/validate", {
      code: "NONEXISTENT_CODE",
      checkout_type: "shop",
      item_price_cents: 5000,
      creator_user_id: ALICE_ID,
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.valid).toBe(false);
    expect(data.message).toBeTruthy();
  });

  test("2.3 Purchase with promo code applies discount", async () => {
    const idemKey = `promo-purchase-${TS}-${Math.random().toString(36).slice(2, 8)}`;
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/shoppingcart/carts/${cartId}/purchase`,
      { promo_code: PROMO_CODE },
      { "X-Idempotency-Key": idemKey },
    );
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.cart_id).toBe(cartId);
    expect(data.order_id).toBeTruthy();
    expect(data.purchased_total_cents).toBe(3750); // 5000 - 1250
    expect(data.original_total_cents).toBe(5000);
    expect(data.discount_cents).toBe(1250);
    expect(data.promo_code_id).toBe(promoCodeId);
    expect(data.promo_discount_type).toBe("percentage");
  });

  test("2.4 Promo code usage incremented after purchase", async () => {
    const resp = await apiGet(alicePage, `/ui/promo-codes/${promoCodeId}`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.current_uses).toBeGreaterThanOrEqual(1);
  });

  test("2.5 Purchase without promo has no discount fields", async () => {
    // Create a new cart for this test
    const cartResp = await apiPost(alicePage, ALICE_ID, "/ui/shoppingcart/carts");
    expect(cartResp.ok()).toBe(true);
    const newCartId = ((await cartResp.json()) as { cart_id: string }).cart_id;

    // Add an item
    await apiPost(alicePage, ALICE_ID, `/ui/shoppingcart/carts/${newCartId}/items`, {
      sku: `no-promo-widget-${TS}`,
      name: `No Promo Widget ${TS}`,
      quantity: 1,
      unit_price_cents: 3000,
    });

    const idemKey = `no-promo-${TS}-${Math.random().toString(36).slice(2, 8)}`;
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/shoppingcart/carts/${newCartId}/purchase`,
      {},
      { "X-Idempotency-Key": idemKey },
    );
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.purchased_total_cents).toBe(3000);
    expect(data.discount_cents).toBeNull();
    expect(data.promo_code_id).toBeNull();
  });
});


// ─────────────────────────────────────────────────────────────────────────────
// Section 3: Checkout UI (3 tests)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 3: Checkout UI", () => {
  let alicePage: Page;

  const UI_PROMO_CODE = `E2EUI${TS}`;
  let cartId: string;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);

    // Create a 30% promo code for shop
    const r1 = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes", {
      code: UI_PROMO_CODE,
      discount_type: "percentage",
      discount_value: 30,
      applies_to: ["shop"],
      max_uses: 0,
      max_uses_per_user: 10,
    });
    expect(r1.ok()).toBe(true);

    // Create a cart with an item
    const cartResp = await apiPost(alicePage, ALICE_ID, "/ui/shoppingcart/carts");
    expect(cartResp.ok()).toBe(true);
    cartId = ((await cartResp.json()) as { cart_id: string }).cart_id;

    await apiPost(alicePage, ALICE_ID, `/ui/shoppingcart/carts/${cartId}/items`, {
      sku: `ui-test-widget-${TS}`,
      name: `UI Widget ${TS}`,
      quantity: 1,
      unit_price_cents: 10000, // $100
    });
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("3.1 'Have a promo code?' section is expandable", async () => {
    await alicePage.goto(`${BASE}/cart/checkout?cartId=${cartId}`, {
      waitUntil: "domcontentloaded",
    });

    // The promo expand button should be visible
    const expandBtn = alicePage.getByTestId("promo-expand-btn");
    await expect(expandBtn).toBeVisible();

    // Input should not be visible yet
    const promoInput = alicePage.getByTestId("promo-input");
    await expect(promoInput).not.toBeVisible();

    // Click to expand
    await expandBtn.click();

    // Now the input and Apply button should appear
    await expect(promoInput).toBeVisible();
    await expect(alicePage.getByTestId("promo-apply-btn")).toBeVisible();
  });

  test("3.2 Apply valid code shows discount and updates total", async () => {
    await alicePage.goto(`${BASE}/cart/checkout?cartId=${cartId}`, {
      waitUntil: "domcontentloaded",
    });

    // Wait for order summary to load
    await expect(alicePage.getByText("Order Summary")).toBeVisible();

    // Expand promo section
    await alicePage.getByTestId("promo-expand-btn").click();
    const promoInput = alicePage.getByTestId("promo-input");
    await expect(promoInput).toBeVisible();

    // Type promo code
    await promoInput.fill(UI_PROMO_CODE);

    // Click Apply
    await alicePage.getByTestId("promo-apply-btn").click();

    // Wait for success message
    const successMsg = alicePage.getByTestId("promo-success");
    await expect(successMsg).toBeVisible({ timeout: 10000 });
    await expect(successMsg).toContainText("discount");

    // Discount line should be visible
    const discountLine = alicePage.getByTestId("promo-discount-line");
    await expect(discountLine).toBeVisible();

    // Input should be disabled after code is applied
    await expect(promoInput).toBeDisabled();

    // Remove button should be visible
    await expect(alicePage.getByTestId("promo-remove-btn")).toBeVisible();
  });

  test("3.3 Remove applied code restores original total", async () => {
    await alicePage.goto(`${BASE}/cart/checkout?cartId=${cartId}`, {
      waitUntil: "domcontentloaded",
    });

    // Expand and apply promo
    await alicePage.getByTestId("promo-expand-btn").click();
    const promoInput = alicePage.getByTestId("promo-input");
    await promoInput.fill(UI_PROMO_CODE);
    await alicePage.getByTestId("promo-apply-btn").click();
    await expect(alicePage.getByTestId("promo-success")).toBeVisible({ timeout: 10000 });

    // Remove the code
    await alicePage.getByTestId("promo-remove-btn").click();

    // Success message and discount line should disappear
    await expect(alicePage.getByTestId("promo-success")).not.toBeVisible();
    await expect(alicePage.getByTestId("promo-discount-line")).not.toBeVisible();

    // Input should be re-enabled and empty
    await expect(promoInput).toBeEnabled();
    await expect(promoInput).toHaveValue("");
  });
});
