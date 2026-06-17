/**
 * E2E tests for Promo Code Checkout Integration (SHOP-002) — section 715.
 *
 * Complements e2e/checkout-promo.spec.ts with the integration / security
 * scenarios the ticket calls out that the older spec does not cover:
 *   - server re-computes the discount (a client cannot inject an arbitrary
 *     discount amount — only the *code* is trusted, never a discount value)
 *   - per-user redemption limit enforced across two purchases
 *   - min-purchase rule enforced
 *   - mixed-creator / wrong-creator scope
 *   - auth required on validate + purchase
 *   - the Checkout UI promo preview (apply / error / remove / discounted total)
 *
 * Sections:
 *   715   — Promo Checkout API (validate + purchase + redemption)
 *   715.x — see individual test titles
 *
 * Auth: cookie-based session for Alice (e2e_alice@test.local) with CSRF.
 * Alice is both seller (creates promo codes) and buyer (purchases carts).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();

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
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
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

// ─── API helpers (cookie session + CSRF) ──────────────────────────────────────

function csrf(userId: string): string {
  return getSessions()[userId].csrf_token;
}

async function apiPost(
  page: Page,
  userId: string,
  path: string,
  body?: object,
  extraHeaders?: Record<string, string>,
) {
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": csrf(userId), ...extraHeaders },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

function idem(label: string): Record<string, string> {
  return {
    "X-Idempotency-Key": `${label}-${TS}-${Math.random().toString(36).slice(2, 10)}`,
  };
}

async function createCode(
  page: Page,
  userId: string,
  body: Record<string, unknown>,
): Promise<string> {
  const r = await apiPost(page, userId, "/ui/promo-codes", body);
  expect(r.ok(), `create code ${JSON.stringify(body.code)}: ${await r.text()}`).toBe(true);
  return ((await r.json()) as { code_id: string }).code_id;
}

async function createCartWithItem(
  page: Page,
  userId: string,
  unitPriceCents: number,
  quantity = 1,
): Promise<string> {
  const cartResp = await apiPost(page, userId, "/ui/shoppingcart/carts");
  expect(cartResp.ok()).toBe(true);
  const cartId = ((await cartResp.json()) as { cart_id: string }).cart_id;
  const itemResp = await apiPost(page, userId, `/ui/shoppingcart/carts/${cartId}/items`, {
    sku: `s715-${cartId}`,
    name: `Item ${cartId}`,
    quantity,
    unit_price_cents: unitPriceCents,
  });
  expect(itemResp.ok(), `add item: ${await itemResp.text()}`).toBe(true);
  return cartId;
}

// ─────────────────────────────────────────────────────────────────────────────
// 715 — Promo Checkout API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("715 — Promo Checkout API", () => {
  let alice: Page;

  // Codes (all creator = Alice, applies_to shop)
  const PCT_CODE = `S715PCT${TS}`; // 20% off
  const PERUSER_CODE = `S715ONE${TS}`; // 50% off, max_uses_per_user=1
  const MIN_CODE = `S715MIN${TS}`; // 10% off, min_purchase 10000
  const INJECT_CODE = `S715INJ${TS}`; // 10% off — used for the injection test

  let pctCodeId: string;
  let peruserCodeId: string;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alice = await newIdentityPage(browser, ALICE_ID);

    pctCodeId = await createCode(alice, ALICE_ID, {
      code: PCT_CODE,
      discount_type: "percentage",
      discount_value: 20,
      applies_to: ["shop"],
      max_uses: 0,
      max_uses_per_user: 10,
    });

    peruserCodeId = await createCode(alice, ALICE_ID, {
      code: PERUSER_CODE,
      discount_type: "percentage",
      discount_value: 50,
      applies_to: ["shop"],
      max_uses: 0,
      max_uses_per_user: 1,
    });

    await createCode(alice, ALICE_ID, {
      code: MIN_CODE,
      discount_type: "percentage",
      discount_value: 10,
      applies_to: ["shop"],
      min_purchase_cents: 10000,
      max_uses_per_user: 10,
    });

    await createCode(alice, ALICE_ID, {
      code: INJECT_CODE,
      discount_type: "percentage",
      discount_value: 10,
      applies_to: ["shop"],
      max_uses_per_user: 10,
    });
  });

  test.afterAll(async () => {
    await alice?.close();
  });

  test("715.1 validate returns server-calculated percentage discount", async () => {
    const resp = await apiPost(alice, ALICE_ID, "/ui/promo-codes/validate", {
      code: PCT_CODE,
      checkout_type: "shop",
      item_price_cents: 5000,
      creator_user_id: ALICE_ID,
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.valid).toBe(true);
    expect(data.discount_cents).toBe(1000); // 20% of 5000
    expect(data.final_price_cents).toBe(4000);
    expect(data.code_id).toBe(pctCodeId);
  });

  test("715.2 purchase with promo applies discount + reports both totals", async () => {
    const cartId = await createCartWithItem(alice, ALICE_ID, 5000, 1);
    const resp = await apiPost(
      alice,
      ALICE_ID,
      `/ui/shoppingcart/carts/${cartId}/purchase`,
      { promo_code: PCT_CODE },
      idem("s715-buy"),
    );
    expect(resp.ok(), await resp.text()).toBe(true);
    const data = await resp.json();
    expect(data.purchased_total_cents).toBe(4000);
    expect(data.original_total_cents).toBe(5000);
    expect(data.discount_cents).toBe(1000);
    expect(data.promo_code_id).toBe(pctCodeId);
    expect(data.promo_discount_type).toBe("percentage");
  });

  test("715.3 redemption increments current_uses on the code", async () => {
    // Read current count, purchase once more, confirm it incremented by 1.
    const before = await apiGet(alice, `/ui/promo-codes/${pctCodeId}`);
    expect(before.ok()).toBe(true);
    const beforeUses = ((await before.json()) as { current_uses: number }).current_uses;

    const cartId = await createCartWithItem(alice, ALICE_ID, 3000, 1);
    const buy = await apiPost(
      alice,
      ALICE_ID,
      `/ui/shoppingcart/carts/${cartId}/purchase`,
      { promo_code: PCT_CODE },
      idem("s715-redeem"),
    );
    expect(buy.ok(), await buy.text()).toBe(true);

    const after = await apiGet(alice, `/ui/promo-codes/${pctCodeId}`);
    const afterUses = ((await after.json()) as { current_uses: number }).current_uses;
    expect(afterUses).toBe(beforeUses + 1);
  });

  test("715.4 server recomputes discount — client cannot inject an amount", async () => {
    // The purchase request body only carries the *code*. Even if a malicious
    // client tries to smuggle a discount/total, the backend ignores it and
    // recomputes from the code (10% here), so the real charge is 4500 not 1.
    const cartId = await createCartWithItem(alice, ALICE_ID, 5000, 1);
    const resp = await apiPost(
      alice,
      ALICE_ID,
      `/ui/shoppingcart/carts/${cartId}/purchase`,
      {
        promo_code: INJECT_CODE,
        // bogus client-supplied fields — must be ignored by the server
        discount_cents: 4999,
        purchased_total_cents: 1,
        original_total_cents: 1,
        final_total: 1,
      },
      idem("s715-inject"),
    );
    expect(resp.ok(), await resp.text()).toBe(true);
    const data = await resp.json();
    expect(data.discount_cents).toBe(500); // 10% of 5000, NOT 4999
    expect(data.purchased_total_cents).toBe(4500); // NOT 1
    expect(data.original_total_cents).toBe(5000);
  });

  test("715.5 per-user limit enforced — second purchase is rejected 422", async () => {
    // First purchase succeeds (uses the only per-user redemption).
    const cart1 = await createCartWithItem(alice, ALICE_ID, 4000, 1);
    const first = await apiPost(
      alice,
      ALICE_ID,
      `/ui/shoppingcart/carts/${cart1}/purchase`,
      { promo_code: PERUSER_CODE },
      idem("s715-peruser1"),
    );
    expect(first.ok(), await first.text()).toBe(true);
    expect((await first.json()).discount_cents).toBe(2000); // 50% of 4000

    // Second purchase with the same code by the same user is re-validated and rejected.
    const cart2 = await createCartWithItem(alice, ALICE_ID, 4000, 1);
    const second = await apiPost(
      alice,
      ALICE_ID,
      `/ui/shoppingcart/carts/${cart2}/purchase`,
      { promo_code: PERUSER_CODE },
      idem("s715-peruser2"),
    );
    expect(second.status()).toBe(422);
    const detail = (await second.json()).detail as string;
    expect(detail.toLowerCase()).toContain("already used");

    // Code count should reflect exactly one redemption.
    const stats = await apiGet(alice, `/ui/promo-codes/${peruserCodeId}`);
    expect(((await stats.json()) as { current_uses: number }).current_uses).toBe(1);
  });

  test("715.6 min-purchase rule enforced at validate + purchase", async () => {
    // Cart below the min ($90 < $100 min) — validate says invalid.
    const v = await apiPost(alice, ALICE_ID, "/ui/promo-codes/validate", {
      code: MIN_CODE,
      checkout_type: "shop",
      item_price_cents: 9000,
      creator_user_id: ALICE_ID,
    });
    expect(v.ok()).toBe(true);
    const vData = await v.json();
    expect(vData.valid).toBe(false);
    expect((vData.message as string).toLowerCase()).toContain("minimum purchase");

    // And the purchase itself is rejected 422.
    const cartId = await createCartWithItem(alice, ALICE_ID, 9000, 1);
    const buy = await apiPost(
      alice,
      ALICE_ID,
      `/ui/shoppingcart/carts/${cartId}/purchase`,
      { promo_code: MIN_CODE },
      idem("s715-min"),
    );
    expect(buy.status()).toBe(422);
  });

  test("715.7 wrong-creator code rejected at validate", async () => {
    const resp = await apiPost(alice, ALICE_ID, "/ui/promo-codes/validate", {
      code: PCT_CODE,
      checkout_type: "shop",
      item_price_cents: 5000,
      creator_user_id: BOB_ID, // Alice's code, Bob's creator scope
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.valid).toBe(false);
    expect((data.message as string).toLowerCase()).toContain("creator");
  });

  test("715.8 unknown code at purchase returns 422", async () => {
    const cartId = await createCartWithItem(alice, ALICE_ID, 5000, 1);
    const resp = await apiPost(
      alice,
      ALICE_ID,
      `/ui/shoppingcart/carts/${cartId}/purchase`,
      { promo_code: `NOPE${TS}` },
      idem("s715-nope"),
    );
    expect(resp.status()).toBe(422);
  });

  test("715.9 purchase without a promo works unchanged (backward compatible)", async () => {
    const cartId = await createCartWithItem(alice, ALICE_ID, 3000, 1);
    const resp = await apiPost(
      alice,
      ALICE_ID,
      `/ui/shoppingcart/carts/${cartId}/purchase`,
      {},
      idem("s715-nopromo"),
    );
    expect(resp.ok(), await resp.text()).toBe(true);
    const data = await resp.json();
    expect(data.purchased_total_cents).toBe(3000);
    expect(data.discount_cents).toBeNull();
    expect(data.promo_code_id).toBeNull();
  });

  test("715.10 validate requires auth (no CSRF/session → 401/403)", async ({ request }) => {
    // Global `request` fixture has no session cookies and no CSRF header.
    const resp = await request.post(`${API}/ui/promo-codes/validate`, {
      data: {
        code: PCT_CODE,
        checkout_type: "shop",
        item_price_cents: 5000,
        creator_user_id: ALICE_ID,
      },
    });
    expect([401, 403]).toContain(resp.status());
  });

  test("715.11 purchase requires auth (no session → 401/403)", async ({ request }) => {
    const resp = await request.post(
      `${API}/ui/shoppingcart/carts/does-not-matter/purchase`,
      { data: { promo_code: PCT_CODE }, headers: idem("s715-auth") },
    );
    expect([401, 403]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 715.UI — Checkout promo UI (preview / error / remove / discounted total)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("715 — Checkout promo UI", () => {
  let alice: Page;
  const UI_CODE = `S715UI${TS}`; // 30% off
  let cartId: string;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alice = await newIdentityPage(browser, ALICE_ID);
    await createCode(alice, ALICE_ID, {
      code: UI_CODE,
      discount_type: "percentage",
      discount_value: 30,
      applies_to: ["shop"],
      max_uses_per_user: 10,
    });
    cartId = await createCartWithItem(alice, ALICE_ID, 10000, 1); // $100
  });

  test.afterAll(async () => {
    await alice?.close();
  });

  test("715.12 apply valid code shows green preview + discount line + disabled input", async () => {
    await alice.goto(`${BASE}/cart/checkout?cartId=${cartId}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(alice.getByText("Order Summary")).toBeVisible();

    await alice.getByTestId("promo-expand-btn").click();
    const input = alice.getByTestId("promo-input");
    await expect(input).toBeVisible();
    await input.fill(UI_CODE);
    await alice.getByTestId("promo-apply-btn").click();

    const success = alice.getByTestId("promo-success");
    await expect(success).toBeVisible({ timeout: 10000 });
    await expect(success).toContainText("discount");

    // Discount line item ($30 off $100) + discounted total reflected.
    const line = alice.getByTestId("promo-discount-line");
    await expect(line).toBeVisible();
    await expect(line).toContainText("30.00");
    await expect(alice.getByRole("button", { name: /Place Order/i })).toContainText("70.00");

    await expect(input).toBeDisabled();
    await expect(alice.getByTestId("promo-remove-btn")).toBeVisible();
  });

  test("715.13 invalid code shows red error, no discount line", async () => {
    await alice.goto(`${BASE}/cart/checkout?cartId=${cartId}`, {
      waitUntil: "domcontentloaded",
    });
    await alice.getByTestId("promo-expand-btn").click();
    const input = alice.getByTestId("promo-input");
    await input.fill(`BADCODE${TS}`);
    await alice.getByTestId("promo-apply-btn").click();

    await expect(alice.getByTestId("promo-error")).toBeVisible({ timeout: 10000 });
    await expect(alice.getByTestId("promo-discount-line")).not.toBeVisible();
  });

  test("715.14 remove applied code reverts total + re-enables input", async () => {
    await alice.goto(`${BASE}/cart/checkout?cartId=${cartId}`, {
      waitUntil: "domcontentloaded",
    });
    await alice.getByTestId("promo-expand-btn").click();
    const input = alice.getByTestId("promo-input");
    await input.fill(UI_CODE);
    await alice.getByTestId("promo-apply-btn").click();
    await expect(alice.getByTestId("promo-success")).toBeVisible({ timeout: 10000 });

    await alice.getByTestId("promo-remove-btn").click();
    await expect(alice.getByTestId("promo-success")).not.toBeVisible();
    await expect(alice.getByTestId("promo-discount-line")).not.toBeVisible();
    await expect(input).toBeEnabled();
    await expect(input).toHaveValue("");
    // Total reverts to full price on the Place Order button.
    await expect(alice.getByRole("button", { name: /Place Order/i })).toContainText("100.00");
  });
});
