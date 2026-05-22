/**
 * E2E tests for the Shopping Cart feature.
 *
 * Sections:
 *   89 — Shopping Cart CRUD API (6 tests)
 *   90 — Cart Checkout Flow API (5 tests)
 *
 * Auth: Cookie-based session for Alice (e2e_alice@test.local) with CSRF.
 *
 * Endpoints under test:
 *   POST   /ui/shoppingcart/carts
 *   GET    /ui/shoppingcart/carts
 *   DELETE /ui/shoppingcart/carts/{cart_id}
 *   POST   /ui/shoppingcart/carts/{cart_id}/items
 *   GET    /ui/shoppingcart/carts/{cart_id}/items
 *   PATCH  /ui/shoppingcart/carts/{cart_id}/items/{sku}
 *   DELETE /ui/shoppingcart/carts/{cart_id}/items/{sku}
 *   GET    /ui/shoppingcart/carts/{cart_id}/total
 *   GET    /ui/shoppingcart/carts/items/search
 *   POST   /ui/shoppingcart/carts/{cart_id}/purchase
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

// ─── Session bootstrap ───────────────────────────────────────────────────────

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
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
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
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(
  page: Page,
  path: string,
  body?: object,
  extraHeaders?: Record<string, string>,
) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": session.csrf_token, ...extraHeaders },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

async function apiPatch(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.patch(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiDelete(page: Page, path: string) {
  const session = getSessions()[ALICE_ID];
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── Section 89: Shopping Cart CRUD ──────────────────────────────────────────

test.describe.serial("89 — Shopping Cart CRUD API", () => {
  let page: Page;
  let cartId: string;
  const SKU_A = `sku-a-${TS}`;
  const SKU_B = `sku-b-${TS}`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => {
    // Clean up: delete the cart if it still exists
    if (cartId) {
      await apiDelete(page, `/ui/shoppingcart/carts/${cartId}`).catch(() => {});
    }
    await page.close();
  });

  test("89.1 Create a new cart", async () => {
    const resp = await apiPost(page, "/ui/shoppingcart/carts");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.cart_id).toBeTruthy();
    expect(data.status).toBeTruthy();
    expect(data.created_at).toBeTruthy();
    cartId = data.cart_id;
  });

  test("89.2 List carts includes new cart", async () => {
    const resp = await apiGet(page, "/ui/shoppingcart/carts");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(Array.isArray(data)).toBe(true);
    const found = data.find((c: any) => c.cart_id === cartId);
    expect(found).toBeTruthy();
  });

  test("89.3 Add items to cart", async () => {
    const respA = await apiPost(
      page,
      `/ui/shoppingcart/carts/${cartId}/items`,
      {
        sku: SKU_A,
        name: `Widget A ${TS}`,
        quantity: 2,
        unit_price_cents: 1500,
      },
    );
    expect(respA.ok()).toBe(true);
    const itemA = await respA.json();
    expect(itemA.sku).toBe(SKU_A);
    expect(itemA.quantity).toBe(2);
    expect(itemA.unit_price_cents).toBe(1500);
    expect(itemA.line_total_cents).toBe(3000);

    const respB = await apiPost(
      page,
      `/ui/shoppingcart/carts/${cartId}/items`,
      {
        sku: SKU_B,
        name: `Widget B ${TS}`,
        quantity: 1,
        unit_price_cents: 500,
      },
    );
    expect(respB.ok()).toBe(true);
    const itemB = await respB.json();
    expect(itemB.sku).toBe(SKU_B);
    expect(itemB.line_total_cents).toBe(500);
  });

  test("89.4 List items returns both items", async () => {
    const resp = await apiGet(
      page,
      `/ui/shoppingcart/carts/${cartId}/items`,
    );
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.cart_id).toBe(cartId);
    expect(data.items).toBeInstanceOf(Array);
    expect(data.items.length).toBe(2);
    const skus = data.items.map((i: any) => i.sku);
    expect(skus).toContain(SKU_A);
    expect(skus).toContain(SKU_B);
  });

  test("89.5 Update item quantity via PATCH", async () => {
    const resp = await apiPatch(
      page,
      `/ui/shoppingcart/carts/${cartId}/items/${SKU_A}`,
      { quantity: 5 },
    );
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.sku).toBe(SKU_A);
    expect(data.quantity).toBe(5);
    expect(data.line_total_cents).toBe(7500);
  });

  test("89.6 Remove an item via DELETE (decrement)", async () => {
    const resp = await apiDelete(
      page,
      `/ui/shoppingcart/carts/${cartId}/items/${SKU_B}?decrement=1`,
    );
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.deleted).toBe(true);

    // Verify item B is gone
    const listResp = await apiGet(
      page,
      `/ui/shoppingcart/carts/${cartId}/items`,
    );
    const listData = await listResp.json();
    const found = listData.items.find((i: any) => i.sku === SKU_B);
    expect(found).toBeFalsy();
  });
});

// ─── Section 90: Cart Checkout Flow ──────────────────────────────────────────

test.describe.serial("90 — Cart Checkout Flow API", () => {
  let page: Page;
  let cartId: string;
  const SKU_X = `sku-x-${TS}`;
  const SKU_Y = `sku-y-${TS}`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);

    // Create cart and add items
    const cartResp = await apiPost(page, "/ui/shoppingcart/carts");
    expect(cartResp.ok()).toBe(true);
    const cart = await cartResp.json();
    cartId = cart.cart_id;

    await apiPost(page, `/ui/shoppingcart/carts/${cartId}/items`, {
      sku: SKU_X,
      name: `Checkout Item X ${TS}`,
      quantity: 3,
      unit_price_cents: 1000,
    });
    await apiPost(page, `/ui/shoppingcart/carts/${cartId}/items`, {
      sku: SKU_Y,
      name: `Checkout Item Y ${TS}`,
      quantity: 2,
      unit_price_cents: 2500,
    });
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("90.1 Get cart total", async () => {
    const resp = await apiGet(
      page,
      `/ui/shoppingcart/carts/${cartId}/total`,
    );
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.cart_id).toBe(cartId);
    // 3*1000 + 2*2500 = 8000
    expect(data.total_cents).toBe(8000);
    expect(data.currency).toBe("USD");
  });

  test("90.2 Purchase requires idempotency key", async () => {
    const resp = await apiPost(
      page,
      `/ui/shoppingcart/carts/${cartId}/purchase`,
    );
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail.code).toBe("idempotency_key_required");
  });

  test("90.3 Purchase cart with idempotency key", async () => {
    const idemKey = `idem-${TS}-${Math.random().toString(36).slice(2, 8)}`;
    const resp = await apiPost(
      page,
      `/ui/shoppingcart/carts/${cartId}/purchase`,
      {},
      { "X-Idempotency-Key": idemKey },
    );
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.cart_id).toBe(cartId);
    expect(data.order_id).toBeTruthy();
    expect(data.purchased_at).toBeTruthy();
    expect(data.purchased_total_cents).toBe(8000);
    expect(data.currency).toBe("USD");
  });

  test("90.4 Cart status is purchased after checkout", async () => {
    const resp = await apiGet(page, "/ui/shoppingcart/carts");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    const found = data.find((c: any) => c.cart_id === cartId);
    expect(found).toBeTruthy();
    expect(found.status.toLowerCase()).toBe("purchased");
    expect(found.purchased_at).toBeTruthy();
    expect(found.purchased_total_cents).toBe(8000);
  });

  test("90.5 Delete cart cleans up", async () => {
    const resp = await apiDelete(
      page,
      `/ui/shoppingcart/carts/${cartId}`,
    );
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.deleted).toBe(true);

    // Verify cart is gone from listing
    const listResp = await apiGet(page, "/ui/shoppingcart/carts");
    const listData = await listResp.json();
    const found = listData.find((c: any) => c.cart_id === cartId);
    expect(found).toBeFalsy();
  });
});
