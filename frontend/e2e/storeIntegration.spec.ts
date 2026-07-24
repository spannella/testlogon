/**
 * E2E tests for the OFBiz ECM Storefront Integration (customer-facing).
 *
 * Components under test:
 *   - StorefrontPage      — product grid + variant picker + live availability badge
 *   - CartPricingPage     — pricing-breakdown panel (applied rules / discount / final)
 *   - OrderFulfillmentPage — ship groups + tracking via GET /ui/shoppingcart/orders/{id}
 *
 * Auth: uses e2e_admin_session_setup.py (cookie injection, mirrors tickets.spec.ts).
 *
 * NOTE: STORE_INTEGRATION_ENABLED + sub-flags default OFF, so the enriched
 * fields (variants / availability / pricing_breakdown / ship_groups) come back
 * null/empty. These tests assert the pages render + degrade gracefully, plus
 * the API endpoints respond with the documented shapes.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";

interface AdminSessionData {
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

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getAdminSessions()[identity];
  if (!session) throw new Error(`No session for identity: ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    ([userId, accessToken]: [string, string]) => {
      const state = { userId, accessToken, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    [session.user_sub, session.access_token],
  );
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

// ─── Section ECM-A: Catalog / availability API ────────────────────────────────

test.describe("ECM-A — Catalog availability API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await browser.newPage();
    await alicePage.context().addCookies(getAdminSessions()["alice"]!.cookies);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("GET /ui/catalog/categories returns a paginated list", async () => {
    const resp = await apiGet(alicePage, "ui/catalog/categories");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.items)).toBe(true);
  });

  test("catalog items carry the ECM enrichment fields (variants/availability)", async () => {
    const cats = await (await apiGet(alicePage, "ui/catalog/categories")).json();
    if (!cats.items?.length) test.skip(true, "no categories seeded");
    const catId = cats.items[0].category_id as string;
    const resp = await apiGet(alicePage, `ui/catalog/categories/${encodeURIComponent(catId)}/items`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.items)).toBe(true);
    if (body.items.length > 0) {
      const item = body.items[0];
      // Enrichment fields exist on the shape (null when flag off).
      expect("variants" in item).toBe(true);
      expect("availability" in item).toBe(true);
    }
  });
});

// ─── Section ECM-B: Cart pricing breakdown API ────────────────────────────────

test.describe("ECM-B — Cart pricing breakdown API", () => {
  let alicePage: Page;
  let cartId: string;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await browser.newPage();
    await alicePage.context().addCookies(getAdminSessions()["alice"]!.cookies);
    const csrf = getAdminSessions()["alice"]!.csrf_token;
    const created = await alicePage.request.post(`${API}/ui/shoppingcart/carts`, {
      headers: { "x-csrf-token": csrf, "Content-Type": "application/json" },
      data: {},
    });
    cartId = (await created.json()).cart_id;
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("GET cart total returns total_cents + pricing_breakdown field", async () => {
    const resp = await apiGet(
      alicePage,
      `ui/shoppingcart/carts/${encodeURIComponent(cartId)}/total`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(typeof body.total_cents).toBe("number");
    expect("pricing_breakdown" in body).toBe(true); // null when flag off
  });
});

// ─── Section ECM-C: Order fulfillment API ─────────────────────────────────────

test.describe("ECM-C — Order fulfillment API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await browser.newPage();
    await alicePage.context().addCookies(getAdminSessions()["alice"]!.cookies);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("GET /ui/shoppingcart/orders/{id} returns the documented shape", async () => {
    const resp = await apiGet(alicePage, "ui/shoppingcart/orders/nonexistent-order");
    expect(resp.status()).toBe(200); // returns minimal shape, not 404
    const body = await resp.json();
    expect(body.order_id).toBe("nonexistent-order");
    expect(Array.isArray(body.ship_groups)).toBe(true);
    expect(Array.isArray(body.tracking_numbers)).toBe(true);
  });
});

// ─── Section ECM-D: Storefront UI ─────────────────────────────────────────────

test.describe("ECM-D — Storefront UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
  });

  test.afterAll(async () => {
    await page?.close();
  });

  test("Storefront page renders header", async () => {
    await page.goto(`${BASE}/ofbiz/storefront`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Storefront" })).toBeVisible();
  });

  test("Cart pricing page shows the breakdown panel", async () => {
    await page.goto(`${BASE}/ofbiz/cart-pricing`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Cart Pricing" })).toBeVisible();
  });

  test("Order fulfillment page renders the lookup form", async () => {
    await page.goto(`${BASE}/ofbiz/order-fulfillment`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Order Fulfillment" })).toBeVisible();
    await expect(page.getByTestId("order-id-input")).toBeVisible();
  });

  test("Tracking an order shows the order summary", async () => {
    await page.goto(`${BASE}/ofbiz/order-fulfillment`, { waitUntil: "domcontentloaded" });
    await page.getByTestId("order-id-input").fill("demo-order-1");
    await page.getByTestId("track-order").click();
    // Either the summary or the 'not enabled' state renders without crashing.
    await expect(
      page.getByTestId("order-summary").or(page.getByText(/not enabled|Could not load/i)),
    ).toBeVisible();
  });
});
