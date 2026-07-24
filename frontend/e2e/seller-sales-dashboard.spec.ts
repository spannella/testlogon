/**
 * ECOMX-SELLDASH-E2 — seller sales dashboard (web) + buyer-sees-tracking render.
 *
 * E1 surfaced the seller ship-group tracking INLINE on the buyer order (backend).
 * E2 builds the WEB surfaces:
 *   (1) a seller-scoped dashboard (/seller/sales + /seller/sales/{sg}) that lists
 *       the seller's sold ship groups, shows GMV analytics, and lets the seller
 *       MARK-SHIPPED with a carrier + tracking# from the web; and
 *   (2) the buyer order-detail (/orders/{id}) rendering the E1 inline shipment
 *       (carrier, tracking# link, status, timeline).
 *
 * Live flow (real HTTP seed + real SPA UI): seller (charlie) creates a catalog
 * item; buyer (alice) buys it; seller opens the dashboard, sees the sale, walks
 * it to "packed" via the API, then MARK-SHIPS it from the WEB dialog with a
 * carrier + tracking#; then the buyer opens the order and SEES the carrier /
 * tracking# / status. A 2nd buyer (bob) never sees the tracking (scope).
 */
import { test, expect, type Page, type Browser, type APIRequestContext } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";

const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");
const BASE = "http://localhost:3000";
const TS = Date.now();

const SELLER = "e2e_charlie@test.local";
const BUYER = "e2e_alice@test.local";
const BUYER2 = "e2e_bob@test.local";

interface SessionData {
  user_sub: string; session_id: string; csrf_token: string; access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function sessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}
function csrf(id: string) { return sessions()[id].csrf_token; }

/** New browser page with the identity's cookies + persisted auth-store. */
async function newUiPage(browser: Browser, id: string): Promise<Page> {
  const s = sessions()[id];
  const page = await browser.newPage();
  await page.context().addCookies(s.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    ([userId, accessToken]: [string, string]) => {
      const state = { userId, accessToken, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    [s.user_sub, s.access_token],
  );
  return page;
}

async function post(rq: APIRequestContext, id: string, p: string, body: object, extra: Record<string, string> = {}) {
  return rq.post(`${API}${p}`, { data: body, headers: { "x-csrf-token": csrf(id), ...extra } });
}

test.describe("ECOMX-SELLDASH-E2 · seller dashboard + buyer tracking (web)", () => {
  let sellerPage: Page, buyerPage: Page, buyer2Page: Page;
  const CAT = `e2_cat_${TS}`;
  const ITEM = `e2_item_${TS}`;
  const ITEM_NAME = `E2 Deluxe Widget ${TS}`;
  const TRACK = `1Z999AA1${(TS % 1000000000).toString().padStart(9, "0")}`;
  let orderId = "";
  let shipGroupId = "";

  test.beforeAll(async ({ browser }) => {
    sellerPage = await newUiPage(browser, SELLER);
    buyerPage = await newUiPage(browser, BUYER);
    buyer2Page = await newUiPage(browser, BUYER2);
  });

  test("seed: seller creates a catalog item, buyer buys it", async () => {
    let r = await post(sellerPage.request, SELLER, "/ui/catalog/categories",
      { category_id: CAT, name: `E2 Goods ${TS}`, description: "e2" });
    expect([200, 201, 409]).toContain(r.status());
    r = await post(sellerPage.request, SELLER, `/ui/catalog/categories/${CAT}/items`,
      { item_id: ITEM, name: ITEM_NAME, description: "w", price_cents: 2499, currency: "USD", stock_count: 25 });
    expect([200, 201, 409]).toContain(r.status());

    r = await post(buyerPage.request, BUYER, "/ui/shoppingcart/carts", {});
    expect(r.ok()).toBeTruthy();
    const cartId = (await r.json()).cart_id;
    r = await post(buyerPage.request, BUYER, `/ui/shoppingcart/carts/${cartId}/items/catalog`,
      { category_id: CAT, item_id: ITEM, quantity: 2 });
    expect(r.ok()).toBeTruthy();
    r = await post(buyerPage.request, BUYER, `/ui/shoppingcart/carts/${cartId}/purchase`, {},
      { "X-Idempotency-Key": `e2_${TS}` });
    expect(r.ok()).toBeTruthy();
    orderId = (await r.json()).order_id;
    expect(orderId).toBeTruthy();
  });

  test("seller DASHBOARD lists the sale (GMV + item name + buyer)", async () => {
    await sellerPage.goto(`${BASE}/seller/sales`, { waitUntil: "domcontentloaded" });
    await expect(sellerPage.getByRole("heading", { name: "Seller Dashboard" })).toBeVisible();
    // GMV card renders (analytics wired)
    await expect(sellerPage.getByTestId("seller-gmv")).toBeVisible();
    // the sale row for our item is present, with the real line-item name
    const row = sellerPage.getByTestId("seller-sale-row").filter({ hasText: ITEM_NAME });
    await expect(row).toBeVisible();
    await expect(row).toContainText(/alice/i);
  });

  test("seller opens the sale detail and walks it to packed (API)", async () => {
    // resolve the ship group id off the seller API (dashboard is UI-verified above)
    const r = await sellerPage.request.get(`${API}/ui/seller/sales`);
    const sales = (await r.json()).sales || [];
    const sg = sales.find((s: { order_id: string }) => s.order_id === orderId);
    expect(sg).toBeTruthy();
    shipGroupId = sg.ship_group_id;
    for (const status of ["allocated", "picking", "packed"]) {
      const tr = await post(sellerPage.request, SELLER, `/ui/seller/sales/${shipGroupId}/transition`,
        { target_status: status });
      expect(tr.ok(), `transition ${status}`).toBeTruthy();
    }
  });

  test("seller MARK-SHIPS from the WEB with a carrier + tracking#", async () => {
    await sellerPage.goto(`${BASE}/seller/sales/${shipGroupId}`, { waitUntil: "domcontentloaded" });
    await expect(sellerPage.getByRole("heading", { name: /Sale ·/ })).toBeVisible();
    await sellerPage.getByTestId("mark-shipped-open").click();
    await sellerPage.getByTestId("ship-carrier").fill("ups");
    await sellerPage.getByTestId("ship-tracking").fill(TRACK);
    await sellerPage.getByTestId("ship-confirm").click();
    // after shipping, the tracking number is surfaced on the seller detail
    await expect(sellerPage.getByTestId("seller-tracking-number")).toContainText(TRACK);
  });

  test("BUYER order-detail RENDERS the carrier / tracking# / status", async () => {
    await buyerPage.goto(`${BASE}/orders/${orderId}`, { waitUntil: "domcontentloaded" });
    await expect(buyerPage.getByTestId("order-shipment-tracking")).toBeVisible();
    await expect(buyerPage.getByTestId("shipment-carrier")).toContainText(/ups/i);
    // tracking number is shown (as a link when the carrier URL is present, else plain)
    const link = buyerPage.getByTestId("shipment-tracking-link");
    const plain = buyerPage.getByTestId("shipment-tracking-number");
    if (await link.count()) {
      await expect(link).toContainText(TRACK);
    } else {
      await expect(plain).toContainText(TRACK);
    }
    await expect(buyerPage.getByTestId("shipment-status")).toBeVisible();
  });

  test("SCOPE: a 2nd buyer's order page never shows this tracking", async () => {
    await buyer2Page.goto(`${BASE}/orders/${orderId}`, { waitUntil: "domcontentloaded" });
    // non-owner: 404-degraded detail, and certainly no shipment block
    await expect(buyer2Page.getByTestId("order-shipment-tracking")).toHaveCount(0);
    // API scope guard also holds
    const track = await buyer2Page.request.get(`${API}/ui/orders/${orderId}/tracking`);
    expect(track.status()).toBe(404);
  });
});
