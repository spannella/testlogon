/**
 * ECOMX-E1 — Buyer-visible ship-group tracking (inline discovery join).
 *
 * Regression guard for the deep-pass finding: seller ship groups are
 * SELLER-partitioned, so before E1 the BUYER order LIST + DETAIL surfaced no
 * carrier / tracking# / status (the buyer never had a ship_group_id). E1 joins
 * the seller ship-group tracking INLINE onto the buyer order via the
 * order_fulfillment_bridge, without the buyer needing the ship_group_id, and
 * strictly scoped to the buyer's OWN order.
 *
 * Live flow (real HTTP, no TestClient): seller (charlie) creates a catalog
 * item; buyer (alice) buys it; seller marks the ship group SHIPPED with a
 * carrier + tracking#; then we assert the buyer's:
 *   GET /ui/orders                     (list)      — inline shipment
 *   GET /ui/orders/{id}/lifecycle      (detail)    — inline shipment
 *   GET /ui/shoppingcart/orders/{id}   (ECM-007)   — ship_groups + tracking#
 *   GET /ui/orders/{id}/tracking       (canonical) — carrier/number/status
 * all surface the SAME carrier/number/status, and that a 2nd buyer (bob) sees
 * NONE of it (scope), and delivered -> completed still reconciles.
 */
import { test, expect, type Page, type APIRequestContext } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";

const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");
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

async function ctxFor(page: Page, id: string): Promise<APIRequestContext> {
  await page.context().addCookies(sessions()[id].cookies);
  return page.request;
}
function csrf(id: string) { return sessions()[id].csrf_token; }

async function post(rq: APIRequestContext, id: string, p: string, body: object, extra: Record<string, string> = {}) {
  return rq.post(`${API}${p}`, { data: body, headers: { "x-csrf-token": csrf(id), ...extra } });
}

test.describe("ECOMX-E1 · Buyer-visible ship-group tracking (inline join)", () => {
  let sellerPage: Page, buyerPage: Page, buyer2Page: Page;
  let sRq: APIRequestContext, bRq: APIRequestContext, b2Rq: APIRequestContext;
  const CAT = `e1_cat_${TS}`;
  const ITEM = `e1_item_${TS}`;
  const TRACK = `1Z999AA1${(TS % 1000000000).toString().padStart(9, "0")}`;
  let orderId = "";
  let shipGroupId = "";

  test.beforeAll(async ({ browser }) => {
    sellerPage = await (await browser.newContext()).newPage();
    buyerPage = await (await browser.newContext()).newPage();
    buyer2Page = await (await browser.newContext()).newPage();
    sRq = await ctxFor(sellerPage, SELLER);
    bRq = await ctxFor(buyerPage, BUYER);
    b2Rq = await ctxFor(buyer2Page, BUYER2);
  });

  test("seller creates a catalog item, buyer buys it", async () => {
    let r = await post(sRq, SELLER, "/ui/catalog/categories",
      { category_id: CAT, name: `E1 Goods ${TS}`, description: "e1" });
    expect([200, 201, 409]).toContain(r.status());
    r = await post(sRq, SELLER, `/ui/catalog/categories/${CAT}/items`,
      { item_id: ITEM, name: `E1 Widget ${TS}`, description: "w", price_cents: 1799, currency: "USD", stock_count: 25 });
    expect([200, 201, 409]).toContain(r.status());

    r = await post(bRq, BUYER, "/ui/shoppingcart/carts", {});
    expect(r.ok()).toBeTruthy();
    const cartId = (await r.json()).cart_id;
    r = await post(bRq, BUYER, `/ui/shoppingcart/carts/${cartId}/items/catalog`,
      { category_id: CAT, item_id: ITEM, quantity: 2 });
    expect(r.ok()).toBeTruthy();
    r = await post(bRq, BUYER, `/ui/shoppingcart/carts/${cartId}/purchase`, {},
      { "X-Idempotency-Key": `e1_${TS}` });
    expect(r.ok()).toBeTruthy();
    orderId = (await r.json()).order_id;
    expect(orderId).toBeTruthy();
  });

  test("BEFORE ship: buyer order detail has no carrier/tracking#", async () => {
    const r = await bRq.get(`${API}/ui/orders/${orderId}/lifecycle`, { params: { include: "ship_groups" } });
    expect(r.ok()).toBeTruthy();
    const j = await r.json();
    // not yet shipped: no shipment carries a tracking number.
    for (const s of (j.shipments || [])) expect(s.tracking_number || "").toBe("");
  });

  test("seller ships the ship group with a carrier + tracking#", async () => {
    const r = await sRq.get(`${API}/ui/seller/sales`);
    expect(r.ok()).toBeTruthy();
    const sales = (await r.json()).sales || [];
    const sg = sales.find((s: { order_id: string }) => s.order_id === orderId);
    expect(sg, "seller sees the sale for this order").toBeTruthy();
    shipGroupId = sg.ship_group_id;
    for (const [status, extra] of [
      ["allocated", {}], ["picking", {}], ["packed", {}],
      ["shipped", { tracking_number: TRACK, carrier: "ups" }],
    ] as Array<[string, object]>) {
      const tr = await post(sRq, SELLER, `/ui/seller/sales/${shipGroupId}/transition`,
        { target_status: status, ...extra });
      expect(tr.ok(), `transition ${status}`).toBeTruthy();
    }
  });

  test("AFTER ship: buyer LIST surfaces the carrier + tracking# inline", async () => {
    const r = await bRq.get(`${API}/ui/orders`, { params: { limit: "50" } });
    expect(r.ok()).toBeTruthy();
    const row = ((await r.json()).orders || []).find((o: { order_id: string }) => o.order_id === orderId);
    expect(row, "order present in buyer list").toBeTruthy();
    expect(row.fulfillment_status).toBe("shipped");
    expect(row.shipments?.length).toBeGreaterThan(0);
    const sh = row.shipments[0];
    expect(sh.tracking_number).toBe(TRACK);
    expect((sh.carrier || "").toUpperCase()).toContain("UPS");
    expect(sh.status).toBeTruthy();
    expect(typeof sh.tracking_url).toBe("string");
  });

  test("AFTER ship: buyer DETAIL surfaces the carrier + tracking# inline", async () => {
    const r = await bRq.get(`${API}/ui/orders/${orderId}/lifecycle`, { params: { include: "ship_groups" } });
    expect(r.ok()).toBeTruthy();
    const j = await r.json();
    expect(j.fulfillment_status).toBe("shipped");
    const sh = (j.shipments || []).find((s: { tracking_number: string }) => s.tracking_number === TRACK);
    expect(sh, "detail carries the shipment inline").toBeTruthy();
    expect((sh.carrier || "").toUpperCase()).toContain("UPS");
    expect(sh.last_event).toBeTruthy();
  });

  test("AFTER ship: ECM-007 fulfilment view populates ship_groups + tracking#", async () => {
    const r = await bRq.get(`${API}/ui/shoppingcart/orders/${orderId}`);
    expect(r.ok()).toBeTruthy();
    const j = await r.json();
    expect(j.fulfillment_status).toBe("shipped");
    expect(j.tracking_numbers).toContain(TRACK);
    expect((j.ship_groups || []).length).toBeGreaterThan(0);
  });

  test("canonical /tracking still agrees", async () => {
    const r = await bRq.get(`${API}/ui/orders/${orderId}/tracking`);
    expect(r.ok()).toBeTruthy();
    const j = await r.json();
    expect(j.fulfillment_status).toBe("shipped");
    const sh = (j.shipments || []).find((s: { tracking_number: string }) => s.tracking_number === TRACK);
    expect(sh).toBeTruthy();
  });

  test("SCOPE: a 2nd buyer sees none of it", async () => {
    const detail = await b2Rq.get(`${API}/ui/orders/${orderId}/lifecycle`);
    expect(detail.status()).toBe(404);
    const track = await b2Rq.get(`${API}/ui/orders/${orderId}/tracking`);
    expect(track.status()).toBe(404);
    const ecm = await b2Rq.get(`${API}/ui/shoppingcart/orders/${orderId}`);
    // ECM-007 returns 200 with an EMPTY shape (never another buyer's tracking).
    if (ecm.ok()) {
      const j = await ecm.json();
      expect(j.ship_groups || []).toEqual([]);
      expect(j.tracking_numbers || []).toEqual([]);
    }
  });

  test("delivered -> completed still reconciles", async () => {
    const r = await post(bRq, BUYER, `/ui/orders/${orderId}/confirm-delivery`, {});
    expect(r.ok()).toBeTruthy();
    const j = await r.json();
    expect(j.lifecycle_status).toBe("completed");
    expect(j.fulfillment_status).toBe("delivered");
  });
});
