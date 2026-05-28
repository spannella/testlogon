import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";
const TS = Date.now();

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon", timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  const qs = params ? "?" + new URLSearchParams(params).toString() : "";
  return page.request.get(`${API}${path}${qs}`);
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await injectAuth(page, identity);
  return page;
}

const ALICE_ID = "alice";

// ─── SHOP-004: Carrier Tracking ─────────────────────────────────────────────

test.describe("81 · Carrier Tracking — Mock tracking API", () => {
  let alicePage: Page;
  const UPS_TRACKING = `TRK_UPS_${TS}`;
  const FEDEX_TRACKING = `TRK_FDX_${TS}`;
  const USPS_TRACKING = `TRK_USPS_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
    // Reset any previously seeded data
    await alicePage.request.post(`${API}/mock/carrier-tracking/reset`);
  });

  test.afterAll(async () => {
    await alicePage.request.post(`${API}/mock/carrier-tracking/reset`);
    await alicePage?.context().close();
  });

  test("81.1 POST seed creates UPS tracking data", async () => {
    const resp = await alicePage.request.post(`${API}/mock/carrier-tracking/seed`, {
      data: {
        carrier: "ups",
        tracking_number: UPS_TRACKING,
        status: "in_transit",
        status_description: "In Transit - On Time",
        estimated_delivery: "2026-06-05",
        events: [
          { timestamp: "2026-05-28T10:00:00Z", description: "Package picked up", location: "New York, NY" },
          { timestamp: "2026-05-28T14:00:00Z", description: "In transit", location: "Philadelphia, PA" },
        ],
      },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.key).toContain("ups:");
  });

  test("81.2 GET tracking returns seeded UPS data", async () => {
    const resp = await alicePage.request.get(`${API}/mock/carrier-tracking/ups/${UPS_TRACKING}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.carrier).toBe("ups");
    expect(body.tracking_number).toBe(UPS_TRACKING);
    expect(body.status).toBe("in_transit");
    expect(body.status_description).toBe("In Transit - On Time");
    expect(body.estimated_delivery).toBe("2026-06-05");
    expect(Array.isArray(body.events)).toBe(true);
    expect(body.events.length).toBe(2);
  });

  test("81.3 POST seed creates FedEx tracking with delivered status", async () => {
    const resp = await alicePage.request.post(`${API}/mock/carrier-tracking/seed`, {
      data: {
        carrier: "fedex",
        tracking_number: FEDEX_TRACKING,
        status: "delivered",
        delivered_at: "2026-05-27T14:30:00Z",
      },
    });
    expect(resp.status()).toBe(200);

    const getResp = await alicePage.request.get(`${API}/mock/carrier-tracking/fedex/${FEDEX_TRACKING}`);
    expect(getResp.status()).toBe(200);
    const body = await getResp.json();
    expect(body.carrier).toBe("fedex");
    expect(body.status).toBe("delivered");
    expect(body.delivered_at).toBe("2026-05-27T14:30:00Z");
  });

  test("81.4 POST seed creates USPS tracking", async () => {
    const resp = await alicePage.request.post(`${API}/mock/carrier-tracking/seed`, {
      data: {
        carrier: "usps",
        tracking_number: USPS_TRACKING,
        status: "out_for_delivery",
      },
    });
    expect(resp.status()).toBe(200);

    const getResp = await alicePage.request.get(`${API}/mock/carrier-tracking/usps/${USPS_TRACKING}`);
    expect(getResp.status()).toBe(200);
    const body = await getResp.json();
    expect(body.carrier).toBe("usps");
    expect(body.status).toBe("out_for_delivery");
  });

  test("81.5 Unknown carrier returns 422", async () => {
    const resp = await alicePage.request.post(`${API}/mock/carrier-tracking/seed`, {
      data: {
        carrier: "nonexistent_carrier",
        tracking_number: "12345",
        status: "in_transit",
      },
    });
    expect(resp.status()).toBe(422);
  });

  test("81.6 Non-existent tracking number returns 404", async () => {
    const resp = await alicePage.request.get(`${API}/mock/carrier-tracking/ups/DOES_NOT_EXIST_999`);
    expect(resp.status()).toBe(404);
  });

  test("81.7 POST reset clears all tracking data", async () => {
    const resetResp = await alicePage.request.post(`${API}/mock/carrier-tracking/reset`);
    expect(resetResp.status()).toBe(200);
    const body = await resetResp.json();
    expect(body.ok).toBe(true);

    // Previously seeded data should be gone
    const resp = await alicePage.request.get(`${API}/mock/carrier-tracking/ups/${UPS_TRACKING}`);
    expect(resp.status()).toBe(404);
  });
});

test.describe("81 · Carrier Tracking — Purchase history integration", () => {
  let alicePage: Page;
  let txnId: string;
  const SHIP_TRACKING = `SHIP_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);

    // Create a purchase transaction
    const s = getSessions()[ALICE_ID];
    const createResp = await alicePage.request.post(`${API}/ui/purchase-history/transactions`, {
      data: {
        money: { amount: 9.99, currency: "usd" },
        description: `TrackWidget_${TS}`,
      },
      headers: {
        "x-csrf-token": s.csrf_token,
        "X-Idempotency-Key": `carrier-track-${TS}`,
      },
    });
    expect(createResp.status()).toBe(200);
    const txnBody = await createResp.json();
    txnId = txnBody.txn_id;
  });

  test.afterAll(async () => {
    await alicePage?.context().close();
  });

  test("81.8 GET tracking returns null when no shipping info", async () => {
    const resp = await apiGet(alicePage, `/ui/purchase-history/transactions/${txnId}/tracking`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.txn_id).toBe(txnId);
    expect(body.tracking_url).toBeNull();
    expect(body.carrier).toBeNull();
    expect(body.tracking_number).toBeNull();
  });

  test("81.9 Tracking URL constructed after shipping update", async () => {
    const s = getSessions()[ALICE_ID];
    // Add shipping info with UPS carrier
    const shipResp = await alicePage.request.put(
      `${API}/ui/purchase-history/transactions/${txnId}/shipping`,
      {
        data: {
          shipping: {
            carrier: "ups",
            tracking_number: SHIP_TRACKING,
            status: "in_transit",
          },
        },
        headers: { "x-csrf-token": s.csrf_token },
      },
    );
    expect(shipResp.status()).toBe(200);

    // Now GET tracking should return a valid URL
    const trackResp = await apiGet(alicePage, `/ui/purchase-history/transactions/${txnId}/tracking`);
    expect(trackResp.status()).toBe(200);
    const body = await trackResp.json();
    expect(body.carrier).toBe("ups");
    expect(body.tracking_number).toBe(SHIP_TRACKING);
    expect(body.tracking_url).toBeTruthy();
    expect(body.tracking_url).toContain("ups.com/track");
    expect(body.tracking_url).toContain(SHIP_TRACKING);
  });
});
