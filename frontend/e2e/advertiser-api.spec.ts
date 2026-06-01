/**
 * E2E tests for the Advertiser API (ADS-011) — /api/v1/ads/*.
 *
 * This is a programmatic, API-key-authenticated API. Requests are made
 * with the global Playwright `request` fixture (NOT page.request) using an
 * `X-API-Key` header, so they authenticate via the API-key path and skip
 * CSRF entirely.
 *
 * Setup:
 *   - Alice (USER) owns an advertiser account (created via session auth).
 *   - Three API keys are minted for Alice via POST /ui/api_keys:
 *       manageKey → ["ads:manage"]  (implies ads:read + ads:serve)
 *       readKey   → ["ads:read"]
 *       serveKey  → ["ads:serve"]
 *
 * Scope model:
 *   ads:manage → full CRUD on campaigns/creatives/budgets
 *   ads:read   → read campaigns/creatives/analytics
 *   ads:serve  → serve-only (cannot read/manage campaigns)
 */

import { test, expect, type Page, type APIRequestContext } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<Record<string, unknown>>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies as never);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

/** Session-auth POST (cookies + CSRF) — used for setup only. */
async function sessionPost(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token, "Content-Type": "application/json" },
  });
}

/** API-key GET via the global request fixture (no cookies → API-key auth). */
function keyGet(request: APIRequestContext, key: string, path: string) {
  return request.get(`${API}${path}`, { headers: { "X-API-Key": key } });
}
function keyPost(request: APIRequestContext, key: string, path: string, body?: object) {
  return request.post(`${API}${path}`, {
    headers: { "X-API-Key": key, "Content-Type": "application/json" },
    data: body ?? {},
  });
}
function keyPatch(request: APIRequestContext, key: string, path: string, body: object) {
  return request.patch(`${API}${path}`, {
    headers: { "X-API-Key": key, "Content-Type": "application/json" },
    data: body,
  });
}
function keyDelete(request: APIRequestContext, key: string, path: string) {
  return request.delete(`${API}${path}`, { headers: { "X-API-Key": key } });
}

let accountId = "";
let manageKey = "";
let readKey = "";
let serveKey = "";

test.beforeAll(async ({ browser }) => {
  const page = await browser.newPage();
  await injectAuth(page, ALICE_ID);

  // Create an advertiser account for Alice.
  const acctResp = await sessionPost(page, "/ui/ads/accounts", {
    company_name: `AdvApiCorp_${TS}`,
    billing_email: `advapi_${TS}@acme.test`,
  });
  expect(acctResp.status()).toBe(201);
  accountId = (await acctResp.json()).account_id;
  expect(accountId).toBeTruthy();

  // Mint three scoped API keys.
  const mint = async (caps: string[]) => {
    const r = await sessionPost(page, "/ui/api_keys", {
      label: `ads_${caps.join("_")}_${TS}`,
      capabilities: caps,
    });
    expect(r.ok()).toBeTruthy();
    return (await r.json()).key_secret as string;
  };
  manageKey = await mint(["ads:manage"]);
  readKey = await mint(["ads:read"]);
  serveKey = await mint(["ads:serve"]);
  expect(manageKey).toContain("ak_");

  await page.close();
});

// ─── Section 388: API Key Scope Enforcement ─────────────────────────

test.describe("388. Advertiser API — scope enforcement", () => {
  test("388.1 ads:manage key can create a campaign", async ({ request }) => {
    const resp = await keyPost(request, manageKey, "/api/v1/ads/campaigns", {
      name: `Camp_${TS}`,
      objective: "awareness",
      budget_cents: 5000,
      budget_type: "daily",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.campaign_id).toBeTruthy();
    expect(data.status).toBe("draft");
  });

  test("388.2 ads:read key cannot create a campaign (403)", async ({ request }) => {
    const resp = await keyPost(request, readKey, "/api/v1/ads/campaigns", {
      name: `CampRead_${TS}`,
      budget_cents: 5000,
    });
    expect(resp.status()).toBe(403);
  });

  test("388.3 ads:read key can list campaigns (200)", async ({ request }) => {
    const resp = await keyGet(request, readKey, "/api/v1/ads/campaigns");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.data)).toBeTruthy();
  });

  test("388.4 ads:serve key cannot list campaigns (403)", async ({ request }) => {
    const resp = await keyGet(request, serveKey, "/api/v1/ads/campaigns");
    expect(resp.status()).toBe(403);
  });

  test("388.5 no API key returns 401", async ({ request }) => {
    const resp = await request.get(`${API}/api/v1/ads/campaigns`);
    expect(resp.status()).toBe(401);
  });

  test("388.6 invalid API key returns 401", async ({ request }) => {
    const resp = await keyGet(request, "ak_deadbeef.notreal", "/api/v1/ads/campaigns");
    expect(resp.status()).toBe(401);
  });
});

// ─── Section 389: Campaign CRUD via API ─────────────────────────────

test.describe("389. Advertiser API — campaign CRUD", () => {
  let campaignId = "";

  test("389.1 create campaign", async ({ request }) => {
    const resp = await keyPost(request, manageKey, "/api/v1/ads/campaigns", {
      name: `CrudCamp_${TS}`,
      objective: "traffic",
      budget_cents: 10000,
      budget_type: "daily",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    campaignId = data.campaign_id;
    expect(campaignId).toBeTruthy();
    expect(data.status).toBe("draft");
  });

  test("389.2 get campaign by id", async ({ request }) => {
    const resp = await keyGet(request, readKey, `/api/v1/ads/campaigns/${campaignId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.campaign_id).toBe(campaignId);
    expect(data.name).toBe(`CrudCamp_${TS}`);
  });

  test("389.3 update campaign name", async ({ request }) => {
    const resp = await keyPatch(request, manageKey, `/api/v1/ads/campaigns/${campaignId}`, {
      name: `CrudCampRenamed_${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.name).toBe(`CrudCampRenamed_${TS}`);
  });

  test("389.4 update campaign budget", async ({ request }) => {
    const resp = await keyPatch(request, manageKey, `/api/v1/ads/campaigns/${campaignId}/budget`, {
      budget_cents: 20000,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Number(data.budget_cents)).toBe(20000);
  });

  test("389.5 bulk archive handles partial failure", async ({ request }) => {
    const resp = await keyPost(request, manageKey, "/api/v1/ads/campaigns/bulk-action", {
      campaign_ids: [campaignId, "camp_doesnotexist"],
      action: "archive",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.success_count).toBe(1);
    expect(data.error_count).toBe(1);
    const ok = data.results.find((r: { campaign_id: string }) => r.campaign_id === campaignId);
    expect(ok.ok).toBe(true);
    expect(ok.status).toBe("archived");
  });

  test("389.6 get on nonexistent campaign returns 404", async ({ request }) => {
    const resp = await keyGet(request, readKey, "/api/v1/ads/campaigns/camp_nope");
    expect(resp.status()).toBe(404);
  });

  test("389.7 invalid create payload returns 422", async ({ request }) => {
    const resp = await keyPost(request, manageKey, "/api/v1/ads/campaigns", {
      name: "",
      budget_cents: 1, // below minimum
    });
    expect(resp.status()).toBe(422);
  });
});

// ─── Section 390: Creatives via API ─────────────────────────────────

test.describe("390. Advertiser API — creatives", () => {
  let campaignId = "";
  let creativeId = "";

  test("390.1 create campaign + creative", async ({ request }) => {
    const camp = await keyPost(request, manageKey, "/api/v1/ads/campaigns", {
      name: `CreativeCamp_${TS}`,
      budget_cents: 5000,
    });
    expect(camp.status()).toBe(201);
    campaignId = (await camp.json()).campaign_id;

    const resp = await keyPost(request, manageKey, "/api/v1/ads/creatives", {
      campaign_id: campaignId,
      format: "image",
      title: `Creative_${TS}`,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    creativeId = data.creative_id;
    expect(creativeId).toBeTruthy();
    expect(data.status).toBe("draft");
  });

  test("390.2 list creatives for campaign", async ({ request }) => {
    const resp = await keyGet(
      request,
      readKey,
      `/api/v1/ads/creatives?campaign_id=${campaignId}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.data.find((c: { creative_id: string }) => c.creative_id === creativeId);
    expect(found).toBeTruthy();
  });

  test("390.3 get + update creative", async ({ request }) => {
    const get = await keyGet(request, readKey, `/api/v1/ads/creatives/${creativeId}`);
    expect(get.status()).toBe(200);

    const upd = await keyPatch(request, manageKey, `/api/v1/ads/creatives/${creativeId}`, {
      title: `CreativeRenamed_${TS}`,
    });
    expect(upd.status()).toBe(200);
    expect((await upd.json()).title).toBe(`CreativeRenamed_${TS}`);
  });

  test("390.4 ads:read key cannot delete creative (403)", async ({ request }) => {
    const resp = await keyDelete(request, readKey, `/api/v1/ads/creatives/${creativeId}`);
    expect(resp.status()).toBe(403);
  });

  test("390.5 ads:manage key deletes creative", async ({ request }) => {
    const resp = await keyDelete(request, manageKey, `/api/v1/ads/creatives/${creativeId}`);
    expect(resp.status()).toBe(200);
    const gone = await keyGet(request, readKey, `/api/v1/ads/creatives/${creativeId}`);
    expect(gone.status()).toBe(404);
  });
});

// ─── Section 391: Analytics & Account ───────────────────────────────

test.describe("391. Advertiser API — analytics & account", () => {
  test("391.1 analytics summary returns metric fields", async ({ request }) => {
    const resp = await keyGet(request, readKey, "/api/v1/ads/analytics/summary?days=30");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data).toHaveProperty("impressions");
    expect(data).toHaveProperty("clicks");
    expect(data).toHaveProperty("spend_cents");
  });

  test("391.2 analytics by-date returns a series array", async ({ request }) => {
    const resp = await keyGet(request, readKey, "/api/v1/ads/analytics/by-date?days=7");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.data)).toBeTruthy();
  });

  test("391.3 analytics with no data returns zeros", async ({ request }) => {
    const resp = await keyGet(request, readKey, "/api/v1/ads/analytics/summary?days=1");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Number(data.impressions)).toBeGreaterThanOrEqual(0);
  });

  test("391.4 get account info with ads:read key", async ({ request }) => {
    const resp = await keyGet(request, readKey, "/api/v1/ads/account");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.account_id).toBe(accountId);
  });

  test("391.5 ads:serve key cannot read account (403)", async ({ request }) => {
    const resp = await keyGet(request, serveKey, "/api/v1/ads/account");
    expect(resp.status()).toBe(403);
  });
});
