/**
 * E2E tests for Ad Targeting Engine (ADS-003).
 *
 * Sections:
 *   350 — Targeting CRUD API (5 tests)
 *   351 — Audience Estimation API (4 tests)
 *   352 — Creator Ad Preferences API (5 tests)
 *   353 — Targeting Editor UI (4 tests)
 *   354 — Input Validation (5 tests)
 *   355 — Concurrent Operations (4 tests)
 *   356 — Authorization Boundary (5 tests)
 *   357 — Creator Ad Settings Edge Cases (4 tests)
 *
 * Prerequisites: ADS-001 (Advertiser Accounts & Campaign Manager) must be deployed.
 *
 * Auth: Cookie-based sessions from e2e_admin_session_setup.py.
 * Test users:
 *   Alice (e2e_alice@test.local)        — advertiser (campaign owner)
 *   Bob   (e2e_bob@test.local)          — creator (ad settings owner)
 *   Root  (root.admin@testdev.local)    — admin (approves accounts)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
// Session keys for e2e_admin_session_setup.py
const ALICE_KEY = "alice";
const BOB_KEY   = "bob";
const ROOT_KEY  = "root";
const ALICE_ID  = "e2e_alice@test.local";
const BOB_ID    = "e2e_bob@test.local";
const ROOT_ID   = "root.admin@testdev.local";
const TS        = Date.now();

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

async function injectAuth(page: Page, sessionKey: string) {
  const session = getSessions()[sessionKey];
  if (!session) throw new Error(`No session for ${sessionKey}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

async function newIdentityPage(browser: Browser, sessionKey: string): Promise<Page> {
  const page = await browser.newPage();
  await injectAuth(page, sessionKey);
  return page;
}

// ─── API helpers (cookie session + CSRF) ──────────────────────────────────────

async function apiPost(page: Page, sessionKey: string, path: string, body: object) {
  const session = getSessions()[sessionKey];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGet(page: Page, sessionKey: string, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiPut(page: Page, sessionKey: string, path: string, body: object) {
  const session = getSessions()[sessionKey];
  return page.request.put(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiPatch(page: Page, sessionKey: string, path: string, body: object) {
  const session = getSessions()[sessionKey];
  return page.request.patch(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiDelete(page: Page, sessionKey: string, path: string) {
  const session = getSessions()[sessionKey];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── Shared state ─────────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;
let rootPage: Page;
let campaignId: string;
let accountId: string;
let targetSetId: string;
let targetSetId2: string;

// ─── DDB cleanup helper ───────────────────────────────────────────────────────

// GAP-0039: a user may own at most 5 (non-terminal) ad accounts; POST
// /ui/ads/accounts returns 422 once the cap is hit. E2E runs accumulate ad
// accounts for Alice/Bob across runs (and across specs in the suite), so without
// cleanup the account-creating setup below eventually trips the cap (422 →
// cascading failures). Delete all ad accounts owned by the given users (and
// their campaigns) directly in DDB before the run so the create paths always
// have headroom.
function ddbDeleteOwnerAccounts(ownerSubs: string[]): void {
  const script = `
import boto3, os
from pathlib import Path
env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
from boto3.dynamodb.conditions import Key
ddb = boto3.resource('dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'),
    region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
accts = ddb.Table('AdAccounts')
camps = ddb.Table('AdCampaigns')
owners = os.environ['OWNER_SUBS'].split(',')
for owner in owners:
    resp = accts.query(IndexName='ByOwner', KeyConditionExpression=Key('owner_sub').eq(owner))
    for item in resp.get('Items', []):
        acct_pk = item['pk']
        cresp = camps.query(KeyConditionExpression=Key('pk').eq(acct_pk))
        for c in cresp.get('Items', []):
            camps.delete_item(Key={'pk': c['pk'], 'sk': c['sk']})
        accts.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
print('ok')
`;
  execSync("python3 -", {
    cwd: REPO_ROOT,
    timeout: 20_000,
    input: script,
    env: { ...process.env, OWNER_SUBS: ownerSubs.join(",") },
  });
}

// ─── Setup ────────────────────────────────────────────────────────────────────

test.beforeAll(async ({ browser }) => {
  // GAP-0039: wipe accumulated ad accounts so the 5-account cap never blocks
  // the account-creation setup below regardless of suite order.
  ddbDeleteOwnerAccounts(["e2e_alice@test.local", "e2e_bob@test.local"]);

  alicePage = await newIdentityPage(browser, ALICE_KEY);
  bobPage = await newIdentityPage(browser, BOB_KEY);
  rootPage = await newIdentityPage(browser, ROOT_KEY);

  // 1. Create an advertiser account for Alice (ADS-001)
  const acctResp = await apiPost(alicePage, ALICE_KEY, "/ui/ads/accounts", {
    company_name: `E2E Ads Co ${TS}`,
    billing_email: "billing@e2e.test",
  });
  expect(acctResp.status()).toBe(201);
  const acct = await acctResp.json();
  accountId = acct.account_id;

  // 2. Admin-approve the account (requires root session)
  const reviewResp = await apiPost(rootPage, ROOT_KEY, `/ui/admin/ads/accounts/${accountId}/review`, {
    decision: "approve",
    notes: "E2E test approval",
  });
  expect(reviewResp.status()).toBe(200);

  // 3. Create a campaign under the account
  const campResp = await apiPost(alicePage, ALICE_KEY, `/ui/ads/accounts/${accountId}/campaigns`, {
    name: `E2E Campaign ${TS}`,
    objective: "awareness",
    budget_cents: 10000,
    budget_type: "daily",
  });
  expect(campResp.status()).toBe(201);
  const camp = await campResp.json();
  campaignId = camp.campaign_id;
});

test.afterAll(async () => {
  await alicePage?.close();
  await bobPage?.close();
  await rootPage?.close();
});

// ─── Section 350: Targeting CRUD API ──────────────────────────────────────────

test.describe("350 — Targeting CRUD API", () => {
  test("350.1 Create targeting set", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting`, {
      name: `US Gamers ${TS}`,
      age_ranges: ["25-34"],
      country_codes: ["US"],
      device_types: ["mobile", "desktop"],
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.target_set_id).toBeTruthy();
    expect(data.campaign_id).toBe(campaignId);
    expect(data.name).toBe(`US Gamers ${TS}`);
    expect(data.age_ranges).toEqual(["25-34"]);
    expect(data.country_codes).toEqual(["US"]);
    expect(data.device_types).toEqual(["mobile", "desktop"]);
    targetSetId = data.target_set_id;
  });

  test("350.2 List targeting sets", async () => {
    const resp = await apiGet(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data)).toBe(true);
    expect(data.length).toBeGreaterThanOrEqual(1);
    const found = data.find((t: { target_set_id: string }) => t.target_set_id === targetSetId);
    expect(found).toBeTruthy();
  });

  test("350.3 Update targeting set", async () => {
    const resp = await apiPut(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting/${targetSetId}`, {
      name: `Updated ${TS}`,
      country_codes: ["US", "CA"],
      age_ranges: ["25-34", "35-44"],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.country_codes).toContain("CA");
    expect(data.age_ranges).toContain("35-44");

    // Verify via GET
    const getResp = await apiGet(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting/${targetSetId}`);
    expect(getResp.status()).toBe(200);
    const getdata = await getResp.json();
    expect(getdata.country_codes).toEqual(expect.arrayContaining(["US", "CA"]));
  });

  test("350.4 Delete targeting set", async () => {
    // Create a temporary targeting set to delete
    const createResp = await apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting`, {
      name: `To Delete ${TS}`,
    });
    const temp = await createResp.json();
    const tempId = temp.target_set_id;

    const delResp = await apiDelete(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting/${tempId}`);
    expect(delResp.status()).toBe(200);

    // Verify it's gone
    const getResp = await apiGet(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting/${tempId}`);
    expect(getResp.status()).toBe(404);
  });

  test("350.5 Create targeting with exclusions", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting`, {
      name: `With Exclusions ${TS}`,
      exclude_creator_ids: ["creator_99"],
      exclude_categories: ["gambling"],
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.exclude_creator_ids).toEqual(["creator_99"]);
    expect(data.exclude_categories).toEqual(["gambling"]);
    targetSetId2 = data.target_set_id;
  });
});

// ─── Section 351: Audience Estimation API ─────────────────────────────────────

test.describe("351 — Audience Estimation API", () => {
  test("351.1 Broad targeting returns large estimate", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting/estimate`, {
      name: "Broad",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.estimated_reach).toBeGreaterThanOrEqual(50000);
  });

  test("351.2 Narrow targeting returns smaller estimate", async () => {
    // First get broad estimate
    const broadResp = await apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting/estimate`, {
      name: "Broad",
    });
    const broad = await broadResp.json();

    // Now narrow
    const narrowResp = await apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting/estimate`, {
      name: "Narrow",
      country_codes: ["US"],
      age_ranges: ["25-34"],
    });
    expect(narrowResp.status()).toBe(200);
    const narrow = await narrowResp.json();
    expect(narrow.estimated_reach).toBeLessThan(broad.estimated_reach);
  });

  test("351.3 Creator-specific targeting returns smallest estimate", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting/estimate`, {
      name: "Creator specific",
      creator_ids: ["single_creator_123"],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.estimated_reach).toBeLessThanOrEqual(1000);
  });

  test("351.4 Estimate returns targeting summary", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting/estimate`, {
      name: "Summary test",
      country_codes: ["US", "GB"],
      device_types: ["mobile"],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.targeting_summary).toBeTruthy();
    expect(data.targeting_summary.country_codes).toEqual(["US", "GB"]);
    expect(data.targeting_summary.device_types).toEqual(["mobile"]);
  });
});

// ─── Section 352: Creator Ad Preferences API ─────────────────────────────────

test.describe("352 — Creator Ad Preferences API", () => {
  test("352.1 Get default ad settings", async () => {
    // Reset to defaults first (previous test runs may have changed settings)
    await apiPatch(bobPage, BOB_KEY, `/ui/ads/creator/ad-settings`, {
      allow_ads: true,
      allowed_ad_categories: [],
      min_cpm_cents: 0,
    });
    const resp = await apiGet(bobPage, BOB_KEY, `/ui/ads/creator/ad-settings`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.allow_ads).toBe(true);
    expect(data.allowed_ad_categories).toEqual([]);
    expect(data.min_cpm_cents).toBe(0);
  });

  test("352.2 Update ad settings — disable ads", async () => {
    const resp = await apiPatch(bobPage, BOB_KEY, `/ui/ads/creator/ad-settings`, {
      allow_ads: false,
    });
    expect(resp.status()).toBe(200);

    const getResp = await apiGet(bobPage, BOB_KEY, `/ui/ads/creator/ad-settings`);
    const data = await getResp.json();
    expect(data.allow_ads).toBe(false);
  });

  test("352.3 Set allowed ad categories", async () => {
    const resp = await apiPatch(bobPage, BOB_KEY, `/ui/ads/creator/ad-settings`, {
      allow_ads: true,
      allowed_ad_categories: ["gaming", "fitness"],
    });
    expect(resp.status()).toBe(200);

    const getResp = await apiGet(bobPage, BOB_KEY, `/ui/ads/creator/ad-settings`);
    const data = await getResp.json();
    expect(data.allowed_ad_categories).toEqual(expect.arrayContaining(["gaming", "fitness"]));
  });

  test("352.4 Block advertiser", async () => {
    const resp = await apiPost(bobPage, BOB_KEY, `/ui/ads/creator/ad-blocks`, {
      account_id: accountId,
      reason: "Competitor brand",
    });
    expect(resp.status()).toBe(200);

    // Check block list
    const listResp = await apiGet(bobPage, BOB_KEY, `/ui/ads/creator/ad-blocks`);
    const blocks = await listResp.json();
    expect(blocks.length).toBeGreaterThanOrEqual(1);
    const found = blocks.find((b: { account_id: string }) => b.account_id === accountId);
    expect(found).toBeTruthy();
    expect(found.reason).toBe("Competitor brand");
  });

  test("352.5 Unblock advertiser", async () => {
    const resp = await apiDelete(bobPage, BOB_KEY, `/ui/ads/creator/ad-blocks/${accountId}`);
    expect(resp.status()).toBe(200);

    // Verify empty block list
    const listResp = await apiGet(bobPage, BOB_KEY, `/ui/ads/creator/ad-blocks`);
    const blocks = await listResp.json();
    const found = blocks.find((b: { account_id: string }) => b.account_id === accountId);
    expect(found).toBeFalsy();
  });
});

// ─── Section 353: Targeting Editor UI ─────────────────────────────────────────

test.describe("353 — Targeting Editor UI", () => {
  test("353.1 Targeting editor shows dimension panels", async () => {
    await alicePage.goto(`${BASE}/ads/targeting`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByTestId("targeting-editor")).toBeVisible();

    // Select existing campaign (campaigns are loaded from the API)
    const campButton = alicePage.getByRole("button", { name: new RegExp(`E2E Campaign ${TS}`) });
    // If campaigns load, click it; otherwise wait
    await expect(campButton).toBeVisible({ timeout: 10000 });
    await campButton.click();

    // Check that dimension sections are visible
    await expect(alicePage.getByText("Demographics")).toBeVisible();
    await expect(alicePage.getByText("Geography")).toBeVisible();
    await expect(alicePage.getByText("Devices")).toBeVisible();
  });

  test("353.2 Age range checkboxes are selectable", async () => {
    await alicePage.goto(`${BASE}/ads/targeting`, { waitUntil: "domcontentloaded" });
    await alicePage.getByRole("button", { name: new RegExp(`E2E Campaign ${TS}`) }).click();

    // Check the 25-34 checkbox
    const checkbox = alicePage.getByTestId("age-25-34");
    await checkbox.click();
    await expect(checkbox).toBeChecked();
  });

  test("353.3 Country multi-select works", async () => {
    await alicePage.goto(`${BASE}/ads/targeting`, { waitUntil: "domcontentloaded" });
    await alicePage.getByRole("button", { name: new RegExp(`E2E Campaign ${TS}`) }).click();

    // Select US and CA
    await alicePage.getByTestId("country-US").click();
    await alicePage.getByTestId("country-CA").click();

    // Both should appear as selected badges
    await expect(alicePage.getByTestId("selected-country-US")).toBeVisible();
    await expect(alicePage.getByTestId("selected-country-CA")).toBeVisible();
  });

  test("353.4 Audience size preview displays", async () => {
    await alicePage.goto(`${BASE}/ads/targeting`, { waitUntil: "domcontentloaded" });
    await alicePage.getByRole("button", { name: new RegExp(`E2E Campaign ${TS}`) }).click();

    // Wait for estimate to load (debounced)
    await expect(alicePage.getByTestId("audience-estimate")).toBeVisible({ timeout: 5000 });
    await expect(alicePage.getByTestId("estimated-reach")).toBeVisible();
    const reachText = await alicePage.getByTestId("estimated-reach").textContent();
    expect(reachText).toBeTruthy();
    // Reach should be a number
    const reach = parseInt(reachText!.replace(/,/g, ""), 10);
    expect(reach).toBeGreaterThan(0);
  });
});

// ─── Section 354: Input Validation ────────────────────────────────────────────

test.describe("354 — Input Validation", () => {
  test("354.1 Invalid age range rejected", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting`, {
      name: "Bad age",
      age_ranges: ["10-15"],
    });
    expect(resp.status()).toBe(422);
  });

  test("354.2 Invalid country code rejected", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting`, {
      name: "Bad country",
      country_codes: ["ZZZ"],
    });
    expect(resp.status()).toBe(422);
  });

  test("354.3 Too many creator IDs rejected", async () => {
    const ids = Array.from({ length: 101 }, (_, i) => `c_${i}`);
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting`, {
      name: "Too many creators",
      creator_ids: ids,
    });
    expect(resp.status()).toBe(422);
  });

  test("354.4 Contradictory creators rejected", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting`, {
      name: "Contradictory",
      creator_ids: ["c1"],
      exclude_creator_ids: ["c1"],
    });
    expect(resp.status()).toBe(422);
  });

  test("354.5 Active hours out of range", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting`, {
      name: "Bad hours",
      active_hours: [25],
    });
    expect(resp.status()).toBe(422);
  });
});

// ─── Section 355: Concurrent Operations ───────────────────────────────────────

test.describe("355 — Concurrent Operations", () => {
  test("355.1 Create two targeting sets simultaneously", async () => {
    const [resp1, resp2] = await Promise.all([
      apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting`, {
        name: `Concurrent A ${TS}`,
        country_codes: ["US"],
      }),
      apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting`, {
        name: `Concurrent B ${TS}`,
        country_codes: ["CA"],
      }),
    ]);
    expect(resp1.status()).toBe(201);
    expect(resp2.status()).toBe(201);

    // Both should appear in the list
    const listResp = await apiGet(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting`);
    const all = await listResp.json();
    const names = all.map((t: { name: string }) => t.name);
    expect(names).toContain(`Concurrent A ${TS}`);
    expect(names).toContain(`Concurrent B ${TS}`);
  });

  test("355.2 Update and delete same set concurrently", async () => {
    // Create a set for this test
    const createResp = await apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting`, {
      name: `Race ${TS}`,
    });
    const raceId = (await createResp.json()).target_set_id;

    const [updateResp, delResp] = await Promise.all([
      apiPut(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting/${raceId}`, {
        name: `Updated Race ${TS}`,
      }),
      apiDelete(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting/${raceId}`),
    ]);
    // At least one should succeed (both return 200 is OK — DDB is eventually consistent)
    const statuses = [updateResp.status(), delResp.status()];
    expect(statuses).toContain(200);
  });

  test("355.3 Estimate with empty targeting", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting/estimate`, {
      name: "Empty",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.estimated_reach).toBeGreaterThanOrEqual(50000);
  });

  test("355.4 Estimate with all dimensions", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/ads/campaigns/${campaignId}/targeting/estimate`, {
      name: "All dimensions",
      country_codes: ["US"],
      age_ranges: ["25-34"],
      genders: ["male"],
      device_types: ["mobile"],
      content_categories: ["gaming"],
      creator_ids: ["single_creator"],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.estimated_reach).toBeLessThan(1000);
  });
});

// ─── Section 356: Authorization Boundary ──────────────────────────────────────

test.describe("356 — Authorization Boundary", () => {
  test("356.1 Non-owner cannot create targeting", async () => {
    const resp = await apiPost(bobPage, BOB_KEY, `/ui/ads/campaigns/${campaignId}/targeting`, {
      name: "Bob targeting",
    });
    expect(resp.status()).toBe(403);
  });

  test("356.2 Non-owner cannot list targeting", async () => {
    const resp = await apiGet(bobPage, BOB_KEY, `/ui/ads/campaigns/${campaignId}/targeting`);
    expect(resp.status()).toBe(403);
  });

  test("356.3 Non-owner cannot update targeting", async () => {
    const resp = await apiPut(bobPage, BOB_KEY, `/ui/ads/campaigns/${campaignId}/targeting/${targetSetId}`, {
      name: "Bob update",
    });
    expect(resp.status()).toBe(403);
  });

  test("356.4 Non-owner cannot delete targeting", async () => {
    const resp = await apiDelete(bobPage, BOB_KEY, `/ui/ads/campaigns/${campaignId}/targeting/${targetSetId}`);
    expect(resp.status()).toBe(403);
  });

  test("356.5 Non-owner cannot estimate audience", async () => {
    const resp = await apiPost(bobPage, BOB_KEY, `/ui/ads/campaigns/${campaignId}/targeting/estimate`, {
      name: "Bob estimate",
    });
    expect(resp.status()).toBe(403);
  });
});

// ─── Section 357: Creator Ad Settings Edge Cases ──────────────────────────────

test.describe("357 — Creator Ad Settings Edge Cases", () => {
  test("357.1 Negative min_cpm rejected", async () => {
    const resp = await apiPatch(bobPage, BOB_KEY, `/ui/ads/creator/ad-settings`, {
      min_cpm_cents: -100,
    });
    expect(resp.status()).toBe(422);
  });

  test("357.2 Invalid ad category rejected", async () => {
    const resp = await apiPatch(bobPage, BOB_KEY, `/ui/ads/creator/ad-settings`, {
      allowed_ad_categories: ["invalid_cat"],
    });
    expect(resp.status()).toBe(422);
  });

  test("357.3 Block already-blocked advertiser is idempotent", async () => {
    const blockBody = { account_id: `idem_${TS}`, reason: "test" };
    const resp1 = await apiPost(bobPage, BOB_KEY, `/ui/ads/creator/ad-blocks`, blockBody);
    expect(resp1.status()).toBe(200);
    const resp2 = await apiPost(bobPage, BOB_KEY, `/ui/ads/creator/ad-blocks`, blockBody);
    expect(resp2.status()).toBe(200);

    // Should only appear once in the list
    const listResp = await apiGet(bobPage, BOB_KEY, `/ui/ads/creator/ad-blocks`);
    const blocks = await listResp.json();
    const matches = blocks.filter((b: { account_id: string }) => b.account_id === `idem_${TS}`);
    expect(matches.length).toBe(1);
  });

  test("357.4 Unblock non-blocked advertiser is idempotent", async () => {
    const resp = await apiDelete(bobPage, BOB_KEY, `/ui/ads/creator/ad-blocks/nonexistent_account`);
    expect(resp.status()).toBe(200);
  });
});
