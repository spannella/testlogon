/**
 * E2E tests for Advertiser Accounts & Campaign Manager (ADS-001).
 *
 * Sections:
 *   340 — Advertiser Account API (5 tests)
 *   341 — Admin Account Review API (4 tests)
 *   342 — Campaign CRUD API (5 tests)
 *   343 — Campaign Lifecycle API (4 tests)
 *   344 — Advertiser Dashboard UI (4 tests)
 *
 * Auth:
 *   Alice (USER) — advertiser who creates accounts + campaigns
 *   Bob (USER)   — second user for ownership isolation tests
 *   Root (ROOT)  — admin who reviews accounts + campaigns
 *
 * Sessions created by e2e_admin_session_setup.py (role-bearing JWT cookies).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "alice";
const BOB_ID   = "bob";
const ROOT_ID  = "root";
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
function getAdminSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, identity: string) {
  const sessions = getAdminSessions();
  const session = sessions[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

// ─── Request helpers ──────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
  });
}

async function apiPatch(page: Page, identity: string, path: string, body: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.patch(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

// ─── DDB cleanup helper ───────────────────────────────────────────────────────

// GAP-0039: a user may own at most 5 (non-terminal) ad accounts; POST
// /ui/ads/accounts returns 422 once the cap is hit. E2E runs accumulate ad
// accounts for Alice/Bob across runs, so without cleanup the account-creating
// tests in this spec eventually trip the cap (422 → cascading 404s). Delete all
// ad accounts owned by the given user (and their campaigns) directly in DDB
// before the run so the API create paths always have headroom.
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
        # Delete this account's campaigns first.
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

// ─── Shared state ─────────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;
let rootPage: Page;
let accountId: string;
let accountId2: string;
let campaignId: string;

// ─── Setup ────────────────────────────────────────────────────────────────────

test.beforeAll(async ({ browser }) => {
  // Wipe accumulated ad accounts for the test users so the 5-account cap
  // (GAP-0039) never blocks the account-creation tests below. Alice/Bob session
  // subs are the email addresses used as owner_sub on the account records.
  ddbDeleteOwnerAccounts(["e2e_alice@test.local", "e2e_bob@test.local"]);

  alicePage = await newIdentityPage(browser, ALICE_ID);
  bobPage = await newIdentityPage(browser, BOB_ID);
  rootPage = await newIdentityPage(browser, ROOT_ID);
});

test.afterAll(async () => {
  await alicePage?.close();
  await bobPage?.close();
  await rootPage?.close();
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 340: Advertiser Account API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("340 — Advertiser Account API", () => {
  test("340.1 Create advertiser account", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/ads/accounts", {
      company_name: `AcmeCorp_${TS}`,
      billing_email: `billing_${TS}@acme.test`,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.account_id).toBeTruthy();
    expect(data.status).toBe("pending_review");
    expect(data.company_name).toBe(`AcmeCorp_${TS}`);
    expect(data.balance_cents).toBe(0);
    accountId = data.account_id;
  });

  test("340.2 List own accounts", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, "/ui/ads/accounts");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data)).toBeTruthy();
    const found = data.find((a: { account_id: string }) => a.account_id === accountId);
    expect(found).toBeTruthy();
  });

  test("340.3 Get account by ID", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/ads/accounts/${accountId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.account_id).toBe(accountId);
    expect(data.company_name).toBe(`AcmeCorp_${TS}`);
  });

  test("340.4 Non-owner cannot access account", async () => {
    const resp = await apiGet(bobPage, BOB_ID, `/ui/ads/accounts/${accountId}`);
    expect(resp.status()).toBe(404);
  });

  test("340.5 Duplicate account creation allowed", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/ads/accounts", {
      company_name: `AcmeCorp2_${TS}`,
      billing_email: `billing2_${TS}@acme.test`,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.account_id).not.toBe(accountId);
    accountId2 = data.account_id;
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 341: Admin Account Review API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("341 — Admin Account Review API", () => {
  test("341.1 List pending accounts", async () => {
    const resp = await apiGet(rootPage, ROOT_ID, "/ui/admin/ads/accounts/pending");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data)).toBeTruthy();
    const found = data.find((a: { account_id: string }) => a.account_id === accountId);
    expect(found).toBeTruthy();
  });

  test("341.2 Approve account", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/ui/admin/ads/accounts/${accountId}/review`, {
      decision: "approve",
      notes: "Looks good",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("active");
  });

  test("341.3 Account status updated after approval", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/ads/accounts/${accountId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("active");
  });

  test("341.4 Reject account", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/ui/admin/ads/accounts/${accountId2}/review`, {
      decision: "reject",
      notes: "Missing information",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("reject");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 342: Campaign CRUD API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("342 — Campaign CRUD API", () => {
  test("342.1 Create campaign", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/ads/accounts/${accountId}/campaigns`, {
      name: `Summer Sale ${TS}`,
      objective: "awareness",
      budget_cents: 5000,
      budget_type: "daily",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.campaign_id).toBeTruthy();
    expect(data.status).toBe("draft");
    expect(data.name).toBe(`Summer Sale ${TS}`);
    expect(data.budget_cents).toBe(5000);
    campaignId = data.campaign_id;
  });

  test("342.2 List campaigns", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/ads/accounts/${accountId}/campaigns`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data)).toBeTruthy();
    const found = data.find((c: { campaign_id: string }) => c.campaign_id === campaignId);
    expect(found).toBeTruthy();
  });

  test("342.3 Get campaign by ID", async () => {
    const resp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/accounts/${accountId}/campaigns/${campaignId}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.campaign_id).toBe(campaignId);
    expect(data.objective).toBe("awareness");
  });

  test("342.4 Update campaign name", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/ads/accounts/${accountId}/campaigns/${campaignId}`,
      { name: `Winter Sale ${TS}` },
    );
    expect(resp.status()).toBe(200);
    // Verify update persisted
    const getResp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/accounts/${accountId}/campaigns/${campaignId}`,
    );
    const data = await getResp.json();
    expect(data.name).toBe(`Winter Sale ${TS}`);
  });

  test("342.5 Update campaign budget", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/ads/accounts/${accountId}/campaigns/${campaignId}`,
      { budget_cents: 10000 },
    );
    expect(resp.status()).toBe(200);
    const getResp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/accounts/${accountId}/campaigns/${campaignId}`,
    );
    const data = await getResp.json();
    expect(Number(data.budget_cents)).toBe(10000);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 343: Campaign Lifecycle API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("343 — Campaign Lifecycle API", () => {
  test("343.1 Submit campaign for review", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/ads/accounts/${accountId}/campaigns/${campaignId}/submit`,
    );
    expect(resp.status()).toBe(200);
    // Verify status changed
    const getResp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/accounts/${accountId}/campaigns/${campaignId}`,
    );
    const data = await getResp.json();
    expect(data.status).toBe("pending_review");
  });

  test("343.2 Admin approve campaign", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/ui/admin/ads/campaigns/${campaignId}/review`, {
      decision: "approve",
      notes: "Campaign approved",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("active");
  });

  test("343.3 Pause active campaign", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/ads/accounts/${accountId}/campaigns/${campaignId}`,
      { status: "paused" },
    );
    expect(resp.status()).toBe(200);
    const getResp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/accounts/${accountId}/campaigns/${campaignId}`,
    );
    const data = await getResp.json();
    expect(data.status).toBe("paused");
  });

  test("343.4 Resume paused campaign", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/ads/accounts/${accountId}/campaigns/${campaignId}`,
      { status: "active" },
    );
    expect(resp.status()).toBe(200);
    const getResp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/accounts/${accountId}/campaigns/${campaignId}`,
    );
    const data = await getResp.json();
    expect(data.status).toBe("active");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 344: Advertiser Dashboard UI
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("344 — Advertiser Dashboard UI", () => {
  test("344.1 Dashboard shows account list", async () => {
    await injectAuth(alicePage, ALICE_ID);
    await alicePage.goto(`${BASE}/ads/dashboard`);
    await expect(alicePage.getByText("Advertiser Dashboard")).toBeVisible();
    await expect(alicePage.getByText(`AcmeCorp_${TS}`)).toBeVisible();
  });

  test("344.2 Create account via dialog", async () => {
    await alicePage.getByRole("button", { name: /Create Advertiser Account/i }).click();
    await expect(alicePage.getByLabel("Company Name")).toBeVisible();
    await alicePage.getByLabel("Company Name").fill(`UITestCo_${TS}`);
    await alicePage.getByLabel("Billing Email").fill(`ui_${TS}@test.local`);
    await alicePage.getByRole("button", { name: /^Create$/i }).click();
    // Wait for dialog to close and new card to appear
    await expect(alicePage.getByText(`UITestCo_${TS}`)).toBeVisible({ timeout: 10000 });
  });

  test("344.3 Campaign list shows campaigns", async () => {
    await alicePage.goto(`${BASE}/ads/campaigns?account=${accountId}`);
    await expect(alicePage.locator("#main-content").getByText("Campaigns", { exact: true })).toBeVisible();
    await expect(alicePage.getByText(`Winter Sale ${TS}`)).toBeVisible({ timeout: 10000 });
  });

  test("344.4 Campaign status badge displays correctly", async () => {
    // The campaign should be "active" from section 343 tests
    await expect(alicePage.locator("#main-content").getByText("active").first()).toBeVisible();
  });
});
