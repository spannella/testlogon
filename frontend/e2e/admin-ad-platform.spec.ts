/**
 * E2E tests for Admin Ad Platform Management (ADS-018).
 *
 * An admin oversight layer over the existing advertiser ad system. Covers:
 *   Section 420 — Cross-user listing API (4 tests)
 *   Section 421 — Account moderation API (4 tests)
 *   Section 422 — Creative moderation API (4 tests)
 *   Section 423 — Platform metrics API (3 tests)
 *   Section 424 — Admin Ad Platform dashboard UI (3 tests)
 *   Section 425 — Emergency Controls / kill-switch UI (GAP-0070) (4 tests)
 *
 * Auth:
 *   Alice (USER)         — advertiser who creates accounts/campaigns/creatives
 *   Charlie (ADMIN)      — platform admin (read + moderation)
 *   Root (ROOT)          — platform admin (also dashboard UI)
 *
 * Sessions created by e2e_admin_session_setup.py (role-bearing JWT cookies).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE       = "http://localhost:3000";
const ALICE_ID   = "alice";
const ROOT_ID    = "root";
const CHARLIE_ID = "charlie_admin";
const TS         = Date.now();

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
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
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
  // Seed the auth-store WITH the real access token so role-aware UI (e.g. the
  // ROOT-only Emergency Controls tab, gated on getRoleFromAccessToken) renders.
  await page.evaluate(
    ({ uid, token }: { uid: string; token: string }) => {
      const state = { userId: uid, accessToken: token, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    { uid: session.user_sub, token: session.access_token },
  );
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

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

// ─── Shared state ─────────────────────────────────────────────────────────────

let alicePage: Page;
let charliePage: Page;
let rootPage: Page;
let accountId: string;       // pending_review account (for moderation)
let approvedAccountId: string;
let campaignId: string;
let creativeId: string;      // pending_review creative (for moderation)

// ─── DDB cleanup helper ───────────────────────────────────────────────────────

// GAP-0039: a user may own at most 5 (non-terminal) ad accounts; POST
// /ui/ads/accounts returns 422 once the cap is hit. E2E runs accumulate ad
// accounts for Alice/Bob across runs (and across specs in the suite), so without
// cleanup the account-creating setup below (which creates TWO accounts for
// Alice) eventually trips the cap (422 → cascading failures). Delete all ad
// accounts owned by the given users (and their campaigns) directly in DDB before
// the run so the create paths always have headroom.
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

// ─── Setup: seed advertiser account / campaign / creative as Alice ──────────────

test.beforeAll(async ({ browser }) => {
  // GAP-0039: wipe accumulated ad accounts so the 5-account cap never blocks
  // the account-creation setup below regardless of suite order.
  ddbDeleteOwnerAccounts(["e2e_alice@test.local", "e2e_bob@test.local"]);

  alicePage = await newIdentityPage(browser, ALICE_ID);
  charliePage = await newIdentityPage(browser, CHARLIE_ID);
  rootPage = await newIdentityPage(browser, ROOT_ID);

  // 1. Pending-review account (moderation target).
  const acct = await apiPost(alicePage, ALICE_ID, "/ui/ads/accounts", {
    company_name: `AdPlatformCo_${TS}`,
    billing_email: `adplat_${TS}@test.local`,
  });
  expect(acct.status()).toBe(201);
  accountId = (await acct.json()).account_id;

  // 2. Approved account so we can create a campaign + creative under it.
  const acct2 = await apiPost(alicePage, ALICE_ID, "/ui/ads/accounts", {
    company_name: `AdPlatformApproved_${TS}`,
    billing_email: `adplat2_${TS}@test.local`,
  });
  expect(acct2.status()).toBe(201);
  approvedAccountId = (await acct2.json()).account_id;

  await apiPost(rootPage, ROOT_ID, `/ui/admin/ads/accounts/${approvedAccountId}/review`, {
    decision: "approve",
    notes: "seed",
  });

  // 3. Campaign under approved account.
  const camp = await apiPost(
    alicePage, ALICE_ID, `/ui/ads/accounts/${approvedAccountId}/campaigns`,
    { name: `AdPlatformCamp_${TS}`, objective: "awareness", budget_cents: 5000, budget_type: "daily" },
  );
  expect(camp.status()).toBe(201);
  campaignId = (await camp.json()).campaign_id;

  // 4. Creative, submitted for review (→ pending_review).
  const cr = await apiPost(
    alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`,
    { format: "image", title: `AdPlatformCreative_${TS}`, alt_text: "test" },
  );
  expect(cr.status()).toBe(201);
  creativeId = (await cr.json()).creative_id;
  await apiPost(
    alicePage, ALICE_ID,
    `/ui/ads/campaigns/${campaignId}/creatives/${creativeId}/submit`,
  );
});

test.afterAll(async () => {
  await alicePage?.close();
  await charliePage?.close();
  await rootPage?.close();
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 420: Cross-user listing API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("420 — Cross-user listing API", () => {
  test("420.1 Admin lists all advertiser accounts across users", async () => {
    const r = await apiGet(charliePage, CHARLIE_ID, "/ui/admin/ad-platform/accounts");
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(Array.isArray(data)).toBe(true);
    expect(data.some((a: { account_id: string }) => a.account_id === accountId)).toBe(true);
  });

  test("420.2 Admin lists all campaigns across users", async () => {
    const r = await apiGet(charliePage, CHARLIE_ID, "/ui/admin/ad-platform/campaigns");
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.some((c: { campaign_id: string }) => c.campaign_id === campaignId)).toBe(true);
  });

  test("420.3 Admin lists all creatives across users", async () => {
    const r = await apiGet(charliePage, CHARLIE_ID, "/ui/admin/ad-platform/creatives");
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.some((c: { creative_id: string }) => c.creative_id === creativeId)).toBe(true);
  });

  test("420.4 Non-admin (USER) cannot list accounts", async () => {
    const r = await apiGet(alicePage, ALICE_ID, "/ui/admin/ad-platform/accounts");
    expect(r.status()).toBe(403);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 421: Account moderation API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("421 — Account moderation API", () => {
  test("421.1 Moderation queue lists pending account", async () => {
    const r = await apiGet(charliePage, CHARLIE_ID, "/ui/admin/ad-platform/moderation/queue");
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.accounts.some((a: { account_id: string }) => a.account_id === accountId)).toBe(true);
  });

  test("421.2 Admin approves account", async () => {
    const r = await apiPost(
      charliePage, CHARLIE_ID, `/ui/admin/ad-platform/accounts/${accountId}/moderate`,
      { action: "approve" },
    );
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.status).toBe("active");
  });

  test("421.3 Moderation history records the approval", async () => {
    const r = await apiGet(
      charliePage, CHARLIE_ID,
      `/ui/admin/ad-platform/moderation/account/${accountId}/history`,
    );
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(Array.isArray(data)).toBe(true);
    expect(data.length).toBeGreaterThanOrEqual(1);
    expect(data[0]).toHaveProperty("action");
  });

  test("421.4 Suspend without reason returns 422", async () => {
    const r = await apiPost(
      charliePage, CHARLIE_ID, `/ui/admin/ad-platform/accounts/${accountId}/moderate`,
      { action: "suspend", reason: "" },
    );
    expect(r.status()).toBe(422);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 422: Creative moderation API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("422 — Creative moderation API", () => {
  test("422.1 Moderation queue lists pending creative", async () => {
    const r = await apiGet(charliePage, CHARLIE_ID, "/ui/admin/ad-platform/moderation/queue");
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.creatives.some((c: { creative_id: string }) => c.creative_id === creativeId)).toBe(true);
  });

  test("422.2 Admin rejects creative with reason", async () => {
    const r = await apiPost(
      charliePage, CHARLIE_ID, `/ui/admin/ad-platform/creatives/${creativeId}/moderate`,
      { action: "reject", reason: "Violates content policy" },
    );
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.status).toBe("rejected");
  });

  test("422.3 Creative moderation history records the rejection", async () => {
    const r = await apiGet(
      charliePage, CHARLIE_ID,
      `/ui/admin/ad-platform/moderation/creative/${creativeId}/history`,
    );
    expect(r.status()).toBe(200);
    const data = await r.json();
    const evt = data.find((e: { action: string }) => e.action === "reject");
    expect(evt).toBeTruthy();
    expect(evt.reason).toBe("Violates content policy");
  });

  test("422.4 Moderate non-existent creative returns 404", async () => {
    const r = await apiPost(
      charliePage, CHARLIE_ID, "/ui/admin/ad-platform/creatives/cr_doesnotexist/moderate",
      { action: "approve" },
    );
    expect(r.status()).toBe(404);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 423: Platform metrics API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("423 — Platform metrics API", () => {
  test("423.1 Admin views platform metrics", async () => {
    const r = await apiGet(charliePage, CHARLIE_ID, "/ui/admin/ad-platform/metrics");
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data).toHaveProperty("total_spend_cents");
    expect(data).toHaveProperty("platform_revenue_cents");
    expect(data.account_count).toBeGreaterThanOrEqual(1);
    expect(data.total_spend_cents).toBeGreaterThanOrEqual(0);
  });

  test("423.2 Revenue series returns an array", async () => {
    const r = await apiGet(charliePage, CHARLIE_ID, "/ui/admin/ad-platform/metrics/revenue-series");
    expect(r.status()).toBe(200);
    expect(Array.isArray(await r.json())).toBe(true);
  });

  test("423.3 Non-admin cannot view metrics", async () => {
    const r = await apiGet(alicePage, ALICE_ID, "/ui/admin/ad-platform/metrics");
    expect(r.status()).toBe(403);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 424: Admin Ad Platform dashboard UI
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("424 — Admin Ad Platform dashboard UI", () => {
  test("424.1 Dashboard loads with revenue tab", async () => {
    await injectAuth(rootPage, ROOT_ID);
    await rootPage.goto(`${BASE}/admin/ad-platform`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByRole("heading", { name: "Ad Platform Management" })).toBeVisible();
    await expect(rootPage.getByRole("tab", { name: "Revenue" })).toBeVisible();
  });

  test("424.2 Moderation tab shows queue", async () => {
    await injectAuth(rootPage, ROOT_ID);
    await rootPage.goto(`${BASE}/admin/ad-platform`, { waitUntil: "domcontentloaded" });
    await rootPage.getByRole("tab", { name: "Moderation" }).click();
    await expect(rootPage.getByText("Pending Accounts", { exact: true })).toBeVisible();
  });

  test("424.3 Accounts tab shows advertiser accounts", async () => {
    await injectAuth(rootPage, ROOT_ID);
    await rootPage.goto(`${BASE}/admin/ad-platform`, { waitUntil: "domcontentloaded" });
    await rootPage.getByRole("tab", { name: "Accounts" }).click();
    await expect(rootPage.getByText("Advertiser Accounts", { exact: true })).toBeVisible();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 425: Emergency Controls / kill-switch UI (GAP-0070)
//
// The ROOT-only "Emergency Controls" tab exposes the platform-wide ad kill switch
// (GAP-0068 backend). These tests assert the UI surface only; the live toggle
// round-trip depends on the GAP-0068 endpoints landing.
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("425 — Emergency Controls / kill-switch UI", () => {
  test("425.1 Emergency Controls tab is present for ROOT", async () => {
    await injectAuth(rootPage, ROOT_ID);
    await rootPage.goto(`${BASE}/admin/ad-platform`, { waitUntil: "domcontentloaded" });
    await expect(
      rootPage.getByRole("tab", { name: /emergency controls/i }),
    ).toBeVisible();
  });

  test("425.2 Kill-switch panel renders with a status badge", async () => {
    await injectAuth(rootPage, ROOT_ID);
    await rootPage.goto(`${BASE}/admin/ad-platform`, { waitUntil: "domcontentloaded" });
    await rootPage.getByRole("tab", { name: /emergency controls/i }).click();
    await expect(rootPage.getByTestId("ks-panel")).toBeVisible();
    await expect(rootPage.getByTestId("ks-status")).toBeVisible();
  });

  test("425.3 Halt button reveals a reason-gated confirmation", async () => {
    await injectAuth(rootPage, ROOT_ID);
    await rootPage.goto(`${BASE}/admin/ad-platform`, { waitUntil: "domcontentloaded" });
    await rootPage.getByRole("tab", { name: /emergency controls/i }).click();

    // Only exercise the halt flow when the switch is currently inactive.
    const statusText = (await rootPage.getByTestId("ks-status").textContent()) ?? "";
    if (/inactive/i.test(statusText)) {
      await rootPage.getByTestId("ks-toggle-btn").click();
      await expect(rootPage.getByTestId("ks-reason-input")).toBeVisible();
      // Confirm is disabled until a reason is supplied.
      await expect(rootPage.getByTestId("ks-confirm-btn")).toBeDisabled();
      await rootPage.getByTestId("ks-reason-input").fill("QA test halt");
      await expect(rootPage.getByTestId("ks-confirm-btn")).toBeEnabled();
    } else {
      // Active: resume flow needs no reason → confirm immediately enabled.
      await rootPage.getByTestId("ks-toggle-btn").click();
      await expect(rootPage.getByTestId("ks-confirm-btn")).toBeEnabled();
    }
  });

  test("425.4 Emergency Controls tab is hidden for non-ROOT admin", async () => {
    await injectAuth(charliePage, CHARLIE_ID);
    await charliePage.goto(`${BASE}/admin/ad-platform`, { waitUntil: "domcontentloaded" });
    await expect(
      charliePage.getByRole("heading", { name: "Ad Platform Management" }),
    ).toBeVisible();
    await expect(
      charliePage.getByRole("tab", { name: /emergency controls/i }),
    ).toHaveCount(0);
  });
});
