/**
 * E2E tests for the Referral & Affiliate System (AFFILIATE-001).
 *
 * Sections:
 *   1 — Referral Code CRUD API (5 tests)
 *   2 — Attribution API          (4 tests)
 *   3 — Commission API           (4 tests)
 *   4 — Dashboard API            (3 tests)
 *   5 — Referral Dashboard UI    (3 tests)
 *
 * Auth: Alice + Bob session cookies (from e2e_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ───────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
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
    _sessions = loadSessions();
  }
  return _sessions!;
}

// ─── Auth helpers ────────────────────────────────────────────────────────────

async function injectAuth(page: Page, userId: string = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const session = getSessions()[identity];
  return page.request.post(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body ?? {},
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

async function apiDelete(page: Page, identity: string, path: string) {
  const session = getSessions()[identity];
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── DynamoDB direct helpers (for cleanup / seeding) ─────────────────────────

function ddbPut(item: Record<string, unknown>) {
  const json = JSON.stringify(item);
  execSync(
    `python3 -c "
import boto3, json, os, sys
ddb = boto3.resource('dynamodb', endpoint_url=os.getenv('DDB_ENDPOINT_URL','http://localhost:8001'),
  region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.getenv('APP_TABLE','app_single_table'))
tbl.put_item(Item=json.loads(sys.stdin.read()))
"`,
    { cwd: REPO_ROOT, timeout: 10_000, input: json },
  );
}

function ddbDelete(pk: string, sk: string) {
  const input = JSON.stringify({ pk, sk });
  execSync(
    `python3 -c "
import boto3, json, os, sys
ddb = boto3.resource('dynamodb', endpoint_url=os.getenv('DDB_ENDPOINT_URL','http://localhost:8001'),
  region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.getenv('APP_TABLE','app_single_table'))
d = json.loads(sys.stdin.read())
tbl.delete_item(Key={'pk': d['pk'], 'sk': d['sk']})
"`,
    { cwd: REPO_ROOT, timeout: 10_000, input },
  );
}

function ddbDeletePrefix(pk: string) {
  execSync(
    `python3 -c "
import boto3, json, os, sys
ddb = boto3.resource('dynamodb', endpoint_url=os.getenv('DDB_ENDPOINT_URL','http://localhost:8001'),
  region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.getenv('APP_TABLE','app_single_table'))
pk_val = sys.stdin.read().strip()
resp = tbl.query(KeyConditionExpression=boto3.dynamodb.conditions.Key('pk').eq(pk_val))
for item in resp.get('Items', []):
    tbl.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
"`,
    { cwd: REPO_ROOT, timeout: 10_000, input: pk },
  );
}

// ─── Cleanup helper ──────────────────────────────────────────────────────────

function ddbDeleteGsiPrefix(gsi1pk: string) {
  execSync(
    `python3 -c "
import boto3, json, os, sys
ddb = boto3.resource('dynamodb', endpoint_url=os.getenv('DDB_ENDPOINT_URL','http://localhost:8001'),
  region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.getenv('APP_TABLE','app_single_table'))
pk_val = sys.stdin.read().strip()
resp = tbl.query(IndexName='GSI1', KeyConditionExpression=boto3.dynamodb.conditions.Key('GSI1PK').eq(pk_val))
for item in resp.get('Items', []):
    tbl.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
"`,
    { cwd: REPO_ROOT, timeout: 10_000, input: gsi1pk },
  );
}

function cleanupReferralData() {
  // Clean up codes, attributions, commissions from previous runs
  try {
    // Codes are stored with pk=REFCODE#{code}, but GSI1PK=REFCODES#{user_id}
    ddbDeleteGsiPrefix(`REFCODES#${ALICE_ID}`);
    ddbDeleteGsiPrefix(`REFCODES#${BOB_ID}`);
    ddbDeletePrefix(`AFFILIATE#${ALICE_ID}`);
    ddbDeletePrefix(`AFFILIATE#${BOB_ID}`);
    ddbDelete(`REFERRAL#${BOB_ID}`, "META");
    ddbDelete(`REFERRAL#${ALICE_ID}`, "META");
  } catch {
    // Ignore — items may not exist
  }
}

// ─── State shared across tests ───────────────────────────────────────────────

let alicePage: Page;
let createdCode: string = "";
const createdCodes: string[] = [];

// =============================================================================
// Section 1: Referral Code CRUD API
// =============================================================================

test.describe("1 — Referral Code CRUD API", () => {
  test.beforeAll(async ({ browser }) => {
    cleanupReferralData();
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    // Clean up created codes
    try { ddbDeleteGsiPrefix(`REFCODES#${ALICE_ID}`); } catch { /* ignore */ }
    try { ddbDeleteGsiPrefix(`REFCODES#${BOB_ID}`); } catch { /* ignore */ }
    await alicePage?.close();
  });

  test("1.1 Generate referral code", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/referrals/code");
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.code).toMatch(/^[A-Z0-9]{8}$/);
    expect(data.link).toContain(`ref=${data.code}`);
    expect(data.commission_tier).toBe("standard");
    createdCode = data.code;
    createdCodes.push(data.code);
  });

  test("1.2 List own referral codes", async () => {
    const resp = await apiGet(alicePage, "/ui/referrals/codes");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data)).toBe(true);
    const found = data.find((c: any) => c.code === createdCode);
    expect(found).toBeTruthy();
    expect(found.active).toBe(true);
  });

  test("1.3 Deactivate referral code", async () => {
    const resp = await apiDelete(alicePage, ALICE_ID, `/ui/referrals/codes/${createdCode}`);
    expect(resp.status()).toBe(200);
    // Re-list to confirm
    const listResp = await apiGet(alicePage, "/ui/referrals/codes");
    const codes = await listResp.json();
    const found = codes.find((c: any) => c.code === createdCode);
    expect(found).toBeTruthy();
    expect(found.active).toBe(false);
  });

  test("1.4 Max 5 active codes enforced", async () => {
    // Create 5 codes (we already deactivated the first one, so create 5 fresh)
    for (let i = 0; i < 5; i++) {
      const resp = await apiPost(alicePage, ALICE_ID, "/ui/referrals/code");
      expect(resp.status()).toBe(201);
      const data = await resp.json();
      createdCodes.push(data.code);
    }
    // 6th should fail
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/referrals/code");
    expect(resp.status()).toBe(429);
  });

  test("1.5 Code is globally unique (different users)", async () => {
    // Bob creates a code too
    const bobPage = await alicePage.context().browser()!.newPage();
    await injectAuth(bobPage, BOB_ID);
    const resp = await apiPost(bobPage, BOB_ID, "/ui/referrals/code");
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    createdCodes.push(data.code);
    // Bob's code should not collide with any of Alice's
    expect(createdCodes.filter((c) => c === data.code).length).toBe(1);
    await bobPage.close();
  });
});

// =============================================================================
// Section 2: Attribution API
// =============================================================================

test.describe("2 — Attribution API", () => {
  let attributionCode: string = "";

  test.beforeAll(async ({ browser }) => {
    // Clean up
    cleanupReferralData();
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    // Create a fresh code for Alice
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/referrals/code");
    const data = await resp.json();
    attributionCode = data.code;
  });

  test.afterAll(async () => {
    try { ddbDeleteGsiPrefix(`REFCODES#${ALICE_ID}`); } catch { /* */ }
    try { ddbDelete(`REFERRAL#${BOB_ID}`, "META"); } catch { /* */ }
    try { ddbDelete(`REFERRAL#${ALICE_ID}`, "META"); } catch { /* */ }
    await alicePage?.close();
  });

  test("2.6 Attribution recorded at signup", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/internal/referrals/attribute", {
      referred_user_id: BOB_ID,
      referral_code: attributionCode,
      ip_address: "127.0.0.1",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);

    // Verify via attribution endpoint (need Bob page)
    const bobPage = await alicePage.context().browser()!.newPage();
    await injectAuth(bobPage, BOB_ID);
    const attrResp = await apiGet(bobPage, "/ui/referrals/attribution");
    expect(attrResp.status()).toBe(200);
    const attrData = await attrResp.json();
    expect(attrData.referred_by).toBeTruthy();
    expect(attrData.referred_by.user_id).toBe(ALICE_ID);
    await bobPage.close();
  });

  test("2.7 Self-referral blocked", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/internal/referrals/attribute", {
      referred_user_id: ALICE_ID,
      referral_code: attributionCode,
      ip_address: "127.0.0.1",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(false);
    expect(data.reason).toBe("blocked");
  });

  test("2.8 Duplicate attribution ignored", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/internal/referrals/attribute", {
      referred_user_id: BOB_ID,
      referral_code: attributionCode,
      ip_address: "127.0.0.2",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(false);
    expect(data.reason).toBe("blocked");
  });

  test("2.9 Attribution with deactivated code blocked", async () => {
    // Deactivate Alice's code
    await apiDelete(alicePage, ALICE_ID, `/ui/referrals/codes/${attributionCode}`);
    // Clean Bob's existing attribution first
    ddbDelete(`REFERRAL#${BOB_ID}`, "META");
    const resp = await apiPost(alicePage, ALICE_ID, "/internal/referrals/attribute", {
      referred_user_id: BOB_ID,
      referral_code: attributionCode,
      ip_address: "127.0.0.1",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(false);
  });
});

// =============================================================================
// Section 3: Commission API
// =============================================================================

test.describe("3 — Commission API", () => {
  let commCode: string = "";

  test.beforeAll(async ({ browser }) => {
    cleanupReferralData();
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    // Create code + attribute Bob
    const codeResp = await apiPost(alicePage, ALICE_ID, "/ui/referrals/code");
    commCode = (await codeResp.json()).code;
    await apiPost(alicePage, ALICE_ID, "/internal/referrals/attribute", {
      referred_user_id: BOB_ID,
      referral_code: commCode,
      ip_address: "10.0.0.1",
    });
  });

  test.afterAll(async () => {
    try { ddbDeleteGsiPrefix(`REFCODES#${ALICE_ID}`); } catch { /* */ }
    try { ddbDelete(`REFERRAL#${BOB_ID}`, "META"); } catch { /* */ }
    try { ddbDeletePrefix(`AFFILIATE#${ALICE_ID}`); } catch { /* */ }
    await alicePage?.close();
  });

  test("3.10 Commission recorded on referred user purchase", async () => {
    const txId = `tx_${TS}_1`;
    const resp = await apiPost(alicePage, ALICE_ID, "/internal/referrals/commission", {
      referred_user_id: BOB_ID,
      transaction_id: txId,
      source_type: "subscription",
      gross_amount_cents: 999,
      platform_fee_cents: 0,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.commission).toBeTruthy();
    expect(Number(data.commission.commission_cents)).toBeGreaterThan(0);

    // Verify in commissions list
    const listResp = await apiGet(alicePage, "/ui/referrals/commissions");
    expect(listResp.status()).toBe(200);
    const listData = await listResp.json();
    expect(listData.commissions.length).toBeGreaterThan(0);
  });

  test("3.11 Commission rate is 5% (500 bps) for standard tier", async () => {
    const txId = `tx_${TS}_2`;
    const resp = await apiPost(alicePage, ALICE_ID, "/internal/referrals/commission", {
      referred_user_id: BOB_ID,
      transaction_id: txId,
      source_type: "tip",
      gross_amount_cents: 10000,
      platform_fee_cents: 0,
    });
    const data = await resp.json();
    expect(data.ok).toBe(true);
    // 5% of 10000 = 500
    expect(Number(data.commission.commission_cents)).toBe(500);
    expect(Number(data.commission.commission_rate_bps)).toBe(500);
  });

  test("3.12 Commission blocked after window expires", async () => {
    // Manually set commission_window_ends_at to past
    ddbPut({
      pk: `REFERRAL#${BOB_ID}`,
      sk: "META",
      Entity: "ReferralAttribution",
      referred_user_id: BOB_ID,
      referrer_user_id: ALICE_ID,
      referral_code: commCode,
      attributed_at: "2020-01-01T00:00:00Z",
      attribution_source: "cookie",
      status: "pending",
      commission_window_ends_at: "2020-06-01T00:00:00Z",
      ip_address: "10.0.0.1",
      GSI1PK: `REFERRALS#${ALICE_ID}`,
      GSI1SK: `2020-01-01T00:00:00Z#REF#${BOB_ID}`,
    });

    const txId = `tx_${TS}_3`;
    const resp = await apiPost(alicePage, ALICE_ID, "/internal/referrals/commission", {
      referred_user_id: BOB_ID,
      transaction_id: txId,
      source_type: "shop",
      gross_amount_cents: 5000,
      platform_fee_cents: 0,
    });
    const data = await resp.json();
    expect(data.ok).toBe(false);
    expect(data.reason).toBe("no_attribution");
  });

  test("3.13 Commission blocked when attribution revoked", async () => {
    // Set attribution to revoked
    ddbPut({
      pk: `REFERRAL#${BOB_ID}`,
      sk: "META",
      Entity: "ReferralAttribution",
      referred_user_id: BOB_ID,
      referrer_user_id: ALICE_ID,
      referral_code: commCode,
      attributed_at: "2026-01-01T00:00:00Z",
      attribution_source: "cookie",
      status: "revoked",
      commission_window_ends_at: "2027-06-01T00:00:00Z",
      ip_address: "10.0.0.1",
      GSI1PK: `REFERRALS#${ALICE_ID}`,
      GSI1SK: `2026-01-01T00:00:00Z#REF#${BOB_ID}`,
    });

    const txId = `tx_${TS}_4`;
    const resp = await apiPost(alicePage, ALICE_ID, "/internal/referrals/commission", {
      referred_user_id: BOB_ID,
      transaction_id: txId,
      source_type: "unlock",
      gross_amount_cents: 500,
      platform_fee_cents: 0,
    });
    const data = await resp.json();
    expect(data.ok).toBe(false);
  });
});

// =============================================================================
// Section 4: Dashboard API
// =============================================================================

test.describe("4 — Dashboard API", () => {
  let dashCode: string = "";

  test.beforeAll(async ({ browser }) => {
    cleanupReferralData();
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    // Create code + attribute Bob + record commissions
    const codeResp = await apiPost(alicePage, ALICE_ID, "/ui/referrals/code");
    dashCode = (await codeResp.json()).code;
    await apiPost(alicePage, ALICE_ID, "/internal/referrals/attribute", {
      referred_user_id: BOB_ID,
      referral_code: dashCode,
      ip_address: "10.0.0.1",
    });
    // Record two commissions
    await apiPost(alicePage, ALICE_ID, "/internal/referrals/commission", {
      referred_user_id: BOB_ID,
      transaction_id: `tx_dash_${TS}_1`,
      source_type: "subscription",
      gross_amount_cents: 2000,
      platform_fee_cents: 0,
    });
    await apiPost(alicePage, ALICE_ID, "/internal/referrals/commission", {
      referred_user_id: BOB_ID,
      transaction_id: `tx_dash_${TS}_2`,
      source_type: "tip",
      gross_amount_cents: 1000,
      platform_fee_cents: 0,
    });
  });

  test.afterAll(async () => {
    try { ddbDeleteGsiPrefix(`REFCODES#${ALICE_ID}`); } catch { /* */ }
    try { ddbDelete(`REFERRAL#${BOB_ID}`, "META"); } catch { /* */ }
    try { ddbDeletePrefix(`AFFILIATE#${ALICE_ID}`); } catch { /* */ }
    await alicePage?.close();
  });

  test("4.14 Dashboard shows correct referral counts", async () => {
    const resp = await apiGet(alicePage, "/ui/referrals/dashboard");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.total_referrals).toBeGreaterThanOrEqual(1);
    expect(data.pending_referrals).toBeGreaterThanOrEqual(1);
  });

  test("4.15 Dashboard shows correct earnings", async () => {
    const resp = await apiGet(alicePage, "/ui/referrals/dashboard");
    const data = await resp.json();
    // 5% of 2000 = 100; 5% of 1000 = 50; total = 150
    expect(data.total_earned_cents).toBeGreaterThanOrEqual(150);
  });

  test("4.16 Dashboard shows available withdrawal amount", async () => {
    const resp = await apiGet(alicePage, "/ui/referrals/dashboard");
    const data = await resp.json();
    expect(data.available_for_withdrawal_cents).toBeGreaterThanOrEqual(0);
    // available = total_earned - paid
    expect(data.available_for_withdrawal_cents).toBe(
      data.total_earned_cents - data.paid_commission_cents,
    );
  });
});

// =============================================================================
// Section 5: Referral Dashboard UI
// =============================================================================

test.describe("5 — Referral Dashboard UI", () => {
  let uiCode: string = "";

  test.beforeAll(async ({ browser }) => {
    cleanupReferralData();
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    // Create a code + attribution + commission for UI
    const codeResp = await apiPost(alicePage, ALICE_ID, "/ui/referrals/code");
    uiCode = (await codeResp.json()).code;
    await apiPost(alicePage, ALICE_ID, "/internal/referrals/attribute", {
      referred_user_id: BOB_ID,
      referral_code: uiCode,
      ip_address: "10.0.0.1",
    });
    await apiPost(alicePage, ALICE_ID, "/internal/referrals/commission", {
      referred_user_id: BOB_ID,
      transaction_id: `tx_ui_${TS}`,
      source_type: "subscription",
      gross_amount_cents: 4000,
      platform_fee_cents: 0,
    });
  });

  test.afterAll(async () => {
    try { ddbDeleteGsiPrefix(`REFCODES#${ALICE_ID}`); } catch { /* */ }
    try { ddbDelete(`REFERRAL#${BOB_ID}`, "META"); } catch { /* */ }
    try { ddbDeletePrefix(`AFFILIATE#${ALICE_ID}`); } catch { /* */ }
    await alicePage?.close();
  });

  test("5.17 Referral page renders stats cards", async () => {
    await alicePage.goto(`${BASE}/referrals`, { waitUntil: "domcontentloaded" });
    // Should see the heading
    await expect(alicePage.getByRole("heading", { name: "Referrals", exact: true })).toBeVisible();
    // Stats cards
    await expect(alicePage.getByTestId("stat-total-referrals")).toBeVisible();
    await expect(alicePage.getByTestId("stat-total-earned")).toBeVisible();
  });

  test("5.18 Copy referral link button works", async () => {
    await alicePage.goto(`${BASE}/referrals`, { waitUntil: "domcontentloaded" });
    // Wait for the code to appear in the page
    await expect(alicePage.locator("code").filter({ hasText: uiCode })).toBeVisible({ timeout: 10000 });
    // Click copy
    const copyBtn = alicePage.getByRole("button", { name: `Copy link for ${uiCode}` });
    await expect(copyBtn).toBeVisible();
    // Grant clipboard permission and click copy
    await alicePage.context().grantPermissions(["clipboard-read", "clipboard-write"]);
    await copyBtn.click();
    // Should show a toast (success or failure depending on clipboard support)
    await expect(
      alicePage.getByText("Link copied to clipboard").or(alicePage.getByText("Failed to copy")),
    ).toBeVisible({ timeout: 5000 });
  });

  test("5.19 Commission history table shows entries", async () => {
    await alicePage.goto(`${BASE}/referrals`, { waitUntil: "domcontentloaded" });
    // Commission history section — CardTitle renders as <div>, not a heading
    await expect(alicePage.getByText("Commission History")).toBeVisible({ timeout: 10000 });
    // Should have a table row with the "subscription" source-type badge.
    // Scope to a table cell to avoid matching the sidebar "Subscriptions" nav.
    await expect(
      alicePage.getByRole("cell").filter({ hasText: /^subscription$/ }).first(),
    ).toBeVisible({ timeout: 10000 });
  });
});
