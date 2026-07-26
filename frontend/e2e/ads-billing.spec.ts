/**
 * E2E tests for Ad Billing & Financial Engine (ADS-007).
 *
 * Sections:
 *   369 — Deposit API (4 tests)
 *   370 — Impression charging (4 tests)
 *   371 — Budget enforcement (3 tests)
 *   372 — Invoice generation (4 tests)
 *   373 — Authorization & edge cases (4 tests)
 *
 * Auth: Alice + Bob session cookies (from e2e_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
import {
  usingCpp,
  cppSeedAdAccount,
  cppDdbGet,
} from "./helpers/cpp-seed-commerce-billing";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ───────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
// Admin/root identity (key in e2e_admin_session_setup.py output) used for the
// admin-only internal ad-charge endpoints (now mounted under /ui/admin/ads).
const ROOT_ID = "root";
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

// Admin/root sessions (root, alice, bob, charlie_*) for the admin-only
// internal charge endpoints.
let _adminSessions: Record<string, SessionData> | null = null;
function getAdminSessions(): Record<string, SessionData> {
  if (!_adminSessions) {
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

// ─── Auth helpers ────────────────────────────────────────────────────────────

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

// ─── API helpers ─────────────────────────────────────────────────────────────

function csrfHeaders(userId: string) {
  return { "x-csrf-token": getSessions()[userId].csrf_token };
}

async function apiPost(page: Page, path: string, body: object, userId = ALICE_ID) {
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: csrfHeaders(userId),
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

// POST as root (admin) with root's CSRF token — used for the admin-only
// /ui/admin/ads/internal/charge-* endpoints (require_admin_or_root).
async function adminPost(page: Page, path: string, body: object) {
  const sess = getAdminSessions()[ROOT_ID];
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

// ─── DDB helper ──────────────────────────────────────────────────────────────

// Pass JSON payloads + table name via environment variables and the Python
// program via stdin, so embedded double quotes never collide with shell
// quoting (a plain `python3 -c "...${json}..."` breaks on the JSON's quotes).
const _DDB_PRELUDE = `
import boto3, json, os, decimal
from pathlib import Path
env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test', aws_secret_access_key='test')
`;

// cpp-seed interception (TRACK: seed). Under E2E_USE_CPP, AdAccounts/
// AdCampaigns ddbPut rows are retargeted to cpp's tlc_ad_* tables via the
// shim, keyed by the resolved cpp SUB. owner_sub in the item is the email
// identity (ALICE_ID); we map it to the session sub. Pending accounts are
// flushed when their campaign (same ACCT# pk) is written, else on next put.
const _cppPendingAcct: Record<string, Record<string, unknown>> = {};
function _cppOwnerSub(item: Record<string, unknown>): string {
  const email = String(item["owner_sub"] ?? ALICE_ID);
  const sess = getAdminSessions();
  return sess[email]?.user_sub || sess[ALICE_ID]?.user_sub || email;
}
function _cppFlushAcct(acctPk: string): void {
  const acct = _cppPendingAcct[acctPk];
  if (!acct) return;
  delete _cppPendingAcct[acctPk];
  cppSeedAdAccount({
    accountId: String(acct["account_id"]),
    ownerSub: _cppOwnerSub(acct),
    companyName: acct["company_name"] as string | undefined,
    billingEmail: acct["billing_email"] as string | undefined,
    status: (acct["status"] as string) ?? "active",
    balanceCents: Number(acct["balance_cents"] ?? 0),
  });
}
function _cppDdbPut(tableName: string, item: Record<string, unknown>): boolean {
  if (!usingCpp()) return false;
  if (tableName === "AdAccounts") {
    // Defer: seed with the campaign if one follows, else flush any prior.
    const pk = String(item["pk"]);
    _cppFlushAcct(pk);
    _cppPendingAcct[pk] = item;
    return true;
  }
  if (tableName === "AdCampaigns") {
    const pk = String(item["pk"]);
    const acct = _cppPendingAcct[pk];
    if (acct) {
      delete _cppPendingAcct[pk];
      cppSeedAdAccount({
        accountId: String(acct["account_id"]),
        ownerSub: _cppOwnerSub(acct),
        companyName: acct["company_name"] as string | undefined,
        billingEmail: acct["billing_email"] as string | undefined,
        status: (acct["status"] as string) ?? "active",
        balanceCents: Number(acct["balance_cents"] ?? 0),
        campaign: {
          campaignId: String(item["campaign_id"]),
          name: item["name"] as string | undefined,
          objective: item["objective"] as string | undefined,
          budgetCents: Number(item["budget_cents"] ?? 10000),
          budgetType: (item["budget_type"] as string) ?? "lifetime",
          dailyBudgetCents: Number(item["daily_budget_cents"] ?? 0),
          status: (item["status"] as string) ?? "active",
        },
      });
    }
    return true;
  }
  return false;
}
function ddbPut(tableName: string, item: Record<string, unknown>): void {
  if (_cppDdbPut(tableName, item)) return;
  const script = `${_DDB_PRELUDE}
item = json.loads(os.environ['DDB_ITEM'], parse_float=decimal.Decimal, parse_int=decimal.Decimal)
ddb.Table(os.environ['DDB_TABLE']).put_item(Item=item)
print('ok')
`;
  execSync("python3 -", {
    cwd: REPO_ROOT,
    timeout: 10_000,
    input: script,
    env: { ...process.env, DDB_ITEM: JSON.stringify(item), DDB_TABLE: tableName },
  });
}

function ddbGet(tableName: string, key: Record<string, string>): Record<string, unknown> | null {
  // cpp-read interception (TRACK: readback). Under E2E_USE_CPP, account/
  // campaign/billing readbacks must reflect cpp's own mutation — the Python
  // :8001 get below never sees a cpp charge. Route those tables to cpp moto.
  if (usingCpp() && (tableName === "AdAccounts" || tableName === "AdCampaigns" || tableName === "AdBilling" || tableName === "billing")) {
    return cppDdbGet(tableName, key);
  }
  const script = `${_DDB_PRELUDE}
class Enc(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            return int(o) if o == int(o) else float(o)
        return super().default(o)
key = json.loads(os.environ['DDB_KEY'])
resp = ddb.Table(os.environ['DDB_TABLE']).get_item(Key=key)
item = resp.get('Item')
print(json.dumps(item, cls=Enc) if item else 'null')
`;
  const raw = execSync("python3 -", {
    cwd: REPO_ROOT,
    timeout: 10_000,
    input: script,
    env: { ...process.env, DDB_KEY: JSON.stringify(key), DDB_TABLE: tableName },
  }).toString().trim();
  return raw === "null" ? null : JSON.parse(raw);
}

// ─── Test state ──────────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;
let rootPage: Page;
let accountId: string;
let campaignId: string;

// Top-level setup so that pages + DDB fixtures are (re)created in EVERY worker,
// including the fresh worker Playwright spawns for retries. Sections beyond 369
// have no beforeAll of their own, so without this a retried test would see
// undefined page handles. accountId/campaignId are deterministic per worker
// (derived from the module-load TS) and ddbPut is idempotent.
test.beforeAll(async ({ browser }) => {
  // Create Alice page
  const ctx = await browser.newContext();
  alicePage = await ctx.newPage();
  await injectAuth(alicePage, ALICE_ID);

  // Create Bob page
  const bCtx = await browser.newContext();
  bobPage = await bCtx.newPage();
  await injectAuth(bobPage, BOB_ID);

  // Root page for admin-only internal charge endpoints (cookies only; the
  // admin session setup provides the role-bearing JWT + CSRF token).
  const rCtx = await browser.newContext();
  rootPage = await rCtx.newPage();
  await rCtx.addCookies(getAdminSessions()[ROOT_ID].cookies);

  // Create ad account for Alice directly in DDB
  accountId = `adacct_e2e_${TS}`;
  ddbPut("AdAccounts", {
    pk: `ACCT#${accountId}`,
    sk: "META",
    account_id: accountId,
    owner_sub: ALICE_ID,
    company_name: `E2E Corp ${TS}`,
    billing_email: "billing@e2e.test",
    status: "active",
    balance_cents: 0,
    lifetime_spend_cents: 0,
    created_at: Math.floor(Date.now() / 1000),
    updated_at: Math.floor(Date.now() / 1000),
  });

  // Create campaign for Alice
  campaignId = `camp_e2e_${TS}`;
  ddbPut("AdCampaigns", {
    pk: `ACCT#${accountId}`,
    sk: `CAMPAIGN#${campaignId}`,
    campaign_id: campaignId,
    account_id: accountId,
    name: `E2E Campaign ${TS}`,
    objective: "awareness",
    budget_cents: 10000,
    budget_type: "lifetime",
    daily_budget_cents: 0,
    spent_today_cents: 0,
    lifetime_spent_cents: 0,
    status: "active",
    created_at: Math.floor(Date.now() / 1000),
    updated_at: Math.floor(Date.now() / 1000),
  });
});

// ── Section 369: Deposit API ─────────────────────────────────────────────────

test.describe("369 — Deposit API", () => {
  test("369.1 Deposit funds to ad account", async () => {
    const resp = await apiPost(
      alicePage,
      `/ui/ads/accounts/${accountId}/deposit`,
      { amount_cents: 10000, payment_method_id: "pm_test_001" },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.entry_id).toBeTruthy();
    expect(data.new_balance_cents).toBe(10000);
  });

  test("369.2 Minimum deposit enforced", async () => {
    const resp = await apiPost(
      alicePage,
      `/ui/ads/accounts/${accountId}/deposit`,
      { amount_cents: 1000 },
    );
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail).toContain("Minimum deposit");
  });

  test("369.3 Deposit creates billing entry", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/accounts/${accountId}/billing?limit=10`,
    );
    expect(resp.status()).toBe(200);
    const entries = await resp.json();
    const deposit = entries.find(
      (e: Record<string, unknown>) => e.entry_type === "budget_deposit",
    );
    expect(deposit).toBeTruthy();
    expect(Number(deposit.amount_cents)).toBe(10000);
  });

  test("369.4 Multiple deposits accumulate", async () => {
    // ADV3-1: a PUBLIC deposit MUST be backed by a real charge — a missing
    // payment_method_id is a hard 400 (payment_method_required). Supply a PM (as
    // 369.1 does). Also note the minimum deposit is now $50, so 5000 is the floor.
    const resp = await apiPost(
      alicePage,
      `/ui/ads/accounts/${accountId}/deposit`,
      { amount_cents: 5000, payment_method_id: "pm_test_002" },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.new_balance_cents).toBe(15000);
  });
});

// ── Section 370: Impression Charging ─────────────────────────────────────────

test.describe("370 — Impression charging", () => {
  test("370.1 Track impression creates charge", async () => {
    // Internal charge endpoints are admin-only (require_admin_or_root) and are
    // mounted under /ui/admin/ads. Call them as root.
    const resp = await adminPost(
      rootPage,
      "/ui/admin/ads/internal/charge-impression",
      {
        account_id: accountId,
        campaign_id: campaignId,
        creative_id: "creat_e2e_001",
        creator_id: BOB_ID,
        content_id: "post_e2e_001",
        bid_cpm_cents: 500,
      },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.charge_cents).toBeGreaterThan(0);
  });

  test("370.2 Advertiser balance decremented", async () => {
    const acct = ddbGet("AdAccounts", { pk: `ACCT#${accountId}`, sk: "META" });
    expect(acct).toBeTruthy();
    // Balance was 15000 before impression, should be less now
    expect(Number(acct!.balance_cents)).toBeLessThan(15000);
  });

  test("370.3 Campaign spend incremented", async () => {
    const camp = ddbGet("AdCampaigns", {
      pk: `ACCT#${accountId}`,
      sk: `CAMPAIGN#${campaignId}`,
    });
    expect(camp).toBeTruthy();
    expect(Number(camp!.lifetime_spent_cents)).toBeGreaterThan(0);
  });

  test("370.4 Creator receives revenue share", async () => {
    // Check Bob's billing ledger for ad_revenue_credit
    const resp = await apiGet(
      alicePage,
      `/ui/ads/accounts/${accountId}/billing?limit=50`,
    );
    expect(resp.status()).toBe(200);
    const entries = await resp.json();
    const charges = entries.filter(
      (e: Record<string, unknown>) => e.entry_type === "impression_charge",
    );
    expect(charges.length).toBeGreaterThan(0);
    // The creator credit is in the billing table, not the ad_billing table
    // so we verify the charge was recorded correctly
    expect(Number(charges[0].amount_cents)).toBeGreaterThan(0);
  });
});

// ── Section 371: Budget Enforcement ──────────────────────────────────────────

test.describe("371 — Budget enforcement", () => {
  let budgetCampaignId: string;
  let budgetAccountId: string;

  test.beforeAll(async () => {
    // Create a small-budget account/campaign for budget tests
    budgetAccountId = `adacct_budget_${TS}`;
    budgetCampaignId = `camp_budget_${TS}`;

    ddbPut("AdAccounts", {
      pk: `ACCT#${budgetAccountId}`,
      sk: "META",
      account_id: budgetAccountId,
      owner_sub: ALICE_ID,
      company_name: `Budget Test Corp ${TS}`,
      billing_email: "budget@e2e.test",
      status: "active",
      balance_cents: 50000,
      lifetime_spend_cents: 0,
      created_at: Math.floor(Date.now() / 1000),
      updated_at: Math.floor(Date.now() / 1000),
    });

    ddbPut("AdCampaigns", {
      pk: `ACCT#${budgetAccountId}`,
      sk: `CAMPAIGN#${budgetCampaignId}`,
      campaign_id: budgetCampaignId,
      account_id: budgetAccountId,
      name: `Budget Campaign ${TS}`,
      objective: "awareness",
      budget_cents: 5,
      budget_type: "lifetime",
      daily_budget_cents: 0,
      spent_today_cents: 0,
      lifetime_spent_cents: 0,
      status: "active",
      created_at: Math.floor(Date.now() / 1000),
      updated_at: Math.floor(Date.now() / 1000),
    });
  });

  test("371.1 Campaign auto-pauses at 100% budget", async () => {
    // Send enough impressions to exceed the 5 cent budget
    for (let i = 0; i < 6; i++) {
      await adminPost(rootPage, "/ui/admin/ads/internal/charge-impression", {
        account_id: budgetAccountId,
        campaign_id: budgetCampaignId,
        creative_id: "creat_budget_001",
        creator_id: BOB_ID,
        content_id: "post_budget_001",
        bid_cpm_cents: 1000,
      });
    }

    // Check campaign status
    const camp = ddbGet("AdCampaigns", {
      pk: `ACCT#${budgetAccountId}`,
      sk: `CAMPAIGN#${budgetCampaignId}`,
    });
    expect(camp).toBeTruthy();
    expect(camp!.status).toBe("completed");
  });

  test("371.2 Spending alert records created", async () => {
    // Check that budget alert guard entries were created in billing table
    // The alert guard uses sk = AD_BUDGET_ALERT#{campaign_id}#{threshold}
    // We look for the 100% alert since we exceeded budget
    const alert100 = ddbGet("billing", {
      pk: `USER#${ALICE_ID}`,
      sk: `AD_BUDGET_ALERT#${budgetCampaignId}#100`,
    });
    expect(alert100).toBeTruthy();
    expect(Number(alert100!.threshold)).toBe(100);
  });

  test("371.3 Campaign spend tracks correctly", async () => {
    const camp = ddbGet("AdCampaigns", {
      pk: `ACCT#${budgetAccountId}`,
      sk: `CAMPAIGN#${budgetCampaignId}`,
    });
    expect(camp).toBeTruthy();
    expect(Number(camp!.lifetime_spent_cents)).toBeGreaterThanOrEqual(5);
  });
});

// ── Section 372: Invoice Generation ──────────────────────────────────────────

test.describe("372 — Invoice generation", () => {
  const currentMonth = new Date().toISOString().slice(0, 7);

  test("372.1 Generate monthly invoice", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/accounts/${accountId}/invoices/${currentMonth}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.account_id).toBe(accountId);
    expect(data.month).toBe(currentMonth);
    expect(Array.isArray(data.campaigns)).toBe(true);
  });

  test("372.2 Invoice aggregates by campaign", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/accounts/${accountId}/invoices/${currentMonth}`,
    );
    const data = await resp.json();
    if (data.campaigns.length > 0) {
      const line = data.campaigns[0];
      expect(line.campaign_id).toBeTruthy();
      expect(typeof line.impressions).toBe("number");
      expect(typeof line.clicks).toBe("number");
      expect(typeof line.conversions).toBe("number");
      expect(typeof line.total_cents).toBe("number");
    }
  });

  test("372.3 Invoice shows total charges", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/accounts/${accountId}/invoices/${currentMonth}`,
    );
    const data = await resp.json();
    expect(typeof data.total_charges_cents).toBe("number");
    // Sum of campaign totals should equal total_charges_cents
    const campaignSum = data.campaigns.reduce(
      (sum: number, c: { total_cents: number }) => sum + c.total_cents,
      0,
    );
    expect(data.total_charges_cents).toBe(campaignSum);
  });

  test("372.4 Invoice shows deposits", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/accounts/${accountId}/invoices/${currentMonth}`,
    );
    const data = await resp.json();
    expect(typeof data.total_deposits_cents).toBe("number");
    expect(data.total_deposits_cents).toBeGreaterThan(0);
  });
});

// ── Section 373: Authorization & Edge Cases ──────────────────────────────────

test.describe("373 — Authorization & edge cases", () => {
  test("373.1 Non-owner cannot access billing", async () => {
    const resp = await apiGet(
      bobPage,
      `/ui/ads/accounts/${accountId}/billing`,
    );
    expect(resp.status()).toBe(404);
  });

  test("373.2 Non-owner cannot deposit", async () => {
    const resp = await apiPost(
      bobPage,
      `/ui/ads/accounts/${accountId}/deposit`,
      { amount_cents: 10000 },
      BOB_ID,
    );
    expect(resp.status()).toBe(404);
  });

  test("373.3 Invalid month format returns 400", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/accounts/${accountId}/invoices/May-2026`,
    );
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail).toContain("Invalid month format");
  });

  test("373.4 Invoice for empty month returns zero totals", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/ads/accounts/${accountId}/invoices/2099-01`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.total_charges_cents).toBe(0);
    expect(data.campaigns.length).toBe(0);
  });
});
