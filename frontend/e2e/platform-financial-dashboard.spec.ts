/**
 * E2E tests for the Platform Financial Dashboard (FIN-013).
 *
 * Sections:
 *   523 — Financial KPI API
 *   524 — Revenue Trends API
 *   525 — Provider & Type Breakdown API + Top Creators
 *   526 — Export & Rollup API
 *   527 — Edge cases
 *
 * Endpoints live under /ui/admin/financial-dashboard and require ADMIN/ROOT
 * (cookie-session auth). The manual rollup trigger requires ROOT.
 *
 * Auth strategy mirrors admin-roles.spec.ts: each identity gets a page with
 * role-bearing cookies from e2e_admin_session_setup.py. Ledger entries are
 * seeded directly into the billing DynamoDB table so totals are deterministic.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
import { usingCpp, cppSeedFinancialLedger } from "./helpers/cpp-seed-financial-dashboard";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const ALICE_ID = "e2e_alice@test.local";

// Unique tag for this run so seeded rows / dates don't collide across runs.
const RUN_TAG = `fin013_${Date.now()}`;
// Seed everything onto a fixed historical date so the daily range is bounded.
const SEED_DATE = "2024-03-15"; // YYYY-MM-DD (UTC)
const RANGE_START = "2024-03-01";
const RANGE_END = "2024-03-31";
const FUTURE_START = "2099-01-01";
const FUTURE_END = "2099-01-31";

// ─── Session bootstrap ──────────────────────────────────────────────────────

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

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

// ─── DDB seed helper ────────────────────────────────────────────────────────

/**
 * Ensure the financial_rollups table exists and seed billing ledger entries
 * for SEED_DATE. Seeds:
 *   - 3 tip_debit (Stripe), creators c1/c2
 *   - 2 unlock_debit (PayPal), creator c1
 *   - 1 subscription_charge (Stripe), creator c2
 *   - 1 platform_commission (revenue)
 */
function seedLedger(): void {
  if (usingCpp()) {
    cppSeedFinancialLedger(SEED_DATE, RUN_TAG);
    return;
  }
  execSync(
    `python3 -c "
import boto3, os, secrets
from pathlib import Path
env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1); os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
client = ddb.meta.client
billing_name = os.environ.get('BILLING_TABLE_NAME') or os.environ.get('DDB_TABLE') or 'billing'
rollup_name = os.environ.get('PLATFORM_FINANCIAL_DASHBOARD_ROLLUPS_TABLE_NAME') or 'financial_rollups'
existing = [t for _p in client.get_paginator('list_tables').paginate() for t in _p['TableNames']]
def ensure(name):
    if name in existing: return
    client.create_table(TableName=name, KeySchema=[{'AttributeName':'pk','KeyType':'HASH'},{'AttributeName':'sk','KeyType':'RANGE'}], AttributeDefinitions=[{'AttributeName':'pk','AttributeType':'S'},{'AttributeName':'sk','AttributeType':'S'}], BillingMode='PAY_PER_REQUEST')
    client.get_waiter('table_exists').wait(TableName=name)
ensure(billing_name); ensure(rollup_name)
billing = ddb.Table(billing_name)
import datetime
d = '${SEED_DATE}'
base_ts = int(datetime.datetime.strptime(d,'%Y-%m-%d').replace(tzinfo=datetime.timezone.utc).timestamp())
def put(user, etype, amount, provider, creator):
    eid = secrets.token_hex(8)
    ts = base_ts + secrets.randbelow(80000)
    billing.put_item(Item={'pk':'USER#'+user,'sk':'LEDGER#'+str(ts)+'#'+eid,'entry_id':eid,'ts':ts,'type':etype,'amount_cents':amount,'state':'settled','reason':'${RUN_TAG}','ledger_date':d,'provider':provider,'creator_id':creator,'user_id':user})
put('payer1','tip_debit',1000,'stripe','c1')
put('payer2','tip_debit',2000,'stripe','c1')
put('payer3','tip_debit',1500,'stripe','c2')
put('payer1','unlock_debit',500,'paypal','c1')
put('payer2','unlock_debit',800,'paypal','c2')
put('payer3','subscription_charge',2500,'stripe','c2')
put('platform','platform_commission',900,'stripe','')
print('seeded')
"`,
    { cwd: REPO_ROOT, timeout: 30_000 },
  );
}

// ─── 523. Financial KPI API ──────────────────────────────────────────────────

test.describe("523. Platform Financial Dashboard — KPIs", () => {
  let rootPage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    seedLedger();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("admin retrieves financial KPIs for date range", async () => {
    const r = await apiGet(rootPage, "ui/admin/financial-dashboard/kpis", {
      start_date: RANGE_START,
      end_date: RANGE_END,
    });
    expect(r.status()).toBe(200);
    const d = (await r.json()) as Record<string, number>;
    expect(d.gmv_cents).toBeGreaterThan(0);
    expect(d.net_revenue_cents).toBeGreaterThanOrEqual(0);
    expect(d.take_rate_bps).toBeGreaterThanOrEqual(0);
    expect(d.tx_count).toBeGreaterThan(0);
  });

  test("KPIs include unique payer count and avg tx", async () => {
    const r = await apiGet(rootPage, "ui/admin/financial-dashboard/kpis", {
      start_date: RANGE_START,
      end_date: RANGE_END,
    });
    const d = (await r.json()) as Record<string, number>;
    expect(d.unique_payers).toBeGreaterThanOrEqual(1);
    expect(d.avg_tx_cents).toBeGreaterThan(0);
  });

  test("KPIs for empty (future) date range return zeroes", async () => {
    const r = await apiGet(rootPage, "ui/admin/financial-dashboard/kpis", {
      start_date: FUTURE_START,
      end_date: FUTURE_END,
    });
    expect(r.status()).toBe(200);
    const d = (await r.json()) as Record<string, number>;
    expect(d.gmv_cents).toBe(0);
    expect(d.tx_count).toBe(0);
  });

  test("non-admin cannot access KPIs (403)", async () => {
    const r = await apiGet(alicePage, "ui/admin/financial-dashboard/kpis", {
      start_date: RANGE_START,
      end_date: RANGE_END,
    });
    expect(r.status()).toBe(403);
  });

  test("invalid date range (end before start) returns 422", async () => {
    const r = await apiGet(rootPage, "ui/admin/financial-dashboard/kpis", {
      start_date: RANGE_END,
      end_date: RANGE_START,
    });
    expect(r.status()).toBe(422);
  });
});

// ─── 524. Revenue Trends API ──────────────────────────────────────────────────

test.describe("524. Platform Financial Dashboard — Trends", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    seedLedger();
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("daily trends return time series", async () => {
    const r = await apiGet(rootPage, "ui/admin/financial-dashboard/trends", {
      start_date: RANGE_START,
      end_date: RANGE_END,
      granularity: "daily",
    });
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { data: Array<Record<string, unknown>> };
    expect(Array.isArray(d.data)).toBe(true);
    expect(d.data.length).toBeGreaterThan(0);
    expect(d.data[0]).toHaveProperty("date");
    expect(d.data[0]).toHaveProperty("gmv_cents");
    expect(d.data[0]).toHaveProperty("net_revenue_cents");
  });

  test("weekly granularity aggregates", async () => {
    const r = await apiGet(rootPage, "ui/admin/financial-dashboard/trends", {
      start_date: RANGE_START,
      end_date: RANGE_END,
      granularity: "weekly",
    });
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { data: unknown[]; granularity: string };
    expect(d.granularity).toBe("weekly");
    expect(Array.isArray(d.data)).toBe(true);
  });

  test("trends sorted by date ascending", async () => {
    const r = await apiGet(rootPage, "ui/admin/financial-dashboard/trends", {
      start_date: RANGE_START,
      end_date: RANGE_END,
      granularity: "daily",
    });
    const d = (await r.json()) as { data: Array<{ date: string }> };
    for (let i = 1; i < d.data.length; i++) {
      expect(d.data[i - 1].date <= d.data[i].date).toBe(true);
    }
  });

  test("invalid granularity returns 422", async () => {
    const r = await apiGet(rootPage, "ui/admin/financial-dashboard/trends", {
      start_date: RANGE_START,
      end_date: RANGE_END,
      granularity: "hourly",
    });
    expect(r.status()).toBe(422);
  });
});

// ─── 525. Provider & Type Breakdown + Top Creators ────────────────────────────

test.describe("525. Platform Financial Dashboard — Breakdowns", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    seedLedger();
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("provider breakdown lists active providers", async () => {
    const r = await apiGet(rootPage, "ui/admin/financial-dashboard/providers", {
      start_date: RANGE_START,
      end_date: RANGE_END,
    });
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { data: Array<Record<string, unknown>> };
    expect(d.data.length).toBeGreaterThan(0);
    expect(d.data[0]).toHaveProperty("provider");
    expect(d.data[0]).toHaveProperty("total_cents");
    expect(d.data[0]).toHaveProperty("pct");
  });

  test("provider percentages sum to ~100", async () => {
    const r = await apiGet(rootPage, "ui/admin/financial-dashboard/providers", {
      start_date: RANGE_START,
      end_date: RANGE_END,
    });
    const d = (await r.json()) as { data: Array<{ pct: number }> };
    const sum = d.data.reduce((acc, e) => acc + e.pct, 0);
    expect(Math.abs(sum - 100)).toBeLessThanOrEqual(1.0);
  });

  test("type breakdown lists transaction types", async () => {
    const r = await apiGet(rootPage, "ui/admin/financial-dashboard/types", {
      start_date: RANGE_START,
      end_date: RANGE_END,
    });
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { data: Array<{ entry_type: string }> };
    const types = d.data.map((e) => e.entry_type);
    expect(types).toContain("tip_debit");
  });

  test("top creators ranked by revenue descending", async () => {
    const r = await apiGet(rootPage, "ui/admin/financial-dashboard/top-creators", {
      start_date: RANGE_START,
      end_date: RANGE_END,
    });
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { data: Array<{ revenue_cents: number }> };
    expect(d.data.length).toBeGreaterThan(0);
    if (d.data.length >= 2) {
      expect(d.data[0].revenue_cents).toBeGreaterThanOrEqual(d.data[1].revenue_cents);
    }
  });
});

// ─── 526. Export & Rollup API ─────────────────────────────────────────────────

test.describe("526. Platform Financial Dashboard — Export & Rollup", () => {
  let rootPage: Page;
  let charliePage: Page;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    seedLedger();
    rootPage = await newIdentityPage(browser, "root");
    charliePage = await newIdentityPage(browser, "charlie_admin");
  });
  test.afterAll(async () => {
    await rootPage?.close();
    await charliePage?.close();
  });

  test("CSV export returns downloadable content", async () => {
    const r = await apiGet(rootPage, "ui/admin/financial-dashboard/export/csv", {
      start_date: RANGE_START,
      end_date: RANGE_END,
    });
    expect(r.status()).toBe(200);
    expect(r.headers()["content-type"]).toContain("text/csv");
    const body = await r.text();
    expect(body).toContain("date,gmv_cents,net_revenue_cents");
  });

  test("root can trigger manual rollup", async () => {
    const r = await apiPost(rootPage, "root", "ui/admin/financial-dashboard/rollup", {
      date: SEED_DATE,
    });
    expect(r.status()).toBe(200);
    const d = (await r.json()) as Record<string, unknown>;
    expect(d.computed_at).toBeTruthy();
    expect(d.date).toBe(SEED_DATE);
  });

  test("non-root (ADMIN) cannot trigger rollup (403)", async () => {
    const r = await apiPost(charliePage, "charlie_admin", "ui/admin/financial-dashboard/rollup", {
      date: SEED_DATE,
    });
    expect(r.status()).toBe(403);
  });
});

// ─── 527. Edge cases ──────────────────────────────────────────────────────────

test.describe("527. Platform Financial Dashboard — Edge cases", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    seedLedger();
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("trends with no data in future range returns empty array", async () => {
    const r = await apiGet(rootPage, "ui/admin/financial-dashboard/trends", {
      start_date: FUTURE_START,
      end_date: FUTURE_END,
      granularity: "daily",
    });
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { data: unknown[] };
    expect(d.data.length).toBe(0);
  });

  test("top creators limited by count param", async () => {
    const r = await apiGet(rootPage, "ui/admin/financial-dashboard/top-creators", {
      start_date: RANGE_START,
      end_date: RANGE_END,
      limit: "1",
    });
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { data: unknown[] };
    expect(d.data.length).toBeLessThanOrEqual(1);
  });

  test("CSV export first data row date >= start_date", async () => {
    const r = await apiGet(rootPage, "ui/admin/financial-dashboard/export/csv", {
      start_date: RANGE_START,
      end_date: RANGE_END,
    });
    const body = await r.text();
    const lines = body.trim().split("\n");
    // line 0 is header; line 1 is first data row
    const firstDate = lines[1].split(",")[0];
    expect(firstDate >= RANGE_START).toBe(true);
  });

  test("monthly granularity returns bucketed data", async () => {
    const r = await apiGet(rootPage, "ui/admin/financial-dashboard/trends", {
      start_date: RANGE_START,
      end_date: RANGE_END,
      granularity: "monthly",
    });
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { data: Array<{ date: string }>; granularity: string };
    expect(d.granularity).toBe("monthly");
    if (d.data.length > 0) {
      // monthly keys are YYYY-MM
      expect(d.data[0].date).toMatch(/^\d{4}-\d{2}$/);
    }
  });

  test("unauthenticated request is rejected", async ({ browser }) => {
    const anonCtx = await browser.newContext({ storageState: undefined });
    const r = await anonCtx.request.get(`${API}/ui/admin/financial-dashboard/kpis`, {
      params: { start_date: RANGE_START, end_date: RANGE_END },
    });
    expect([401, 403]).toContain(r.status());
    await anonCtx.close();
  });
});
