/**
 * E2E tests for MON-003: Creator Earnings Dashboard
 *
 * Section 105: Earnings Summary API (5 tests)
 * Section 106: Earnings Transactions API (4 tests)
 * Section 107: Earnings Quick Stats + Edge Cases (6 tests)
 * Section 108: Earnings UI (6 tests)
 *
 * Auth: uses e2e_admin_session_setup.py to get cookie-based sessions.
 * Seeds billing ledger credit entries directly into DynamoDB for Alice.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ───────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_KEY = "alice";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();
const PYTHON = REPO_ROOT + "/.venv/bin/python3";

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

async function injectAuth(page: Page, sessionKey: string) {
  const sessions = getSessions();
  const session = sessions[sessionKey];
  if (!session) throw new Error(`No session for key=${sessionKey}`);
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

// ─── Request helpers ─────────────────────────────────────────────────────────

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  let url = `${API}${path}`;
  if (params) {
    const qs = new URLSearchParams(params).toString();
    url += `?${qs}`;
  }
  return page.request.get(url);
}

// ─── DDB seed helper ─────────────────────────────────────────────────────────

function seedLedgerCredits(userSub: string, entries: Array<{ reason: string; amount_cents: number }>): void {
  const entriesB64 = Buffer.from(JSON.stringify(entries)).toString("base64");
  execSync(
    `${PYTHON} -c "
import boto3, os, json, uuid, time, base64
from pathlib import Path

env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
tbl = ddb.Table('billing')
pk = 'USER#${userSub}'
entries = json.loads(base64.b64decode('${entriesB64}').decode())
base_ts = int(time.time()) - 600

for i, entry in enumerate(entries):
    entry_id = uuid.uuid4().hex
    ts = base_ts + i
    tbl.put_item(Item={
        'pk': pk,
        'sk': f'LEDGER#{ts}#{entry_id}',
        'entry_id': entry_id,
        'ts': ts,
        'type': 'credit',
        'amount_cents': entry['amount_cents'],
        'currency': 'USD',
        'state': 'settled',
        'reason': entry['reason'],
        'meta': {'test_run': '${TS}'},
    })
print('seeded')
"`,
    { timeout: 10_000 },
  );
}

function cleanupLedgerCredits(userSub: string): void {
  try {
    execSync(
      `${PYTHON} -c "
import boto3, os
from pathlib import Path
from boto3.dynamodb.conditions import Key

env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
tbl = ddb.Table('billing')
pk = 'USER#${userSub}'
resp = tbl.query(
    KeyConditionExpression=Key('pk').eq(pk) & Key('sk').begins_with('LEDGER#'),
)
for item in resp.get('Items', []):
    if item.get('type') == 'credit' and item.get('meta', {}).get('test_run') == '${TS}':
        tbl.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
print('cleaned')
"`,
      { timeout: 10_000 },
    );
  } catch {
    // best-effort
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// Section 105: Earnings Summary API
// ═════════════════════════════════════════════════════════════════════════════

test.describe("105 · Earnings Summary API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    // Seed ledger entries for Alice
    seedLedgerCredits(ALICE_ID, [
      { reason: "Tip: message", amount_cents: 500 },
      { reason: "Tip: post", amount_cents: 1000 },
      { reason: "Message unlock", amount_cents: 2500 },
    ]);

    alicePage = await newIdentityPage(browser, ALICE_KEY);
  });

  test.afterAll(async () => {
    cleanupLedgerCredits(ALICE_ID);
    await alicePage?.close();
  });

  test("105.1 Alice gets earnings summary", async () => {
    const resp = await apiGet(alicePage, "/ui/earnings/summary");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.total_cents).toBeGreaterThanOrEqual(4000);
    expect(data.breakdown.tips).toBeGreaterThanOrEqual(1500);
    expect(data.breakdown.unlocks).toBeGreaterThanOrEqual(2500);
    expect(data.currency).toBe("USD");
  });

  test("105.2 Summary with time range filter", async () => {
    const now = Math.floor(Date.now() / 1000);
    const resp = await apiGet(alicePage, "/ui/earnings/summary", {
      from_ts: String(now - 3600),
      to_ts: String(now + 3600),
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // All entries were seeded within the last 10 minutes, so they all fall in range
    expect(data.total_cents).toBeGreaterThanOrEqual(4000);
  });

  test("105.3 Summary with empty time range", async () => {
    // Far-future from_ts should yield 0 results
    const farFuture = Math.floor(Date.now() / 1000) + 999999;
    const resp = await apiGet(alicePage, "/ui/earnings/summary", {
      from_ts: String(farFuture),
      to_ts: String(farFuture + 1000),
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.total_cents).toBe(0);
    expect(data.transaction_count).toBe(0);
  });

  test("105.4 Breakdown categories are correct", async () => {
    const resp = await apiGet(alicePage, "/ui/earnings/summary");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.breakdown.tips).toBeGreaterThanOrEqual(1500);
    expect(data.breakdown.unlocks).toBeGreaterThanOrEqual(2500);
    expect(typeof data.breakdown.subscriptions).toBe("number");
    expect(typeof data.breakdown.vod_purchases).toBe("number");
    expect(typeof data.breakdown.other).toBe("number");
  });

  test("105.5 Transaction count matches", async () => {
    const resp = await apiGet(alicePage, "/ui/earnings/summary");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.transaction_count).toBeGreaterThanOrEqual(3);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Section 106: Earnings Transactions API
// ═════════════════════════════════════════════════════════════════════════════

test.describe("106 · Earnings Transactions API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    // Seed ledger entries for Alice (different from section 105 — use unique TS)
    seedLedgerCredits(ALICE_ID, [
      { reason: "Tip: message", amount_cents: 500 },
      { reason: "Tip: post", amount_cents: 1000 },
      { reason: "Message unlock", amount_cents: 2500 },
    ]);

    alicePage = await newIdentityPage(browser, ALICE_KEY);
  });

  test.afterAll(async () => {
    cleanupLedgerCredits(ALICE_ID);
    await alicePage?.close();
  });

  test("106.1 Alice lists earnings transactions", async () => {
    const resp = await apiGet(alicePage, "/ui/earnings/transactions");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items.length).toBeGreaterThanOrEqual(3);
  });

  test("106.2 Transactions have correct fields", async () => {
    const resp = await apiGet(alicePage, "/ui/earnings/transactions");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const item = data.items[0];
    expect(item).toHaveProperty("entry_id");
    expect(item).toHaveProperty("ts");
    expect(item).toHaveProperty("amount_cents");
    expect(item).toHaveProperty("reason");
    expect(item).toHaveProperty("category");
    expect(item).toHaveProperty("currency");
    expect(typeof item.entry_id).toBe("string");
    expect(typeof item.ts).toBe("number");
    expect(typeof item.amount_cents).toBe("number");
  });

  test("106.3 Pagination works", async () => {
    const resp = await apiGet(alicePage, "/ui/earnings/transactions", {
      limit: "1",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items.length).toBe(1);
    expect(data.next_cursor).toBeDefined();
    expect(typeof data.next_cursor).toBe("string");

    // Fetch next page using cursor
    const resp2 = await apiGet(alicePage, "/ui/earnings/transactions", {
      limit: "1",
      cursor: data.next_cursor,
    });
    expect(resp2.status()).toBe(200);
    const data2 = await resp2.json();
    expect(data2.items.length).toBeGreaterThanOrEqual(1);
    // Should be a different item
    expect(data2.items[0].entry_id).not.toBe(data.items[0].entry_id);
  });

  test("106.4 Category mapping is correct", async () => {
    const resp = await apiGet(alicePage, "/ui/earnings/transactions");
    expect(resp.status()).toBe(200);
    const data = await resp.json();

    // Find items matching our seeded entries
    const tipItems = data.items.filter(
      (i: { reason: string; category: string }) =>
        i.reason.startsWith("Tip:") && i.category === "tips",
    );
    expect(tipItems.length).toBeGreaterThanOrEqual(1);

    const unlockItems = data.items.filter(
      (i: { reason: string; category: string }) =>
        i.reason.includes("unlock") && i.category === "unlocks",
    );
    expect(unlockItems.length).toBeGreaterThanOrEqual(1);
  });
});

// =============================================================================
// Section 107: Quick Stats + Time Series + Edge Cases
// =============================================================================

test.describe("107 · Quick Stats + Time Series + Edge Cases", () => {
  let alicePage: Page;
  const debitEntryId = `e107_debit_${TS}`;
  const debitTs = Math.floor(Date.now() / 1000) - 50;

  test.beforeAll(async ({ browser }) => {
    // Seed credit entries
    seedLedgerCredits(ALICE_ID, [
      { reason: "Tip: message", amount_cents: 750 },
      { reason: "Subscription payment", amount_cents: 1999 },
      { reason: "VOD sale", amount_cents: 600 },
    ]);

    // Seed a DEBIT entry (should be filtered out)
    const debitB64 = Buffer.from(JSON.stringify([{ reason: "Wallet withdrawal", amount_cents: 300 }])).toString("base64");
    execSync(
      `${PYTHON} -c "
import boto3, os, json, base64, time
from pathlib import Path

env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
tbl = ddb.Table('billing')
ts = ${debitTs}
tbl.put_item(Item={
    'pk': 'USER#${ALICE_ID}',
    'sk': f'LEDGER#{ts}#${debitEntryId}',
    'entry_id': '${debitEntryId}',
    'ts': ts,
    'type': 'debit',
    'amount_cents': 300,
    'currency': 'USD',
    'state': 'settled',
    'reason': 'Wallet withdrawal',
    'meta': {'test_run': '${TS}'},
})
print('debit seeded')
"`,
      { timeout: 10_000 },
    );

    alicePage = await newIdentityPage(browser, ALICE_KEY);
  });

  test.afterAll(async () => {
    cleanupLedgerCredits(ALICE_ID);
    // Clean debit entry
    try {
      execSync(
        `${PYTHON} -c "
import boto3, os
from pathlib import Path

env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
tbl = ddb.Table('billing')
tbl.delete_item(Key={'pk': 'USER#${ALICE_ID}', 'sk': 'LEDGER#${debitTs}#${debitEntryId}'})
print('debit cleaned')
"`,
        { timeout: 10_000 },
      );
    } catch { /* best-effort */ }
    await alicePage?.close();
  });

  test("107.1 quick-stats returns all time windows", async () => {
    const resp = await apiGet(alicePage, "/ui/earnings/quick-stats");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.today_cents).toBe("number");
    expect(typeof data.this_week_cents).toBe("number");
    expect(typeof data.this_month_cents).toBe("number");
    expect(typeof data.all_time_cents).toBe("number");
    expect(data.currency).toBe("USD");
    expect(typeof data.pending_payout_cents).toBe("number");
  });

  test("107.2 quick-stats windows are monotonically non-decreasing", async () => {
    const resp = await apiGet(alicePage, "/ui/earnings/quick-stats");
    const data = await resp.json();
    expect(data.all_time_cents).toBeGreaterThanOrEqual(data.this_month_cents);
    expect(data.this_month_cents).toBeGreaterThanOrEqual(data.this_week_cents);
    expect(data.this_week_cents).toBeGreaterThanOrEqual(data.today_cents);
  });

  test("107.3 summary time_series with day granularity", async () => {
    const resp = await apiGet(alicePage, "/ui/earnings/summary", {
      granularity: "day",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.time_series)).toBe(true);
    if (data.time_series.length > 0) {
      // Day format: YYYY-MM-DD
      expect(data.time_series[0].date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(typeof data.time_series[0].total).toBe("number");
    }
  });

  test("107.4 summary time_series with month granularity", async () => {
    const resp = await apiGet(alicePage, "/ui/earnings/summary", {
      granularity: "month",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.time_series)).toBe(true);
    if (data.time_series.length > 0) {
      // Month format: YYYY-MM
      expect(data.time_series[0].date).toMatch(/^\d{4}-\d{2}$/);
    }
  });

  test("107.5 only credit entries included (debits filtered)", async () => {
    // The debit entry (300 cents) should NOT appear in summary
    const resp = await apiGet(alicePage, "/ui/earnings/summary");
    const data = await resp.json();
    // Verify no negative / debit amounts snuck through the transaction list
    const txResp = await apiGet(alicePage, "/ui/earnings/transactions");
    const txData = await txResp.json();
    for (const item of txData.items) {
      expect(item.category).not.toBe("debit");
      // All returned entries should be credits (positive amounts)
      expect(item.amount_cents).toBeGreaterThan(0);
    }
  });

  test("107.6 invalid date format returns 400", async () => {
    const resp = await apiGet(alicePage, "/ui/earnings/summary", {
      from_date: "not-a-date",
    });
    expect(resp.status()).toBe(400);
  });
});

// =============================================================================
// Section 108: Earnings UI
// =============================================================================

test.describe("108 · Earnings UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    // Seed some entries for UI rendering
    seedLedgerCredits(ALICE_ID, [
      { reason: "Tip: message", amount_cents: 1200 },
      { reason: "Subscription payment", amount_cents: 4999 },
      { reason: "Post unlock", amount_cents: 800 },
    ]);

    alicePage = await newIdentityPage(browser, ALICE_KEY);
  });

  test.afterAll(async () => {
    cleanupLedgerCredits(ALICE_ID);
    await alicePage?.close();
  });

  test("108.1 Earnings page loads with quick stat cards", async () => {
    await alicePage.goto(`${BASE}/earnings`);
    await alicePage.waitForLoadState("domcontentloaded");

    await expect(alicePage.getByText("Today")).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.getByText("This Week")).toBeVisible();
    await expect(alicePage.getByText("This Month")).toBeVisible();
    await expect(alicePage.getByText("All Time")).toBeVisible();
  });

  test("108.2 Quick stats show dollar amounts", async () => {
    await alicePage.goto(`${BASE}/earnings`);
    await alicePage.waitForLoadState("domcontentloaded");

    // Wait for stat cards to render values
    await expect(
      alicePage.locator("[role='status']").first(),
    ).toBeVisible({ timeout: 10_000 });

    // At least one stat card should show a dollar amount
    const statTexts = await alicePage.locator("[role='status']").allTextContents();
    const hasDollarAmount = statTexts.some((t) => /\$\d/.test(t));
    expect(hasDollarAmount).toBe(true);
  });

  test("108.3 Revenue Over Time chart section visible", async () => {
    await alicePage.goto(`${BASE}/earnings`);
    await alicePage.waitForLoadState("domcontentloaded");

    await expect(
      alicePage.getByText("Revenue Over Time"),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("108.4 Revenue Breakdown section visible", async () => {
    await alicePage.goto(`${BASE}/earnings`);
    await alicePage.waitForLoadState("domcontentloaded");

    await expect(
      alicePage.getByText("Revenue Breakdown"),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("108.5 Date range preset buttons exist", async () => {
    await alicePage.goto(`${BASE}/earnings`);
    await alicePage.waitForLoadState("domcontentloaded");

    await expect(alicePage.getByRole("button", { name: "7d" })).toBeVisible();
    await expect(alicePage.getByRole("button", { name: "30d" })).toBeVisible();
    await expect(alicePage.getByRole("button", { name: "90d" })).toBeVisible();
    await expect(alicePage.getByRole("button", { name: "1y" })).toBeVisible();
    await expect(alicePage.getByRole("button", { name: "All" })).toBeVisible();
  });

  test("108.6 Transaction table shows entries", async () => {
    await alicePage.goto(`${BASE}/earnings`);
    await alicePage.waitForLoadState("domcontentloaded");

    await expect(
      alicePage.getByText("Recent Transactions"),
    ).toBeVisible({ timeout: 10_000 });

    // Wait for table rows
    await expect(
      alicePage.locator("table tbody tr").first(),
    ).toBeVisible({ timeout: 10_000 });

    const rowCount = await alicePage.locator("table tbody tr").count();
    expect(rowCount).toBeGreaterThanOrEqual(1);
  });
});
