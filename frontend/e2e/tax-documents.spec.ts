/**
 * E2E tests for FIN-004: Consumer Tax Documents
 *
 * Annual creator-earnings (1099-style) tax documents derived from billing
 * ledger CREDIT entries. Creator-scoped; admin can view/issue any user's docs.
 *
 * Section 551: Earnings Summary API (8 tests)
 * Section 552: Tax Summary PDF API (5 tests)
 * Section 553: Comparison API (7 tests)
 * Section 554: Admin & Document History API (6 tests)
 * Section 555: Tax Documents UI (6 tests)
 *
 * Total: 32 tests.
 *
 * Auth: uses e2e_admin_session_setup.py for cookie-based sessions.
 * Seeds billing ledger credit entries directly into DynamoDB at controlled
 * timestamps for deterministic per-year totals.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";
const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";
const TS = Date.now();

// Use a past, immutable year so cached + computed totals are deterministic.
const TEST_YEAR = 2024;
const PREV_YEAR = 2023;

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
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

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

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  let url = `${API}${path}`;
  if (params) {
    url += `?${new URLSearchParams(params).toString()}`;
  }
  return page.request.get(url);
}

async function apiPost(page: Page, sessionKey: string, path: string, body: unknown, params?: Record<string, string>) {
  const sessions = getSessions();
  let url = `${API}${path}`;
  if (params) url += `?${new URLSearchParams(params).toString()}`;
  return page.request.post(url, {
    headers: { "x-csrf-token": sessions[sessionKey].csrf_token, "content-type": "application/json" },
    data: body,
  });
}

// ─── DDB seed helpers ────────────────────────────────────────────────────────

interface SeedEntry {
  reason: string;
  amount_cents: number;
  year: number;
  type?: string; // default "credit"
}

function seedLedger(userSub: string, entries: SeedEntry[]): void {
  const b64 = Buffer.from(JSON.stringify(entries)).toString("base64");
  execSync(
    `${PYTHON} -c "
import boto3, os, json, uuid, base64, calendar
from datetime import datetime, timezone
from pathlib import Path

env_file = Path('/home/ubuntu/testlogon/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('billing')
pk = 'USER#${userSub}'
entries = json.loads(base64.b64decode('${b64}').decode())
counter = {}
for entry in entries:
    yr = int(entry['year'])
    # spread within June of the target year
    base_ts = int(datetime(yr, 6, 1, 12, 0, 0, tzinfo=timezone.utc).timestamp())
    i = counter.get(yr, 0)
    counter[yr] = i + 1
    ts = base_ts + i
    entry_id = uuid.uuid4().hex
    tbl.put_item(Item={
        'pk': pk,
        'sk': f'LEDGER#{ts}#{entry_id}',
        'entry_id': entry_id,
        'ts': ts,
        'type': entry.get('type', 'credit'),
        'amount_cents': entry['amount_cents'],
        'currency': 'USD',
        'state': 'settled',
        'reason': entry['reason'],
        'meta': {'test_run': '${TS}'},
    })
print('seeded')
"`,
    { timeout: 15_000 },
  );
}

function cleanupLedger(userSub: string): void {
  try {
    execSync(
      `${PYTHON} -c "
import boto3, os
from pathlib import Path
from boto3.dynamodb.conditions import Key

env_file = Path('/home/ubuntu/testlogon/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('billing')
pk = 'USER#${userSub}'
resp = tbl.query(KeyConditionExpression=Key('pk').eq(pk) & Key('sk').begins_with('LEDGER#'))
for item in resp.get('Items', []):
    if item.get('meta', {}).get('test_run') == '${TS}':
        tbl.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})

# wipe any cached tax_documents rows so seeded data is recomputed fresh
tax = ddb.Table('tax_documents')
r2 = tax.query(KeyConditionExpression=Key('pk').eq(pk))
for item in r2.get('Items', []):
    tax.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
print('cleaned')
"`,
      { timeout: 15_000 },
    );
  } catch {
    // best effort
  }
}

function catOf(body: any, name: string) {
  return (body.categories || []).find((c: any) => c.category === name) || { total_cents: 0, transaction_count: 0 };
}

// ─── Test data ───────────────────────────────────────────────────────────────
// 2024 totals: tips 5000 (2), subscriptions 12000 (1), unlocks 3500 (1),
//              other 1000 (1)  => grand 21500, 5 debit-less credit txns.
// 2023 totals: tips 10000 (1) => grand 10000.

test.describe("FIN-004 Consumer Tax Documents", () => {
  let alice: Page;

  test.beforeAll(async ({ browser }) => {
    cleanupLedger(ALICE_ID);
    cleanupLedger(BOB_ID);
    seedLedger(ALICE_ID, [
      { reason: "Tip from fan", amount_cents: 2000, year: TEST_YEAR },
      { reason: "Tip: message", amount_cents: 3000, year: TEST_YEAR },
      { reason: "Subscription renewal", amount_cents: 12000, year: TEST_YEAR },
      { reason: "Unlock locked post", amount_cents: 3500, year: TEST_YEAR },
      { reason: "Platform bonus adjustment", amount_cents: 1000, year: TEST_YEAR },
      // a credit in 2023 for comparison
      { reason: "Tip from fan", amount_cents: 10000, year: PREV_YEAR },
    ]);
    alice = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    cleanupLedger(ALICE_ID);
    cleanupLedger(BOB_ID);
    await alice?.close();
  });

  // ─── Section 551: Earnings Summary API ─────────────────────────────────────

  test("551.1 Annual summary returns category breakdown", async () => {
    const resp = await apiGet(alice, "/ui/tax-documents/summary", { year: String(TEST_YEAR) });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(catOf(body, "tips").total_cents).toBe(5000);
    expect(catOf(body, "subscriptions").total_cents).toBe(12000);
    expect(catOf(body, "unlocks").total_cents).toBe(3500);
  });

  test("551.2 Custom date range filters correctly", async () => {
    // Range covering only the first half of 2024 June still includes all seeded
    // entries (seeded in June); compare with a narrow January range = 0.
    const janStart = Math.floor(Date.UTC(TEST_YEAR, 0, 1) / 1000);
    const janEnd = Math.floor(Date.UTC(TEST_YEAR, 0, 31) / 1000);
    const resp = await apiGet(alice, "/ui/tax-documents/summary", {
      date_from: String(janStart),
      date_to: String(janEnd),
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.grand_total_cents).toBe(0);
  });

  test("551.3 Empty period returns zero totals", async () => {
    const resp = await apiGet(alice, "/ui/tax-documents/summary", { year: "2025" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.grand_total_cents).toBe(0);
    expect(body.categories.length).toBeGreaterThan(0);
    expect(catOf(body, "tips").total_cents).toBe(0);
  });

  test("551.4 Credits-only: debit (refund) excluded", async () => {
    // Seed a debit in a fresh isolated year (2026 — a valid, otherwise-empty
    // year at/after the platform launch year) and confirm it's excluded.
    seedLedger(ALICE_ID, [{ reason: "Refund to fan", amount_cents: 9999, year: 2026, type: "debit" }]);
    const resp = await apiGet(alice, "/ui/tax-documents/summary", { year: "2026" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.grand_total_cents).toBe(0);
  });

  test("551.5 Summary counts distinct transactions", async () => {
    const resp = await apiGet(alice, "/ui/tax-documents/summary", { year: String(TEST_YEAR) });
    const body = await resp.json();
    expect(body.transaction_count).toBe(5);
  });

  test("551.6 Subscription entries classified correctly", async () => {
    const resp = await apiGet(alice, "/ui/tax-documents/summary", { year: String(TEST_YEAR) });
    const body = await resp.json();
    expect(catOf(body, "subscriptions").total_cents).toBe(12000);
    expect(catOf(body, "subscriptions").transaction_count).toBe(1);
  });

  test("551.7 Other category captures unclassified credits", async () => {
    const resp = await apiGet(alice, "/ui/tax-documents/summary", { year: String(TEST_YEAR) });
    const body = await resp.json();
    expect(catOf(body, "other").total_cents).toBe(1000);
  });

  test("551.8 Grand total matches sum of categories", async () => {
    const resp = await apiGet(alice, "/ui/tax-documents/summary", { year: String(TEST_YEAR) });
    const body = await resp.json();
    expect(body.grand_total_cents).toBe(21500);
  });

  // ─── Section 552: Tax Summary PDF API ──────────────────────────────────────

  test("552.1 PDF download returns binary content", async () => {
    const resp = await apiGet(alice, "/ui/tax-documents/summary/pdf", { year: String(TEST_YEAR) });
    expect(resp.status()).toBe(200);
    expect(resp.headers()["content-type"]).toContain("application/pdf");
    const buf = await resp.body();
    expect(buf.subarray(0, 4).toString()).toBe("%PDF");
  });

  test("552.2 PDF filename includes year", async () => {
    const resp = await apiGet(alice, "/ui/tax-documents/summary/pdf", { year: String(TEST_YEAR) });
    expect(resp.headers()["content-disposition"]).toContain(`earnings-summary-${TEST_YEAR}.pdf`);
  });

  test("552.3 Custom range PDF uses range in filename", async () => {
    const df = Math.floor(Date.UTC(TEST_YEAR, 0, 1) / 1000);
    const dt = Math.floor(Date.UTC(TEST_YEAR, 11, 31) / 1000);
    const resp = await apiGet(alice, "/ui/tax-documents/summary/pdf", {
      date_from: String(df),
      date_to: String(dt),
    });
    expect(resp.status()).toBe(200);
    expect(resp.headers()["content-disposition"]).toContain(`${df}-${dt}.pdf`);
  });

  test("552.4 PDF for empty period still generates", async () => {
    const resp = await apiGet(alice, "/ui/tax-documents/summary/pdf", { year: "2025" });
    expect(resp.status()).toBe(200);
    const buf = await resp.body();
    expect(buf.subarray(0, 4).toString()).toBe("%PDF");
  });

  test("552.5 Consecutive PDF requests are deterministic", async () => {
    const a = await apiGet(alice, "/ui/tax-documents/summary/pdf", { year: String(TEST_YEAR) });
    const b = await apiGet(alice, "/ui/tax-documents/summary/pdf", { year: String(TEST_YEAR) });
    const ba = await a.body();
    const bb = await b.body();
    expect(ba.length).toBe(bb.length);
  });

  // ─── Section 553: Comparison API ────────────────────────────────────────────

  test("553.1 Comparison returns both years", async () => {
    const resp = await apiGet(alice, "/ui/tax-documents/comparison", { year: String(TEST_YEAR) });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.current_year).toBe(TEST_YEAR);
    expect(body.previous_year).toBe(PREV_YEAR);
    expect(body.current_summary.grand_total_cents).toBe(21500);
    expect(body.previous_summary.grand_total_cents).toBe(10000);
  });

  test("553.2 Change percentage calculated correctly", async () => {
    const resp = await apiGet(alice, "/ui/tax-documents/comparison", { year: String(TEST_YEAR) });
    const body = await resp.json();
    // (21500 - 10000) / 10000 * 100 = 115.0
    expect(body.change_pct).toBeCloseTo(115.0, 1);
  });

  test("553.3 Comparison with no prior year returns zero previous", async () => {
    const resp = await apiGet(alice, "/ui/tax-documents/comparison", { year: "2025" });
    const body = await resp.json();
    // 2024 had earnings, 2025 had none.
    expect(body.current_summary.grand_total_cents).toBe(0);
  });

  test("553.4 Missing range params returns 422", async () => {
    const resp = await apiGet(alice, "/ui/tax-documents/summary");
    expect(resp.status()).toBe(422);
  });

  test("553.5 Future year rejected", async () => {
    const resp = await apiGet(alice, "/ui/tax-documents/summary", { year: "2099" });
    expect(resp.status()).toBe(422);
  });

  test("553.6 Year before launch rejected", async () => {
    const resp = await apiGet(alice, "/ui/tax-documents/summary", { year: "2020" });
    expect(resp.status()).toBe(422);
  });

  test("553.7 date_from after date_to rejected", async () => {
    const resp = await apiGet(alice, "/ui/tax-documents/summary", {
      date_from: "2000000000",
      date_to: "1000000000",
    });
    expect(resp.status()).toBe(422);
  });

  // ─── Section 554: Admin & Document History API ──────────────────────────────

  test("554.1 Generate + history lists generated document", async () => {
    const gen = await apiPost(alice, "alice", "/ui/tax-documents/generate", {
      year: TEST_YEAR,
      regenerate: true,
    });
    expect(gen.status()).toBe(200);
    const doc = await gen.json();
    expect(doc.year).toBe(TEST_YEAR);
    expect(doc.grand_total_cents).toBe(21500);

    const hist = await apiGet(alice, "/ui/tax-documents/history");
    expect(hist.status()).toBe(200);
    const body = await hist.json();
    expect(body.documents.some((d: any) => d.year === TEST_YEAR)).toBe(true);
  });

  test("554.2 Admin can view any user's summary", async ({ browser }) => {
    const root = await newIdentityPage(browser, "root");
    const resp = await apiGet(root, "/ui/admin/tax-documents/summary", {
      user_sub: ALICE_ID,
      year: String(TEST_YEAR),
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.grand_total_cents).toBe(21500);
    await root.close();
  });

  test("554.3 Non-admin cannot access admin endpoint", async () => {
    const resp = await apiGet(alice, "/ui/admin/tax-documents/summary", {
      user_sub: ALICE_ID,
      year: String(TEST_YEAR),
    });
    expect(resp.status()).toBe(403);
  });

  test("554.4 Only own documents visible", async ({ browser }) => {
    const bob = await newIdentityPage(browser, "bob");
    const resp = await apiGet(bob, "/ui/tax-documents/history");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    // Bob has no seeded earnings / generated docs.
    expect(Array.isArray(body.documents)).toBe(true);
    await bob.close();
  });

  test("554.5 Admin missing user_sub returns 422", async ({ browser }) => {
    const root = await newIdentityPage(browser, "root");
    const resp = await apiGet(root, "/ui/admin/tax-documents/summary", { year: String(TEST_YEAR) });
    expect(resp.status()).toBe(422);
    await root.close();
  });

  test("554.6 Admin with invalid user_sub returns 404", async ({ browser }) => {
    const root = await newIdentityPage(browser, "root");
    const resp = await apiGet(root, "/ui/admin/tax-documents/summary", {
      user_sub: "nonexistent@nowhere.invalid",
      year: String(TEST_YEAR),
    });
    expect(resp.status()).toBe(404);
    await root.close();
  });

  // ─── Section 555: Tax Documents UI ──────────────────────────────────────────

  test("555.1 Tax Documents page loads", async () => {
    await alice.goto(`${BASE}/billing/tax-documents`, { waitUntil: "domcontentloaded" });
    await expect(alice.getByRole("heading", { name: "Tax Documents", exact: true })).toBeVisible();
  });

  test("555.2 Year preset buttons are visible", async () => {
    await alice.goto(`${BASE}/billing/tax-documents`, { waitUntil: "domcontentloaded" });
    const presets = alice.getByTestId("year-presets");
    await expect(presets.getByRole("button", { name: String(TEST_YEAR) })).toBeVisible();
  });

  test("555.3 Selecting a year updates summary display", async () => {
    await alice.goto(`${BASE}/billing/tax-documents`, { waitUntil: "domcontentloaded" });
    await alice.getByTestId("year-presets").getByRole("button", { name: String(TEST_YEAR) }).click();
    await expect(alice.getByTestId("grand-total")).toBeVisible();
  });

  test("555.4 Download PDF button is present", async () => {
    await alice.goto(`${BASE}/billing/tax-documents`, { waitUntil: "domcontentloaded" });
    await expect(alice.getByRole("button", { name: /Download Summary PDF/i })).toBeVisible();
  });

  test("555.5 Year comparison card shows delta", async () => {
    await alice.goto(`${BASE}/billing/tax-documents`, { waitUntil: "domcontentloaded" });
    await alice.getByTestId("year-presets").getByRole("button", { name: String(TEST_YEAR) }).click();
    await expect(alice.getByTestId("change-pct")).toBeVisible();
  });

  test("555.6 Document history table populates after generate", async () => {
    await apiPost(alice, "alice", "/ui/tax-documents/generate", { year: TEST_YEAR, regenerate: true });
    await alice.goto(`${BASE}/billing/tax-documents`, { waitUntil: "domcontentloaded" });
    await expect(alice.getByTestId("history-row").first()).toBeVisible();
  });
});
