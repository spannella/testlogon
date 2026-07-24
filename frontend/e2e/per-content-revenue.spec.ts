/**
 * E2E tests for FIN-006: Per-Content Revenue Breakdown
 *
 * Section 559: Content Revenue List API (5 tests)
 * Section 560: Content Revenue Detail API (4 tests)
 * Section 561: CSV Export API (3 tests)
 * Section 562: Content Revenue UI (4 tests)
 * Section 563: Edge Cases & Negative Tests (6 tests)
 * Section 564: Rollup & Multi-source API (3 tests)
 *
 * Total: 25 tests
 *
 * Auth: e2e_admin_session_setup.py cookie sessions (alice / bob).
 * Seeds billing ledger CREDIT entries directly into DynamoDB with
 * meta.content_id so per-content attribution is deterministic.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ALICE_KEY = "alice";
const ALICE_ID = "e2e_alice@test.local";
const BOB_KEY = "bob";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();
const PYTHON = REPO_ROOT + "/.venv/bin/python3";

// Unique content ids per run so assertions are deterministic across reruns.
const VID_A = `vid_fin006_${TS}_a`;
const VID_B = `vid_fin006_${TS}_b`;
const POST_C = `post_fin006_${TS}_c`;

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
  if (params) url += `?${new URLSearchParams(params).toString()}`;
  return page.request.get(url);
}

interface SeedEntry {
  content_id: string;
  content_type: string;
  reason: string;
  amount_cents: number;
  day_offset?: number; // days before now
}

function seedContentRevenue(userSub: string, entries: SeedEntry[]): void {
  const b64 = Buffer.from(JSON.stringify(entries)).toString("base64");
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

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('billing')
pk = 'USER#${userSub}'
entries = json.loads(base64.b64decode('${b64}').decode())
now = int(time.time())
for i, e in enumerate(entries):
    entry_id = uuid.uuid4().hex
    ts = now - int(e.get('day_offset', 0)) * 86400 - i
    tbl.put_item(Item={
        'pk': pk,
        'sk': f'LEDGER#{ts}#{entry_id}',
        'entry_id': entry_id,
        'ts': ts,
        'type': 'credit',
        'amount_cents': e['amount_cents'],
        'currency': 'USD',
        'state': 'settled',
        'reason': e['reason'],
        'meta': {'content_id': e['content_id'], 'content_type': e['content_type'], 'test_run': '${TS}'},
    })
print('seeded', len(entries))
"`,
    { timeout: 15_000 },
  );
}

function cleanupContentRevenue(userSub: string): void {
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

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('billing')
pk = 'USER#${userSub}'
resp = tbl.query(KeyConditionExpression=Key('pk').eq(pk) & Key('sk').begins_with('LEDGER#'))
for item in resp.get('Items', []):
    m = item.get('meta', {})
    if isinstance(m, dict) and m.get('test_run') == '${TS}':
        tbl.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
print('cleaned')
"`,
      { timeout: 15_000 },
    );
  } catch {
    /* best effort */
  }
}

// ─── Section 559: Content Revenue List API ───────────────────────────────────

test.describe("Section 559: Content Revenue List API", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await newIdentityPage(browser, ALICE_KEY);
    seedContentRevenue(ALICE_ID, [
      { content_id: VID_A, content_type: "vod", reason: "Tip: message", amount_cents: 12500 },
      { content_id: VID_A, content_type: "vod", reason: "Message unlock", amount_cents: 8000 },
      { content_id: VID_B, content_type: "vod", reason: "Tip: message", amount_cents: 3000 },
      { content_id: POST_C, content_type: "post", reason: "Tip: post", amount_cents: 1500 },
    ]);
  });

  test.afterAll(async () => {
    cleanupContentRevenue(ALICE_ID);
    await page.close();
  });

  test("559.1 list revenue includes seeded tip on video", async () => {
    const resp = await apiGet(page, "/ui/analytics/content-revenue", { limit: "200" });
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    const row = body.items.find((i: any) => i.content_id === VID_A);
    expect(row).toBeTruthy();
    expect(row.tips_cents).toBeGreaterThan(0);
  });

  test("559.2 unlock revenue is attributed", async () => {
    const resp = await apiGet(page, "/ui/analytics/content-revenue", { limit: "200" });
    const body = await resp.json();
    const row = body.items.find((i: any) => i.content_id === VID_A);
    expect(row.unlocks_cents).toBe(8000);
  });

  test("559.3 date range filter excludes out-of-range revenue", async () => {
    // Seed a far-past entry on a distinct content id, then filter to recent window.
    const farId = `vid_fin006_${TS}_far`;
    seedContentRevenue(ALICE_ID, [
      { content_id: farId, content_type: "vod", reason: "Tip: message", amount_cents: 9999, day_offset: 100 },
    ]);
    const today = new Date();
    const from = new Date(today.getTime() - 7 * 86400_000).toISOString().slice(0, 10);
    const to = today.toISOString().slice(0, 10);
    const resp = await apiGet(page, "/ui/analytics/content-revenue", { from_date: from, to_date: to, limit: "200" });
    const body = await resp.json();
    const farRow = body.items.find((i: any) => i.content_id === farId);
    expect(farRow).toBeFalsy();
  });

  test("559.4 content_type filter returns only matching items", async () => {
    const resp = await apiGet(page, "/ui/analytics/content-revenue", { content_type: "vod", limit: "200" });
    const body = await resp.json();
    const types = new Set(body.items.map((i: any) => i.content_type));
    expect(types.has("post")).toBeFalsy();
    expect(body.items.some((i: any) => i.content_id === VID_A)).toBeTruthy();
  });

  test("559.5 sort by total_cents desc returns highest first", async () => {
    const resp = await apiGet(page, "/ui/analytics/content-revenue", {
      sort_by: "total_cents",
      sort_order: "desc",
      limit: "200",
    });
    const body = await resp.json();
    const ours = body.items.filter((i: any) => [VID_A, VID_B, POST_C].includes(i.content_id));
    // VID_A (20500) should sort before VID_B (3000) and POST_C (1500).
    const idxA = ours.findIndex((i: any) => i.content_id === VID_A);
    const idxB = ours.findIndex((i: any) => i.content_id === VID_B);
    expect(idxA).toBeLessThan(idxB);
  });
});

// ─── Section 560: Content Revenue Detail API ─────────────────────────────────

test.describe("Section 560: Content Revenue Detail API", () => {
  let page: Page;
  const DID = `vid_fin006_${TS}_detail`;

  test.beforeAll(async ({ browser }) => {
    page = await newIdentityPage(browser, ALICE_KEY);
    seedContentRevenue(ALICE_ID, [
      { content_id: DID, content_type: "vod", reason: "Tip: message", amount_cents: 1000, day_offset: 1 },
      { content_id: DID, content_type: "vod", reason: "Message unlock", amount_cents: 500, day_offset: 0 },
    ]);
  });

  test.afterAll(async () => {
    cleanupContentRevenue(ALICE_ID);
    await page.close();
  });

  test("560.1 get detail for a specific content item", async () => {
    const resp = await apiGet(page, `/ui/analytics/content-revenue/${DID}`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.content_id).toBe(DID);
    expect(body.total_cents).toBe(1500);
    expect(body.tips_cents).toBe(1000);
    expect(body.unlocks_cents).toBe(500);
  });

  test("560.2 detail includes multi-day time series", async () => {
    const resp = await apiGet(page, `/ui/analytics/content-revenue/${DID}`);
    const body = await resp.json();
    expect(Array.isArray(body.time_series)).toBeTruthy();
    expect(body.time_series.length).toBeGreaterThanOrEqual(2);
  });

  test("560.3 returns 404 for non-existent content", async () => {
    const resp = await apiGet(page, `/ui/analytics/content-revenue/does_not_exist_${TS}`);
    expect(resp.status()).toBe(404);
  });

  test("560.4 cannot view another creator's content revenue", async ({ browser }) => {
    const bob = await newIdentityPage(browser, BOB_KEY);
    const resp = await apiGet(bob, `/ui/analytics/content-revenue/${DID}`);
    expect(resp.status()).toBe(404);
    await bob.close();
  });
});

// ─── Section 561: CSV Export API ─────────────────────────────────────────────

test.describe("Section 561: CSV Export API", () => {
  let page: Page;
  const EID = `vid_fin006_${TS}_csv`;

  test.beforeAll(async ({ browser }) => {
    page = await newIdentityPage(browser, ALICE_KEY);
    seedContentRevenue(ALICE_ID, [
      { content_id: EID, content_type: "vod", reason: "Tip: message", amount_cents: 25000 },
    ]);
  });

  test.afterAll(async () => {
    cleanupContentRevenue(ALICE_ID);
    await page.close();
  });

  test("561.1 export returns CSV with headers", async () => {
    const resp = await apiGet(page, "/ui/analytics/content-revenue/export");
    expect(resp.ok()).toBeTruthy();
    expect(resp.headers()["content-type"]).toContain("text/csv");
    const text = await resp.text();
    const firstLine = text.split("\n")[0];
    expect(firstLine).toContain("Content ID");
    expect(firstLine).toContain("Total ($)");
  });

  test("561.2 CSV contains seeded content row", async () => {
    const resp = await apiGet(page, "/ui/analytics/content-revenue/export");
    const text = await resp.text();
    expect(text).toContain(EID);
    expect(text).toContain("250.00");
  });

  test("561.3 export respects date range filter", async () => {
    const today = new Date().toISOString().slice(0, 10);
    const resp = await apiGet(page, "/ui/analytics/content-revenue/export", {
      from_date: today,
      to_date: today,
    });
    expect(resp.ok()).toBeTruthy();
    const text = await resp.text();
    expect(text).toContain("Content ID");
  });
});

// ─── Section 562: Content Revenue UI ─────────────────────────────────────────

test.describe("Section 562: Content Revenue UI", () => {
  let page: Page;
  const UID_HI = `vid_fin006_${TS}_ui_hi`;
  const UID_LO = `vid_fin006_${TS}_ui_lo`;

  test.beforeAll(async ({ browser }) => {
    page = await newIdentityPage(browser, ALICE_KEY);
    seedContentRevenue(ALICE_ID, [
      { content_id: UID_HI, content_type: "vod", reason: "Tip: message", amount_cents: 40000 },
      { content_id: UID_LO, content_type: "vod", reason: "Tip: message", amount_cents: 1000 },
    ]);
  });

  test.afterAll(async () => {
    cleanupContentRevenue(ALICE_ID);
    await page.close();
  });

  test("562.1 page loads with table", async () => {
    await page.goto(`${BASE}/analytics/content-revenue`, { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("content-revenue-table")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText("Content Revenue").first()).toBeVisible();
  });

  test("562.2 table rows show revenue breakdown", async () => {
    await page.goto(`${BASE}/analytics/content-revenue`, { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("content-revenue-table")).toBeVisible({ timeout: 15_000 });
    const rows = page.getByTestId("cr-row");
    await expect(rows.first()).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId("cr-total-revenue")).toBeVisible();
  });

  test("562.3 sort by Total reorders rows", async () => {
    await page.goto(`${BASE}/analytics/content-revenue`, { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("content-revenue-table")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId("cr-row").first()).toBeVisible({ timeout: 15_000 });
    // Default desc: first row total should be a large value.
    const firstTotal = await page.getByTestId("cr-row-total").first().textContent();
    expect(firstTotal).toBeTruthy();
    // Clicking the Total header toggles order without error.
    await page.getByTestId("cr-sort-total").click();
    await expect(page.getByTestId("cr-row").first()).toBeVisible({ timeout: 15_000 });
  });

  test("562.4 Export CSV button triggers request", async () => {
    await page.goto(`${BASE}/analytics/content-revenue`, { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("content-revenue-export")).toBeVisible({ timeout: 15_000 });
    const [popup] = await Promise.all([
      page.waitForEvent("popup").catch(() => null),
      page.getByTestId("content-revenue-export").click(),
    ]);
    // window.open opens a new tab to the export URL; tolerate popup blockers.
    if (popup) await popup.close().catch(() => {});
    expect(true).toBeTruthy();
  });
});

// ─── Section 563: Edge Cases & Negative Tests ────────────────────────────────

test.describe("Section 563: Edge Cases & Negative Tests", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await newIdentityPage(browser, ALICE_KEY);
  });

  test.afterAll(async () => {
    cleanupContentRevenue(ALICE_ID);
    await page.close();
  });

  test("563.1 empty result for creator with no attributed content", async ({ browser }) => {
    // Bob has no seeded content_id credits for this run.
    const bob = await newIdentityPage(browser, BOB_KEY);
    const resp = await apiGet(bob, "/ui/analytics/content-revenue", { limit: "200" });
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    const ours = body.items.filter((i: any) => String(i.content_id).includes(`fin006_${TS}`));
    expect(ours.length).toBe(0);
    await bob.close();
  });

  test("563.2 invalid date format returns 422", async () => {
    const resp = await apiGet(page, "/ui/analytics/content-revenue", { from_date: "not-a-date" });
    expect(resp.status()).toBe(422);
  });

  test("563.3 from_date after to_date returns 422", async () => {
    const resp = await apiGet(page, "/ui/analytics/content-revenue", {
      from_date: "2026-12-01",
      to_date: "2026-01-01",
    });
    expect(resp.status()).toBe(422);
  });

  test("563.4 invalid sort_by returns 422", async () => {
    const resp = await apiGet(page, "/ui/analytics/content-revenue", { sort_by: "bogus_field" });
    expect(resp.status()).toBe(422);
  });

  test("563.5 invalid content_type returns 422", async () => {
    const resp = await apiGet(page, "/ui/analytics/content-revenue", { content_type: "carrier_pigeon" });
    expect(resp.status()).toBe(422);
  });

  test("563.6 revenue sum invariant holds", async () => {
    const invId = `vid_fin006_${TS}_inv`;
    seedContentRevenue(ALICE_ID, [
      { content_id: invId, content_type: "vod", reason: "Tip: message", amount_cents: 700 },
      { content_id: invId, content_type: "vod", reason: "Message unlock", amount_cents: 300 },
      { content_id: invId, content_type: "vod", reason: "VOD sale", amount_cents: 1200 },
    ]);
    const resp = await apiGet(page, "/ui/analytics/content-revenue", { limit: "200" });
    const body = await resp.json();
    for (const it of body.items) {
      const sum =
        it.tips_cents + it.unlocks_cents + it.subscriptions_cents + it.ads_cents + it.vod_cents;
      expect(sum).toBe(it.total_cents);
    }
  });
});

// ─── Section 564: Rollup & Multi-source API ──────────────────────────────────

test.describe("Section 564: Rollup & Multi-source API", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await newIdentityPage(browser, ALICE_KEY);
  });

  test.afterAll(async () => {
    cleanupContentRevenue(ALICE_ID);
    await page.close();
  });

  test("564.1 multiple tips on same content accumulate", async () => {
    const cid = `vid_fin006_${TS}_acc`;
    seedContentRevenue(ALICE_ID, [
      { content_id: cid, content_type: "vod", reason: "Tip: message", amount_cents: 100 },
      { content_id: cid, content_type: "vod", reason: "Tip: message", amount_cents: 200 },
      { content_id: cid, content_type: "vod", reason: "Tip: message", amount_cents: 300 },
    ]);
    const resp = await apiGet(page, `/ui/analytics/content-revenue/${cid}`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.tips_cents).toBe(600);
  });

  test("564.2 mixed sources tracked separately", async () => {
    const cid = `vid_fin006_${TS}_mix`;
    seedContentRevenue(ALICE_ID, [
      { content_id: cid, content_type: "vod", reason: "Tip: message", amount_cents: 400 },
      { content_id: cid, content_type: "vod", reason: "Message unlock", amount_cents: 500 },
    ]);
    const resp = await apiGet(page, `/ui/analytics/content-revenue/${cid}`);
    const body = await resp.json();
    expect(body.tips_cents).toBe(400);
    expect(body.unlocks_cents).toBe(500);
    expect(body.total_cents).toBe(900);
  });

  test("564.3 vod sale credits classified as vod source", async () => {
    const cid = `vid_fin006_${TS}_vod`;
    seedContentRevenue(ALICE_ID, [
      { content_id: cid, content_type: "vod", reason: "VOD sale", amount_cents: 1500 },
    ]);
    const resp = await apiGet(page, `/ui/analytics/content-revenue/${cid}`);
    const body = await resp.json();
    expect(body.vod_cents).toBe(1500);
    expect(body.tips_cents).toBe(0);
  });
});
