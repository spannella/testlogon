/**
 * E2E tests for FIN-008: Creator 1099 / Tax-Form Generation
 *
 * Platform-issuer side: annual 1099-NEC earnings forms for CREATORS / payees,
 * derived from billing ledger CREDIT entries. DISTINCT from FIN-004 consumer
 * tax documents (consumer/buyer side).
 *
 * Section 580: Creator 1099 generation + download API (7 tests)
 * Section 581: Correction / re-generate API (3 tests)
 * Section 582: Admin batch generation + concurrency (4 tests)
 * Section 583: Auth + UI (3 tests)
 *
 * Total: 17 tests.
 *
 * Auth: e2e_admin_session_setup.py cookie sessions (alice=creator, root/charlie
 * =admin). Seeds billing ledger credit entries + profile rows directly into
 * DynamoDB at controlled timestamps for deterministic per-year totals.
 *
 * Threshold: $600 (60000 cents). Tax year 2099 is used for batch/concurrency
 * tests so accumulated dev data never pollutes the batch creator discovery.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, resolveIdentityId } from "./helpers/session";
import {
  usingCpp,
  cppSeedTaxLedger,
  cppSeedProfile,
  cppCleanupTax,
  cppSeedBatchLock,
} from "./helpers/cpp-seed-appeals-moderation-tail";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
// Under cpp these resolve to the JWT sub (tlc_billing/tlc_profile keyed by sub);
// Python path returns the email verbatim (unchanged).
const ALICE_ID = resolveIdentityId("e2e_alice@test.local");
const BOB_ID = resolveIdentityId("e2e_bob@test.local");
const PYTHON = REPO_ROOT + "/.venv/bin/python3";
const TS = Date.now();

const TEST_YEAR = 2090; // alice single-generate / download / correction
const BATCH_YEAR = 2091; // batch + concurrency (isolated from TEST_YEAR)

// The admin batch (Section 582) discovers qualifying creators via a GLOBAL scan
// of the billing ledger and writes forms scanned back by Section 582.3's
// year-list. Running the file's describes in parallel (fullyParallel/-workers>1)
// races that global scan against the concurrent seed/generate/cleanup in
// Sections 580/581, so 582.3 intermittently sees no form for Alice. Serialize
// the whole file so the batch operates on a stable snapshot (passes fine
// serially).
test.describe.configure({ mode: "serial" });

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

async function apiPost(
  page: Page,
  sessionKey: string,
  path: string,
  body?: unknown,
  params?: Record<string, string>,
) {
  const sessions = getSessions();
  let url = `${API}${path}`;
  if (params) url += `?${new URLSearchParams(params).toString()}`;
  return page.request.post(url, {
    headers: { "x-csrf-token": sessions[sessionKey].csrf_token, "content-type": "application/json" },
    data: body ?? {},
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
  if (usingCpp()) {
    cppSeedTaxLedger(userSub, entries, TS);
    return;
  }
  const b64 = Buffer.from(JSON.stringify(entries)).toString("base64");
  execSync(
    `${PYTHON} -c "
import boto3, os, json, uuid, base64
from datetime import datetime, timezone
from pathlib import Path

env_file = Path('${REPO_ROOT}/.env.local')
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

function seedProfile(userSub: string, displayName: string): void {
  if (usingCpp()) {
    cppSeedProfile(userSub, displayName);
    return;
  }
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

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('profiles')
existing = tbl.get_item(Key={'user_sub': '${userSub}'}).get('Item')
if not existing:
    tbl.put_item(Item={'user_sub': '${userSub}', 'display_name': '${displayName}'})
print('profile ok')
"`,
    { timeout: 15_000 },
  );
}

function cleanup(userSubs: string[], years: number[]): void {
  if (usingCpp()) {
    try {
      for (const sub of userSubs) cppCleanupTax(sub, TS, years);
    } catch {
      // best effort
    }
    return;
  }
  const subsB64 = Buffer.from(JSON.stringify(userSubs)).toString("base64");
  const yearsB64 = Buffer.from(JSON.stringify(years)).toString("base64");
  try {
    execSync(
      `${PYTHON} -c "
import boto3, os, json, base64
from pathlib import Path
from boto3.dynamodb.conditions import Key

env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
subs = json.loads(base64.b64decode('${subsB64}').decode())
years = json.loads(base64.b64decode('${yearsB64}').decode())
billing = ddb.Table('billing')
forms = ddb.Table('tax_forms_1099')
for sub in subs:
    pk = f'USER#{sub}'
    resp = billing.query(KeyConditionExpression=Key('pk').eq(pk) & Key('sk').begins_with('LEDGER#'))
    for item in resp.get('Items', []):
        if item.get('meta', {}).get('test_run') == '${TS}':
            billing.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
    fr = forms.query(KeyConditionExpression=Key('pk').eq(pk))
    for item in fr.get('Items', []):
        forms.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
for yr in years:
    forms.delete_item(Key={'pk': f'BATCH#{yr}', 'sk': 'LOCK'})
print('cleaned')
"`,
      { timeout: 20_000 },
    );
  } catch {
    // best effort
  }
}

// ─── Section 580: Creator 1099 generation + download API ─────────────────────

test.describe("FIN-008 Section 580: Creator 1099 generation API", () => {
  let alice: Page;

  test.beforeAll(async ({ browser }) => {
    cleanup([ALICE_ID, BOB_ID], [TEST_YEAR, BATCH_YEAR]);
    seedProfile(ALICE_ID, "E2E Alice");
    seedProfile(BOB_ID, "E2E Bob");
    // Alice: $1000 (above $600). Bob: $100 (below threshold).
    seedLedger(ALICE_ID, [
      { reason: "Tip", amount_cents: 50000, year: TEST_YEAR },
      { reason: "Subscription", amount_cents: 50000, year: TEST_YEAR },
    ]);
    seedLedger(BOB_ID, [{ reason: "Tip", amount_cents: 10000, year: TEST_YEAR }]);
    alice = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await alice?.close();
    cleanup([ALICE_ID, BOB_ID], [TEST_YEAR, BATCH_YEAR]);
  });

  test("580.1 generate 1099 above threshold returns qualifies + totals", async () => {
    const resp = await apiPost(alice, "alice", `/ui/tax-forms/1099s/${TEST_YEAR}/generate`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.tax_year).toBe(TEST_YEAR);
    expect(body.total_earnings_cents).toBe(100000);
    expect(body.qualifies).toBe(true);
    expect(body.status).toBe("generated");
  });

  test("580.2 re-generate same year returns 409", async () => {
    const resp = await apiPost(alice, "alice", `/ui/tax-forms/1099s/${TEST_YEAR}/generate`);
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail.code).toBe("already_generated");
  });

  test("580.3 get own 1099 returns the form", async () => {
    const resp = await apiGet(alice, `/ui/tax-forms/1099s/${TEST_YEAR}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.tax_year).toBe(TEST_YEAR);
    expect(body.total_earnings_cents).toBe(100000);
  });

  test("580.4 list 1099s includes the generated form", async () => {
    const resp = await apiGet(alice, `/ui/tax-forms/1099s`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const found = (body.items || []).find((f: any) => f.tax_year === TEST_YEAR);
    expect(found).toBeTruthy();
    expect(found.qualifies).toBe(true);
  });

  test("580.5 download returns a PDF URL", async () => {
    const resp = await apiGet(alice, `/ui/tax-forms/1099s/${TEST_YEAR}/download`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(typeof body.download_url).toBe("string");
    // Python's dev path returns a /mock/s3/ URL; cpp under moto returns a REAL
    // presigned S3 URL to the same PDF object (/_s3/... ?X-Amz-...). Both are
    // valid downloadable URLs, so accept either shape under cpp.
    if (usingCpp()) {
      expect(body.download_url).toMatch(/\/mock\/s3\/|\/_s3\/|X-Amz-/);
    } else {
      expect(body.download_url).toContain("/mock/s3/");
    }
  });

  test("580.6 download missing year returns 404", async () => {
    const resp = await apiGet(alice, `/ui/tax-forms/1099s/2077/download`);
    expect(resp.status()).toBe(404);
    const body = await resp.json();
    expect(body.detail.code).toBe("not_found");
  });

  test("580.7 below-threshold creator generation returns 422", async ({ browser }) => {
    const bobPage = await newIdentityPage(browser, "bob");
    const resp = await apiPost(bobPage, "bob", `/ui/tax-forms/1099s/${TEST_YEAR}/generate`);
    expect(resp.status()).toBe(422);
    const body = await resp.json();
    expect(body.detail.code).toBe("below_threshold");
    await bobPage.close();
  });
});

// ─── Section 581: Correction / re-generate API ───────────────────────────────

test.describe("FIN-008 Section 581: Correction API", () => {
  let alice: Page;
  let admin: Page;

  test.beforeAll(async ({ browser }) => {
    cleanup([ALICE_ID], [TEST_YEAR]);
    seedProfile(ALICE_ID, "E2E Alice");
    seedLedger(ALICE_ID, [{ reason: "Tip", amount_cents: 70000, year: TEST_YEAR }]);
    alice = await newIdentityPage(browser, "alice");
    admin = await newIdentityPage(browser, "root");
    // Generate the original form first (creator side).
    await apiPost(alice, "alice", `/ui/tax-forms/1099s/${TEST_YEAR}/generate`);
  });

  test.afterAll(async () => {
    await alice?.close();
    await admin?.close();
    cleanup([ALICE_ID], [TEST_YEAR]);
  });

  test("581.1 admin correct existing 1099 returns corrected status", async () => {
    const resp = await apiPost(
      admin,
      "root",
      `/ui/tax-forms/admin/1099s/${TEST_YEAR}/correct`,
      undefined,
      { user_sub: ALICE_ID },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("corrected");
    expect(body.correction_count).toBeGreaterThanOrEqual(1);
  });

  test("581.2 correct missing form returns 404", async () => {
    const resp = await apiPost(
      admin,
      "root",
      `/ui/tax-forms/admin/1099s/2066/correct`,
      undefined,
      { user_sub: ALICE_ID },
    );
    expect(resp.status()).toBe(404);
    const body = await resp.json();
    expect(body.detail.code).toBe("not_found");
  });

  test("581.3 non-admin cannot correct (403)", async () => {
    const resp = await apiPost(
      alice,
      "alice",
      `/ui/tax-forms/admin/1099s/${TEST_YEAR}/correct`,
      undefined,
      { user_sub: ALICE_ID },
    );
    expect(resp.status()).toBe(403);
  });
});

// ─── Section 582: Admin batch generation + concurrency ───────────────────────

test.describe("FIN-008 Section 582: Admin batch generation", () => {
  let admin: Page;

  test.beforeAll(async ({ browser }) => {
    cleanup([ALICE_ID, BOB_ID], [BATCH_YEAR]);
    seedProfile(ALICE_ID, "E2E Alice");
    seedProfile(BOB_ID, "E2E Bob");
    // Alice qualifies ($800); Bob below threshold ($50).
    seedLedger(ALICE_ID, [{ reason: "Tip", amount_cents: 80000, year: BATCH_YEAR }]);
    seedLedger(BOB_ID, [{ reason: "Tip", amount_cents: 5000, year: BATCH_YEAR }]);
    admin = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await admin?.close();
    cleanup([ALICE_ID, BOB_ID], [BATCH_YEAR]);
  });

  test("582.1 batch generates only qualifying creators", async () => {
    const resp = await apiPost(admin, "root", `/ui/tax-forms/admin/batch`, {
      tax_year: BATCH_YEAR,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.tax_year).toBe(BATCH_YEAR);
    expect(body.qualifying).toBeGreaterThanOrEqual(1);
    expect(body.generated).toBeGreaterThanOrEqual(1);
    expect(body.errors).toBe(0);
  });

  test("582.2 batch is idempotent (skips already-generated)", async () => {
    const resp = await apiPost(admin, "root", `/ui/tax-forms/admin/batch`, {
      tax_year: BATCH_YEAR,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.generated).toBe(0);
    expect(body.skipped).toBeGreaterThanOrEqual(1);
  });

  test("582.3 admin can list forms issued for the year", async () => {
    const resp = await apiGet(admin, `/ui/tax-forms/admin/year/${BATCH_YEAR}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const found = (body.items || []).find((f: any) => f.user_sub === ALICE_ID);
    expect(found).toBeTruthy();
    // Bob (below threshold) must NOT appear.
    const bob = (body.items || []).find((f: any) => f.user_sub === BOB_ID);
    expect(bob).toBeFalsy();
  });

  test("582.4 second concurrent batch returns 429", async () => {
    // Manually plant an in-progress lock, then attempt a batch.
    if (usingCpp()) {
      cppSeedBatchLock(BATCH_YEAR);
    } else {
    execSync(
      `${PYTHON} -c "
import boto3, os, time
from pathlib import Path

env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('tax_forms_1099')
tbl.put_item(Item={'pk': 'BATCH#${BATCH_YEAR}', 'sk': 'LOCK', 'state': 'in_progress', 'started_at': int(time.time())})
print('locked')
"`,
      { timeout: 15_000 },
    );
    }
    const resp = await apiPost(admin, "root", `/ui/tax-forms/admin/batch`, {
      tax_year: BATCH_YEAR,
    });
    expect(resp.status()).toBe(429);
    const body = await resp.json();
    expect(body.detail.code).toBe("batch_in_progress");
  });
});

// ─── Section 583: Auth + UI ──────────────────────────────────────────────────

test.describe("FIN-008 Section 583: Auth + UI", () => {
  test("583.1 non-admin cannot run batch (403)", async ({ browser }) => {
    const alice = await newIdentityPage(browser, "alice");
    const resp = await apiPost(alice, "alice", `/ui/tax-forms/admin/batch`, {
      tax_year: TEST_YEAR,
    });
    expect(resp.status()).toBe(403);
    await alice.close();
  });

  test("583.2 creator tax-forms page renders", async ({ browser }) => {
    const alice = await newIdentityPage(browser, "alice");
    await alice.goto(`${BASE}/billing/tax-forms`, { waitUntil: "domcontentloaded" });
    await expect(
      alice.getByRole("heading", { name: "Tax Forms (1099-NEC)" }),
    ).toBeVisible({ timeout: 15_000 });
    await alice.close();
  });

  test("583.3 admin 1099 batch page renders", async ({ browser }) => {
    const admin = await newIdentityPage(browser, "root");
    await admin.goto(`${BASE}/admin/tax-forms-1099`, { waitUntil: "domcontentloaded" });
    await expect(
      admin.getByRole("heading", { name: "1099 Batch Generation" }),
    ).toBeVisible({ timeout: 15_000 });
    await admin.close();
  });
});
