/**
 * E2E tests for MOD-003: User Appeals System
 *
 * Section 100: User Appeal Submission API (7 tests)
 * Section 101: Admin Appeal Review API (8 tests)
 * Section 102: Rate Limiting (4 tests)
 * Section 103: Appeal Lifecycle (5 tests)
 *
 * Auth: uses e2e_admin_session_setup.py cookie-based sessions.
 * Alice = enforcement target (appeals), Root = admin reviewer.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ── Constants ─────────────────────────────────────────────────────────────

const API = "http://localhost:8000";
const BASE = "http://localhost:3000";

const ALICE_KEY = "alice";
const BOB_KEY = "bob";
const ROOT_KEY = "root";
const ALICE_SUB = "e2e_alice@test.local";
const BOB_SUB = "e2e_bob@test.local";
const ROOT_SUB = "root.admin@testdev.local";

const TS = Date.now();

// ── Session bootstrap ─────────────────────────────────────────────────────

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
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ── Auth helpers ──────────────────────────────────────────────────────────

async function injectAuth(page: Page, sessionKey: string) {
  const sessions = getSessions();
  const session = sessions[sessionKey];
  if (!session) throw new Error(`No session for key=${sessionKey}`);
  await page.context().addCookies(session.cookies);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

async function newIdentityPage(
  browser: Browser,
  sessionKey: string,
): Promise<Page> {
  const page = await browser.newPage();
  await injectAuth(page, sessionKey);
  return page;
}

async function apiPost(
  page: Page,
  sessionKey: string,
  path: string,
  body: object,
) {
  const sessions = getSessions();
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": sessions[sessionKey].csrf_token },
  });
}

async function apiGet(
  page: Page,
  path: string,
  params?: Record<string, string>,
) {
  let url = `${API}${path}`;
  if (params) {
    const qs = new URLSearchParams(params).toString();
    url += `?${qs}`;
  }
  return page.request.get(url);
}

// ── DDB helpers ──────────────────────────────────────────────────────────

function seedEnforcement(
  userId: string,
  enforcementType: "warn" | "ban",
  suffix: string,
): string {
  const enfId = `enf_e2e_${suffix}_${TS}`;
  const cmd = `python3 -c "
import boto3, time
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('UserEnforcementHistory')
tbl.put_item(Item={
    'user_id': '${userId}',
    'enforcement_id': '${enfId}',
    'entity_type': 'user_enforcement',
    'status': 'active' if '${enforcementType}' == 'ban' else 'recorded',
    'enforcement_type': '${enforcementType}',
    'source_ticket_id': 'ticket_e2e_${suffix}_${TS}',
    'created_at': str(int(time.time())),
    'created_by_admin_user_id': '${ROOT_SUB}',
    'note': 'E2E test enforcement ${suffix}',
})
print('OK')
"`;
  execSync(cmd, { cwd: REPO_ROOT, timeout: 10_000 });
  return enfId;
}

function seedBan(userId: string, suffix: string): void {
  const cmd = `python3 -c "
import boto3, time
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('account_state')
tbl.put_item(Item={
    'user_sub': '${userId}',
    'status': 'banned',
    'ban_duration_days': 0,
    'ban_started_at': int(time.time()),
    'ban_until': 0,
    'reason': 'moderation_ban',
    'ban_note': 'E2E test ban ${suffix}',
    'requested_by': '${ROOT_SUB}',
    'source_ticket_id': 'ticket_e2e_${suffix}_${TS}',
    'updated_at': int(time.time()),
})
print('OK')
"`;
  execSync(cmd, { cwd: REPO_ROOT, timeout: 10_000 });
}

function clearBan(userId: string): void {
  const cmd = `python3 -c "
import boto3
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('account_state')
try:
    tbl.delete_item(Key={'user_sub': '${userId}'})
except Exception:
    pass
print('OK')
"`;
  execSync(cmd, { cwd: REPO_ROOT, timeout: 10_000 });
}

function clearAppeals(): void {
  const cmd = `python3 -c "
import boto3
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('Appeals')
resp = tbl.scan()
for item in resp.get('Items', []):
    tbl.delete_item(Key={'appeal_id': item['appeal_id']})
print(f'Cleared {len(resp.get(chr(73)+chr(116)+chr(101)+chr(109)+chr(115), []))} appeals')
"`;
  execSync(cmd, { cwd: REPO_ROOT, timeout: 10_000 });
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 100: User Appeal Submission API
// ═══════════════════════════════════════════════════════════════════════════

test.describe("100 · User Appeal Submission API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let enfId: string;
  let appealId: string;

  test.beforeAll(async ({ browser }) => {
    clearAppeals();
    clearBan(ALICE_SUB);
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage = await newIdentityPage(browser, BOB_KEY);
    enfId = seedEnforcement(ALICE_SUB, "warn", "s100");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("100.1 Alice files appeal against warning", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/v1/appeals", {
      enforcement_id: enfId,
      appeal_text: `I believe this warning was issued in error ${TS}`,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.appeal_id).toBeTruthy();
    expect(data.status).toBe("submitted");
    appealId = data.appeal_id;
  });

  test("100.2 Appeal has correct status and fields", async () => {
    const resp = await apiGet(alicePage, `/v1/appeals/${appealId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.appeal_id).toBe(appealId);
    expect(data.user_id).toBe(ALICE_SUB);
    expect(data.enforcement_id).toBe(enfId);
    expect(data.status).toBe("submitted");
    expect(data.appeal_text).toContain("warning was issued in error");
    expect(data.created_at).toBeGreaterThan(0);
  });

  test("100.3 Duplicate appeal returns 409", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/v1/appeals", {
      enforcement_id: enfId,
      appeal_text: "Trying to file again",
    });
    expect(resp.status()).toBe(409);
  });

  test("100.4 Appeal with non-existent enforcement returns 404", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/v1/appeals", {
      enforcement_id: "enf_nonexistent_00000000",
      appeal_text: "This enforcement does not exist at all",
    });
    expect(resp.status()).toBe(404);
  });

  test("100.5 Bob cannot appeal Alice's enforcement", async () => {
    const enfId2 = seedEnforcement(ALICE_SUB, "warn", "s100bob");
    // Withdraw existing appeal first so Alice doesn't have pending
    await apiPost(alicePage, ALICE_KEY, `/v1/appeals/${appealId}/withdraw`, {});
    // Bob tries to appeal Alice's enforcement
    const resp = await apiPost(bobPage, BOB_KEY, "/v1/appeals", {
      enforcement_id: enfId2,
      appeal_text: "I am Bob trying to appeal Alice's enforcement",
    });
    expect(resp.status()).toBe(404);
  });

  test("100.6 Alice lists her appeals", async () => {
    const resp = await apiGet(alicePage, "/v1/appeals");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items.length).toBeGreaterThanOrEqual(1);
    const found = data.items.find(
      (a: { appeal_id: string }) => a.appeal_id === appealId,
    );
    expect(found).toBeTruthy();
  });

  test("100.7 Alice withdraws her appeal", async () => {
    // Re-file since we withdrew in 100.5
    const enfId3 = seedEnforcement(ALICE_SUB, "warn", "s100withdraw");
    const fileResp = await apiPost(alicePage, ALICE_KEY, "/v1/appeals", {
      enforcement_id: enfId3,
      appeal_text: "Appeal to withdraw test",
    });
    expect(fileResp.status()).toBe(201);
    const filed = await fileResp.json();

    const resp = await apiPost(
      alicePage,
      ALICE_KEY,
      `/v1/appeals/${filed.appeal_id}/withdraw`,
      {},
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("withdrawn");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 101: Admin Appeal Review API
// ═══════════════════════════════════════════════════════════════════════════

test.describe("101 · Admin Appeal Review API", () => {
  let alicePage: Page;
  let rootPage: Page;
  let enfId: string;
  let appealId: string;

  test.beforeAll(async ({ browser }) => {
    clearAppeals();
    clearBan(ALICE_SUB);
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    rootPage = await newIdentityPage(browser, ROOT_KEY);

    enfId = seedEnforcement(ALICE_SUB, "warn", "s101");
    const resp = await apiPost(alicePage, ALICE_KEY, "/v1/appeals", {
      enforcement_id: enfId,
      appeal_text: `Admin review test appeal ${TS}`,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    appealId = data.appeal_id;
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await rootPage?.close();
  });

  test("101.1 Root lists submitted appeals", async () => {
    const resp = await apiGet(rootPage, "/v1/admin/appeals", {
      status: "submitted",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items.length).toBeGreaterThanOrEqual(1);
    const found = data.items.find(
      (a: { appeal_id: string }) => a.appeal_id === appealId,
    );
    expect(found).toBeTruthy();
  });

  test("101.2 Root views appeal detail", async () => {
    const resp = await apiGet(rootPage, `/v1/admin/appeals/${appealId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.appeal).toBeTruthy();
    expect(data.appeal.appeal_id).toBe(appealId);
    expect(data.enforcement_record).toBeTruthy();
    expect(data.enforcement_record.enforcement_id).toBe(enfId);
  });

  test("101.3 Root claims appeal for review", async () => {
    const resp = await apiPost(
      rootPage,
      ROOT_KEY,
      `/v1/admin/appeals/${appealId}/claim`,
      {},
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.assigned_admin_user_id).toBe(ROOT_SUB);
  });

  test("101.4 Appeal status is now under_review", async () => {
    const resp = await apiGet(rootPage, `/v1/admin/appeals/${appealId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.appeal.status).toBe("under_review");
  });

  test("101.5 Root upholds appeal", async () => {
    const resp = await apiPost(
      rootPage,
      ROOT_KEY,
      `/v1/admin/appeals/${appealId}/decide`,
      {
        decision: "upheld",
        decision_note: "Enforcement was appropriate",
      },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("decided_upheld");
    expect(data.decision).toBe("upheld");
    expect(data.decided_at).toBeGreaterThan(0);
  });

  test("101.6 Root reverses ban enforcement via appeal", async () => {
    const banEnfId = seedEnforcement(ALICE_SUB, "ban", "s101rev");

    // File appeal BEFORE banning, since banned users get 403
    const fileResp = await apiPost(alicePage, ALICE_KEY, "/v1/appeals", {
      enforcement_id: banEnfId,
      appeal_text: "Please reverse my ban",
    });
    expect(fileResp.status()).toBe(201);
    const filed = await fileResp.json();

    // Now apply the ban
    seedBan(ALICE_SUB, "s101rev");

    // Claim
    await apiPost(
      rootPage,
      ROOT_KEY,
      `/v1/admin/appeals/${filed.appeal_id}/claim`,
      {},
    );

    // Reverse
    const resp = await apiPost(
      rootPage,
      ROOT_KEY,
      `/v1/admin/appeals/${filed.appeal_id}/decide`,
      {
        decision: "reversed",
        decision_note: "Ban was applied in error",
      },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.enforcement_reversed).toBe(true);
    expect(data.status).toBe("decided_reversed");
  });

  test("101.7 Alice is no longer banned after reversal", async () => {
    // Verify Alice can access protected endpoint
    const resp = await apiGet(alicePage, "/v1/appeals");
    expect(resp.status()).toBe(200);
  });

  test("101.8 Root views queue stats", async () => {
    const resp = await apiGet(rootPage, "/v1/admin/appeals/stats");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.total_submitted).toBe("number");
    expect(typeof data.total_under_review).toBe("number");
    expect(typeof data.oldest_submitted_age_minutes).toBe("number");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 102: Rate Limiting
// ═══════════════════════════════════════════════════════════════════════════

test.describe("102 · Appeal Rate Limiting", () => {
  let alicePage: Page;
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    clearAppeals();
    clearBan(ALICE_SUB);
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    rootPage = await newIdentityPage(browser, ROOT_KEY);
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await rootPage?.close();
  });

  test("102.1 One appeal per enforcement action", async () => {
    const enfId = seedEnforcement(ALICE_SUB, "warn", "s102dup");
    const resp1 = await apiPost(alicePage, ALICE_KEY, "/v1/appeals", {
      enforcement_id: enfId,
      appeal_text: "First appeal for this enforcement",
    });
    expect(resp1.status()).toBe(201);

    const resp2 = await apiPost(alicePage, ALICE_KEY, "/v1/appeals", {
      enforcement_id: enfId,
      appeal_text: "Second appeal attempt",
    });
    expect(resp2.status()).toBe(409);
  });

  test("102.2 One pending appeal at a time", async () => {
    const enfId2 = seedEnforcement(ALICE_SUB, "warn", "s102pending");
    const resp = await apiPost(alicePage, ALICE_KEY, "/v1/appeals", {
      enforcement_id: enfId2,
      appeal_text: "Another appeal while first is pending",
    });
    expect(resp.status()).toBe(429);
  });

  test("102.3 Can file new appeal after previous resolved", async () => {
    // Get the pending appeal and have admin resolve it
    const listResp = await apiGet(alicePage, "/v1/appeals");
    const items = (await listResp.json()).items;
    const pending = items.find(
      (a: { status: string }) =>
        a.status === "submitted" || a.status === "under_review",
    );
    expect(pending).toBeTruthy();

    // Admin claims and upholds
    await apiPost(
      rootPage,
      ROOT_KEY,
      `/v1/admin/appeals/${pending.appeal_id}/claim`,
      {},
    );
    await apiPost(
      rootPage,
      ROOT_KEY,
      `/v1/admin/appeals/${pending.appeal_id}/decide`,
      { decision: "upheld", decision_note: "Resolved for rate limit test" },
    );

    // Now Alice can file a new appeal
    const enfId3 = seedEnforcement(ALICE_SUB, "warn", "s102after");
    const resp = await apiPost(alicePage, ALICE_KEY, "/v1/appeals", {
      enforcement_id: enfId3,
      appeal_text: "New appeal after previous resolved",
    });
    expect(resp.status()).toBe(201);
  });

  test("102.4 Can re-file after withdrawal", async () => {
    // First, resolve the pending appeal from 102.3
    const listResp = await apiGet(alicePage, "/v1/appeals");
    const items = (await listResp.json()).items;
    const pending = items.find(
      (a: { status: string }) => a.status === "submitted",
    );
    if (pending) {
      await apiPost(
        alicePage,
        ALICE_KEY,
        `/v1/appeals/${pending.appeal_id}/withdraw`,
        {},
      );
    }

    const enfId4 = seedEnforcement(ALICE_SUB, "warn", "s102refile");
    // File and withdraw
    const resp1 = await apiPost(alicePage, ALICE_KEY, "/v1/appeals", {
      enforcement_id: enfId4,
      appeal_text: "Appeal to withdraw then refile",
    });
    expect(resp1.status()).toBe(201);
    const filed = await resp1.json();

    await apiPost(
      alicePage,
      ALICE_KEY,
      `/v1/appeals/${filed.appeal_id}/withdraw`,
      {},
    );

    // Re-file for same enforcement
    const resp2 = await apiPost(alicePage, ALICE_KEY, "/v1/appeals", {
      enforcement_id: enfId4,
      appeal_text: "Re-filed after withdrawal",
    });
    expect(resp2.status()).toBe(201);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 103: Appeal Lifecycle
// ═══════════════════════════════════════════════════════════════════════════

test.describe("103 · Appeal Lifecycle", () => {
  let alicePage: Page;
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    clearAppeals();
    clearBan(ALICE_SUB);
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    rootPage = await newIdentityPage(browser, ROOT_KEY);
  });

  test.afterAll(async () => {
    clearBan(ALICE_SUB);
    await alicePage?.close();
    await rootPage?.close();
  });

  test("103.1 Full lifecycle: submit → claim → uphold", async () => {
    const enfId = seedEnforcement(ALICE_SUB, "warn", "s103full");
    // Submit
    const submitResp = await apiPost(alicePage, ALICE_KEY, "/v1/appeals", {
      enforcement_id: enfId,
      appeal_text: "Full lifecycle test appeal",
    });
    expect(submitResp.status()).toBe(201);
    const { appeal_id } = await submitResp.json();

    // Claim
    const claimResp = await apiPost(
      rootPage,
      ROOT_KEY,
      `/v1/admin/appeals/${appeal_id}/claim`,
      {},
    );
    expect(claimResp.status()).toBe(200);

    // Decide - uphold
    const decideResp = await apiPost(
      rootPage,
      ROOT_KEY,
      `/v1/admin/appeals/${appeal_id}/decide`,
      { decision: "upheld", decision_note: "Enforcement appropriate" },
    );
    expect(decideResp.status()).toBe(200);
    const result = await decideResp.json();
    expect(result.status).toBe("decided_upheld");
    expect(result.enforcement_reversed).toBe(false);
    expect(result.enforcement_modified).toBe(false);
  });

  test("103.2 Cannot decide appeal that is not under_review", async () => {
    const enfId = seedEnforcement(ALICE_SUB, "warn", "s103state");
    const submitResp = await apiPost(alicePage, ALICE_KEY, "/v1/appeals", {
      enforcement_id: enfId,
      appeal_text: "State transition test",
    });
    const { appeal_id } = await submitResp.json();

    // Try to decide without claiming first
    const resp = await apiPost(
      rootPage,
      ROOT_KEY,
      `/v1/admin/appeals/${appeal_id}/decide`,
      { decision: "upheld" },
    );
    expect(resp.status()).toBe(409);
  });

  test("103.3 Cannot withdraw decided appeal", async () => {
    // Get the upheld appeal from 103.1
    const listResp = await apiGet(alicePage, "/v1/appeals");
    const items = (await listResp.json()).items;
    const upheld = items.find(
      (a: { status: string }) => a.status === "decided_upheld",
    );
    expect(upheld).toBeTruthy();

    const resp = await apiPost(
      alicePage,
      ALICE_KEY,
      `/v1/appeals/${upheld.appeal_id}/withdraw`,
      {},
    );
    expect(resp.status()).toBe(409);
  });

  test("103.4 Modify ban duration via appeal", async () => {
    // First resolve pending appeal from 103.2
    const listResp = await apiGet(alicePage, "/v1/appeals");
    const items = (await listResp.json()).items;
    const pending = items.find(
      (a: { status: string }) => a.status === "submitted",
    );
    if (pending) {
      await apiPost(
        alicePage,
        ALICE_KEY,
        `/v1/appeals/${pending.appeal_id}/withdraw`,
        {},
      );
    }

    const banEnfId = seedEnforcement(ALICE_SUB, "ban", "s103mod");

    // File appeal BEFORE banning — banned users get 403
    const submitResp = await apiPost(alicePage, ALICE_KEY, "/v1/appeals", {
      enforcement_id: banEnfId,
      appeal_text: "Please reduce my permanent ban",
    });
    expect(submitResp.status()).toBe(201);
    const { appeal_id } = await submitResp.json();

    seedBan(ALICE_SUB, "s103mod");

    await apiPost(
      rootPage,
      ROOT_KEY,
      `/v1/admin/appeals/${appeal_id}/claim`,
      {},
    );

    const resp = await apiPost(
      rootPage,
      ROOT_KEY,
      `/v1/admin/appeals/${appeal_id}/decide`,
      {
        decision: "modified",
        decision_note: "Reducing to 30-day ban",
        modified_duration_days: 30,
      },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.enforcement_modified).toBe(true);
    expect(data.status).toBe("decided_modified");
  });

  test("103.5 Appeal text validation - too short", async () => {
    clearBan(ALICE_SUB);
    // First resolve any pending
    const listResp = await apiGet(alicePage, "/v1/appeals");
    const items = (await listResp.json()).items;
    const pending = items.find(
      (a: { status: string }) =>
        a.status === "submitted" || a.status === "under_review",
    );
    if (pending) {
      await apiPost(
        alicePage,
        ALICE_KEY,
        `/v1/appeals/${pending.appeal_id}/withdraw`,
        {},
      );
    }

    const enfId = seedEnforcement(ALICE_SUB, "warn", "s103short");
    const resp = await apiPost(alicePage, ALICE_KEY, "/v1/appeals", {
      enforcement_id: enfId,
      appeal_text: "Hi",
    });
    expect(resp.status()).toBe(422);
  });
});
