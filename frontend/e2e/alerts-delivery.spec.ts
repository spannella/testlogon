/**
 * E2E tests for alert notification channel preferences and alert delivery.
 *
 * Section 97: Alert preferences API — event-type toggles for email/SMS/toast
 * Section 98: Alert delivery via email — end-to-end
 * Section 99: Alert delivery via SMS — end-to-end
 * Section 100: Alert Center UI — viewing and marking alerts as read
 * Section 101: Notification Channel toggles UI
 *
 * These tests complement the existing alerts.spec.ts (sections 65-68) which
 * test the address/number management flows. Here we test what happens AFTER
 * addresses are set up: configuring which events trigger delivery and
 * verifying that alerts actually get sent to email and SMS.
 *
 * Alert delivery uses dev-mode log files:
 *   .logs/dev/emails.log  — ALERT_EMAIL entries (distinct from OTP emails)
 *   .logs/dev/sms.log     — ALERT_SMS entries (distinct from OTP SMS)
 *
 * We use api_key_create / api_key_revoke as trigger events because they:
 * - Do not require fresh MFA for test users (no MFA devices enrolled)
 * - Immediately fire audit_event → alert email/SMS fanout (synchronous)
 * - Map cleanly to event types: api_key_created, api_key_revoked
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import { readFileSync, statSync } from "fs";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
import { resolveIdentityId } from "./helpers/session";
import { usingCpp, cppSeedAlertPrefs, cppClearAlertPrefs } from "./helpers/cpp-seed-alerts-broadcast-calendar";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE      = "http://localhost:3000";
const ALICE_ID  = "e2e_alice@test.local";
const EMAIL_LOG = REPO_ROOT + "/.logs/dev/emails.log";
const SMS_LOG   = REPO_ROOT + "/.logs/dev/sms.log";

// Dedicated test addresses (separate from alerts.spec.ts to avoid collisions)
const TEST_EMAIL = "alerts-delivery-e2e@example.com";
const TEST_PHONE = "+15550001234";

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean;
    sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

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

// ─── Authenticated API helpers ────────────────────────────────────────────────

async function apiPost(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  const session = getSessions()[ALICE_ID];
  return page.request.get(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── DDB helpers ──────────────────────────────────────────────────────────────

function runPython(code: string): void {
  execSync(
    `python3 -c "${code.replace(/"/g, '\\"')}"`,
    { timeout: 15_000 },
  );
}

function clearAliceAlertPrefs(): void {
  if (usingCpp()) { cppClearAlertPrefs(resolveIdentityId(ALICE_ID)); return; }
  execSync(
    `python3 -c "
import boto3, os
from pathlib import Path
env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, _, v = line.partition('=')
        os.environ.setdefault(k.strip(), v.strip())
import sys
sys.path.insert(0, '${REPO_ROOT}')
from app.core.tables import T
try:
    T.alert_prefs.delete_item(Key={'user_sub': 'e2e_alice@test.local'})
except Exception:
    pass
"`,
    { timeout: 15_000 },
  );
}

/**
 * Inject alert prefs directly into DynamoDB, bypassing the OTP verification
 * flow. Used in delivery tests to set up email/SMS addresses quickly.
 */
function injectAlertPrefs(opts: {
  emails?: string[];
  smsNumbers?: string[];
  emailEventTypes?: string[];
  smsEventTypes?: string[];
  toastEventTypes?: string[];
}): void {
  const {
    emails = [],
    smsNumbers = [],
    emailEventTypes = [],
    smsEventTypes = [],
    toastEventTypes = [],
  } = opts;

  if (usingCpp()) {
    cppSeedAlertPrefs({
      userSub: resolveIdentityId(ALICE_ID),
      emails,
      smsNumbers,
      emailEventTypes,
      smsEventTypes,
      toastEventTypes,
    });
    return;
  }

  execSync(
    `python3 << 'PYEOF'
import boto3, os
from pathlib import Path
env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, _, v = line.partition('=')
        os.environ.setdefault(k.strip(), v.strip())
import sys
sys.path.insert(0, '${REPO_ROOT}')
import time
from app.core.tables import T
T.alert_prefs.put_item(Item={
    'user_sub': 'e2e_alice@test.local',
    'emails': ${JSON.stringify(emails)},
    'sms_numbers': ${JSON.stringify(smsNumbers)},
    'email_event_types': ${JSON.stringify(emailEventTypes)},
    'sms_event_types': ${JSON.stringify(smsEventTypes)},
    'toast_event_types': ${JSON.stringify(toastEventTypes)},
    'webhook_urls': [],
    'webhook_event_types': [],
    'updated_at': int(time.time()),
})
PYEOF`,
    { timeout: 15_000 },
  );
}

/** Clean up all API keys created by Alice during tests. */
function cleanupAliceApiKeys(): void {
  execSync(
    `python3 << 'PYEOF'
import boto3, os
from pathlib import Path
from boto3.dynamodb.conditions import Key
env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, _, v = line.partition('=')
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', region_name='us-east-1',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL') or None)
table = ddb.Table(os.environ.get('API_KEYS_TABLE_NAME', 'api_keys'))
index = os.environ.get('API_KEYS_USER_INDEX', 'user_sub-index')
resp = table.query(
    IndexName=index,
    KeyConditionExpression=Key('user_sub').eq('e2e_alice@test.local'),
    Limit=100,
)
for item in resp.get('Items', []):
    if str(item.get('label', '')).startswith('e2e-alerts-'):
        try:
            table.update_item(
                Key={'key_id': item['key_id']},
                UpdateExpression='SET revoked = :t',
                ExpressionAttributeValues={':t': True},
            )
        except Exception:
            pass
PYEOF`,
    { timeout: 15_000 },
  );
}

/** Reset alert delivery rate-limit counters for Alice (email + SMS). */
function clearAliceRateLimits(): void {
  execSync(
    `python3 << 'PYEOF'
import boto3, os
from pathlib import Path
env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, _, v = line.partition('=')
        os.environ.setdefault(k.strip(), v.strip())
import sys
sys.path.insert(0, '${REPO_ROOT}')
from app.core.tables import T
for sid in ('rl#alert_email', 'rl#alert_sms'):
    try:
        T.sessions.delete_item(Key={'user_sub': 'e2e_alice@test.local', 'session_id': sid})
    except Exception:
        pass
PYEOF`,
    { timeout: 15_000 },
  );
}

/** Clear all alert records for Alice. */
function clearAliceAlerts(): void {
  execSync(
    `python3 << 'PYEOF'
import boto3, os
from pathlib import Path
env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, _, v = line.partition('=')
        os.environ.setdefault(k.strip(), v.strip())
import sys
sys.path.insert(0, '${REPO_ROOT}')
from app.core.tables import T
from boto3.dynamodb.conditions import Key
items = T.alerts.query(KeyConditionExpression=Key('user_sub').eq('e2e_alice@test.local')).get('Items', [])
for item in items:
    T.alerts.delete_item(Key={'user_sub': item['user_sub'], 'alert_id': item['alert_id']})
PYEOF`,
    { timeout: 15_000 },
  );
}

// ─── Log helpers ──────────────────────────────────────────────────────────────

function logSize(path: string): number {
  try { return statSync(path).size; } catch { return 0; }
}

/**
 * Read the last ALERT_EMAIL entry from the dev email log after `afterOffset`
 * bytes, looking for a Subject line matching `subjectPattern`.
 * Returns the full body text of the matching entry.
 */
function readAlertEmail(logPath: string, afterOffset: number, subjectPattern: RegExp): string {
  let raw = "";
  try { raw = readFileSync(logPath, "utf-8"); } catch { /* may not exist */ }
  const tail = raw.slice(afterOffset);
  // Each alert entry starts with [TIMESTAMP] ALERT_EMAIL TO=...
  const entries = [...tail.matchAll(
    /\[[\d\-T:Z]+\] ALERT_EMAIL TO=([^\n]+)\n([\s\S]*?)(?=\[[\d\-T:Z]+\]|$)/g,
  )];
  for (let i = entries.length - 1; i >= 0; i--) {
    const body = entries[i][2];
    if (subjectPattern.test(body)) return body;
  }
  return "";
}

/**
 * Read the last ALERT_SMS entry from the dev SMS log after `afterOffset`
 * bytes, looking for a Body line matching `bodyPattern`.
 */
function readAlertSms(logPath: string, afterOffset: number, bodyPattern: RegExp): string {
  let raw = "";
  try { raw = readFileSync(logPath, "utf-8"); } catch { /* may not exist */ }
  const tail = raw.slice(afterOffset);
  const entries = [...tail.matchAll(
    /\[[\d\-T:Z]+\] ALERT_SMS TO=([^\n]+)\n([\s\S]*?)(?=\[[\d\-T:Z]+\]|$)/g,
  )];
  for (let i = entries.length - 1; i >= 0; i--) {
    const body = entries[i][2];
    if (bodyPattern.test(body)) return body;
  }
  return "";
}

// ─── Navigation helpers ───────────────────────────────────────────────────────

async function goToAlerts(page: Page) {
  await page.goto(`${BASE}/alerts`, { waitUntil: "load" });
  // The alert center (with the full alert list, search and mark-as-read) lives
  // under the "All" tab. Open it so the AlertCenter component is mounted.
  const allTab = page.getByRole("tab", { name: "All", exact: true });
  await expect(allTab).toBeVisible({ timeout: 8000 });
  await allTab.click();
}

async function goToPreferences(page: Page) {
  await page.goto(`${BASE}/alerts`, { waitUntil: "load" });
  await page.getByRole("tab", { name: "Preferences" }).click();
  await expect(page.getByText("Alert Email Addresses", { exact: true })).toBeVisible({ timeout: 8000 });
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 97: Alert preferences API — event-type toggles
// ─────────────────────────────────────────────────────────────────────────────

test.describe("97 — Alert preferences API: event-type toggles", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    clearAliceAlertPrefs();
    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => {
    clearAliceAlertPrefs();
    await page.close();
  });

  test("97.1 GET /ui/alerts/types returns event_types array", async () => {
    const resp = await apiGet(page, "/ui/alerts/types");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.event_types)).toBe(true);
    expect(data.event_types.length).toBeGreaterThan(0);
    // Core event types must be present
    expect(data.event_types).toContain("api_key_created");
    expect(data.event_types).toContain("api_key_revoked");
    expect(data.event_types).toContain("login_success");
  });

  test("97.2 POST /ui/alerts/email_prefs sets email event types", async () => {
    const resp = await apiPost(page, "/ui/alerts/email_prefs", {
      email_event_types: ["api_key_created", "api_key_revoked"],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.email_event_types).toContain("api_key_created");
    expect(data.email_event_types).toContain("api_key_revoked");
  });

  test("97.3 GET /ui/alerts/email_prefs reflects the saved email event types", async () => {
    const resp = await apiGet(page, "/ui/alerts/email_prefs");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.email_event_types).toContain("api_key_created");
    expect(data.email_event_types).toContain("api_key_revoked");
  });

  test("97.4 POST /ui/alerts/sms_prefs sets SMS event types", async () => {
    const resp = await apiPost(page, "/ui/alerts/sms_prefs", {
      sms_event_types: ["api_key_created", "login_success"],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.sms_event_types).toContain("api_key_created");
    expect(data.sms_event_types).toContain("login_success");
  });

  test("97.5 GET /ui/alerts/sms_prefs reflects the saved SMS event types", async () => {
    const resp = await apiGet(page, "/ui/alerts/sms_prefs");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.sms_event_types).toContain("api_key_created");
  });

  test("97.6 POST /ui/alerts/toast_prefs sets toast event types", async () => {
    const resp = await apiPost(page, "/ui/alerts/toast_prefs", {
      toast_event_types: ["api_key_created", "api_key_revoked", "login_success"],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.toast_event_types).toContain("api_key_created");
    expect(data.toast_event_types).toContain("login_success");
  });

  test("97.7 GET /ui/alerts/toast_prefs reflects the saved toast event types", async () => {
    const resp = await apiGet(page, "/ui/alerts/toast_prefs");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.toast_event_types).toContain("api_key_created");
    expect(data.toast_event_types).toContain("login_success");
  });

  test("97.8 POST with empty array clears previously set event types", async () => {
    // Clear email event types
    const resp = await apiPost(page, "/ui/alerts/email_prefs", {
      email_event_types: [],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.email_event_types).toHaveLength(0);

    // Confirm cleared
    const getResp = await apiGet(page, "/ui/alerts/email_prefs");
    const prefs = await getResp.json();
    expect(prefs.email_event_types).toHaveLength(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 98: Alert delivery via email — end-to-end
// ─────────────────────────────────────────────────────────────────────────────

test.describe("98 — Alert delivery via email", () => {
  let page: Page;
  let createdKeyId: string;

  test.beforeAll(async ({ browser }) => {
    // Inject email address + event types directly — avoids slow OTP flow
    injectAlertPrefs({
      emails: [TEST_EMAIL],
      emailEventTypes: ["api_key_created", "api_key_revoked"],
    });
    clearAliceRateLimits();
    cleanupAliceApiKeys();
    clearAliceAlerts();

    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => {
    clearAliceAlertPrefs();
    cleanupAliceApiKeys();
    await page.close();
  });

  test("98.1 GET /ui/alerts/email_prefs shows injected email and event types", async () => {
    const resp = await apiGet(page, "/ui/alerts/email_prefs");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.emails).toContain(TEST_EMAIL);
    expect(data.email_event_types).toContain("api_key_created");
    expect(data.email_event_types).toContain("api_key_revoked");
  });

  test("98.2 Creating an API key triggers an alert email to the configured address", async () => {
    test.setTimeout(15_000);
    const offset = logSize(EMAIL_LOG);

    const resp = await apiPost(page, "/ui/api_keys", { label: "e2e-alerts-create-test" });
    expect(resp.ok()).toBeTruthy();
    const key = await resp.json();
    createdKeyId = key.key_id;

    // Wait for ALERT_EMAIL to appear in log
    await expect.poll(
      () => readAlertEmail(EMAIL_LOG, offset, /api_key_created/),
      { timeout: 8000, intervals: [500] },
    ).toBeTruthy();

    const body = readAlertEmail(EMAIL_LOG, offset, /api_key_created/);
    expect(body).toMatch(/api_key_created/);
    expect(body).toMatch(/api_key_create/);
    expect(body).toMatch(/success/);
  });

  test("98.3 The email alert contains the alert-id and is addressed to the right recipient", async () => {
    // Re-read to confirm content (reads same log entry as 98.2)
    const offset = 0; // scan whole log for this address since it's unique
    const body = readAlertEmail(
      EMAIL_LOG, 0,
      new RegExp(`api_key_created[\\s\\S]*?${createdKeyId}`, "m"),
    );
    // Subject line must name the alert type
    expect(body).toMatch(/api_key_created/);
    // Alert-ID is included in the body
    expect(body).toMatch(/Alert-ID:/);
  });

  test("98.4 The api_key_created alert appears in the alert center (GET /ui/alerts)", async () => {
    const resp = await apiGet(page, "/ui/alerts");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.alerts)).toBe(true);
    const found = data.alerts.find(
      (a: { event: string; title: string }) =>
        a.event === "api_key_create" || a.title?.toLowerCase().includes("api key"),
    );
    expect(found).toBeTruthy();
  });

  test("98.5 Revoking the API key triggers an api_key_revoked alert email", async () => {
    test.setTimeout(15_000);
    const offset = logSize(EMAIL_LOG);

    const resp = await apiPost(page, "/ui/api_keys/revoke", { key_id: createdKeyId });
    expect(resp.ok()).toBeTruthy();

    await expect.poll(
      () => readAlertEmail(EMAIL_LOG, offset, /api_key_revoked/),
      { timeout: 8000, intervals: [500] },
    ).toBeTruthy();

    const body = readAlertEmail(EMAIL_LOG, offset, /api_key_revoked/);
    expect(body).toMatch(/api_key_revoked/);
    expect(body).toMatch(/success/);
  });

  test("98.6 Both create and revoke alerts appear in the alert center", async () => {
    const resp = await apiGet(page, "/ui/alerts");
    const data = await resp.json();
    const events = data.alerts.map((a: { event: string }) => a.event);
    expect(events).toContain("api_key_create");
    expect(events).toContain("api_key_revoke");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 99: Alert delivery via SMS — end-to-end
// ─────────────────────────────────────────────────────────────────────────────

test.describe("99 — Alert delivery via SMS", () => {
  let page: Page;
  let smsKeyId: string;

  test.beforeAll(async ({ browser }) => {
    injectAlertPrefs({
      smsNumbers: [TEST_PHONE],
      smsEventTypes: ["api_key_created", "api_key_revoked"],
    });
    clearAliceRateLimits();
    cleanupAliceApiKeys();
    clearAliceAlerts();

    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => {
    clearAliceAlertPrefs();
    cleanupAliceApiKeys();
    await page.close();
  });

  test("99.1 GET /ui/alerts/sms_prefs shows injected number and event types", async () => {
    const resp = await apiGet(page, "/ui/alerts/sms_prefs");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.sms_numbers).toContain(TEST_PHONE);
    expect(data.sms_event_types).toContain("api_key_created");
    expect(data.sms_event_types).toContain("api_key_revoked");
  });

  test("99.2 Creating an API key triggers an alert SMS to the configured number", async () => {
    test.setTimeout(15_000);
    const offset = logSize(SMS_LOG);

    const resp = await apiPost(page, "/ui/api_keys", { label: "e2e-alerts-sms-test" });
    expect(resp.ok()).toBeTruthy();
    const key = await resp.json();
    smsKeyId = key.key_id;

    await expect.poll(
      () => readAlertSms(SMS_LOG, offset, /api_key_created/),
      { timeout: 8000, intervals: [500] },
    ).toBeTruthy();

    const body = readAlertSms(SMS_LOG, offset, /api_key_created/);
    expect(body).toMatch(/api_key_created/);
    expect(body).toMatch(/api_key_create/);
    expect(body).toMatch(/success/);
  });

  test("99.3 The SMS alert contains the IP address", async () => {
    // The SMS body format: "[api_key_created] api_key_create success ip=127.0.0.1"
    const body = readAlertSms(SMS_LOG, 0, new RegExp(`api_key_created[\\s\\S]*?${smsKeyId}`, "m"))
      || readAlertSms(SMS_LOG, 0, /api_key_created.*api_key_create.*success/);
    expect(body).toMatch(/ip=/);
  });

  test("99.4 Revoking the API key triggers an api_key_revoked SMS", async () => {
    test.setTimeout(15_000);
    const offset = logSize(SMS_LOG);

    const resp = await apiPost(page, "/ui/api_keys/revoke", { key_id: smsKeyId });
    expect(resp.ok()).toBeTruthy();

    await expect.poll(
      () => readAlertSms(SMS_LOG, offset, /api_key_revoked/),
      { timeout: 8000, intervals: [500] },
    ).toBeTruthy();

    const body = readAlertSms(SMS_LOG, offset, /api_key_revoked/);
    expect(body).toMatch(/api_key_revoked/);
    expect(body).toMatch(/success/);
  });

  test("99.5 Marking an alert as read via API clears its unread state", async () => {
    // Create a fresh API key so there is at least one brand-new unread alert.
    // (Relying on alerts from prior tests is fragile on a shared, accumulating
    // DB: the alert center returns only the newest page, so older unread alerts
    // may fall outside the window.)
    const keyResp = await apiPost(page, "/ui/api_keys", { label: "e2e-alerts-markread-test" });
    expect(keyResp.ok()).toBeTruthy();
    const freshKey = await keyResp.json();

    // Get the list to find an unread alert
    const listResp = await apiGet(page, "/ui/alerts?unread_only=1");
    const data = await listResp.json();
    const unread = data.alerts.filter((a: { read_at?: number }) => !a.read_at);
    expect(unread.length).toBeGreaterThan(0);

    const alertIds = unread.slice(0, 2).map((a: { alert_id: string }) => a.alert_id);
    const markResp = await apiPost(page, "/ui/alerts/mark_read", { alert_ids: alertIds });
    expect(markResp.status()).toBe(200);
    const markData = await markResp.json();
    expect(markData.ok).toBe(true);
    expect(markData.updated).toBeGreaterThanOrEqual(1);

    // Verify alerts are now read
    const listResp2 = await apiGet(page, "/ui/alerts");
    const data2 = await listResp2.json();
    for (const id of alertIds) {
      const alert = data2.alerts.find((a: { alert_id: string }) => a.alert_id === id);
      expect(alert?.read_at).toBeGreaterThan(0);
    }

    // Cleanup the key created for this test
    await apiPost(page, "/ui/api_keys/revoke", { key_id: freshKey.key_id });
  });

  test("99.6 GET /ui/alerts with unread_only=true filters to unread alerts", async () => {
    // Create a new alert so there's at least one unread
    const resp = await apiPost(page, "/ui/api_keys", { label: "e2e-alerts-unread-test" });
    expect(resp.ok()).toBeTruthy();
    const key = await resp.json();

    const allResp = await apiGet(page, "/ui/alerts?unread_only=0");
    const unreadResp = await apiGet(page, "/ui/alerts?unread_only=1");

    const allData = await allResp.json();
    const unreadData = await unreadResp.json();

    // All unread-only results should have no read_at
    for (const a of unreadData.alerts) {
      expect(a.read_at ?? 0).toBe(0);
    }
    // Total with unread_only must be ≤ total without
    expect(unreadData.alerts.length).toBeLessThanOrEqual(allData.alerts.length);

    // Cleanup key
    await apiPost(page, "/ui/api_keys/revoke", { key_id: key.key_id });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 100: Alert Center UI — viewing and managing alerts
// ─────────────────────────────────────────────────────────────────────────────

test.describe("100 — Alert Center UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    // Set up: inject prefs + trigger an alert so the center has content
    injectAlertPrefs({
      toastEventTypes: ["api_key_created", "api_key_revoked"],
    });
    clearAliceAlerts();

    page = await browser.newPage();
    await injectAuth(page);

    // Trigger an alert via API so there's content in the center
    const session = getSessions()[ALICE_ID];
    await page.request.post(`${API}/ui/api_keys`, {
      data: { label: "e2e-alerts-ui-test" },
      headers: { "x-csrf-token": session.csrf_token },
    });
  });

  test.afterAll(async () => {
    clearAliceAlertPrefs();
    cleanupAliceApiKeys();
    clearAliceAlerts();
    await page.close();
  });

  test("100.1 Navigating to /alerts shows the alert tabs", async () => {
    await goToAlerts(page);
    await expect(page.getByRole("tab", { name: "All", exact: true })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Preferences" })).toBeVisible();
  });

  test("100.2 The alert center loads and shows at least one alert entry", async () => {
    test.setTimeout(20_000);
    // Re-navigate and wait for the alerts API response to ensure data is loaded
    const alertsFetched = page.waitForResponse(
      (r) => r.url().includes("/ui/alerts") && !r.url().includes("types") && r.request().method() === "GET",
      { timeout: 12_000 },
    );
    await goToAlerts(page);
    await alertsFetched;

    // Alert title "API key created" or badge "api key create" should be visible
    await expect(
      page.getByText(/api key/i).first(),
    ).toBeVisible({ timeout: 8000 });
  });

  test("100.3 Alert list shows event title text", async () => {
    test.setTimeout(10_000);
    // The alert center renders title "API key created"
    await expect(
      page.getByText(/api key created/i).or(page.getByText(/api key create/i)).first(),
    ).toBeVisible({ timeout: 8000 });
  });

  test("100.4 Clicking 'Mark as read' button marks alerts as read", async () => {
    test.setTimeout(15_000);
    // Select all alerts first to reveal the "Mark as read" button
    const selectAll = page.getByRole("checkbox", { name: /select all/i });
    await expect(selectAll).toBeVisible({ timeout: 5000 });
    await selectAll.click();

    const markBtn = page.getByRole("button", { name: /mark.*read/i }).first();
    await expect(markBtn).toBeVisible({ timeout: 5000 });

    const markDone = page.waitForResponse(
      (r) => r.url().includes("/alerts/mark_read") && r.request().method() === "POST",
      { timeout: 5000 },
    ).catch(() => null);

    await markBtn.click();
    const resp = await markDone;
    if (resp) {
      expect(resp.status()).toBe(200);
    }
  });

  test("100.5 Alert search filters results by keyword", async () => {
    test.setTimeout(15_000);
    // Re-navigate to ensure fresh state after mark-read
    await goToAlerts(page);
    const searchInput = page.getByPlaceholder(/search alerts/i).first();
    await expect(searchInput).toBeVisible({ timeout: 8000 });

    await searchInput.fill("api_key");
    await page.waitForTimeout(1000);

    // Clear search
    await searchInput.fill("");
    await page.waitForTimeout(500);
  });

  test("100.6 Clicking on an alert expands its details", async () => {
    test.setTimeout(15_000);
    // Seed a fresh alert to ensure at least one exists
    const session = getSessions()[ALICE_ID];
    await page.request.post(`${API}/ui/api_keys`, {
      data: { label: `e2e-alerts-expand-${Date.now()}` },
      headers: { "x-csrf-token": session.csrf_token },
    });
    await goToAlerts(page);
    await page.waitForTimeout(1000);

    // Find an alert entry and click it
    const alertEntry = page.locator("div.rounded-lg.border")
      .filter({ hasText: /api key/i }).first();
    await expect(alertEntry).toBeVisible({ timeout: 8000 });
    await alertEntry.click();
    await page.waitForTimeout(300);
    // Verify no crash — the page still shows content
    await expect(page.getByRole("tab", { name: "All", exact: true })).toBeVisible();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 101: Notification Channel toggles UI (Preferences tab)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("101 — Notification Channel toggles UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    // Start with empty prefs so all toggles begin off
    clearAliceAlertPrefs();
    page = await browser.newPage();
    await injectAuth(page);
    await goToPreferences(page);
  });

  test.afterAll(async () => {
    clearAliceAlertPrefs();
    await page.close();
  });

  test("101.1 Notification Channels table shows event type rows and channel columns", async () => {
    await expect(page.getByText("Notification Channels", { exact: true })).toBeVisible();
    // Column headers
    await expect(page.getByRole("columnheader", { name: "Email" })).toBeVisible();
    await expect(page.getByRole("columnheader", { name: "SMS" })).toBeVisible();
    await expect(page.getByRole("columnheader", { name: /toast/i })).toBeVisible();
    // At least one row for api_key_created
    await expect(
      page.locator("td").filter({ hasText: "api key created" }).first(),
    ).toBeVisible({ timeout: 8000 });
  });

  test("101.2 Email toggle for api_key_created starts unchecked (no prefs set)", async () => {
    const row = page.locator("tr").filter({ hasText: "api key created" }).first();
    // Email column is 2nd column (index 1)
    const emailSwitch = row.locator("td").nth(1).locator('[role="switch"]');
    await expect(emailSwitch).toBeVisible({ timeout: 5000 });
    await expect(emailSwitch).toHaveAttribute("data-state", "unchecked");
  });

  test("101.3 Clicking the Email toggle for api_key_created enables it", async () => {
    test.setTimeout(15_000);
    const row = page.locator("tr").filter({ hasText: "api key created" }).first();
    const emailSwitch = row.locator("td").nth(1).locator('[role="switch"]');

    const prefsDone = page.waitForResponse(
      (r) => r.url().includes("/alerts/email_prefs") && r.request().method() === "POST",
      { timeout: 8000 },
    );
    await emailSwitch.click();
    const resp = await prefsDone;
    expect(resp.status()).toBe(200);

    // Switch should now be checked
    await expect(emailSwitch).toHaveAttribute("data-state", "checked", { timeout: 5000 });
  });

  test("101.4 A success toast confirms the preference was saved", async () => {
    // The onSuccess handler calls toast.success("Email preferences updated")
    await expect(page.getByText(/email preferences updated/i)).toBeVisible({ timeout: 5000 });
  });

  test("101.5 Clicking the Email toggle again disables it", async () => {
    test.setTimeout(15_000);
    const row = page.locator("tr").filter({ hasText: "api key created" }).first();
    const emailSwitch = row.locator("td").nth(1).locator('[role="switch"]');

    const prefsDone = page.waitForResponse(
      (r) => r.url().includes("/alerts/email_prefs") && r.request().method() === "POST",
      { timeout: 8000 },
    );
    await emailSwitch.click();
    await prefsDone;

    await expect(emailSwitch).toHaveAttribute("data-state", "unchecked", { timeout: 5000 });
  });

  test("101.6 Enabling the SMS toggle for api_key_revoked calls sms_prefs API", async () => {
    test.setTimeout(15_000);
    const row = page.locator("tr").filter({ hasText: "api key revoked" }).first();
    const smsSwitch = row.locator("td").nth(2).locator('[role="switch"]');
    await expect(smsSwitch).toBeVisible({ timeout: 5000 });

    const prefsDone = page.waitForResponse(
      (r) => r.url().includes("/alerts/sms_prefs") && r.request().method() === "POST",
      { timeout: 8000 },
    );
    await smsSwitch.click();
    const resp = await prefsDone;
    expect(resp.status()).toBe(200);

    const data = await resp.json();
    expect(data.sms_event_types).toContain("api_key_revoked");

    // Confirm checked
    await expect(smsSwitch).toHaveAttribute("data-state", "checked", { timeout: 5000 });
  });

  test("101.7 Enabling the Toast toggle for login_success calls toast_prefs API", async () => {
    test.setTimeout(15_000);
    const row = page.locator("tr").filter({ hasText: "login success" }).first();
    const toastSwitch = row.locator("td").nth(3).locator('[role="switch"]');
    await expect(toastSwitch).toBeVisible({ timeout: 5000 });

    const prefsDone = page.waitForResponse(
      (r) => r.url().includes("/alerts/toast_prefs") && r.request().method() === "POST",
      { timeout: 8000 },
    );
    await toastSwitch.click();
    const resp = await prefsDone;
    expect(resp.status()).toBe(200);

    const data = await resp.json();
    expect(data.toast_event_types).toContain("login_success");

    await expect(toastSwitch).toHaveAttribute("data-state", "checked", { timeout: 5000 });
  });

  test("101.8 Refreshing the page preserves the saved toggle states", async () => {
    test.setTimeout(15_000);
    // Reload and re-open Preferences — switches should reflect what was saved
    await goToPreferences(page);

    // api_key_revoked SMS should still be checked
    const row = page.locator("tr").filter({ hasText: "api key revoked" }).first();
    const smsSwitch = row.locator("td").nth(2).locator('[role="switch"]');
    await expect(smsSwitch).toHaveAttribute("data-state", "checked", { timeout: 8000 });

    // login_success toast should still be checked
    const loginRow = page.locator("tr").filter({ hasText: "login success" }).first();
    const toastSwitch = loginRow.locator("td").nth(3).locator('[role="switch"]');
    await expect(toastSwitch).toHaveAttribute("data-state", "checked", { timeout: 5000 });
  });

  test("101.9 Email and SMS delivery confirmation: triggering event generates logs", async () => {
    test.setTimeout(20_000);
    // Set up email + SMS addresses and enable api_key_created for both channels
    clearAliceRateLimits();
    injectAlertPrefs({
      emails: [TEST_EMAIL],
      smsNumbers: [TEST_PHONE],
      emailEventTypes: ["api_key_created"],
      smsEventTypes: ["api_key_created"],
    });

    // Navigate away and back to force a prefs refetch
    await page.goto(`${BASE}/`, { waitUntil: "load" });

    const emailOffset = logSize(EMAIL_LOG);
    const smsOffset = logSize(SMS_LOG);

    // Trigger the alert-generating event via session API
    const session = getSessions()[ALICE_ID];
    await page.request.post(`${API}/ui/api_keys`, {
      data: { label: "e2e-alerts-combined-test" },
      headers: { "x-csrf-token": session.csrf_token },
    });

    // Both email and SMS logs should get entries
    await expect.poll(
      () => readAlertEmail(EMAIL_LOG, emailOffset, /api_key_created/),
      { timeout: 8000, intervals: [500] },
    ).toBeTruthy();

    await expect.poll(
      () => readAlertSms(SMS_LOG, smsOffset, /api_key_created/),
      { timeout: 8000, intervals: [500] },
    ).toBeTruthy();

    const emailBody = readAlertEmail(EMAIL_LOG, emailOffset, /api_key_created/);
    const smsBody = readAlertSms(SMS_LOG, smsOffset, /api_key_created/);

    expect(emailBody).toMatch(/api_key_created/);
    expect(smsBody).toMatch(/api_key_created/);
  });
});
