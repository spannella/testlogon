/**
 * E2E tests — MFA code recovery via Dev Tools Log UI and billing ledger tie-out.
 *
 * Sections:
 *   79 — Email MFA: enroll via API, retrieve the OTP from the dev log UI, confirm
 *         enrollment, then drive a full login-challenge begin→verify round-trip.
 *   80 — SMS MFA: enroll via API, retrieve the code from the dev SMS log UI, confirm.
 *   81 — Billing ledger tie-out: inject known Stripe-format test events into the log
 *         file and verify the summary arithmetic (gross − fees = net) ties out in both
 *         the API and the browser Billing tab.
 *
 * Prerequisites (set in .env.local / frontend/.env.local):
 *   DEV_MODE=1                    — enables /internal/dev-tools/* and writes email/SMS logs
 *   Backend running on port 8000, Vite dev servers on port 3000 (main) and 3001 (devtools)
 */

import { tmpdir } from "os";
import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import { writeFileSync, unlinkSync, appendFileSync } from "fs";
import { randomBytes } from "crypto";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, resolveIdentityId, cppRegisterThrowaway } from "./helpers/session";
import { usingCpp, cppDeleteEmailDevices, cppDeleteSmsDevices, cppAppendBillingLog } from "./helpers/cpp-seed";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE     = "http://localhost:3000";
const DEVTOOLS = "http://localhost:3001";  // standalone devtools UI
const REPO = REPO_ROOT;

/** Stripe-format billing log that the dev-tools billing endpoint reads. */
const STRIPE_LOG = `${REPO}/.local/logs/stripe-mock.log`;

const ALICE_ID = resolveIdentityId("e2e_alice@test.local");

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  csrf_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;

function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    localStorage.setItem(
      "auth-store",
      JSON.stringify({ state: { userId: uid, accessToken: null, isAuthenticated: true }, version: 0 }),
    );
  }, userId);
}

// ─── Python / DDB helpers ─────────────────────────────────────────────────────

/** Run a Python script via a temp file (avoids shell-escaping issues). */
function runPython(script: string): void {
  const tmp = `${tmpdir()}/e2e-mfa-${randomBytes(4).toString("hex")}.py`;
  writeFileSync(tmp, script);
  try {
    execSync(`python3 ${tmp}`, { cwd: REPO, timeout: 15_000, stdio: "pipe" });
  } finally {
    try { unlinkSync(tmp); } catch { /* ignore */ }
  }
}

const DDB_PREAMBLE = `
import boto3, os, time
from boto3.dynamodb.conditions import Key
os.environ.setdefault('AWS_ACCESS_KEY_ID', 'test')
os.environ.setdefault('AWS_SECRET_ACCESS_KEY', 'test')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001')
`;

/**
 * Stamp mfa_verified_at on the given session record so that require_fresh_mfa
 * passes even when Alice has other MFA devices enrolled from concurrent test runs.
 */
function stampMfaVerified(userSub: string, sessionId: string): void {
  runPython(`${DDB_PREAMBLE}
T = ddb.Table('sessions')
T.update_item(
    Key={'user_sub': '${userSub}', 'session_id': '${sessionId}'},
    UpdateExpression='SET mfa_verified_at = :t',
    ExpressionAttributeValues={':t': int(time.time())},
)`);
}

/** Delete all email MFA devices for a user (clean slate for enrollment tests). */
function deleteEmailDevices(userSub: string): void {
  if (usingCpp()) { cppDeleteEmailDevices(userSub); return; }
  runPython(`${DDB_PREAMBLE}
T = ddb.Table('email_devices')
resp = T.query(KeyConditionExpression=Key('user_sub').eq('${userSub}'))
for item in resp.get('Items', []):
    T.delete_item(Key={'user_sub': item['user_sub'], 'email_device_id': item['email_device_id']})
`);
}

/** Delete all SMS MFA devices for a user. */
function deleteSmsDevices(userSub: string): void {
  if (usingCpp()) { cppDeleteSmsDevices(userSub); return; }
  runPython(`${DDB_PREAMBLE}
T = ddb.Table('sms_devices')
resp = T.query(KeyConditionExpression=Key('user_sub').eq('${userSub}'))
for item in resp.get('Items', []):
    T.delete_item(Key={'user_sub': item['user_sub'], 'sms_device_id': item['sms_device_id']})
`);
}

/**
 * Insert a bare login-style challenge into the sessions table.
 * Used in section 79 to test the email begin/verify round-trip without going
 * through the full login flow.
 */
function insertLoginChallenge(userSub: string, challengeId: string, factors: string[]): void {
  runPython(`${DDB_PREAMBLE}
import json
T = ddb.Table('sessions')
now = int(time.time())
T.put_item(Item={
    'user_sub': '${userSub}',
    'session_id': '${challengeId}',
    'required_factors': ${JSON.stringify(factors)},
    'passed': {},
    'pending_auth': True,
    'revoked': False,
    'created_at': now,
    'expires_at': now + 600,
    'ttl': now + 600,
})
`);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, csrf: string, path: string, body: object) {
  return page.request.post(`${API}${path}`, {
    data: JSON.stringify(body),
    headers: { "x-csrf-token": csrf, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}${path}`, { params });
}

/** Extract the first 6-digit OTP from a log message body or SMS body. */
function extractCode(text: string): string | null {
  const m = text.match(/\b(\d{6})\b/);
  return m ? m[1] : null;
}

// ═════════════════════════════════════════════════════════════════════════════
// Section 79 — Email MFA code recovery via Dev Log UI
// ═════════════════════════════════════════════════════════════════════════════

test.describe("Section 79: Email MFA via dev log UI", () => {
  let page: Page;
  let aliceSub: string;
  let csrf: string;
  let sessionId: string;
  let enrollChallengeId = "";
  let enrolledEmailDeviceId = "";
  // Under cpp, enroll email MFA on a THROWAWAY user (not shared e2e_alice) so a
  // CONFIRMED factor never MFA-gates alice's later login (suite-wide poison).
  let MFA_ID = ALICE_ID;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await browser.newPage();
    if (usingCpp()) {
      const tw = cppRegisterThrowaway("mfaemail");
      if (tw) { getSessions()[tw.email] = tw.session as unknown as SessionData; MFA_ID = tw.email; }
    }
    const session = getSessions()[MFA_ID];
    aliceSub    = session.user_sub;
    csrf        = session.csrf_token;
    sessionId   = session.cookies.find(c => c.name === "ui_session")!.value;

    // Stamp mfa_verified_at so require_fresh_mfa passes even when Alice has
    // TOTP devices enrolled by bug-fixes-2.spec.ts section 22.
    stampMfaVerified(aliceSub, sessionId);
    // Delete existing email devices so enrollment starts from a clean slate
    // and doesn't hit the device limit.
    deleteEmailDevices(aliceSub);

    await injectAuth(page, MFA_ID);
  });

  test.afterAll(async () => {
    deleteEmailDevices(aliceSub);
    await page.close();
  });

  test("79.1 begin email MFA enrollment returns challenge_id and sends email to alice", async () => {
    const resp = await apiPost(page, csrf, "/ui/mfa/email/devices/begin", {
      email: MFA_ID,
      label: "e2e-mfa-email",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json() as {
      challenge_id: string; sent_to: string[]; email_device_id: string;
    };
    expect(typeof body.challenge_id).toBe("string");
    expect(body.challenge_id.length).toBeGreaterThan(0);
    expect(body.sent_to).toContain(MFA_ID);
    expect(typeof body.email_device_id).toBe("string");
    enrollChallengeId    = body.challenge_id;
    enrolledEmailDeviceId = body.email_device_id;
  });

  test("79.2 dev tools email API shows the enrollment email with a 6-digit OTP", async () => {
    const resp = await apiGet(page, "/internal/dev-tools/email/messages", { mailbox: MFA_ID });
    expect(resp.status()).toBe(200);
    const body = await resp.json() as {
      messages: Array<{ mailbox: string; body_text: string; subject: string }>;
    };
    const msg = body.messages.find(m => m.mailbox === MFA_ID);
    expect(msg, `no email for ${MFA_ID} in dev tools`).toBeDefined();
    expect(msg!.subject).toMatch(/verification/i);
    expect(extractCode(msg!.body_text)).toMatch(/^\d{6}$/);
  });

  test("79.3 code from dev tools email confirms enrollment and issues recovery codes", async () => {
    // Re-fetch so we always use the most-recently sent code
    const emailResp = await apiGet(page, "/internal/dev-tools/email/messages", { mailbox: MFA_ID });
    const { messages } = await emailResp.json() as {
      messages: Array<{ mailbox: string; body_text: string; sent_at: string }>;
    };
    const latest = [...messages]
      .filter(m => m.mailbox === MFA_ID)
      .sort((a, b) => b.sent_at.localeCompare(a.sent_at))[0];
    const code = extractCode(latest.body_text)!;
    expect(code).toMatch(/^\d{6}$/);

    const resp = await apiPost(page, csrf, "/ui/mfa/email/devices/confirm", {
      challenge_id: enrollChallengeId,
      code,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json() as {
      ok: boolean; email_device_id: string; recovery_codes: string[];
    };
    expect(body.ok).toBe(true);
    expect(body.email_device_id).toBe(enrolledEmailDeviceId);
    // First email device → backend issues 10 recovery codes
    expect(Array.isArray(body.recovery_codes)).toBe(true);
    expect(body.recovery_codes.length).toBeGreaterThan(0);
  });

  test("79.4 enrolled email device is listed as enabled", async () => {
    const resp = await apiGet(page, "/ui/mfa/email/devices");
    expect(resp.status()).toBe(200);
    const { devices } = await resp.json() as {
      devices: Array<{ email_device_id: string; email: string; enabled: boolean; label: string }>;
    };
    const device = devices.find(d => d.email_device_id === enrolledEmailDeviceId);
    expect(device, "enrolled device not found in list").toBeDefined();
    expect(device!.enabled).toBe(true);
    expect(device!.email).toBe(MFA_ID);
    expect(device!.label).toBe("e2e-mfa-email");
  });

  test("79.5 full MFA login-challenge flow: begin sends email, dev tools shows code, verify succeeds", async () => {
    // Create a synthetic login-type challenge (simulates what POST /ui/session/start
    // would create for a user with email MFA required).
    const challengeId = `e2e-login-chal-${Date.now()}`;
    insertLoginChallenge(aliceSub, challengeId, ["email"]);

    // Begin: backend sends an OTP to alice's enrolled email address
    const beginResp = await apiPost(page, csrf, "/ui/mfa/email/begin", { challenge_id: challengeId });
    expect(beginResp.status()).toBe(200);
    expect((await beginResp.json() as { status: string }).status).toBe("sent");

    // Read the most-recent email for alice from the dev tools log
    const emailResp = await apiGet(page, "/internal/dev-tools/email/messages", { mailbox: MFA_ID });
    const { messages } = await emailResp.json() as {
      messages: Array<{ mailbox: string; body_text: string; sent_at: string; purpose?: string }>;
    };
    // Filter by purpose="login" so we don't accidentally pick the enrollment OTP
    // (both emails can share the same sent_at second in fast test runs).
    const latest = [...messages]
      .filter(m => m.mailbox === MFA_ID && m.purpose === "login")
      .sort((a, b) => b.sent_at.localeCompare(a.sent_at))[0];
    const code = extractCode(latest.body_text)!;
    expect(code).toMatch(/^\d{6}$/);

    // Verify: submit the code — challenge becomes complete
    const verifyResp = await apiPost(page, csrf, "/ui/mfa/email/verify", {
      challenge_id: challengeId,
      code,
    });
    expect(verifyResp.status()).toBe(200);
    const verifyBody = await verifyResp.json() as {
      status: string; passed: Record<string, boolean>; remaining_factors: string[];
    };
    expect(verifyBody.status).toBe("ok");
    expect(verifyBody.passed?.email).toBe(true);
    expect(verifyBody.remaining_factors).toHaveLength(0);
  });

  test("79.6 dev tools Email tab shows alice's enrollment email in the browser UI", async () => {
    await page.goto(`${DEVTOOLS}`, { waitUntil: "domcontentloaded" });
    // Email tab is default; mailbox list and the OTP body text should be visible
    await expect(page.getByText("All Inboxes")).toBeVisible();
    await expect(page.getByText(MFA_ID).first()).toBeVisible();
    // The reading pane shows "Your verification code is: XXXXXX"
    await expect(page.getByText(/Your verification code is: \d{6}/).first()).toBeVisible();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Section 80 — SMS MFA code recovery via Dev Log UI
// ═════════════════════════════════════════════════════════════════════════════

// 555-0008x numbers are reserved for fictional use in North America
const SMS_PHONE = "+15550000080";

test.describe("Section 80: SMS MFA via dev log UI", () => {
  let page: Page;
  let aliceSub: string;
  let csrf: string;
  let sessionId: string;
  let enrollChallengeId = "";
  let smsDeviceId = "";
  // Under cpp, enroll SMS MFA on a THROWAWAY user (not shared e2e_alice).
  let MFA_ID = ALICE_ID;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await browser.newPage();
    if (usingCpp()) {
      const tw = cppRegisterThrowaway("mfasms");
      if (tw) { getSessions()[tw.email] = tw.session as unknown as SessionData; MFA_ID = tw.email; }
    }
    const session = getSessions()[MFA_ID];
    aliceSub  = session.user_sub;
    csrf      = session.csrf_token;
    sessionId = session.cookies.find(c => c.name === "ui_session")!.value;

    // Alice may have email MFA from section 79. Stamp mfa_verified_at so
    // require_fresh_mfa passes for SMS enrollment.
    stampMfaVerified(aliceSub, sessionId);
    // Remove any leftover SMS devices from previous runs
    deleteSmsDevices(aliceSub);

    await injectAuth(page, MFA_ID);
  });

  test.afterAll(async () => {
    deleteSmsDevices(aliceSub);
    await page.close();
  });

  test("80.1 begin SMS enrollment returns challenge_id and sends SMS to the test phone", async () => {
    const resp = await apiPost(page, csrf, "/ui/mfa/sms/devices/begin", {
      phone_e164: SMS_PHONE,
      label: "e2e-mfa-sms",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json() as {
      challenge_id: string; sent_to: string[]; sms_device_id: string;
    };
    expect(typeof body.challenge_id).toBe("string");
    expect(body.sent_to).toContain(SMS_PHONE);
    expect(typeof body.sms_device_id).toBe("string");
    enrollChallengeId = body.challenge_id;
    smsDeviceId       = body.sms_device_id;
  });

  test("80.2 dev tools SMS API shows a conversation for the test phone with a 6-digit code", async () => {
    const resp = await apiGet(page, "/internal/dev-tools/sms/conversations", {
      participant: SMS_PHONE,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json() as {
      // body_text is null for plain SMS log entries; the OTP is in the `code` field
      messages: Array<{ to_number: string; body_text: string | null; code: string | null }>;
    };
    const sms = body.messages.find(m => m.to_number === SMS_PHONE);
    expect(sms, `no SMS to ${SMS_PHONE} in dev tools`).toBeDefined();
    // Plain SMS log format "Code: XXXXXX" → parser stores digits in `code` field, body_text stays null
    expect(sms!.code).toMatch(/^\d{6}$/);
  });

  test("80.3 code from dev tools SMS confirms SMS enrollment successfully", async () => {
    const resp = await apiGet(page, "/internal/dev-tools/sms/conversations", {
      participant: SMS_PHONE,
    });
    const { messages } = await resp.json() as {
      messages: Array<{ to_number: string; body_text: string | null; code: string | null; sent_at: string }>;
    };
    // Use the most-recently sent SMS to this phone
    const sorted = [...messages]
      .filter(m => m.to_number === SMS_PHONE)
      .sort((a, b) => b.sent_at.localeCompare(a.sent_at));
    // Plain SMS log format → OTP in `code` field; body_text is null
    const code = sorted[0].code!;
    expect(code).toMatch(/^\d{6}$/);

    const confirmResp = await apiPost(page, csrf, "/ui/mfa/sms/devices/confirm", {
      challenge_id: enrollChallengeId,
      code,
    });
    expect(confirmResp.status()).toBe(200);
    const body = await confirmResp.json() as {
      ok: boolean; sms_device_id: string; recovery_codes: string[];
    };
    expect(body.ok).toBe(true);
    expect(body.sms_device_id).toBe(smsDeviceId);
    // First SMS device → backend issues recovery codes
    expect(body.recovery_codes.length).toBeGreaterThan(0);
  });

  test("80.4 enrolled SMS device appears as enabled in the device list", async () => {
    const resp = await apiGet(page, "/ui/mfa/sms/devices");
    expect(resp.status()).toBe(200);
    const { devices } = await resp.json() as {
      devices: Array<{ sms_device_id: string; phone_e164: string; enabled: boolean }>;
    };
    const device = devices.find(d => d.sms_device_id === smsDeviceId);
    expect(device, "SMS device not in list").toBeDefined();
    expect(device!.enabled).toBe(true);
    expect(device!.phone_e164).toBe(SMS_PHONE);
  });

  test("80.5 dev tools SMS tab shows the enrollment conversation in the browser UI", async () => {
    await page.goto(`${DEVTOOLS}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "SMS" }).click();
    // The test phone number appears as the conversation title in the sidebar
    await expect(page.getByText(SMS_PHONE).first()).toBeVisible({ timeout: 10_000 });
    // The conversation preview shows the raw OTP digits (body_text is null; parser puts code
    // in the `code` field which is used as latest_preview, so only digits are rendered).
    await expect(page.getByText(/^\d{6}$/).first()).toBeVisible();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Section 81 — Billing ledger tie-out via Dev Log UI
// ═════════════════════════════════════════════════════════════════════════════

test.describe("Section 81: Billing ledger tie-out via dev log UI", () => {
  let page: Page;

  // Unique per-run ID so re-runs produce distinct external_ids (no dedup collisions)
  const RUN_ID = randomBytes(4).toString("hex");

  // Three synthetic Stripe charge events with known dollar amounts
  const TEST_ENTRIES = [
    { id: `e2e-ch-${RUN_ID}-A`, amountCents: 5000, feeCents: 150 }, // $50.00 / $1.50
    { id: `e2e-ch-${RUN_ID}-B`, amountCents: 7500, feeCents: 225 }, // $75.00 / $2.25
    { id: `e2e-ch-${RUN_ID}-C`, amountCents: 3000, feeCents:  90 }, // $30.00 / $0.90
  ] as const;

  // Expected aggregates (dollars)
  const TOTAL_AMOUNT = TEST_ENTRIES.reduce((s, e) => s + e.amountCents / 100, 0); // $155.00
  const TOTAL_FEES   = TEST_ENTRIES.reduce((s, e) => s + e.feeCents   / 100, 0); //   $4.65
  const TOTAL_NET    = TOTAL_AMOUNT - TOTAL_FEES;                                  // $150.35

  type Summary = {
    gross_inflow: number; fees: number; net_total_balance: number; transaction_count: number;
  };
  let baselineSummary: Summary;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    // Snapshot the current summary so tests can compute deltas and remain
    // stable even when prior runs have already written entries to the log.
    const baseResp = await page.request.get(`${API}/internal/dev-tools/billing/summary`);
    baselineSummary = await baseResp.json() as Summary;

    // Append Stripe-format JSON log lines. The billing_log_parser detects the
    // "type" + "data" keys and treats them as Stripe events; amounts are in
    // cents (the parser divides integer values by 100 to get dollars).
    const created = Math.floor(Date.now() / 1000);
    for (const entry of TEST_ENTRIES) {
      const line = JSON.stringify({
        type: "charge.succeeded",
        created,
        data: {
          object: {
            id:       entry.id,
            amount:   entry.amountCents,
            fee:      entry.feeCents,
            currency: "usd",
            status:   "succeeded",
            created,
          },
        },
      });
      if (usingCpp()) cppAppendBillingLog(line);
      else appendFileSync(STRIPE_LOG, line + "\n");
    }
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("81.1 dev tools billing API returns all three test entries by external_id", async () => {
    const resp = await page.request.get(`${API}/internal/dev-tools/billing/ledger`);
    expect(resp.status()).toBe(200);
    const { entries } = await resp.json() as {
      entries: Array<{ external_id: string; amount: number; fee: number; net: number; provider: string }>;
    };
    for (const te of TEST_ENTRIES) {
      const found = entries.find(e => e.external_id === te.id);
      expect(found, `entry ${te.id} missing from ledger`).toBeDefined();
      expect(found!.provider).toBe("stripe");
      expect(found!.amount).toBeCloseTo(te.amountCents / 100, 2);
      expect(found!.fee).toBeCloseTo(te.feeCents / 100, 2);
      expect(found!.net).toBeCloseTo((te.amountCents - te.feeCents) / 100, 2);
    }
  });

  test("81.2 gross_inflow delta equals sum of injected entry amounts ($155.00)", async () => {
    const resp = await page.request.get(`${API}/internal/dev-tools/billing/summary`);
    const summary = await resp.json() as Summary;
    const delta = summary.gross_inflow - baselineSummary.gross_inflow;
    expect(delta).toBeCloseTo(TOTAL_AMOUNT, 1);
  });

  test("81.3 fees delta equals sum of injected entry fees ($4.65)", async () => {
    const resp = await page.request.get(`${API}/internal/dev-tools/billing/summary`);
    const summary = await resp.json() as Summary;
    const delta = summary.fees - baselineSummary.fees;
    expect(delta).toBeCloseTo(TOTAL_FEES, 1);
  });

  test("81.4 net_total_balance delta = gross delta − fees delta (ledger ties out)", async () => {
    const resp = await page.request.get(`${API}/internal/dev-tools/billing/summary`);
    const summary = await resp.json() as Summary;
    const grossDelta = summary.gross_inflow    - baselineSummary.gross_inflow;
    const feesDelta  = summary.fees            - baselineSummary.fees;
    const netDelta   = summary.net_total_balance - baselineSummary.net_total_balance;
    // Core tie-out assertion: net ≡ gross − fees
    expect(netDelta).toBeCloseTo(grossDelta - feesDelta, 1);
    expect(netDelta).toBeCloseTo(TOTAL_NET, 1);
  });

  test("81.5 transaction_count delta matches the number of injected entries", async () => {
    const resp = await page.request.get(`${API}/internal/dev-tools/billing/summary`);
    const summary = await resp.json() as Summary;
    expect(summary.transaction_count - baselineSummary.transaction_count).toBe(TEST_ENTRIES.length);
  });

  test("81.6 dev tools Billing tab shows injected entries in the ledger table", async () => {
    await page.goto(`${DEVTOOLS}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "Billing" }).click();
    // Wait for ledger data to render (many rows may show "charge.succeeded"; use .first())
    await expect(page.getByRole("cell", { name: "charge.succeeded" }).first()).toBeVisible();
    // Each unique external_id must appear as a row in the table
    for (const te of TEST_ENTRIES) {
      await expect(page.getByText(te.id)).toBeVisible();
    }
  });

  test("81.7 billing summary is internally consistent: gross = net + fees", async () => {
    await page.goto(`${DEVTOOLS}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "Billing" }).click();
    await expect(page.getByRole("cell", { name: "charge.succeeded" }).first()).toBeVisible();
    // Fetch the live summary and verify the fundamental accounting identity
    const resp = await page.request.get(`${API}/internal/dev-tools/billing/summary`);
    const summary = await resp.json() as Summary;
    expect(summary.gross_inflow).toBeCloseTo(summary.net_total_balance + summary.fees, 1);
    expect(summary.gross_inflow).toBeGreaterThanOrEqual(summary.net_total_balance);
    expect(summary.fees).toBeGreaterThanOrEqual(0);
    // Summary section is visible in the UI
    await expect(page.getByText("Gross inflow")).toBeVisible();
    await expect(page.locator("div.text-2xl.font-semibold").first()).toBeVisible();
  });
});
