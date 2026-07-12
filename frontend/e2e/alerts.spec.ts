/**
 * E2E tests for alert delivery address configuration UI.
 *
 * Section 65: Alert email delivery address — API
 * Section 66: Alert SMS delivery address — API
 * Section 67: Alert Email Addresses — UI card
 * Section 68: Alert SMS Numbers — UI card
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import { readFileSync, statSync } from "fs";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE      = "http://localhost:3000";
const API       = "http://localhost:8000";
const ALICE_ID  = "e2e_alice@test.local";
const EMAIL_LOG = REPO_ROOT + "/.logs/dev/emails.log";
const SMS_LOG   = REPO_ROOT + "/.logs/dev/sms.log";

// Fixed test addresses — cleaned up in beforeAll/afterAll.
const TEST_EMAIL = "alerts-e2e@example.com";
const TEST_PHONE = "+15550009876"; // valid E164, no normalization needed

// ─── Session bootstrap ────────────────────────────────────────────────────────

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
      "python3 " + REPO_ROOT + "/e2e_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
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

// ─── DDB cleanup ──────────────────────────────────────────────────────────────

function clearAliceAlertPrefs(): void {
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

// ─── Log helpers ──────────────────────────────────────────────────────────────

function logSize(path: string): number {
  try { return statSync(path).size; } catch { return 0; }
}

/**
 * Read the LAST OTP code written to a dev log file after `afterOffset` bytes.
 * The alert email/sms log format contains:
 *   "Your confirmation code is: XXXXXX"
 * Uses matchAll + last-wins so previous test runs' codes don't interfere.
 */
function readOtpFromLog(logPath: string, afterOffset: number): string {
  let raw = "";
  try { raw = readFileSync(logPath, "utf-8"); } catch { /* file may not exist yet */ }
  const tail = raw.slice(afterOffset);
  const matches = [...tail.matchAll(/Your confirmation code is: (\d{6})/g)];
  if (!matches.length) throw new Error(`OTP not found in ${logPath} (scanned ${tail.length} bytes after offset ${afterOffset})`);
  return matches[matches.length - 1][1];
}

// ─── Navigation helper ────────────────────────────────────────────────────────

async function goToPreferences(page: Page) {
  await page.goto(`${BASE}/alerts`, { waitUntil: "load" });
  await page.getByRole("tab", { name: "Preferences" }).click();
  // CardTitle renders as <div>, not <h3> — use text match
  await expect(page.getByText("Alert Email Addresses", { exact: true })).toBeVisible({ timeout: 8000 });
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 65: Alert email delivery address — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("65 — Alert email delivery address API", () => {
  let page: Page;
  let challengeId: string;
  let logOffsetBeforeBegin: number;

  test.beforeAll(async ({ browser }) => {
    clearAliceAlertPrefs();
    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => {
    clearAliceAlertPrefs();
    await page.close();
  });

  test("65.1 GET /ui/alerts/email_prefs — emails list is empty after cleanup", async () => {
    const resp = await apiGet(page, "/ui/alerts/email_prefs");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.emails)).toBe(true);
    expect(data.emails).toHaveLength(0);
  });

  test("65.2 POST /ui/alerts/emails/begin — returns challenge_id and sent_to", async () => {
    logOffsetBeforeBegin = logSize(EMAIL_LOG);
    const resp = await apiPost(page, "/ui/alerts/emails/begin", { email: TEST_EMAIL });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data).toHaveProperty("challenge_id");
    expect(typeof data.challenge_id).toBe("string");
    expect(data.sent_to).toBe(TEST_EMAIL);
    challengeId = data.challenge_id;
    // OTP written to dev email log
    await expect.poll(() => logSize(EMAIL_LOG), { timeout: 5000 }).toBeGreaterThan(logOffsetBeforeBegin);
  });

  test("65.3 POST /ui/alerts/emails/confirm — wrong code returns 401", async () => {
    const resp = await apiPost(page, "/ui/alerts/emails/confirm", {
      challenge_id: challengeId,
      code: "000000",
    });
    expect(resp.status()).toBe(401);
  });

  test("65.4 POST /ui/alerts/emails/confirm — correct code adds the email", async () => {
    const code = readOtpFromLog(EMAIL_LOG, logOffsetBeforeBegin);
    const resp = await apiPost(page, "/ui/alerts/emails/confirm", {
      challenge_id: challengeId,
      code,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.emails).toContain(TEST_EMAIL);
  });

  test("65.5 GET /ui/alerts/email_prefs — email present in list", async () => {
    const resp = await apiGet(page, "/ui/alerts/email_prefs");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.emails).toContain(TEST_EMAIL);
  });

  test("65.6 POST /ui/alerts/emails/remove — email removed from list", async () => {
    const resp = await apiPost(page, "/ui/alerts/emails/remove", { email: TEST_EMAIL });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.emails).not.toContain(TEST_EMAIL);
    // Verify with a follow-up GET
    const getResp = await apiGet(page, "/ui/alerts/email_prefs");
    const prefs = await getResp.json();
    expect(prefs.emails).not.toContain(TEST_EMAIL);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 66: Alert SMS delivery address — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("66 — Alert SMS delivery address API", () => {
  let page: Page;
  let challengeId: string;
  let logOffsetBeforeBegin: number;

  test.beforeAll(async ({ browser }) => {
    clearAliceAlertPrefs();
    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => {
    clearAliceAlertPrefs();
    await page.close();
  });

  test("66.1 GET /ui/alerts/sms_prefs — sms_numbers list is empty after cleanup", async () => {
    const resp = await apiGet(page, "/ui/alerts/sms_prefs");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.sms_numbers)).toBe(true);
    expect(data.sms_numbers).toHaveLength(0);
  });

  test("66.2 POST /ui/alerts/sms/begin — returns challenge_id and sent_to", async () => {
    logOffsetBeforeBegin = logSize(SMS_LOG);
    const resp = await apiPost(page, "/ui/alerts/sms/begin", { phone: TEST_PHONE });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data).toHaveProperty("challenge_id");
    expect(typeof data.challenge_id).toBe("string");
    expect(data.sent_to).toBe(TEST_PHONE);
    challengeId = data.challenge_id;
    // OTP written to dev SMS log
    await expect.poll(() => logSize(SMS_LOG), { timeout: 5000 }).toBeGreaterThan(logOffsetBeforeBegin);
  });

  test("66.3 POST /ui/alerts/sms/confirm — wrong code returns 401", async () => {
    const resp = await apiPost(page, "/ui/alerts/sms/confirm", {
      challenge_id: challengeId,
      code: "000000",
    });
    expect(resp.status()).toBe(401);
  });

  test("66.4 POST /ui/alerts/sms/confirm — correct code adds the number", async () => {
    const code = readOtpFromLog(SMS_LOG, logOffsetBeforeBegin);
    const resp = await apiPost(page, "/ui/alerts/sms/confirm", {
      challenge_id: challengeId,
      code,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.sms_numbers).toContain(TEST_PHONE);
  });

  test("66.5 GET /ui/alerts/sms_prefs — number present in list", async () => {
    const resp = await apiGet(page, "/ui/alerts/sms_prefs");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.sms_numbers).toContain(TEST_PHONE);
  });

  test("66.6 POST /ui/alerts/sms/remove — number removed from list", async () => {
    const resp = await apiPost(page, "/ui/alerts/sms/remove", { phone: TEST_PHONE });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.sms_numbers).not.toContain(TEST_PHONE);
    // Verify with a follow-up GET
    const getResp = await apiGet(page, "/ui/alerts/sms_prefs");
    const prefs = await getResp.json();
    expect(prefs.sms_numbers).not.toContain(TEST_PHONE);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 67: Alert Email Addresses — UI card
// ─────────────────────────────────────────────────────────────────────────────

test.describe("67 — Alert Email Addresses UI card", () => {
  let page: Page;
  let emailLogOffset = 0; // captured just before the begin call in 67.3

  test.beforeAll(async ({ browser }) => {
    clearAliceAlertPrefs();
    page = await browser.newPage();
    await injectAuth(page);
    await goToPreferences(page);
  });

  test.afterAll(async () => {
    clearAliceAlertPrefs();
    await page.close();
  });

  test("67.1 Preferences tab shows both address cards above Notification Channels", async () => {
    // CardTitle is a <div>, not <h3> — use exact text match
    const emailCard  = page.getByText("Alert Email Addresses", { exact: true });
    const smsCard    = page.getByText("Alert SMS Numbers", { exact: true });
    const notifCard  = page.getByText("Notification Channels", { exact: true });

    await expect(emailCard).toBeVisible();
    await expect(smsCard).toBeVisible();
    await expect(notifCard).toBeVisible();

    // Verify DOM order: email card comes before SMS card, which comes before Notification Channels.
    const boxes = await Promise.all([emailCard, smsCard, notifCard].map(el => el.boundingBox()));
    expect(boxes[0]!.y).toBeLessThan(boxes[1]!.y); // email above SMS
    expect(boxes[1]!.y).toBeLessThan(boxes[2]!.y); // SMS above Notification Channels
  });

  test("67.2 Email card shows Add input and button in idle state", async () => {
    const input = page.getByPlaceholder("you@example.com");
    const addBtn = page.getByRole("button", { name: /Add/i }).first();
    await expect(input).toBeVisible();
    await expect(addBtn).toBeVisible();
    // OTP verify form must not be visible yet
    await expect(page.getByRole("button", { name: "Verify" }).first()).not.toBeVisible();
  });

  test("67.3 Clicking Add sends begin request and shows OTP verify form", async () => {
    test.setTimeout(20_000);
    emailLogOffset = logSize(EMAIL_LOG); // capture before begin so we read the right code in 67.4

    const input  = page.getByPlaceholder("you@example.com");
    const addBtn = page.getByRole("button", { name: /Add/i }).first();

    await input.fill(TEST_EMAIL);

    const beginDone = page.waitForResponse(
      (r) => r.url().includes("/alerts/emails/begin") && r.request().method() === "POST",
    );
    await addBtn.click();
    const beginResp = await beginDone;
    expect(beginResp.status()).toBe(200);

    // OTP verify form replaces the input row
    await expect(page.getByText(/6-digit code/i)).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("button", { name: "Verify" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Cancel" })).toBeVisible();
    // Input field for code
    await expect(page.getByPlaceholder("000000")).toBeVisible();

    // OTP written to log
    await expect.poll(() => logSize(EMAIL_LOG), { timeout: 5000 }).toBeGreaterThan(emailLogOffset);
  });

  test("67.4 Entering the correct OTP and clicking Verify adds the email to the list", async () => {
    test.setTimeout(20_000);
    // Use the offset captured in 67.3 so we read only the code from *this* begin call,
    // not a previously-consumed code from sections 65/66.
    const code = readOtpFromLog(EMAIL_LOG, emailLogOffset);

    const codeInput = page.getByPlaceholder("000000");
    const verifyBtn = page.getByRole("button", { name: "Verify" });

    await codeInput.fill(code);

    const confirmDone = page.waitForResponse(
      (r) => r.url().includes("/alerts/emails/confirm") && r.request().method() === "POST",
    );
    await verifyBtn.click();
    const confirmResp = await confirmDone;
    expect(confirmResp.status()).toBe(200);

    // OTP form hidden, email appears in the list (React Query refetches after invalidation)
    await expect(page.getByRole("button", { name: "Verify" })).not.toBeVisible();
    await expect(page.locator("span.font-mono").filter({ hasText: TEST_EMAIL })).toBeVisible({ timeout: 8000 });
    await expect(page.getByPlaceholder("you@example.com")).toBeVisible();
  });

  test("67.5 Clicking × on a listed email removes it", async () => {
    test.setTimeout(20_000);

    // Scope to the email row via the font-mono span → parent flex div → remove button
    const removeBtn = page.locator("span.font-mono")
      .filter({ hasText: TEST_EMAIL })
      .locator("..")
      .getByRole("button");

    const removeDone = page.waitForResponse(
      (r) => r.url().includes("/alerts/emails/remove") && r.request().method() === "POST",
    );
    await removeBtn.click();
    const removeResp = await removeDone;
    expect(removeResp.status()).toBe(200);

    // Email row disappears after React Query refetch
    await expect(page.locator("span.font-mono").filter({ hasText: TEST_EMAIL })).not.toBeVisible({ timeout: 8000 });
  });

  test("67.6 Cancel button in OTP form resets back to idle state", async () => {
    test.setTimeout(20_000);
    const logOffset = logSize(EMAIL_LOG);

    const input  = page.getByPlaceholder("you@example.com");
    const addBtn = page.getByRole("button", { name: /Add/i }).first();

    await input.fill(TEST_EMAIL);

    const beginDone = page.waitForResponse(
      (r) => r.url().includes("/alerts/emails/begin") && r.request().method() === "POST",
    );
    await addBtn.click();
    await beginDone;
    await expect.poll(() => logSize(EMAIL_LOG), { timeout: 5000 }).toBeGreaterThan(logOffset);

    // OTP form is visible — click Cancel
    const cancelBtn = page.getByRole("button", { name: "Cancel" });
    await expect(cancelBtn).toBeVisible();
    await cancelBtn.click();

    // Should return to idle: input visible, OTP form gone
    await expect(page.getByPlaceholder("you@example.com")).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("button", { name: "Verify" })).not.toBeVisible();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 68: Alert SMS Numbers — UI card
// ─────────────────────────────────────────────────────────────────────────────

test.describe("68 — Alert SMS Numbers UI card", () => {
  let page: Page;
  let smsLogOffset = 0; // captured just before the begin call in 68.2

  test.beforeAll(async ({ browser }) => {
    clearAliceAlertPrefs();
    page = await browser.newPage();
    await injectAuth(page);
    await goToPreferences(page);
  });

  test.afterAll(async () => {
    clearAliceAlertPrefs();
    await page.close();
  });

  test("68.1 SMS card shows Add input and button in idle state", async () => {
    // There are 3 "Add" buttons: email (.first()), SMS (.nth(1)), webhooks (.last())
    const input  = page.getByPlaceholder("+1 555 000 0000");
    const addBtn = page.getByRole("button", { name: /Add/i }).nth(1);
    await expect(input).toBeVisible();
    await expect(addBtn).toBeVisible();
    await expect(page.getByRole("button", { name: "Verify" })).not.toBeVisible();
  });

  test("68.2 Clicking Add sends begin request and shows OTP verify form", async () => {
    test.setTimeout(20_000);
    smsLogOffset = logSize(SMS_LOG); // capture before begin so we read the right code in 68.3

    const input  = page.getByPlaceholder("+1 555 000 0000");
    const addBtn = page.getByRole("button", { name: /Add/i }).nth(1); // email=0, SMS=1, webhooks=2

    await input.fill(TEST_PHONE);

    const beginDone = page.waitForResponse(
      (r) => r.url().includes("/alerts/sms/begin") && r.request().method() === "POST",
    );
    await addBtn.click();
    const beginResp = await beginDone;
    expect(beginResp.status()).toBe(200);

    // OTP verify form rendered inside SMS card
    await expect(page.getByText(/6-digit code/i)).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("button", { name: "Verify" })).toBeVisible();
    await expect(page.getByPlaceholder("000000")).toBeVisible();

    // OTP written to SMS log
    await expect.poll(() => logSize(SMS_LOG), { timeout: 5000 }).toBeGreaterThan(smsLogOffset);
  });

  test("68.3 Entering the correct OTP and clicking Verify adds the number to the list", async () => {
    test.setTimeout(20_000);
    // Use the offset captured in 68.2 so we read only the code from *this* begin call
    const code = readOtpFromLog(SMS_LOG, smsLogOffset);

    const codeInput = page.getByPlaceholder("000000");
    const verifyBtn = page.getByRole("button", { name: "Verify" });

    await codeInput.fill(code);

    const confirmDone = page.waitForResponse(
      (r) => r.url().includes("/alerts/sms/confirm") && r.request().method() === "POST",
    );
    await verifyBtn.click();
    const confirmResp = await confirmDone;
    expect(confirmResp.status()).toBe(200);

    // OTP form hidden, phone number appears in the list
    await expect(page.getByRole("button", { name: "Verify" })).not.toBeVisible();
    await expect(page.locator("span.font-mono").filter({ hasText: TEST_PHONE })).toBeVisible({ timeout: 8000 });
    await expect(page.getByPlaceholder("+1 555 000 0000")).toBeVisible();
  });

  test("68.4 Clicking × on a listed number removes it", async () => {
    test.setTimeout(20_000);

    const removeBtn = page.locator("span.font-mono")
      .filter({ hasText: TEST_PHONE })
      .locator("..")
      .getByRole("button");

    const removeDone = page.waitForResponse(
      (r) => r.url().includes("/alerts/sms/remove") && r.request().method() === "POST",
    );
    await removeBtn.click();
    const removeResp = await removeDone;
    expect(removeResp.status()).toBe(200);

    // Number no longer shown
    await expect(page.locator("span.font-mono").filter({ hasText: TEST_PHONE })).not.toBeVisible({ timeout: 8000 });
  });
});
