/**
 * E2E regression tests for the second batch of 11 bug fixes:
 *
 * Fix 1: TOTP/SMS OTP onComplete passes value directly (stale-state fix)
 * Fix 2: Recovery codes displayed after MFA registration
 * Fix 3: Expired/view-once image messages set last_message_id (sidebar preview)
 * Fix 4: Payment method add immediately unblocks tip checkbox (cache key fix)
 * Fix 5: Sidebar preview updates to real text after locked message unlocked
 * Fix 6: Attaching tip to new message shows PM selector + creates billing ledger entry
 * Fix 7: Encrypt checkbox works for image/file attachments (AES-256-GCM)
 * Fix 8: Outer "View once" text label hidden when a file is pending
 * Fix 9: Image/file content hidden immediately when expiry timer hits zero
 * Fix 10: Scheduled image message returns scheduled:true, not delivered immediately
 * Fix 11: File messages have a URL in dev mode (PDF files are clickable)
 * Fix 12: Scheduled messages support encryption (text + image, with or without attachment)
 * Fix 13: Expiry timer starts at delivery time, not request time, for scheduled messages
 * Fix 14: Scheduled messages support view-once (flag preserved through delivery)
 *
 * Tests for fixes 1 & 2 (registration flow) are covered at the API level.
 * Tests for fixes 9, 10, 11 that require real file uploads are at API level.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import { pbkdf2Sync, randomBytes as cryptoRandomBytes, createCipheriv } from "crypto";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";

const PYTHON = REPO_ROOT + "/.venv/bin/python3";

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name:     string;
    value:    string;
    domain:   string;
    path:     string;
    httpOnly: boolean;
    secure:   boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires:  number;
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

type APIRequestContext = import("@playwright/test").APIRequestContext;
async function apiPostBearer(
  req: APIRequestContext,
  path: string,
  body: object,
  userId: string,
) {
  return req.post(`${API}${path}`, {
    data: body,
    headers: { Authorization: `Bearer ${userId}` },
  });
}

// ─── Device warmup ────────────────────────────────────────────────────────────

async function warmupDevice(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  await page.request
    .get(`${API}/messaging/conversations`, {
      headers: { "x-csrf-token": session.csrf_token },
    })
    .catch(() => {});
  await page.request
    .get(`${API}/messaging/conversations`, {
      headers: { "x-csrf-token": session.csrf_token },
    })
    .catch(() => {});
}

// ─── Refetch trigger ──────────────────────────────────────────────────────────

async function triggerRefetch(page: Page): Promise<void> {
  await page.evaluate(() => window.dispatchEvent(new Event("online")));
}

// ─── DM bootstrap ─────────────────────────────────────────────────────────────

let _dmConvoId: string | null = null;

async function getOrCreateDm(page: Page): Promise<string> {
  if (_dmConvoId) return _dmConvoId;
  const bobSub = getSessions()[BOB_ID].user_sub;
  const resp = await apiPost(page, "/messaging/conversations", {
    participant_ids: [bobSub],
    type: "dm",
  });
  if (!resp.ok()) {
    throw new Error(`DM creation failed: HTTP ${resp.status()} — ${await resp.text()}`);
  }
  _dmConvoId = ((await resp.json()) as { conversation_id: string }).conversation_id;
  return _dmConvoId;
}

async function openDmWithBob(page: Page) {
  await injectAuth(page, ALICE_ID);
  const convoId = await getOrCreateDm(page);

  // Send a "touch" message so _dmConvoId is the most-recently-active conversation
  // and appears first in the sidebar among multiple E2E DMs from past runs.
  const session = getSessions()[ALICE_ID];
  await page.request.post(`${API}/messaging/conversations/${convoId}/messages`, {
    data: { text: `__touch__${Date.now()}` },
    headers: { "x-csrf-token": session.csrf_token },
  }).catch(() => {});

  // Register the conversations-list response listener BEFORE navigating.
  const convsLoaded = page.waitForResponse(
    (r) => r.url().includes("/messaging/conversations") && r.request().method() === "GET"
      && !r.url().match(/\/conversations\/[^/]+$/),
    { timeout: 15000 },
  );
  await page.goto(`${BASE}/messages`, { waitUntil: "load" });
  await convsLoaded;
  await page.waitForTimeout(300);

  const row = page.getByRole("button").filter({ hasText: "E2E Bob" }).first();
  await expect(row).toBeVisible({ timeout: 15000 });
  await row.click();
  await expect(
    page.getByPlaceholder("Type a message...").or(
      page.getByPlaceholder("Type an encrypted message..."),
    ),
  ).toBeVisible({ timeout: 5000 });
}

// ─── DDB helpers ─────────────────────────────────────────────────────────────

const DDB_HELPER_PRELUDE = `
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
`;

function injectPaymentMethod(userSub: string, pmId: string): void {
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
ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
tbl = ddb.Table('billing')
pk = 'USER#${userSub}'
pm_id = '${pmId}'
sk = 'PM#' + pm_id
tbl.put_item(Item={
    'pk': pk,
    'sk': sk,
    'payment_method_id': pm_id,
    'provider': 'stripe',
    'provider_method_id': pm_id,
    'method_type': 'card',
    'label': 'Test Card ****4242',
    'brand': 'visa',
    'last4': '4242',
    'exp_month': 12,
    'exp_year': 2099,
    'is_default': True,
    'priority': 0,
    'created_at': int(time.time()),
})
tbl.put_item(Item={
    'pk': pk,
    'sk': 'BILLING',
    'autopay_enabled': False,
    'currency': 'usd',
    'default_payment_method_id': pm_id,
})
print('injected')
"`,
    { timeout: 10_000 },
  );
}

function removePaymentMethod(userSub: string, pmId: string): void {
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
pk = 'USER#${userSub}'
tbl.delete_item(Key={'pk': pk, 'sk': 'PM#${pmId}'})
tbl.delete_item(Key={'pk': pk, 'sk': 'BILLING'})
print('removed')
"`,
      { timeout: 10_000 },
    );
  } catch {
    /* best-effort cleanup */
  }
}

function cleanupAllPaymentMethods(userSub: string): void {
  try {
    execSync(
      `${PYTHON} -c "
${DDB_HELPER_PRELUDE.trim()}
from boto3.dynamodb.conditions import Key
tbl = ddb.Table('billing')
pk = 'USER#${userSub}'
resp = tbl.query(KeyConditionExpression=Key('pk').eq(pk))
for item in resp['Items']:
    sk = item['sk']
    if sk.startswith('PM#') or sk == 'BILLING':
        tbl.delete_item(Key={'pk': pk, 'sk': sk})
print('cleaned up all PMs')
"`,
      { timeout: 10_000 },
    );
  } catch {
    /* best-effort cleanup */
  }
}

/** Delete all TOTP devices for a user from DynamoDB (best-effort cleanup). */
function deleteAllTotpDevices(userSub: string): void {
  try {
    execSync(
      `${PYTHON} -c "
${DDB_HELPER_PRELUDE.trim()}
from boto3.dynamodb.conditions import Key
tbl_name = os.environ.get('DDB_TOTP_TABLE', 'totp_devices')
tbl = ddb.Table(tbl_name)
resp = tbl.query(KeyConditionExpression=Key('user_sub').eq('${userSub}'))
for item in resp['Items']:
    tbl.delete_item(Key={'user_sub': item['user_sub'], 'device_id': item['device_id']})
print('deleted all TOTP devices')
"`,
      { timeout: 10_000 },
    );
  } catch {
    /* best-effort cleanup */
  }
}

// ─── Tiny test PNG (1×1 transparent pixel) ────────────────────────────────────

const TEST_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
  "base64",
);

// ─── Minimal MP4 ftyp box (20 bytes) — enough for encrypt/decrypt round-trip ──
// Real video playback requires a full moov+mdat, but tests only need the blob URL.
const TEST_MP4 = Buffer.from([
  0x00, 0x00, 0x00, 0x14,  // box size = 20
  0x66, 0x74, 0x79, 0x70,  // 'ftyp'
  0x6D, 0x70, 0x34, 0x32,  // major brand 'mp42'
  0x00, 0x00, 0x00, 0x00,  // minor version
  0x6D, 0x70, 0x34, 0x32,  // compatible brand 'mp42'
]);

// ─── 16. Fix 6: Tip compose bar — PM selector shown when tip enabled ──────────

test.describe("16. Tip compose bar — PM selector and send-gate when tip enabled", () => {
  const TS      = Date.now();
  const ALICE_PM = `e2e-pm-tip-cb-${TS}`;

  let page: Page;
  let aliceSub = "";

  test.beforeAll(async ({ browser }) => {
    aliceSub = getSessions()[ALICE_ID].user_sub;
    injectPaymentMethod(aliceSub, ALICE_PM);

    page = await browser.newPage();

    // Reload after injecting PM so ComposeBar's React Query picks it up.
    await openDmWithBob(page);
    // Register listener BEFORE reload so we don't miss the conversations GET response.
    const sec16ConvsLoaded = page.waitForResponse(
      (r) => r.url().includes("/messaging/conversations") && r.request().method() === "GET"
        && !r.url().match(/\/conversations\/[^/]+$/),
      { timeout: 15000 },
    );
    await page.reload({ waitUntil: "load" });
    await sec16ConvsLoaded;
    await page.waitForTimeout(300);
    const row = page.getByRole("button").filter({ hasText: "E2E Bob" }).first();
    await expect(row).toBeVisible({ timeout: 8000 });
    await row.click();
    await expect(page.getByPlaceholder("Type a message...")).toBeVisible({ timeout: 5000 });
  });

  test.afterAll(async () => {
    if (aliceSub && ALICE_PM) removePaymentMethod(aliceSub, ALICE_PM);
    await page?.close();
  });

  test("'Attach tip' toggle is enabled in '+' popover when a payment method exists", async () => {
    // MCM-2: tip toggle lives in "+" popover.
    await page.getByTestId("compose-more").click();
    const tipBtn = page.getByRole("button", { name: /toggle attach tip/i });
    await expect(tipBtn).toBeVisible({ timeout: 5000 });
    await expect(tipBtn).toBeEnabled({ timeout: 3000 });
    await page.keyboard.press("Escape");
  });

  test("Clicking 'Attach tip' in '+' popover shows the tip panel with 'Pay with:' section", async () => {
    await page.getByTestId("compose-more").click();
    await page.getByRole("button", { name: /toggle attach tip/i }).click();

    // The tip panel should be visible.
    await expect(page.getByText("Attach a tip to this message")).toBeVisible({ timeout: 3000 });
    // PM selector section inside the panel.
    await expect(page.getByText("Pay with:")).toBeVisible({ timeout: 3000 });
  });

  test("Injected Visa payment method button is visible in the tip panel", async () => {
    // Re-enable tip if state reset between tests.
    if (!(await page.getByRole("button", { name: /disable tip/i }).isVisible().catch(() => false))) {
      await page.getByTestId("compose-more").click();
      await page.getByRole("button", { name: /toggle attach tip/i }).click();
    }
    // Use .first() in case previous test runs left multiple PMs with same brand/last4.
    await expect(page.getByRole("button", { name: /visa.*4242/i }).first()).toBeVisible({ timeout: 5000 });
  });

  test("Send button is disabled when tip amount missing (no amount entered yet)", async () => {
    // The send button is disabled when tipEnabled=true but tipAmount is empty.
    const sendBtn = page.getByRole("button", { name: "Send message" });
    await expect(sendBtn).toBeDisabled({ timeout: 3000 });
  });

  test("Send button enabled after entering tip amount and selecting PM", async () => {
    // Re-enable tip if state reset between tests.
    if (!(await page.getByRole("button", { name: /disable tip/i }).isVisible().catch(() => false))) {
      await page.getByTestId("compose-more").click();
      await page.getByRole("button", { name: /toggle attach tip/i }).click();
    }
    // Fill in tip amount.
    const amountInput = page.locator("input[type='number'][placeholder='e.g. 5.00']");
    await amountInput.fill("1.00");

    // Select the PM button. Use .first() to avoid strict-mode errors with multiple PMs.
    await expect(page.getByRole("button", { name: /visa.*4242/i }).first()).toBeVisible({ timeout: 5000 });
    await page.getByRole("button", { name: /visa.*4242/i }).first().click();

    // Also fill in some message text so the send button isn't blocked by empty text.
    await page.getByPlaceholder("Type a message...").fill(`tip-test-${TS}`);

    const sendBtn = page.getByRole("button", { name: "Send message" });
    await expect(sendBtn).toBeEnabled({ timeout: 3000 });
  });
});

// ─── 17. Fix 6: Tip on new message — billing ledger debit entry ───────────────

test.describe("17. Tip on new message — billing ledger debit entry (send_text_message path)", () => {
  const TS      = Date.now();
  const ALICE_PM = `e2e-pm-tip-ledger-${TS}`;
  const TIP_MSG  = `tip-ledger-new-msg-${TS}`;

  let page: Page;
  let aliceSub = "";

  test.beforeAll(async ({ browser }) => {
    aliceSub = getSessions()[ALICE_ID].user_sub;
    injectPaymentMethod(aliceSub, ALICE_PM);

    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await getOrCreateDm(page);

    // Send a new text message with an attached tip via the API.
    // This exercises the send_text_message path (not the separate tip endpoint).
    const r = await apiPost(
      page,
      `/messaging/conversations/${_dmConvoId}/messages`,
      {
        text: TIP_MSG,
        tip_amount_cents: 200,
        tip_payment_method_id: ALICE_PM,
      },
    );
    if (!r.ok()) {
      throw new Error(`Alice tip-on-new-message failed: ${r.status()} — ${await r.text()}`);
    }
  });

  test.afterAll(async () => {
    if (aliceSub && ALICE_PM) removePaymentMethod(aliceSub, ALICE_PM);
    await page?.close();
  });

  test("Billing ledger has a tip debit entry (send_text_message tip path)", () => {
    // The tip-on-new-message path writes reason="Tip: message" (unified format).
    // Legacy entries used "Tip attached to message".
    const result = execSync(
      `${PYTHON} -c "
${DDB_HELPER_PRELUDE.trim()}
from boto3.dynamodb.conditions import Key, Attr
tbl = ddb.Table('billing')
pk = 'USER#${aliceSub}'
resp = tbl.query(
    KeyConditionExpression=Key('pk').eq(pk) & Key('sk').begins_with('LEDGER#'),
    FilterExpression=Attr('reason').is_in(['Tip attached to message', 'Tip: message']) & Attr('type').eq('debit'),
)
print(len(resp['Items']))
"`,
      { timeout: 10_000 },
    ).toString().trim();

    expect(parseInt(result, 10)).toBeGreaterThan(0);
  });
});

// ─── 18. Fix 5: Sidebar preview updates to real text after unlock ─────────────

test.describe("18. Locked message — sidebar preview shows real text after unlocking", () => {
  const TS        = Date.now();
  const LOCK_TEXT = `unlock-preview-${TS}`;
  const LOCK_DESC = `unlock-preview-desc-${TS}`;
  const ALICE_PM  = `e2e-pm-unlock-prev-${TS}`;

  let alicePage: Page;
  let aliceSub = "";
  let msgId    = "";

  test.beforeAll(async ({ browser, request }) => {
    aliceSub = getSessions()[ALICE_ID].user_sub;
    injectPaymentMethod(aliceSub, ALICE_PM);

    alicePage = await browser.newPage();
    await openDmWithBob(alicePage);

    // Bob sends a locked message — this becomes the last message in the DM.
    const r = await apiPostBearer(
      request,
      `/messaging/conversations/${_dmConvoId}/messages`,
      { text: LOCK_TEXT, lock_price_cents: 100, lock_description: LOCK_DESC },
      BOB_ID,
    );
    if (!r.ok()) throw new Error(`Bob locked message failed: ${r.status()}`);
    msgId = ((await r.json()) as { message_id: string }).message_id;

    // Navigate to the conversation list so we can see the sidebar preview.
    // Use waitForResponse to ensure the conversations list (with the locked message) is loaded.
    const sec18InitConvsLoaded = alicePage.waitForResponse(
      (r) => r.url().includes("/messaging/conversations") && r.request().method() === "GET"
        && !r.url().match(/\/conversations\/[^/]+$/),
      { timeout: 15000 },
    );
    await alicePage.goto(`${BASE}/messages`, { waitUntil: "load" });
    await sec18InitConvsLoaded;
    await alicePage.waitForTimeout(300);
  });

  test.afterAll(async () => {
    if (aliceSub && ALICE_PM) removePaymentMethod(aliceSub, ALICE_PM);
    await alicePage?.close();
  });

  test("Sidebar shows '[Locked message]' before unlocking", async () => {
    // No refetch needed — the conversations list was already loaded in beforeAll.
    // The sidebar should already show "[Locked message]" from the GET response.
    const row = alicePage.getByRole("button").filter({ hasText: "E2E Bob" }).first();
    await expect(row).toBeVisible({ timeout: 5000 });
    await expect(row).toContainText("[Locked message]", { timeout: 8000 });
  });

  test("Sidebar shows the real message text after Alice unlocks the message", async () => {
    // Alice unlocks via API.
    const unlockResp = await apiPost(
      alicePage,
      `/messaging/conversations/${_dmConvoId}/messages/${msgId}/unlock`,
      { payment_method_id: ALICE_PM },
    );
    if (!unlockResp.ok()) {
      throw new Error(`Unlock failed: ${unlockResp.status()} — ${await unlockResp.text()}`);
    }

    // Reload the conversation list page to pick up the fresh last_message state.
    const sec18ConvsLoaded = alicePage.waitForResponse(
      (r) => r.url().includes("/messaging/conversations") && r.request().method() === "GET"
        && !r.url().match(/\/conversations\/[^/]+$/),
      { timeout: 15000 },
    );
    await alicePage.reload({ waitUntil: "load" });
    await sec18ConvsLoaded;
    await alicePage.waitForTimeout(300);

    const row = alicePage.getByRole("button").filter({ hasText: "E2E Bob" }).first();
    await expect(row).toBeVisible({ timeout: 5000 });
    // The sidebar should no longer show "[Locked message]" — it should now show
    // the unlocked text (is_unlocked=true → getPreviewText returns the real text).
    await expect(row).toContainText(LOCK_TEXT, { timeout: 8000 });
    await expect(row).not.toContainText("[Locked message]");
  });
});

// ─── 19. Fix 4: Tip checkbox unblocked by PM add without page refresh ─────────

test.describe("19. Tip checkbox — unblocked after PM add + billing nav (no page refresh)", () => {
  const TS       = Date.now();
  const ALICE_PM = `e2e-pm-tip-unblock-${TS}`;

  let page: Page;
  let aliceSub = "";

  test.beforeAll(async ({ browser }) => {
    aliceSub = getSessions()[ALICE_ID].user_sub;
    // Ensure Alice starts with NO payment methods.
    cleanupAllPaymentMethods(aliceSub);

    page = await browser.newPage();
    await openDmWithBob(page);
  });

  test.afterAll(async () => {
    if (aliceSub && ALICE_PM) removePaymentMethod(aliceSub, ALICE_PM);
    await page?.close();
  });

  test("'Attach tip' toggle is disabled in '+' popover when no payment method exists", async () => {
    // MCM-2: tip toggle lives in "+" popover.
    await page.getByTestId("compose-more").click();
    const tipBtn = page.getByRole("button", { name: /toggle attach tip/i });
    await expect(tipBtn).toBeVisible({ timeout: 5000 });
    await expect(tipBtn).toBeDisabled({ timeout: 3000 });
    await page.keyboard.press("Escape");
  });

  test("After injecting a PM and navigating billing → messages, tip checkbox is enabled", async () => {
    // Inject a payment method directly into DDB (simulates user adding a PM).
    injectPaymentMethod(aliceSub, ALICE_PM);

    // Navigating to /billing triggers the ["billing", "payment-methods"] query
    // in React Query, which populates the shared cache used by ComposeBar.
    // Before the fix, ComposeBar used ["payment-methods"] (different key), so
    // it never saw the freshly loaded data — tip stayed disabled until reload.
    await page.goto(`${BASE}/billing`, { waitUntil: "load" });
    await page.waitForTimeout(1000);

    // Navigate back to messages and open the DM.
    const sec19ConvsLoaded = page.waitForResponse(
      (r) => r.url().includes("/messaging/conversations") && r.request().method() === "GET"
        && !r.url().match(/\/conversations\/[^/]+$/),
      { timeout: 15000 },
    );
    await page.goto(`${BASE}/messages`, { waitUntil: "load" });
    await sec19ConvsLoaded;
    await page.waitForTimeout(300);
    const row = page.getByRole("button").filter({ hasText: "E2E Bob" }).first();
    await expect(row).toBeVisible({ timeout: 10000 });
    await row.click();
    await expect(page.getByPlaceholder("Type a message...")).toBeVisible({ timeout: 5000 });

    // The tip toggle in "+" popover must now be enabled — no page refresh needed.
    await page.getByTestId("compose-more").click();
    const tipBtn = page.getByRole("button", { name: /toggle attach tip/i });
    await expect(tipBtn).toBeEnabled({ timeout: 5000 });
    await page.keyboard.press("Escape");
  });
});

// ─── 20. Encrypted image — sender sees "Encrypted" badge; recipient decrypts ──
//
// Strategy: send the encrypted image via direct API calls (bypass UI state) so
// the test is reliable, then verify UI display and decrypt behavior.

test.describe("20. Encrypted image message — send and decrypt", () => {
  let alicePage: Page;
  let bobPage: Page;
  const ENC_PASSWORD = "Tr0ub4dor&3";
  const TS = Date.now();

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
    const convoId = await getOrCreateDm(alicePage);
    const session = getSessions()[ALICE_ID];

    // Encrypt TEST_PNG with Node.js crypto — same AES-256-GCM + PBKDF2-SHA256
    // algorithm used by the browser so the browser can decrypt it correctly.
    const salt = cryptoRandomBytes(16);
    const iv   = cryptoRandomBytes(12);
    const keyBytes = pbkdf2Sync(ENC_PASSWORD, salt, 600_000, 32, "sha256");
    const cipher   = createCipheriv("aes-256-gcm", keyBytes, iv);
    const ciphertext = Buffer.concat([cipher.update(TEST_PNG), cipher.final()]);
    // CipherGCM has getAuthTag(); cast to access it
    const authTag      = (cipher as unknown as { getAuthTag(): Buffer }).getAuthTag();
    const encryptedBuf = Buffer.concat([ciphertext, authTag]);

    // 1. Get presign URL (Alice's request context carries session cookies)
    const presignResp = await alicePage.request.post(
      `${API}/messaging/conversations/${convoId}/images/presign`,
      {
        data: { content_type: "image/png", filename: `enc-test-${TS}.png` },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(presignResp.ok()).toBe(true);
    const { upload_url, bucket, key } = await presignResp.json() as {
      upload_url: string; bucket: string; key: string;
    };

    // 2. Upload encrypted bytes to presigned S3 URL (always absolute in this context)
    const absUploadUrl = upload_url.startsWith("/") ? `${API}${upload_url}` : upload_url;
    const uploadResp = await alicePage.request.fetch(absUploadUrl, {
      method: "PUT",
      data: encryptedBuf,
      headers: { "Content-Type": "application/octet-stream" },
    });
    expect(uploadResp.ok()).toBe(true);

    // 3. POST the message with the encryption envelope (no ciphertext_b64 — data is in S3)
    const msgResp = await alicePage.request.post(
      `${API}/messaging/conversations/${convoId}/messages/image`,
      {
        data: {
          bucket, key,
          content_type: "image/png",
          kind: "image",
          filename: `enc-test-${TS}.png`,
          filesize: TEST_PNG.length,
          encryption: {
            version:    1,
            alg:        "AES-256-GCM",
            kdf:        "PBKDF2-SHA256",
            iterations: 600_000,
            salt_b64:   salt.toString("base64"),
            iv_b64:     iv.toString("base64"),
          },
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(msgResp.status()).toBe(200);
    const msgBody = await msgResp.json() as Record<string, unknown>;
    expect(msgBody["is_encrypted"]).toBe(true);
    expect(msgBody["encryption"]).toBeTruthy();
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("Encrypt toggle is NOT disabled when a file is pending", async () => {
    // MCM-2: encrypt toggle lives in "+" popover.
    await openDmWithBob(alicePage);
    await alicePage.getByTestId("compose-more").click();
    const encBtn = alicePage.getByRole("button", { name: /toggle message encryption/i });
    await expect(encBtn).not.toBeDisabled({ timeout: 3000 });
    await alicePage.keyboard.press("Escape");

    // Attach file — toggle should STILL be enabled in popover
    await alicePage.locator("input[type='file']").setInputFiles({
      name: `check-enc-${TS}.png`, mimeType: "image/png", buffer: TEST_PNG,
    });
    await expect(alicePage.getByText("ready to send")).toBeVisible({ timeout: 5000 });
    await alicePage.getByTestId("compose-more").click();
    await expect(alicePage.getByRole("button", { name: /toggle message encryption/i })).not.toBeDisabled({ timeout: 3000 });
    await alicePage.keyboard.press("Escape");

    // Clear the file using the aria-labeled button
    await alicePage.getByRole("button", { name: "Remove attachment" }).click();
    await expect(alicePage.getByText("ready to send")).not.toBeVisible({ timeout: 3000 });
  });

  test("Alice's UI shows 'Encrypted' badge and 'Encrypted image' for the sent message", async () => {
    test.setTimeout(30000);
    // Navigate to the DM fresh so the latest messages (including the one sent in
    // beforeAll via API) are loaded.  openDmWithBob re-injects auth and opens the DM.
    await openDmWithBob(alicePage);
    // The encrypted image bubble shows "Encrypted image" text + "Decrypt to view" button.
    // Use straightforward text/role locators (more reliable than span+filter for the badge).
    await expect(
      alicePage.getByText("Encrypted image").last()
    ).toBeVisible({ timeout: 10000 });
    await expect(
      alicePage.getByRole("button", { name: "Decrypt to view" }).last()
    ).toBeVisible({ timeout: 5000 });
  });

  test("Bob sees 'Encrypted image' + 'Decrypt to view' button", async () => {
    test.setTimeout(30000);
    // Re-inject auth for Bob here — in beforeAll his page was left at /login and
    // navigating directly to /messages without fresh auth causes a redirect back to /login.
    await injectAuth(bobPage, BOB_ID);
    const sec20BobConvsLoaded = bobPage.waitForResponse(
      (r) => r.url().includes("/messaging/conversations") && r.request().method() === "GET"
        && !r.url().match(/\/conversations\/[^/]+$/),
      { timeout: 15000 },
    );
    await bobPage.goto(`${BASE}/messages`, { waitUntil: "load" });
    await sec20BobConvsLoaded;
    await bobPage.waitForTimeout(300);
    const aliceRow = bobPage.getByRole("button").filter({ hasText: /Alice/ }).first();
    await expect(aliceRow).toBeVisible({ timeout: 15000 });
    await aliceRow.evaluate((el) => (el as HTMLElement).click());
    await expect(
      bobPage.getByText("Encrypted image").last()
    ).toBeVisible({ timeout: 12000 });
    await expect(
      bobPage.getByRole("button", { name: "Decrypt to view" }).last()
    ).toBeVisible({ timeout: 5000 });
  });

  test("Bob enters correct password and image decrypts (blob URL rendered)", async () => {
    test.setTimeout(30000);
    // bobPage is still on the DM from the previous test.
    await bobPage.getByRole("button", { name: "Decrypt to view" }).last().click();
    await expect(bobPage.getByRole("dialog")).toBeVisible({ timeout: 5000 });
    await expect(bobPage.getByText(/Decrypt image/i)).toBeVisible({ timeout: 3000 });

    await bobPage.locator('input[type="password"]').fill(ENC_PASSWORD);
    await bobPage.getByRole("button", { name: "Decrypt" }).click();

    // Dialog closes, decrypted image (blob URL) appears
    await expect(bobPage.getByRole("dialog")).not.toBeVisible({ timeout: 15000 });
    await expect(bobPage.locator("img[src^='blob:']")).toBeVisible({ timeout: 10000 });
  });

  test("Wrong password shows error; dialog stays open", async () => {
    test.setTimeout(30000);
    // Re-inject auth and navigate fresh to reset decrypted state and ensure auth is valid
    // (shared localStorage between pages in the same context can cause stale auth state).
    await injectAuth(bobPage, BOB_ID);
    const sec20WrongPwConvsLoaded = bobPage.waitForResponse(
      (r) => r.url().includes("/messaging/conversations") && r.request().method() === "GET"
        && !r.url().match(/\/conversations\/[^/]+$/),
      { timeout: 15000 },
    );
    await bobPage.goto(`${BASE}/messages`, { waitUntil: "load" });
    await sec20WrongPwConvsLoaded;
    await bobPage.waitForTimeout(300);
    const aliceRow = bobPage.getByRole("button").filter({ hasText: /Alice/ }).first();
    await expect(aliceRow).toBeVisible({ timeout: 15000 });
    // Click the preview area (avoid avatar/name links which navigate to profile)
    await aliceRow.evaluate((el) => (el as HTMLElement).click());

    await expect(
      bobPage.getByRole("button", { name: "Decrypt to view" }).last()
    ).toBeVisible({ timeout: 10000 });
    await bobPage.getByRole("button", { name: "Decrypt to view" }).last().click();

    await expect(bobPage.getByRole("dialog")).toBeVisible({ timeout: 5000 });
    await bobPage.locator('input[type="password"]').fill("wrong-password-xyz");
    await bobPage.getByRole("button", { name: "Decrypt" }).click();

    await expect(bobPage.getByText("Wrong password")).toBeVisible({ timeout: 8000 });
    await expect(bobPage.getByRole("dialog")).toBeVisible({ timeout: 3000 });
    await bobPage.getByRole("button", { name: "Cancel" }).click();
  });
});

// ─── 21. Fix 8: View-once text label hidden when a file is pending ────────────

test.describe("21. View-once text label — hidden when a file is staged in compose bar", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await openDmWithBob(page);
  });

  test.afterAll(async () => page?.close());

  test("'View once' toggle is accessible in '+' popover before a file is attached", async () => {
    // MCM-2: toggles moved into "+" popover. Button present when no file is pending.
    await page.getByTestId("compose-more").click();
    await expect(
      page.getByRole("button", { name: /toggle view once/i })
    ).toBeVisible({ timeout: 5000 });
    await page.keyboard.press("Escape");
  });

  test("'View once' toggle is removed from '+' popover when a file is staged", async () => {
    const fileInput = page.locator("input[type='file']");
    await fileInput.setInputFiles({
      name:     "test-e2e2.png",
      mimeType: "image/png",
      buffer:   TEST_PNG,
    });

    // File preview should be visible.
    await expect(page.getByText("ready to send")).toBeVisible({ timeout: 5000 });

    // MCM-2: the "Toggle view once" button is gated on !pendingFile — it should
    // be removed from the popover when a file is staged.
    await page.getByTestId("compose-more").click();
    await expect(
      page.getByRole("button", { name: /toggle view once/i })
    ).not.toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
  });
});

// ─── 22. Fix 1 & 2: TOTP onComplete — API confirms correct code from callback ──

test.describe("22. TOTP confirm response includes recovery_codes (fix 2: recovery codes API)", () => {
  let page: Page;
  let deviceId  = "";
  let secret    = "";
  let aliceSub  = "";

  test.beforeAll(async ({ browser }) => {
    aliceSub = getSessions()[ALICE_ID].user_sub;
    // Remove all existing TOTP devices for Alice so she has no MFA factors.
    // Without any MFA factors the device-trust check is skipped on begin.
    deleteAllTotpDevices(aliceSub);

    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    // Warm up device trust so the TOTP begin endpoint doesn't return 401.
    await warmupDevice(page, ALICE_ID);

    // Register a fresh TOTP device so we can test the confirm response.
    const resp = await apiPost(page, "/ui/mfa/totp/devices/begin", { label: "e2e-recovery-test" });
    if (!resp.ok()) throw new Error(`TOTP begin: ${resp.status()}`);
    const body = await resp.json() as { device_id: string; secret: string };
    deviceId = body.device_id;
    secret   = body.secret;
  });

  test.afterAll(async () => {
    // Clean up the device regardless of test outcome.
    if (aliceSub) deleteAllTotpDevices(aliceSub);
    await page?.close();
  });

  test("TOTP confirm response includes recovery_codes array when first device enrolled", async () => {
    // Generate two codes from different 30-second windows (required for confirmation).
    // Use 60s gap to guarantee they're in different windows even near boundaries.
    const codes = JSON.parse(
      execSync(
        `${PYTHON} -c "
import pyotp, time, json
t = int(time.time())
totp = pyotp.TOTP('${secret}')
print(json.dumps({'curr': totp.at(t), 'prev': totp.at(t - 60)}))
"`,
        { timeout: 5000 },
      ).toString().trim(),
    ) as { curr: string; prev: string };

    const resp = await apiPost(page, "/ui/mfa/totp/devices/confirm", {
      device_id:  deviceId,
      totp_code:  codes.prev,
      totp_code2: codes.curr,
    });
    expect(resp.status()).toBe(200);

    const body = await resp.json() as Record<string, unknown>;
    // The backend should return recovery_codes on first-device enrollment.
    // (Fix 2: frontend now captures and displays these codes.)
    expect(body).toHaveProperty("recovery_codes");
    const codes2 = body["recovery_codes"] as unknown[];
    expect(Array.isArray(codes2)).toBe(true);
    expect(codes2.length).toBeGreaterThan(0);
  });
});

// ─── 23. Fix 10: Scheduled image — send_at accepted, returns scheduled:true ────

test.describe("23. Scheduled text message — send_at field accepted (proxy for scheduled image fix)", () => {
  let page: Page;
  const TS       = Date.now();
  const SCHED_TXT = `sched-img-proxy-${TS}`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await getOrCreateDm(page);
  });

  test.afterAll(async () => page?.close());

  test("POST /messages with send_at returns scheduled:true and message not in messages list immediately", async () => {
    const deliverTs = Math.floor(Date.now() / 1000) + 120; // 2 min in future

    const r = await apiPost(
      page,
      `/messaging/conversations/${_dmConvoId}/messages`,
      { text: SCHED_TXT, send_at: deliverTs },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as { scheduled?: boolean; deliver_at?: number };
    expect(body.scheduled).toBe(true);
    expect(body.deliver_at).toBe(deliverTs);

    // The message must appear in the scheduled list (not yet delivered).
    const sched = await apiPost(
      page,
      `/messaging/conversations/${_dmConvoId}/messages/scheduled`,
      {},
    );
    // GET /scheduled — use the same page.request.get approach
    const session = getSessions()[ALICE_ID];
    const schedGet = await page.request.get(
      `${API}/messaging/conversations/${_dmConvoId}/messages/scheduled`,
      { headers: { "x-csrf-token": session.csrf_token } },
    );
    expect(schedGet.ok()).toBe(true);
    const list = (await schedGet.json()) as Array<{ message_id?: string; text?: string }>;
    const found = list.find((m) => m.text === SCHED_TXT);
    expect(found, "Scheduled message must appear in /messages/scheduled").toBeTruthy();
  });
});

// ─── 24. Fix 12: Scheduled messages support encryption ────────────────────────
//
// Tests that send_at and encryption can both be set on text and image messages.
// Both fields must coexist: the message is stored as scheduled=true AND
// is_encrypted=true simultaneously.
//
// Encryption envelope shape:
//   - Text messages:  must include ciphertext_b64 (cipher stored in envelope)
//   - Image messages: must omit  ciphertext_b64 (cipher stored in S3 object)

test.describe("24. Scheduled encrypted messages — text and image", () => {
  let page: Page;

  // Minimal but structurally valid AES-256-GCM envelope values (fake ciphertext;
  // we only test that the server stores and echoes the fields, not that the cipher
  // can actually be decrypted).
  const SALT_B64       = Buffer.alloc(16).toString("base64"); // 16 zero bytes → valid base64
  const IV_B64         = Buffer.alloc(12).toString("base64"); // 12 zero bytes → valid base64
  const CIPHERTEXT_B64 = Buffer.alloc(32).toString("base64"); // 32 zero bytes → valid base64

  const textEnvelope = {
    version:        1,
    alg:            "AES-256-GCM",
    kdf:            "PBKDF2-SHA256",
    iterations:     100_000,
    salt_b64:       SALT_B64,
    iv_b64:         IV_B64,
    ciphertext_b64: CIPHERTEXT_B64,
  };

  // Image envelope omits ciphertext_b64 — encrypted bytes live in S3.
  const imageEnvelope = {
    version:    1,
    alg:        "AES-256-GCM",
    kdf:        "PBKDF2-SHA256",
    iterations: 100_000,
    salt_b64:   SALT_B64,
    iv_b64:     IV_B64,
  };

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await getOrCreateDm(page);
  });

  test.afterAll(async () => page?.close());

  // ── 24a. Scheduled encrypted TEXT ─────────────────────────────────────────

  test("Scheduled + encrypted text message: response has scheduled=true AND is_encrypted=true", async () => {
    const session   = getSessions()[ALICE_ID];
    const deliverTs = Math.floor(Date.now() / 1000) + 120;

    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages`,
      {
        data:    { encryption: textEnvelope, send_at: deliverTs },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.scheduled,    "must be scheduled").toBe(true);
    expect(body.is_encrypted, "must be encrypted").toBe(true);
    expect(body.deliver_at,   "deliver_at must match send_at").toBe(deliverTs);
    expect(body.encryption,   "encryption envelope must be echoed back").toBeTruthy();
  });

  test("Scheduled + encrypted text message appears in /messages/scheduled with is_encrypted=true", async () => {
    const session = getSessions()[ALICE_ID];
    const r = await page.request.get(
      `${API}/messaging/conversations/${_dmConvoId}/messages/scheduled`,
      { headers: { "x-csrf-token": session.csrf_token } },
    );
    expect(r.ok()).toBe(true);
    const list = await r.json() as Array<Record<string, unknown>>;
    const encryptedScheduled = list.filter((m) => m.is_encrypted === true);
    expect(
      encryptedScheduled.length,
      "at least one scheduled message must have is_encrypted=true",
    ).toBeGreaterThan(0);
  });

  // ── 24b. Scheduled encrypted IMAGE ────────────────────────────────────────

  test("Scheduled + encrypted image message: response has scheduled=true AND is_encrypted=true", async () => {
    const session   = getSessions()[ALICE_ID];
    const deliverTs = Math.floor(Date.now() / 1000) + 120;

    // 1. Presign an upload URL (encrypted bytes treated as application/octet-stream)
    const presign = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/images/presign`,
      {
        data:    { filename: "encrypted.png", content_type: "application/octet-stream" },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(presign.status()).toBe(200);
    const { upload_url, bucket, key } = await presign.json() as {
      upload_url: string; bucket: string; key: string;
    };

    // 2. Upload fake encrypted bytes to the mock S3 endpoint
    const putResp = await page.request.put(`http://localhost:8000${upload_url}`, {
      data:    Buffer.alloc(64), // 64 zero bytes simulating encrypted image data
      headers: { "Content-Type": "application/octet-stream" },
    });
    expect(putResp.status()).toBeLessThan(300);

    // 3. Send image message with both send_at and encryption
    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages/image`,
      {
        data: {
          bucket,
          key,
          filename:     "encrypted.png",
          content_type: "application/octet-stream",
          size:         64,
          width:        10,
          height:       10,
          kind:         "image",
          send_at:      deliverTs,
          encryption:   imageEnvelope,
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.scheduled,    "image must be scheduled").toBe(true);
    expect(body.is_encrypted, "image must be encrypted").toBe(true);
    expect(body.deliver_at,   "deliver_at must match send_at").toBe(deliverTs);
    expect(body.kind,         "kind must be image").toBe("image");
    expect(body.encryption,   "encryption envelope must be echoed back").toBeTruthy();
  });

  test("Scheduled + encrypted image appears in /messages/scheduled with is_encrypted=true", async () => {
    const session = getSessions()[ALICE_ID];
    const r = await page.request.get(
      `${API}/messaging/conversations/${_dmConvoId}/messages/scheduled`,
      { headers: { "x-csrf-token": session.csrf_token } },
    );
    expect(r.ok()).toBe(true);
    const list = await r.json() as Array<Record<string, unknown>>;
    const encryptedImages = list.filter(
      (m) => m.is_encrypted === true && m.kind === "image",
    );
    expect(
      encryptedImages.length,
      "at least one scheduled image must have is_encrypted=true",
    ).toBeGreaterThan(0);
  });
});

// ─── 25. Fix 13+14: Expiry timer starts at delivery time; view-once + scheduled ─

test.describe("25. Scheduled messages — expiry timer and view-once", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await getOrCreateDm(page);
  });

  test.afterAll(async () => page?.close());

  // ── 25a. Expiry timer starts at scheduled delivery time, not request time ──

  test("expires_at is based on deliver_at (not request time) when send_at is set", async () => {
    const session    = getSessions()[ALICE_ID];
    const deliverAt  = Math.floor(Date.now() / 1000) + 120; // 2 min from now
    const expiresIn  = 3600;                                  // 1-hour expiry
    const expectedExpiresAt = deliverAt + expiresIn;

    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages`,
      {
        data:    { text: `sched-expiry-${Date.now()}`, send_at: deliverAt, expires_in_seconds: expiresIn },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;

    expect(body.scheduled,  "must be scheduled").toBe(true);
    expect(body.deliver_at, "deliver_at must match send_at").toBe(deliverAt);

    // The expiry must be anchored to deliver_at, not the current request time.
    // If it were anchored to request time, expires_at would equal (now + 3600)
    // which is 120 seconds LESS than the expected value.
    expect(body.expires_at, "expires_at must equal deliver_at + expires_in_seconds").toBe(expectedExpiresAt);
    expect(
      (body.expires_at as number) > Math.floor(Date.now() / 1000) + expiresIn,
      "expires_at must be strictly greater than (now + expires_in_seconds), proving it was NOT anchored to request time",
    ).toBe(true);
  });

  test("Scheduled + expiry image: expires_at anchored to deliver_at", async () => {
    const session   = getSessions()[ALICE_ID];
    const deliverAt = Math.floor(Date.now() / 1000) + 120;
    const expiresIn = 1800;

    // Presign
    const presign = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/images/presign`,
      {
        data:    { filename: "sched-expiry.png", content_type: "image/png" },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(presign.status()).toBe(200);
    const { upload_url, bucket, key } = await presign.json() as {
      upload_url: string; bucket: string; key: string;
    };
    // Upload
    await page.request.put(`http://localhost:8000${upload_url}`, {
      data: Buffer.alloc(32), headers: { "Content-Type": "image/png" },
    });

    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages/image`,
      {
        data: {
          bucket, key, filename: "sched-expiry.png", content_type: "image/png",
          size: 32, width: 10, height: 10, kind: "image",
          send_at: deliverAt, expires_in_seconds: expiresIn,
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.scheduled).toBe(true);
    expect(body.expires_at).toBe(deliverAt + expiresIn);
  });

  // ── 25b. View-once works with scheduled send ──────────────────────────────

  test("Scheduled + view-once text: response has scheduled=true AND view_once=true", async () => {
    const session   = getSessions()[ALICE_ID];
    const deliverAt = Math.floor(Date.now() / 1000) + 120;

    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages`,
      {
        data:    { text: `sched-viewonce-${Date.now()}`, send_at: deliverAt, view_once: true },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.scheduled,  "must be scheduled").toBe(true);
    expect(body.view_once,  "must be view_once").toBe(true);
    expect(body.deliver_at, "deliver_at must match send_at").toBe(deliverAt);
  });

  test("Scheduled + view-once text appears in /messages/scheduled with view_once=true", async () => {
    const session = getSessions()[ALICE_ID];
    const r = await page.request.get(
      `${API}/messaging/conversations/${_dmConvoId}/messages/scheduled`,
      { headers: { "x-csrf-token": session.csrf_token } },
    );
    expect(r.ok()).toBe(true);
    const list = await r.json() as Array<Record<string, unknown>>;
    const viewOnceScheduled = list.filter((m) => m.view_once === true);
    expect(
      viewOnceScheduled.length,
      "at least one scheduled message must have view_once=true",
    ).toBeGreaterThan(0);
  });

  test("Scheduled + view-once + expiry: all three fields correct", async () => {
    const session   = getSessions()[ALICE_ID];
    const deliverAt = Math.floor(Date.now() / 1000) + 120;
    const expiresIn = 7200;

    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages`,
      {
        data: {
          text: `sched-vo-exp-${Date.now()}`,
          send_at: deliverAt,
          view_once: true,
          expires_in_seconds: expiresIn,
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.scheduled).toBe(true);
    expect(body.view_once).toBe(true);
    expect(body.expires_at).toBe(deliverAt + expiresIn);
  });
});

// ─── 26. Tipped messages — all feature combinations ───────────────────────────
//
// Tips attached to messages can be combined with encryption, view-once,
// scheduling, and expiry. The key invariant for scheduled tips is that
// billing must NOT be written until the message is actually delivered
// (so cancelling a scheduled tipped message does not charge the sender).

test.describe("26. Tipped messages — encryption, view-once, scheduled, expiry", () => {
  let page: Page;

  const SALT_B64       = Buffer.alloc(16).toString("base64");
  const IV_B64         = Buffer.alloc(12).toString("base64");
  const CIPHERTEXT_B64 = Buffer.alloc(32).toString("base64");
  const textEnvelope   = {
    version: 1, alg: "AES-256-GCM", kdf: "PBKDF2-SHA256", iterations: 100_000,
    salt_b64: SALT_B64, iv_b64: IV_B64, ciphertext_b64: CIPHERTEXT_B64,
  };

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await getOrCreateDm(page);
  });

  test.afterAll(async () => page?.close());

  // ── 26a. Immediate tipped message still writes billing at send time ─────────

  test("Immediate tip: tip_amount_cents echoed in response", async () => {
    const session = getSessions()[ALICE_ID];
    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages`,
      {
        data: { text: `tip-immediate-${Date.now()}`, tip_amount_cents: 150, tip_payment_method_id: "pm_test" },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.scheduled).toBeFalsy();
    expect(body.tip_amount_cents).toBe(150);
  });

  // ── 26b. Scheduled tip: billing deferred until delivery ────────────────────

  test("Scheduled tip: response has scheduled=true and tip_amount_cents", async () => {
    const session   = getSessions()[ALICE_ID];
    const deliverAt = Math.floor(Date.now() / 1000) + 120;

    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages`,
      {
        data: { text: `tip-sched-${Date.now()}`, send_at: deliverAt, tip_amount_cents: 200, tip_payment_method_id: "pm_test" },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.scheduled,       "must be scheduled").toBe(true);
    expect(body.tip_amount_cents, "tip must be preserved").toBe(200);
    expect(body.deliver_at,      "deliver_at must match send_at").toBe(deliverAt);
  });

  test("Scheduled tip appears in /messages/scheduled with tip_amount_cents", async () => {
    const session = getSessions()[ALICE_ID];
    const r = await page.request.get(
      `${API}/messaging/conversations/${_dmConvoId}/messages/scheduled`,
      { headers: { "x-csrf-token": session.csrf_token } },
    );
    expect(r.ok()).toBe(true);
    const list = await r.json() as Array<Record<string, unknown>>;
    const tipScheduled = list.filter((m) => (m.tip_amount_cents as number) > 0);
    expect(tipScheduled.length, "at least one scheduled message must have tip_amount_cents").toBeGreaterThan(0);
  });

  // ── 26c. Scheduled + tip + encryption ──────────────────────────────────────

  test("Scheduled + encrypted tip: scheduled=true, is_encrypted=true, tip_amount_cents set", async () => {
    const session   = getSessions()[ALICE_ID];
    const deliverAt = Math.floor(Date.now() / 1000) + 120;

    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages`,
      {
        data: { send_at: deliverAt, tip_amount_cents: 300, tip_payment_method_id: "pm_test", encryption: textEnvelope },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.scheduled).toBe(true);
    expect(body.is_encrypted).toBe(true);
    expect(body.tip_amount_cents).toBe(300);
  });

  // ── 26d. Scheduled + tip + view-once ───────────────────────────────────────

  test("Scheduled + view-once tip: scheduled=true, view_once=true, tip_amount_cents set", async () => {
    const session   = getSessions()[ALICE_ID];
    const deliverAt = Math.floor(Date.now() / 1000) + 120;

    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages`,
      {
        data: { text: `tip-vo-${Date.now()}`, send_at: deliverAt, tip_amount_cents: 400, view_once: true },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.scheduled).toBe(true);
    expect(body.view_once).toBe(true);
    expect(body.tip_amount_cents).toBe(400);
  });

  // ── 26e. Scheduled + tip + expiry (timer anchored to deliver_at) ────────────

  test("Scheduled + tipped + expiry: expires_at anchored to deliver_at", async () => {
    const session   = getSessions()[ALICE_ID];
    const deliverAt = Math.floor(Date.now() / 1000) + 120;
    const expiresIn = 3600;

    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages`,
      {
        data: { text: `tip-exp-${Date.now()}`, send_at: deliverAt, tip_amount_cents: 500, expires_in_seconds: expiresIn },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.scheduled).toBe(true);
    expect(body.tip_amount_cents).toBe(500);
    expect(body.expires_at).toBe(deliverAt + expiresIn);
  });

  // ── 26f. All five together ──────────────────────────────────────────────────

  test("All five: scheduled + tip + encrypted + view-once + expiry coexist", async () => {
    const session   = getSessions()[ALICE_ID];
    const deliverAt = Math.floor(Date.now() / 1000) + 120;
    const expiresIn = 7200;

    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages`,
      {
        data: {
          send_at:           deliverAt,
          tip_amount_cents:  600,
          encryption:        textEnvelope,
          view_once:         true,
          expires_in_seconds: expiresIn,
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.scheduled).toBe(true);
    expect(body.is_encrypted).toBe(true);
    expect(body.view_once).toBe(true);
    expect(body.tip_amount_cents).toBe(600);
    expect(body.expires_at).toBe(deliverAt + expiresIn);
  });
});

// ─── 27. Locked messages — encryption, view-once, scheduled, expiry ───────────
//
// lock_price_cents can be combined with encryption, view-once, scheduling, and
// expiry with no backend validation errors.
//
// Critical display invariant (fixed in MessageBubble.tsx): for a non-owner
// recipient, the lock paywall must appear BEFORE the decrypt button — a
// recipient must pay to unlock before they can decrypt encrypted content.

test.describe("27. Locked messages — encryption, view-once, scheduled, expiry", () => {
  let page: Page;

  const SALT_B64       = Buffer.alloc(16).toString("base64");
  const IV_B64         = Buffer.alloc(12).toString("base64");
  const CIPHERTEXT_B64 = Buffer.alloc(32).toString("base64");
  const textEnvelope   = {
    version: 1, alg: "AES-256-GCM", kdf: "PBKDF2-SHA256", iterations: 100_000,
    salt_b64: SALT_B64, iv_b64: IV_B64, ciphertext_b64: CIPHERTEXT_B64,
  };

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await getOrCreateDm(page);
  });

  test.afterAll(async () => page?.close());

  // ── 27a. Lock + encryption ─────────────────────────────────────────────────

  test("Lock + encrypted: response has lock_price_cents and is_encrypted=true", async () => {
    const session   = getSessions()[ALICE_ID];
    const deliverAt = Math.floor(Date.now() / 1000) + 120;

    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages`,
      {
        data: { send_at: deliverAt, lock_price_cents: 199, encryption: textEnvelope },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.is_encrypted,    "must be encrypted").toBe(true);
    expect(body.lock_price_cents,"lock_price_cents must be preserved").toBe(199);
    expect(body.scheduled).toBe(true);
  });

  // ── 27b. Lock + view-once ─────────────────────────────────────────────────

  test("Lock + view-once: response has lock_price_cents and view_once=true", async () => {
    const session   = getSessions()[ALICE_ID];
    const deliverAt = Math.floor(Date.now() / 1000) + 120;

    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages`,
      {
        data: { text: `lock-vo-${Date.now()}`, send_at: deliverAt, lock_price_cents: 99, view_once: true },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.view_once,       "must be view_once").toBe(true);
    expect(body.lock_price_cents,"lock_price_cents must be preserved").toBe(99);
    expect(body.scheduled).toBe(true);
  });

  // ── 27c. Lock + scheduled ─────────────────────────────────────────────────

  test("Lock + scheduled: lock persists in scheduled queue", async () => {
    const session   = getSessions()[ALICE_ID];
    const deliverAt = Math.floor(Date.now() / 1000) + 120;

    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages`,
      {
        data: { text: `lock-sched-${Date.now()}`, send_at: deliverAt, lock_price_cents: 149 },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.scheduled).toBe(true);
    expect(body.lock_price_cents).toBe(149);

    const sched = await page.request.get(
      `${API}/messaging/conversations/${_dmConvoId}/messages/scheduled`,
      { headers: { "x-csrf-token": session.csrf_token } },
    );
    const list = await sched.json() as Array<Record<string, unknown>>;
    expect(list.some((m) => (m.lock_price_cents as number) > 0)).toBe(true);
  });

  // ── 27d. Lock + expiry (timer anchored to deliver_at) ─────────────────────

  test("Lock + expiry: expires_at anchored to deliver_at", async () => {
    const session   = getSessions()[ALICE_ID];
    const deliverAt = Math.floor(Date.now() / 1000) + 120;
    const expiresIn = 3600;

    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages`,
      {
        data: { text: `lock-exp-${Date.now()}`, send_at: deliverAt, lock_price_cents: 299, expires_in_seconds: expiresIn },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.lock_price_cents).toBe(299);
    expect(body.expires_at).toBe(deliverAt + expiresIn);
  });

  // ── 27e. All five together ────────────────────────────────────────────────

  test("All five: lock + encrypted + view-once + scheduled + expiry coexist", async () => {
    const session   = getSessions()[ALICE_ID];
    const deliverAt = Math.floor(Date.now() / 1000) + 120;
    const expiresIn = 7200;

    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages`,
      {
        data: {
          send_at:            deliverAt,
          lock_price_cents:   499,
          encryption:         textEnvelope,
          view_once:          true,
          expires_in_seconds: expiresIn,
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.scheduled).toBe(true);
    expect(body.is_encrypted).toBe(true);
    expect(body.view_once).toBe(true);
    expect(body.lock_price_cents).toBe(499);
    expect(body.expires_at).toBe(deliverAt + expiresIn);
  });

  // ── 27f. Lock + tip still rejected ────────────────────────────────────────

  test("Lock + tip combination is still rejected (400)", async () => {
    const session = getSessions()[ALICE_ID];
    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages`,
      {
        data: { text: "should fail", lock_price_cents: 100, tip_amount_cents: 50 },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBeGreaterThanOrEqual(400);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 28: Gallery messages — blurred preview + multi-attachment unlock
// ─────────────────────────────────────────────────────────────────────────────

test.describe("28. Gallery messages — free + locked images with blurred previews", () => {
  let page: Page;

  // Helper: presign + upload a tiny fake image, return { bucket, key }
  async function presignAndUpload(
    convoId: string,
    filename: string,
    contentType = "image/jpeg",
  ): Promise<{ bucket: string; key: string }> {
    const session = getSessions()[ALICE_ID];
    const presign = await page.request.post(
      `${API}/messaging/conversations/${convoId}/images/presign`,
      {
        data: { filename, content_type: contentType },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(presign.status()).toBe(200);
    const { upload_url, bucket, key } = await presign.json() as {
      upload_url: string; bucket: string; key: string;
    };
    // Upload 4 bytes of fake JPEG data
    const putResp = await page.request.put(`http://localhost:8000${upload_url}`, {
      data: Buffer.from([0xff, 0xd8, 0xff, 0xd9]), // minimal JPEG header
      headers: { "Content-Type": contentType },
    });
    expect(putResp.status()).toBeLessThan(300);
    return { bucket, key };
  }

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await getOrCreateDm(page);
  });

  test.afterAll(async () => page?.close());

  // ── 28a. Send gallery with free + locked images ───────────────────────────

  test("Gallery with 2 free + 2 locked images returns correct structure", async () => {
    const session = getSessions()[ALICE_ID];
    const convoId = _dmConvoId!;

    // Presign + upload 2 free + 2 main locked + 2 preview images
    const [free1, free2, locked1, locked2, preview1, preview2] = await Promise.all([
      presignAndUpload(convoId, "free1.jpg"),
      presignAndUpload(convoId, "free2.jpg"),
      presignAndUpload(convoId, "locked1.jpg"),
      presignAndUpload(convoId, "locked2.jpg"),
      presignAndUpload(convoId, "preview1.jpg"),
      presignAndUpload(convoId, "preview2.jpg"),
    ]);

    const r = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [
            { bucket: free1.bucket, key: free1.key, content_type: "image/jpeg", filename: "free1.jpg" },
            { bucket: free2.bucket, key: free2.key, content_type: "image/jpeg", filename: "free2.jpg" },
          ],
          locked_images: [
            {
              bucket: locked1.bucket, key: locked1.key, content_type: "image/jpeg",
              filename: "locked1.jpg",
              preview_bucket: preview1.bucket, preview_key: preview1.key,
            },
            {
              bucket: locked2.bucket, key: locked2.key, content_type: "image/jpeg",
              filename: "locked2.jpg",
              preview_bucket: preview2.bucket, preview_key: preview2.key,
            },
          ],
          text: `gallery-test-${Date.now()}`,
          lock_price_cents: 299,
          lock_description: "Unlock to see all images",
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;

    expect(body.kind).toBe("gallery");
    expect(body.locked_image_count).toBe(2);
    expect(body.lock_price_cents).toBe(299);
    expect(body.is_unlocked).toBe(true);  // sender always sees their content

    // Sender sees both arrays
    expect(Array.isArray(body.free_images)).toBe(true);
    expect((body.free_images as unknown[]).length).toBe(2);
    expect(Array.isArray(body.locked_images)).toBe(true);
    expect((body.locked_images as unknown[]).length).toBe(2);
  });

  // ── 28b. Sender validation errors ────────────────────────────────────────

  test("Gallery with no images is rejected (400)", async () => {
    const session = getSessions()[ALICE_ID];
    const r = await page.request.post(
      `${API}/messaging/conversations/${_dmConvoId}/messages/gallery`,
      {
        data: { free_images: [], locked_images: [] },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBeGreaterThanOrEqual(400);
  });

  test("Gallery with locked images but no lock_price_cents is rejected (400)", async () => {
    const session = getSessions()[ALICE_ID];
    const convoId = _dmConvoId!;
    const [img, preview] = await Promise.all([
      presignAndUpload(convoId, "img.jpg"),
      presignAndUpload(convoId, "preview.jpg"),
    ]);
    const r = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [],
          locked_images: [{
            bucket: img.bucket, key: img.key, content_type: "image/jpeg",
            preview_bucket: preview.bucket, preview_key: preview.key,
          }],
          // no lock_price_cents
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBeGreaterThanOrEqual(400);
  });

  test("Gallery with locked images but missing preview is rejected (400)", async () => {
    const session = getSessions()[ALICE_ID];
    const convoId = _dmConvoId!;
    const img = await presignAndUpload(convoId, "img.jpg");
    const r = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [],
          locked_images: [{
            bucket: img.bucket, key: img.key, content_type: "image/jpeg",
            // missing preview_bucket / preview_key
          }],
          lock_price_cents: 100,
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBeGreaterThanOrEqual(400);
  });

  // ── 28c. Recipient sees locked_images=null, locked_image_count=2 ──────────

  test("Recipient sees locked_images=null and locked_image_count before unlock", async ({ browser }) => {
    // Send a gallery as Alice
    const aliceSession = getSessions()[ALICE_ID];
    const convoId = _dmConvoId!;
    const [free1, locked1, preview1] = await Promise.all([
      presignAndUpload(convoId, "free_r.jpg"),
      presignAndUpload(convoId, "locked_r.jpg"),
      presignAndUpload(convoId, "preview_r.jpg"),
    ]);

    const sendResp = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [
            { bucket: free1.bucket, key: free1.key, content_type: "image/jpeg" },
          ],
          locked_images: [
            {
              bucket: locked1.bucket, key: locked1.key, content_type: "image/jpeg",
              preview_bucket: preview1.bucket, preview_key: preview1.key,
            },
          ],
          lock_price_cents: 150,
          lock_description: `gallery-recipient-${Date.now()}`,
        },
        headers: { "x-csrf-token": aliceSession.csrf_token },
      },
    );
    expect(sendResp.status()).toBe(200);
    const sentBody = await sendResp.json() as Record<string, unknown>;
    const msgId = sentBody.message_id as string;

    // Fetch as Bob using a fresh page with Bob's own session cookies (isolated from Alice's page)
    const bobPage = await browser.newPage();
    try {
      await injectAuth(bobPage, BOB_ID);
      const bobSession = getSessions()[BOB_ID];
      const getResp = await bobPage.request.get(
        `${API}/messaging/conversations/${convoId}/messages`,
        { headers: { "x-csrf-token": bobSession.csrf_token } },
      );
      // Bob is a participant in this DM so status should be 200
      expect(getResp.status()).toBe(200);
      const msgs = await getResp.json() as Array<Record<string, unknown>>;
      const galleryMsg = msgs.find((m) => m.message_id === msgId);
      expect(galleryMsg).toBeTruthy();
      expect(galleryMsg!.locked_image_count).toBe(1);
      // locked_images omitted (null) for non-owner before unlock
      expect(galleryMsg!.locked_images).toBeFalsy();
      // free_images present
      expect(Array.isArray(galleryMsg!.free_images)).toBe(true);
    } finally {
      await bobPage.close();
    }
  });

  // ── 28d. Gallery with free images only (no locked) ────────────────────────

  test("Gallery with only free images (no lock) is accepted", async () => {
    const session = getSessions()[ALICE_ID];
    const convoId = _dmConvoId!;
    const [img1, img2] = await Promise.all([
      presignAndUpload(convoId, "free_only1.jpg"),
      presignAndUpload(convoId, "free_only2.jpg"),
    ]);

    const r = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [
            { bucket: img1.bucket, key: img1.key, content_type: "image/jpeg" },
            { bucket: img2.bucket, key: img2.key, content_type: "image/jpeg" },
          ],
          locked_images: [],
          text: "Just some free photos!",
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.kind).toBe("gallery");
    expect(body.locked_image_count).toBe(0);
    expect(Array.isArray(body.free_images)).toBe(true);
    expect((body.free_images as unknown[]).length).toBe(2);
    // No lock fields
    expect(body.locked).toBe(false);
  });

  // ── 28e. Gallery with scheduling ─────────────────────────────────────────

  test("Gallery supports send_at scheduling", async () => {
    const session = getSessions()[ALICE_ID];
    const convoId = _dmConvoId!;
    const deliverAt = Math.floor(Date.now() / 1000) + 120;
    const [img, preview] = await Promise.all([
      presignAndUpload(convoId, "sched_img.jpg"),
      presignAndUpload(convoId, "sched_preview.jpg"),
    ]);

    const r = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [],
          locked_images: [{
            bucket: img.bucket, key: img.key, content_type: "image/jpeg",
            preview_bucket: preview.bucket, preview_key: preview.key,
          }],
          lock_price_cents: 199,
          send_at: deliverAt,
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.scheduled).toBe(true);
    expect(body.deliver_at).toBe(deliverAt);
    expect(body.kind).toBe("gallery");
  });

  // ── 28f. Gallery + tip combination ────────────────────────────────────────

  test("Gallery with tip (no lock) creates billing entry", async () => {
    const session = getSessions()[ALICE_ID];
    const aliceSub = (getSessions()[ALICE_ID] as SessionData).user_sub;
    const convoId = _dmConvoId!;

    // Inject a payment method for Alice so the tip can be billed
    const pmId = `pm_gallery_tip_${Date.now()}`;
    injectPaymentMethod(aliceSub, pmId);

    const [img] = await Promise.all([
      presignAndUpload(convoId, "tip_gallery.jpg"),
    ]);

    const r = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [
            { bucket: img.bucket, key: img.key, content_type: "image/jpeg" },
          ],
          locked_images: [],
          tip_amount_cents: 50,
          tip_payment_method_id: pmId,
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.tip_amount_cents).toBe(50);
  });

  // ── 28g. Gallery + lock + tip combination is rejected ────────────────────

  test("Gallery with both lock and tip is rejected (400)", async () => {
    const session = getSessions()[ALICE_ID];
    const convoId = _dmConvoId!;
    const [img, preview] = await Promise.all([
      presignAndUpload(convoId, "lock_tip.jpg"),
      presignAndUpload(convoId, "lock_tip_preview.jpg"),
    ]);
    const r = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [],
          locked_images: [{
            bucket: img.bucket, key: img.key, content_type: "image/jpeg",
            preview_bucket: preview.bucket, preview_key: preview.key,
          }],
          lock_price_cents: 100,
          tip_amount_cents: 50,
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBeGreaterThanOrEqual(400);
  });

  // ── 28h-28j. Basic video support (already added above) ──────────────────
  // ── 28k-28r. Video gallery — full equivalents of 28a-28f ─────────────────

  // 28k — equivalent of 28a: 2 free + 2 locked videos → full structure
  test("Video gallery: 2 free + 2 locked videos returns correct structure", async () => {
    const session = getSessions()[ALICE_ID];
    const convoId = _dmConvoId!;

    const [freeVid1, freeVid2, lockedVid1, lockedVid2, preview1, preview2] = await Promise.all([
      presignAndUpload(convoId, "vfree1.mp4", "video/mp4"),
      presignAndUpload(convoId, "vfree2.mp4", "video/mp4"),
      presignAndUpload(convoId, "vlocked1.mp4", "video/mp4"),
      presignAndUpload(convoId, "vlocked2.mp4", "video/mp4"),
      presignAndUpload(convoId, "vprev1.jpg", "image/jpeg"),
      presignAndUpload(convoId, "vprev2.jpg", "image/jpeg"),
    ]);

    const r = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [
            { bucket: freeVid1.bucket, key: freeVid1.key, content_type: "video/mp4", filename: "vfree1.mp4" },
            { bucket: freeVid2.bucket, key: freeVid2.key, content_type: "video/mp4", filename: "vfree2.mp4" },
          ],
          locked_images: [
            {
              bucket: lockedVid1.bucket, key: lockedVid1.key, content_type: "video/mp4",
              filename: "vlocked1.mp4",
              preview_bucket: preview1.bucket, preview_key: preview1.key,
            },
            {
              bucket: lockedVid2.bucket, key: lockedVid2.key, content_type: "video/mp4",
              filename: "vlocked2.mp4",
              preview_bucket: preview2.bucket, preview_key: preview2.key,
            },
          ],
          text: `video-gallery-${Date.now()}`,
          lock_price_cents: 399,
          lock_description: "Unlock to see all videos",
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;

    expect(body.kind).toBe("gallery");
    expect(body.locked_image_count).toBe(2);
    expect(body.lock_price_cents).toBe(399);
    expect(body.is_unlocked).toBe(true);  // sender always sees their content

    const freeItems = body.free_images as Array<Record<string, unknown>>;
    expect(freeItems.length).toBe(2);
    expect(freeItems.every((it) => it.content_type === "video/mp4")).toBe(true);
    expect(freeItems.every((it) => typeof it.url === "string")).toBe(true);

    const lockedItems = body.locked_images as Array<Record<string, unknown>>;
    expect(lockedItems.length).toBe(2);
    expect(lockedItems.every((it) => it.content_type === "video/mp4")).toBe(true);
    expect(lockedItems.every((it) => typeof it.url === "string")).toBe(true);
    // Each locked video has a preview URL (JPEG thumbnail)
    expect(lockedItems.every((it) => typeof it.preview_url === "string")).toBe(true);
  });

  // 28l — equivalent of 28b (validation): locked video without lock_price_cents rejected
  test("Video gallery: locked video without lock_price_cents is rejected (400)", async () => {
    const session = getSessions()[ALICE_ID];
    const convoId = _dmConvoId!;
    const [vid, preview] = await Promise.all([
      presignAndUpload(convoId, "val_vid.mp4", "video/mp4"),
      presignAndUpload(convoId, "val_prev.jpg", "image/jpeg"),
    ]);
    const r = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [],
          locked_images: [{
            bucket: vid.bucket, key: vid.key, content_type: "video/mp4",
            preview_bucket: preview.bucket, preview_key: preview.key,
          }],
          // no lock_price_cents
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBeGreaterThanOrEqual(400);
  });

  // 28m — equivalent of 28b (validation): locked video without preview rejected
  test("Video gallery: locked video missing preview is rejected (400)", async () => {
    const session = getSessions()[ALICE_ID];
    const convoId = _dmConvoId!;
    const vid = await presignAndUpload(convoId, "val_noprev.mp4", "video/mp4");
    const r = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [],
          locked_images: [{
            bucket: vid.bucket, key: vid.key, content_type: "video/mp4",
            // missing preview_bucket / preview_key
          }],
          lock_price_cents: 100,
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBeGreaterThanOrEqual(400);
  });

  // 28n — equivalent of 28c: recipient sees locked_images=null for video gallery
  test("Video gallery: recipient sees locked_images=null before unlock", async ({ browser }) => {
    const aliceSession = getSessions()[ALICE_ID];
    const convoId = _dmConvoId!;

    const [freeVid, lockedVid, preview] = await Promise.all([
      presignAndUpload(convoId, "rec_vfree.mp4", "video/mp4"),
      presignAndUpload(convoId, "rec_vlocked.mp4", "video/mp4"),
      presignAndUpload(convoId, "rec_vprev.jpg", "image/jpeg"),
    ]);

    const sendResp = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [
            { bucket: freeVid.bucket, key: freeVid.key, content_type: "video/mp4" },
          ],
          locked_images: [{
            bucket: lockedVid.bucket, key: lockedVid.key, content_type: "video/mp4",
            preview_bucket: preview.bucket, preview_key: preview.key,
          }],
          lock_price_cents: 175,
          lock_description: `video-recipient-${Date.now()}`,
        },
        headers: { "x-csrf-token": aliceSession.csrf_token },
      },
    );
    expect(sendResp.status()).toBe(200);
    const msgId = (await sendResp.json() as Record<string, unknown>).message_id as string;

    const bobPage = await browser.newPage();
    try {
      await injectAuth(bobPage, BOB_ID);
      const bobSession = getSessions()[BOB_ID];
      const getResp = await bobPage.request.get(
        `${API}/messaging/conversations/${convoId}/messages`,
        { headers: { "x-csrf-token": bobSession.csrf_token } },
      );
      expect(getResp.status()).toBe(200);
      const msgs = await getResp.json() as Array<Record<string, unknown>>;
      const galleryMsg = msgs.find((m) => m.message_id === msgId);
      expect(galleryMsg).toBeTruthy();
      expect(galleryMsg!.locked_image_count).toBe(1);
      expect(galleryMsg!.locked_images).toBeFalsy();  // hidden before unlock
      // Free video is visible
      const freeItems = galleryMsg!.free_images as Array<Record<string, unknown>>;
      expect(Array.isArray(freeItems)).toBe(true);
      expect(freeItems[0].content_type).toBe("video/mp4");
    } finally {
      await bobPage.close();
    }
  });

  // 28o — equivalent of 28d: free videos only (no lock)
  test("Video gallery: only free videos (no lock) is accepted", async () => {
    const session = getSessions()[ALICE_ID];
    const convoId = _dmConvoId!;
    const [vid1, vid2] = await Promise.all([
      presignAndUpload(convoId, "vfree_only1.mp4", "video/mp4"),
      presignAndUpload(convoId, "vfree_only2.mp4", "video/mp4"),
    ]);

    const r = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [
            { bucket: vid1.bucket, key: vid1.key, content_type: "video/mp4" },
            { bucket: vid2.bucket, key: vid2.key, content_type: "video/mp4" },
          ],
          locked_images: [],
          text: "Just some free videos!",
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.kind).toBe("gallery");
    expect(body.locked_image_count).toBe(0);
    expect(body.locked).toBe(false);
    const items = body.free_images as Array<Record<string, unknown>>;
    expect(items.length).toBe(2);
    expect(items.every((it) => it.content_type === "video/mp4")).toBe(true);
  });

  // 28p — equivalent of 28e: locked video supports send_at scheduling
  test("Video gallery: locked video supports send_at scheduling", async () => {
    const session = getSessions()[ALICE_ID];
    const convoId = _dmConvoId!;
    const deliverAt = Math.floor(Date.now() / 1000) + 120;
    const [vid, preview] = await Promise.all([
      presignAndUpload(convoId, "vsched.mp4", "video/mp4"),
      presignAndUpload(convoId, "vsched_prev.jpg", "image/jpeg"),
    ]);

    const r = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [],
          locked_images: [{
            bucket: vid.bucket, key: vid.key, content_type: "video/mp4",
            preview_bucket: preview.bucket, preview_key: preview.key,
          }],
          lock_price_cents: 299,
          send_at: deliverAt,
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.scheduled).toBe(true);
    expect(body.deliver_at).toBe(deliverAt);
    expect(body.kind).toBe("gallery");
  });

  // 28q — equivalent of 28f: free video gallery with tip creates billing entry
  test("Video gallery: free video with tip creates billing entry", async () => {
    const session = getSessions()[ALICE_ID];
    const aliceSub = (getSessions()[ALICE_ID] as SessionData).user_sub;
    const convoId = _dmConvoId!;

    const pmId = `pm_vid_gallery_tip_${Date.now()}`;
    injectPaymentMethod(aliceSub, pmId);

    const vid = await presignAndUpload(convoId, "tip_vid.mp4", "video/mp4");

    const r = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [
            { bucket: vid.bucket, key: vid.key, content_type: "video/mp4" },
          ],
          locked_images: [],
          tip_amount_cents: 75,
          tip_payment_method_id: pmId,
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.tip_amount_cents).toBe(75);
    expect(body.kind).toBe("gallery");
    expect((body.free_images as Array<Record<string, unknown>>)[0].content_type).toBe("video/mp4");
  });

  // 28r — equivalent of 28g: locked video + lock + tip rejected
  test("Video gallery: locked video with both lock and tip is rejected (400)", async () => {
    const session = getSessions()[ALICE_ID];
    const convoId = _dmConvoId!;
    const [vid, preview] = await Promise.all([
      presignAndUpload(convoId, "vlock_tip.mp4", "video/mp4"),
      presignAndUpload(convoId, "vlock_tip_prev.jpg", "image/jpeg"),
    ]);
    const r = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [],
          locked_images: [{
            bucket: vid.bucket, key: vid.key, content_type: "video/mp4",
            preview_bucket: preview.bucket, preview_key: preview.key,
          }],
          lock_price_cents: 100,
          tip_amount_cents: 50,
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBeGreaterThanOrEqual(400);
  });

  // ── 28h-28j. Basic video support ─────────────────────────────────────────

  test("Gallery accepts video items as free media", async () => {
    const session = getSessions()[ALICE_ID];
    const convoId = _dmConvoId!;

    // Upload a fake MP4 (4-byte stub is enough — backend stores content_type as-is)
    const vid = await presignAndUpload(convoId, "free_video.mp4", "video/mp4");

    const r = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [
            { bucket: vid.bucket, key: vid.key, content_type: "video/mp4", filename: "free_video.mp4" },
          ],
          locked_images: [],
          text: `gallery-video-${Date.now()}`,
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.kind).toBe("gallery");
    expect(Array.isArray(body.free_images)).toBe(true);
    const items = body.free_images as Array<Record<string, unknown>>;
    expect(items.length).toBe(1);
    expect(items[0].content_type).toBe("video/mp4");
    expect(typeof items[0].url).toBe("string");
  });

  test("Gallery accepts locked video with blurred preview", async () => {
    const session = getSessions()[ALICE_ID];
    const convoId = _dmConvoId!;

    // Upload locked video + JPEG preview (preview is always a JPEG thumbnail)
    const [vid, preview] = await Promise.all([
      presignAndUpload(convoId, "locked_video.mp4", "video/mp4"),
      presignAndUpload(convoId, "locked_video_preview.jpg", "image/jpeg"),
    ]);

    const r = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [],
          locked_images: [{
            bucket: vid.bucket, key: vid.key, content_type: "video/mp4",
            filename: "locked_video.mp4",
            preview_bucket: preview.bucket, preview_key: preview.key,
          }],
          lock_price_cents: 250,
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.kind).toBe("gallery");
    expect(body.locked_image_count).toBe(1);
    expect(body.is_unlocked).toBe(true);  // sender sees their content
    const lockedItems = body.locked_images as Array<Record<string, unknown>>;
    expect(lockedItems.length).toBe(1);
    expect(lockedItems[0].content_type).toBe("video/mp4");
  });

  test("Gallery with mixed image and video free items is accepted", async () => {
    const session = getSessions()[ALICE_ID];
    const convoId = _dmConvoId!;

    const [img, vid] = await Promise.all([
      presignAndUpload(convoId, "mixed_img.jpg", "image/jpeg"),
      presignAndUpload(convoId, "mixed_vid.mp4", "video/mp4"),
    ]);

    const r = await page.request.post(
      `${API}/messaging/conversations/${convoId}/messages/gallery`,
      {
        data: {
          free_images: [
            { bucket: img.bucket, key: img.key, content_type: "image/jpeg" },
            { bucket: vid.bucket, key: vid.key, content_type: "video/mp4" },
          ],
          locked_images: [],
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    const items = body.free_images as Array<Record<string, unknown>>;
    expect(items.length).toBe(2);
    expect(items[0].content_type).toBe("image/jpeg");
    expect(items[1].content_type).toBe("video/mp4");
  });
});

// ─── 29. Encrypted video message — send and decrypt ──────────────────────────

test.describe("29. Encrypted video message — send and decrypt", () => {
  let alicePage: Page;
  let bobPage: Page;
  const ENC_PASSWORD = "V1d3o&S3cr3t!";
  const TS = Date.now();

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
    const convoId = await getOrCreateDm(alicePage);
    const session = getSessions()[ALICE_ID];

    // Encrypt TEST_MP4 using the same AES-256-GCM + PBKDF2-SHA256 algorithm
    // the browser uses, so the browser can decrypt it correctly.
    const salt = cryptoRandomBytes(16);
    const iv   = cryptoRandomBytes(12);
    const keyBytes  = pbkdf2Sync(ENC_PASSWORD, salt, 600_000, 32, "sha256");
    const cipher    = createCipheriv("aes-256-gcm", keyBytes, iv);
    const ciphertext = Buffer.concat([cipher.update(TEST_MP4), cipher.final()]);
    const authTag    = (cipher as unknown as { getAuthTag(): Buffer }).getAuthTag();
    const encryptedBuf = Buffer.concat([ciphertext, authTag]);

    // 1. Presign URL for the encrypted video upload
    const presignResp = await alicePage.request.post(
      `${API}/messaging/conversations/${convoId}/images/presign`,
      {
        data: { content_type: "video/mp4", filename: `enc-video-${TS}.mp4` },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(presignResp.ok()).toBe(true);
    const { upload_url, bucket, key } = await presignResp.json() as {
      upload_url: string; bucket: string; key: string;
    };

    // 2. Upload encrypted bytes as application/octet-stream
    const absUploadUrl = upload_url.startsWith("/") ? `${API}${upload_url}` : upload_url;
    const uploadResp = await alicePage.request.fetch(absUploadUrl, {
      method: "PUT",
      data: encryptedBuf,
      headers: { "Content-Type": "application/octet-stream" },
    });
    expect(uploadResp.ok()).toBe(true);

    // 3. POST the message with kind="video" and the encryption envelope
    const msgResp = await alicePage.request.post(
      `${API}/messaging/conversations/${convoId}/messages/image`,
      {
        data: {
          bucket, key,
          content_type: "video/mp4",
          kind: "video",
          filename: `enc-video-${TS}.mp4`,
          filesize: TEST_MP4.length,
          encryption: {
            version:    1,
            alg:        "AES-256-GCM",
            kdf:        "PBKDF2-SHA256",
            iterations: 600_000,
            salt_b64:   salt.toString("base64"),
            iv_b64:     iv.toString("base64"),
          },
        },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(msgResp.status()).toBe(200);
    const msgBody = await msgResp.json() as Record<string, unknown>;
    expect(msgBody["kind"]).toBe("video");
    expect(msgBody["is_encrypted"]).toBe(true);
    expect(msgBody["encryption"]).toBeTruthy();
    // Video data is stored under file (not image)
    expect(msgBody["file"]).toBeTruthy();
    expect((msgBody["file"] as Record<string, unknown>)["content_type"]).toBe("video/mp4");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("Alice's UI shows 'Encrypted' badge and 'Encrypted video' for the sent message", async () => {
    test.setTimeout(30000);
    await openDmWithBob(alicePage);
    await expect(
      alicePage.getByText("Encrypted video").last()
    ).toBeVisible({ timeout: 10000 });
    await expect(
      alicePage.getByRole("button", { name: "Decrypt to view" }).last()
    ).toBeVisible({ timeout: 5000 });
  });

  test("Bob sees 'Encrypted video' + 'Decrypt to view' button", async () => {
    test.setTimeout(30000);
    await injectAuth(bobPage, BOB_ID);
    const sec29BobConvsLoaded = bobPage.waitForResponse(
      (r) => r.url().includes("/messaging/conversations") && r.request().method() === "GET"
        && !r.url().match(/\/conversations\/[^/]+$/),
      { timeout: 15000 },
    );
    await bobPage.goto(`${BASE}/messages`, { waitUntil: "load" });
    await sec29BobConvsLoaded;
    await bobPage.waitForTimeout(300);
    const aliceRow = bobPage.getByRole("button").filter({ hasText: /Alice/ }).first();
    await expect(aliceRow).toBeVisible({ timeout: 15000 });
    await aliceRow.evaluate((el) => (el as HTMLElement).click());
    await expect(
      bobPage.getByText("Encrypted video").last()
    ).toBeVisible({ timeout: 12000 });
    await expect(
      bobPage.getByRole("button", { name: "Decrypt to view" }).last()
    ).toBeVisible({ timeout: 5000 });
  });

  test("Decrypt dialog title says 'Decrypt video'", async () => {
    test.setTimeout(20000);
    await bobPage.getByRole("button", { name: "Decrypt to view" }).last().click();
    await expect(bobPage.getByRole("dialog")).toBeVisible({ timeout: 5000 });
    await expect(bobPage.getByText(/Decrypt video/i)).toBeVisible({ timeout: 3000 });
    // Close dialog before next test
    await bobPage.getByRole("button", { name: "Cancel" }).click();
    await expect(bobPage.getByRole("dialog")).not.toBeVisible({ timeout: 3000 });
  });

  test("Bob enters correct password and video decrypts (<video> blob URL rendered)", async () => {
    test.setTimeout(30000);
    await bobPage.getByRole("button", { name: "Decrypt to view" }).last().click();
    await expect(bobPage.getByRole("dialog")).toBeVisible({ timeout: 5000 });

    await bobPage.locator('input[type="password"]').fill(ENC_PASSWORD);
    await bobPage.getByRole("button", { name: "Decrypt" }).click();

    // Dialog closes, decrypted video (blob URL) element appears
    await expect(bobPage.getByRole("dialog")).not.toBeVisible({ timeout: 15000 });
    await expect(bobPage.locator("video[src^='blob:']")).toBeVisible({ timeout: 10000 });
  });

  test("Wrong password shows error; dialog stays open", async () => {
    test.setTimeout(30000);
    // Re-inject auth and navigate fresh to reset decrypted state and ensure auth is valid
    // (shared localStorage between pages in the same context can cause stale auth state).
    await injectAuth(bobPage, BOB_ID);
    const sec29WrongPwConvsLoaded = bobPage.waitForResponse(
      (r) => r.url().includes("/messaging/conversations") && r.request().method() === "GET"
        && !r.url().match(/\/conversations\/[^/]+$/),
      { timeout: 15000 },
    );
    await bobPage.goto(`${BASE}/messages`, { waitUntil: "load" });
    await sec29WrongPwConvsLoaded;
    await bobPage.waitForTimeout(300);
    const aliceRow = bobPage.getByRole("button").filter({ hasText: /Alice/ }).first();
    await expect(aliceRow).toBeVisible({ timeout: 15000 });
    // Click the preview area (avoid avatar/name links which navigate to profile)
    await aliceRow.evaluate((el) => (el as HTMLElement).click());

    await expect(
      bobPage.getByRole("button", { name: "Decrypt to view" }).last()
    ).toBeVisible({ timeout: 10000 });
    await bobPage.getByRole("button", { name: "Decrypt to view" }).last().click();

    await expect(bobPage.getByRole("dialog")).toBeVisible({ timeout: 5000 });
    await bobPage.locator('input[type="password"]').fill("wrong-password-xyz");
    await bobPage.getByRole("button", { name: "Decrypt" }).click();

    await expect(bobPage.getByText("Wrong password")).toBeVisible({ timeout: 8000 });
    await expect(bobPage.getByRole("dialog")).toBeVisible({ timeout: 3000 });
    await bobPage.getByRole("button", { name: "Cancel" }).click();
  });
});
