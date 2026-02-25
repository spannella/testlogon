/**
 * E2E regression tests for the 8 bug fixes.
 *
 * Bug 1: TOTP registration — same-window code rejected
 * Bug 2: Expired message shows stub immediately (no reload needed)
 * Bug 3: Scheduled message appears in sender's chat without reload
 * Bug 4: View-once consumed shows "Already viewed" stub (not tap box)
 * Bug 5: Compose-bar "Attach tip" checkbox disabled when no payment method
 * Bug 6: View-once text not auto-consumed when message scrolls into view
 * Bug 7: Locked-message unlock button opens a confirmation dialog
 * Bug 8: API Keys — Info button opens usage dialog; CIDR list UI works
 *
 * Auth pattern matches messaging-features.spec.ts.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";

// Python interpreter that has pyotp installed.
const PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";

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
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
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

/**
 * Register the Playwright browser as a known device with the backend.
 *
 * The first API call from a new browser context triggers the device-trust
 * check and returns 401 "Re-auth required" when the user has no MFA factors.
 * However, the device IS stored in DynamoDB during that first call, so all
 * subsequent calls from the same context succeed (new_device=false).
 *
 * Calling this warmup function ensures that any POST made immediately
 * afterward will see an already-known device.
 */
async function warmupDevice(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  // Attempt a GET — it may return 401 on the first ever call (device
  // registration), but that's fine; the device is registered regardless.
  await page.request
    .get(`${API}/messaging/conversations`, {
      headers: { "x-csrf-token": session.csrf_token },
    })
    .catch(() => {});
  // Second call: device is now known, should succeed.
  await page.request
    .get(`${API}/messaging/conversations`, {
      headers: { "x-csrf-token": session.csrf_token },
    })
    .catch(() => {});
}

// ─── Refetch trigger ──────────────────────────────────────────────────────────

/**
 * Force React Query to refetch messages/conversations without navigating away.
 *
 * ConversationView listens to the browser's `online` event and calls
 * `queryClient.invalidateQueries` for both messages and conversations.
 * Dispatching this event is a reliable way to trigger a refetch after an
 * API-level message send (which bypasses the UI's optimistic update path).
 *
 * This is equivalent to the real-time SSE path: both ultimately invalidate
 * the same queries without any page navigation.
 */
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

  // If there are multiple E2E DMs from past test runs, the newest DM (just
  // created by getOrCreateDm) has no messages and therefore sits at the bottom
  // of the list (sorted by last_message_at).  Send a "touch" message so that
  // _dmConvoId becomes the most-recently-active conversation and therefore
  // the FIRST "E2E Bob" row after navigating.
  const session = getSessions()[ALICE_ID];
  await page.request.post(`${API}/messaging/conversations/${convoId}/messages`, {
    data: { text: `__touch__${Date.now()}` },
    headers: { "x-csrf-token": session.csrf_token },
  }).catch(() => {});

  await page.goto(`${BASE}/messages`, { waitUntil: "load" });
  await page.waitForTimeout(800);
  const row = page.getByRole("button").filter({ hasText: "E2E Bob" }).first();
  await expect(row).toBeVisible({ timeout: 8000 });
  await row.click();
  await expect(
    page.getByPlaceholder("Type a message...").or(
      page.getByPlaceholder("Type an encrypted message..."),
    ),
  ).toBeVisible({ timeout: 5000 });
}

// ─── DDB cleanup helper ───────────────────────────────────────────────────────

const DDB_HELPER_PRELUDE = `
import boto3, os
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
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

/** Delete a TOTP device record directly from DynamoDB local. */
function deleteTotpDevice(userSub: string, deviceId: string) {
  try {
    execSync(
      `${PYTHON} -c "${DDB_HELPER_PRELUDE}
tbl = ddb.Table(os.environ.get('DDB_TOTP_TABLE', 'totp_devices'))
tbl.delete_item(Key={'user_sub': '${userSub}', 'device_id': '${deviceId}'})
print('cleaned up')
"`,
      { timeout: 10_000 },
    );
  } catch {
    /* best-effort cleanup */
  }
}

/**
 * Inject a test payment method for the given user directly into DynamoDB.
 * Required for section 7: Bob needs a payment method to enable the "Unlock for"
 * button (otherwise it's rendered disabled).
 */
function injectPaymentMethod(userSub: string, pmId: string): void {
  execSync(
    `${PYTHON} -c "
import boto3, os, time
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
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
    'priority': 0,
    'created_at': int(time.time()),
})
# Also set BILLING row so current_default_pm() finds it.
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

/** Remove the injected test payment method from DynamoDB (best-effort cleanup). */
function removePaymentMethod(userSub: string, pmId: string): void {
  try {
    execSync(
      `${PYTHON} -c "
import boto3, os
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
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

// ─── 1. Bug fix: TOTP — same-window code rejection ───────────────────────────

test.describe("1. TOTP — same-window code rejected, different-window accepted", () => {
  let page: Page;
  let deviceId = "";
  let secret = "";

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    // Register this browser device so the subsequent POST succeeds.
    // (First call may return 401 but still registers the device fingerprint.)
    await warmupDevice(page, ALICE_ID);

    const resp = await apiPost(page, "/ui/mfa/totp/devices/begin", { label: "e2e-bug1" });
    if (!resp.ok()) {
      throw new Error(`TOTP begin failed: ${resp.status()} ${await resp.text()}`);
    }
    const body = await resp.json() as { device_id: string; secret: string };
    deviceId = body.device_id;
    secret   = body.secret;
  });

  test.afterAll(async () => {
    if (deviceId) deleteTotpDevice(ALICE_ID, deviceId);
    await page?.close();
  });

  test("Confirming TOTP enrollment with the SAME code twice returns 401", async () => {
    const code = execSync(
      `${PYTHON} -c "import pyotp, time; print(pyotp.TOTP('${secret}').at(int(time.time())))"`,
      { timeout: 5000 },
    ).toString().trim();

    const resp = await apiPost(page, "/ui/mfa/totp/devices/confirm", {
      device_id:  deviceId,
      totp_code:  code,
      totp_code2: code,
    });
    // Two codes from the same 30-second window must be rejected.
    expect(resp.status()).toBe(401);
  });

  test("Confirming TOTP enrollment with codes from DIFFERENT windows returns 200", async () => {
    const codes = JSON.parse(
      execSync(
        `${PYTHON} -c "
import pyotp, time, json
t = int(time.time())
totp = pyotp.TOTP('${secret}')
print(json.dumps({'curr': totp.at(t), 'prev': totp.at(t - 30)}))
"`,
        { timeout: 5000 },
      ).toString().trim(),
    ) as { curr: string; prev: string };

    const resp = await apiPost(page, "/ui/mfa/totp/devices/confirm", {
      device_id:  deviceId,
      totp_code:  codes.prev,  // older 30-second window
      totp_code2: codes.curr,  // current 30-second window
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { ok: boolean };
    expect(body.ok).toBe(true);
  });
});

// ─── 2. Bug fix: Expired message shows stub immediately ───────────────────────

test.describe("2. Expired message — stub visible without page reload", () => {
  let page: Page;
  const TS       = Date.now();
  const MSG_TEXT = `expiry-test-${TS}`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await openDmWithBob(page);
  });

  test.afterAll(async () => page?.close());

  test("Expired message body is replaced by stub after TTL elapses (no reload)", async () => {
    test.setTimeout(45_000);

    // Send a message that expires in 12 seconds (minimum allowed value is 10 s).
    const resp = await apiPost(
      page,
      `/messaging/conversations/${_dmConvoId}/messages`,
      { text: MSG_TEXT, expires_in_seconds: 12 },
    );
    expect(resp.ok()).toBe(true);

    // Trigger a React Query refetch so the message appears without a page reload.
    // (The SSE path does the same thing in production; here we nudge it via the
    // 'online' event listener that ConversationView registers.)
    await triggerRefetch(page);
    await expect(
      page.locator("p").filter({ hasText: MSG_TEXT }),
    ).toBeVisible({ timeout: 8000 });

    // Wait for client-side expiry timer (12 s TTL + 4 s buffer).
    const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
    await sleep(16_000);

    // WITHOUT any navigation, the "This message has expired" stub must appear.
    await expect(
      page.getByText("This message has expired"),
    ).toBeVisible({ timeout: 5000 });

    // Original text must be gone.
    await expect(
      page.locator("p").filter({ hasText: MSG_TEXT }),
    ).not.toBeAttached();
  });
});

// ─── 3. Bug fix: Scheduled message appears in sender's chat without reload ────

test.describe("3. Scheduled message — appears in sender's chat after delivery", () => {
  let page: Page;
  const TS         = Date.now();
  const SCHED_TEXT = `sched-sender-${TS}`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await openDmWithBob(page);
  });

  test.afterAll(async () => page?.close());

  test("Delivered scheduled message is visible in sender's conversation (no reload)", async () => {
    // Background delivery loop runs every ~30 s.  Schedule for now+8 s;
    // total wait is at most ≈ 8+30+5 = 43 s.
    test.setTimeout(60_000);

    const deliverTs = Math.floor(Date.now() / 1000) + 8;
    const resp = await apiPost(
      page,
      `/messaging/conversations/${_dmConvoId}/messages`,
      { text: SCHED_TEXT, send_at: deliverTs },
    );
    expect(resp.status()).toBe(200);
    const { message_id: deliveryId } = (await resp.json()) as { message_id: string };

    const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

    // Poll GET /scheduled until the message disappears (delivered).
    let delivered = false;
    for (let i = 0; i < 15 && !delivered; i++) {
      await sleep(3000);
      const r = await apiGet(
        page,
        `/messaging/conversations/${_dmConvoId}/messages/scheduled`,
      );
      const list = (await r.json()) as Array<{ message_id: string }>;
      if (!list.find((m) => m.message_id === deliveryId)) delivered = true;
    }
    expect(delivered, "scheduled message should have been delivered within ~45 s").toBe(true);

    // Without navigating away, trigger a React Query refetch via the 'online'
    // event (which ConversationView listens to).  In production this would be
    // triggered by the SSE "message:new" event from the delivery loop.
    await triggerRefetch(page);
    const msgLocator = page.locator("p").filter({ hasText: SCHED_TEXT });
    await expect(msgLocator).toBeVisible({ timeout: 8000 });
  });
});

// ─── 4. Bug fix: View-once consumed — "Already viewed" stub shown ─────────────

test.describe("4. View-once text — 'Already viewed' stub after consuming", () => {
  let page: Page;
  const TS      = Date.now();
  const VO_TEXT = `vo-consumed-${TS}`;

  test.beforeAll(async ({ browser, request }) => {
    page = await browser.newPage();
    await openDmWithBob(page);

    const r = await apiPostBearer(
      request,
      `/messaging/conversations/${_dmConvoId}/messages`,
      { text: VO_TEXT, view_once: true },
      BOB_ID,
    );
    if (!r.ok()) {
      throw new Error(`Bob view-once send failed: ${r.status()} — ${await r.text()}`);
    }
    // Trigger a React Query refetch so Alice's UI picks up Bob's new message.
    await triggerRefetch(page);
  });

  test.afterAll(async () => page?.close());

  test("'Tap to view once' button appears before consuming", async () => {
    await expect(
      page.getByRole("button", { name: /tap to view once/i }),
    ).toBeVisible({ timeout: 8000 });
  });

  test("After tapping, message text becomes visible", async () => {
    await page.getByRole("button", { name: /tap to view once/i }).click();
    await expect(
      page.locator("p").filter({ hasText: VO_TEXT }),
    ).toBeVisible({ timeout: 5000 });
  });

  test("After navigating away and back, shows 'Already viewed' stub", async () => {
    // Navigate away.
    await page.goto(`${BASE}/messages`, { waitUntil: "load" });
    await page.waitForTimeout(600);

    // Navigate back to the DM.
    const row = page.getByRole("button").filter({ hasText: "E2E Bob" }).first();
    await expect(row).toBeVisible({ timeout: 8000 });
    await row.click();

    // "Tap to view once" must NOT reappear (message was already consumed).
    await expect(
      page.getByRole("button", { name: /tap to view once/i }),
    ).not.toBeVisible({ timeout: 5000 });

    // "Already viewed" stub must appear.
    await expect(page.getByText("Already viewed")).toBeVisible({ timeout: 5000 });
  });
});

// ─── 5. Bug fix: Compose tip disabled with no payment method ──────────────────

test.describe("5. Compose bar — Attach tip disabled when no payment method", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    // Alice has no payment methods by default.
    await openDmWithBob(page);
  });

  test.afterAll(async () => page?.close());

  test("'Attach tip' checkbox is disabled when Alice has no payment methods", async () => {
    // The tip label/checkbox is always rendered in the compose area.
    const tipLabel = page.locator("label", { hasText: "Attach tip" });
    await expect(tipLabel).toBeVisible({ timeout: 5000 });

    // The checkbox inside the label must be disabled.
    const checkbox = tipLabel.locator("input[type='checkbox']");
    await expect(checkbox).toBeDisabled({ timeout: 3000 });
  });

  test("Hovering 'Attach tip' shows a tooltip about missing payment method", async () => {
    const tipLabel = page.locator("label", { hasText: "Attach tip" });
    await tipLabel.hover();
    await expect(
      page.getByText(/add a payment method in billing/i),
    ).toBeVisible({ timeout: 4000 });
  });
});

// ─── 6. Bug fix: View-once text not auto-consumed on scroll ───────────────────

test.describe("6. View-once text — not auto-consumed when it scrolls into view", () => {
  let page: Page;
  const TS      = Date.now();
  const VO_TEXT = `vo-scroll-${TS}`;

  test.beforeAll(async ({ browser, request }) => {
    page = await browser.newPage();
    await openDmWithBob(page);

    const r = await apiPostBearer(
      request,
      `/messaging/conversations/${_dmConvoId}/messages`,
      { text: VO_TEXT, view_once: true },
      BOB_ID,
    );
    if (!r.ok()) {
      throw new Error(`Bob view-once send failed: ${r.status()} — ${await r.text()}`);
    }
    // Trigger a React Query refetch so Alice's UI picks up Bob's new message.
    await triggerRefetch(page);
  });

  test.afterAll(async () => page?.close());

  test("'Tap to view once' button is visible after message arrives", async () => {
    await expect(
      page.getByRole("button", { name: /tap to view once/i }),
    ).toBeVisible({ timeout: 10000 });
  });

  test("After navigating away WITHOUT tapping, the tap button is still shown (not consumed)", async () => {
    // Do NOT click the tap button — just navigate away and come back.
    await page.goto(`${BASE}/messages`, { waitUntil: "load" });
    await page.waitForTimeout(600);

    const row = page.getByRole("button").filter({ hasText: "E2E Bob" }).first();
    await expect(row).toBeVisible({ timeout: 8000 });
    await row.click();

    // If the ViewTracker auto-consumed the message via IntersectionObserver,
    // the "Tap to view once" button would be gone (replaced by "Already viewed").
    // With the fix, the button must still be present, proving non-consumption.
    // NOTE: we do NOT assert `"Already viewed" is not visible` because an earlier
    // view-once message (from section 4) in this same conversation is already
    // consumed and shows "Already viewed" — that assertion would be a false negative.
    await expect(
      page.getByRole("button", { name: /tap to view once/i }),
    ).toBeVisible({ timeout: 8000 });
  });
});

// ─── 7. Bug fix: Locked-message unlock opens a confirmation dialog ────────────

test.describe("7. Locked message — unlock button opens dialog (not direct mutation)", () => {
  const TS        = Date.now();
  const LOCK_TEXT = `lock-dialog-${TS}`;
  const LOCK_DESC = `lock-desc-${TS}`;
  const BOB_PM_ID = `e2e-test-pm-${TS}`;

  let alicePage: Page;
  let bobPage:   Page;
  let bobSub = "";

  test.beforeAll(async ({ browser }) => {
    bobSub = getSessions()[BOB_ID].user_sub;

    // Inject a fake payment method for Bob so the "Unlock for" button is enabled.
    injectPaymentMethod(bobSub, BOB_PM_ID);

    // ── Alice's page ──
    alicePage = await browser.newPage();
    await openDmWithBob(alicePage);

    // Alice sends a locked message ($1.00) via the API.
    const r = await apiPost(
      alicePage,
      `/messaging/conversations/${_dmConvoId}/messages`,
      { text: LOCK_TEXT, lock_price_cents: 100, lock_description: LOCK_DESC },
    );
    expect(r.ok()).toBe(true);

    // ── Bob's page ──
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);
    await bobPage.goto(`${BASE}/messages`, { waitUntil: "load" });
    await bobPage.waitForTimeout(800);
    const bobRow = bobPage.getByRole("button").filter({ hasText: "E2E Alice" }).first();
    await expect(bobRow).toBeVisible({ timeout: 8000 });
    await bobRow.click();
    await expect(
      bobPage.getByPlaceholder("Type a message...").or(
        bobPage.getByPlaceholder("Type an encrypted message..."),
      ),
    ).toBeVisible({ timeout: 5000 });

    // Wait for the locked message to appear on Bob's page.
    await expect(bobPage.getByText(LOCK_DESC)).toBeVisible({ timeout: 8000 });
  });

  test.afterAll(async () => {
    // Clean up the injected payment method.
    if (bobSub) removePaymentMethod(bobSub, BOB_PM_ID);
    await alicePage?.close();
    await bobPage?.close();
  });

  test("Bob sees the lock badge and 'Unlock for' button", async () => {
    await expect(
      bobPage.getByRole("button", { name: /unlock for/i }),
    ).toBeVisible({ timeout: 5000 });
  });

  test("Clicking 'Unlock for' opens a dialog with payment method section", async () => {
    // Click the Unlock button.
    await bobPage.getByRole("button", { name: /unlock for/i }).click();

    // The confirmation dialog must appear.
    const dlg = bobPage.getByRole("dialog");
    await expect(dlg).toBeVisible({ timeout: 5000 });

    // Dialog title.
    await expect(dlg).toContainText("Unlock message");

    // Payment method section and total charge summary.
    await expect(dlg).toContainText("Payment method");
    await expect(dlg).toContainText("Total charge");
    await expect(dlg).toContainText("$1.00");

    // Cancel and Pay & Unlock buttons.
    await expect(dlg.getByRole("button", { name: "Cancel" })).toBeVisible();
    await expect(dlg.getByRole("button", { name: /pay.*unlock/i })).toBeVisible();

    // Close the dialog so subsequent tests start clean.
    await dlg.getByRole("button", { name: "Cancel" }).click();
    await expect(dlg).not.toBeVisible({ timeout: 3000 });
  });

  test("After cancelling the dialog, the Unlock button is still present (message still locked)", async () => {
    // The message must still be locked after cancellation.
    await expect(
      bobPage.getByRole("button", { name: /unlock for/i }),
    ).toBeVisible({ timeout: 3000 });
  });
});

// ─── 8. Bug fix: API Keys — Info dialog and CIDR list UI ─────────────────────

test.describe("8. API Keys — 'View key details' dialog and CIDR list UI", () => {
  let page: Page;
  let keyId = "";
  const KEY_LABEL = `e2e-info-${Date.now()}`;

  async function gotoApiKeys(p: Page) {
    await injectAuth(p, ALICE_ID);
    await p.goto(`${BASE}/security`, { waitUntil: "load" });
    await p.waitForTimeout(600);
    await p.getByRole("tab", { name: "API Keys" }).click();
    await p.waitForTimeout(400);
  }

  async function revokeAllKeys(p: Page) {
    const resp = await apiGet(p, "/ui/api_keys");
    if (!resp.ok()) return;
    const { keys = [] } = (await resp.json()) as { keys: Array<{ key_id: string }> };
    for (const k of keys) {
      await apiPost(p, "/ui/api_keys/revoke", { key_id: k.key_id });
    }
  }

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await gotoApiKeys(page);

    // Start with a clean slate.
    await revokeAllKeys(page);

    // Create a key via the API so Info / IP-rules buttons are available.
    const cr = await apiPost(page, "/ui/api_keys", { label: KEY_LABEL });
    expect(cr.ok()).toBe(true);
    keyId = ((await cr.json()) as { key_id: string }).key_id;

    // Reload the page so the new key appears in the list.
    await page.reload({ waitUntil: "load" });
    await page.waitForTimeout(400);
    await page.getByRole("tab", { name: "API Keys" }).click();
    await page.waitForTimeout(400);

    // Confirm the key label is visible in the list.
    await expect(page.getByText(KEY_LABEL)).toBeVisible({ timeout: 6000 });
  });

  test.afterAll(async () => {
    if (keyId) await apiPost(page, "/ui/api_keys/revoke", { key_id: keyId }).catch(() => {});
    await page?.close();
  });

  // ── Info / Key-details dialog ─────────────────────────────────────────────

  test("Each key row has a 'View key details' button (Info icon)", async () => {
    await expect(
      page.getByRole("button", { name: "View key details" }),
    ).toBeVisible({ timeout: 5000 });
  });

  test("Clicking 'View key details' opens a dialog with key label and usage stats", async () => {
    await page.getByRole("button", { name: "View key details" }).first().click();

    const dlg = page.getByRole("dialog");
    await expect(dlg).toBeVisible({ timeout: 5000 });

    // Dialog title is the key label (or "Unnamed key").
    await expect(dlg).toContainText(KEY_LABEL);

    // Usage section with call statistics.
    await expect(dlg).toContainText(/total calls|calls|usage/i);

    // Close.
    await page.keyboard.press("Escape");
    await expect(dlg).not.toBeVisible({ timeout: 3000 });
  });

  // ── IP rules / CIDR list dialog ───────────────────────────────────────────

  test("Each key row has a 'Manage IP rules' button (Globe icon)", async () => {
    await expect(
      page.getByRole("button", { name: "Manage IP rules" }),
    ).toBeVisible({ timeout: 5000 });
  });

  test("Clicking 'Manage IP rules' opens a dialog with 'IP Access Rules' title", async () => {
    await page.getByRole("button", { name: "Manage IP rules" }).first().click();

    const dlg = page.getByRole("dialog");
    await expect(dlg).toBeVisible({ timeout: 5000 });
    await expect(dlg).toContainText("IP Access Rules");
    await expect(dlg).toContainText("Allow CIDRs");
    await expect(dlg).toContainText("Deny CIDRs");
  });

  test("CIDR list UI: adding a CIDR entry shows it in the list", async () => {
    const dlg = page.getByRole("dialog");

    // The Allow CIDRs input has placeholder "e.g. 10.0.0.0/8".
    const allowInput = dlg.locator("input[placeholder='e.g. 10.0.0.0/8']");
    await expect(allowInput).toBeVisible({ timeout: 3000 });

    await allowInput.fill("10.0.0.0/8");

    // Click the "Add" button next to the Allow CIDRs input.
    const addBtn = dlg.getByRole("button", { name: "Add" }).first();
    await addBtn.click();

    // The CIDR entry should appear as a tagged row with <code>.
    await expect(dlg.locator("code", { hasText: "10.0.0.0/8" })).toBeVisible({ timeout: 3000 });
  });

  test("CIDR list UI: removing a CIDR entry removes it from the list", async () => {
    const dlg = page.getByRole("dialog");

    // The remove button has aria-label "Remove 10.0.0.0/8".
    await dlg.getByRole("button", { name: "Remove 10.0.0.0/8" }).click();

    // The entry should disappear.
    await expect(
      dlg.locator("code", { hasText: "10.0.0.0/8" }),
    ).not.toBeVisible({ timeout: 3000 });

    // Close the dialog.
    await page.keyboard.press("Escape");
  });
});
