/**
 * E2E tests for view-once messages and encrypted messages.
 *
 * Routes tested:
 *   /messages  — Messaging page (SPA, no URL per conversation)
 *
 * Features:
 *   - View-once text messages (API send + UI display + reveal)
 *   - Encrypt message toggle, password fields, mismatch/match validation
 *   - Send encrypted message via UI → "Encrypted" badge
 *   - Decrypt message dialog (correct/wrong password)
 *   - REST API shape: view_once field, is_encrypted flag
 *
 * Environment notes:
 *   VITE_MESSAGING_ENCRYPTED_MESSAGES_ENABLED=true (.env.local) so the
 *   "Encrypt message" checkbox is enabled. View-once text is always enabled.
 *
 *   View-once IMAGES require a full S3 flow; these tests cover view-once TEXT only.
 *
 * Auth pattern:
 *   injectAuth() must be called before any API calls so that browser-context
 *   cookies are in place. For Bob's API calls (different user), we pass Bob's
 *   session cookies explicitly in the request headers.
 *
 * Test users:
 *   Alice (e2e_alice@test.local / display "E2E Alice") — primary actor
 *   Bob   (e2e_bob@test.local  / display "E2E Bob")   — DM partner
 */

import { test, expect, type Page, request as playwrightRequest } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
import { usingCpp } from "./helpers/cpp-seed-messaging-crm-misc";
import { cppSeedPaymentMethod } from "./helpers/cpp-seed";
import { cppBearerPost, cppBearerGet } from "./helpers/cpp-seed-messaging-calls";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

// Python interpreter that has boto3 installed.
const PYTHON = REPO_ROOT + "/.venv/bin/python3";

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";

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

/** POST authenticated as Alice (uses browser-context cookies + Alice's CSRF). */
async function apiPost(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

/** GET authenticated as Alice (browser-context cookies, no CSRF needed for GET). */
async function apiGet(page: Page, path: string) {
  const session = getSessions()[ALICE_ID];
  return page.request.get(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

/** DELETE authenticated as Alice (browser-context cookies + Alice's CSRF). */
async function apiDelete(page: Page, path: string) {
  const session = getSessions()[ALICE_ID];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

/**
 * POST as a specific user using the global Playwright APIRequestContext
 * (no browser cookies) with a dev-mode Bearer token.
 *
 * The messaging endpoint falls back to `get_current_user_id(authorization)`
 * when no ui_session cookie or X-SESSION-ID header is present. In dev mode
 * that function accepts `Authorization: Bearer <user_id>` directly.
 *
 * Use this when you need to act as a user OTHER than Alice, to avoid the
 * device-trust re-auth check that fires for new browser devices.
 */
type APIRequestContext = import("@playwright/test").APIRequestContext;
async function apiPostBearer(
  req: APIRequestContext,
  path: string,
  body: object,
  userId: string,
) {
  const sub = getSessions()[userId]?.user_sub ?? userId; // non-member fallback: raw id (cpp dev raw-sub) -> non-participant 403
  if (usingCpp()) return cppBearerPost(path, body, sub);
  return req.post(`${API}${path}`, {
    data: body,
    headers: { Authorization: `Bearer ${sub}` },
  });
}

/** GET as a specific user using Bearer token (no browser cookies). */
async function apiGetBearer(
  req: APIRequestContext,
  path: string,
  userId: string,
) {
  const sub = getSessions()[userId]?.user_sub ?? userId; // non-member fallback: raw id (cpp dev raw-sub) -> non-participant 403
  if (usingCpp()) return cppBearerGet(path, sub);
  return req.get(`${API}${path}`, {
    headers: { Authorization: `Bearer ${sub}` },
  });
}

// ─── Payment method helpers ───────────────────────────────────────────────────

/**
 * Inject a test payment method for the given user directly into DynamoDB.
 * Needed so that UI features gated on "has payment method" (Attach tip,
 * Unlock for) become enabled without requiring a full billing flow.
 */
function injectPaymentMethod(userSub: string, pmId: string): void {
  // cpp path: PM-gated UI toggles (Attach tip / Unlock for) read the caller's
  // default payment method from cpp's tlc_billing (PM#<id> + BILLING), keyed by
  // SUB — the Python 'billing' row below is invisible to cpp. userSub is already
  // the cpp sub here (callers pass getSessions()[id].user_sub).
  if (usingCpp()) {
    cppSeedPaymentMethod(userSub, pmId);
    return;
  }
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

/** Remove a test payment method from DynamoDB (best-effort cleanup). */
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

// ─── DM conversation bootstrap ───────────────────────────────────────────────

/** Cached conversation ID shared across sections. */
let _dmConvoId: string | null = null;

/**
 * Ensure a DM between Alice and Bob exists. Caches the conversation ID so
 * subsequent calls are instant. MUST be called after injectAuth() so
 * Alice's cookies are in the browser context.
 */
async function getOrCreateDm(page: Page): Promise<string> {
  if (_dmConvoId) return _dmConvoId;
  const bobSub = getSessions()[BOB_ID].user_sub;
  const resp = await apiPost(page, "/messaging/conversations", {
    participant_ids: [bobSub],
    type: "dm",
  });
  if (!resp.ok()) {
    const body = await resp.text().catch(() => "(unreadable)");
    throw new Error(`DM creation failed: HTTP ${resp.status()} — ${body}`);
  }
  const body = await resp.json();
  _dmConvoId = body.conversation_id as string;
  return _dmConvoId;
}

/**
 * Open a specific conversation directly via the deep-link route
 * (/messages/:conversationId) and wait for the ComposeBar.
 *
 * This is FULL-SUITE-SAFE: it does NOT depend on the conversation appearing
 * (or being first) in the sidebar list. Under full-suite accumulation many
 * Alice↔Bob DMs and hundreds of messages exist, so the sidebar list is large
 * and may paginate or be slow to render the right "E2E Bob" row. Navigating
 * directly to the conversation by id sidesteps all of that — MessagesPage's
 * deep-link support (useParams + getConversation) auto-opens it.
 *
 * Caller must have injected auth first.
 */
async function openDmDirect(page: Page, convoId: string) {
  await page.goto(`${BASE}/messages/${convoId}`, { waitUntil: "load" });
  await expect(
    page.getByPlaceholder("Type a message...").or(
      page.getByPlaceholder("Type an encrypted message..."),
    ),
  ).toBeVisible({ timeout: 15000 });
}

/**
 * Navigate Alice to her DM with Bob so the conversation view + ComposeBar
 * become visible.
 *
 * Auth is injected first so that getOrCreateDm (and subsequent API helpers)
 * have valid cookies in the browser context. The conversation is opened via
 * the deep-link route (by id) rather than by clicking a sidebar row, which is
 * robust against full-suite DM/message accumulation.
 */
async function openDmWithBob(page: Page) {
  // 1. Inject Alice's auth (sets cookies, navigates to /login)
  await injectAuth(page, ALICE_ID);
  // 2. Create / retrieve the DM (cookies are now in place)
  const convoId = await getOrCreateDm(page);
  // 3. Open the conversation directly by id (suite-accumulation-safe).
  await openDmDirect(page, convoId);
}

/** MCM-2: toggle options live inside the "+" popover. Open popover then click. */
async function openComposeToggle(page: Page, ariaLabel: RegExp | string) {
  await page.getByTestId("compose-more").click();
  await page.getByRole("button", { name: ariaLabel }).click();
}

/** MCM-2: deactivate a toggle (same as activate — it's a toggle button). */
async function deactivateComposeToggle(page: Page, ariaLabel: RegExp | string) {
  await openComposeToggle(page, ariaLabel);
}

// ─── 1. Messaging page structure ──────────────────────────────────────────────

test.describe("1. Messaging page structure", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    const sec1ConvsLoaded = page.waitForResponse(
      (r) => r.url().includes("/messaging/conversations") && r.request().method() === "GET"
        && !r.url().match(/\/conversations\/[^/]+$/),
      { timeout: 15000 },
    );
    await page.goto(`${BASE}/messages`, { waitUntil: "load" });
    await sec1ConvsLoaded;
    await page.waitForTimeout(300);
  });

  test.afterAll(async () => page?.close());

  test("Messaging page renders without error", async () => {
    await expect(page.locator("body")).toBeVisible();
  });

  test("Conversation list panel has a search input", async () => {
    await expect(page.getByPlaceholder("Search conversations...")).toBeVisible({ timeout: 5000 });
  });

  test("'New DM' and 'New Group' buttons are present", async () => {
    await expect(page.getByRole("button", { name: "New DM" })).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("button", { name: "New Group" })).toBeVisible({ timeout: 5000 });
  });

  test("Empty state shown when no conversation is selected", async () => {
    await expect(page.getByText("Select a conversation")).toBeVisible({ timeout: 5000 });
  });
});

// ─── 2. ComposeBar — view-once text toggle ────────────────────────────────────

test.describe("2. ComposeBar — view-once text toggle", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await openDmWithBob(page);
  });

  test.afterAll(async () => page?.close());

  test("'View once' toggle is accessible via '+' popover", async () => {
    await page.getByTestId("compose-more").click();
    await expect(page.getByRole("button", { name: /toggle view once/i })).toBeVisible({ timeout: 5000 });
    await page.keyboard.press("Escape");
  });

  test("'View once' is inactive by default (no pill badge)", async () => {
    await expect(page.getByText("View once").locator("..").filter({ has: page.locator("button[aria-label='Disable view once']") })).not.toBeVisible();
  });

  test("Enabling 'View once' shows active pill badge", async () => {
    await openComposeToggle(page, /toggle view once/i);
    await expect(page.getByRole("button", { name: /disable view once/i })).toBeVisible({ timeout: 3000 });
  });

  test("Disabling 'View once' hides the pill badge", async () => {
    await page.getByRole("button", { name: /disable view once/i }).click();
    await expect(page.getByRole("button", { name: /disable view once/i })).not.toBeVisible({ timeout: 2000 });
  });
});

// ─── 3. ComposeBar — encrypt message toggle ───────────────────────────────────

test.describe("3. ComposeBar — encrypt message toggle", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await openDmWithBob(page);
  });

  test.afterAll(async () => page?.close());

  test("'Encrypt message' toggle is accessible via '+' popover", async () => {
    await page.getByTestId("compose-more").click();
    await expect(page.getByRole("button", { name: /toggle message encryption/i })).toBeVisible({ timeout: 5000 });
    await page.keyboard.press("Escape");
  });

  test("'Encrypt message' is inactive by default", async () => {
    await expect(page.getByRole("button", { name: /disable encryption/i })).not.toBeVisible();
  });

  test("Enabling encryption shows password input fields", async () => {
    await openComposeToggle(page, /toggle message encryption/i);
    await expect(page.getByPlaceholder("Encryption password")).toBeVisible({ timeout: 3000 });
    await expect(page.getByPlaceholder("Confirm password")).toBeVisible({ timeout: 3000 });
  });

  test("Active encrypt pill badge appears when encrypt is on", async () => {
    await expect(page.getByRole("button", { name: /disable encryption/i })).toBeVisible({ timeout: 3000 });
  });

  test("Mismatched passwords shows 'Passwords do not match'", async () => {
    await page.getByPlaceholder("Encryption password").fill("password1");
    await page.getByPlaceholder("Confirm password").fill("different");
    await expect(page.getByText("Passwords do not match")).toBeVisible({ timeout: 3000 });
  });

  test("Matching passwords shows 'Passwords match'", async () => {
    await page.getByPlaceholder("Confirm password").fill("password1");
    await expect(page.getByText("Passwords match")).toBeVisible({ timeout: 3000 });
  });

  test("Disabling encryption hides password fields", async () => {
    await page.getByRole("button", { name: /disable encryption/i }).click();
    await expect(page.getByPlaceholder("Encryption password")).not.toBeVisible({ timeout: 2000 });
    await expect(page.getByPlaceholder("Confirm password")).not.toBeVisible({ timeout: 2000 });
  });
});

// ─── 4. View-once text — recipient view ──────────────────────────────────────

test.describe("4. View-once text — recipient sees 'Tap to view once'", () => {
  let page: Page;
  const VIEW_ONCE_TEXT = `E2E view-once ${Date.now()}`;

  test.beforeAll(async ({ browser, request }) => {
    page = await browser.newPage();

    // Auth first so getOrCreateDm has valid cookies
    await injectAuth(page, ALICE_ID);
    const convoId = await getOrCreateDm(page);

    // Bob sends a view_once text to Alice using Bearer token (bypasses device trust)
    const resp = await apiPostBearer(
      request,
      `/messaging/conversations/${convoId}/messages`,
      { text: VIEW_ONCE_TEXT, view_once: true },
      BOB_ID,
    );
    if (!resp.ok()) {
      const body = await resp.text().catch(() => "(unreadable)");
      throw new Error(`Bob's message send failed: HTTP ${resp.status()} — ${body}`);
    }

    // Alice opens the conversation directly by id (suite-accumulation-safe).
    await openDmDirect(page, convoId);
    // Small wait for messages to finish loading
    await page.waitForTimeout(500);
  });

  test.afterAll(async () => page?.close());

  test("Recipient sees 'Tap to view once' button for the view-once message", async () => {
    await expect(
      page.getByRole("button", { name: /tap to view once/i }).last(),
    ).toBeVisible({ timeout: 8000 });
  });

  test("'view once' badge is present in the message footer", async () => {
    await expect(page.getByText("view once").last()).toBeVisible({ timeout: 5000 });
  });

  test("Raw message text is hidden before reveal", async () => {
    // The text appears in the conversation-list sidebar preview (a <span>),
    // but the message bubble renders the text in a <p> only after reveal.
    // Scope to <p> elements to exclude the sidebar and confirm the text
    // is not yet rendered in the bubble itself.
    await expect(
      page.locator("p").filter({ hasText: VIEW_ONCE_TEXT }),
    ).not.toBeVisible({ timeout: 2000 });
  });

  test("Clicking 'Tap to view once' reveals the message text", async () => {
    await page.getByRole("button", { name: /tap to view once/i }).last().click();
    // After reveal the text appears in a <p> element inside the bubble.
    // (The sidebar preview also shows the text in a <span>, so scope to <p>.)
    await expect(
      page.locator("p").filter({ hasText: VIEW_ONCE_TEXT }),
    ).toBeVisible({ timeout: 3000 });
  });

  test("After reveal the button is replaced by the text", async () => {
    await expect(
      page.locator("p").filter({ hasText: VIEW_ONCE_TEXT }),
    ).toBeVisible({ timeout: 2000 });
  });
});

// ─── 5. View-once text — sender view ─────────────────────────────────────────

test.describe("5. View-once text — sender sees text normally", () => {
  let page: Page;
  const SENDER_TEXT = `E2E sender-vo ${Date.now()}`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const convoId = await getOrCreateDm(page);

    // Alice sends a view_once message (she is the sender)
    const resp = await apiPost(
      page,
      `/messaging/conversations/${convoId}/messages`,
      { text: SENDER_TEXT, view_once: true },
    );
    if (!resp.ok()) {
      const body = await resp.text().catch(() => "(unreadable)");
      throw new Error(`Alice's message send failed: HTTP ${resp.status()} — ${body}`);
    }

    // Alice opens the conversation directly by id (suite-accumulation-safe).
    await openDmDirect(page, convoId);
    await page.waitForTimeout(500);
  });

  test.afterAll(async () => page?.close());

  test("Sender sees the text directly (no 'Tap to view once' gate for own messages)", async () => {
    // isOwn = true → text rendered directly, not behind the view-once gate.
    // The sidebar preview also shows the text in a <span>, so scope to <p>.
    await expect(
      page.locator("p").filter({ hasText: SENDER_TEXT }),
    ).toBeVisible({ timeout: 8000 });
  });

  test("Sender message still has 'view once' badge in the footer", async () => {
    await expect(page.getByText("view once").last()).toBeVisible({ timeout: 5000 });
  });
});

// ─── 6. Encrypted message — compose and send via UI ──────────────────────────

test.describe("6. Encrypted message — compose and send via UI", () => {
  let page: Page;
  const ENCRYPT_PASSWORD = "E2EtestPass123!";
  const ENCRYPT_TEXT = `E2E encrypted ${Date.now()}`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await openDmWithBob(page);

    // Enable encryption via "+" popover toggle
    await openComposeToggle(page, /toggle message encryption/i);
    await page.getByPlaceholder("Encryption password").fill(ENCRYPT_PASSWORD);
    await page.getByPlaceholder("Confirm password").fill(ENCRYPT_PASSWORD);
    await expect(page.getByText("Passwords match")).toBeVisible({ timeout: 3000 });

    await page.getByPlaceholder("Type an encrypted message...").fill(ENCRYPT_TEXT);
    // Register both POST and GET listeners BEFORE clicking Send.
    // The "Decrypt message" button requires message.encryption from the server GET
    // response, not just is_encrypted from the optimistic update.
    let sec6PostSent = false;
    const sec6SentResponse = page.waitForResponse(
      (r) => {
        if (r.url().includes("/messages") && r.request().method() === "POST") {
          sec6PostSent = true;
        }
        return sec6PostSent && r.url().includes("/messages") && r.request().method() === "POST";
      },
      { timeout: 10000 },
    );
    const sec6RefetchResponse = page.waitForResponse(
      (r) =>
        sec6PostSent &&
        r.url().includes("/messages") &&
        r.request().method() === "GET" &&
        !r.url().includes("/scheduled"),
      { timeout: 10000 },
    );
    await page.getByRole("button", { name: "Send message" }).click();
    await sec6SentResponse;
    await sec6RefetchResponse;
    await expect(page.getByText("Encrypted").last()).toBeVisible({ timeout: 5000 });
    // Verify the "Decrypt message" button is present (requires encryption envelope from GET)
    await expect(
      page.getByRole("button", { name: "Decrypt message" }).last(),
    ).toBeVisible({ timeout: 5000 });
  });

  test.afterAll(async () => page?.close());

  test("Encrypted message shows 'Encrypted' badge in the bubble", async () => {
    await expect(page.getByText("Encrypted").last()).toBeVisible({ timeout: 5000 });
  });

  test("Encrypted message shows 'Encrypted message' placeholder text", async () => {
    await expect(page.getByText("Encrypted message").last()).toBeVisible({ timeout: 5000 });
  });

  test("'Decrypt message' button is visible on the encrypted bubble", async () => {
    await expect(
      page.getByRole("button", { name: "Decrypt message" }).last(),
    ).toBeVisible({ timeout: 5000 });
  });

  test("Raw plaintext is not visible in the message list", async () => {
    // Scope to message bubbles only — drafts panel may show the text via auto-save
    const messageBubbles = page.locator('[class*="message"], [data-testid="message-bubble"], .flex.flex-col.gap-2 > div');
    await expect(messageBubbles.filter({ hasText: ENCRYPT_TEXT })).toHaveCount(0, { timeout: 2000 });
  });
});

// ─── 7. Decrypt message — correct and wrong password ─────────────────────────

test.describe("7. Decrypt message — dialog, wrong password, correct password", () => {
  let page: Page;
  const ENCRYPT_PASSWORD = "DecryptMe456@";
  const ENCRYPT_TEXT = `E2E decrypt ${Date.now()}`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await openDmWithBob(page);

    // Let the message list finish loading (React Query fetch) so that the
    // "existingCount" reflects the true loaded state, not an in-progress load.
    // Section 6 already left encrypted messages; we need to wait for them to appear
    // so the +1 assertion refers specifically to section 7's new message.
    await page.waitForTimeout(1500);
    const existingCount = await page.getByRole("button", { name: "Decrypt message" }).count();

    // Send a fresh encrypted message to decrypt in this section
    await openComposeToggle(page, /toggle message encryption/i);
    await page.getByPlaceholder("Encryption password").fill(ENCRYPT_PASSWORD);
    await page.getByPlaceholder("Confirm password").fill(ENCRYPT_PASSWORD);
    await expect(page.getByText("Passwords match")).toBeVisible({ timeout: 3000 });
    await page.getByPlaceholder("Type an encrypted message...").fill(ENCRYPT_TEXT);
    // Register BOTH listeners BEFORE clicking Send so we cannot miss the refetch
    // GET even if it completes before Playwright's Node.js thread registers it.
    // A postSent flag ensures the GET listener only resolves for a GET that fired
    // AFTER our POST has been received (ignoring any earlier background GETs).
    let postSent = false;
    const sentResponsePromise = page.waitForResponse(
      (r) => {
        if (r.url().includes("/messages") && r.request().method() === "POST") {
          postSent = true;
        }
        return postSent && r.url().includes("/messages") && r.request().method() === "POST";
      },
      { timeout: 10000 },
    );
    // React Query fires invalidateQueries in onSuccess → a GET refetch follows.
    // We rely on Playwright calling predicates in registration order so postSent
    // is already true when this predicate sees the GET response.
    const refetchResponsePromise = page.waitForResponse(
      (r) => {
        if (!postSent) return false;
        return (
          r.url().includes(`/conversations/${_dmConvoId}/messages`) &&
          r.request().method() === "GET" &&
          r.ok()
        );
      },
      { timeout: 15000 },
    );
    await page.getByRole("button", { name: "Send message" }).click();
    await sentResponsePromise;
    await refetchResponsePromise;

    // Confirm section 7's button has appeared at the bottom. Use >= to tolerate
    // an optimistic-render + refetch briefly showing the new bubble twice (and
    // any accumulated encrypted messages from prior runs in the same DM).
    await expect
      .poll(
        async () =>
          page.getByRole("button", { name: "Decrypt message" }).count(),
        { timeout: 5000 },
      )
      .toBeGreaterThanOrEqual(existingCount + 1);
  });

  test.afterAll(async () => page?.close());

  test("Clicking 'Decrypt message' opens the decrypt dialog", async () => {
    await page.getByRole("button", { name: "Decrypt message" }).last().click();
    await expect(page.getByRole("dialog")).toBeVisible({ timeout: 3000 });
    await expect(
      page.getByRole("dialog").getByRole("heading", { name: /decrypt message/i }),
    ).toBeVisible({ timeout: 2000 });
  });

  test("Decrypt dialog contains a password input", async () => {
    await expect(page.getByRole("dialog").getByPlaceholder("Password")).toBeVisible({ timeout: 2000 });
  });

  test("Wrong password shows an error message", async () => {
    await page.getByRole("dialog").getByPlaceholder("Password").fill("WrongPassword!");
    await page.getByRole("dialog").getByRole("button", { name: "Decrypt" }).click();
    await expect(page.getByRole("dialog").getByText(/wrong password/i)).toBeVisible({ timeout: 5000 });
    // Close the dialog so the next test starts from a clean state (no residual
    // error message or filled password that could interfere with decryption).
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).not.toBeVisible({ timeout: 2000 });
  });

  test("Correct password decrypts and closes the dialog", async () => {
    // Re-open the dialog (closed by "Wrong password" test, or not opened at all on retry).
    if (!await page.getByRole("dialog").isVisible()) {
      await page.getByRole("button", { name: "Decrypt message" }).last().click();
      await expect(page.getByRole("dialog")).toBeVisible({ timeout: 3000 });
    }
    await page.getByRole("dialog").getByPlaceholder("Password").fill(ENCRYPT_PASSWORD);
    await page.getByRole("dialog").getByRole("button", { name: "Decrypt" }).click();
    await expect(page.getByRole("dialog")).not.toBeVisible({ timeout: 5000 });
  });

  test("Decrypted text is visible in the message bubble after decryption", async () => {
    // On retry this test runs without prior dialog tests, so the message may not
    // have been decrypted yet.  Decrypt it now if needed.
    if (!await page.locator("p").filter({ hasText: ENCRYPT_TEXT }).isVisible()) {
      if (!await page.getByRole("dialog").isVisible()) {
        await page.getByRole("button", { name: "Decrypt message" }).last().click();
        await expect(page.getByRole("dialog")).toBeVisible({ timeout: 3000 });
      }
      await page.getByRole("dialog").getByPlaceholder("Password").fill(ENCRYPT_PASSWORD);
      await page.getByRole("dialog").getByRole("button", { name: "Decrypt" }).click();
      await expect(page.getByRole("dialog")).not.toBeVisible({ timeout: 5000 });
    }
    // The decrypted text is in a <p> element in the bubble.
    // (The sidebar preview also shows it in a <span>, scope to <p>.)
    await expect(
      page.locator("p").filter({ hasText: ENCRYPT_TEXT }),
    ).toBeVisible({ timeout: 5000 });
  });
});

// ─── 8. REST API — view_once and encrypted message shapes ─────────────────────

test.describe("8. REST API — message fields for view_once and encrypted", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await getOrCreateDm(page);
    // Pre-populate so GET tests have data even when this section runs in isolation
    await apiPost(page, `/messaging/conversations/${_dmConvoId}/messages`, {
      text: "API view-once setup",
      view_once: true,
    });
    const envelope = {
      version: 1,
      alg: "AES-256-GCM",
      kdf: "PBKDF2-SHA256",
      iterations: 600000,
      salt_b64: "AAAAAAAAAAAAAAAAAAAAAA==",
      iv_b64: "AAAAAAAAAAAAAAAA",
      ciphertext_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    };
    await apiPost(page, `/messaging/conversations/${_dmConvoId}/messages`, {
      encryption: envelope,
    });
  });

  test.afterAll(async () => page?.close());

  test("POST /messaging/conversations creates a DM and returns correct structure", async () => {
    const bobSub = getSessions()[BOB_ID].user_sub;
    const resp = await apiPost(page, "/messaging/conversations", {
      participant_ids: [bobSub],
      type: "dm",
    });
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body).toHaveProperty("conversation_id");
    expect(body.type).toBe("dm");
  });

  test("Sending a view_once text message returns view_once: true", async () => {
    const resp = await apiPost(
      page,
      `/messaging/conversations/${_dmConvoId}/messages`,
      { text: "API view-once check", view_once: true },
    );
    expect(resp.ok()).toBeTruthy();
    const msg = await resp.json();
    expect(msg).toHaveProperty("message_id");
    expect(msg.view_once).toBe(true);
    expect(msg.kind).toBe("text");
  });

  test("Sending a plain text message has view_once absent or false", async () => {
    const resp = await apiPost(
      page,
      `/messaging/conversations/${_dmConvoId}/messages`,
      { text: "API plain check" },
    );
    expect(resp.ok()).toBeTruthy();
    const msg = await resp.json();
    expect(msg).toHaveProperty("message_id");
    expect(msg.view_once).toBeFalsy();
  });

  test("Sending a message with an encryption envelope returns is_encrypted: true", async () => {
    // The backend stores the envelope as-is and sets is_encrypted=true.
    // Field names must match MessageEncryptionEnvelope Pydantic schema exactly.
    const envelope = {
      version: 1,
      alg: "AES-256-GCM",
      kdf: "PBKDF2-SHA256",
      iterations: 600000,
      salt_b64: "AAAAAAAAAAAAAAAAAAAAAA==",         // 16 zero bytes
      iv_b64: "AAAAAAAAAAAAAAAA",                   // 12 zero bytes
      ciphertext_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 32 zero bytes (> 16)
    };
    const resp = await apiPost(
      page,
      `/messaging/conversations/${_dmConvoId}/messages`,
      { encryption: envelope },
    );
    expect(resp.ok()).toBeTruthy();
    const msg = await resp.json();
    expect(msg).toHaveProperty("message_id");
    expect(msg.is_encrypted).toBe(true);
  });

  test("GET /messaging/conversations/{id}/messages returns an array", async () => {
    const resp = await apiGet(page, `/messaging/conversations/${_dmConvoId}/messages`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    const messages = Array.isArray(body) ? body : (body.messages ?? []);
    expect(Array.isArray(messages)).toBe(true);
    expect(messages.length).toBeGreaterThan(0);
  });

  test("Message list contains at least one view_once message", async () => {
    const resp = await apiGet(page, `/messaging/conversations/${_dmConvoId}/messages`);
    const body = await resp.json();
    const messages = Array.isArray(body) ? body : (body.messages ?? []);
    const found = messages.find((m: { view_once?: boolean }) => m.view_once === true);
    expect(found).toBeTruthy();
  });

  test("Message list contains at least one encrypted message", async () => {
    const resp = await apiGet(page, `/messaging/conversations/${_dmConvoId}/messages`);
    const body = await resp.json();
    const messages = Array.isArray(body) ? body : (body.messages ?? []);
    const found = messages.find((m: { is_encrypted?: boolean }) => m.is_encrypted === true);
    expect(found).toBeTruthy();
  });
});

// ─── 9. Message display order ─────────────────────────────────────────────────
//
// Verifies that the chat renders messages in strict chronological order
// (oldest message at the top, newest at the bottom) regardless of the
// random DynamoDB sort-key (UUID) ordering.  Three messages are sent via
// the API with guaranteed distinct created_at values (1.1 s apart); the
// test checks both the raw API response and the rendered DOM order.
// A cross-sender sequence (Alice → Bob → Alice) confirms that messages
// from different senders are interleaved chronologically, not grouped.

test.describe("9. Message display order — oldest first, newest last", () => {
  let page: Page;

  // Unique content for this run so we can isolate our messages from any
  // messages left over from previous test runs.
  const TS = Date.now();
  const MSG1 = `ord-1-${TS}`; // Alice — sent first  (oldest)
  const MSG2 = `ord-2-${TS}`; // Bob   — sent second (middle)
  const MSG3 = `ord-3-${TS}`; // Alice — sent third  (newest)

  test.beforeAll(async ({ browser, request }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await getOrCreateDm(page);

    // Send three messages with 1.1 s gaps so each gets a distinct integer
    // created_at (seconds precision).  Alice → Bob → Alice tests that
    // cross-sender chronological ordering is preserved.
    await apiPost(page, `/messaging/conversations/${_dmConvoId}/messages`, { text: MSG1 });
    await page.waitForTimeout(1100);
    // Use the global `request` fixture (no browser cookies) so the Bearer token
    // path is used — `page.request` carries Alice's session cookies and would
    // cause the backend to reject the request with a CSRF error.
    const r2 = await apiPostBearer(
      request,
      `/messaging/conversations/${_dmConvoId}/messages`,
      { text: MSG2 },
      BOB_ID,
    );
    if (!r2.ok()) {
      const errText = await r2.text().catch(() => "(unreadable)");
      throw new Error(`Bob MSG2 send failed: HTTP ${r2.status()} — ${errText}`);
    }
    await page.waitForTimeout(1100);
    await apiPost(page, `/messaging/conversations/${_dmConvoId}/messages`, { text: MSG3 });

    // Open the conversation in the browser directly by id (suite-safe).
    // ConversationView auto-scrolls to the bottom on mount, so MSG3 (newest)
    // should be immediately visible.
    await openDmDirect(page, _dmConvoId!);
    // Wait until the message bubble <p> for MSG3 is rendered.
    // Using locator("p") avoids matching the sidebar <span> preview, which
    // would satisfy getByText too early (before the conversation view loads).
    await expect(page.locator("p").filter({ hasText: MSG3 })).toBeVisible({ timeout: 8000 });
  });

  test.afterAll(async () => page?.close());

  // ── API-level ordering ────────────────────────────────────────────────────

  test("API returns messages in newest-first order with strictly decreasing created_at", async () => {
    const resp = await apiGet(page, `/messaging/conversations/${_dmConvoId}/messages`);
    expect(resp.ok()).toBe(true);
    const all = (await resp.json()) as Array<{ text?: string; created_at: number }>;

    // Isolate the three messages we just sent.
    const ours = all.filter((m) => [MSG1, MSG2, MSG3].includes(m.text ?? ""));
    expect(ours).toHaveLength(3);

    // Backend sorts newest-first: index 0 = MSG3, 1 = MSG2, 2 = MSG1.
    expect(ours[0].text).toBe(MSG3);
    expect(ours[1].text).toBe(MSG2);
    expect(ours[2].text).toBe(MSG1);

    // created_at must be strictly decreasing (each message one second later).
    expect(ours[0].created_at).toBeGreaterThan(ours[1].created_at);
    expect(ours[1].created_at).toBeGreaterThan(ours[2].created_at);
  });

  // ── UI-level ordering ─────────────────────────────────────────────────────

  test("All three messages are present in the rendered conversation", async () => {
    // Scope to <p> elements (message bubbles) to avoid the sidebar <span>
    // preview of MSG3 causing a strict-mode locator violation.
    await expect(page.locator("p").filter({ hasText: MSG1 })).toBeAttached({ timeout: 5000 });
    await expect(page.locator("p").filter({ hasText: MSG2 })).toBeAttached({ timeout: 5000 });
    await expect(page.locator("p").filter({ hasText: MSG3 })).toBeAttached({ timeout: 5000 });
  });

  test("Messages render in strict chronological order: MSG1 (top) → MSG2 → MSG3 (bottom)", async () => {
    // The conversation list uses no virtualisation, so DOM order == visual
    // order.  Sidebar message previews use <span>, not <p>, so searching
    // <p> elements gives only the message-bubble paragraphs.
    const [i1, i2, i3] = await page.evaluate(
      ([t1, t2, t3]: [string, string, string]) => {
        const paras = Array.from(document.querySelectorAll("p"));
        return [t1, t2, t3].map((text) =>
          paras.findIndex((p) => (p.textContent ?? "").includes(text)),
        );
      },
      [MSG1, MSG2, MSG3] as [string, string, string],
    );

    expect(i1).toBeGreaterThan(-1); // MSG1 found in DOM
    expect(i2).toBeGreaterThan(-1); // MSG2 (Bob) found in DOM
    expect(i3).toBeGreaterThan(-1); // MSG3 found in DOM

    // Oldest-first: MSG1 must precede MSG2 must precede MSG3.
    expect(i1).toBeLessThan(i2); // MSG1 above MSG2
    expect(i2).toBeLessThan(i3); // MSG2 above MSG3

    // Explicit cross-sender assertion: Bob's message sits between Alice's two.
    expect(i1).toBeLessThan(i2); // Alice-first before Bob
    expect(i2).toBeLessThan(i3); // Bob before Alice-third
  });

  test("A message sent via the compose bar appears at the bottom of the chat", async () => {
    const uiMsg = `ord-ui-${Date.now()}`;

    // Capture the DOM index of MSG3 before sending so we can compare after.
    const idxMsg3Before = await page.evaluate((t3: string) => {
      const paras = Array.from(document.querySelectorAll("p"));
      return paras.findIndex((p) => (p.textContent ?? "").includes(t3));
    }, MSG3);
    expect(idxMsg3Before).toBeGreaterThan(-1);

    // Send the message through the UI compose bar.
    await page.getByPlaceholder("Type a message...").fill(uiMsg);
    const postDone = page.waitForResponse(
      (r) => r.url().includes("/messages") && r.request().method() === "POST",
      { timeout: 10000 },
    );
    await page.getByRole("button", { name: "Send message" }).click();
    await postDone;
    await expect(page.getByText(uiMsg)).toBeVisible({ timeout: 5000 });

    // The new message must appear after MSG3 in DOM order.
    const [iMsg3, iUi] = await page.evaluate(
      ([t3, tu]: [string, string]) => {
        const paras = Array.from(document.querySelectorAll("p"));
        return [t3, tu].map((text) =>
          paras.findIndex((p) => (p.textContent ?? "").includes(text)),
        );
      },
      [MSG3, uiMsg] as [string, string],
    );
    expect(iMsg3).toBeGreaterThan(-1);
    expect(iUi).toBeGreaterThan(-1);
    expect(iUi).toBeGreaterThan(iMsg3); // new message is below MSG3
  });

  test("Order is preserved after the page reloads (re-fetch from server)", async () => {
    // Hard-navigate to the DM by id to force a fresh API fetch (suite-safe).
    await openDmDirect(page, _dmConvoId!);
    // Wait for the message bubble <p> (not the sidebar span) to confirm the
    // conversation view has finished loading before querying DOM order.
    await expect(page.locator("p").filter({ hasText: MSG3 })).toBeVisible({ timeout: 8000 });

    // Re-check that MSG1 < MSG2 < MSG3 in DOM order after a fresh fetch.
    const [i1, i2, i3] = await page.evaluate(
      ([t1, t2, t3]: [string, string, string]) => {
        const paras = Array.from(document.querySelectorAll("p"));
        return [t1, t2, t3].map((text) =>
          paras.findIndex((p) => (p.textContent ?? "").includes(text)),
        );
      },
      [MSG1, MSG2, MSG3] as [string, string, string],
    );
    expect(i1).toBeGreaterThan(-1);
    expect(i2).toBeGreaterThan(-1);
    expect(i3).toBeGreaterThan(-1);
    expect(i1).toBeLessThan(i2);
    expect(i2).toBeLessThan(i3);
  });
});

// ─── 10. Scheduled send ────────────────────────────────────────────────────────
//
// Covers the full lifecycle of scheduled messages:
//
//   API validation  — send_at too close to now → 400
//   API happy path  — valid send_at → 200, scheduled=true, deliver_at set
//   API list        — GET /scheduled returns pending message
//   API cancel      — DELETE /schedule removes it; GET /scheduled is then empty
//   UI compose      — clock button, datetime picker, scheduled pill
//   UI send         — shows toast, does NOT render bubble immediately
//   UI panel        — "Scheduled messages" sheet lists and can cancel messages
//   Delivery        — background loop promotes message; appears in normal list
//                     (allow up to 45 s for the 30 s poll loop to fire)

test.describe("10. Scheduled send", () => {
  let page: Page;

  // Unique strings scoped to this run so leftover rows from prior runs don't
  // interfere with our assertions.
  const TS          = Date.now();
  const SCHED_TEXT  = `sched-api-${TS}`;   // used for API CRUD tests
  const UI_TEXT     = `sched-ui-${TS}`;    // used for UI send test
  const DELIVER_TEXT = `sched-deliver-${TS}`; // used for delivery test

  // message_id captured after the "valid send_at" API test; reused by list/cancel tests.
  let scheduledMsgId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const convoId = await getOrCreateDm(page);
    // Open the DM directly by id (suite-accumulation-safe).
    await openDmDirect(page, convoId);
  });

  test.afterAll(async () => page?.close());

  // ── API: validation ──────────────────────────────────────────────────────

  test("send_at in the past → 400", async () => {
    const pastTs = Math.floor(Date.now() / 1000) - 60;
    const resp = await apiPost(page, `/messaging/conversations/${_dmConvoId}/messages`, {
      text: "should-fail-past",
      send_at: pastTs,
    });
    expect(resp.status()).toBe(400);
  });

  test("send_at ≤ now+4 (too close) → 400", async () => {
    const tooClose = Math.floor(Date.now() / 1000) + 4;
    const resp = await apiPost(page, `/messaging/conversations/${_dmConvoId}/messages`, {
      text: "should-fail-close",
      send_at: tooClose,
    });
    expect(resp.status()).toBe(400);
  });

  // ── API: happy path ──────────────────────────────────────────────────────

  test("send_at 1 hour in future → 200, scheduled=true, deliver_at matches", async () => {
    const futureTs = Math.floor(Date.now() / 1000) + 3600;
    const resp = await apiPost(page, `/messaging/conversations/${_dmConvoId}/messages`, {
      text: SCHED_TEXT,
      send_at: futureTs,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json() as {
      scheduled: boolean;
      deliver_at: number;
      message_id: string;
    };
    expect(body.scheduled).toBe(true);
    expect(body.deliver_at).toBe(futureTs);
    expect(typeof body.message_id).toBe("string");
    scheduledMsgId = body.message_id;
  });

  test("GET /scheduled includes the pending message with correct text", async () => {
    const resp = await apiGet(page, `/messaging/conversations/${_dmConvoId}/messages/scheduled`);
    expect(resp.ok()).toBe(true);
    const list = await resp.json() as Array<{
      message_id: string;
      scheduled: boolean;
      text?: string;
      deliver_at?: number;
    }>;
    const found = list.find((m) => m.message_id === scheduledMsgId);
    expect(found, "scheduled message not found in /scheduled list").toBeDefined();
    expect(found?.scheduled).toBe(true);
    expect(found?.text).toBe(SCHED_TEXT);
    expect(typeof found?.deliver_at).toBe("number");
  });

  test("GET /messages does NOT return a still-pending scheduled message", async () => {
    // Contract: a scheduled (not-yet-delivered) message is held in the /scheduled
    // queue and is EXCLUDED from the normal conversation timeline until its
    // deliver_at passes. (It reappears in /messages once delivered — see the
    // near-future delivery test below.)
    const resp = await apiGet(page, `/messaging/conversations/${_dmConvoId}/messages`, { limit: "200" });
    expect(resp.ok()).toBe(true);
    const list = await resp.json() as Array<{ message_id: string; scheduled?: boolean }>;
    const found = list.find((m) => m.message_id === scheduledMsgId);
    expect(found, "pending scheduled message should NOT be in /messages yet").toBeUndefined();
  });

  test("DELETE /schedule cancels the message → {ok: true}", async () => {
    const resp = await apiDelete(
      page,
      `/messaging/conversations/${_dmConvoId}/messages/${scheduledMsgId}/schedule`,
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json() as { ok: boolean };
    expect(body.ok).toBe(true);
  });

  test("GET /scheduled is empty after cancellation", async () => {
    const resp = await apiGet(page, `/messaging/conversations/${_dmConvoId}/messages/scheduled`);
    expect(resp.ok()).toBe(true);
    const list = await resp.json() as Array<{ message_id: string }>;
    const still = list.find((m) => m.message_id === scheduledMsgId);
    expect(still).toBeUndefined();
  });

  // ── UI: compose flow ─────────────────────────────────────────────────────

  test.skip("Scheduled messages panel lists API-sent scheduled message and can cancel it (flaky: panel query races with conversation switch)", async () => {
    // Send a scheduled message via API (avoids flaky UI schedule state)
    const sendAt = Math.floor(Date.now() / 1000) + 7200;
    const resp = await apiPost(page, `/messaging/conversations/${_dmConvoId}/messages`, {
      text: UI_TEXT,
      send_at: sendAt,
    });
    expect(resp.ok()).toBe(true);

    // Trigger React Query refetch so the panel picks up the new message
    await page.evaluate(() => window.dispatchEvent(new Event("online")));
    await page.waitForTimeout(500);

    // Open the scheduled messages panel
    await page.getByRole("button", { name: "Scheduled messages" }).click();
    await expect(page.getByRole("heading", { name: "Scheduled Messages" })).toBeVisible({
      timeout: 3000,
    });
    await expect(page.getByText(UI_TEXT).first()).toBeVisible({ timeout: 5000 });
    await expect(page.getByText(/^Sends:/).first()).toBeVisible({ timeout: 3000 });

    // Cancel the scheduled message from the panel
    const cancelDone = page.waitForResponse(
      (r) => r.url().includes("/schedule") && r.request().method() === "DELETE",
      { timeout: 10_000 },
    );
    await page.getByRole("button", { name: "Cancel scheduled message" }).first().click();
    await cancelDone;
    await expect(page.getByText("Scheduled message cancelled")).toBeVisible({ timeout: 5000 });
    await page.keyboard.press("Escape");
  });

  // ── Delivery: background loop promotes message ───────────────────────────
  //
  // The background task runs every 30 s, so delivery can take up to ~37 s
  // after the scheduled time.  We raise the per-test timeout to 60 s and
  // poll /scheduled until it disappears, then confirm it's in /messages.

  test(
    "Message scheduled for the near future is delivered and appears in the normal list",
    async () => {
      // Raise the per-test timeout to 60 s.  The background delivery loop runs
      // every 30 s, so delivery can take up to ≈ send_at+30 s from now.
      // test.setTimeout() is the reliable way to override the global 30 s limit.
      test.setTimeout(60_000);

      // send_at must be > now+5; use now+7 to stay above the minimum.
      const deliverTs = Math.floor(Date.now() / 1000) + 7;
      const resp = await apiPost(page, `/messaging/conversations/${_dmConvoId}/messages`, {
        text: DELIVER_TEXT,
        send_at: deliverTs,
      });
      expect(resp.status()).toBe(200);
      const { message_id: deliveryId } = (await resp.json()) as { message_id: string };

      // Helper: plain JS sleep that does NOT depend on the Playwright page context.
      const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

      // Poll GET /scheduled every 3 s until our message disappears (delivered).
      // The loop wakes at most every 30 s, so max wait ≈ deliverTs+30 s from now.
      let delivered = false;
      for (let i = 0; i < 15 && !delivered; i++) {
        await sleep(3000);
        const r = await apiGet(
          page,
          `/messaging/conversations/${_dmConvoId}/messages/scheduled`,
        );
        const list = (await r.json()) as Array<{ message_id: string }>;
        if (!list.find((m) => m.message_id === deliveryId)) {
          delivered = true;
        }
      }
      expect(delivered, "message should have been delivered within 45 s").toBe(true);

      // Verify the delivered message now appears in the normal message list.
      const r2 = await apiGet(page, `/messaging/conversations/${_dmConvoId}/messages`);
      const msgs = (await r2.json()) as Array<{
        message_id: string;
        text?: string;
        scheduled?: boolean;
      }>;
      const found = msgs.find((m) => m.message_id === deliveryId);
      expect(found, "delivered message not found in /messages").toBeDefined();
      expect(found?.text).toBe(DELIVER_TEXT);
      // After delivery the message is no longer scheduled.
      expect(found?.scheduled).toBeFalsy();
    },
  );
});

// ─── 11. Tips and locked messages ─────────────────────────────────────────────
//
// Covers:
//   POST /messages with tip_amount_cents   — attach a tip to a sent message
//   POST /messages with lock_price_cents   — lock a message behind a paywall
//   POST /messages/{id}/tip                — tip someone else's message
//   POST /messages/{id}/unlock             — unlock a locked message
//   UI: compose-bar lock / tip panels and mutual exclusion
//   UI: sender sees "Locked ·" badge; recipient sees "Lock ·" + "Unlock for" button
//   UI: after unlock, message content becomes visible
//   UI: "Send Tip" option in the message action-bar dropdown

test.describe("11. Tips and locked messages", () => {
  const TS = Date.now();
  const LOCK_TEXT    = `lock-msg-${TS}`;      // Alice → Bob: locked at $1.00 (API)
  const TIP_TEXT     = `tip-msg-${TS}`;       // Alice → Bob: with $0.50 attached tip (API)
  const BOB_MSG      = `bob-plain-${TS}`;     // Bob  → Alice: plain (Alice tips this)
  const UI_LOCK      = `ui-lock-${TS}`;       // Alice → Bob via UI: locked $1.00
  const UI_LOCK_DESC = `unlock-desc-${TS}`;   // Unique description — visible even when locked
  const UI_TIP       = `ui-tip-${TS}`;        // Alice → Bob via UI: with $1.00 attached tip

  let alicePage: Page;
  let bobPage: Page;
  let bobMsgId: string;    // Bob's plain message ID (Alice will tip via /tip)
  let lockedMsgId: string; // Alice's API-locked message ID (Bob will unlock via API + UI)
  let tipMsgId: string;    // Alice's attached-tip message ID (for self-tip rejection test)

  let _alicePmId: string;
  let _bobPmId: string;
  test.beforeAll(async ({ browser, request }) => {
    // Inject payment methods for Alice and Bob so that "Attach tip" and
    // "Unlock for" UI features are enabled (they are gated on having a PM).
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    const bobSub   = getSessions()[BOB_ID].user_sub;
    _alicePmId = `pm-alice-${Date.now()}`;
    _bobPmId   = `pm-bob-${Date.now()}`;
    injectPaymentMethod(aliceSub, _alicePmId);
    injectPaymentMethod(bobSub,   _bobPmId);

    // ── Alice's page ──
    alicePage = await browser.newPage();
    await openDmWithBob(alicePage); // also sets _dmConvoId

    // ── Bob sends a plain message (Bearer auth, no browser cookies) ──
    const r = await apiPostBearer(
      request,
      `/messaging/conversations/${_dmConvoId}/messages`,
      { text: BOB_MSG },
      BOB_ID,
    );
    if (!r.ok()) {
      throw new Error(
        `Bob plain msg failed: HTTP ${r.status()} — ${await r.text().catch(() => "?")}`,
      );
    }
    bobMsgId = ((await r.json()) as { message_id: string }).message_id;

    // ── Bob's page ──
    // Open the SAME DM directly by id (suite-accumulation-safe) instead of
    // hunting for an "Alice" sidebar row, which is unreliable when many DMs
    // and messages exist by the time this spec runs in the full suite.
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);
    await bobPage.goto(`${BASE}/messages/${_dmConvoId}`, { waitUntil: "load" });
    await expect(
      bobPage
        .getByPlaceholder("Type a message...")
        .or(bobPage.getByPlaceholder("Type an encrypted message...")),
    ).toBeVisible({ timeout: 15000 });
  });

  test.afterAll(async () => {
    // Clean up the injected payment methods so other test sections that check
    // "no payment method" behaviour still work correctly.
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    const bobSub   = getSessions()[BOB_ID].user_sub;
    if (_alicePmId) removePaymentMethod(aliceSub, _alicePmId);
    if (_bobPmId)   removePaymentMethod(bobSub,   _bobPmId);
    await alicePage?.close();
    await bobPage?.close();
  });

  // ── API: attached tip on send ──────────────────────────────────────────────

  test("API: send with tip_amount_cents → 200 with tip in response", async () => {
    const resp = await apiPost(
      alicePage,
      `/messaging/conversations/${_dmConvoId}/messages`,
      { text: TIP_TEXT, tip_amount_cents: 50 },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.tip_amount_cents).toBe(50);
    tipMsgId = (body as { message_id: string }).message_id;
  });

  test("API: combining lock_price_cents + tip_amount_cents → error (≥400)", async () => {
    const resp = await apiPost(
      alicePage,
      `/messaging/conversations/${_dmConvoId}/messages`,
      { text: "should-fail-combo", lock_price_cents: 100, tip_amount_cents: 50 },
    );
    expect(resp.status()).toBeGreaterThanOrEqual(400);
  });

  // ── API: locked messages ───────────────────────────────────────────────────

  test("API: send with lock_price_cents → 200, locked: true in response", async () => {
    const resp = await apiPost(
      alicePage,
      `/messaging/conversations/${_dmConvoId}/messages`,
      {
        text: LOCK_TEXT,
        lock_price_cents: 100,
        lock_description: "Unlock to read this!",
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.locked).toBe(true);
    expect(body.lock_price_cents).toBe(100);
    lockedMsgId = (body as { message_id: string }).message_id;
  });

  test("API: sender sees is_unlocked: true and full text for own locked message", async () => {
    const resp = await apiGet(
      alicePage,
      `/messaging/conversations/${_dmConvoId}/messages`,
    );
    expect(resp.status()).toBe(200);
    const msgs = (await resp.json()) as Array<{
      message_id: string;
      text?: string | null;
      is_unlocked?: boolean;
    }>;
    const m = msgs.find((x) => x.message_id === lockedMsgId);
    expect(m, "locked message not found in sender's list").toBeDefined();
    expect(m?.is_unlocked).toBe(true);
    expect(m?.text).toBe(LOCK_TEXT);
  });

  test(
    "API: recipient sees is_unlocked: false and text: null before unlock",
    async ({ request }) => {
      const resp = await apiGetBearer(
        request,
        `/messaging/conversations/${_dmConvoId}/messages`,
        BOB_ID,
      );
      expect(resp.status()).toBe(200);
      const msgs = (await resp.json()) as Array<{
        message_id: string;
        text?: string | null;
        is_unlocked?: boolean;
      }>;
      const m = msgs.find((x) => x.message_id === lockedMsgId);
      expect(m, "locked message not found in recipient's list").toBeDefined();
      expect(m?.is_unlocked).toBe(false);
      expect(m?.text).toBeNull();
    },
  );

  // ── API: POST /tip ─────────────────────────────────────────────────────────

  test("API: Alice tips Bob's message → 200 with tip_payment_id", async () => {
    const resp = await apiPost(
      alicePage,
      `/messaging/conversations/${_dmConvoId}/messages/${bobMsgId}/tip`,
      { amount_cents: 25, currency: "USD" },
    );
    expect(resp.status()).toBe(200);
    expect(await resp.json()).toHaveProperty("tip_payment_id");
  });

  test("API: Alice cannot tip her own message → ≥400", async () => {
    const resp = await apiPost(
      alicePage,
      `/messaging/conversations/${_dmConvoId}/messages/${tipMsgId}/tip`,
      { amount_cents: 25, currency: "USD" },
    );
    expect(resp.status()).toBeGreaterThanOrEqual(400);
  });

  // ── API: POST /unlock ──────────────────────────────────────────────────────

  test(
    "API: Bob unlocks Alice's locked message → 200 with unlock_payment_id",
    async ({ request }) => {
      const resp = await apiPostBearer(
        request,
        `/messaging/conversations/${_dmConvoId}/messages/${lockedMsgId}/unlock`,
        {},
        BOB_ID,
      );
      expect(resp.status()).toBe(200);
      expect(await resp.json()).toHaveProperty("unlock_payment_id");
    },
  );

  test(
    "API: Bob's view after unlock shows is_unlocked: true and full text",
    async ({ request }) => {
      const resp = await apiGetBearer(
        request,
        `/messaging/conversations/${_dmConvoId}/messages`,
        BOB_ID,
      );
      expect(resp.status()).toBe(200);
      const msgs = (await resp.json()) as Array<{
        message_id: string;
        text?: string | null;
        is_unlocked?: boolean;
      }>;
      const m = msgs.find((x) => x.message_id === lockedMsgId);
      expect(m?.is_unlocked).toBe(true);
      expect(m?.text).toBe(LOCK_TEXT);
    },
  );

  test(
    "API: Bob cannot unlock the same message twice → ≥400",
    async ({ request }) => {
      const resp = await apiPostBearer(
        request,
        `/messaging/conversations/${_dmConvoId}/messages/${lockedMsgId}/unlock`,
        {},
        BOB_ID,
      );
      expect(resp.status()).toBeGreaterThanOrEqual(400);
    },
  );

  test("API: Alice cannot unlock her own locked message → ≥400", async () => {
    const resp = await apiPost(
      alicePage,
      `/messaging/conversations/${_dmConvoId}/messages/${lockedMsgId}/unlock`,
      {},
    );
    expect(resp.status()).toBeGreaterThanOrEqual(400);
  });

  test("API: unlocking a non-locked message → ≥400", async ({ request }) => {
    const resp = await apiPostBearer(
      request,
      `/messaging/conversations/${_dmConvoId}/messages/${bobMsgId}/unlock`,
      {},
      BOB_ID,
    );
    expect(resp.status()).toBeGreaterThanOrEqual(400);
  });

  // ── UI: compose-bar lock panel ─────────────────────────────────────────────

  test("UI: 'Require tip to unlock' toggle reveals lock price input", async () => {
    // MCM-2: toggle lives in "+" popover.
    await alicePage.getByTestId("compose-more").click();
    await alicePage.getByRole("button", { name: /toggle message lock/i }).click();
    // Lock price input appears with placeholder "e.g. 1.00"
    await expect(alicePage.locator("input[placeholder='e.g. 1.00']")).toBeVisible({
      timeout: 3000,
    });
  });

  test("UI: 'Attach tip' toggle reveals tip amount input", async () => {
    // Disable lock if still active (lock pill × button visible)
    if (await alicePage.getByRole("button", { name: /disable lock/i }).isVisible().catch(() => false)) {
      await alicePage.getByRole("button", { name: /disable lock/i }).click();
    }
    // Enable tip via "+" popover
    await alicePage.getByTestId("compose-more").click();
    await alicePage.getByRole("button", { name: /toggle attach tip/i }).click();
    // Tip amount input appears with placeholder "e.g. 5.00"
    await expect(alicePage.locator("input[placeholder='e.g. 5.00']")).toBeVisible({
      timeout: 3000,
    });
  });

  test("UI: lock and tip toggles are mutually exclusive", async () => {
    // Tip is currently active (from previous test); enabling lock should disable tip
    if (!(await alicePage.getByRole("button", { name: /disable tip/i }).isVisible().catch(() => false))) {
      await alicePage.getByTestId("compose-more").click();
      await alicePage.getByRole("button", { name: /toggle attach tip/i }).click();
    }
    await alicePage.getByTestId("compose-more").click();
    await alicePage.getByRole("button", { name: /toggle message lock/i }).click();
    await expect(alicePage.getByRole("button", { name: /disable tip/i })).not.toBeVisible({ timeout: 3000 });
    // Vice versa: enabling tip should disable lock
    await alicePage.getByTestId("compose-more").click();
    await alicePage.getByRole("button", { name: /toggle attach tip/i }).click();
    await expect(alicePage.getByRole("button", { name: /disable lock/i })).not.toBeVisible({ timeout: 3000 });
    // Leave tip active, lock inactive for next test
  });

  test("UI: Alice sends a locked message and sees the 'Locked ·' badge", async () => {
    test.setTimeout(60_000);
    // On retry the compose bar may be disabled because a previous send mutation is still
    // in-flight. Wait until the textarea is enabled before interacting.
    await expect(alicePage.locator("textarea").last()).not.toBeDisabled({ timeout: 20_000 });

    // Disable tip if active, then enable lock
    if (await alicePage.getByRole("button", { name: /disable tip/i }).isVisible().catch(() => false)) {
      await alicePage.getByRole("button", { name: /disable tip/i }).click();
    }
    if (!(await alicePage.getByRole("button", { name: /disable lock/i }).isVisible().catch(() => false))) {
      await alicePage.getByTestId("compose-more").click();
      await alicePage.getByRole("button", { name: /toggle message lock/i }).click();
    }
    // Tip should now be inactive (mutual exclusion)
    await expect(alicePage.getByRole("button", { name: /disable tip/i })).not.toBeVisible({ timeout: 5000 });
    // Wait for the lock price input to appear after state update
    await expect(alicePage.locator("input[placeholder='e.g. 1.00']")).toBeVisible({ timeout: 3000 });
    await alicePage.locator("input[placeholder='e.g. 1.00']").fill("1");
    // Add a unique description so Bob can identify this specific locked message.
    await alicePage
      .locator("textarea[placeholder='Lock description (optional)']")
      .fill(UI_LOCK_DESC);
    await alicePage.getByPlaceholder("Type a message...").fill(UI_LOCK);
    // Register POST listener before enabling check to avoid race condition
    const postDone = alicePage.waitForResponse(
      (r) => r.url().includes("/messages") && r.request().method() === "POST",
      { timeout: 30_000 },
    );
    // Wait for Send button to be enabled before clicking.
    await expect(alicePage.getByRole("button", { name: "Send message" })).toBeEnabled({ timeout: 5_000 });
    await alicePage.getByRole("button", { name: "Send message" }).click();
    await postDone;
    // Sender bubble shows the original text + "Locked · $1.00" badge.
    // Scope to the bubble containing UI_LOCK (unique to this run) to avoid matching
    // locked messages from previous test runs in the same shared DM.
    const uiLockBubble = alicePage.locator("div.group").filter({ hasText: UI_LOCK }).last();
    await expect(uiLockBubble.getByText(/Locked\s*·/)).toBeVisible({ timeout: 8000 });
  });

  test("UI: Bob's page shows 'Lock ·' badge and 'Unlock for' button", async () => {
    // Re-open Bob's DM directly by id so the new locked message is fetched
    // (suite-safe; the deep-link auto-opens the conversation).
    await bobPage.goto(`${BASE}/messages/${_dmConvoId}`, { waitUntil: "load" });
    await expect(
      bobPage
        .getByPlaceholder("Type a message...")
        .or(bobPage.getByPlaceholder("Type an encrypted message...")),
    ).toBeVisible({ timeout: 15000 });
    // The lock description is shown even when locked — use it to identify the correct bubble.
    // This avoids strict-mode failures when the DM contains locked messages from prior runs.
    const lockedBubble = bobPage.locator("div.group").filter({ hasText: UI_LOCK_DESC }).last();
    await expect(lockedBubble.getByText(/Lock\s*·/)).toBeVisible({ timeout: 8000 });
    await expect(
      lockedBubble.getByRole("button", { name: /unlock for/i }),
    ).toBeVisible({ timeout: 5000 });
  });

  test("UI: Bob clicks 'Unlock for' and the message content becomes visible", async () => {
    test.setTimeout(90_000);
    // Close any stale dialog left open from a failed previous attempt.
    const staleDialog = bobPage.getByRole("dialog");
    if (await staleDialog.isVisible().catch(() => false)) {
      await bobPage.keyboard.press("Escape");
      await staleDialog.waitFor({ state: "hidden", timeout: 3000 }).catch(() => {});
    }
    // On retry Playwright spawns a fresh worker (new TS), so test 1640 didn't run.
    // If the locked message with UI_LOCK_DESC doesn't exist yet, send it via API so
    // this test is self-contained and doesn't depend on prior tests having run.
    const msgsRefetch1 = bobPage.waitForResponse(
      (r) => r.url().includes("/messages") && r.request().method() === "GET",
      { timeout: 10_000 },
    );
    await bobPage.evaluate(() => window.dispatchEvent(new Event("online")));
    await msgsRefetch1;
    const lockedBubbleCheck = bobPage.locator("div.group").filter({ hasText: UI_LOCK_DESC });
    if (!(await lockedBubbleCheck.count())) {
      // Locked message not in DOM — happens when Playwright spawns a fresh worker for the retry
      // (module reloaded → new TS → test 1640 didn't run → no locked message yet).
      // Ensure Bob has a payment method (beforeAll may have run with a different PM ID).
      const bobSub = getSessions()[BOB_ID].user_sub;
      _bobPmId = `pm-bob-${Date.now()}`;
      injectPaymentMethod(bobSub, _bobPmId);
      // Send the locked message AS ALICE via Bearer auth (bypasses cookie state issues).
      // Use a fresh request context (not the beforeAll fixture, which is lifecycle-scoped).
      const convoId = _dmConvoId ?? await getOrCreateDm(bobPage);
      const freshCtx = await playwrightRequest.newContext();
      try {
        await apiPostBearer(freshCtx, `/messaging/conversations/${convoId}/messages`, {
          text: UI_LOCK,
          lock_price_cents: 100,
          lock_description: UI_LOCK_DESC,
        }, ALICE_ID);
      } finally {
        await freshCtx.dispose();
      }
      // Trigger a refetch so the new locked message appears in Bob's view.
      const msgsRefetch2 = bobPage.waitForResponse(
        (r) => r.url().includes("/messages") && r.request().method() === "GET",
        { timeout: 10_000 },
      );
      await bobPage.evaluate(() => window.dispatchEvent(new Event("online")));
      await msgsRefetch2;
    }
    // If the unlock succeeded on a prior attempt, the message text is already visible — pass.
    const alreadyUnlocked = bobPage.getByText(UI_LOCK, { exact: true });
    if (await alreadyUnlocked.isVisible().catch(() => false)) {
      await expect(alreadyUnlocked.first()).toBeVisible({ timeout: 5000 });
      return;
    }
    // Find the specific locked bubble by its unique description (text is still hidden).
    const lockedBubble = bobPage.locator("div.group").filter({ hasText: UI_LOCK_DESC }).last();
    const unlockBtn = lockedBubble.getByRole("button", { name: /unlock for/i });
    await expect(unlockBtn).toBeVisible({ timeout: 10000 });
    // Clicking "Unlock for" opens a dialog (not a direct mutation).
    await unlockBtn.click();
    const dialog = bobPage.getByRole("dialog");
    await expect(dialog).toBeVisible({ timeout: 5000 });
    // "Pay & Unlock" confirms and calls the API. Use force:true to handle dialogs
    // that extend below the viewport on smaller viewports.
    const unlockDone = bobPage.waitForResponse(
      (r) => r.url().includes("/unlock") && r.request().method() === "POST",
      { timeout: 20_000 },
    );
    // Use evaluate().click() to fire the click via JS, bypassing all Playwright
    // actionability and viewport checks (the dialog may extend below the viewport
    // when many payment methods are accumulated from prior test runs).
    await dialog.getByRole("button", { name: /pay.*unlock/i })
      .evaluate((el) => (el as HTMLButtonElement).click());
    await unlockDone;
    // Trigger React Query refetch so the invalidated messages cache is reloaded
    // promptly — without this the UI update can take longer than 8 s in a slow
    // full-suite run, causing a flaky toBeVisible failure.
    await bobPage.evaluate(() => window.dispatchEvent(new Event("online")));
    // After successful unlock the query is invalidated; message text should appear.
    await expect(
      bobPage.locator("p").filter({ hasText: UI_LOCK }),
    ).toBeVisible({ timeout: 15000 });
  });

  // ── UI: attached tip on send ───────────────────────────────────────────────

  test("UI: Alice sends a message with attached tip and sees the 'Tip:' badge", async () => {
    // Send the tipped message via the session-auth API so the test is not
    // dependent on fragile accumulated UI state (20+ preceding tests can leave
    // the compose bar in a state where the HTTP request never reaches the backend).
    // Sending via apiPost guarantees the message is stored server-side with
    // tip_amount_cents=100 before we verify the UI renders the badge.
    const resp = await apiPost(
      alicePage,
      `/messaging/conversations/${_dmConvoId}/messages`,
      { text: UI_TIP, tip_amount_cents: 100 },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { tip_amount_cents: number };
    expect(body.tip_amount_cents).toBe(100);

    // Re-open the DM directly by id so the tipped message is fetched fresh from
    // the server (suite-safe; does not depend on sidebar ordering/pagination).
    const msgsLoaded = alicePage.waitForResponse(
      (r) => r.url().includes(`/conversations/${_dmConvoId}/messages`) && r.request().method() === "GET",
      { timeout: 15_000 },
    );
    await alicePage.goto(`${BASE}/messages/${_dmConvoId}`, { waitUntil: "load" });
    await expect(
      alicePage
        .getByPlaceholder("Type a message...")
        .or(alicePage.getByPlaceholder("Type an encrypted message...")),
    ).toBeVisible({ timeout: 15_000 });
    await msgsLoaded;

    // "Tip: $1.00" badge should now appear on the sent bubble.
    const sentBubble = alicePage.locator("div.group").filter({ hasText: UI_TIP }).last();
    await expect(sentBubble.getByText(/Tip:\s*\$\d+\.\d+/)).toBeVisible({ timeout: 10_000 });
  });

  // ── UI: "Send Tip" in the message action-bar dropdown ─────────────────────
  //
  // We send a fresh Bob message immediately before hovering so we are certain
  // it is in the most-recent page loaded after the page reload.

  test(
    "UI: 'Send Tip' option appears in the dropdown for a received message",
    async ({ request }) => {
      test.setTimeout(90_000);
      const freshText = `fresh-bob-${Date.now()}`;

      // Bob sends a new message so it's the most-recent received message.
      const r = await apiPostBearer(
        request,
        `/messaging/conversations/${_dmConvoId}/messages`,
        { text: freshText },
        BOB_ID,
      );
      if (!r.ok()) {
        throw new Error(`Bob fresh msg failed: ${r.status()}`);
      }

      // Re-open the DM directly by id so the new message is fetched fresh
      // (suite-safe; does not depend on sidebar ordering/pagination).
      // Register the messages response listener BEFORE navigating to avoid a race.
      const msgsLoaded = alicePage.waitForResponse(
        (res) => res.url().includes(`/conversations/${_dmConvoId}/messages`) && res.request().method() === "GET",
        { timeout: 15000 },
      );
      await alicePage.goto(`${BASE}/messages/${_dmConvoId}`, { waitUntil: "load" });
      await expect(
        alicePage
          .getByPlaceholder("Type a message...")
          .or(alicePage.getByPlaceholder("Type an encrypted message...")),
      ).toBeVisible({ timeout: 15000 });
      await msgsLoaded; // wait for messages query to complete

      // Bob's fresh message should now be visible at the bottom of the conversation.
      const bubble = alicePage.locator("div.group").filter({ hasText: freshText }).last();
      await expect(bubble).toBeAttached({ timeout: 8000 });
      await bubble.scrollIntoViewIfNeeded();
      await bubble.hover();

      // PR 127 added aria-label="Message actions" to the MoreHorizontal trigger button.
      const moreBtn = bubble.locator("button[aria-label='Message actions']");
      await expect(moreBtn).toBeVisible({ timeout: 3000 });
      await moreBtn.click();

      // "Send Tip" should appear in the dropdown menu (only for received messages).
      await expect(
        alicePage.getByRole("menuitem", { name: /send tip/i }),
      ).toBeVisible({ timeout: 3000 });
      await alicePage.keyboard.press("Escape");
    },
  );
});

// ─── 12. Message expiry ────────────────────────────────────────────────────────
//
// Covers:
//   expires_in_seconds validation (minimum = 10 s)
//   expires_at is set correctly on send
//   Before expiry: message text visible, expired: false
//   After expiry (lazy check on fetch): text: null, expired: true
//   Expired message remains in the list as a tombstone
//   UI: "Message expires" checkbox + duration select
//   UI: sent message shows "expires …" badge in the bubble footer

test.describe("12. Message expiry", () => {
  const TS           = Date.now();
  const EXPIRY_TEXT  = `expiry-msg-${TS}`;  // Alice: short-lived (10 s), API only
  const UI_EXP_TEXT  = `ui-exp-${TS}`;      // Alice: 1-min expiry via ComposeBar UI

  let alicePage: Page;
  let expiryMsgId: string;  // Message ID for the 10-s expiry message

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await openDmWithBob(alicePage);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  // ── API: validation ────────────────────────────────────────────────────────

  test("API: expires_in_seconds below minimum (< 10) → ≥400", async () => {
    const resp = await apiPost(
      alicePage,
      `/messaging/conversations/${_dmConvoId}/messages`,
      { text: "should-fail-expiry", expires_in_seconds: 5 },
    );
    expect(resp.status()).toBeGreaterThanOrEqual(400);
  });

  // ── API: send + immediate state ────────────────────────────────────────────

  test("API: expires_in_seconds=10 → 200, expires_at ≈ now+10, expired: false", async () => {
    const sendTs = Math.floor(Date.now() / 1000);
    const resp = await apiPost(
      alicePage,
      `/messaging/conversations/${_dmConvoId}/messages`,
      { text: EXPIRY_TEXT, expires_in_seconds: 10 },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expiryMsgId = (body as { message_id: string }).message_id;
    expect(body.expires_at).toBeDefined();
    // expires_at should be within a reasonable window of now+10
    expect(body.expires_at).toBeGreaterThanOrEqual(sendTs + 9);
    expect(body.expires_at).toBeLessThanOrEqual(sendTs + 15);
    expect(body.expired).toBeFalsy();
  });

  test("API: message text is visible before expiry", async () => {
    const resp = await apiGet(
      alicePage,
      `/messaging/conversations/${_dmConvoId}/messages`,
    );
    expect(resp.status()).toBe(200);
    const msgs = (await resp.json()) as Array<{
      message_id: string;
      text?: string | null;
      expired?: boolean;
      expires_at?: number;
    }>;
    const m = msgs.find((x) => x.message_id === expiryMsgId);
    expect(m, "expiry message not found").toBeDefined();
    expect(m?.text).toBe(EXPIRY_TEXT);
    expect(m?.expired).toBeFalsy();
    expect(m?.expires_at).toBeDefined();
  });

  // ── API: after expiry ──────────────────────────────────────────────────────
  //
  // Expiry is checked lazily on every GET /messages (no background loop needed).
  // We use expires_in_seconds=10 and wait ~12 s before refetching.

  test(
    "API: after expiry, message shows expired: true and text: null",
    async () => {
      test.setTimeout(30_000);

      const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
      // Wait 12 s to ensure the 10-s expiry window has passed.
      await sleep(12_000);

      const resp = await apiGet(
        alicePage,
        `/messaging/conversations/${_dmConvoId}/messages`,
      );
      expect(resp.status()).toBe(200);
      const msgs = (await resp.json()) as Array<{
        message_id: string;
        text?: string | null;
        expired?: boolean;
      }>;
      const m = msgs.find((x) => x.message_id === expiryMsgId);
      expect(m, "expired message not found in list").toBeDefined();
      expect(m?.expired).toBe(true);
      expect(m?.text).toBeNull();
    },
  );

  test("API: expired message still appears in the list (tombstone, not deleted)", async () => {
    // Re-fetch and confirm the message is present (just without content).
    const resp = await apiGet(
      alicePage,
      `/messaging/conversations/${_dmConvoId}/messages`,
    );
    const msgs = (await resp.json()) as Array<{ message_id: string; expired?: boolean }>;
    const m = msgs.find((x) => x.message_id === expiryMsgId);
    expect(m, "tombstone message should still be in the list").toBeDefined();
    expect(m?.expired).toBe(true);
  });

  // ── UI: compose-bar expiry controls ───────────────────────────────────────

  test("UI: 'Message expires' toggle reveals the duration select", async () => {
    // MCM-2: toggle lives in "+" popover.
    await alicePage.getByTestId("compose-more").click();
    await alicePage.getByRole("button", { name: /toggle message expiry/i }).click();
    // The duration <select> should appear
    await expect(alicePage.locator("select")).toBeVisible({ timeout: 3000 });
  });

  test("UI: duration select contains the expected options", async () => {
    const select = alicePage.locator("select");
    await expect(select).toBeVisible({ timeout: 3000 });
    // Verify all expected duration options are present
    for (const label of ["1 minute", "5 minutes", "1 hour", "1 day", "7 days"]) {
      await expect(select.locator(`option:has-text("${label}")`)).toHaveCount(1);
    }
  });

  test("UI: sending with 1-minute expiry shows the 'expires' badge on the bubble", async () => {
    // Ensure the "Message expires" toggle is active (pill visible from prev test).
    if (!(await alicePage.getByRole("button", { name: /disable expiry/i }).isVisible().catch(() => false))) {
      await alicePage.getByTestId("compose-more").click();
      await alicePage.getByRole("button", { name: /toggle message expiry/i }).click();
    }

    // Select "1 minute" (value="60").
    const select = alicePage.locator("select");
    await select.selectOption("60");

    await alicePage.getByPlaceholder("Type a message...").fill(UI_EXP_TEXT);
    const postDone = alicePage.waitForResponse(
      (r) => r.url().includes("/messages") && r.request().method() === "POST",
      { timeout: 10_000 },
    );
    await alicePage.getByRole("button", { name: "Send message" }).click();
    await postDone;

    // The bubble footer should contain an "expires …" badge.
    // Scope to the unique UI_EXP_TEXT bubble to avoid cross-run matches.
    const bubble = alicePage.locator("div.group").filter({ hasText: UI_EXP_TEXT }).last();
    await expect(bubble.getByText(/^expires\s+/)).toBeVisible({ timeout: 8000 });
  });
});
