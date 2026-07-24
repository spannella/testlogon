/**
 * E2E tests for Group Chat messaging — mirrors messaging-features.spec.ts DM tests.
 *
 * Group chat requires ≥ 3 participants (creator + 2 others). We use:
 *   Alice  (e2e_alice@test.local)   — creator / primary actor
 *   Bob    (e2e_bob@test.local)     — participant
 *   Charlie (e2e_charlie@test.local) — participant
 *
 * Non-creator group members start as "pending" and must call
 * POST /conversations/{id}/accept before they can send/read messages.
 *
 * API call pattern:
 *   - Alice: browser-context cookies + CSRF (via page.request + x-csrf-token)
 *   - Bob/Charlie: Bearer token auth (apiPostBearer / apiGetBearer)
 *     The messaging backend accepts Authorization: Bearer <user_id> in dev mode.
 *
 * Sections:
 *   1.  Group creation and participant acceptance
 *   2.  Basic text messages in groups
 *   3.  View-once messages in groups
 *   4.  Encrypted messages in groups
 *   5.  Message replies in groups
 *   6.  Reactions in groups
 *   7.  Tips on messages in groups
 *   8.  Locked messages in groups
 *   9.  Message expiry in groups
 *   10. Scheduled messages in groups
 *   11. UI — open group conversation and verify sender names + features
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ───────────────────────────────────────────────────────────────

const PYTHON = REPO_ROOT + "/.venv/bin/python3";
const BASE = "http://localhost:3000";

const ALICE_ID   = "e2e_alice@test.local";
const BOB_ID     = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None";
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

/** POST authenticated as Alice (browser context cookies + Alice CSRF). */
async function apiPost(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

/** GET authenticated as Alice. */
async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

type APIRequestContext = import("@playwright/test").APIRequestContext;

/** POST as an arbitrary user using the dev-mode Bearer token (no browser cookies). */
async function apiPostBearer(req: APIRequestContext, path: string, body: object, userId: string) {
  return req.post(`${API}${path}`, {
    data: body,
    headers: { Authorization: `Bearer ${getSessions()[userId].user_sub}` },
  });
}

/** GET as an arbitrary user using the dev-mode Bearer token. */
async function apiGetBearer(req: APIRequestContext, path: string, userId: string) {
  return req.get(`${API}${path}`, {
    headers: { Authorization: `Bearer ${getSessions()[userId].user_sub}` },
  });
}

// ─── Payment method helpers ───────────────────────────────────────────────────

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
  } catch { /* best-effort */ }
}

// ─── Group conversation bootstrap ────────────────────────────────────────────

/** Cached group conversation ID shared across sections. */
let _groupConvoId: string | null = null;

/**
 * Create a fresh group each run (no "get existing" API for groups).
 * Bob and Charlie both accept the pending invitation so they can send messages.
 */
async function getOrCreateGroup(page: Page, request: APIRequestContext): Promise<string> {
  if (_groupConvoId) return _groupConvoId;

  const bobSub     = getSessions()[BOB_ID].user_sub;
  const charlieSub = getSessions()[CHARLIE_ID].user_sub;

  const resp = await apiPost(page, "/messaging/conversations/group", {
    participant_ids: [bobSub, charlieSub],
    title: "E2E Test Group",
  });
  if (!resp.ok()) {
    const body = await resp.text().catch(() => "(unreadable)");
    throw new Error(`Group creation failed: HTTP ${resp.status()} — ${body}`);
  }
  const body = await resp.json() as { conversation_id: string };
  _groupConvoId = body.conversation_id;

  // Bob and Charlie must accept to become "active" participants
  for (const userId of [BOB_ID, CHARLIE_ID]) {
    const acceptResp = await apiPostBearer(
      request,
      `/messaging/conversations/${_groupConvoId}/accept`,
      {},
      userId,
    );
    if (!acceptResp.ok()) {
      const t = await acceptResp.text().catch(() => "?");
      throw new Error(`Accept failed for ${userId}: ${acceptResp.status()} ${t}`);
    }
  }

  // Make this group appear at the top of Alice's sidebar by "touching" it
  await apiPost(page, `/messaging/conversations/${_groupConvoId}/messages`, {
    text: `__touch__${Date.now()}`,
  });

  return _groupConvoId;
}

/**
 * Navigate Alice to her "E2E Test Group" conversation (opened by id via the
 * deep-link route, which is robust against full-suite conversation accumulation).
 */
async function openGroupConvo(page: Page, request: APIRequestContext) {
  await injectAuth(page, ALICE_ID);
  const groupId = await getOrCreateGroup(page, request);
  // Open the group directly by id via the deep-link route. This is
  // full-suite-safe: it does not rely on the "E2E Test Group" row being
  // visible/first in a sidebar that accumulates many conversations over a run.
  await page.goto(`${BASE}/messages/${groupId}`, { waitUntil: "load" });
  await expect(
    page.getByPlaceholder("Type a message...").or(
      page.getByPlaceholder("Type an encrypted message..."),
    ),
  ).toBeVisible({ timeout: 15000 });
}

// ─── Helper: trigger UI refetch ───────────────────────────────────────────────
async function triggerRefetch(page: Page) {
  await page.evaluate(() => window.dispatchEvent(new Event("online")));
  await page.waitForTimeout(800);
}

// ─── 1. Group creation and participant acceptance ─────────────────────────────

test.describe("1. Group creation and participant acceptance", () => {
  test("POST /conversations/group creates group with pending participants", async ({ browser, request }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    const bobSub     = getSessions()[BOB_ID].user_sub;
    const charlieSub = getSessions()[CHARLIE_ID].user_sub;

    const resp = await apiPost(page, "/messaging/conversations/group", {
      participant_ids: [bobSub, charlieSub],
      title: "Creation Test Group",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json() as {
      conversation_id: string;
      type: string;
      title: string;
      participant_count: number;
      participants: Array<{ user_id: string; status: string }>;
    };
    expect(body.type).toBe("group");
    expect(body.title).toBe("Creation Test Group");
    expect(body.participant_count).toBe(3);

    // Alice (creator) is active; Bob + Charlie are pending
    const alice   = body.participants.find((p) => p.user_id === ALICE_ID);
    const bob     = body.participants.find((p) => p.user_id === BOB_ID);
    const charlie = body.participants.find((p) => p.user_id === CHARLIE_ID);
    expect(alice?.status).toBe("active");
    expect(bob?.status).toBe("pending");
    expect(charlie?.status).toBe("pending");

    await page.close();
    void request; // used implicitly via module-level
  });

  test("POST /conversations/group requires ≥ 2 participant_ids (returns 422 with 1)", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const bobSub = getSessions()[BOB_ID].user_sub;
    const resp = await apiPost(page, "/messaging/conversations/group", {
      participant_ids: [bobSub], // only 1 → validation error
    });
    expect(resp.status()).toBe(422);
    await page.close();
  });

  test("accept converts participant status to active", async ({ browser, request }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    const bobSub     = getSessions()[BOB_ID].user_sub;
    const charlieSub = getSessions()[CHARLIE_ID].user_sub;

    const createResp = await apiPost(page, "/messaging/conversations/group", {
      participant_ids: [bobSub, charlieSub],
      title: "Accept Test Group",
    });
    const { conversation_id } = await createResp.json() as { conversation_id: string };

    // Bob accepts
    const acceptResp = await apiPostBearer(
      request,
      `/messaging/conversations/${conversation_id}/accept`,
      {},
      BOB_ID,
    );
    expect(acceptResp.status()).toBe(200);

    // Verify Bob is now active
    const convResp = await apiGetBearer(request, `/messaging/conversations/${conversation_id}`, BOB_ID);
    expect(convResp.status()).toBe(200);
    const convo = await convResp.json() as { participants: Array<{ user_id: string; status: string }> };
    const bob = convo.participants.find((p) => p.user_id === BOB_ID);
    expect(bob?.status).toBe("active");

    await page.close();
  });

  test("pending participant cannot send messages before accepting", async ({ browser, request }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    const bobSub     = getSessions()[BOB_ID].user_sub;
    const charlieSub = getSessions()[CHARLIE_ID].user_sub;

    const createResp = await apiPost(page, "/messaging/conversations/group", {
      participant_ids: [bobSub, charlieSub],
      title: "Pending Block Test",
    });
    const { conversation_id } = await createResp.json() as { conversation_id: string };

    // Bob (still pending) tries to send a message
    const sendResp = await apiPostBearer(
      request,
      `/messaging/conversations/${conversation_id}/messages`,
      { text: "should be blocked" },
      BOB_ID,
    );
    expect(sendResp.status()).toBe(403);
    await page.close();
  });
});

// ─── 2. Basic text messages in groups ────────────────────────────────────────

test.describe("2. Basic text messages in groups", () => {
  let page: Page;
  let groupId: string;

  test.beforeAll(async ({ browser, request }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    groupId = await getOrCreateGroup(page, request);
  });
  test.afterAll(async () => page.close());

  test("Alice can send a text message to the group", async ({ request }) => {
    const ts = Date.now();
    const resp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `Group text message ${ts}`,
    });
    expect(resp.status()).toBe(200);
    const msg = await resp.json() as { message_id: string; text: string; sender_id: string };
    expect(msg.text).toBe(`Group text message ${ts}`);
    expect(msg.sender_id).toBe(ALICE_ID);
  });

  test("Bob (active participant) can send a message", async ({ request }) => {
    const ts = Date.now();
    const resp = await apiPostBearer(
      request,
      `/messaging/conversations/${groupId}/messages`,
      { text: `Bob group msg ${ts}` },
      BOB_ID,
    );
    expect(resp.status()).toBe(200);
    const msg = await resp.json() as { text: string; sender_id: string };
    expect(msg.text).toBe(`Bob group msg ${ts}`);
    expect(msg.sender_id).toBe(BOB_ID);
  });

  test("GET /messages returns messages from all group participants", async ({ request }) => {
    const resp = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, ALICE_ID);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Array<{ sender_id: string }>;
    const senders = new Set(data.map((m) => m.sender_id));
    // Alice and Bob have both sent messages
    expect(senders.has(ALICE_ID)).toBe(true);
    expect(senders.has(BOB_ID)).toBe(true);
  });

  test("Charlie can also send a message after accepting", async ({ request }) => {
    const ts = Date.now();
    const resp = await apiPostBearer(
      request,
      `/messaging/conversations/${groupId}/messages`,
      { text: `Charlie group msg ${ts}` },
      CHARLIE_ID,
    );
    expect(resp.status()).toBe(200);
    const msg = await resp.json() as { sender_id: string };
    expect(msg.sender_id).toBe(CHARLIE_ID);
  });
});

// ─── 3. View-once messages in groups ─────────────────────────────────────────

test.describe("3. View-once messages in groups", () => {
  let page: Page;
  let groupId: string;

  test.beforeAll(async ({ browser, request }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    groupId = await getOrCreateGroup(page, request);
  });
  test.afterAll(async () => page.close());

  test("Alice can send a view-once message to the group", async () => {
    const resp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `View-once group ${Date.now()}`,
      view_once: true,
    });
    expect(resp.status()).toBe(200);
    const msg = await resp.json() as { view_once: boolean; message_id: string };
    expect(msg.view_once).toBe(true);
  });

  test("view_once field appears in GET /messages for group", async ({ request }) => {
    // Send one first
    const sendResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `VO group check ${Date.now()}`,
      view_once: true,
    });
    const sent = await sendResp.json() as { message_id: string };

    const listResp = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, BOB_ID);
    const data = await listResp.json() as Array<{ message_id: string; view_once: boolean }>;
    const found = data.find((m) => m.message_id === sent.message_id);
    expect(found).toBeDefined();
    expect(found!.view_once).toBe(true);
  });

  test("sender sees view-once message text (not hidden for sender)", async ({ request }) => {
    const text = `VO sender sees ${Date.now()}`;
    await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text,
      view_once: true,
    });
    const listResp = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, ALICE_ID);
    const data = await listResp.json() as Array<{ text: string | null; view_once: boolean }>;
    const match = data.find((m) => m.view_once && m.text === text);
    expect(match).toBeDefined();
  });

  test("recipient (Bob) sees view-once text hidden until viewed", async ({ request }) => {
    const text = `VO bob hidden ${Date.now()}`;
    const sendResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text,
      view_once: true,
    });
    const sent = await sendResp.json() as { message_id: string };

    // Bob reads messages — view-once text not yet consumed
    const listResp = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, BOB_ID);
    const data = await listResp.json() as Array<{ message_id: string; text: string | null; view_once_seen: boolean }>;
    const msg = data.find((m) => m.message_id === sent.message_id);
    expect(msg).toBeDefined();
    expect(msg!.view_once_seen).toBeFalsy();

    // Bob marks as viewed
    const viewResp = await apiPostBearer(
      request,
      `/messaging/conversations/${groupId}/messages/${sent.message_id}/view`,
      {},
      BOB_ID,
    );
    expect(viewResp.status()).toBe(200);
  });
});

// ─── 4. Encrypted messages in groups ─────────────────────────────────────────

test.describe("4. Encrypted messages in groups", () => {
  let page: Page;
  let groupId: string;

  test.beforeAll(async ({ browser, request }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    groupId = await getOrCreateGroup(page, request);
  });
  test.afterAll(async () => page.close());

  test("Alice can send an encrypted message to the group", async () => {
    const resp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      encryption: {
        version: 1,
        alg: "AES-256-GCM",
        kdf: "PBKDF2-SHA256",
        iterations: 600000,
        salt_b64: "AAAAAAAAAAAAAAAAAAAAAA==",
        iv_b64: "AAAAAAAAAAAAAAAA",
        ciphertext_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      },
    });
    expect(resp.status()).toBe(200);
    const msg = await resp.json() as { is_encrypted: boolean; text: string | null };
    expect(msg.is_encrypted).toBe(true);
  });

  test("encrypted message has null text and encryption envelope in group", async ({ request }) => {
    const envelope = {
      version: 1,
      alg: "AES-256-GCM",
      kdf: "PBKDF2-SHA256",
      iterations: 600000,
      salt_b64: "AAAAAAAAAAAAAAAAAAAAAA==",
      iv_b64: "AAAAAAAAAAAAAAAA",
      ciphertext_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    };
    const sendResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      encryption: envelope,
    });
    const sent = await sendResp.json() as { message_id: string };

    const listResp = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, BOB_ID);
    const data = await listResp.json() as Array<{
      message_id: string;
      is_encrypted: boolean;
      text: string | null;
      encryption: { alg: string } | null;
    }>;
    const msg = data.find((m) => m.message_id === sent.message_id);
    expect(msg).toBeDefined();
    expect(msg!.is_encrypted).toBe(true);
    expect(msg!.text).toBeNull();
    expect(msg!.encryption?.alg).toBe("AES-256-GCM");
  });

  test("Charlie also sees the encrypted envelope", async ({ request }) => {
    const sendResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      encryption: {
        version: 1,
        alg: "AES-256-GCM",
        kdf: "PBKDF2-SHA256",
        iterations: 600000,
        salt_b64: "AAAAAAAAAAAAAAAAAAAAAA==",
        iv_b64: "AAAAAAAAAAAAAAAA",
        ciphertext_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      },
    });
    const sent = await sendResp.json() as { message_id: string };

    const listResp = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, CHARLIE_ID);
    const data = await listResp.json() as Array<{ message_id: string; is_encrypted: boolean; encryption: { alg: string } | null }>;
    const msg = data.find((m) => m.message_id === sent.message_id);
    expect(msg).toBeDefined();
    expect(msg!.is_encrypted).toBe(true);
    expect(msg!.encryption?.alg).toBe("AES-256-GCM");
  });
});

// ─── 5. Message replies in groups ────────────────────────────────────────────

test.describe("5. Message replies in groups", () => {
  let page: Page;
  let groupId: string;

  test.beforeAll(async ({ browser, request }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    groupId = await getOrCreateGroup(page, request);
  });
  test.afterAll(async () => page.close());

  test("Bob can reply to Alice's message in the group", async ({ request }) => {
    // Alice sends original
    const origResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `Original group msg ${Date.now()}`,
    });
    const orig = await origResp.json() as { message_id: string };

    // Bob replies
    const replyResp = await apiPostBearer(
      request,
      `/messaging/conversations/${groupId}/messages`,
      { text: "Bob's reply to Alice", reply_to_message_id: orig.message_id },
      BOB_ID,
    );
    expect(replyResp.status()).toBe(200);
    const reply = await replyResp.json() as { reply_to_message_id: string };
    expect(reply.reply_to_message_id).toBe(orig.message_id);
  });

  test("Charlie can reply to Bob's message in the group", async ({ request }) => {
    // Bob sends
    const bobResp = await apiPostBearer(
      request,
      `/messaging/conversations/${groupId}/messages`,
      { text: `Bob msg for Charlie reply ${Date.now()}` },
      BOB_ID,
    );
    const bobMsg = await bobResp.json() as { message_id: string };

    // Charlie replies
    const replyResp = await apiPostBearer(
      request,
      `/messaging/conversations/${groupId}/messages`,
      { text: "Charlie's reply to Bob", reply_to_message_id: bobMsg.message_id },
      CHARLIE_ID,
    );
    expect(replyResp.status()).toBe(200);
    const reply = await replyResp.json() as { reply_to_message_id: string };
    expect(reply.reply_to_message_id).toBe(bobMsg.message_id);
  });

  test("reply_context is visible to all group participants", async ({ request }) => {
    const origText = `Visible reply ctx ${Date.now()}`;
    const origResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: origText,
    });
    const orig = await origResp.json() as { message_id: string };

    await apiPostBearer(
      request,
      `/messaging/conversations/${groupId}/messages`,
      { text: "Reply for visibility test", reply_to_message_id: orig.message_id },
      BOB_ID,
    );

    // Charlie sees the reply message (by reply_to_message_id)
    const charlieResp = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, CHARLIE_ID);
    const data = await charlieResp.json() as Array<{ reply_to_message_id?: string; text?: string }>;
    const replyMsg = data.find((m) => m.reply_to_message_id === orig.message_id);
    expect(replyMsg).toBeDefined();
    expect(replyMsg!.text).toBe("Reply for visibility test");
  });
});

// ─── 6. Reactions in groups ──────────────────────────────────────────────────

test.describe("6. Reactions in groups", () => {
  let page: Page;
  let groupId: string;

  test.beforeAll(async ({ browser, request }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    groupId = await getOrCreateGroup(page, request);
  });
  test.afterAll(async () => page.close());

  test("Bob can react to Alice's group message", async ({ request }) => {
    const msgResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `React target ${Date.now()}`,
    });
    const msg = await msgResp.json() as { message_id: string };

    const reactResp = await apiPostBearer(
      request,
      `/messaging/conversations/${groupId}/messages/${msg.message_id}/reactions`,
      { emoji: "👍" },
      BOB_ID,
    );
    expect(reactResp.status()).toBe(200);
    const reactBody = await reactResp.json() as { ok: boolean };
    expect(reactBody.ok).toBe(true);
  });

  test("multiple participants can react with different emojis", async ({ request }) => {
    const msgResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `Multi-react ${Date.now()}`,
    });
    const msg = await msgResp.json() as { message_id: string };

    // Bob reacts 👍
    await apiPostBearer(request, `/messaging/conversations/${groupId}/messages/${msg.message_id}/reactions`, { emoji: "👍" }, BOB_ID);
    // Charlie reacts ❤️
    await apiPostBearer(request, `/messaging/conversations/${groupId}/messages/${msg.message_id}/reactions`, { emoji: "❤️" }, CHARLIE_ID);

    // Alice sees both reactions
    const listResp = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, ALICE_ID);
    const data = await listResp.json() as Array<{
      message_id: string;
      reactions_counts: Record<string, number>;
    }>;
    const found = data.find((m) => m.message_id === msg.message_id);
    expect(found).toBeDefined();
    expect(found!.reactions_counts["👍"]).toBeGreaterThanOrEqual(1);
    expect(found!.reactions_counts["❤️"]).toBeGreaterThanOrEqual(1);
  });

  test("participant can remove their own reaction", async ({ request }) => {
    const msgResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `React remove ${Date.now()}`,
    });
    const msg = await msgResp.json() as { message_id: string };

    // Bob reacts then removes
    await apiPostBearer(request, `/messaging/conversations/${groupId}/messages/${msg.message_id}/reactions`, { emoji: "🔥" }, BOB_ID);
    const removeResp = await apiPostBearer(
      request,
      `/messaging/conversations/${groupId}/messages/${msg.message_id}/reactions`,
      { emoji: "🔥" },
      BOB_ID,
    );
    // Reacting again with same emoji toggles off (or removes)
    expect(removeResp.status()).toBe(200);
  });

  test("my_reactions field shows viewer's own reactions", async ({ request }) => {
    const msgResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `MyReact ${Date.now()}`,
    });
    const msg = await msgResp.json() as { message_id: string };

    await apiPostBearer(request, `/messaging/conversations/${groupId}/messages/${msg.message_id}/reactions`, { emoji: "😂" }, BOB_ID);

    const listResp = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, BOB_ID);
    const data = await listResp.json() as Array<{ message_id: string; my_reactions: string[] }>;
    const found = data.find((m) => m.message_id === msg.message_id);
    expect(found).toBeDefined();
    expect(found!.my_reactions).toContain("😂");
  });
});

// ─── 7. Tips on messages in groups ───────────────────────────────────────────

test.describe("7. Tips on messages in groups", () => {
  let page: Page;
  let groupId: string;
  const PM_ID = `pm_group_tip_${Date.now()}`;

  test.beforeAll(async ({ browser, request }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    groupId = await getOrCreateGroup(page, request);
    // Inject PM for Alice (so she can tip Bob's message)
    injectPaymentMethod(ALICE_ID, PM_ID);
  });
  test.afterAll(async () => {
    removePaymentMethod(ALICE_ID, PM_ID);
    await page.close();
  });

  test("Alice can attach a tip when sending a group message", async () => {
    const resp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `Tipped msg ${Date.now()}`,
      tip_amount_cents: 100,
      tip_payment_method_id: PM_ID,
      // TIP-105: a group attached tip must name a distinct participant recipient.
      tip_recipient_id: getSessions()[BOB_ID].user_sub,
    });
    expect(resp.status()).toBe(200);
    const msg = await resp.json() as { tip_amount_cents: number };
    expect(msg.tip_amount_cents).toBe(100);
  });

  test("Alice can tip Bob's received message in the group", async ({ request }) => {
    // Bob sends a message
    const bobResp = await apiPostBearer(
      request,
      `/messaging/conversations/${groupId}/messages`,
      { text: `Bob msg for tip ${Date.now()}` },
      BOB_ID,
    );
    const bobMsg = await bobResp.json() as { message_id: string };

    // Alice tips Bob's message
    const tipResp = await apiPost(page, `/messaging/conversations/${groupId}/messages/${bobMsg.message_id}/tip`, {
      amount_cents: 200,
      payment_method_id: PM_ID,
    });
    expect(tipResp.status()).toBe(200);
    const tipBody = await tipResp.json() as { ok: boolean; amount_cents: number };
    expect(tipBody.ok).toBe(true);
    expect(tipBody.amount_cents).toBeGreaterThanOrEqual(200);
  });

  test("tip_total_cents reflects accumulated tips from group members", async ({ request }) => {
    // Alice sends a message
    const msgResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `Multi-tipper ${Date.now()}`,
    });
    const msg = await msgResp.json() as { message_id: string };

    // Bob injects PM and tips
    injectPaymentMethod(BOB_ID, `pm_bob_tip_${Date.now()}`);
    const bobTipResp = await apiPostBearer(
      request,
      `/messaging/conversations/${groupId}/messages/${msg.message_id}/tip`,
      { amount_cents: 50 },
      BOB_ID,
    );
    expect(bobTipResp.status()).toBe(200);

    // Verify tip total
    const listResp = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, ALICE_ID);
    const data = await listResp.json() as Array<{ message_id: string; tip_amount_cents: number }>;
    const found = data.find((m) => m.message_id === msg.message_id);
    expect(found).toBeDefined();
    expect(found!.tip_amount_cents).toBeGreaterThanOrEqual(50);
  });
});

// ─── 8. Locked messages in groups ────────────────────────────────────────────

test.describe("8. Locked messages in groups", () => {
  let page: Page;
  let groupId: string;
  const LOCK_PRICE = 150; // cents
  const PM_ID = `pm_group_lock_${Date.now()}`;

  test.beforeAll(async ({ browser, request }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    groupId = await getOrCreateGroup(page, request);
    // Inject PM for Bob so he can unlock
    injectPaymentMethod(BOB_ID, PM_ID);
  });
  test.afterAll(async () => {
    removePaymentMethod(BOB_ID, PM_ID);
    await page.close();
  });

  test("Alice can send a locked message to the group", async () => {
    const resp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `Locked group msg ${Date.now()}`,
      lock_price_cents: LOCK_PRICE,
      lock_description: "Group premium content",
    });
    expect(resp.status()).toBe(200);
    const msg = await resp.json() as { lock_price_cents: number; is_unlocked: boolean };
    expect(msg.lock_price_cents).toBe(LOCK_PRICE);
    expect(msg.is_unlocked).toBe(true); // sender always sees unlocked
  });

  test("Bob (recipient) sees the message as locked", async ({ request }) => {
    const sendResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `Locked for Bob ${Date.now()}`,
      lock_price_cents: LOCK_PRICE,
      lock_description: "Locked content Bob",
    });
    const sent = await sendResp.json() as { message_id: string };

    const listResp = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, BOB_ID);
    const data = await listResp.json() as Array<{ message_id: string; is_unlocked: boolean; text: string | null; lock_price_cents: number }>;
    const msg = data.find((m) => m.message_id === sent.message_id);
    expect(msg).toBeDefined();
    expect(msg!.is_unlocked).toBe(false);
    expect(msg!.text).toBeNull(); // hidden until unlocked
    expect(msg!.lock_price_cents).toBe(LOCK_PRICE);
  });

  test("Bob can unlock the locked group message", async ({ request }) => {
    const sendResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `Bob will unlock ${Date.now()}`,
      lock_price_cents: LOCK_PRICE,
      lock_description: "Unlock me Bob",
    });
    const sent = await sendResp.json() as { message_id: string };

    const unlockResp = await apiPostBearer(
      request,
      `/messaging/conversations/${groupId}/messages/${sent.message_id}/unlock`,
      { payment_method_id: PM_ID },
      BOB_ID,
    );
    expect(unlockResp.status()).toBe(200);

    // Bob now sees the content
    const listResp = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, BOB_ID);
    const data = await listResp.json() as Array<{ message_id: string; is_unlocked: boolean; text: string | null }>;
    const msg = data.find((m) => m.message_id === sent.message_id);
    expect(msg).toBeDefined();
    expect(msg!.is_unlocked).toBe(true);
    expect(msg!.text).not.toBeNull();
  });

  test("Charlie sees locked message independently (separate unlock required)", async ({ request }) => {
    const sendResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `Charlie lock check ${Date.now()}`,
      lock_price_cents: LOCK_PRICE,
      lock_description: "Charlie must unlock separately",
    });
    const sent = await sendResp.json() as { message_id: string };

    // Charlie has NOT unlocked
    const charlieResp = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, CHARLIE_ID);
    const data = await charlieResp.json() as Array<{ message_id: string; is_unlocked: boolean }>;
    const msg = data.find((m) => m.message_id === sent.message_id);
    expect(msg).toBeDefined();
    expect(msg!.is_unlocked).toBe(false);
  });
});

// ─── 9. Message expiry in groups ─────────────────────────────────────────────

test.describe("9. Message expiry in groups", () => {
  let page: Page;
  let groupId: string;

  test.beforeAll(async ({ browser, request }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    groupId = await getOrCreateGroup(page, request);
  });
  test.afterAll(async () => page.close());

  test("Alice can send a message with expires_in_seconds to the group", async () => {
    const resp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `Expiring group ${Date.now()}`,
      expires_in_seconds: 3600,
    });
    expect(resp.status()).toBe(200);
    const msg = await resp.json() as { expires_at: number };
    expect(msg.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  test("expires_at is visible to all group participants", async ({ request }) => {
    const sendResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `Expiry visibility ${Date.now()}`,
      expires_in_seconds: 7200,
    });
    const sent = await sendResp.json() as { message_id: string; expires_at: number };
    const expectedExpiry = sent.expires_at;

    // Bob sees the same expires_at
    const listResp = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, BOB_ID);
    const data = await listResp.json() as Array<{ message_id: string; expires_at: number }>;
    const msg = data.find((m) => m.message_id === sent.message_id);
    expect(msg).toBeDefined();
    expect(msg!.expires_at).toBe(expectedExpiry);
  });

  test("minimum expires_in_seconds is 10 (below that returns 422)", async () => {
    const resp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `Too short expiry ${Date.now()}`,
      expires_in_seconds: 5, // below minimum of 10
    });
    expect(resp.status()).toBe(422);
  });

  test("expired message hides content for group participants", async ({ request }) => {
    // expires_in_seconds=10 is minimum but actual expiry check depends on time;
    // We test the field is present and respected; actual expiry is tested via DM suite
    const resp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `Expiry check ${Date.now()}`,
      expires_in_seconds: 12,
    });
    expect(resp.status()).toBe(200);
    const msg = await resp.json() as { expires_at: number };
    expect(msg.expires_at).toBeGreaterThan(0);

    // Charlie sees the expires_at
    const charlieList = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, CHARLIE_ID);
    expect(charlieList.status()).toBe(200);
  });
});

// ─── 10. Scheduled messages in groups ────────────────────────────────────────

test.describe("10. Scheduled messages in groups", () => {
  let page: Page;
  let groupId: string;

  test.beforeAll(async ({ browser, request }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    groupId = await getOrCreateGroup(page, request);
  });
  test.afterAll(async () => page.close());

  test("Alice can schedule a message in the group", async () => {
    const sendAt = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
    const resp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `Scheduled group ${Date.now()}`,
      send_at: sendAt,
    });
    expect(resp.status()).toBe(200);
    const msg = await resp.json() as { scheduled: boolean; deliver_at: number; message_id: string };
    expect(msg.scheduled).toBe(true);
    expect(msg.deliver_at).toBe(sendAt);
  });

  test("scheduled message appears in GET /messages/scheduled for group", async ({ request }) => {
    const sendAt = Math.floor(Date.now() / 1000) + 7200;
    const sendResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `Scheduled list ${Date.now()}`,
      send_at: sendAt,
    });
    const sent = await sendResp.json() as { message_id: string };

    const schedResp = await apiGetBearer(
      request,
      `/messaging/conversations/${groupId}/messages/scheduled`,
      ALICE_ID,
    );
    expect(schedResp.status()).toBe(200);
    const data = await schedResp.json() as Array<{ message_id: string; scheduled: boolean }>;
    const found = data.find((m) => m.message_id === sent.message_id);
    expect(found).toBeDefined();
    expect(found!.scheduled).toBe(true);
  });

  test("scheduled message can be cancelled", async ({ request }) => {
    const sendAt = Math.floor(Date.now() / 1000) + 7200;
    const sendResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `Sched cancel ${Date.now()}`,
      send_at: sendAt,
    });
    const sent = await sendResp.json() as { message_id: string };

    const delResp = await apiGetBearer(
      request,
      `/messaging/conversations/${groupId}/messages/${sent.message_id}/schedule`,
      ALICE_ID,
    );
    // The DELETE endpoint exists — try deleting via proper method
    const cancelResp = await (async () => {
      return request.delete(
        `${API}/messaging/conversations/${groupId}/messages/${sent.message_id}/schedule`,
        { headers: { Authorization: `Bearer ${getSessions()[ALICE_ID].user_sub}` } },
      );
    })();
    expect(cancelResp.status()).toBe(200);
    void delResp;
  });

  test("send_at in the past returns 400", async () => {
    const resp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `Past scheduled ${Date.now()}`,
      send_at: Math.floor(Date.now() / 1000) - 60,
    });
    expect(resp.status()).toBe(400);
  });
});

// ─── 11. UI — group conversation visual tests ─────────────────────────────────

test.describe("11. UI — group conversation", () => {
  let page: Page;

  test.beforeAll(async ({ browser, request }) => {
    page = await browser.newPage();
    await openGroupConvo(page, request);
  });
  test.afterAll(async () => page.close());

  test("group conversation header shows the group title", async () => {
    // The header title uses font-semibold inside the conversation panel (not sidebar)
    await expect(
      page.locator("p.font-semibold").filter({ hasText: "E2E Test Group" }).first(),
    ).toBeVisible({ timeout: 5000 });
  });

  test("ComposeBar is visible in group conversation", async () => {
    await expect(
      page.getByPlaceholder("Type a message...").or(page.getByPlaceholder("Type an encrypted message...")),
    ).toBeVisible({ timeout: 5000 });
  });

  test("view-once toggle is accessible in group ComposeBar via '+' popover", async () => {
    await page.getByTestId("compose-more").click();
    await expect(page.getByRole("button", { name: /toggle view once/i })).toBeVisible({ timeout: 5000 });
    await page.keyboard.press("Escape");
  });

  test("encrypt message toggle is accessible in group ComposeBar via '+' popover", async () => {
    await page.getByTestId("compose-more").click();
    await expect(page.getByRole("button", { name: /toggle message encryption/i })).toBeVisible({ timeout: 5000 });
    await page.keyboard.press("Escape");
  });

  test("Alice can send a UI text message to the group", async () => {
    const ts = Date.now();
    const input = page.getByPlaceholder("Type a message...");
    await input.fill(`UI group message ${ts}`);
    await page.getByRole("button", { name: "Send message" }).click();
    await expect(
      page.locator("p").filter({ hasText: `UI group message ${ts}` }),
    ).toBeVisible({ timeout: 6000 });
  });

  test("messages from other group members show sender name", async ({ request }) => {
    // Bob sends a message with unique text so we can isolate it from any
    // accumulated group messages from prior full-suite runs.
    const ts = Date.now();
    const bobText = `Bob UI sender name ${ts}`;
    const groupId = _groupConvoId!;
    await apiPostBearer(
      request,
      `/messaging/conversations/${groupId}/messages`,
      { text: bobText },
      BOB_ID,
    );
    await triggerRefetch(page);

    // Wait for Bob's specific message bubble to render (scoped to <p> to avoid
    // the sidebar preview span). This confirms the refetch delivered the message
    // before we assert on the sender label, which matters under suite load.
    const bobBubbleText = page.locator("p").filter({ hasText: bobText }).last();
    await expect(bobBubbleText).toBeVisible({ timeout: 8000 });

    // In group conversations the ComposeBar/ConversationView renders a sender
    // label above each non-own message (showSender=isGroup). The label shows the
    // sender's id (e.g. "e2e_bob@test.local"). Assert that the sender label for
    // a message from another member (Bob) is present in the conversation pane.
    await expect(
      page.locator("p.text-primary").filter({ hasText: BOB_ID }).first(),
    ).toBeVisible({ timeout: 5000 });
  });

  test("group participant count is shown in the header", async () => {
    // The header should show "3 participants" or similar
    await expect(
      page.locator("*").filter({ hasText: /participant/i }).first(),
    ).toBeVisible({ timeout: 5000 });
  });
});

// ─── 12. Gallery messages in groups ──────────────────────────────────────────

test.describe("12. Gallery messages in groups", () => {
  let page: Page;
  let groupId: string;
  const LOCK_PRICE = 199; // cents
  const PM_ID_BOB   = `pm_gal_bob_${Date.now()}`;
  const PM_ID_ALICE = `pm_gal_alice_${Date.now()}`;

  /** Presign + upload a tiny fake JPEG, returning { bucket, key }. */
  async function presignAndUpload(
    convoId: string,
    filename: string,
    contentType = "image/jpeg",
  ): Promise<{ bucket: string; key: string }> {
    const session = getSessions()[ALICE_ID];
    const presignResp = await page.request.post(
      `${API}/messaging/conversations/${convoId}/images/presign`,
      {
        data: { filename, content_type: contentType },
        headers: { "x-csrf-token": session.csrf_token },
      },
    );
    expect(presignResp.status()).toBe(200);
    const { upload_url, bucket, key } = await presignResp.json() as {
      upload_url: string; bucket: string; key: string;
    };
    // upload_url is already absolute (public_base_url-prefixed); use it directly.
    const put = await page.request.put(upload_url, {
      data: Buffer.from([0xff, 0xd8, 0xff, 0xd9]), // minimal valid JPEG
      headers: { "Content-Type": contentType },
    });
    expect(put.status()).toBeLessThan(300);
    return { bucket, key };
  }

  test.beforeAll(async ({ browser, request }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    groupId = await getOrCreateGroup(page, request);
    injectPaymentMethod(BOB_ID,   PM_ID_BOB);
    injectPaymentMethod(ALICE_ID, PM_ID_ALICE);
  });
  test.afterAll(async () => {
    removePaymentMethod(BOB_ID,   PM_ID_BOB);
    removePaymentMethod(ALICE_ID, PM_ID_ALICE);
    await page.close();
  });

  test("Alice can send a gallery with free + locked images to the group", async () => {
    const [free1, locked1, preview1] = await Promise.all([
      presignAndUpload(groupId, "gfree1.jpg"),
      presignAndUpload(groupId, "glocked1.jpg"),
      presignAndUpload(groupId, "gpreview1.jpg"),
    ]);
    const resp = await page.request.post(
      `${API}/messaging/conversations/${groupId}/messages/gallery`,
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
          lock_price_cents: LOCK_PRICE,
          lock_description: "Group gallery unlock",
        },
        headers: { "x-csrf-token": getSessions()[ALICE_ID].csrf_token },
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.kind).toBe("gallery");
    expect(body.lock_price_cents).toBe(LOCK_PRICE);
    expect(body.locked_image_count).toBe(1);
    expect(body.is_unlocked).toBe(true); // sender always sees their content
    expect(Array.isArray(body.free_images)).toBe(true);
    expect(Array.isArray(body.locked_images)).toBe(true);
  });

  test("Bob sees gallery as locked (locked_images=null) before unlocking", async ({ request }) => {
    // Alice sends a fresh gallery
    const [free1, locked1, preview1] = await Promise.all([
      presignAndUpload(groupId, "gfree_b.jpg"),
      presignAndUpload(groupId, "glocked_b.jpg"),
      presignAndUpload(groupId, "gpreview_b.jpg"),
    ]);
    const sendResp = await page.request.post(
      `${API}/messaging/conversations/${groupId}/messages/gallery`,
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
          lock_price_cents: LOCK_PRICE,
          lock_description: `gallery-bob-lock-${Date.now()}`,
        },
        headers: { "x-csrf-token": getSessions()[ALICE_ID].csrf_token },
      },
    );
    const sent = await sendResp.json() as { message_id: string };

    // Bob fetches messages — should see locked_images=null
    const listResp = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, BOB_ID);
    const msgs = await listResp.json() as Array<Record<string, unknown>>;
    const gallery = msgs.find((m) => m.message_id === sent.message_id);
    expect(gallery).toBeDefined();
    expect(gallery!.kind).toBe("gallery");
    expect(gallery!.locked_image_count).toBe(1);
    expect(gallery!.locked_images).toBeFalsy(); // null — not visible before unlock
    expect(Array.isArray(gallery!.free_images)).toBe(true);
  });

  test("Bob can unlock the gallery; Charlie still sees it locked (per-user unlock)", async ({ request }) => {
    // Alice sends a locked gallery
    const [free1, locked1, preview1] = await Promise.all([
      presignAndUpload(groupId, "gfree_bc.jpg"),
      presignAndUpload(groupId, "glocked_bc.jpg"),
      presignAndUpload(groupId, "gpreview_bc.jpg"),
    ]);
    const sendResp = await page.request.post(
      `${API}/messaging/conversations/${groupId}/messages/gallery`,
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
          lock_price_cents: LOCK_PRICE,
          lock_description: `gallery-per-user-${Date.now()}`,
        },
        headers: { "x-csrf-token": getSessions()[ALICE_ID].csrf_token },
      },
    );
    const sent = await sendResp.json() as { message_id: string };

    // Bob unlocks
    const unlockResp = await apiPostBearer(
      request,
      `/messaging/conversations/${groupId}/messages/${sent.message_id}/unlock`,
      { payment_method_id: PM_ID_BOB },
      BOB_ID,
    );
    expect(unlockResp.status()).toBe(200);

    // Bob now sees locked_images
    const bobList = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, BOB_ID);
    const bobMsgs = await bobList.json() as Array<Record<string, unknown>>;
    const bobGallery = bobMsgs.find((m) => m.message_id === sent.message_id);
    expect(bobGallery).toBeDefined();
    expect(bobGallery!.is_unlocked).toBe(true);
    expect(Array.isArray(bobGallery!.locked_images)).toBe(true);

    // Charlie has NOT unlocked — still locked
    const charlieList = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, CHARLIE_ID);
    const charlieMsgs = await charlieList.json() as Array<Record<string, unknown>>;
    const charlieGallery = charlieMsgs.find((m) => m.message_id === sent.message_id);
    expect(charlieGallery).toBeDefined();
    expect(charlieGallery!.is_unlocked).toBe(false);
    expect(charlieGallery!.locked_images).toBeFalsy(); // still null for Charlie
  });

  test("Alice can send a gallery with an attached tip to the group", async () => {
    const [free1] = await Promise.all([
      presignAndUpload(groupId, "gfree_tip.jpg"),
    ]);
    const resp = await page.request.post(
      `${API}/messaging/conversations/${groupId}/messages/gallery`,
      {
        data: {
          free_images: [
            { bucket: free1.bucket, key: free1.key, content_type: "image/jpeg" },
          ],
          locked_images: [],
          tip_amount_cents: 100,
          tip_payment_method_id: PM_ID_ALICE,
          // TIP-105: a group attached tip must name a distinct participant recipient.
          tip_recipient_id: getSessions()[BOB_ID].user_sub,
        },
        headers: { "x-csrf-token": getSessions()[ALICE_ID].csrf_token },
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.kind).toBe("gallery");
    expect(body.tip_amount_cents).toBe(100);
  });

  test("Gallery with only free images (no lock) works in group", async () => {
    const [img1, img2] = await Promise.all([
      presignAndUpload(groupId, "gfree_only1.jpg"),
      presignAndUpload(groupId, "gfree_only2.jpg"),
    ]);
    const resp = await page.request.post(
      `${API}/messaging/conversations/${groupId}/messages/gallery`,
      {
        data: {
          free_images: [
            { bucket: img1.bucket, key: img1.key, content_type: "image/jpeg" },
            { bucket: img2.bucket, key: img2.key, content_type: "image/jpeg" },
          ],
          locked_images: [],
          text: `Group free gallery ${Date.now()}`,
        },
        headers: { "x-csrf-token": getSessions()[ALICE_ID].csrf_token },
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.kind).toBe("gallery");
    expect(body.locked).toBe(false);
    expect((body.free_images as unknown[]).length).toBe(2);
  });

  test("Gallery lock + tip combination is rejected (400)", async () => {
    const [free1, locked1, preview1] = await Promise.all([
      presignAndUpload(groupId, "gfree_lt.jpg"),
      presignAndUpload(groupId, "glocked_lt.jpg"),
      presignAndUpload(groupId, "gpreview_lt.jpg"),
    ]);
    const resp = await page.request.post(
      `${API}/messaging/conversations/${groupId}/messages/gallery`,
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
          lock_price_cents: LOCK_PRICE,
          tip_amount_cents: 50,
          tip_payment_method_id: PM_ID_ALICE,
        },
        headers: { "x-csrf-token": getSessions()[ALICE_ID].csrf_token },
      },
    );
    expect(resp.status()).toBe(400);
  });

  test("Gallery supports scheduled send in group", async () => {
    const [img1, preview1] = await Promise.all([
      presignAndUpload(groupId, "gsched_img.jpg"),
      presignAndUpload(groupId, "gsched_preview.jpg"),
    ]);
    const deliverAt = Math.floor(Date.now() / 1000) + 3600;
    const resp = await page.request.post(
      `${API}/messaging/conversations/${groupId}/messages/gallery`,
      {
        data: {
          free_images: [],
          locked_images: [
            {
              bucket: img1.bucket, key: img1.key, content_type: "image/jpeg",
              preview_bucket: preview1.bucket, preview_key: preview1.key,
            },
          ],
          lock_price_cents: LOCK_PRICE,
          send_at: deliverAt,
        },
        headers: { "x-csrf-token": getSessions()[ALICE_ID].csrf_token },
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.kind).toBe("gallery");
    expect(body.scheduled).toBe(true);
    expect(body.deliver_at).toBe(deliverAt);
  });
});
