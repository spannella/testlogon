/**
 * E2E tests for Chat Delegation (DELEGATE-002).
 *
 * Sections:
 *   491 — Chat Read Delegation API         (4 tests)
 *   492 — Chat Respond Delegation API      (4 tests)
 *   493 — Chat Delegate Audit API          (3 tests)
 *   494 — Chat Delegation Edge Cases       (4 tests)
 *
 * Auth: Alice (creator), Bob (delegate with chat_read + chat_respond),
 *        Charlie (delegate with feed_read only — no chat perms).
 *
 * Uses cookie-based auth with CSRF headers on all mutating requests.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";

// Session keys (how they are keyed in the session JSON)
const ALICE_KEY = "alice";
const BOB_KEY = "bob";
const CHARLIE_KEY = "charlie_admin";

// User subs (used for API endpoint paths and delegate IDs)
const ALICE_SUB = "e2e_alice@test.local";
const BOB_SUB = "e2e_bob@test.local";
const CHARLIE_SUB = "e2e_charlie@test.local";

const TS = Date.now();

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
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, sessionKey: string) {
  const session = getSessions()[sessionKey];
  if (!session) throw new Error(`No session for key=${sessionKey}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, sessionKey: string, path: string, body: object) {
  const session = getSessions()[sessionKey];
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

async function apiPut(page: Page, sessionKey: string, path: string, body: object) {
  const session = getSessions()[sessionKey];
  return page.request.put(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiDelete(page: Page, sessionKey: string, path: string) {
  const session = getSessions()[sessionKey];
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── Cleanup helper ──────────────────────────────────────────────────────────

async function cleanupDelegates(page: Page, sessionKey: string) {
  const resp = await apiGet(page, "/ui/delegates");
  if (resp.ok()) {
    const delegates = await resp.json();
    for (const d of delegates) {
      try {
        await apiDelete(page, sessionKey, `/ui/delegates/${d.delegate_id}`);
      } catch {
        /* best-effort */
      }
    }
  }
}

/** Add delegate, tolerating 409 (already exists) by revoking and re-adding. */
async function addDelegateSafe(
  page: Page,
  sessionKey: string,
  delegateId: string,
  permissions: string[],
  extra?: { preset?: string; label?: string },
) {
  let resp = await apiPost(page, sessionKey, "/ui/delegates", {
    delegate_id: delegateId,
    permissions,
    ...extra,
  });
  if (resp.status() === 409) {
    // Already exists — revoke and re-add
    await apiDelete(page, sessionKey, `/ui/delegates/${delegateId}`);
    resp = await apiPost(page, sessionKey, "/ui/delegates", {
      delegate_id: delegateId,
      permissions,
      ...extra,
    });
  }
  return resp;
}

// ─── Shared state ────────────────────────────────────────────────────────────

let _aliceBobDmId: string | null = null;

async function ensureAliceBobDm(alicePage: Page): Promise<string> {
  if (_aliceBobDmId) return _aliceBobDmId;
  const resp = await apiPost(alicePage, ALICE_KEY, "/messaging/conversations", {
    participant_ids: [BOB_SUB],
    type: "dm",
  });
  if (!resp.ok()) {
    throw new Error(`DM creation failed: ${resp.status()}`);
  }
  const body = await resp.json();
  _aliceBobDmId = body.conversation_id as string;
  return _aliceBobDmId;
}

// ─── Section 491: Chat Read Delegation API ──────────────────────────────────

test.describe("491 — Chat Read Delegation API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let charliePage: Page;
  let dmConvoId: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_KEY);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_KEY);

    const charlieCtx = await browser.newContext();
    charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, CHARLIE_KEY);

    // Setup: configure Alice's delegate settings (no acceptance required)
    await apiPut(alicePage, ALICE_KEY, "/ui/delegates/settings", {
      require_acceptance: false,
      max_delegates: 10,
      delegate_tag_enabled: true,
      delegate_tag_format: "[via @{delegate_name}]",
    });

    // Cleanup existing delegates
    await cleanupDelegates(alicePage, ALICE_KEY);

    // Add Bob as delegate with chat_read + chat_respond
    const addBob = await addDelegateSafe(alicePage, ALICE_KEY, BOB_SUB,
      ["chat_read", "chat_respond"], { preset: "chat_agent", label: "Bob - Chat Agent" });
    expect(addBob.ok()).toBeTruthy();

    // Add Charlie as delegate with feed_read only (no chat perms)
    const addCharlie = await addDelegateSafe(alicePage, ALICE_KEY, CHARLIE_SUB,
      ["feed_read"], { label: "Charlie - Reader" });
    expect(addCharlie.ok()).toBeTruthy();

    // Create DM between Alice and Bob, and send a test message
    dmConvoId = await ensureAliceBobDm(alicePage);

    // Alice sends a normal message
    await apiPost(alicePage, ALICE_KEY, `/messaging/conversations/${dmConvoId}/messages`, {
      text: `Hello from Alice ${TS}`,
    });
  });

  test.afterAll(async () => {
    await cleanupDelegates(alicePage, ALICE_KEY);
    await alicePage.context().close();
    await bobPage.context().close();
    await charliePage.context().close();
  });

  test("491.1 Delegate lists creator's conversations", async () => {
    const resp = await apiGet(
      bobPage,
      `/messaging/delegate/${ALICE_SUB}/conversations`,
    );
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(Array.isArray(data)).toBeTruthy();
    expect(data.length).toBeGreaterThanOrEqual(1);

    // Should contain the DM with Bob
    const dm = data.find((c: any) => c.conversation_id === dmConvoId);
    expect(dm).toBeTruthy();
    expect(dm.type).toBe("dm");
  });

  test("491.2 Delegate reads messages in creator's conversation", async () => {
    const resp = await apiGet(
      bobPage,
      `/messaging/delegate/${ALICE_SUB}/conversations/${dmConvoId}/messages`,
    );
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(Array.isArray(data)).toBeTruthy();
    expect(data.length).toBeGreaterThanOrEqual(1);

    // Should find Alice's message
    const aliceMsg = data.find((m: any) =>
      m.text?.includes(`Hello from Alice ${TS}`),
    );
    expect(aliceMsg).toBeTruthy();
    expect(aliceMsg.sender_id).toBe(ALICE_SUB);
  });

  test("491.3 Delegate without chat_read gets 403", async () => {
    // Charlie has feed_read only, no chat permissions
    const resp = await apiGet(
      charliePage,
      `/messaging/delegate/${ALICE_SUB}/conversations`,
    );
    expect(resp.status()).toBe(403);
  });

  test("491.4 Encrypted messages redacted for delegate", async () => {
    // Write an encrypted message directly to DDB to ensure it exists
    // regardless of whether the encryption API endpoint is enabled
    const msgId = `m_enc_${TS}`;
    execSync(
      `python3 -c "
import boto3, os, json
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
tbl = ddb.Table('Messages')
import time
tbl.put_item(Item={
    'conversation_id': '${dmConvoId}',
    'message_id': '${msgId}',
    'sender_id': '${ALICE_SUB}',
    'created_at': int(time.time()),
    'kind': 'text',
    'text': None,
    'is_encrypted': True,
    'encryption': {
        'version': 1,
        'alg': 'AES-256-GCM',
        'kdf': 'PBKDF2-SHA256',
        'iterations': 600000,
        'salt_b64': 'AAAAAAAAAAAAAAAAAAAAAA==',
        'iv_b64': 'AAAAAAAAAAAAAAAA',
        'ciphertext_b64': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    },
    'reactions': {},
})
print('encrypted message seeded')
"`,
      { timeout: 10_000 },
    );

    // Bob reads via delegate endpoint — encrypted msg should be redacted
    const resp = await apiGet(
      bobPage,
      `/messaging/delegate/${ALICE_SUB}/conversations/${dmConvoId}/messages`,
    );
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();

    // Find the encrypted message
    const encMsg = data.find((m: any) => m.delegate_cannot_decrypt === true);
    expect(encMsg).toBeTruthy();
    expect(encMsg.text).toBeNull();
  });
});

// ─── Section 492: Chat Respond Delegation API ───────────────────────────────

test.describe("492 — Chat Respond Delegation API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let charliePage: Page;
  let dmConvoId: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_KEY);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_KEY);

    const charlieCtx = await browser.newContext();
    charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, CHARLIE_KEY);

    // Setup delegates
    await apiPut(alicePage, ALICE_KEY, "/ui/delegates/settings", {
      require_acceptance: false,
      max_delegates: 10,
      delegate_tag_enabled: true,
      delegate_tag_format: "[via @{delegate_name}]",
    });
    await cleanupDelegates(alicePage, ALICE_KEY);

    await addDelegateSafe(alicePage, ALICE_KEY, BOB_SUB, ["chat_read", "chat_respond"]);

    // Charlie: chat_read only (no chat_respond)
    await addDelegateSafe(alicePage, ALICE_KEY, CHARLIE_SUB, ["chat_read"]);

    dmConvoId = await ensureAliceBobDm(alicePage);
  });

  test.afterAll(async () => {
    await cleanupDelegates(alicePage, ALICE_KEY);
    await alicePage.context().close();
    await bobPage.context().close();
    await charliePage.context().close();
  });

  test("492.1 Delegate sends message as creator", async () => {
    const msgText = `Delegated msg ${TS}`;
    const resp = await apiPost(
      bobPage,
      BOB_KEY,
      `/messaging/delegate/${ALICE_SUB}/conversations/${dmConvoId}/messages`,
      { text: msgText },
    );
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.sender_id).toBe(ALICE_SUB);
    expect(data.sent_by_delegate).toBe(BOB_SUB);
    expect(data.kind).toBe("text");
    // Text should contain the original text
    expect(data.text).toContain(msgText);
  });

  test("492.2 Delegate tag appended when enabled", async () => {
    const msgText = `Tagged msg ${TS}`;
    const resp = await apiPost(
      bobPage,
      BOB_KEY,
      `/messaging/delegate/${ALICE_SUB}/conversations/${dmConvoId}/messages`,
      { text: msgText },
    );
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    // Tag should be appended since delegate_tag_enabled=true
    expect(data.delegate_tag).toBeTruthy();
    expect(data.text).toContain("[via @");
  });

  test("492.3 Delegate tag omitted when disabled", async () => {
    // Update Alice's delegate settings to disable tag
    await apiPut(alicePage, ALICE_KEY, "/ui/delegates/settings", {
      require_acceptance: false,
      max_delegates: 10,
      delegate_tag_enabled: false,
      delegate_tag_format: "[via @{delegate_name}]",
    });

    // Re-add Bob with new settings (revoke + re-add to pick up show_delegate_tag=false)
    await apiDelete(alicePage, ALICE_KEY, `/ui/delegates/${BOB_SUB}`);
    await addDelegateSafe(alicePage, ALICE_KEY, BOB_SUB, ["chat_read", "chat_respond"]);

    const msgText = `Untagged msg ${TS}`;
    const resp = await apiPost(
      bobPage,
      BOB_KEY,
      `/messaging/delegate/${ALICE_SUB}/conversations/${dmConvoId}/messages`,
      { text: msgText },
    );
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    // Text should be exact (no tag appended) since show_delegate_tag=false
    expect(data.text).toBe(msgText);
    expect(data.delegate_tag).toBeNull();

    // Restore tag settings
    await apiPut(alicePage, ALICE_KEY, "/ui/delegates/settings", {
      require_acceptance: false,
      max_delegates: 10,
      delegate_tag_enabled: true,
      delegate_tag_format: "[via @{delegate_name}]",
    });
  });

  test("492.4 Delegate without chat_respond gets 403 on send", async () => {
    // Charlie has chat_read only
    const resp = await apiPost(
      charliePage,
      CHARLIE_KEY,
      `/messaging/delegate/${ALICE_SUB}/conversations/${dmConvoId}/messages`,
      { text: "Should fail" },
    );
    expect(resp.status()).toBe(403);
  });
});

// ─── Section 493: Chat Delegate Audit API ───────────────────────────────────

test.describe("493 — Chat Delegate Audit API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let dmConvoId: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_KEY);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_KEY);

    await apiPut(alicePage, ALICE_KEY, "/ui/delegates/settings", {
      require_acceptance: false,
      max_delegates: 10,
      delegate_tag_enabled: true,
      delegate_tag_format: "[via @{delegate_name}]",
    });
    await cleanupDelegates(alicePage, ALICE_KEY);

    await addDelegateSafe(alicePage, ALICE_KEY, BOB_SUB, ["chat_read", "chat_respond"]);

    dmConvoId = await ensureAliceBobDm(alicePage);

    // Bob sends a delegated message to create audit trail
    await apiPost(
      bobPage,
      BOB_KEY,
      `/messaging/delegate/${ALICE_SUB}/conversations/${dmConvoId}/messages`,
      { text: `Audit test msg ${TS}` },
    );
  });

  test.afterAll(async () => {
    await cleanupDelegates(alicePage, ALICE_KEY);
    await alicePage.context().close();
    await bobPage.context().close();
  });

  test("493.1 Creator sees delegated messages in audit", async () => {
    const resp = await apiGet(
      alicePage,
      `/messaging/delegate/${ALICE_SUB}/audit`,
    );
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(Array.isArray(data)).toBeTruthy();
    expect(data.length).toBeGreaterThanOrEqual(1);

    // Should find Bob's delegated message
    const bobEntry = data.find(
      (e: any) => e.delegate_id === BOB_SUB && e.text_preview.includes("Audit test msg"),
    );
    expect(bobEntry).toBeTruthy();
    expect(bobEntry.conversation_id).toBe(dmConvoId);
  });

  test("493.2 Audit filters by conversation", async () => {
    const resp = await apiGet(
      alicePage,
      `/messaging/delegate/${ALICE_SUB}/audit?conversation_id=${dmConvoId}`,
    );
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(Array.isArray(data)).toBeTruthy();
    // All entries should be from this conversation
    for (const entry of data) {
      expect(entry.conversation_id).toBe(dmConvoId);
    }
  });

  test("493.3 Delegate cannot access creator's audit endpoint", async () => {
    const resp = await apiGet(
      bobPage,
      `/messaging/delegate/${ALICE_SUB}/audit`,
    );
    expect(resp.status()).toBe(403);
  });
});

// ─── Section 494: Chat Delegation Edge Cases ────────────────────────────────

test.describe("494 — Chat Delegation Edge Cases", () => {
  let alicePage: Page;
  let bobPage: Page;
  let dmConvoId: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_KEY);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_KEY);

    await apiPut(alicePage, ALICE_KEY, "/ui/delegates/settings", {
      require_acceptance: false,
      max_delegates: 10,
      delegate_tag_enabled: true,
      delegate_tag_format: "[via @{delegate_name}]",
    });
    await cleanupDelegates(alicePage, ALICE_KEY);

    await addDelegateSafe(alicePage, ALICE_KEY, BOB_SUB, ["chat_read", "chat_respond"]);

    dmConvoId = await ensureAliceBobDm(alicePage);
  });

  test.afterAll(async () => {
    // Re-add Bob as delegate if revoked during tests
    try {
      await addDelegateSafe(alicePage, ALICE_KEY, BOB_SUB, ["chat_read", "chat_respond"]);
    } catch {
      /* ignore */
    }
    await cleanupDelegates(alicePage, ALICE_KEY);
    await alicePage.context().close();
    await bobPage.context().close();
  });

  test("494.1 Delegate sees new message sent by creator", async () => {
    // Alice sends a message directly
    const msgText = `Direct from creator ${TS}`;
    await apiPost(
      alicePage,
      ALICE_KEY,
      `/messaging/conversations/${dmConvoId}/messages`,
      { text: msgText },
    );

    // Bob should see it via delegate endpoint
    const resp = await apiGet(
      bobPage,
      `/messaging/delegate/${ALICE_SUB}/conversations/${dmConvoId}/messages`,
    );
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    const found = data.find((m: any) => m.text?.includes(msgText));
    expect(found).toBeTruthy();
    // This message was NOT sent by a delegate
    expect(found.sent_by_delegate).toBeFalsy();
  });

  test("494.2 Revoked delegate gets 403", async () => {
    // Alice revokes Bob's delegation
    const revokeResp = await apiDelete(
      alicePage,
      ALICE_KEY,
      `/ui/delegates/${BOB_SUB}`,
    );
    expect(revokeResp.ok()).toBeTruthy();

    // Bob tries to list conversations — should get 403
    const resp = await apiGet(
      bobPage,
      `/messaging/delegate/${ALICE_SUB}/conversations`,
    );
    expect(resp.status()).toBe(403);

    // Bob tries to send — should also get 403
    const sendResp = await apiPost(
      bobPage,
      BOB_KEY,
      `/messaging/delegate/${ALICE_SUB}/conversations/${dmConvoId}/messages`,
      { text: "Should fail" },
    );
    expect(sendResp.status()).toBe(403);

    // Restore delegation for remaining tests
    await addDelegateSafe(alicePage, ALICE_KEY, BOB_SUB, ["chat_read", "chat_respond"]);
  });

  test("494.3 Delegate cannot access non-existent conversation", async () => {
    const resp = await apiGet(
      bobPage,
      `/messaging/delegate/${ALICE_SUB}/conversations/nonexistent_conv_123/messages`,
    );
    expect(resp.status()).toBe(404);
  });

  test("494.4 Multiple delegated messages have correct attribution", async () => {
    // Send two messages via delegation
    const msg1 = `Multi-1 ${TS}`;
    const msg2 = `Multi-2 ${TS}`;

    const resp1 = await apiPost(
      bobPage,
      BOB_KEY,
      `/messaging/delegate/${ALICE_SUB}/conversations/${dmConvoId}/messages`,
      { text: msg1 },
    );
    expect(resp1.ok()).toBeTruthy();

    const resp2 = await apiPost(
      bobPage,
      BOB_KEY,
      `/messaging/delegate/${ALICE_SUB}/conversations/${dmConvoId}/messages`,
      { text: msg2 },
    );
    expect(resp2.ok()).toBeTruthy();

    // Read messages
    const listResp = await apiGet(
      bobPage,
      `/messaging/delegate/${ALICE_SUB}/conversations/${dmConvoId}/messages`,
    );
    expect(listResp.ok()).toBeTruthy();
    const messages = await listResp.json();

    // Both messages should show creator as sender and Bob as delegate
    const found1 = messages.find((m: any) => m.text?.includes(msg1));
    const found2 = messages.find((m: any) => m.text?.includes(msg2));

    expect(found1).toBeTruthy();
    expect(found1.sender_id).toBe(ALICE_SUB);
    expect(found1.sent_by_delegate).toBe(BOB_SUB);

    expect(found2).toBeTruthy();
    expect(found2.sender_id).toBe(ALICE_SUB);
    expect(found2.sent_by_delegate).toBe(BOB_SUB);
  });
});
