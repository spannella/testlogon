import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

/* ------------------------------------------------------------------ */
/*  Constants & helpers                                                */
/* ------------------------------------------------------------------ */

const API = "http://localhost:8000";
const TS = Date.now();
const PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";

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
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
}

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body: object,
) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiDelete(page: Page, identity: string, path: string) {
  const s = getSessions()[identity];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": s.csrf_token },
  });
}

function injectPaymentMethod(userSub: string, pmId: string): void {
  execSync(
    `${PYTHON} -c "
${DDB_HELPER_PRELUDE.trim()}
import time
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

function setExpiresAtToPast(sessionId: string, messageId: string): void {
  execSync(
    `${PYTHON} -c "
${DDB_HELPER_PRELUDE.trim()}
from boto3.dynamodb.conditions import Key, Attr
tbl = ddb.Table('BroadcastChatMessages')
resp = tbl.query(
    KeyConditionExpression=Key('session_id').eq('${sessionId}'),
    FilterExpression=Attr('message_id').eq('${messageId}'),
    Limit=200,
    ScanIndexForward=False,
)
items = resp.get('Items', [])
if not items:
    raise Exception('Message not found: ${messageId}')
sk = items[0]['sort_key']
tbl.update_item(
    Key={'session_id': '${sessionId}', 'sort_key': sk},
    UpdateExpression='SET expires_at = :ea',
    ExpressionAttributeValues={':ea': 1},
)
print('done')
"`,
    { timeout: 10_000 },
  );
}

function resetRichRateLimits(): void {
  execSync(
    `${PYTHON} -c "
import sys; sys.path.insert(0, '/home/ubuntu/testlogon')
from app.services.broadcast_chat_rich import reset_rich_rate_limits
reset_rich_rate_limits()
print('reset')
"`,
    { timeout: 10_000 },
  );
}

/* ------------------------------------------------------------------ */
/*  Shared state: create a live broadcast session for rich chat tests  */
/* ------------------------------------------------------------------ */

let liveSessionId: string;

async function ensureLiveSession(page: Page): Promise<string> {
  if (liveSessionId) return liveSessionId;

  // Create a profile + session + start it
  const profResp = await apiPost(page, "root", "/broadcast/profiles", {
    name: `Rich Chat Profile ${TS}`,
    region: "us-east-1",
    rendition_preset: "720p30",
  });
  const profBody = await profResp.json();

  const sessResp = await apiPost(page, "root", "/broadcast/sessions", {
    profile_id: profBody.id,
  });
  const sessBody = await sessResp.json();
  liveSessionId = sessBody.id;

  await apiPost(
    page,
    "root",
    `/broadcast/sessions/${liveSessionId}/start`,
    { reason: "e2e-rich-chat-test" },
  );

  return liveSessionId;
}

/* ------------------------------------------------------------------ */
/*  Section 138 — Chat Reactions API                                  */
/* ------------------------------------------------------------------ */

test.describe("Section 138 — Broadcast Chat Reactions", () => {
  let page: Page;
  let msgId: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, "root");

    await ensureLiveSession(page);

    // Wait for rate limit to clear
    await new Promise((r) => setTimeout(r, 2200));

    // Send a message to react to
    const msgResp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat`,
      { text: `React target ${TS}` },
    );
    expect(msgResp.status()).toBe(201);
    const msgBody = await msgResp.json();
    msgId = msgBody.message_id;
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("138.1 Viewer adds a reaction to a chat message", async () => {
    const resp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat/${msgId}/react`,
      { emoji: "\u{1F525}", action: "add" },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.reactions_counts["\u{1F525}"]).toBe(1);
  });

  test("138.2 Multiple reactions — different emoji", async () => {
    await new Promise((r) => setTimeout(r, 600));

    const resp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat/${msgId}/react`,
      { emoji: "\u{1F44D}", action: "add" },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.reactions_counts["\u{1F44D}"]).toBe(1);
    expect(body.reactions_counts["\u{1F525}"]).toBe(1);
  });

  test("138.3 Remove a reaction — count decrements", async () => {
    await new Promise((r) => setTimeout(r, 600));

    const resp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat/${msgId}/react`,
      { emoji: "\u{1F525}", action: "remove" },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const fireCount = body.reactions_counts["\u{1F525}"] || 0;
    expect(fireCount).toBe(0);
  });

  test("138.4 Invalid emoji rejected with 400", async () => {
    await new Promise((r) => setTimeout(r, 600));

    const resp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat/${msgId}/react`,
      { emoji: "\u{1F355}", action: "add" },
    );
    expect(resp.status()).toBe(400);
  });

  test("138.5 Reaction rate limit enforced", async () => {
    // First react
    const r1 = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat/${msgId}/react`,
      { emoji: "\u{1F602}", action: "add" },
    );
    expect(r1.status()).toBe(200);

    // Immediate second react — should be rate limited
    const r2 = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat/${msgId}/react`,
      { emoji: "\u{1F62E}", action: "add" },
    );
    expect(r2.status()).toBe(429);
  });

  test("138.6 Reactions appear in chat history", async () => {
    const resp = await apiGet(
      page,
      `/broadcast/sessions/${liveSessionId}/chat?limit=100`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();

    const target = body.messages.find(
      (m: { message_id: string }) => m.message_id === msgId,
    );
    expect(target).toBeTruthy();
    expect(target.reactions_counts).toBeTruthy();
    expect(target.reactions_counts["\u{1F44D}"]).toBeGreaterThanOrEqual(1);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 139 — Chat Replies API                                    */
/* ------------------------------------------------------------------ */

test.describe("Section 139 — Broadcast Chat Replies", () => {
  let page: Page;
  let parentMsgId: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, "root");

    await ensureLiveSession(page);

    // Wait for rate limit
    await new Promise((r) => setTimeout(r, 2200));

    // Send a parent message
    const resp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat`,
      { text: `Parent message for reply ${TS}` },
    );
    expect(resp.status()).toBe(201);
    parentMsgId = (await resp.json()).message_id;
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("139.1 Reply stores reply_to_message_id and preview", async () => {
    await new Promise((r) => setTimeout(r, 2200));

    const resp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat`,
      {
        text: `Reply to parent ${TS}`,
        reply_to_message_id: parentMsgId,
      },
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.reply_to_message_id).toBe(parentMsgId);
    expect(body.reply_to_preview).toBeTruthy();
    expect(body.reply_to_preview.text).toContain("Parent message for reply");
  });

  test("139.2 Reply preview truncates long parent text to 100 chars", async () => {
    await new Promise((r) => setTimeout(r, 2200));

    // Send a long parent
    const longText = "A".repeat(280);
    const longParent = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat`,
      { text: longText },
    );
    expect(longParent.status()).toBe(201);
    const longParentId = (await longParent.json()).message_id;

    await new Promise((r) => setTimeout(r, 2200));

    const resp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat`,
      {
        text: `Reply to long ${TS}`,
        reply_to_message_id: longParentId,
      },
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.reply_to_preview.text.length).toBeLessThanOrEqual(100);
  });

  test("139.3 Reply to nonexistent message returns 400", async () => {
    await new Promise((r) => setTimeout(r, 2200));

    const resp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat`,
      {
        text: `Reply to nothing ${TS}`,
        reply_to_message_id: "cm_nonexistent12345",
      },
    );
    expect(resp.status()).toBe(400);
  });

  test("139.4 Reply to deleted message returns 400", async () => {
    await new Promise((r) => setTimeout(r, 2200));

    // Send + delete a message
    const sendResp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat`,
      { text: `Will delete ${TS}` },
    );
    expect(sendResp.status()).toBe(201);
    const deletedMsgId = (await sendResp.json()).message_id;

    const delResp = await apiDelete(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat/${deletedMsgId}`,
    );
    expect(delResp.status()).toBe(200);

    await new Promise((r) => setTimeout(r, 2200));

    const resp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat`,
      {
        text: `Reply to deleted ${TS}`,
        reply_to_message_id: deletedMsgId,
      },
    );
    expect(resp.status()).toBe(400);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 140 — Expiring Messages API                               */
/* ------------------------------------------------------------------ */

test.describe("Section 140 — Broadcast Chat Expiring Messages", () => {
  let page: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, "root");

    await ensureLiveSession(page);

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");
  });

  test.afterAll(async () => {
    await page.context().close();
    await alicePage.context().close();
  });

  test("140.1 Broadcaster sends expiring message with expires_at", async () => {
    await new Promise((r) => setTimeout(r, 2200));

    const resp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat`,
      {
        text: `Expiring msg ${TS}`,
        expires_in_seconds: 120,
      },
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(body.text).toBe(`Expiring msg ${TS}`);
  });

  test("140.2 Expired message text is redacted in chat history", async () => {
    await new Promise((r) => setTimeout(r, 2200));

    // Send with expiry
    const sendResp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat`,
      {
        text: `Will expire ${TS}`,
        expires_in_seconds: 3600,
      },
    );
    expect(sendResp.status()).toBe(201);
    const sendBody = await sendResp.json();
    const msgId = sendBody.message_id;

    // Set expires_at to past via DDB directly
    setExpiresAtToPast(liveSessionId, msgId);

    // Fetch history as alice (non-sender) to see redacted text
    const histResp = await apiGet(
      alicePage,
      `/broadcast/sessions/${liveSessionId}/chat?limit=200`,
    );
    expect(histResp.status()).toBe(200);
    const histBody = await histResp.json();

    const expired = histBody.messages.find(
      (m: { message_id: string }) => m.message_id === msgId,
    );
    expect(expired).toBeTruthy();
    expect(expired.expired).toBe(true);
    expect(expired.text).toBeNull();
  });

  test("140.3 Non-broadcaster cannot send expiring messages", async () => {
    await new Promise((r) => setTimeout(r, 2200));

    const resp = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${liveSessionId}/chat`,
      {
        text: `Alice expiring ${TS}`,
        expires_in_seconds: 60,
      },
    );
    expect(resp.status()).toBe(403);
  });

  test("140.4 Sender still sees own expired message text", async () => {
    // Fetch history as root (the sender/broadcaster)
    const histResp = await apiGet(
      page,
      `/broadcast/sessions/${liveSessionId}/chat?limit=200`,
    );
    expect(histResp.status()).toBe(200);
    const histBody = await histResp.json();

    // Find messages with expires_at in the past sent by root
    const rootSub = getSessions().root.user_sub;
    const nowTs = Math.floor(Date.now() / 1000);
    const expiredMsgs = histBody.messages.filter(
      (m: { expires_at?: number; sender_id: string }) =>
        m.expires_at && m.expires_at < nowTs &&
        m.sender_id === rootSub,
    );
    // Sender should see their own text even when expired for others
    for (const m of expiredMsgs) {
      expect(m.expired).toBeFalsy();
      expect(m.text).not.toBeNull();
    }
  });
});

/* ------------------------------------------------------------------ */
/*  Section 141 — Locked Messages API                                 */
/* ------------------------------------------------------------------ */

test.describe("Section 141 — Broadcast Chat Locked Messages", () => {
  let page: Page;
  let alicePage: Page;
  let lockedMsgId: string;
  const ALICE_PM = `pm_rich_${TS}`;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, "root");

    await ensureLiveSession(page);

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    // Inject payment method for Alice
    const aliceSub = getSessions().alice.user_sub;
    injectPaymentMethod(aliceSub, ALICE_PM);

    await new Promise((r) => setTimeout(r, 2200));

    // Broadcaster sends a locked message
    const resp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat`,
      {
        text: `SECRET_CODE_${TS}`,
        lock_price_cents: 500,
        lock_description: "Unlock for the secret code",
      },
    );
    expect(resp.status()).toBe(201);
    lockedMsgId = (await resp.json()).message_id;
  });

  test.afterAll(async () => {
    await page.context().close();
    await alicePage.context().close();
  });

  test("141.1 Viewer sees locked message with text=null", async () => {
    const histResp = await apiGet(
      alicePage,
      `/broadcast/sessions/${liveSessionId}/chat?limit=200`,
    );
    expect(histResp.status()).toBe(200);
    const body = await histResp.json();

    const locked = body.messages.find(
      (m: { message_id: string }) => m.message_id === lockedMsgId,
    );
    expect(locked).toBeTruthy();
    expect(locked.text).toBeNull();
    expect(locked.is_unlocked).toBe(false);
    expect(locked.lock_price_cents).toBe(500);
    expect(locked.lock_description).toBe("Unlock for the secret code");
  });

  test("141.2 Broadcaster sees own locked message text", async () => {
    const histResp = await apiGet(
      page,
      `/broadcast/sessions/${liveSessionId}/chat?limit=200`,
    );
    expect(histResp.status()).toBe(200);
    const body = await histResp.json();

    const locked = body.messages.find(
      (m: { message_id: string }) => m.message_id === lockedMsgId,
    );
    expect(locked).toBeTruthy();
    expect(locked.text).toContain("SECRET_CODE_");
    expect(locked.is_unlocked).toBe(true);
  });

  test("141.3 Viewer unlocks message with valid PM", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${liveSessionId}/chat/${lockedMsgId}/unlock`,
      { payment_method_id: ALICE_PM },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.text).toContain("SECRET_CODE_");
    expect(body.amount_cents).toBe(500);
    expect(body.unlock_payment_id).toMatch(/^bcunlock_/);
  });

  test("141.4 Double unlock returns 400", async () => {
    // Wait for unlock rate limit (2s) to clear after 141.3
    await new Promise((r) => setTimeout(r, 2500));

    const resp = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${liveSessionId}/chat/${lockedMsgId}/unlock`,
      { payment_method_id: ALICE_PM },
    );
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail).toContain("Already unlocked");
  });

  test("141.5 Non-broadcaster cannot send locked messages", async () => {
    await new Promise((r) => setTimeout(r, 2200));

    const resp = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${liveSessionId}/chat`,
      {
        text: `Alice locked ${TS}`,
        lock_price_cents: 100,
      },
    );
    expect(resp.status()).toBe(403);
  });

  test("141.6 Unlock without valid PM returns 400", async () => {
    // Send another locked message
    await new Promise((r) => setTimeout(r, 2200));
    const sendResp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat`,
      {
        text: `Another locked ${TS}`,
        lock_price_cents: 200,
      },
    );
    expect(sendResp.status()).toBe(201);
    const newLockedId = (await sendResp.json()).message_id;

    const resp = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${liveSessionId}/chat/${newLockedId}/unlock`,
      { payment_method_id: "pm_nonexistent_999" },
    );
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail).toContain("Payment method not found");
  });
});
