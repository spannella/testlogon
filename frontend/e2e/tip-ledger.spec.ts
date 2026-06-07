/**
 * E2E tests for MON-002: Tip Ledger Integration.
 *
 * Verifies that all four tipping surfaces (message attached, post-send message,
 * post tip, comment tip) write paired debit + credit ledger entries.
 *
 * Auth: cookie-based sessions via injectAuth().
 * DDB queries: via Python helper scripts (queryLedger).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

const PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";
const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();

// ─── Session bootstrap ──────────────────────────────────────────────────────

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
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ────────────────────────────────────────────────────────────

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

// ─── Authenticated API helpers ───────────────────────────────────────────────

async function apiPost(page: Page, userId: string, path: string, body: object) {
  const session = getSessions()[userId];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

// ─── Payment method helpers ──────────────────────────────────────────────────

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
    // best-effort
  }
}

// ─── Ledger query helper ─────────────────────────────────────────────────────

interface LedgerEntry {
  pk: string;
  sk: string;
  entry_id: string;
  ts: number;
  type: string;
  amount_cents: number | string;
  currency: string;
  state: string;
  reason: string;
  meta: Record<string, unknown>;
}

// FIN-018 / GAP-0214: tip credit entries are now NET of the admin-configured
// platform fee. The tipper is debited the full gross amount; the recipient is
// credited gross minus the platform fee. Each ledger entry records the applied
// fee under meta.platform_fee_cents, so the expected net is derived from the
// entry itself rather than hard-coding the fee BPS (which is runtime-configurable).
function expectedNet(gross: number, entry: LedgerEntry): number {
  const fee = Number((entry.meta?.platform_fee_cents as number | string | undefined) ?? 0);
  return gross - fee;
}

function queryLedger(userSub: string): LedgerEntry[] {
  const raw = execSync(
    `${PYTHON} -c "
import boto3, os, json
from pathlib import Path
from boto3.dynamodb.conditions import Key
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
resp = tbl.query(
    KeyConditionExpression=Key('pk').eq('USER#${userSub}') & Key('sk').begins_with('LEDGER#'),
)
print(json.dumps(resp['Items'], default=str))
"`,
    { timeout: 10_000 },
  ).toString().trim();
  return JSON.parse(raw) as LedgerEntry[];
}

// ═════════════════════════════════════════════════════════════════════════════
// 85. Tip Ledger -- Messages
// ═════════════════════════════════════════════════════════════════════════════

test.describe("85. Tip Ledger -- Messages", () => {
  let alicePage: Page;
  let bobPage: Page;
  let dmConvoId: string;
  const PM_ID = `pm_tl_msg_${TS}`;
  const ATTACH_TIP_TEXT = `tl-attach-${TS}`;
  const POST_SEND_TIP_TEXT = `tl-bob-msg-${TS}`;
  let attachedTipMsgId: string;
  let bobMsgId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);

    // Inject payment method for Alice
    injectPaymentMethod(ALICE_ID, PM_ID);

    // Create or get DM between Alice and Bob
    const dmResp = await apiPost(alicePage, ALICE_ID, "/messaging/conversations", {
      participant_ids: [getSessions()[BOB_ID].user_sub],
      type: "dm",
    });
    expect(dmResp.ok()).toBe(true);
    const dmBody = await dmResp.json() as { conversation_id: string };
    dmConvoId = dmBody.conversation_id;

    // Bob sends a message (for post-send tip test)
    const bobMsgResp = await apiPost(bobPage, BOB_ID,
      `/messaging/conversations/${dmConvoId}/messages`,
      { text: POST_SEND_TIP_TEXT },
    );
    expect(bobMsgResp.ok()).toBe(true);
    const bobMsgBody = await bobMsgResp.json() as { message_id: string };
    bobMsgId = bobMsgBody.message_id;
  });

  test.afterAll(async () => {
    removePaymentMethod(ALICE_ID, PM_ID);
    await alicePage.close();
    await bobPage.close();
  });

  test("Attached tip writes debit for sender and credit for recipient", async () => {
    // Alice sends message with attached tip
    const resp = await apiPost(alicePage, ALICE_ID,
      `/messaging/conversations/${dmConvoId}/messages`,
      { text: ATTACH_TIP_TEXT, tip_amount_cents: 100, tip_payment_method_id: PM_ID },
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json() as { message_id: string; tip_amount_cents: number };
    expect(body.tip_amount_cents).toBe(100);
    attachedTipMsgId = body.message_id;

    // Check Alice has debit
    const aliceLedger = queryLedger(ALICE_ID);
    const debit = aliceLedger.find(
      (e) => e.reason === "Tip: message" && e.type === "debit" &&
             e.meta?.content_id === attachedTipMsgId,
    );
    expect(debit).toBeDefined();
    expect(Number(debit!.amount_cents)).toBe(100);
    expect(debit!.meta.content_type).toBe("message");
    expect(debit!.meta.conversation_id).toBe(dmConvoId);

    // Check Bob has credit
    const bobLedger = queryLedger(BOB_ID);
    const credit = bobLedger.find(
      (e) => e.reason === "Tip: message" && e.type === "credit" &&
             e.meta?.content_id === attachedTipMsgId,
    );
    expect(credit).toBeDefined();
    expect(Number(credit!.amount_cents)).toBe(expectedNet(100, credit!));
    expect(credit!.meta.content_type).toBe("message");
  });

  test("Post-send tip writes paired ledger entries", async () => {
    // Alice tips Bob's message
    const resp = await apiPost(alicePage, ALICE_ID,
      `/messaging/conversations/${dmConvoId}/messages/${bobMsgId}/tip`,
      { amount_cents: 200, currency: "USD", payment_method_id: PM_ID },
    );
    expect(resp.ok()).toBe(true);
    const tipBody = await resp.json() as { tip_payment_id: string };
    expect(tipBody.tip_payment_id).toBeDefined();

    // Alice debit
    const aliceLedger = queryLedger(ALICE_ID);
    const debit = aliceLedger.find(
      (e) => e.reason === "Tip: message" && e.type === "debit" &&
             e.meta?.content_id === bobMsgId,
    );
    expect(debit).toBeDefined();
    expect(Number(debit!.amount_cents)).toBe(200);

    // Bob credit
    const bobLedger = queryLedger(BOB_ID);
    const credit = bobLedger.find(
      (e) => e.reason === "Tip: message" && e.type === "credit" &&
             e.meta?.content_id === bobMsgId,
    );
    expect(credit).toBeDefined();
    expect(Number(credit!.amount_cents)).toBe(expectedNet(200, credit!));
  });

  test("Tip without payment_method_id still writes ledger entries", async () => {
    // Alice sends message with attached tip, no PM
    const resp = await apiPost(alicePage, ALICE_ID,
      `/messaging/conversations/${dmConvoId}/messages`,
      { text: `tl-no-pm-${TS}`, tip_amount_cents: 50 },
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json() as { message_id: string };

    const aliceLedger = queryLedger(ALICE_ID);
    const debit = aliceLedger.find(
      (e) => e.reason === "Tip: message" && e.type === "debit" &&
             e.meta?.content_id === body.message_id,
    );
    expect(debit).toBeDefined();
    // No payment_method_id in meta
    expect(debit!.meta.payment_method_id).toBeUndefined();
  });

  test("Ledger entry meta contains conversation_id and content_type=message", async () => {
    const aliceLedger = queryLedger(ALICE_ID);
    const debit = aliceLedger.find(
      (e) => e.reason === "Tip: message" && e.type === "debit" &&
             e.meta?.content_id === attachedTipMsgId,
    );
    expect(debit).toBeDefined();
    expect(debit!.meta.conversation_id).toBe(dmConvoId);
    expect(debit!.meta.content_type).toBe("message");
    expect(debit!.meta.tipper_user_id).toBe(ALICE_ID);
    expect(debit!.meta.recipient_user_id).toBe(BOB_ID);
    expect(debit!.meta.tip_payment_id).toBeDefined();
  });

  test("Debit and credit entries have matching amount and currency", async () => {
    const aliceLedger = queryLedger(ALICE_ID);
    const bobLedger = queryLedger(BOB_ID);

    const debit = aliceLedger.find(
      (e) => e.reason === "Tip: message" && e.type === "debit" &&
             e.meta?.content_id === attachedTipMsgId,
    );
    const credit = bobLedger.find(
      (e) => e.reason === "Tip: message" && e.type === "credit" &&
             e.meta?.content_id === attachedTipMsgId,
    );
    expect(debit).toBeDefined();
    expect(credit).toBeDefined();
    // FIN-018: debit is gross; credit is net after the platform fee.
    expect(Number(credit!.amount_cents)).toBe(expectedNet(Number(debit!.amount_cents), credit!));
    expect(debit!.currency).toBe(credit!.currency);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 86. Tip Ledger -- Posts
// ═════════════════════════════════════════════════════════════════════════════

test.describe("86. Tip Ledger -- Posts", () => {
  let alicePage: Page;
  let bobPage: Page;
  let postId: string;
  const PM_ID = `pm_tl_post_${TS}`;
  const TIP_AMOUNT = 300;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);

    // Inject PM for Bob
    injectPaymentMethod(BOB_ID, PM_ID);

    // Alice creates a post
    const resp = await apiPost(alicePage, ALICE_ID, "/posts", {
      body: `Tip ledger test post ${TS}`,
    });
    expect(resp.ok()).toBe(true);
    const body = await resp.json() as { post_id: string };
    postId = body.post_id;
  });

  test.afterAll(async () => {
    removePaymentMethod(BOB_ID, PM_ID);
    await alicePage.close();
    await bobPage.close();
  });

  test("Post tip writes debit for tipper", async () => {
    const resp = await apiPost(bobPage, BOB_ID, `/posts/${postId}/tip`, {
      amount_cents: TIP_AMOUNT,
      currency: "usd",
      payment_method_id: PM_ID,
    });
    expect(resp.ok()).toBe(true);

    const bobLedger = queryLedger(BOB_ID);
    const debit = bobLedger.find(
      (e) => e.reason === "Tip: post" && e.type === "debit" &&
             e.meta?.content_id === postId,
    );
    expect(debit).toBeDefined();
    expect(Number(debit!.amount_cents)).toBe(TIP_AMOUNT);
  });

  test("Post tip writes credit for post author", async () => {
    const aliceLedger = queryLedger(ALICE_ID);
    const credit = aliceLedger.find(
      (e) => e.reason === "Tip: post" && e.type === "credit" &&
             e.meta?.content_id === postId,
    );
    expect(credit).toBeDefined();
    expect(Number(credit!.amount_cents)).toBe(expectedNet(TIP_AMOUNT, credit!));
  });

  test("Post tip ledger meta contains post_id and content_type=post", async () => {
    const bobLedger = queryLedger(BOB_ID);
    const debit = bobLedger.find(
      (e) => e.reason === "Tip: post" && e.type === "debit" &&
             e.meta?.content_id === postId,
    );
    expect(debit).toBeDefined();
    expect(debit!.meta.content_type).toBe("post");
    expect(debit!.meta.post_id).toBe(postId);
    expect(debit!.meta.tipper_user_id).toBe(BOB_ID);
    expect(debit!.meta.recipient_user_id).toBe(ALICE_ID);
  });

  test("Multiple tips on same post create separate ledger entries", async () => {
    // Bob tips the same post again
    const resp = await apiPost(bobPage, BOB_ID, `/posts/${postId}/tip`, {
      amount_cents: 100,
      currency: "usd",
      payment_method_id: PM_ID,
    });
    expect(resp.ok()).toBe(true);

    const bobLedger = queryLedger(BOB_ID);
    const debits = bobLedger.filter(
      (e) => e.reason === "Tip: post" && e.type === "debit" &&
             e.meta?.content_id === postId,
    );
    expect(debits.length).toBeGreaterThanOrEqual(2);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 87. Tip Ledger -- Comments
// ═════════════════════════════════════════════════════════════════════════════

test.describe("87. Tip Ledger -- Comments", () => {
  let alicePage: Page;
  let bobPage: Page;
  let postId: string;
  let commentId: string;
  const PM_ID = `pm_tl_cmt_${TS}`;
  const TIP_AMOUNT = 75;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);

    // Inject PM for Bob
    injectPaymentMethod(BOB_ID, PM_ID);

    // Alice creates a post
    const postResp = await apiPost(alicePage, ALICE_ID, "/posts", {
      body: `Comment tip test post ${TS}`,
    });
    expect(postResp.ok()).toBe(true);
    const postBody = await postResp.json() as { post_id: string };
    postId = postBody.post_id;

    // Alice creates a comment
    const cmtResp = await apiPost(alicePage, ALICE_ID, `/posts/${postId}/comments`, {
      body: `Tippable comment ${TS}`,
    });
    expect(cmtResp.ok()).toBe(true);
    const cmtBody = await cmtResp.json() as { comment_id: string };
    commentId = cmtBody.comment_id;
  });

  test.afterAll(async () => {
    removePaymentMethod(BOB_ID, PM_ID);
    await alicePage.close();
    await bobPage.close();
  });

  test("Comment tip writes debit for tipper", async () => {
    const resp = await apiPost(bobPage, BOB_ID,
      `/posts/${postId}/comments/${commentId}/tip`,
      { amount_cents: TIP_AMOUNT, currency: "usd" },
    );
    expect(resp.ok()).toBe(true);

    const bobLedger = queryLedger(BOB_ID);
    const debit = bobLedger.find(
      (e) => e.reason === "Tip: comment" && e.type === "debit" &&
             e.meta?.content_id === commentId,
    );
    expect(debit).toBeDefined();
    expect(Number(debit!.amount_cents)).toBe(TIP_AMOUNT);
  });

  test("Comment tip writes credit for comment author", async () => {
    const aliceLedger = queryLedger(ALICE_ID);
    const credit = aliceLedger.find(
      (e) => e.reason === "Tip: comment" && e.type === "credit" &&
             e.meta?.content_id === commentId,
    );
    expect(credit).toBeDefined();
    expect(Number(credit!.amount_cents)).toBe(expectedNet(TIP_AMOUNT, credit!));
  });

  test("Comment tip ledger meta contains post_id, comment_id, content_type=comment", async () => {
    const bobLedger = queryLedger(BOB_ID);
    const debit = bobLedger.find(
      (e) => e.reason === "Tip: comment" && e.type === "debit" &&
             e.meta?.content_id === commentId,
    );
    expect(debit).toBeDefined();
    expect(debit!.meta.content_type).toBe("comment");
    expect(debit!.meta.post_id).toBe(postId);
    expect(debit!.meta.comment_id).toBe(commentId);
    expect(debit!.meta.tipper_user_id).toBe(BOB_ID);
    expect(debit!.meta.recipient_user_id).toBe(ALICE_ID);
  });

  test("Self-tip on own comment is rejected (no ledger entry)", async () => {
    // Alice tries to tip her own comment
    const resp = await apiPost(alicePage, ALICE_ID,
      `/posts/${postId}/comments/${commentId}/tip`,
      { amount_cents: 50, currency: "usd" },
    );
    // The endpoint does not explicitly reject self-tips on comments with 400,
    // but the ledger write is skipped because comment_author == tipper_id.
    // The tip_total_cents still increments (pre-existing behavior).
    // Verify no credit entry was written for Alice on this comment from Alice.
    const aliceLedger = queryLedger(ALICE_ID);
    const selfCredit = aliceLedger.find(
      (e) => e.reason === "Tip: comment" && e.type === "credit" &&
             e.meta?.content_id === commentId &&
             e.meta?.tipper_user_id === ALICE_ID,
    );
    // Self-tip should NOT have a credit entry (tipper == recipient)
    expect(selfCredit).toBeUndefined();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 88. Tip Ledger -- Cross-Cutting
// ═════════════════════════════════════════════════════════════════════════════

test.describe("88. Tip Ledger -- Cross-Cutting", () => {
  let alicePage: Page;
  let bobPage: Page;
  let dmConvoId: string;
  let postId: string;
  let commentId: string;
  const PM_ID = `pm_tl_cross_${TS}`;
  let msgId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);

    injectPaymentMethod(ALICE_ID, PM_ID);
    injectPaymentMethod(BOB_ID, PM_ID);

    // Create DM
    const dmResp = await apiPost(alicePage, ALICE_ID, "/messaging/conversations", {
      participant_ids: [getSessions()[BOB_ID].user_sub],
      type: "dm",
    });
    expect(dmResp.ok()).toBe(true);
    dmConvoId = ((await dmResp.json()) as { conversation_id: string }).conversation_id;

    // Alice sends tipped message
    const msgResp = await apiPost(alicePage, ALICE_ID,
      `/messaging/conversations/${dmConvoId}/messages`,
      { text: `cross-msg-${TS}`, tip_amount_cents: 150 },
    );
    expect(msgResp.ok()).toBe(true);
    msgId = ((await msgResp.json()) as { message_id: string }).message_id;

    // Alice creates post
    const postResp = await apiPost(alicePage, ALICE_ID, "/posts", {
      body: `cross-post-${TS}`,
    });
    expect(postResp.ok()).toBe(true);
    postId = ((await postResp.json()) as { post_id: string }).post_id;

    // Bob tips Alice's post
    await apiPost(bobPage, BOB_ID, `/posts/${postId}/tip`, {
      amount_cents: 200, currency: "usd", payment_method_id: PM_ID,
    });

    // Alice creates comment, Bob tips it
    const cmtResp = await apiPost(alicePage, ALICE_ID, `/posts/${postId}/comments`, {
      body: `cross-cmt-${TS}`,
    });
    expect(cmtResp.ok()).toBe(true);
    commentId = ((await cmtResp.json()) as { comment_id: string }).comment_id;
    await apiPost(bobPage, BOB_ID,
      `/posts/${postId}/comments/${commentId}/tip`,
      { amount_cents: 50, currency: "usd" },
    );
  });

  test.afterAll(async () => {
    removePaymentMethod(ALICE_ID, PM_ID);
    removePaymentMethod(BOB_ID, PM_ID);
    await alicePage.close();
    await bobPage.close();
  });

  test("All tip types use consistent reason format ('Tip: {type}')", async () => {
    // Check Alice's ledger for message debit
    const aliceLedger = queryLedger(ALICE_ID);
    const msgDebit = aliceLedger.find(
      (e) => e.type === "debit" && e.meta?.content_id === msgId,
    );
    expect(msgDebit?.reason).toBe("Tip: message");

    // Check Bob's ledger for post debit
    const bobLedger = queryLedger(BOB_ID);
    const postDebit = bobLedger.find(
      (e) => e.type === "debit" && e.meta?.content_id === postId,
    );
    expect(postDebit?.reason).toBe("Tip: post");

    // Check Bob's ledger for comment debit
    const cmtDebit = bobLedger.find(
      (e) => e.type === "debit" && e.meta?.content_id === commentId,
    );
    expect(cmtDebit?.reason).toBe("Tip: comment");
  });

  test("Debit and credit entries have matching amount and currency for all types", async () => {
    const aliceLedger = queryLedger(ALICE_ID);
    const bobLedger = queryLedger(BOB_ID);

    // Message tip: Alice debit, Bob credit
    const msgDebit = aliceLedger.find(
      (e) => e.type === "debit" && e.meta?.content_id === msgId,
    );
    const msgCredit = bobLedger.find(
      (e) => e.type === "credit" && e.meta?.content_id === msgId,
    );
    expect(msgDebit).toBeDefined();
    expect(msgCredit).toBeDefined();
    // FIN-018: credit is net of the platform fee; debit is gross.
    expect(Number(msgCredit!.amount_cents)).toBe(expectedNet(Number(msgDebit!.amount_cents), msgCredit!));

    // Post tip: Bob debit, Alice credit
    const postDebit = bobLedger.find(
      (e) => e.type === "debit" && e.meta?.content_id === postId,
    );
    const postCredit = aliceLedger.find(
      (e) => e.type === "credit" && e.meta?.content_id === postId,
    );
    expect(postDebit).toBeDefined();
    expect(postCredit).toBeDefined();
    expect(Number(postCredit!.amount_cents)).toBe(expectedNet(Number(postDebit!.amount_cents), postCredit!));
  });

  test("Tipper billing history shows all tip debits", async () => {
    const bobLedger = queryLedger(BOB_ID);
    // Bob should have at least a post tip debit and a comment tip debit
    const tipDebits = bobLedger.filter(
      (e) => e.type === "debit" && (e.reason as string).startsWith("Tip:"),
    );
    expect(tipDebits.length).toBeGreaterThanOrEqual(2);

    // Check content_types are diverse
    const contentTypes = new Set(tipDebits.map((e) => e.meta?.content_type as string));
    expect(contentTypes.has("post")).toBe(true);
    expect(contentTypes.has("comment")).toBe(true);
  });
});
