import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
import { usingCpp, cppSeedPaymentMethod } from "./helpers/cpp-seed";
import { cppQueryBillingLedgerRows } from "./helpers/cpp-seed-broadcast-private";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

/* ------------------------------------------------------------------ */
/*  Constants & helpers                                                */
/* ------------------------------------------------------------------ */

const TS = Date.now();

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

async function apiPut(
  page: Page,
  identity: string,
  path: string,
  body: object,
) {
  const s = getSessions()[identity];
  return page.request.put(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

/* ------------------------------------------------------------------ */
/*  DDB helpers                                                        */
/* ------------------------------------------------------------------ */

function runPython(code: string): string {
  return execSync(
    `python3 -c "${code.replace(/"/g, '\\"')}"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  ).toString().trim();
}

const PY_PREAMBLE = `
import sys, os, json
sys.path.insert(0, '${REPO_ROOT}')
os.environ.setdefault('AWS_ACCESS_KEY_ID', 'test')
os.environ.setdefault('AWS_SECRET_ACCESS_KEY', 'test')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
os.environ.setdefault('DDB_ENDPOINT_URL', 'http://localhost:8001')
import boto3, time
from decimal import Decimal
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001')
`.trim();

function setSessionStatus(sessionId: string, status: string) {
  const code = `
${PY_PREAMBLE}
table = ddb.Table('BroadcastSessions')
table.update_item(
    Key={'session_id': '${sessionId}'},
    UpdateExpression='SET #s = :s',
    ExpressionAttributeNames={'#s': 'status'},
    ExpressionAttributeValues={':s': '${status}'},
)
print('ok')
`;
  runPython(code);
}

function enablePrivateChat(sessionId: string) {
  const code = `
${PY_PREAMBLE}
table = ddb.Table('BroadcastSessions')
table.update_item(
    Key={'session_id': '${sessionId}'},
    UpdateExpression='SET private_chat_enabled = :e, private_chat_voyeur_enabled = :v, private_chat_voyeur_price_cents = :vp, private_chat_tiers = :t',
    ExpressionAttributeValues={
        ':e': True,
        ':v': True,
        ':vp': 100,
        ':t': [{'minutes': 5, 'price_cents': 2500}, {'minutes': 15, 'price_cents': 7500}],
    },
)
print('ok')
`;
  runPython(code);
}

function seedPaymentMethod(userId: string, pmId: string) {
  if (usingCpp()) {
    cppSeedPaymentMethod(userId, pmId);
    return;
  }
  const code = `
${PY_PREAMBLE}
table = ddb.Table('billing')
table.put_item(Item={
    'pk': 'USER#${userId}',
    'sk': 'PM#${pmId}',
    'payment_method_id': '${pmId}',
    'brand': 'visa',
    'last4': '4242',
    'type': 'card',
})
table.put_item(Item={
    'pk': 'USER#${userId}',
    'sk': 'BILLING',
    'default_payment_method_id': '${pmId}',
})
print('ok')
`;
  runPython(code);
}

function queryBillingLedger(userId: string): Array<Record<string, unknown>> {
  if (usingCpp()) {
    return cppQueryBillingLedgerRows(userId, "Private chat") as unknown as Array<
      Record<string, unknown>
    >;
  }
  const code = `
${PY_PREAMBLE}
from boto3.dynamodb.conditions import Key as K

class DE(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal): return int(o) if o == int(o) else float(o)
        return super().default(o)

table = ddb.Table('billing')
resp = table.query(
    KeyConditionExpression=K('pk').eq('USER#${userId}') & K('sk').begins_with('LEDGER#'),
)
entries = [i for i in resp.get('Items', []) if 'Private chat' in str(i.get('reason', ''))]
print(json.dumps(entries, cls=DE))
`;
  return JSON.parse(runPython(code));
}

/* ------------------------------------------------------------------ */
/*  Shared broadcast setup                                            */
/* ------------------------------------------------------------------ */

async function createLiveBroadcast(page: Page): Promise<{ profileId: string; sessionId: string }> {
  const profileResp = await apiPost(page, "root", "/broadcast/profiles", {
    name: `pchat-profile-${TS}-${Math.random().toString(36).slice(2, 8)}`,
    region: "us-east-1",
    rendition_preset: "720p30",
  });
  expect(profileResp.status()).toBe(201);
  const profileId = (await profileResp.json()).id;

  const sessionResp = await apiPost(page, "root", "/broadcast/sessions", {
    profile_id: profileId,
  });
  expect(sessionResp.status()).toBe(201);
  const sessionId = (await sessionResp.json()).id;

  // Set session to live and enable private chat
  if (usingCpp()) {
    // cpp: promote draft->live + enable private-chat via the real APIs (root owns
    // the session). h_pchat_purchase gates on private_chat_enabled +
    // voyeur_enabled/voyeur_price_cents (the tiers array isn't read by purchase).
    const startResp = await apiPost(page, "root", `/broadcast/sessions/${sessionId}/start`, {});
    expect([200, 202]).toContain(startResp.status());
    const tierResp = await apiPut(page, "root", `/broadcast/sessions/${sessionId}/chat-tiers`, {
      private_chat_enabled: true,
      private_chat_rate_per_minute_cents: 500,
      voyeur_rate_per_minute_cents: 100,
      private_chat_time_blocks: [5, 15, 30],
      private_chat_max_concurrent: 5,
    });
    expect(tierResp.status()).toBe(200);
  } else {
    setSessionStatus(sessionId, "live");
    enablePrivateChat(sessionId);
  }

  return { profileId, sessionId };
}

/* ------------------------------------------------------------------ */
/*  Section 125 — Private Chat Purchase + Messaging                    */
/* ------------------------------------------------------------------ */

test.describe("125 — Private Chat Purchase + Messaging", () => {
  let rootPage: Page;
  let alicePage: Page;
  let bobPage: Page;
  let sessionId: string;
  let chatId: string;
  const ALICE_PM = `pm_pchat_alice_${TS}`;
  const BOB_PM = `pm_pchat_bob_${TS}`;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, "root");

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, "bob");

    // Seed payment methods
    const aliceSub = getSessions()["alice"].user_sub;
    const bobSub = getSessions()["bob"].user_sub;
    seedPaymentMethod(aliceSub, ALICE_PM);
    seedPaymentMethod(bobSub, BOB_PM);

    // Create a live broadcast with private chat enabled
    const broadcast = await createLiveBroadcast(rootPage);
    sessionId = broadcast.sessionId;
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
    await bobPage.context().close();
  });

  test("125.1 Configure chat tiers → 200", async () => {
    const resp = await apiPut(rootPage, "root", `/broadcast/sessions/${sessionId}/chat-tiers`, {
      private_chat_enabled: true,
      private_chat_rate_per_minute_cents: 500,
      voyeur_rate_per_minute_cents: 100,
      private_chat_time_blocks: [5, 15, 30],
      private_chat_max_concurrent: 5,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.private_chat_enabled).toBe(true);
  });

  test("125.2 Get tiers → returns configured tiers", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/chat-tiers`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.private_chat_enabled).toBe(true);
    expect(body.private_chat_time_blocks).toContain(5);
  });

  test("125.3 Purchase tier 1 private chat → chat created, wallet debited", async () => {
    const resp = await apiPost(alicePage, "alice", `/broadcast/sessions/${sessionId}/private-chat/purchase`, {
      tier: 1,
      duration_minutes: 5,
      payment_method_id: ALICE_PM,
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.status).toBe("active");
    expect(body.tier).toBe(1);
    expect(body.total_paid_cents).toBe(2500); // 5 * 500
    expect(body.chat_id).toBeTruthy();
    expect(body.expires_at).toBeGreaterThan(0);
    chatId = body.chat_id;

    // Verify billing ledger debit
    const aliceSub = getSessions()["alice"].user_sub;
    const entries = queryBillingLedger(aliceSub);
    const debits = entries.filter((e) => e.type === "debit");
    expect(debits.length).toBeGreaterThanOrEqual(1);
  });

  test("125.4 Send message in active chat → 201", async () => {
    const resp = await apiPost(alicePage, "alice", `/broadcast/sessions/${sessionId}/private-chat/${chatId}/message`, {
      text: "Hello from private chat!",
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.private_chat_id).toBe(chatId);
    expect(body.kind).toBe("private_chat");
    expect(body.text).toBe("Hello from private chat!");
  });

  test("125.5 Message content filtered", async () => {
    const resp = await apiPost(alicePage, "alice", `/broadcast/sessions/${sessionId}/private-chat/${chatId}/message`, {
      text: "What the fuck is this?",
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.text).not.toContain("fuck");
    expect(body.text).toContain("****");
    expect(body.filtered).toBe(true);
  });

  test("125.6 List messages → returns sent messages", async () => {
    const resp = await apiGet(alicePage, `/broadcast/sessions/${sessionId}/private-chat/${chatId}/messages`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.messages.length).toBeGreaterThanOrEqual(2);
    // All messages should have the correct private_chat_id
    for (const msg of body.messages) {
      expect(msg.private_chat_id).toBe(chatId);
    }
  });

  test("125.7 Creator can send messages in any private chat", async () => {
    const resp = await apiPost(rootPage, "root", `/broadcast/sessions/${sessionId}/private-chat/${chatId}/message`, {
      text: "Creator response",
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.sender_id).toBe(getSessions()["root"].user_sub);
  });

  test("125.8 Non-participant message → 403", async () => {
    const resp = await apiPost(bobPage, "bob", `/broadcast/sessions/${sessionId}/private-chat/${chatId}/message`, {
      text: "I should not be able to send this",
    });
    expect(resp.status()).toBe(403);
  });

  test("125.9 Get chat status → returns time remaining", async () => {
    const resp = await apiGet(alicePage, `/broadcast/sessions/${sessionId}/private-chat/${chatId}/status`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.chat_id).toBe(chatId);
    expect(body.remaining_seconds).toBeGreaterThan(0);
    expect(body.status).toBe("active");
  });

  test("125.10 End chat → ok", async () => {
    const resp = await apiPost(alicePage, "alice", `/broadcast/sessions/${sessionId}/private-chat/${chatId}/end`, {});
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.ended_reason).toBe("viewer_ended");
  });

  test("125.11 Message after end → 409", async () => {
    const resp = await apiPost(alicePage, "alice", `/broadcast/sessions/${sessionId}/private-chat/${chatId}/message`, {
      text: "Should fail after end",
    });
    expect(resp.status()).toBe(409);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 126 — Voyeur Tier + Billing                                */
/* ------------------------------------------------------------------ */

test.describe("126 — Voyeur Tier + Billing", () => {
  let rootPage: Page;
  let alicePage: Page;
  let bobPage: Page;
  let sessionId: string;
  let chatId: string;
  const ALICE_PM = `pm_pchat2_alice_${TS}`;
  const BOB_PM = `pm_pchat2_bob_${TS}`;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, "root");

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, "bob");

    const aliceSub = getSessions()["alice"].user_sub;
    const bobSub = getSessions()["bob"].user_sub;
    seedPaymentMethod(aliceSub, ALICE_PM);
    seedPaymentMethod(bobSub, BOB_PM);

    const broadcast = await createLiveBroadcast(rootPage);
    sessionId = broadcast.sessionId;

    // Alice purchases tier 1
    const purchaseResp = await apiPost(alicePage, "alice", `/broadcast/sessions/${sessionId}/private-chat/purchase`, {
      tier: 1,
      duration_minutes: 15,
      payment_method_id: ALICE_PM,
    });
    expect(purchaseResp.status()).toBe(201);
    chatId = (await purchaseResp.json()).chat_id;
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
    await bobPage.context().close();
  });

  test("126.1 Voyeur purchases tier 2 access → 201", async () => {
    const resp = await apiPost(bobPage, "bob", `/broadcast/sessions/${sessionId}/private-chat/purchase`, {
      tier: 2,
      duration_minutes: 15,
      payment_method_id: BOB_PM,
      chat_id: chatId,
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.tier).toBe(2);
    expect(body.chat_id).toBe(chatId);
    expect(body.total_paid_cents).toBe(1500); // 15 * 100
  });

  test("126.2 Voyeur can read messages → 200", async () => {
    // Send a message first
    await apiPost(alicePage, "alice", `/broadcast/sessions/${sessionId}/private-chat/${chatId}/message`, {
      text: `voyeur-read-test-${TS}`,
    });

    const resp = await apiGet(bobPage, `/broadcast/sessions/${sessionId}/private-chat/${chatId}/messages`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.messages.length).toBeGreaterThanOrEqual(1);
  });

  test("126.3 Voyeur cannot send messages → 403", async () => {
    const resp = await apiPost(bobPage, "bob", `/broadcast/sessions/${sessionId}/private-chat/${chatId}/message`, {
      text: "I should not be able to send",
    });
    expect(resp.status()).toBe(403);
  });

  test("126.4 Tier 2 purchase fails for nonexistent chat → 404", async () => {
    const resp = await apiPost(bobPage, "bob", `/broadcast/sessions/${sessionId}/private-chat/purchase`, {
      tier: 2,
      duration_minutes: 5,
      payment_method_id: BOB_PM,
      chat_id: "pchat_invalid_nonexistent",
    });
    expect(resp.status()).toBe(404);
  });

  test("126.5 Billing: debit full amount, credit minus platform fee", async () => {
    const rootSub = getSessions()["root"].user_sub;
    const aliceSub = getSessions()["alice"].user_sub;

    const aliceEntries = queryBillingLedger(aliceSub);
    const debits = aliceEntries.filter((e) => e.type === "debit");
    expect(debits.length).toBeGreaterThanOrEqual(1);

    const creatorEntries = queryBillingLedger(rootSub);
    const credits = creatorEntries.filter((e) => e.type === "credit");
    expect(credits.length).toBeGreaterThanOrEqual(1);
    // Creator credit should be less than viewer debit (platform fee deducted)
    if (debits.length > 0 && credits.length > 0) {
      const debitAmount = Number(debits[0].amount_cents);
      const creditAmount = Number(credits[0].amount_cents);
      expect(creditAmount).toBeLessThan(debitAmount);
    }
  });

  test("126.6 Creator lists active private chats", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/private-chats`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.chats.length).toBeGreaterThanOrEqual(1);
    const chat = body.chats.find((c: Record<string, unknown>) => c.chat_id === chatId);
    expect(chat).toBeTruthy();
    expect(chat.voyeur_count).toBeGreaterThanOrEqual(1);
  });

  test("126.7 End chat ends all voyeur sessions too", async () => {
    await apiPost(rootPage, "root", `/broadcast/sessions/${sessionId}/private-chat/${chatId}/end`, {});

    // Bob's voyeur session is ended, so reading messages returns 403
    const resp = await apiGet(bobPage, `/broadcast/sessions/${sessionId}/private-chat/${chatId}/messages`);
    expect(resp.status()).toBe(403);
  });
});
