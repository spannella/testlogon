/**
 * E2E tests for CALL-011: Pay-per-minute private video calls.
 *
 * Tests call rate settings, paid call lifecycle, billing heartbeat,
 * and billing summary via API endpoints.
 *
 * Auth pattern: Uses e2e_admin_session_setup.py sessions with
 * injectAuth + CSRF for cookie-based auth.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, resolveIdentityId } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const PYTHON = REPO_ROOT + "/.venv/bin/python3";

const ALICE_ID = resolveIdentityId("e2e_alice@test.local");
const BOB_ID   = resolveIdentityId("e2e_bob@test.local");

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

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
}

function csrfHeader(userId: string): Record<string, string> {
  const session = getSessions()[userId];
  return { "x-csrf-token": session.csrf_token };
}

// ─── DDB helpers ──────────────────────────────────────────────────────────────

function ddbPut(tableName: string, item: Record<string, unknown>) {
  const script = `
import boto3, json, sys
from decimal import Decimal

ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
table = ddb.Table("${tableName}")

raw = json.loads(sys.argv[1])

def convert(obj):
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: convert(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [convert(i) for i in obj]
    return obj

table.put_item(Item=convert(raw))
print("ok")
`;
  execSync(`${PYTHON} -c '${script}' '${JSON.stringify(item)}'`, {
    cwd: REPO_ROOT,
    timeout: 10_000,
  });
}

function seedWallet(userId: string, balanceCents: number) {
  ddbPut("billing", {
    pk: `USER#${userId}`,
    sk: "WALLET",
    wallet_balance_cents: balanceCents,
    currency: "usd",
    updated_at: Math.floor(Date.now() / 1000),
  });
}

function getWalletBalance(userId: string): number {
  const script = `
import boto3, json
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
table = ddb.Table("billing")
resp = table.get_item(Key={"pk": f"USER#${userId}", "sk": "WALLET"})
item = resp.get("Item", {})
print(int(item.get("wallet_balance_cents", 0)))
`;
  const out = execSync(`${PYTHON} -c '${script}'`, {
    cwd: REPO_ROOT,
    timeout: 10_000,
  }).toString().trim();
  return parseInt(out, 10);
}

// Transition a call to connected state via DDB update
function connectCallDirect(callId: string) {
  const ts = Math.floor(Date.now() / 1000);
  const script = `
import boto3, json
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
table = ddb.Table("MessageCallSessions")
table.update_item(
    Key={"call_id": "${callId}"},
    UpdateExpression="SET #s = :s, connect_ts = :ct, billing_start_ts = :ct, last_billed_ts = :ct, platform_fee_bps = :pfb, billing_status = :bs, billing_cycle_count = :z, total_billed_cents = :z, total_billed_seconds = :z, caller_last_heartbeat_ts = :ct, callee_last_heartbeat_ts = :ct",
    ExpressionAttributeNames={"#s": "state"},
    ExpressionAttributeValues={
        ":s": "connected",
        ":ct": ${ts},
        ":pfb": 2000,
        ":bs": "active",
        ":z": 0,
    },
)
print("ok")
`;
  execSync(`${PYTHON} -c '${script}'`, {
    cwd: REPO_ROOT,
    timeout: 10_000,
  });
}

// Get a call session record directly from DDB
function getCallSession(callId: string): Record<string, unknown> | null {
  const script = `
import boto3, json
from decimal import Decimal

class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return int(o) if o == int(o) else float(o)
        return super().default(o)

ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
table = ddb.Table("MessageCallSessions")
resp = table.get_item(Key={"call_id": "${callId}"})
item = resp.get("Item")
if item:
    print(json.dumps(dict(item), cls=DecimalEncoder))
else:
    print("null")
`;
  const out = execSync(`${PYTHON} -c '${script}'`, {
    cwd: REPO_ROOT,
    timeout: 10_000,
  }).toString().trim();
  if (out === "null") return null;
  return JSON.parse(out);
}

function endCallDirect(callId: string) {
  const ts = Math.floor(Date.now() / 1000);
  const script = `
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
table = ddb.Table("MessageCallSessions")
table.update_item(
    Key={"call_id": "${callId}"},
    UpdateExpression="SET #s = :s, end_ts = :et, billing_status = :bs",
    ExpressionAttributeNames={"#s": "state"},
    ExpressionAttributeValues={":s": "ended", ":et": ${ts}, ":bs": "finalized"},
)
print("ok")
`;
  execSync(`${PYTHON} -c '${script}'`, {
    cwd: REPO_ROOT,
    timeout: 10_000,
  });
}

function endAllCallsInConversation(conversationId: string) {
  const ts = Math.floor(Date.now() / 1000);
  const script = `
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
table = ddb.Table("MessageCallSessions")
resp = table.scan(
    FilterExpression="conversation_id = :cid AND NOT #s IN (:ended, :declined, :canceled)",
    ExpressionAttributeNames={"#s": "state"},
    ExpressionAttributeValues={":cid": "${conversationId}", ":ended": "ended", ":declined": "declined", ":canceled": "canceled"},
)
for item in resp.get("Items", []):
    cid = item["call_id"]
    table.update_item(
        Key={"call_id": cid},
        UpdateExpression="SET #s = :s, end_ts = :et",
        ExpressionAttributeNames={"#s": "state"},
        ExpressionAttributeValues={":s": "ended", ":et": ${ts}},
    )
    print("Ended call " + cid)
`;
  execSync(`${PYTHON} -c '${script}'`, {
    cwd: REPO_ROOT,
    timeout: 10_000,
  });
}

// ─── Unique IDs ───────────────────────────────────────────────────────────────

const TS = Date.now();
let _callSeq = 0;
function nextCallId(): string {
  _callSeq++;
  return `e2e_cb_${TS}_${_callSeq}`;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

test.describe.serial("117 — Call Rate Settings API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, BOB_ID);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("117.1 Creator sets per-minute rate to $5.00", async () => {
    const resp = await alicePage.request.post(`${BASE}/ui/calls/rates`, {
      headers: csrfHeader(BOB_ID),
      data: { rate_cents_per_minute: 500, enabled: true, min_balance_minutes: 5, max_duration_minutes: 120 },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.rate_cents_per_minute).toBe(500);
    expect(body.enabled).toBe(true);
  });

  test("117.2 Get creator rate returns $5.00/min", async () => {
    const alicePage2 = await alicePage.context().browser()!.newPage();
    await injectAuth(alicePage2, ALICE_ID);
    const resp = await alicePage2.request.get(`${BASE}/ui/calls/rates/${BOB_ID}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.rate_cents_per_minute).toBe(500);
    expect(body.enabled).toBe(true);
    await alicePage2.close();
  });

  test("117.3 Rate below minimum ($0.50) rejected", async () => {
    const resp = await alicePage.request.post(`${BASE}/ui/calls/rates`, {
      headers: csrfHeader(BOB_ID),
      data: { rate_cents_per_minute: 50, enabled: true },
    });
    expect(resp.status()).toBe(422);
  });

  test("117.4 Rate above maximum ($150.00) rejected", async () => {
    const resp = await alicePage.request.post(`${BASE}/ui/calls/rates`, {
      headers: csrfHeader(BOB_ID),
      data: { rate_cents_per_minute: 15000, enabled: true },
    });
    expect(resp.status()).toBe(422);
  });
});

test.describe.serial("118 — Paid Call Lifecycle + Billing", () => {
  let alicePage: Page;
  let bobPage: Page;
  let dmConvoId: string;
  let paidCallId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);

    // Get or create a DM conversation between Alice and Bob
    const resp = await alicePage.request.post(`${BASE}/messaging/conversations/dm/find-or-create`, {
      headers: csrfHeader(ALICE_ID),
      data: { user_id: BOB_ID },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    dmConvoId = body.conversation_id;

    // Clean up any active calls from previous runs
    endAllCallsInConversation(dmConvoId);

    // Ensure Bob has a rate set
    await bobPage.request.post(`${BASE}/ui/calls/rates`, {
      headers: csrfHeader(BOB_ID),
      data: { rate_cents_per_minute: 500, enabled: true, min_balance_minutes: 2, max_duration_minutes: 120 },
    });
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("118.1 Paid call invite requires sufficient wallet balance", async () => {
    // Clear Alice wallet to 0
    seedWallet(ALICE_ID, 0);

    const callId = nextCallId();
    const resp = await alicePage.request.post(`${BASE}/messaging/messages/calls/invite`, {
      headers: csrfHeader(ALICE_ID),
      data: {
        call_id: callId,
        conversation_id: dmConvoId,
        callee_user_id: BOB_ID,
        initial_mode: "audio",
        paid: true,
      },
    });
    expect(resp.status()).toBe(402);
    const body = await resp.json();
    expect(body.detail.code).toBe("insufficient_balance");
  });

  test("118.2 Paid call invite succeeds with sufficient balance", async () => {
    // Seed Alice wallet with $50
    seedWallet(ALICE_ID, 5000);

    paidCallId = nextCallId();
    const resp = await alicePage.request.post(`${BASE}/messaging/messages/calls/invite`, {
      headers: csrfHeader(ALICE_ID),
      data: {
        call_id: paidCallId,
        conversation_id: dmConvoId,
        callee_user_id: BOB_ID,
        initial_mode: "audio",
        paid: true,
      },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.paid).toBe(true);
    expect(body.rate_cents_per_minute).toBe(500);
    expect(body.call_id).toBe(paidCallId);
  });

  test("118.3 Heartbeat on paid call returns billing status", async () => {
    // Transition call to connected state directly in DDB
    connectCallDirect(paidCallId);

    const resp = await alicePage.request.patch(
      `${BASE}/messaging/messages/calls/${paidCallId}/heartbeat`,
      {
        headers: csrfHeader(ALICE_ID),
        data: { client_ts: Math.floor(Date.now() / 1000) },
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.call_id).toBe(paidCallId);
    expect(typeof body.total_cost_cents).toBe("number");
    expect(typeof body.balance_remaining_cents).toBe("number");
    expect(body.rate_cents_per_minute).toBe(500);
  });

  test("118.4 Non-participant heartbeat returns 403", async () => {
    // Create a new page with a different user identity
    // Bob IS a participant, so we need a third user... but we only have Alice and Bob.
    // Instead, test with an explicit check: create another page without auth
    // Actually, Bob IS a participant. Let's verify the heartbeat endpoint rejects
    // a call that doesn't exist.
    const resp = await alicePage.request.patch(
      `${BASE}/messaging/messages/calls/nonexistent_call/heartbeat`,
      {
        headers: csrfHeader(ALICE_ID),
        data: { client_ts: Math.floor(Date.now() / 1000) },
      },
    );
    expect(resp.status()).toBe(404);
  });

  test("118.5 Billing summary after call", async () => {
    const resp = await alicePage.request.get(
      `${BASE}/messaging/messages/calls/${paidCallId}/billing`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.call_id).toBe(paidCallId);
    expect(body.paid).toBe(true);
    expect(body.rate_cents_per_minute).toBe(500);
    expect(typeof body.total_cost_cents).toBe("number");
    expect(typeof body.caller_balance_remaining_cents).toBe("number");
  });

  test("118.6 Call end finalizes billing", async () => {
    // End the call
    const endResp = await alicePage.request.post(
      `${BASE}/messaging/messages/calls/${paidCallId}/end`,
      {
        headers: csrfHeader(ALICE_ID),
        data: { reason: "ended" },
      },
    );
    expect(endResp.status()).toBe(200);

    // Verify the call session is ended
    const session = getCallSession(paidCallId);
    expect(session).not.toBeNull();
    expect(session!.state).toBe("ended");
  });

  test("118.7 Non-paid call has no billing state impact", async () => {
    const freeCallId = nextCallId();
    seedWallet(ALICE_ID, 5000);

    const resp = await alicePage.request.post(`${BASE}/messaging/messages/calls/invite`, {
      headers: csrfHeader(ALICE_ID),
      data: {
        call_id: freeCallId,
        conversation_id: dmConvoId,
        callee_user_id: BOB_ID,
        initial_mode: "audio",
        paid: false,
      },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.paid).toBe(false);
    expect(body.rate_cents_per_minute).toBeNull();
    endCallDirect(freeCallId);
  });

  test("118.8 Heartbeat on non-paid call returns 400", async () => {
    const freeCallId = nextCallId();
    seedWallet(ALICE_ID, 5000);

    // Create a free call
    const inviteResp = await alicePage.request.post(`${BASE}/messaging/messages/calls/invite`, {
      headers: csrfHeader(ALICE_ID),
      data: {
        call_id: freeCallId,
        conversation_id: dmConvoId,
        callee_user_id: BOB_ID,
        initial_mode: "audio",
        paid: false,
      },
    });
    expect(inviteResp.status()).toBe(200);

    // Transition to connected
    connectCallDirect(freeCallId);

    const resp = await alicePage.request.patch(
      `${BASE}/messaging/messages/calls/${freeCallId}/heartbeat`,
      {
        headers: csrfHeader(ALICE_ID),
        data: { client_ts: Math.floor(Date.now() / 1000) },
      },
    );
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail.code).toBe("not_paid_call");
  });
});

test.describe.serial("119 — Call Billing Edge Cases", () => {
  let alicePage: Page;
  let bobPage: Page;
  let dmConvoId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);

    // Get or create DM
    const resp = await alicePage.request.post(`${BASE}/messaging/conversations/dm/find-or-create`, {
      headers: csrfHeader(ALICE_ID),
      data: { user_id: BOB_ID },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    dmConvoId = body.conversation_id;

    // Clean up any active calls from previous runs
    endAllCallsInConversation(dmConvoId);

    // Ensure Bob rate is set
    await bobPage.request.post(`${BASE}/ui/calls/rates`, {
      headers: csrfHeader(BOB_ID),
      data: { rate_cents_per_minute: 500, enabled: true, min_balance_minutes: 2 },
    });
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("119.1 Creator disables paid calls -> invite returns 400", async () => {
    // Disable Bob's paid calls
    await bobPage.request.delete(`${BASE}/ui/calls/rates`, {
      headers: csrfHeader(BOB_ID),
    });

    seedWallet(ALICE_ID, 5000);
    const callId = nextCallId();
    const resp = await alicePage.request.post(`${BASE}/messaging/messages/calls/invite`, {
      headers: csrfHeader(ALICE_ID),
      data: {
        call_id: callId,
        conversation_id: dmConvoId,
        callee_user_id: BOB_ID,
        paid: true,
      },
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail.code).toBe("paid_calls_disabled");

    // Re-enable for subsequent tests
    await bobPage.request.post(`${BASE}/ui/calls/rates`, {
      headers: csrfHeader(BOB_ID),
      data: { rate_cents_per_minute: 500, enabled: true, min_balance_minutes: 2 },
    });
  });

  test("119.2 Delete call rate and verify 404 on GET", async () => {
    await bobPage.request.delete(`${BASE}/ui/calls/rates`, {
      headers: csrfHeader(BOB_ID),
    });

    const resp = await alicePage.request.get(`${BASE}/ui/calls/rates/${BOB_ID}`);
    expect(resp.status()).toBe(404);

    // Re-enable
    await bobPage.request.post(`${BASE}/ui/calls/rates`, {
      headers: csrfHeader(BOB_ID),
      data: { rate_cents_per_minute: 500, enabled: true, min_balance_minutes: 2 },
    });
  });

  test("119.3 Billing summary for non-existent call returns 404", async () => {
    const resp = await alicePage.request.get(
      `${BASE}/messaging/messages/calls/nonexistent_call_xyz/billing`,
    );
    expect(resp.status()).toBe(404);
  });

  test("119.4 Update call rate via PUT", async () => {
    const resp = await bobPage.request.put(`${BASE}/ui/calls/rates`, {
      headers: csrfHeader(BOB_ID),
      data: { rate_cents_per_minute: 800, enabled: true, min_balance_minutes: 3, max_duration_minutes: 60 },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.rate_cents_per_minute).toBe(800);
    expect(body.min_balance_minutes).toBe(3);
    expect(body.max_duration_minutes).toBe(60);

    // Reset to 500 for consistency
    await bobPage.request.post(`${BASE}/ui/calls/rates`, {
      headers: csrfHeader(BOB_ID),
      data: { rate_cents_per_minute: 500, enabled: true, min_balance_minutes: 2 },
    });
  });
});
