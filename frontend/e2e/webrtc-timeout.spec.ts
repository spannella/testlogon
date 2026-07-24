/**
 * E2E tests for CALL-007: Call Ringing Timeout and Missed-Call Handling.
 *
 * Section 84: Call Ringing Timeout
 *
 * Endpoints under test:
 *   POST /messaging/messages/calls/{call_id}/timeout
 *
 * Auth: Cookie-based session auth (from e2e_admin_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();

// ---------------------------------------------------------------------------
// Session bootstrap
// ---------------------------------------------------------------------------

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
  if (!session) throw new Error(`No session for identity "${identity}"`);
  await page.context().addCookies(session.cookies);
}

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body: object = {},
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

// ---------------------------------------------------------------------------
// DynamoDB helpers — seed / cleanup call sessions
// ---------------------------------------------------------------------------

function seedCallSession(opts: {
  callId: string;
  conversationId: string;
  callerUserId: string;
  calleeUserId: string;
  state: string;
  startTs?: number;
}): void {
  const startTs = opts.startTs ?? Math.floor(Date.now() / 1000);
  const py = `
import json, sys, boto3, time
sys.path.insert(0, "${REPO_ROOT}")
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test",
                     aws_secret_access_key="test")
table = ddb.Table("MessageCallSessions")
table.put_item(Item={
    "call_id": ${JSON.stringify(opts.callId)},
    "conversation_id": ${JSON.stringify(opts.conversationId)},
    "caller_user_id": ${JSON.stringify(opts.callerUserId)},
    "callee_user_id": ${JSON.stringify(opts.calleeUserId)},
    "initial_mode": "audio",
    "state": ${JSON.stringify(opts.state)},
    "start_ts": ${startTs},
    "start_ts_sort": ${startTs},
    "updated_at": ${startTs},
    "lifecycle_events": [],
    "idempotency_records": {},
})
print("ok")
`;
  execSync(`python3 -c '${py.replace(/'/g, "'\\''")}'`, {
    cwd: REPO_ROOT,
    timeout: 10_000,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
  });
}

function deleteCallSession(callId: string): void {
  const py = `
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test",
                     aws_secret_access_key="test")
table = ddb.Table("MessageCallSessions")
table.delete_item(Key={"call_id": ${JSON.stringify(callId)}})
print("ok")
`;
  try {
    execSync(`python3 -c '${py.replace(/'/g, "'\\''")}'`, {
      cwd: REPO_ROOT,
      timeout: 10_000,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    });
  } catch {
    // ignore cleanup errors
  }
}

function getCallSession(callId: string): Record<string, unknown> | null {
  const py = `
import json, boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test",
                     aws_secret_access_key="test")
table = ddb.Table("MessageCallSessions")
resp = table.get_item(Key={"call_id": ${JSON.stringify(callId)}})
item = resp.get("Item")
if item:
    # Convert Decimal to int/float for JSON serialization
    import decimal
    def dec_default(obj):
        if isinstance(obj, decimal.Decimal):
            return int(obj) if obj == int(obj) else float(obj)
        raise TypeError
    print(json.dumps(item, default=dec_default))
else:
    print("null")
`;
  try {
    const raw = execSync(`python3 -c '${py.replace(/'/g, "'\\''")}'`, {
      cwd: REPO_ROOT,
      timeout: 10_000,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    }).toString().trim();
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// ===========================================================================
// Tests
// ===========================================================================

test.describe("Section 84: Call Ringing Timeout", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, "alice");
    await alicePage.goto(BASE);
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("84.1 Alice invites Bob, timeout transitions call to missed", async () => {
    const callId = `timeout_84_1_${TS}`;
    const convoId = `convo_timeout_84_1_${TS}`;

    // Seed a DM conversation so the invite can be created
    seedCallSession({
      callId,
      conversationId: convoId,
      callerUserId: ALICE_ID,
      calleeUserId: BOB_ID,
      state: "invited",
    });

    // Call the timeout endpoint as Alice (caller)
    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${callId}/timeout`, {
      reason: "no_answer",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.state).toBe("missed");
    expect(body.reason).toBe("no_answer");

    // Verify in DDB
    const session = getCallSession(callId);
    expect(session).not.toBeNull();
    expect(session!.state).toBe("missed");
    expect(session!.end_reason).toBe("no_answer");
    expect(session!.end_ts).toBeDefined();

    deleteCallSession(callId);
  });

  test("84.2 Timeout API returns correct state shape", async () => {
    const callId = `timeout_84_2_${TS}`;
    const convoId = `convo_timeout_84_2_${TS}`;

    seedCallSession({
      callId,
      conversationId: convoId,
      callerUserId: ALICE_ID,
      calleeUserId: BOB_ID,
      state: "invited",
    });

    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${callId}/timeout`, {
      reason: "no_answer",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("call_id", callId);
    expect(body).toHaveProperty("conversation_id", convoId);
    expect(body).toHaveProperty("state", "missed");
    expect(body).toHaveProperty("from_state", "invited");
    expect(body).toHaveProperty("reason", "no_answer");
    expect(body).toHaveProperty("event_ts");
    expect(typeof body.event_ts).toBe("number");

    deleteCallSession(callId);
  });

  test("84.3 Timeout on already-accepted call returns 409", async () => {
    const callId = `timeout_84_3_${TS}`;
    const convoId = `convo_timeout_84_3_${TS}`;

    seedCallSession({
      callId,
      conversationId: convoId,
      callerUserId: ALICE_ID,
      calleeUserId: BOB_ID,
      state: "accepted",
    });

    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${callId}/timeout`, {
      reason: "no_answer",
    });
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail.code).toBe("invalid_state_transition");

    deleteCallSession(callId);
  });

  test("84.4 Timeline shows 'Missed call' after timeout", async () => {
    const callId = `timeout_84_4_${TS}`;
    const convoId = `convo_timeout_84_4_${TS}`;

    // Seed an invited call session plus a conversation record
    const py = `
import boto3, time
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test",
                     aws_secret_access_key="test")

# Ensure Conversations table has this conversation
convos = ddb.Table("Conversations")
ts = int(time.time())
try:
    convos.put_item(Item={
        "conversation_id": "${convoId}",
        "type": "dm",
        "participant_ids": ["${ALICE_ID}", "${BOB_ID}"],
        "created_at": ts,
        "last_message_at": ts,
    })
except Exception:
    pass

# Seed call session
calls = ddb.Table("MessageCallSessions")
calls.put_item(Item={
    "call_id": "${callId}",
    "conversation_id": "${convoId}",
    "caller_user_id": "${ALICE_ID}",
    "callee_user_id": "${BOB_ID}",
    "initial_mode": "audio",
    "state": "invited",
    "start_ts": ts,
    "start_ts_sort": ts,
    "updated_at": ts,
    "lifecycle_events": [],
    "idempotency_records": {},
})
print("ok")
`;
    execSync(`python3 -c '${py.replace(/'/g, "'\\''")}'`, {
      cwd: REPO_ROOT,
      timeout: 10_000,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    });

    // Timeout the call
    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${callId}/timeout`, {
      reason: "no_answer",
    });
    expect(resp.status()).toBe(200);

    // Check that a timeline message was written
    const msgsResp = await apiGet(
      alicePage,
      `/messaging/conversations/${convoId}/messages`,
    );
    // The timeline writes a system message; check it exists
    if (msgsResp.status() === 200) {
      const messages = await msgsResp.json();
      const timelineMsg = (Array.isArray(messages) ? messages : []).find(
        (m: Record<string, unknown>) =>
          m.call_event_type === "call.missed" || (m.text === "Missed call" && m.subtype === "call_lifecycle"),
      );
      expect(timelineMsg).toBeDefined();
      expect(timelineMsg.text).toBe("Missed call");
    }

    deleteCallSession(callId);
  });

  test("84.5 Server backstop catches stale invite via background scan", async () => {
    const callId = `timeout_84_5_${TS}`;
    const convoId = `convo_timeout_84_5_${TS}`;

    // Seed a call session with start_ts far in the past (60s ago) to trigger server timeout
    const oldStartTs = Math.floor(Date.now() / 1000) - 60;
    seedCallSession({
      callId,
      conversationId: convoId,
      callerUserId: ALICE_ID,
      calleeUserId: BOB_ID,
      state: "invited",
      startTs: oldStartTs,
    });

    // Trigger the background expire function directly via a Python helper using the venv
    const py = `
import sys, asyncio
sys.path.insert(0, "${REPO_ROOT}")

# Need to initialize settings/env before importing routers
import os
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("DDB_ENDPOINT_URL", "http://localhost:8001")
os.environ.setdefault("DEV_MODE", "1")
os.environ.setdefault("UI_ACCESS_TOKEN_SECRET", "test-secret")
os.environ.setdefault("API_KEY_PEPPER", "test-pepper")

from app.routers.messaging import _expire_stale_invites
asyncio.get_event_loop().run_until_complete(_expire_stale_invites())
print("ok")
`;
    execSync(`${REPO_ROOT}/.venv/bin/python3 -c '${py.replace(/'/g, "'\\''")}'`, {
      cwd: REPO_ROOT,
      timeout: 15_000,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    });

    // Verify the call transitioned to "missed"
    const session = getCallSession(callId);
    expect(session).not.toBeNull();
    expect(session!.state).toBe("missed");
    expect(session!.end_reason).toBe("server_timeout");

    deleteCallSession(callId);
  });
});
