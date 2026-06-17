/**
 * E2E tests for WebRTC TURN credential issuance.
 *
 * Endpoint under test:
 *   POST /messaging/messages/calls/{call_id}/turn-credentials
 *
 * Auth: Cookie-based session auth (from e2e_admin_session_setup.py).
 *
 * The TURN feature is gated by MESSAGING_WEBRTC_TURN_ENABLED. When disabled
 * (the default in dev), the endpoint returns 403 with code "feature_disabled".
 * When enabled but no call session exists, the endpoint returns 404 with code
 * "call_not_found". Tests cover both paths plus auth enforcement.
 *
 * To test the success path (actual credential issuance), the env must have:
 *   MESSAGING_WEBRTC_TURN_ENABLED=true
 *   MESSAGING_WEBRTC_TURN_URLS=turn:turn.example.com:3478
 *   MESSAGING_WEBRTC_TURN_SECRET=some-secret
 * AND a valid call session must be seeded in DynamoDB.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const API = "http://localhost:8000";
const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();
const TURN_PATH = (callId: string) =>
  `/messaging/messages/calls/${callId}/turn-credentials`;

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
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
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
}): void {
  const py = `
import json, sys, boto3, time
sys.path.insert(0, "${REPO_ROOT}")
from app.core.settings import S
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test",
                     aws_secret_access_key="test")
table = ddb.Table("MessageCallSessions")
ts = int(time.time())
table.put_item(Item={
    "call_id": ${JSON.stringify(opts.callId)},
    "conversation_id": ${JSON.stringify(opts.conversationId)},
    "caller_user_id": ${JSON.stringify(opts.callerUserId)},
    "callee_user_id": ${JSON.stringify(opts.calleeUserId)},
    "initial_mode": "audio",
    "state": ${JSON.stringify(opts.state)},
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

// ---------------------------------------------------------------------------
// Detect whether TURN feature is enabled
// ---------------------------------------------------------------------------

let _turnEnabled: boolean | null = null;

/**
 * Probe the endpoint with a valid auth session and a seeded call to
 * distinguish "feature_disabled" (403) from other error codes.
 * We seed a throwaway call session so the only possible 403 is from the
 * feature flag, not from a "forbidden" (wrong participant) error.
 */
async function isTurnEnabled(page: Page): Promise<boolean> {
  if (_turnEnabled !== null) return _turnEnabled;

  const probeCallId = `probe_turn_${TS}`;
  seedCallSession({
    callId: probeCallId,
    conversationId: `probe_convo_${TS}`,
    callerUserId: ALICE_ID,
    calleeUserId: BOB_ID,
    state: "accepted",
  });

  const resp = await apiPost(page, "alice", TURN_PATH(probeCallId));
  const status = resp.status();

  deleteCallSession(probeCallId);

  if (status === 200) {
    _turnEnabled = true;
  } else if (status === 403) {
    const body = await resp.json();
    _turnEnabled = body?.detail?.code !== "feature_disabled";
  } else {
    // 503 (not configured) means enabled but misconfigured — still "enabled"
    _turnEnabled = status !== 403;
  }
  return _turnEnabled;
}

// ===========================================================================
// Tests
// ===========================================================================

test.describe("73 — WebRTC TURN credentials", () => {
  const CALL_ID_VALID = `e2e_turn_call_${TS}`;
  const CONVO_ID = `e2e_turn_convo_${TS}`;

  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, "alice");
    // Navigate to BASE so cookies are attached to localhost origin
    await alicePage.goto(BASE);

    // Seed a call session where Alice is caller and Bob is callee
    seedCallSession({
      callId: CALL_ID_VALID,
      conversationId: CONVO_ID,
      callerUserId: ALICE_ID,
      calleeUserId: BOB_ID,
      state: "accepted",
    });
  });

  test.afterAll(async () => {
    deleteCallSession(CALL_ID_VALID);
    await alicePage?.context().close();
  });

  // ── 73.1  Missing auth returns 401 ──────────────────────────────────────

  test("73.1 — request without auth returns 401", async ({ request }) => {
    const resp = await request.post(
      `${API}${TURN_PATH("no_auth_call")}`,
    );
    expect(resp.status()).toBe(401);
  });

  // ── 73.2  Feature-disabled or success path ─────────────────────────────

  test("73.2 — TURN credentials request returns structured response", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      TURN_PATH(CALL_ID_VALID),
    );
    const status = resp.status();
    const body = await resp.json();

    const enabled = await isTurnEnabled(alicePage);

    if (enabled && status === 200) {
      // Feature enabled + TURN configured + valid call session
      expect(body).toHaveProperty("ttl_seconds");
      expect(typeof body.ttl_seconds).toBe("number");
      expect(body).toHaveProperty("expires_at");
      expect(typeof body.expires_at).toBe("number");
      expect(body).toHaveProperty("ice_servers");
      expect(Array.isArray(body.ice_servers)).toBe(true);
      expect(body.ice_servers.length).toBeGreaterThan(0);
      const server = body.ice_servers[0];
      expect(server).toHaveProperty("urls");
      expect(server).toHaveProperty("username");
      expect(server).toHaveProperty("credential");
    } else {
      // Feature disabled (403) or TURN not configured (503)
      expect([403, 503]).toContain(status);
      expect(body).toHaveProperty("detail");
      expect(body.detail).toHaveProperty("code");
      expect(body.detail).toHaveProperty("message");
      expect(typeof body.detail.code).toBe("string");
      expect(typeof body.detail.message).toBe("string");
    }
  });

  // ── 73.3  Non-existent call ID ─────────────────────────────────────────

  test("73.3 — non-existent call_id returns 404 or 403 (feature disabled)", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      TURN_PATH(`nonexistent_call_${TS}`),
    );
    const status = resp.status();
    const body = await resp.json();

    // If TURN feature is disabled, we get 403 before any call lookup
    // If enabled, we get 404 (call_not_found)
    expect([403, 404]).toContain(status);
    expect(body).toHaveProperty("detail");
    expect(body.detail).toHaveProperty("code");
    expect(body.detail).toHaveProperty("message");

    if (status === 404) {
      expect(body.detail.code).toBe("call_not_found");
    } else {
      expect(body.detail.code).toBe("feature_disabled");
    }
  });

  // ── 73.4  Repeated requests succeed consistently ───────────────────────

  test("73.4 — multiple requests for same call_id return consistent responses", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 3; i++) {
      const resp = await apiPost(
        alicePage,
        "alice",
        TURN_PATH(CALL_ID_VALID),
      );
      statuses.push(resp.status());
      const body = await resp.json();
      expect(body).toHaveProperty("detail" in body ? "detail" : "ttl_seconds");
    }
    // All three requests should return the same status code
    expect(statuses[0]).toBe(statuses[1]);
    expect(statuses[1]).toBe(statuses[2]);
  });

  // ── 73.5  Bob can also request credentials for the same call ───────────

  test("73.5 — different user (Bob) can request credentials for same call", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const bobPage = await ctx.newPage();
    await injectAuth(bobPage, "bob");
    await bobPage.goto(BASE);

    const resp = await apiPost(
      bobPage,
      "bob",
      TURN_PATH(CALL_ID_VALID),
    );
    const status = resp.status();
    const body = await resp.json();

    // Either success (200) or feature disabled (403) or not configured (503)
    expect([200, 403, 503]).toContain(status);

    if (status === 200) {
      expect(body).toHaveProperty("ice_servers");
      expect(body.ice_servers[0]).toHaveProperty("username");
      // Bob's username should include Bob's user ID
      expect(body.ice_servers[0].username).toContain(BOB_ID);
    } else {
      expect(body).toHaveProperty("detail");
      expect(body.detail).toHaveProperty("code");
    }

    await ctx.close();
  });

  // ── 73.6  Non-participant gets 403 ─────────────────────────────────────

  test("73.6 — non-participant of call gets 403 (forbidden or feature_disabled)", async ({
    browser,
  }) => {
    // Seed a call where neither Alice nor Bob are participants
    const isolatedCallId = `e2e_isolated_call_${TS}`;
    seedCallSession({
      callId: isolatedCallId,
      conversationId: `e2e_isolated_convo_${TS}`,
      callerUserId: "other_user_1@test.local",
      calleeUserId: "other_user_2@test.local",
      state: "accepted",
    });

    try {
      const resp = await apiPost(
        alicePage,
        "alice",
        TURN_PATH(isolatedCallId),
      );
      const status = resp.status();
      const body = await resp.json();

      // 403 from either feature_disabled or forbidden (not a participant)
      expect(status).toBe(403);
      expect(body).toHaveProperty("detail");
      expect(["feature_disabled", "forbidden"]).toContain(body.detail.code);
    } finally {
      deleteCallSession(isolatedCallId);
    }
  });

  // ── 73.7  Ended call returns 409 or 403 ────────────────────────────────

  test("73.7 — ended call returns 409 (invalid_state) or 403 (feature_disabled)", async () => {
    const endedCallId = `e2e_ended_call_${TS}`;
    seedCallSession({
      callId: endedCallId,
      conversationId: `e2e_ended_convo_${TS}`,
      callerUserId: ALICE_ID,
      calleeUserId: BOB_ID,
      state: "ended",
    });

    try {
      const resp = await apiPost(
        alicePage,
        "alice",
        TURN_PATH(endedCallId),
      );
      const status = resp.status();
      const body = await resp.json();

      // 403 if feature disabled (checked first), 409 if call in invalid state
      expect([403, 409]).toContain(status);
      expect(body).toHaveProperty("detail");

      if (status === 409) {
        expect(body.detail.code).toBe("invalid_state");
        expect(body.detail.message).toContain("ended");
      } else {
        expect(body.detail.code).toBe("feature_disabled");
      }
    } finally {
      deleteCallSession(endedCallId);
    }
  });

  // ── 73.8  Error response always has code + message ─────────────────────

  test("73.8 — error responses always include code and message fields", async () => {
    // Request for a call_id that does not exist to force an error
    const resp = await apiPost(
      alicePage,
      "alice",
      TURN_PATH(`e2e_error_shape_${TS}`),
    );
    const status = resp.status();
    // Any non-200 status should have the structured error body
    expect(status).toBeGreaterThanOrEqual(400);

    const body = await resp.json();
    expect(body).toHaveProperty("detail");
    expect(body.detail).toHaveProperty("code");
    expect(body.detail).toHaveProperty("message");
    expect(typeof body.detail.code).toBe("string");
    expect(typeof body.detail.message).toBe("string");
    expect(body.detail.code.length).toBeGreaterThan(0);
    expect(body.detail.message.length).toBeGreaterThan(0);
  });
});

// ===========================================================================
// 74 — Call Lifecycle: Invite
// ===========================================================================

function seedConversation(conversationId: string, participantIds: string[]): void {
  const py = `
import boto3, time
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test",
                     aws_secret_access_key="test")
table = ddb.Table("Conversations")
ts = int(time.time())
cid = ${JSON.stringify("__CONVO_ID__")}
pids = ${JSON.stringify("__PARTICIPANTS__")}
table.put_item(Item={
    "conversation_id": cid,
    "participant_ids": pids,
    "type": "dm",
    "created_at": ts,
    "last_message_at": ts,
    "updated_at": ts,
})
# Call lifecycle resolves participants from the Participants table via GSI1
# (GSI1PK=conversation_id). One row per participant — mirror production schema.
ptable = ddb.Table("Participants")
for pid in pids:
    ptable.put_item(Item={
        "user_id": pid,
        "conversation_id": cid,
        "status": "active",
        "role": "member",
        "muted_until": 0,
        "last_read_at": 0,
        "unread_count": 0,
        "joined_at": ts,
        "left_at": 0,
        "GSI1PK": cid,
        "GSI1SK": pid,
    })
print("ok")
`.replace("__CONVO_ID__", conversationId).replace('"__PARTICIPANTS__"', JSON.stringify(participantIds));
  execSync(`python3 -c '${py.replace(/'/g, "'\\''")}'`, {
    cwd: REPO_ROOT,
    timeout: 10_000,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
  });
}

function deleteConversation(conversationId: string): void {
  const py = `
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test",
                     aws_secret_access_key="test")
table = ddb.Table("Conversations")
table.delete_item(Key={"conversation_id": ${JSON.stringify(conversationId)}})
print("ok")
`;
  try {
    execSync(`python3 -c '${py.replace(/'/g, "'\\''")}'`, {
      cwd: REPO_ROOT,
      timeout: 10_000,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    });
  } catch { /* ignore */ }
}

test.describe("74 — Call Lifecycle: Invite Flow", () => {
  const CONVO_ID = `e2e_call_convo_${TS}`;
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    seedConversation(CONVO_ID, [ALICE_ID, BOB_ID]);

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");
    await alicePage.goto(BASE);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, "bob");
    await bobPage.goto(BASE);
  });

  test.afterAll(async () => {
    deleteConversation(CONVO_ID);
    await alicePage?.context().close();
    await bobPage?.context().close();
  });

  test("74.1 — Alice creates a call invite", async () => {
    const callId = `e2e_invite_${TS}_1`;
    const resp = await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: callId,
      conversation_id: CONVO_ID,
      callee_user_id: BOB_ID,
      initial_mode: "audio",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.call_id).toBe(callId);
    expect(body.conversation_id).toBe(CONVO_ID);
    expect(body.caller_user_id).toBe(ALICE_ID);
    expect(body.callee_user_id).toBe(BOB_ID);
    expect(body.state).toBe("invited");
    expect(body.initial_mode).toBe("audio");
    expect(typeof body.start_ts).toBe("number");
    deleteCallSession(callId);
  });

  test("74.2 — duplicate call_id returns 409", async () => {
    const callId = `e2e_invite_${TS}_2`;
    const resp1 = await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: callId,
      conversation_id: CONVO_ID,
      callee_user_id: BOB_ID,
      initial_mode: "audio",
    });
    expect(resp1.status()).toBe(200);

    const resp2 = await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: callId,
      conversation_id: CONVO_ID,
      callee_user_id: BOB_ID,
      initial_mode: "audio",
    });
    expect(resp2.status()).toBe(409);
    const body = await resp2.json();
    expect(body.detail.code).toBe("duplicate_call_id");
    deleteCallSession(callId);
  });

  test("74.3 — non-participant cannot create invite", async ({ browser }) => {
    const charlieCtx = await browser.newContext();
    const charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, "charlie_admin");
    await charliePage.goto(BASE);

    const resp = await apiPost(charliePage, "charlie_admin", "/messaging/messages/calls/invite", {
      call_id: `e2e_invite_${TS}_3`,
      conversation_id: CONVO_ID,
      callee_user_id: BOB_ID,
      initial_mode: "audio",
    });
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.detail.code).toBe("forbidden");
    await charlieCtx.close();
  });

  test("74.4 — idempotent retry with same key returns same result", async () => {
    const callId = `e2e_invite_${TS}_4`;
    const idemKey = `idem_${TS}_4`;
    const body1 = { call_id: callId, conversation_id: CONVO_ID, callee_user_id: BOB_ID, initial_mode: "video", idempotency_key: idemKey };

    const resp1 = await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", body1);
    expect(resp1.status()).toBe(200);
    const data1 = await resp1.json();

    const resp2 = await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", body1);
    expect(resp2.status()).toBe(200);
    const data2 = await resp2.json();
    expect(data2.call_id).toBe(data1.call_id);
    expect(data2.state).toBe("invited");
    deleteCallSession(callId);
  });

  test("74.5 — request without auth returns 401", async ({ request }) => {
    const resp = await request.post(`${API}/messaging/messages/calls/invite`, {
      data: { call_id: "noauth", conversation_id: CONVO_ID, callee_user_id: BOB_ID, initial_mode: "audio" },
    });
    expect(resp.status()).toBe(401);
  });
});

// ===========================================================================
// 75 — Call Lifecycle: Accept / Decline
// ===========================================================================

test.describe("75 — Call Lifecycle: Accept & Decline", () => {
  const CONVO_ID = `e2e_ad_convo_${TS}`;
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    seedConversation(CONVO_ID, [ALICE_ID, BOB_ID]);
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");
    await alicePage.goto(BASE);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, "bob");
    await bobPage.goto(BASE);
  });

  test.afterAll(async () => {
    deleteConversation(CONVO_ID);
    await alicePage?.context().close();
    await bobPage?.context().close();
  });

  test("75.1 — Bob accepts Alice's invite", async () => {
    const callId = `e2e_accept_${TS}_1`;
    const invResp = await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: callId, conversation_id: CONVO_ID, callee_user_id: BOB_ID, initial_mode: "audio",
    });
    expect(invResp.status()).toBe(200);

    const resp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${callId}/accept`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.call_id).toBe(callId);
    expect(body.state).toBe("accepted");
    expect(body.from_state).toBe("invited");
    deleteCallSession(callId);
  });

  test("75.2 — only callee can accept (Alice gets 403)", async () => {
    const callId = `e2e_accept_${TS}_2`;
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: callId, conversation_id: CONVO_ID, callee_user_id: BOB_ID, initial_mode: "audio",
    });

    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${callId}/accept`);
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.detail.code).toBe("forbidden");
    deleteCallSession(callId);
  });

  test("75.3 — Bob declines Alice's invite", async () => {
    const callId = `e2e_decline_${TS}_3`;
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: callId, conversation_id: CONVO_ID, callee_user_id: BOB_ID, initial_mode: "audio",
    });

    const resp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${callId}/decline`, {
      reason: "declined",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.call_id).toBe(callId);
    expect(body.state).toBe("declined");
    expect(body.reason).toBe("declined");
    deleteCallSession(callId);
  });

  test("75.4 — decline with reason=busy sets state to busy", async () => {
    const callId = `e2e_decline_${TS}_4`;
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: callId, conversation_id: CONVO_ID, callee_user_id: BOB_ID, initial_mode: "audio",
    });

    const resp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${callId}/decline`, {
      reason: "busy",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.state).toBe("busy");
    deleteCallSession(callId);
  });

  test("75.5 — accept already-declined call returns 409", async () => {
    const callId = `e2e_decline_${TS}_5`;
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: callId, conversation_id: CONVO_ID, callee_user_id: BOB_ID, initial_mode: "audio",
    });
    await apiPost(bobPage, "bob", `/messaging/messages/calls/${callId}/decline`);

    const resp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${callId}/accept`);
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail.code).toBe("invalid_state_transition");
    deleteCallSession(callId);
  });
});

// ===========================================================================
// 76 — Call Lifecycle: End Call
// ===========================================================================

test.describe("76 — Call Lifecycle: End Call", () => {
  const CONVO_ID = `e2e_end_convo_${TS}`;
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    seedConversation(CONVO_ID, [ALICE_ID, BOB_ID]);
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");
    await alicePage.goto(BASE);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, "bob");
    await bobPage.goto(BASE);
  });

  test.afterAll(async () => {
    deleteConversation(CONVO_ID);
    await alicePage?.context().close();
    await bobPage?.context().close();
  });

  test("76.1 — either participant ends accepted call → state=ended", async () => {
    const callId = `e2e_end_${TS}_1`;
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: callId, conversation_id: CONVO_ID, callee_user_id: BOB_ID, initial_mode: "audio",
    });
    await apiPost(bobPage, "bob", `/messaging/messages/calls/${callId}/accept`);

    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${callId}/end`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.state).toBe("ended");
    expect(body.from_state).toBe("accepted");
    deleteCallSession(callId);
  });

  test("76.2 — end invited call → state=canceled", async () => {
    const callId = `e2e_end_${TS}_2`;
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: callId, conversation_id: CONVO_ID, callee_user_id: BOB_ID, initial_mode: "audio",
    });

    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${callId}/end`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.state).toBe("canceled");
    expect(body.from_state).toBe("invited");
    deleteCallSession(callId);
  });

  test("76.3 — end already-ended call returns 409", async () => {
    const callId = `e2e_end_${TS}_3`;
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: callId, conversation_id: CONVO_ID, callee_user_id: BOB_ID, initial_mode: "audio",
    });
    await apiPost(bobPage, "bob", `/messaging/messages/calls/${callId}/accept`);
    await apiPost(alicePage, "alice", `/messaging/messages/calls/${callId}/end`);

    const resp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${callId}/end`);
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail.code).toBe("invalid_state_transition");
    deleteCallSession(callId);
  });

  test("76.4 — non-participant cannot end call", async ({ browser }) => {
    const callId = `e2e_end_${TS}_4`;
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: callId, conversation_id: CONVO_ID, callee_user_id: BOB_ID, initial_mode: "audio",
    });

    const charlieCtx = await browser.newContext();
    const charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, "charlie_admin");
    await charliePage.goto(BASE);

    const resp = await apiPost(charliePage, "charlie_admin", `/messaging/messages/calls/${callId}/end`);
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.detail.code).toBe("forbidden");
    await charlieCtx.close();
    deleteCallSession(callId);
  });
});

// ===========================================================================
// 77 — Call Lifecycle: Full Happy Path
// ===========================================================================

test.describe("77 — Call Lifecycle: Full Happy Path", () => {
  const CONVO_ID = `e2e_happy_convo_${TS}`;
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    seedConversation(CONVO_ID, [ALICE_ID, BOB_ID]);
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");
    await alicePage.goto(BASE);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, "bob");
    await bobPage.goto(BASE);
  });

  test.afterAll(async () => {
    deleteConversation(CONVO_ID);
    await alicePage?.context().close();
    await bobPage?.context().close();
  });

  test("77.1 — invite → accept → end (happy path)", async () => {
    const callId = `e2e_happy_${TS}_1`;

    const invResp = await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: callId, conversation_id: CONVO_ID, callee_user_id: BOB_ID, initial_mode: "video",
    });
    expect(invResp.status()).toBe(200);
    const invBody = await invResp.json();
    expect(invBody.state).toBe("invited");
    expect(invBody.initial_mode).toBe("video");

    const accResp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${callId}/accept`);
    expect(accResp.status()).toBe(200);
    const accBody = await accResp.json();
    expect(accBody.state).toBe("accepted");

    const endResp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${callId}/end`);
    expect(endResp.status()).toBe(200);
    const endBody = await endResp.json();
    expect(endBody.state).toBe("ended");
    deleteCallSession(callId);
  });

  test("77.2 — invite → decline (terminal state)", async () => {
    const callId = `e2e_happy_${TS}_2`;

    const invResp = await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: callId, conversation_id: CONVO_ID, callee_user_id: BOB_ID, initial_mode: "audio",
    });
    expect(invResp.status()).toBe(200);

    const decResp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${callId}/decline`);
    expect(decResp.status()).toBe(200);
    const decBody = await decResp.json();
    expect(decBody.state).toBe("declined");

    const endResp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${callId}/end`);
    expect(endResp.status()).toBe(409);
    deleteCallSession(callId);
  });
});
