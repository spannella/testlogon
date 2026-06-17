/**
 * E2E tests for WebRTC Call Recording with Mutual Consent (CALL-009).
 *
 * Tests cover:
 * - Section 90: Recording Consent API (6 tests)
 * - Section 91: Recording Upload & Download API (7 tests)
 * - Section 92: Recording Lifecycle (5 tests)
 *
 * Auth: Cookie-based session auth (from e2e_admin_session_setup.py).
 * Call sessions are seeded directly in DynamoDB (MessageCallSessions table).
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
const CHARLIE_ID = "e2e_charlie@test.local";
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

async function apiDelete(page: Page, identity: string, path: string) {
  const s = getSessions()[identity];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": s.csrf_token },
  });
}

// ---------------------------------------------------------------------------
// DynamoDB helpers
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

function seedConversation(opts: {
  conversationId: string;
  participantIds: string[];
}): void {
  const py = `
import boto3, time
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test",
                     aws_secret_access_key="test")
table = ddb.Table("Conversations")
ts = int(time.time())
table.put_item(Item={
    "conversation_id": ${JSON.stringify(opts.conversationId)},
    "participant_ids": ${JSON.stringify(opts.participantIds)},
    "type": "dm",
    "created_at": ts,
    "last_message_at": ts,
    "updated_at": ts,
})
# Also seed participants
ptable = ddb.Table("Participants")
for uid in ${JSON.stringify(opts.participantIds)}:
    ptable.put_item(Item={
        "user_id": uid,
        "conversation_id": ${JSON.stringify(opts.conversationId)},
        "status": "active",
        "joined_at": ts,
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

function deleteRecording(recordingId: string): void {
  const py = `
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test",
                     aws_secret_access_key="test")
table = ddb.Table("CallRecordings")
table.delete_item(Key={"recording_id": ${JSON.stringify(recordingId)}})
print("ok")
`;
  try {
    execSync(`python3 -c '${py.replace(/'/g, "'\\''")}'`, {
      cwd: REPO_ROOT,
      timeout: 10_000,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    });
  } catch {
    // ignore
  }
}

// ---------------------------------------------------------------------------
// Detect whether recording feature is enabled
// ---------------------------------------------------------------------------

let _recordingEnabled: boolean | null = null;

async function isRecordingEnabled(page: Page): Promise<boolean> {
  if (_recordingEnabled !== null) return _recordingEnabled;

  const probeCallId = `probe_rec_${TS}`;
  const probeConvoId = `probe_rec_conv_${TS}`;
  seedConversation({
    conversationId: probeConvoId,
    participantIds: [ALICE_ID, BOB_ID],
  });
  seedCallSession({
    callId: probeCallId,
    conversationId: probeConvoId,
    callerUserId: ALICE_ID,
    calleeUserId: BOB_ID,
    state: "connected",
  });

  const resp = await apiPost(page, "alice", `/messages/calls/${probeCallId}/recording/request`);
  const status = resp.status();

  deleteCallSession(probeCallId);

  if (status === 200) {
    // Clean up the recording we just created
    const body = await resp.json();
    if (body.recording_id) deleteRecording(body.recording_id);
    _recordingEnabled = true;
  } else if (status === 503) {
    _recordingEnabled = false;
  } else {
    _recordingEnabled = true;
  }
  return _recordingEnabled;
}

// ===========================================================================
// Tests
// ===========================================================================

let alicePage: Page;
let bobPage: Page;

test.beforeAll(async ({ browser }) => {
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
  await alicePage?.context().close();
  await bobPage?.context().close();
});

// ---------------------------------------------------------------------------
// Section 90: Recording Consent Protocol (6 tests)
// ---------------------------------------------------------------------------

test.describe("Section 90 · Recording Consent API", () => {
  const CALL_ID_90 = `rec_call_90_${TS}`;
  const CONVO_ID_90 = `rec_convo_90_${TS}`;
  let recordingId: string;

  test.beforeAll(() => {
    seedConversation({
      conversationId: CONVO_ID_90,
      participantIds: [ALICE_ID, BOB_ID],
    });
    seedCallSession({
      callId: CALL_ID_90,
      conversationId: CONVO_ID_90,
      callerUserId: ALICE_ID,
      calleeUserId: BOB_ID,
      state: "connected",
    });
  });

  test.afterAll(() => {
    deleteCallSession(CALL_ID_90);
    if (recordingId) deleteRecording(recordingId);
  });

  test("90.1 Alice requests recording on an active call", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    const resp = await apiPost(alicePage, "alice", `/messages/calls/${CALL_ID_90}/recording/request`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.recording_id).toBeTruthy();
    expect(body.status).toBe("pending_consent");
    recordingId = body.recording_id;
  });

  test("90.2 Bob accepts recording request", async () => {
    const enabled = await isRecordingEnabled(bobPage);
    test.skip(!enabled, "Call recording feature is disabled");
    test.skip(!recordingId, "No recording to consent to");

    const resp = await apiPost(bobPage, "bob", `/messages/calls/${CALL_ID_90}/recording/consent`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.recording_id).toBe(recordingId);
    expect(body.status).toBe("recording");
    expect(body.started_at).toBeGreaterThan(0);
  });

  test("90.3 Only one active recording per call", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    // The previous test created a recording in "recording" state
    const resp = await apiPost(alicePage, "alice", `/messages/calls/${CALL_ID_90}/recording/request`);
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail.code).toBe("recording_already_active");
  });

  test("90.4 Recording request rejected when call not connected", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    const callId = `rec_call_90_4_${TS}`;
    const convoId = `rec_convo_90_4_${TS}`;
    seedConversation({
      conversationId: convoId,
      participantIds: [ALICE_ID, BOB_ID],
    });
    seedCallSession({
      callId,
      conversationId: convoId,
      callerUserId: ALICE_ID,
      calleeUserId: BOB_ID,
      state: "accepted",
    });

    const resp = await apiPost(alicePage, "alice", `/messages/calls/${callId}/recording/request`);
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail.code).toBe("invalid_state");

    deleteCallSession(callId);
  });

  test("90.5 Non-participant cannot request recording", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    // Create a new context for Charlie
    const charlieCtx = await alicePage.context().browser()!.newContext();
    const charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, "charlie_admin");
    await charliePage.goto(BASE);

    const callId = `rec_call_90_5_${TS}`;
    const convoId = `rec_convo_90_5_${TS}`;
    seedConversation({
      conversationId: convoId,
      participantIds: [ALICE_ID, BOB_ID],
    });
    seedCallSession({
      callId,
      conversationId: convoId,
      callerUserId: ALICE_ID,
      calleeUserId: BOB_ID,
      state: "connected",
    });

    const resp = await apiPost(charliePage, "charlie_admin", `/messages/calls/${callId}/recording/request`);
    expect(resp.status()).toBe(403);

    deleteCallSession(callId);
    await charlieCtx.close();
  });

  test("90.6 Bob can decline recording request", async () => {
    const enabled = await isRecordingEnabled(bobPage);
    test.skip(!enabled, "Call recording feature is disabled");

    // Create a fresh call and recording for decline test
    const callId = `rec_call_90_6_${TS}`;
    const convoId = `rec_convo_90_6_${TS}`;
    seedConversation({
      conversationId: convoId,
      participantIds: [ALICE_ID, BOB_ID],
    });
    seedCallSession({
      callId,
      conversationId: convoId,
      callerUserId: ALICE_ID,
      calleeUserId: BOB_ID,
      state: "connected",
    });

    // Alice requests
    const reqResp = await apiPost(alicePage, "alice", `/messages/calls/${callId}/recording/request`);
    expect(reqResp.status()).toBe(200);
    const reqBody = await reqResp.json();
    const recId = reqBody.recording_id;

    // Bob declines
    const decResp = await apiPost(bobPage, "bob", `/messages/calls/${callId}/recording/decline`);
    expect(decResp.status()).toBe(200);
    const decBody = await decResp.json();
    expect(decBody.ok).toBe(true);

    deleteCallSession(callId);
    deleteRecording(recId);
  });
});

// ---------------------------------------------------------------------------
// Section 91: Recording Upload & Download API (7 tests)
// ---------------------------------------------------------------------------

test.describe("Section 91 · Recording Upload & Download API", () => {
  const CALL_ID_91 = `rec_call_91_${TS}`;
  const CONVO_ID_91 = `rec_convo_91_${TS}`;
  let recordingId: string;

  test.beforeAll(async () => {
    seedConversation({
      conversationId: CONVO_ID_91,
      participantIds: [ALICE_ID, BOB_ID],
    });
    seedCallSession({
      callId: CALL_ID_91,
      conversationId: CONVO_ID_91,
      callerUserId: ALICE_ID,
      calleeUserId: BOB_ID,
      state: "connected",
    });
  });

  test.afterAll(() => {
    deleteCallSession(CALL_ID_91);
    if (recordingId) deleteRecording(recordingId);
  });

  test("91.1 Presign upload returns valid URL", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    // Create and consent to recording first
    const reqResp = await apiPost(alicePage, "alice", `/messages/calls/${CALL_ID_91}/recording/request`);
    expect(reqResp.status()).toBe(200);
    const reqBody = await reqResp.json();
    recordingId = reqBody.recording_id;

    const consentResp = await apiPost(bobPage, "bob", `/messages/calls/${CALL_ID_91}/recording/consent`);
    expect(consentResp.status()).toBe(200);

    // Get presigned upload URL
    const presignResp = await apiPost(alicePage, "alice", `/messages/calls/${CALL_ID_91}/recording/upload/presign`, {
      content_type: "video/webm",
      file_size_bytes: 1024,
    });
    expect(presignResp.status()).toBe(200);
    const presignBody = await presignResp.json();
    expect(presignBody.upload_url).toBeTruthy();
    expect(presignBody.recording_id).toBe(recordingId);
    expect(presignBody.s3_key).toContain("call-recordings/");
    expect(presignBody.expires_at).toBeGreaterThan(0);
  });

  test("91.2 Upload URL rejected for oversized file", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");
    test.skip(!recordingId, "No recording created");

    const resp = await apiPost(alicePage, "alice", `/messages/calls/${CALL_ID_91}/recording/upload/presign`, {
      content_type: "video/webm",
      file_size_bytes: 3 * 1024 * 1024 * 1024, // 3 GB > 2 GB limit
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail.code).toBe("file_too_large");
  });

  test("91.3 Complete upload transitions to ready", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");
    test.skip(!recordingId, "No recording created");

    const resp = await apiPost(alicePage, "alice", `/messages/calls/${CALL_ID_91}/recording/upload/complete`, {
      recording_id: recordingId,
      duration_seconds: 120.5,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.recording_id).toBe(recordingId);
    expect(body.status).toBe("ready");
  });

  test("91.4 Both participants can get recording metadata", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");
    test.skip(!recordingId, "No recording created");

    // Alice
    const aliceResp = await apiGet(alicePage, `/messages/calls/${CALL_ID_91}/recording`);
    expect(aliceResp.status()).toBe(200);
    const aliceBody = await aliceResp.json();
    expect(aliceBody.recording_id).toBe(recordingId);
    expect(aliceBody.status).toBe("ready");

    // Bob
    const bobResp = await apiGet(bobPage, `/messages/calls/${CALL_ID_91}/recording`);
    expect(bobResp.status()).toBe(200);
    const bobBody = await bobResp.json();
    expect(bobBody.recording_id).toBe(recordingId);
  });

  test("91.5 Both participants can download", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");
    test.skip(!recordingId, "No recording created");

    const aliceResp = await apiGet(alicePage, `/messages/recordings/${recordingId}/download`);
    expect(aliceResp.status()).toBe(200);
    const aliceBody = await aliceResp.json();
    expect(aliceBody.download_url).toBeTruthy();
    expect(aliceBody.filename).toContain("recording_");

    const bobResp = await apiGet(bobPage, `/messages/recordings/${recordingId}/download`);
    expect(bobResp.status()).toBe(200);
  });

  test("91.6 Non-participant cannot download", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");
    test.skip(!recordingId, "No recording created");

    const charlieCtx = await alicePage.context().browser()!.newContext();
    const charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, "charlie_admin");
    await charliePage.goto(BASE);

    const resp = await apiGet(charliePage, `/messages/recordings/${recordingId}/download`);
    expect(resp.status()).toBe(403);

    await charlieCtx.close();
  });

  test("91.7 Delete recording soft-deletes record", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");
    test.skip(!recordingId, "No recording created");

    const resp = await apiDelete(alicePage, "alice", `/messages/recordings/${recordingId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("deleted");

    // Subsequent download should fail
    const dlResp = await apiGet(alicePage, `/messages/recordings/${recordingId}/download`);
    expect(dlResp.status()).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// Section 92: Recording Lifecycle (5 tests)
// ---------------------------------------------------------------------------

test.describe("Section 92 · Recording Lifecycle", () => {
  test("92.1 Full recording lifecycle: request -> consent -> upload -> download", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    const callId = `rec_call_92_1_${TS}`;
    const convoId = `rec_convo_92_1_${TS}`;
    seedConversation({ conversationId: convoId, participantIds: [ALICE_ID, BOB_ID] });
    seedCallSession({ callId, conversationId: convoId, callerUserId: ALICE_ID, calleeUserId: BOB_ID, state: "connected" });

    // Request
    const reqResp = await apiPost(alicePage, "alice", `/messages/calls/${callId}/recording/request`);
    expect(reqResp.status()).toBe(200);
    const recId = (await reqResp.json()).recording_id;

    // Consent
    const consentResp = await apiPost(bobPage, "bob", `/messages/calls/${callId}/recording/consent`);
    expect(consentResp.status()).toBe(200);
    expect((await consentResp.json()).status).toBe("recording");

    // Presign upload
    const presignResp = await apiPost(alicePage, "alice", `/messages/calls/${callId}/recording/upload/presign`, {
      content_type: "video/webm", file_size_bytes: 512,
    });
    expect(presignResp.status()).toBe(200);

    // Complete upload
    const completeResp = await apiPost(alicePage, "alice", `/messages/calls/${callId}/recording/upload/complete`, {
      recording_id: recId, duration_seconds: 60,
    });
    expect(completeResp.status()).toBe(200);
    expect((await completeResp.json()).status).toBe("ready");

    // Download
    const dlResp = await apiGet(alicePage, `/messages/recordings/${recId}/download`);
    expect(dlResp.status()).toBe(200);
    expect((await dlResp.json()).download_url).toBeTruthy();

    deleteCallSession(callId);
    deleteRecording(recId);
  });

  test("92.2 Get recording for call returns metadata", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    const callId = `rec_call_92_2_${TS}`;
    const convoId = `rec_convo_92_2_${TS}`;
    seedConversation({ conversationId: convoId, participantIds: [ALICE_ID, BOB_ID] });
    seedCallSession({ callId, conversationId: convoId, callerUserId: ALICE_ID, calleeUserId: BOB_ID, state: "connected" });

    const reqResp = await apiPost(alicePage, "alice", `/messages/calls/${callId}/recording/request`);
    const recId = (await reqResp.json()).recording_id;

    const getResp = await apiGet(alicePage, `/messages/calls/${callId}/recording`);
    expect(getResp.status()).toBe(200);
    const body = await getResp.json();
    expect(body.call_id).toBe(callId);
    expect(body.conversation_id).toBe(convoId);
    expect(body.participants).toContain(ALICE_ID);
    expect(body.participants).toContain(BOB_ID);

    deleteCallSession(callId);
    deleteRecording(recId);
  });

  test("92.3 List user recordings returns recorded calls", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    const callId = `rec_call_92_3_${TS}`;
    const convoId = `rec_convo_92_3_${TS}`;
    seedConversation({ conversationId: convoId, participantIds: [ALICE_ID, BOB_ID] });
    seedCallSession({ callId, conversationId: convoId, callerUserId: ALICE_ID, calleeUserId: BOB_ID, state: "connected" });

    const reqResp = await apiPost(alicePage, "alice", `/messages/calls/${callId}/recording/request`);
    const recId = (await reqResp.json()).recording_id;

    const listResp = await apiGet(alicePage, `/messages/recordings`);
    expect(listResp.status()).toBe(200);
    const body = await listResp.json();
    expect(body.items).toBeDefined();
    expect(Array.isArray(body.items)).toBe(true);
    // Our recording should be in the list
    const found = body.items.find((r: { recording_id: string }) => r.recording_id === recId);
    expect(found).toBeTruthy();

    deleteCallSession(callId);
    deleteRecording(recId);
  });

  test("92.4 Recording metadata includes correct call info", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    const callId = `rec_call_92_4_${TS}`;
    const convoId = `rec_convo_92_4_${TS}`;
    seedConversation({ conversationId: convoId, participantIds: [ALICE_ID, BOB_ID] });
    seedCallSession({ callId, conversationId: convoId, callerUserId: ALICE_ID, calleeUserId: BOB_ID, state: "connected" });

    const reqResp = await apiPost(alicePage, "alice", `/messages/calls/${callId}/recording/request`);
    const recId = (await reqResp.json()).recording_id;

    const consentResp = await apiPost(bobPage, "bob", `/messages/calls/${callId}/recording/consent`);
    expect(consentResp.status()).toBe(200);

    // Presign + complete
    await apiPost(alicePage, "alice", `/messages/calls/${callId}/recording/upload/presign`, {
      content_type: "video/webm", file_size_bytes: 256,
    });
    await apiPost(alicePage, "alice", `/messages/calls/${callId}/recording/upload/complete`, {
      recording_id: recId, duration_seconds: 42.5,
    });

    const getResp = await apiGet(alicePage, `/messages/calls/${callId}/recording`);
    expect(getResp.status()).toBe(200);
    const body = await getResp.json();
    expect(body.status).toBe("ready");
    expect(body.initiated_by).toBe(ALICE_ID);
    expect(body.duration_seconds).toBe(42.5);
    expect(body.download_url).toBeTruthy();

    deleteCallSession(callId);
    deleteRecording(recId);
  });

  test("92.5 Call not found returns 404", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    const resp = await apiPost(alicePage, "alice", `/messages/calls/nonexistent_call_id/recording/request`);
    expect(resp.status()).toBe(404);
    const body = await resp.json();
    expect(body.detail.code).toBe("call_not_found");
  });
});
