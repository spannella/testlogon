/**
 * CALL-009: E2E Integration Tests for Call Recording
 *
 * These tests cover the integration scenarios for call recording that
 * complement the unit-level tests in call-recording.spec.ts (sections 90-92).
 *
 * Sections:
 *   131 — Recording Consent Protocol (6 tests)
 *   132 — Recording Upload & Download (5 tests)
 *   133 — Recording Edge Cases (3 tests)
 *
 * Auth: Cookie-based session auth (from e2e_admin_session_setup.py).
 * Call sessions are seeded directly in DynamoDB.
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

async function apiPost(page: Page, identity: string, path: string, body: object = {}) {
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

function deleteCallSession(callId: string): void {
  const py = `
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test",
                     aws_secret_access_key="test")
ddb.Table("MessageCallSessions").delete_item(Key={"call_id": ${JSON.stringify(callId)}})
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
ddb.Table("CallRecordings").delete_item(Key={"recording_id": ${JSON.stringify(recordingId)}})
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
// Feature detection
// ---------------------------------------------------------------------------

let _recordingEnabled: boolean | null = null;

async function isRecordingEnabled(page: Page): Promise<boolean> {
  if (_recordingEnabled !== null) return _recordingEnabled;

  const probeCallId = `crinte_probe_${TS}`;
  const probeConvoId = `crinte_probe_conv_${TS}`;
  seedConversation({ conversationId: probeConvoId, participantIds: [ALICE_ID, BOB_ID] });
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
// Shared page setup
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
// Section 131: Recording Consent Protocol (6 tests)
// ---------------------------------------------------------------------------

test.describe("131 — Recording Consent Protocol", () => {
  const CALL_ID = `crinte_131_${TS}`;
  const CONVO_ID = `crinte_131_conv_${TS}`;
  let recordingId: string;

  test.beforeAll(() => {
    seedConversation({ conversationId: CONVO_ID, participantIds: [ALICE_ID, BOB_ID] });
    seedCallSession({
      callId: CALL_ID,
      conversationId: CONVO_ID,
      callerUserId: ALICE_ID,
      calleeUserId: BOB_ID,
      state: "connected",
    });
  });

  test.afterAll(() => {
    deleteCallSession(CALL_ID);
    if (recordingId) deleteRecording(recordingId);
  });

  test("131.1 Seed call in connected state → recording request returns 200 with recording_id", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    const resp = await apiPost(alicePage, "alice", `/messages/calls/${CALL_ID}/recording/request`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.recording_id).toBeTruthy();
    expect(body.status).toBe("pending_consent");
    expect(body.created_at).toBeGreaterThan(0);
    recordingId = body.recording_id;
  });

  test("131.2 Pending recording transitions to recording on consent", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");
    test.skip(!recordingId, "No recording created");

    const resp = await apiPost(bobPage, "bob", `/messages/calls/${CALL_ID}/recording/consent`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.recording_id).toBe(recordingId);
    expect(body.status).toBe("recording");
    expect(body.started_at).toBeGreaterThan(0);
  });

  test("131.3 Duplicate recording request → 409 recording_already_active", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    const resp = await apiPost(alicePage, "alice", `/messages/calls/${CALL_ID}/recording/request`);
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail.code).toBe("recording_already_active");
  });

  test("131.4 Non-participant cannot request recording → 403", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    const callId = `crinte_131_4_${TS}`;
    const convoId = `crinte_131_4_conv_${TS}`;
    seedConversation({ conversationId: convoId, participantIds: [ALICE_ID, BOB_ID] });
    seedCallSession({
      callId,
      conversationId: convoId,
      callerUserId: ALICE_ID,
      calleeUserId: BOB_ID,
      state: "connected",
    });

    const charlieCtx = await alicePage.context().browser()!.newContext();
    const charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, "charlie_admin");
    await charliePage.goto(BASE);

    const resp = await apiPost(charliePage, "charlie_admin", `/messages/calls/${callId}/recording/request`);
    expect(resp.status()).toBe(403);

    deleteCallSession(callId);
    await charlieCtx.close();
  });

  test("131.5 Decline removes pending recording → decline returns ok", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    // Create a fresh call for this test
    const callId = `crinte_131_5_${TS}`;
    const convoId = `crinte_131_5_conv_${TS}`;
    seedConversation({ conversationId: convoId, participantIds: [ALICE_ID, BOB_ID] });
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
    const recId = (await reqResp.json()).recording_id;

    // Bob declines
    const decResp = await apiPost(bobPage, "bob", `/messages/calls/${callId}/recording/decline`);
    expect(decResp.status()).toBe(200);
    const decBody = await decResp.json();
    expect(decBody.ok).toBe(true);

    deleteCallSession(callId);
    deleteRecording(recId);
  });

  test("131.6 Self-consent rejected → 400 self_consent", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    // Create a fresh call where Alice both requests and tries to consent
    const callId = `crinte_131_6_${TS}`;
    const convoId = `crinte_131_6_conv_${TS}`;
    seedConversation({ conversationId: convoId, participantIds: [ALICE_ID, BOB_ID] });
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
    const recId = (await reqResp.json()).recording_id;

    // Alice tries to consent to her own request
    const selfConsentResp = await apiPost(alicePage, "alice", `/messages/calls/${callId}/recording/consent`);
    expect(selfConsentResp.status()).toBe(400);
    const body = await selfConsentResp.json();
    expect(body.detail.code).toBe("self_consent");

    deleteCallSession(callId);
    deleteRecording(recId);
  });
});

// ---------------------------------------------------------------------------
// Section 132: Recording Upload & Download (5 tests)
// ---------------------------------------------------------------------------

test.describe("132 — Recording Upload & Download", () => {
  const CALL_ID = `crinte_132_${TS}`;
  const CONVO_ID = `crinte_132_conv_${TS}`;
  let recordingId: string;

  test.beforeAll(async () => {
    seedConversation({ conversationId: CONVO_ID, participantIds: [ALICE_ID, BOB_ID] });
    seedCallSession({
      callId: CALL_ID,
      conversationId: CONVO_ID,
      callerUserId: ALICE_ID,
      calleeUserId: BOB_ID,
      state: "connected",
    });
  });

  test.afterAll(() => {
    deleteCallSession(CALL_ID);
    if (recordingId) deleteRecording(recordingId);
  });

  test("132.1 Presign upload returns valid URL and s3_key", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    // Create and consent to a recording first
    const reqResp = await apiPost(alicePage, "alice", `/messages/calls/${CALL_ID}/recording/request`);
    expect(reqResp.status()).toBe(200);
    recordingId = (await reqResp.json()).recording_id;

    const consentResp = await apiPost(bobPage, "bob", `/messages/calls/${CALL_ID}/recording/consent`);
    expect(consentResp.status()).toBe(200);

    // Presign
    const presignResp = await apiPost(alicePage, "alice", `/messages/calls/${CALL_ID}/recording/upload/presign`, {
      content_type: "video/webm",
      file_size_bytes: 2048,
    });
    expect(presignResp.status()).toBe(200);
    const presignBody = await presignResp.json();
    expect(presignBody.upload_url).toBeTruthy();
    expect(presignBody.recording_id).toBe(recordingId);
    expect(presignBody.s3_key).toContain("call-recordings/");
    expect(presignBody.expires_at).toBeGreaterThan(0);
  });

  test("132.2 Complete upload transitions status to ready", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");
    test.skip(!recordingId, "No recording created in 132.1");

    const resp = await apiPost(alicePage, "alice", `/messages/calls/${CALL_ID}/recording/upload/complete`, {
      recording_id: recordingId,
      duration_seconds: 85.3,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.recording_id).toBe(recordingId);
    expect(body.status).toBe("ready");
  });

  test("132.3 Both participants can download the recording", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");
    test.skip(!recordingId, "No recording created in 132.1");

    // Alice downloads
    const aliceResp = await apiGet(alicePage, `/messages/recordings/${recordingId}/download`);
    expect(aliceResp.status()).toBe(200);
    const aliceBody = await aliceResp.json();
    expect(aliceBody.download_url).toBeTruthy();
    expect(aliceBody.filename).toContain("recording_");

    // Bob downloads
    const bobResp = await apiGet(bobPage, `/messages/recordings/${recordingId}/download`);
    expect(bobResp.status()).toBe(200);
    const bobBody = await bobResp.json();
    expect(bobBody.download_url).toBeTruthy();
  });

  test("132.4 Non-participant cannot download the recording → 403", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");
    test.skip(!recordingId, "No recording created in 132.1");

    const charlieCtx = await alicePage.context().browser()!.newContext();
    const charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, "charlie_admin");
    await charliePage.goto(BASE);

    const resp = await apiGet(charliePage, `/messages/recordings/${recordingId}/download`);
    expect(resp.status()).toBe(403);

    await charlieCtx.close();
  });

  test("132.5 List recordings filtered by conversation_id includes the recording", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");
    test.skip(!recordingId, "No recording created in 132.1");

    const listResp = await apiGet(
      alicePage,
      `/messages/recordings?conversation_id=${encodeURIComponent(CONVO_ID)}`,
    );
    expect(listResp.status()).toBe(200);
    const body = await listResp.json();
    expect(body.items).toBeDefined();
    expect(Array.isArray(body.items)).toBe(true);
    const found = body.items.find(
      (r: { recording_id: string }) => r.recording_id === recordingId,
    );
    expect(found).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// Section 133: Recording Edge Cases (3 tests)
// ---------------------------------------------------------------------------

test.describe("133 — Recording Edge Cases", () => {
  test("133.1 Recording request when feature disabled returns 503", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    // Only run this test if recording is DISABLED
    test.skip(enabled === true, "Recording is enabled — 503 path not reachable");

    const callId = `crinte_133_1_${TS}`;
    const convoId = `crinte_133_1_conv_${TS}`;
    seedConversation({ conversationId: convoId, participantIds: [ALICE_ID, BOB_ID] });
    seedCallSession({
      callId,
      conversationId: convoId,
      callerUserId: ALICE_ID,
      calleeUserId: BOB_ID,
      state: "connected",
    });

    const resp = await apiPost(alicePage, "alice", `/messages/calls/${callId}/recording/request`);
    expect(resp.status()).toBe(503);
    const body = await resp.json();
    expect(body.detail.code).toBe("feature_disabled");

    deleteCallSession(callId);
  });

  test("133.2 Recording request on non-connected call (state=accepted) → 409 invalid_state", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    const callId = `crinte_133_2_${TS}`;
    const convoId = `crinte_133_2_conv_${TS}`;
    seedConversation({ conversationId: convoId, participantIds: [ALICE_ID, BOB_ID] });
    seedCallSession({
      callId,
      conversationId: convoId,
      callerUserId: ALICE_ID,
      calleeUserId: BOB_ID,
      state: "accepted", // not yet connected
    });

    const resp = await apiPost(alicePage, "alice", `/messages/calls/${callId}/recording/request`);
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail.code).toBe("invalid_state");

    deleteCallSession(callId);
  });

  test("133.3 Recording request on non-existent call → 404 call_not_found", async () => {
    const enabled = await isRecordingEnabled(alicePage);
    test.skip(!enabled, "Call recording feature is disabled");

    const resp = await apiPost(alicePage, "alice", `/messages/calls/crinte_no_such_call_${TS}/recording/request`);
    expect(resp.status()).toBe(404);
    const body = await resp.json();
    expect(body.detail.code).toBe("call_not_found");
  });
});
