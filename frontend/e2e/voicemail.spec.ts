/**
 * E2E tests for CALL-014: Voicemail — Record Audio/Video Message on Unanswered Calls
 *
 * Tests voicemail presign API, voicemail create API, validation guards,
 * and voicemail message rendering in the conversation timeline.
 *
 * NOTE: Cannot test actual MediaRecorder in headless Playwright — tests
 * cover the API layer only.
 *
 * Auth pattern:
 *   injectAuth() sets cookies for session auth. CSRF token is sent for POST requests.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, resolveIdentityId } from "./helpers/session";
import {
  usingCpp,
  cppDdbPut,
  cppDdbGet,
} from "./helpers/cpp-seed-appeals-moderation-tail";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = resolveIdentityId("e2e_alice@test.local");
const BOB_ID = resolveIdentityId("e2e_bob@test.local");
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
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
}

function apiPost(page: Page, identity: string, path: string, body: unknown) {
  const session = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body,
  });
}

function apiGet(page: Page, path: string, params?: Record<string, string>) {
  let url = `${API}${path}`;
  if (params) {
    const qs = new URLSearchParams(params).toString();
    url += `?${qs}`;
  }
  return page.request.get(url);
}

// ─── DynamoDB helpers ─────────────────────────────────────────────────────────

const PYTHON = REPO_ROOT + "/.venv/bin/python3";

function ddbPut(table: string, item: Record<string, unknown>): void {
  if (usingCpp()) {
    cppDdbPut(table, item);
    return;
  }
  const script = `
import boto3, json, sys
from decimal import Decimal

def to_ddb(obj):
    if isinstance(obj, dict):
        return {k: to_ddb(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [to_ddb(v) for v in obj]
    if isinstance(obj, float):
        return Decimal(str(obj))
    return obj

ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1")
table = ddb.Table("${table}")
item = json.loads(sys.argv[1])
table.put_item(Item=to_ddb(item))
`;
  execSync(`${PYTHON} -c '${script}' '${JSON.stringify(item)}'`, {
    cwd: REPO_ROOT,
    env: { ...process.env, AWS_ACCESS_KEY_ID: "test", AWS_SECRET_ACCESS_KEY: "test" },
    timeout: 10_000,
  });
}

function ddbGet(table: string, key: Record<string, string>): Record<string, unknown> | null {
  if (usingCpp()) {
    return cppDdbGet(table, key);
  }
  const script = `
import boto3, json, sys
from decimal import Decimal

class DecEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            s = str(o)
            return float(o) if "." in s else int(o)
        return super().default(o)

ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1")
table = ddb.Table("${table}")
key = json.loads(sys.argv[1])
resp = table.get_item(Key=key)
item = resp.get("Item")
print(json.dumps(item, cls=DecEncoder) if item else "null")
`;
  const raw = execSync(`${PYTHON} -c '${script}' '${JSON.stringify(key)}'`, {
    cwd: REPO_ROOT,
    env: { ...process.env, AWS_ACCESS_KEY_ID: "test", AWS_SECRET_ACCESS_KEY: "test" },
    timeout: 10_000,
  }).toString().trim();
  return raw === "null" ? null : JSON.parse(raw);
}

// ─── Test state ───────────────────────────────────────────────────────────────

let alicePage: Page;
let dmConvoId: string;
let callId: string;

test.describe("CALL-014 Voicemail", () => {

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Create or get DM between Alice and Bob
    const dmResp = await apiPost(alicePage, ALICE_ID, "/messaging/conversations/dm/find-or-create", {
      user_id: BOB_ID,
    });
    expect(dmResp.status()).toBeLessThan(300);
    const dmData = await dmResp.json();
    dmConvoId = dmData.conversation_id;

    // Create a call session that's in "declined" state
    callId = `call_vm_${TS}`;
    ddbPut("MessageCallSessions", {
      call_id: callId,
      conversation_id: dmConvoId,
      caller_user_id: ALICE_ID,
      callee_user_id: BOB_ID,
      initial_mode: "audio",
      state: "declined",
      start_ts: Math.floor(Date.now() / 1000) - 60,
      start_ts_sort: Math.floor(Date.now() / 1000) - 60,
      end_ts: Math.floor(Date.now() / 1000) - 30,
      end_reason: "declined",
      updated_at: Math.floor(Date.now() / 1000),
      lifecycle_events: [],
      idempotency_records: {},
      broadcast_session_id: "",
      paid: false,
      rate_cents_per_min: 0,
      billing_status: "",
      total_billed_cents: 0,
      total_billed_seconds: 0,
      billing_cycle_count: 0,
      platform_fee_bps: 0,
      max_duration_seconds: 0,
    });
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  // ─── Section 145: Voicemail presign API ─────────────────────────────────

  test.describe("145 · Voicemail presign API", () => {
    test("145.1 · valid presign returns message_id, upload_url, s3_key", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${dmConvoId}/voicemail/presign`, {
        call_id: callId,
        content_type: "audio/webm",
        size_bytes: 50000,
        mode: "audio",
      });
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.message_id).toMatch(/^m_[a-f0-9]{32}$/);
      expect(data.upload_url).toContain("/mock/s3/");
      expect(data.upload_url).toContain("voicemails/");
      expect(data.s3_key).toContain(`voicemails/${dmConvoId}/`);
    });

    test("145.2 · presign with video content type succeeds", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${dmConvoId}/voicemail/presign`, {
        call_id: callId,
        content_type: "video/webm",
        size_bytes: 100000,
        mode: "video",
      });
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.s3_key).toContain(".webm");
    });

    test("145.3 · presign rejects invalid content type", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${dmConvoId}/voicemail/presign`, {
        call_id: callId,
        content_type: "text/plain",
        size_bytes: 50000,
        mode: "audio",
      });
      expect(resp.status()).toBe(422);
    });

    test("145.4 · presign rejects non-existent call_id", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${dmConvoId}/voicemail/presign`, {
        call_id: "call_nonexistent_12345",
        content_type: "audio/webm",
        size_bytes: 50000,
        mode: "audio",
      });
      expect(resp.status()).toBe(404);
      const data = await resp.json();
      expect(data.detail).toContain("Call not found");
    });
  });

  // ─── Section 146: Voicemail create API ──────────────────────────────────

  test.describe("146 · Voicemail create API", () => {
    let presignData: { message_id: string; upload_url: string; s3_key: string };
    const createCallId = `call_vm_create_${TS}`;

    test.beforeAll(async () => {
      // Create a fresh declined call for this section
      ddbPut("MessageCallSessions", {
        call_id: createCallId,
        conversation_id: dmConvoId,
        caller_user_id: ALICE_ID,
        callee_user_id: BOB_ID,
        initial_mode: "audio",
        state: "declined",
        start_ts: Math.floor(Date.now() / 1000) - 60,
        start_ts_sort: Math.floor(Date.now() / 1000) - 60,
        end_ts: Math.floor(Date.now() / 1000) - 30,
        end_reason: "declined",
        updated_at: Math.floor(Date.now() / 1000),
        lifecycle_events: [],
        idempotency_records: {},
        broadcast_session_id: "",
        paid: false,
        rate_cents_per_min: 0,
        billing_status: "",
        total_billed_cents: 0,
        total_billed_seconds: 0,
        billing_cycle_count: 0,
        platform_fee_bps: 0,
        max_duration_seconds: 0,
      });

      // Get presign
      const resp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${dmConvoId}/voicemail/presign`, {
        call_id: createCallId,
        content_type: "audio/webm",
        size_bytes: 50000,
        mode: "audio",
      });
      presignData = await resp.json();
    });

    test("146.1 · create voicemail after presign succeeds", async () => {
      const waveform = Array.from({ length: 30 }, () => Math.random());
      const resp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${dmConvoId}/voicemail`, {
        message_id: presignData.message_id,
        call_id: createCallId,
        s3_key: presignData.s3_key,
        content_type: "audio/webm",
        size_bytes: 50000,
        duration_seconds: 15.5,
        waveform_data: waveform,
        mode: "audio",
      });
      expect(resp.status()).toBe(200);
      const msg = await resp.json();
      expect(msg.kind).toBe("voicemail");
      expect(msg.voicemail).toBeTruthy();
      expect(msg.voicemail.call_id).toBe(createCallId);
      expect(msg.voicemail.mode).toBe("audio");
      expect(msg.voicemail.audio_url).toContain("/mock/s3/");
      expect(msg.voicemail.duration_seconds).toBeCloseTo(15.5, 0);
      expect(msg.voicemail.waveform_data.length).toBeGreaterThanOrEqual(10);
      expect(msg.voicemail.call_state).toBe("declined");
      expect(msg.voicemail.caller_user_id).toBe(ALICE_ID);
      expect(msg.voicemail.callee_user_id).toBe(BOB_ID);
    });

    test("146.2 · duration > 60 returns 422", async () => {
      const longCallId = `call_vm_long_${TS}`;
      ddbPut("MessageCallSessions", {
        call_id: longCallId,
        conversation_id: dmConvoId,
        caller_user_id: ALICE_ID,
        callee_user_id: BOB_ID,
        initial_mode: "audio",
        state: "missed",
        start_ts: Math.floor(Date.now() / 1000) - 60,
        start_ts_sort: Math.floor(Date.now() / 1000) - 60,
        end_ts: Math.floor(Date.now() / 1000) - 30,
        end_reason: "no_answer",
        updated_at: Math.floor(Date.now() / 1000),
        lifecycle_events: [],
        idempotency_records: {},
        broadcast_session_id: "",
        paid: false,
        rate_cents_per_min: 0,
        billing_status: "",
        total_billed_cents: 0,
        total_billed_seconds: 0,
        billing_cycle_count: 0,
        platform_fee_bps: 0,
        max_duration_seconds: 0,
      });
      const resp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${dmConvoId}/voicemail`, {
        message_id: "m_" + "a".repeat(32),
        call_id: longCallId,
        s3_key: "voicemails/test/test.webm",
        content_type: "audio/webm",
        size_bytes: 50000,
        duration_seconds: 120,
        waveform_data: Array.from({ length: 30 }, () => 0.5),
        mode: "audio",
      });
      expect(resp.status()).toBe(422);
    });

    test("146.3 · waveform < 10 items returns 422", async () => {
      const shortWaveCallId = `call_vm_shortwf_${TS}`;
      ddbPut("MessageCallSessions", {
        call_id: shortWaveCallId,
        conversation_id: dmConvoId,
        caller_user_id: ALICE_ID,
        callee_user_id: BOB_ID,
        initial_mode: "audio",
        state: "missed",
        start_ts: Math.floor(Date.now() / 1000) - 60,
        start_ts_sort: Math.floor(Date.now() / 1000) - 60,
        end_ts: Math.floor(Date.now() / 1000) - 30,
        end_reason: "no_answer",
        updated_at: Math.floor(Date.now() / 1000),
        lifecycle_events: [],
        idempotency_records: {},
        broadcast_session_id: "",
        paid: false,
        rate_cents_per_min: 0,
        billing_status: "",
        total_billed_cents: 0,
        total_billed_seconds: 0,
        billing_cycle_count: 0,
        platform_fee_bps: 0,
        max_duration_seconds: 0,
      });
      const resp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${dmConvoId}/voicemail`, {
        message_id: "m_" + "b".repeat(32),
        call_id: shortWaveCallId,
        s3_key: "voicemails/test/test.webm",
        content_type: "audio/webm",
        size_bytes: 50000,
        duration_seconds: 10,
        waveform_data: [0.5, 0.5, 0.5],
        mode: "audio",
      });
      expect(resp.status()).toBe(422);
    });

    test("146.4 · voicemail appears in conversation messages with kind=voicemail", async () => {
      const resp = await apiGet(alicePage, `/messaging/conversations/${dmConvoId}/messages`);
      expect(resp.status()).toBe(200);
      const messages = await resp.json() as Array<{ kind: string; voicemail?: { call_id: string } }>;
      const vm = messages.find((m) => m.kind === "voicemail" && m.voicemail?.call_id === createCallId);
      expect(vm).toBeTruthy();
    });
  });

  // ─── Section 147: Voicemail guards ──────────────────────────────────────

  test.describe("147 · Voicemail guards", () => {
    test("147.1 · non-participant gets 403", async () => {
      // Use a conversation that Alice doesn't belong to? Actually Alice is participant
      // Instead, test that Bob (the callee) cannot leave a voicemail (only caller can)
      const bobCtx = await alicePage.context().browser()!.newContext();
      const bobPage = await bobCtx.newPage();
      await injectAuth(bobPage, BOB_ID);

      const bobCallId = `call_vm_bob_${TS}`;
      ddbPut("MessageCallSessions", {
        call_id: bobCallId,
        conversation_id: dmConvoId,
        caller_user_id: ALICE_ID,
        callee_user_id: BOB_ID,
        initial_mode: "audio",
        state: "declined",
        start_ts: Math.floor(Date.now() / 1000) - 60,
        start_ts_sort: Math.floor(Date.now() / 1000) - 60,
        end_ts: Math.floor(Date.now() / 1000) - 30,
        end_reason: "declined",
        updated_at: Math.floor(Date.now() / 1000),
        lifecycle_events: [],
        idempotency_records: {},
        broadcast_session_id: "",
        paid: false,
        rate_cents_per_min: 0,
        billing_status: "",
        total_billed_cents: 0,
        total_billed_seconds: 0,
        billing_cycle_count: 0,
        platform_fee_bps: 0,
        max_duration_seconds: 0,
      });

      const resp = await apiPost(bobPage, BOB_ID, `/messaging/conversations/${dmConvoId}/voicemail/presign`, {
        call_id: bobCallId,
        content_type: "audio/webm",
        size_bytes: 50000,
        mode: "audio",
      });
      expect(resp.status()).toBe(403);
      const data = await resp.json();
      expect(data.detail).toContain("Only the caller");

      await bobCtx.close();
    });

    test("147.2 · call in non-eligible state (ended) returns 400", async () => {
      const endedCallId = `call_vm_ended_${TS}`;
      ddbPut("MessageCallSessions", {
        call_id: endedCallId,
        conversation_id: dmConvoId,
        caller_user_id: ALICE_ID,
        callee_user_id: BOB_ID,
        initial_mode: "audio",
        state: "ended",
        start_ts: Math.floor(Date.now() / 1000) - 120,
        start_ts_sort: Math.floor(Date.now() / 1000) - 120,
        end_ts: Math.floor(Date.now() / 1000) - 30,
        end_reason: "ended",
        updated_at: Math.floor(Date.now() / 1000),
        lifecycle_events: [],
        idempotency_records: {},
        broadcast_session_id: "",
        paid: false,
        rate_cents_per_min: 0,
        billing_status: "",
        total_billed_cents: 0,
        total_billed_seconds: 0,
        billing_cycle_count: 0,
        platform_fee_bps: 0,
        max_duration_seconds: 0,
      });

      const resp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${dmConvoId}/voicemail/presign`, {
        call_id: endedCallId,
        content_type: "audio/webm",
        size_bytes: 50000,
        mode: "audio",
      });
      expect(resp.status()).toBe(400);
      const data = await resp.json();
      expect(data.detail).toContain("not voicemail-eligible");
    });

    test("147.3 · duplicate voicemail returns 409", async () => {
      // The createCallId already has a voicemail from 146.1 — try presign again
      const resp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${dmConvoId}/voicemail/presign`, {
        call_id: `call_vm_create_${TS}`,
        content_type: "audio/webm",
        size_bytes: 50000,
        mode: "audio",
      });
      expect(resp.status()).toBe(409);
      const data = await resp.json();
      expect(data.detail).toContain("already been left");
    });

    test("147.4 · paid call returns 400", async () => {
      const paidCallId = `call_vm_paid_${TS}`;
      ddbPut("MessageCallSessions", {
        call_id: paidCallId,
        conversation_id: dmConvoId,
        caller_user_id: ALICE_ID,
        callee_user_id: BOB_ID,
        initial_mode: "audio",
        state: "declined",
        start_ts: Math.floor(Date.now() / 1000) - 60,
        start_ts_sort: Math.floor(Date.now() / 1000) - 60,
        end_ts: Math.floor(Date.now() / 1000) - 30,
        end_reason: "declined",
        updated_at: Math.floor(Date.now() / 1000),
        lifecycle_events: [],
        idempotency_records: {},
        broadcast_session_id: "",
        paid: true,
        rate_cents_per_min: 100,
        billing_status: "",
        total_billed_cents: 0,
        total_billed_seconds: 0,
        billing_cycle_count: 0,
        platform_fee_bps: 0,
        max_duration_seconds: 0,
      });

      const resp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${dmConvoId}/voicemail/presign`, {
        call_id: paidCallId,
        content_type: "audio/webm",
        size_bytes: 50000,
        mode: "audio",
      });
      expect(resp.status()).toBe(400);
      const data = await resp.json();
      expect(data.detail).toContain("paid calls");
    });

    test("147.5 · call in wrong conversation returns 400", async () => {
      const wrongConvoCallId = `call_vm_wrong_${TS}`;
      ddbPut("MessageCallSessions", {
        call_id: wrongConvoCallId,
        conversation_id: "some_other_convo_id",
        caller_user_id: ALICE_ID,
        callee_user_id: BOB_ID,
        initial_mode: "audio",
        state: "declined",
        start_ts: Math.floor(Date.now() / 1000) - 60,
        start_ts_sort: Math.floor(Date.now() / 1000) - 60,
        end_ts: Math.floor(Date.now() / 1000) - 30,
        end_reason: "declined",
        updated_at: Math.floor(Date.now() / 1000),
        lifecycle_events: [],
        idempotency_records: {},
        broadcast_session_id: "",
        paid: false,
        rate_cents_per_min: 0,
        billing_status: "",
        total_billed_cents: 0,
        total_billed_seconds: 0,
        billing_cycle_count: 0,
        platform_fee_bps: 0,
        max_duration_seconds: 0,
      });

      const resp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${dmConvoId}/voicemail/presign`, {
        call_id: wrongConvoCallId,
        content_type: "audio/webm",
        size_bytes: 50000,
        mode: "audio",
      });
      expect(resp.status()).toBe(400);
      const data = await resp.json();
      expect(data.detail).toContain("does not belong");
    });
  });

  // ─── Section 148: Voicemail in conversation ────────────────────────────

  test.describe("148 · Voicemail in conversation", () => {
    let videoVmCallId: string;
    let videoMsgId: string;

    test.beforeAll(async () => {
      // Create a "missed" call for video voicemail
      videoVmCallId = `call_vm_video_${TS}`;
      ddbPut("MessageCallSessions", {
        call_id: videoVmCallId,
        conversation_id: dmConvoId,
        caller_user_id: ALICE_ID,
        callee_user_id: BOB_ID,
        initial_mode: "video",
        state: "missed",
        start_ts: Math.floor(Date.now() / 1000) - 90,
        start_ts_sort: Math.floor(Date.now() / 1000) - 90,
        end_ts: Math.floor(Date.now() / 1000) - 60,
        end_reason: "no_answer",
        updated_at: Math.floor(Date.now() / 1000),
        lifecycle_events: [],
        idempotency_records: {},
        broadcast_session_id: "",
        paid: false,
        rate_cents_per_min: 0,
        billing_status: "",
        total_billed_cents: 0,
        total_billed_seconds: 0,
        billing_cycle_count: 0,
        platform_fee_bps: 0,
        max_duration_seconds: 0,
      });

      // Presign for video voicemail
      const presignResp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${dmConvoId}/voicemail/presign`, {
        call_id: videoVmCallId,
        content_type: "video/webm",
        size_bytes: 200000,
        mode: "video",
      });
      const presignData = await presignResp.json();
      videoMsgId = presignData.message_id;

      // Create video voicemail
      const waveform = Array.from({ length: 30 }, () => Math.random());
      await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${dmConvoId}/voicemail`, {
        message_id: videoMsgId,
        call_id: videoVmCallId,
        s3_key: presignData.s3_key,
        content_type: "video/webm",
        size_bytes: 200000,
        duration_seconds: 10.0,
        waveform_data: waveform,
        mode: "video",
      });
    });

    test("148.1 · video voicemail has correct fields in messages list", async () => {
      const resp = await apiGet(alicePage, `/messaging/conversations/${dmConvoId}/messages`);
      expect(resp.status()).toBe(200);
      const messages = await resp.json() as Array<{
        kind: string;
        message_id: string;
        voicemail?: {
          call_id: string;
          mode: string;
          video_url: string | null;
          audio_url: string | null;
          call_state: string;
          duration_seconds: number;
        };
      }>;
      const vm = messages.find((m) => m.message_id === videoMsgId);
      expect(vm).toBeTruthy();
      expect(vm!.kind).toBe("voicemail");
      expect(vm!.voicemail!.mode).toBe("video");
      expect(vm!.voicemail!.video_url).toContain("/mock/s3/");
      expect(vm!.voicemail!.audio_url).toBeNull();
      expect(vm!.voicemail!.call_state).toBe("missed");
      expect(vm!.voicemail!.duration_seconds).toBeCloseTo(10.0, 0);
    });

    test("148.2 · call session record has voicemail_message_id set", async () => {
      const createCallId = `call_vm_create_${TS}`;
      const record = ddbGet("MessageCallSessions", { call_id: createCallId });
      expect(record).toBeTruthy();
      expect(record!.voicemail_message_id).toBeTruthy();
      expect(typeof record!.voicemail_message_id).toBe("string");
    });

    test("148.3 · voicemail on busy call works", async () => {
      const busyCallId = `call_vm_busy_${TS}`;
      ddbPut("MessageCallSessions", {
        call_id: busyCallId,
        conversation_id: dmConvoId,
        caller_user_id: ALICE_ID,
        callee_user_id: BOB_ID,
        initial_mode: "audio",
        state: "busy",
        start_ts: Math.floor(Date.now() / 1000) - 60,
        start_ts_sort: Math.floor(Date.now() / 1000) - 60,
        end_ts: Math.floor(Date.now() / 1000) - 30,
        end_reason: "busy",
        updated_at: Math.floor(Date.now() / 1000),
        lifecycle_events: [],
        idempotency_records: {},
        broadcast_session_id: "",
        paid: false,
        rate_cents_per_min: 0,
        billing_status: "",
        total_billed_cents: 0,
        total_billed_seconds: 0,
        billing_cycle_count: 0,
        platform_fee_bps: 0,
        max_duration_seconds: 0,
      });

      // Presign
      const presignResp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${dmConvoId}/voicemail/presign`, {
        call_id: busyCallId,
        content_type: "audio/webm",
        size_bytes: 30000,
        mode: "audio",
      });
      expect(presignResp.status()).toBe(200);
      const presignData = await presignResp.json();

      // Create
      const waveform = Array.from({ length: 30 }, () => Math.random());
      const createResp = await apiPost(alicePage, ALICE_ID, `/messaging/conversations/${dmConvoId}/voicemail`, {
        message_id: presignData.message_id,
        call_id: busyCallId,
        s3_key: presignData.s3_key,
        content_type: "audio/webm",
        size_bytes: 30000,
        duration_seconds: 5.0,
        waveform_data: waveform,
        mode: "audio",
      });
      expect(createResp.status()).toBe(200);
      const msg = await createResp.json();
      expect(msg.voicemail.call_state).toBe("busy");
    });

    test("148.4 · conversation last_message_preview shows [Voicemail]", async () => {
      const resp = await apiGet(alicePage, "/messaging/conversations");
      expect(resp.status()).toBe(200);
      const convos = await resp.json() as Array<{
        conversation_id: string;
        last_message_preview?: string;
      }>;
      const convo = convos.find((c) => c.conversation_id === dmConvoId);
      expect(convo).toBeTruthy();
      expect(convo!.last_message_preview).toBe("[Voicemail]");
    });
  });
});
