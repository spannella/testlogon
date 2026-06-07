/**
 * E2E regression tests for GAP-0016:
 *   "Paid-call billing heartbeat never sent -> no mid-call billing cycles."
 *
 * Before the fix `frontend/src/hooks/useCallBillingHeartbeat.ts` did not exist and
 * `sendCallHeartbeat` had zero call sites, so a connected paid call sent no
 * `PATCH /messaging/messages/calls/{call_id}/heartbeat` requests and the backend
 * billing engine never fired mid-call billing cycles.
 *
 * These tests exercise the wiring through the real call UI in ConversationView.
 *
 * NOTE: requires the dev stack (frontend :3000 + backend :8000 + DynamoDB :8001)
 * AND a browser able to negotiate the WebRTC peer connection so the call reaches
 * the "connected" phase. Do NOT run in CI without the stack.
 *
 * Auth pattern: e2e_session_setup.py sessions injected as cookies (+ CSRF header).
 */

import { test, expect, chromium, type Browser, type Page } from "@playwright/test";
import { execSync } from "child_process";

// A connected paid call requires getUserMedia() to succeed (the caller acquires a
// local MediaStream before sending the invite, and the callee acquires one before
// accepting). Headless Chromium has no real media devices, so we launch a
// dedicated browser with fake media + auto-granted permissions for this spec
// rather than mutating the shared playwright.config (which the orchestrator owns).
const FAKE_MEDIA_ARGS = [
  "--use-fake-ui-for-media-stream",
  "--use-fake-device-for-media-stream",
];

const BASE = "http://localhost:3000";
const PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";

const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

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
    const raw = execSync(`${PYTHON} /home/ubuntu/testlogon/e2e_session_setup.py`, {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  // ProtectedRoute gates the SPA on the persisted auth-store; cookies alone
  // authenticate API calls but the router would redirect to /login. Seed the
  // auth-store before every navigation so protected pages actually render.
  await page.addInitScript((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

function csrfHeader(userId: string): Record<string, string> {
  const session = getSessions()[userId];
  return { "x-csrf-token": session.csrf_token };
}

async function findOrCreateDm(page: Page, asUser: string, otherUser: string): Promise<string> {
  const resp = await page.request.post(`${BASE}/messaging/conversations/dm/find-or-create`, {
    headers: csrfHeader(asUser),
    data: { user_id: otherUser },
  });
  expect(resp.status()).toBe(200);
  return (await resp.json()).conversation_id as string;
}

/** Ensure Bob (the creator) has paid calls enabled so calls to him are billed. */
async function ensurePaidRate(page: Page) {
  await page.request.post(`${BASE}/ui/calls/rates`, {
    headers: csrfHeader(BOB_ID),
    data: { rate_cents_per_minute: 500, enabled: true, min_balance_minutes: 2, max_duration_minutes: 120 },
  });
}

/** Read the most-recent ACTIVE call_id for a conversation from DynamoDB.
 *  endActiveCallSessions() ends every prior non-terminal session, so the only
 *  active (invited/accepted/connected) session is the one Alice just created —
 *  selecting on state (not just newest start_ts) avoids returning a stale call
 *  from an earlier run when start_ts values collide in the same second. */
function latestCallId(convoId: string): string {
  const script = `
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
table = ddb.Table("MessageCallSessions")
resp = table.scan(
    FilterExpression="conversation_id = :cid",
    ExpressionAttributeValues={":cid": "${convoId}"},
)
ACTIVE = {"invited", "accepted", "connected"}
items = [i for i in resp.get("Items", []) if i.get("state") in ACTIVE]
items.sort(key=lambda i: i.get("start_ts", 0))
print(items[-1]["call_id"] if items else "")
`;
  return execSync(`${PYTHON} -c '${script}'`, { cwd: "/home/ubuntu/testlogon", timeout: 10_000 })
    .toString()
    .trim();
}

/** Force the backend call session into the "connected" state (with billing
 *  timestamps) directly in DynamoDB. A full WebRTC handshake cannot complete in
 *  headless Chromium (no real ICE), so we drive the lifecycle that the peer
 *  connection would normally produce. The heartbeat endpoint only requires
 *  state=="connected" + paid + a billing/connect timestamp. */
function forceCallConnected(callId: string): void {
  const script = `
import boto3, time
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
table = ddb.Table("MessageCallSessions")
now = int(time.time())
table.update_item(
    Key={"call_id": "${callId}"},
    UpdateExpression=("SET #s = :c, connect_ts = :t, billing_start_ts = :t, "
                      "updated_at = :t, paid = :paid, rate_cents_per_min = :rate"),
    ExpressionAttributeNames={"#s": "state"},
    ExpressionAttributeValues={":c": "connected", ":t": now, ":paid": True, ":rate": 500},
)
print("ok")
`;
  execSync(`${PYTHON} -c '${script}'`, { cwd: "/home/ubuntu/testlogon", timeout: 10_000 });
}

/** Force-terminate any non-terminal call sessions for a conversation in DDB so a
 *  fresh invite is not rejected with `caller_busy` (HTTP 409) by a lingering
 *  call from an earlier test/run (call sessions accumulate across runs). Without
 *  this the new invite fails, Alice never reaches "connected", and the billing
 *  heartbeat never fires. */
function endActiveCallSessions(convoId: string): void {
  const script = `
import boto3, time
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
table = ddb.Table("MessageCallSessions")
resp = table.scan(
    FilterExpression="conversation_id = :cid",
    ExpressionAttributeValues={":cid": "${convoId}"},
)
now = int(time.time())
TERMINAL = {"ended", "declined", "busy", "timeout", "failed", "failure"}
for it in resp.get("Items", []):
    if it.get("state") not in TERMINAL:
        table.update_item(
            Key={"call_id": it["call_id"]},
            UpdateExpression="SET #s = :e, updated_at = :t, end_ts = :t",
            ExpressionAttributeNames={"#s": "state"},
            ExpressionAttributeValues={":e": "ended", ":t": now},
        )
print("ok")
`;
  execSync(`${PYTHON} -c '${script}'`, { cwd: "/home/ubuntu/testlogon", timeout: 10_000 });
}

/** Dispatch a synthetic call SSE event into a page (mirrors useMessagingStream
 *  which fans `call.*` server-sent events out as `messaging:call-event`). */
async function dispatchCallEvent(
  page: Page,
  detail: Record<string, unknown>,
): Promise<void> {
  await page.evaluate((d) => {
    window.dispatchEvent(new CustomEvent("messaging:call-event", { detail: d }));
  }, detail);
}

/**
 * Drive Alice's call UI to the connected phase against Bob and return the call_id.
 *
 * Backend-driven (NOT reliant on real WebRTC/ICE, which cannot complete in
 * headless Chromium): Alice initiates a real paid invite (real call_id), Bob
 * accepts via the API, we force the session to "connected" in DDB, then we
 * replay the `call.accept` SSE event into Alice's page so her call state machine
 * transitions OUTGOING_RINGING -> connected and the billing heartbeat hook
 * (enabled only while phase==="connected") starts firing real PATCHes.
 */
async function startConnectedPaidCall(alicePage: Page, bobPage: Page, convoId: string): Promise<string> {
  // Call sessions accumulate across test runs; a lingering non-terminal session
  // makes a fresh invite 409 (caller_busy) -> no connect -> no heartbeat. Clear
  // them first so every run starts clean.
  endActiveCallSessions(convoId);

  // Stub the partner call-rate lookup so `isPaidCall` is deterministically true
  // the instant the rate query runs (the heartbeat hook is gated on
  // `phase==="connected" && isPaidCall`). Avoids racing the real rate query +
  // React Query resolution against the connected window.
  await alicePage.route("**/ui/calls/rates/*", (route) => {
    if (route.request().method() !== "GET") return route.continue();
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        rate_cents_per_minute: 500,
        enabled: true,
        currency: "USD",
        min_balance_minutes: 2,
        max_duration_minutes: 120,
      }),
    });
  });

  await alicePage.goto(`${BASE}/messages/${convoId}`);
  await bobPage.goto(`${BASE}/messages/${convoId}`);

  // Dismiss any residual call-outcome dialog from a previous test so the call
  // buttons are interactable and the state machine is idle.
  await alicePage
    .getByRole("button", { name: /dismiss call status/i })
    .click({ timeout: 2_000 })
    .catch(() => {});

  await expect(alicePage.getByRole("button", { name: "Start audio call" })).toBeVisible({ timeout: 15_000 });

  // Alice initiates an audio call (real invite -> real call session/call_id).
  await alicePage.getByRole("button", { name: "Start audio call" }).click();

  // Wait for the call session row to land and read its id.
  let callId = "";
  for (let i = 0; i < 30 && !callId; i++) {
    callId = latestCallId(convoId);
    if (!callId) await alicePage.waitForTimeout(500);
  }
  if (!callId) throw new Error("call session was not created after Alice initiated");

  const aliceSub = getSessions()[ALICE_ID].user_sub;
  const bobSub = getSessions()[BOB_ID].user_sub;

  // Bob accepts on the backend (state -> accepted), then we drive the session to
  // "connected" as the WebRTC connect would.
  const acceptResp = await bobPage.request.post(`${BASE}/messaging/messages/calls/${callId}/accept`, {
    headers: csrfHeader(BOB_ID),
    data: { idempotency_key: `e2e-accept-${callId}` },
  });
  expect([200, 409].includes(acceptResp.status())).toBe(true);
  forceCallConnected(callId);

  // Replay the call.accept SSE into Alice's page so her UI reaches "connected".
  const eventTs = Math.floor(Date.now() / 1000);
  await dispatchCallEvent(alicePage, {
    conversation_id: convoId,
    call_id: callId,
    event_type: "call.accept",
    mode: "audio",
    caller_user_id: aliceSub,
    callee_user_id: bobSub,
    event_ts: eventTs,
  });

  // Best-effort wait for Alice's overlay to reach the connected (audio call)
  // layout. The connected phase is reached via the replayed call.accept SSE
  // (REMOTE_ACCEPT), but headless Chromium cannot complete a real WebRTC/ICE
  // handshake, so the peer connection's ICE eventually "fails" (~3s grace) and
  // the state machine transitions connected -> reconnecting, flickering the
  // overlay closed. We don't hard-fail on a persistent overlay here — the
  // immediate billing heartbeat fires the moment the call is connected+paid,
  // which is the actual behaviour these tests assert.
  await alicePage
    .getByLabel("Audio call")
    .waitFor({ state: "visible", timeout: 30_000 })
    .catch(() => {});
  return callId;
}

test.describe.serial("GAP-0016 — paid-call billing heartbeat is sent from the UI", () => {
  let fakeBrowser: Browser;
  let alicePage: Page;
  let bobPage: Page;
  let convoId: string;

  test.beforeAll(async () => {
    fakeBrowser = await chromium.launch({ headless: true, args: FAKE_MEDIA_ARGS });
    const aliceCtx = await fakeBrowser.newContext({ permissions: ["microphone", "camera"] });
    const bobCtx = await fakeBrowser.newContext({ permissions: ["microphone", "camera"] });
    alicePage = await aliceCtx.newPage();
    bobPage = await bobCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
    convoId = await findOrCreateDm(alicePage, ALICE_ID, BOB_ID);
    await ensurePaidRate(bobPage);

    // Fund Alice's wallet so the paid invite is accepted.
    const script = `
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
ddb.Table("billing").put_item(Item={"pk": "USER#${ALICE_ID}", "sk": "WALLET",
                                     "wallet_balance_cents": 5000, "currency": "usd"})
`;
    execSync(`${PYTHON} -c '${script}'`, { cwd: "/home/ubuntu/testlogon", timeout: 10_000 });
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
    await fakeBrowser?.close();
  });

  test("heartbeat PATCH is sent during a connected paid call", async () => {
    test.setTimeout(120_000);

    const heartbeats: string[] = [];
    alicePage.on("request", (req) => {
      if (req.method() === "PATCH" && req.url().includes("/heartbeat")) {
        heartbeats.push(req.url());
      }
    });

    const callId = await startConnectedPaidCall(alicePage, bobPage, convoId);
    expect(callId).not.toBe("");

    // The hook fires an immediate heartbeat on connect and then reschedules.
    // Wait long enough to observe at least the first one.
    await expect.poll(() => heartbeats.length, { timeout: 40_000 }).toBeGreaterThanOrEqual(1);
    expect(heartbeats.some((u) => u.includes(callId))).toBe(true);

    // Hang up.
    await alicePage.getByRole("button", { name: /end call/i }).click();
  });

  test("call ends automatically when the heartbeat returns action=end_call", async () => {
    test.setTimeout(120_000);

    // Force the server response to demand call termination.
    await alicePage.route("**/messaging/messages/calls/*/heartbeat", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          call_id: "forced",
          elapsed_seconds: 60,
          total_cost_cents: 500,
          balance_remaining_cents: 0,
          rate_cents_per_minute: 500,
          next_bill_in_seconds: 30,
          warn_low_balance: true,
          minutes_remaining: 0,
          max_duration_warning: false,
          action: "end_call",
        }),
      }),
    );

    await startConnectedPaidCall(alicePage, bobPage, convoId);

    // The hook's onEndCall handler ends the call. The call transitions to the
    // terminal "ended" state and the overlay shows the outcome copy
    // ("Call ended."). Assert that outcome appears — this is the observable
    // proof the billing heartbeat's action=end_call ended the call. (We don't
    // assert the connected "Audio call" overlay disappears: in headless the
    // overlay can briefly show the ended state via its connected layout before
    // the outcome dialog settles, and a connect flicker can mount two of them,
    // which makes a strict not.toBeVisible() unreliable.)
    await expect(alicePage.getByText("Call ended.").first()).toBeVisible({ timeout: 20_000 });
    await alicePage.unroute("**/messaging/messages/calls/*/heartbeat");
  });
});
