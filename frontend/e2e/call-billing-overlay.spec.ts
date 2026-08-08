/**
 * E2E regression tests for GAP-0147:
 *   "No billing props wired into ConversationView.tsx or CallSessionOverlay.tsx."
 *
 * GAP-0016 added the `useCallBillingHeartbeat` hook + wiring so heartbeats are
 * sent during a connected paid call. GAP-0147 is the *secondary* wiring gap:
 * the `CallBillingOverlay` component (cost ticker + low-balance warning) existed
 * but was never rendered, and no billing props were passed from
 * ConversationView -> CallSessionOverlay -> CallBillingOverlay.
 *
 * Before the fix: a connected paid call showed no in-call cost ticker, rate,
 * balance, or low-balance banner.
 * After the fix: the overlay renders the running cost / rate / balance from the
 * latest heartbeat response and shows the low-balance warning when the backend
 * sets `warn_low_balance`.
 *
 * NOTE: requires the dev stack (frontend :3000 + backend :8000 + DynamoDB :8001)
 * AND a browser able to negotiate the WebRTC peer connection so the call reaches
 * the "connected" phase. Do NOT run in CI without the stack.
 *
 * Auth pattern: e2e_session_setup.py sessions injected as cookies (+ CSRF header).
 */

import { test, expect, chromium, type Browser, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions, resolveIdentityId } from "./helpers/session";
import { runCppShim, usingCpp } from "./helpers/cpp-seed";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

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
const PYTHON = REPO_ROOT + "/.venv/bin/python3";

const ALICE_ID = resolveIdentityId("e2e_alice@test.local");
const BOB_ID = resolveIdentityId("e2e_bob@test.local");

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
  // ProtectedRoute gates the SPA on the persisted auth-store; cookies alone
  // authenticate API calls but the router would redirect to /login. Seed the
  // auth-store before every navigation so protected pages actually render.
  await page.addInitScript((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);

  // Headless Chromium cannot complete a real WebRTC/ICE handshake between two
  // isolated browser contexts. The call state machine reaches "connected" via
  // the replayed call.accept SSE (REMOTE_ACCEPT), but useRtcPeerConnection
  // watches pc.iceConnectionState and, on "disconnected"/"failed", dispatches
  // CONNECTION_LOST -> reconnecting -> (after retries) the terminal "failure"
  // state, which closes the billing overlay. Pin the reported ICE/connection
  // state to "connected" so that escalation never fires and the connected
  // overlay stays mounted for the duration of the assertions. The real
  // RTCPeerConnection is otherwise untouched (offer/answer/tracks still work).
  await page.addInitScript(() => {
    try {
      const proto = (window as unknown as { RTCPeerConnection?: { prototype: object } })
        .RTCPeerConnection?.prototype;
      if (proto) {
        Object.defineProperty(proto, "iceConnectionState", {
          configurable: true,
          get() {
            return "connected";
          },
        });
        Object.defineProperty(proto, "connectionState", {
          configurable: true,
          get() {
            return "connected";
          },
        });
      }
    } catch {
      /* leave the native implementation in place */
    }
  });
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

/** Read the most-recent call_id for a conversation from DynamoDB. */
function latestCallId(convoId: string): string {
  if (usingCpp()) {
    // cpp keeps call sessions in tlc_message_call_sessions on .82 moto, not the
    // Python DDB-Local MessageCallSessions table. Route via the cpp shim.
    const out = runCppShim("read_call_sessions_latest_active.py", { conversation_id: convoId });
    const lines = out.split(/\r?\n/).map((l) => l.trim());
    // last non-"ok" line is the call_id (may be empty while none active yet)
    for (let i = lines.length - 1; i >= 0; i--) {
      if (lines[i] === "ok" || lines[i] === "") continue;
      return lines[i];
    }
    return "";
  }
  const script = `
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
table = ddb.Table("MessageCallSessions")
resp = table.scan(
    FilterExpression="conversation_id = :cid",
    ExpressionAttributeValues={":cid": "${convoId}"},
)
items = sorted(resp.get("Items", []), key=lambda i: i.get("start_ts", 0))
print(items[-1]["call_id"] if items else "")
`;
  return execSync(`${PYTHON} -c '${script}'`, { cwd: REPO_ROOT, timeout: 10_000 })
    .toString()
    .trim();
}

/** Force the backend call session into the "connected" state directly in DDB
 *  (a full WebRTC handshake cannot complete in headless Chromium). */
function forceCallConnected(callId: string): void {
  if (usingCpp()) {
    runCppShim("force_call_connected.py", { call_id: callId });
    return;
  }
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
  execSync(`${PYTHON} -c '${script}'`, { cwd: REPO_ROOT, timeout: 10_000 });
}

/** Force-terminate any non-terminal call sessions for a conversation in DDB so a
 *  fresh invite is not rejected (409) by an earlier test's lingering call. */
function endActiveCallSessions(convoId: string): void {
  if (usingCpp()) {
    runCppShim("end_active_call_sessions.py", { conversation_id: convoId });
    return;
  }
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
  execSync(`${PYTHON} -c '${script}'`, { cwd: REPO_ROOT, timeout: 10_000 });
}

/**
 * Drive Alice's call UI to the connected (audio) phase against Bob.
 *
 * Backend-driven (NOT reliant on real WebRTC/ICE, which cannot complete in
 * headless Chromium): Alice sends a real paid invite, Bob accepts via the API,
 * we force the session to "connected" in DDB, then replay the call.accept SSE
 * event into Alice's page so her state machine reaches "connected".
 */
async function startConnectedPaidCall(alicePage: Page, bobPage: Page, convoId: string) {
  // Defensive: terminate any lingering non-terminal call sessions for this
  // conversation in DDB. A prior test can leave a call "connected", and
  // create_invite rejects a new invite with `caller_busy` (HTTP 409) while an
  // active session exists in the conversation — which would land Alice in a
  // "Call status" outcome overlay instead of "connected".
  endActiveCallSessions(convoId);

  // Stub the partner call-rate lookup so `isPaidCall` is deterministically true
  // the instant the rate query runs. The CallBillingOverlay (and the heartbeat
  // hook) are gated on `isPaidCall`; depending on the real backend rate + the
  // React Query resolution timing relative to the transient connected window
  // makes this race, so pin it.
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

  const startBtn = alicePage.getByRole("button", { name: "Start audio call" });
  await expect(startBtn).toBeVisible({ timeout: 15_000 });
  await expect(startBtn).toBeEnabled({ timeout: 15_000 });
  await startBtn.click();

  let callId = "";
  for (let i = 0; i < 30 && !callId; i++) {
    callId = latestCallId(convoId);
    if (!callId) await alicePage.waitForTimeout(500);
  }
  if (!callId) throw new Error("call session was not created after Alice initiated");

  const aliceSub = getSessions()[ALICE_ID].user_sub;
  const bobSub = getSessions()[BOB_ID].user_sub;

  const acceptResp = await bobPage.request.post(`${BASE}/messaging/messages/calls/${callId}/accept`, {
    headers: csrfHeader(BOB_ID),
    data: { idempotency_key: `e2e-accept-${callId}` },
  });
  expect([200, 409].includes(acceptResp.status())).toBe(true);
  forceCallConnected(callId);

  // Replay call.accept (REMOTE_ACCEPT) so Alice's state machine reaches
  // "connected". Headless Chromium cannot complete a real WebRTC/ICE handshake,
  // so the peer connection's ICE eventually "fails" (~3s grace) and the machine
  // transitions connected -> reconnecting, flickering the overlay closed. From
  // "reconnecting", another REMOTE_ACCEPT recovers back to "connected", so we
  // install a page-side keep-alive that re-dispatches call.accept with a
  // monotonically-increasing event_ts (the handler ignores stale/older ts) to
  // hold the connected overlay open for the duration of the assertions. The
  // interval id is stashed on window so stopCallKeepAlive() can clear it.
  await alicePage.evaluate(
    (d: Record<string, unknown>) => {
      const w = window as unknown as { __callKeepAlive?: ReturnType<typeof setInterval> };
      const fire = () => {
        window.dispatchEvent(
          new CustomEvent("messaging:call-event", {
            detail: { ...d, event_ts: Date.now() },
          }),
        );
      };
      fire();
      if (w.__callKeepAlive) clearInterval(w.__callKeepAlive);
      // Fire frequently so a connected->reconnecting flicker (ICE "failed" with
      // no real peer) is recovered to "connected" almost immediately, keeping
      // the billing overlay continuously mounted for the assertions.
      w.__callKeepAlive = setInterval(fire, 300);
    },
    {
      conversation_id: convoId,
      call_id: callId,
      event_type: "call.accept",
      mode: "audio",
      caller_user_id: aliceSub,
      callee_user_id: bobSub,
    },
  );

  await expect(alicePage.getByLabel("Audio call").first()).toBeVisible({ timeout: 30_000 });
}

/** Stop the connected-overlay keep-alive loop installed by startConnectedPaidCall. */
async function stopCallKeepAlive(page: Page): Promise<void> {
  await page.evaluate(() => {
    const w = window as unknown as { __callKeepAlive?: ReturnType<typeof setInterval> };
    if (w.__callKeepAlive) {
      clearInterval(w.__callKeepAlive);
      w.__callKeepAlive = undefined;
    }
  });
}

test.describe.serial("GAP-0147 — paid-call billing overlay renders in the call UI", () => {
  let fakeBrowser: Browser;
  let alicePage: Page;
  let bobPage: Page;
  let convoId: string;

  test.beforeAll(async () => {
    fakeBrowser = await chromium.launch({ headless: true, args: FAKE_MEDIA_ARGS });
    // One-time DM + paid-rate + wallet funding (shared across tests).
    const aliceCtx = await fakeBrowser.newContext({ permissions: ["microphone", "camera"] });
    const bobCtx = await fakeBrowser.newContext({ permissions: ["microphone", "camera"] });
    const setupAlice = await aliceCtx.newPage();
    const setupBob = await bobCtx.newPage();
    await injectAuth(setupAlice, ALICE_ID);
    await injectAuth(setupBob, BOB_ID);
    convoId = await findOrCreateDm(setupAlice, ALICE_ID, BOB_ID);
    // ensurePaidRate posts the rate as BOB; page.request carries the page's
    // context cookies, so it MUST run on a Bob-authenticated page (otherwise the
    // rate is written for Alice and getCallRate(Bob) returns rate_not_found ->
    // isPaidCall is false -> the cost ticker never renders).
    await ensurePaidRate(setupBob);
    await aliceCtx.close();
    await bobCtx.close();

    // Fund Alice's wallet so the paid invite is accepted.
    const script = `
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
ddb.Table("billing").put_item(Item={"pk": "USER#${ALICE_ID}", "sk": "WALLET",
                                     "wallet_balance_cents": 5000, "currency": "usd"})
`;
    execSync(`${PYTHON} -c '${script}'`, { cwd: REPO_ROOT, timeout: 10_000 });
  });

  // Fresh browser contexts per test so React Query / call-state machine never
  // carries over between serial tests (a prior test's connected call otherwise
  // pollutes the next test's overlay assertions).
  test.beforeEach(async () => {
    const aliceCtx = await fakeBrowser.newContext({ permissions: ["microphone", "camera"] });
    const bobCtx = await fakeBrowser.newContext({ permissions: ["microphone", "camera"] });
    alicePage = await aliceCtx.newPage();
    bobPage = await bobCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
    // Clear any lingering call sessions from a previous test on this DM.
    endActiveCallSessions(convoId);
  });

  test.afterEach(async () => {
    await alicePage?.context().close();
    await bobPage?.context().close();
  });

  test.afterAll(async () => {
    await fakeBrowser?.close();
  });

  test("cost ticker shows running cost, rate, and balance from the heartbeat", async () => {
    test.setTimeout(120_000);

    // Stub the heartbeat so the overlay renders deterministic billing values.
    await alicePage.route("**/messaging/messages/calls/*/heartbeat", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          call_id: "stub",
          elapsed_seconds: 90,
          total_cost_cents: 750,
          balance_remaining_cents: 4250,
          rate_cents_per_minute: 500,
          next_bill_in_seconds: 30,
          warn_low_balance: false,
          minutes_remaining: 8.5,
          max_duration_warning: false,
          action: "ok",
        }),
      }),
    );

    await startConnectedPaidCall(alicePage, bobPage, convoId);

    // CallBillingOverlay renders the cost ($7.50), the rate ($5.00/min), and
    // the remaining balance ($42.50). Before GAP-0147 none of these existed.
    await expect(alicePage.getByText("$7.50").first()).toBeVisible({ timeout: 20_000 });
    await expect(alicePage.getByText("$5.00/min").first()).toBeVisible();
    await expect(alicePage.getByText(/Bal:\s*\$42\.50/).first()).toBeVisible();

    await stopCallKeepAlive(alicePage);
    await alicePage.getByRole("button", { name: /end call/i }).first().click();
    await alicePage.unroute("**/messaging/messages/calls/*/heartbeat");
  });

  test("low-balance warning banner appears when warn_low_balance is true", async () => {
    test.setTimeout(120_000);

    await alicePage.route("**/messaging/messages/calls/*/heartbeat", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          call_id: "stub",
          elapsed_seconds: 120,
          total_cost_cents: 1000,
          balance_remaining_cents: 200,
          rate_cents_per_minute: 500,
          next_bill_in_seconds: 30,
          warn_low_balance: true,
          minutes_remaining: 0.4,
          max_duration_warning: false,
          action: "ok",
        }),
      }),
    );

    await startConnectedPaidCall(alicePage, bobPage, convoId);

    await expect(alicePage.getByText(/Low balance/i).first()).toBeVisible({ timeout: 20_000 });
    await expect(alicePage.getByText(/0\.4 min remaining/i).first()).toBeVisible();

    await stopCallKeepAlive(alicePage);
    await alicePage.getByRole("button", { name: /end call/i }).first().click();
    await alicePage.unroute("**/messaging/messages/calls/*/heartbeat");
  });
});
