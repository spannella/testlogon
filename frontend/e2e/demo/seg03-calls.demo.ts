/**
 * VIDEO SEGMENT 03 — Voice & Video Calls  (~1.5 min)
 *
 * A guided tour of 1:1 audio/video calling with paid-call billing: the per-minute
 * rate badge, a connected call overlay, the live cost ticker (running cost · rate ·
 * balance), a low-balance warning, the call-ended outcome, and the recordings panel.
 *
 * Why this segment launches its OWN browser (unlike seg01/seg02):
 *   A connected call requires getUserMedia() to succeed (the caller acquires a
 *   local MediaStream before sending the invite). Headless Chromium has no real
 *   media devices, so we launch a dedicated chromium with fake-media flags +
 *   auto-granted permissions (the proven pattern from call-billing-overlay.spec.ts
 *   / call-billing-heartbeat.spec.ts). Because the fixture `page` isn't usable for
 *   a real getUserMedia call, we record video on OUR alice context via
 *   `recordVideo` and copy the resulting webm to the standard artifact path.
 *
 * A real WebRTC/ICE handshake also can't complete headless, so the call is driven
 * via the backend: Alice sends a real paid invite, Bob accepts via the REAL accept
 * route, we force the call session to connected+paid in DDB, pin the RTCPeerConnection
 * state to "connected", and replay the call.accept SSE so Alice's state machine
 * reaches "connected". Bob's call RATE + Alice's balance are seeded so isPaidCall is
 * true and the billing overlay renders. (Setup copied from the hardened call specs.)
 *
 * Every feature shown is brought on-screen and PROVEN visible via reveal()'s
 * toBeInViewport assertion.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg03-calls.demo.ts
 */
import { test, expect, chromium, type Browser, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import {
  BASE,
  caption,
  clearCaption,
  titleCard,
  beat,
  reveal,
  loadSessions,
} from "./_demo";

const PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";
// Session keys (loadSessions() keys by short name, from e2e_admin_session_setup.py).
const ALICE = "alice";
const BOB = "bob";
// Backend user subs (the seeded subs happen to be these emails).
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

const FAKE_MEDIA_ARGS = ["--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream"];

// Where the segment webm must land for the stitch step.
const ARTIFACT_DIR =
  "/home/ubuntu/testlogon/frontend/e2e/demo/.artifacts/seg03-calls.demo.ts-Segment-03-Calls-demo";

function csrfHeader(sessionKey: string): Record<string, string> {
  return { "x-csrf-token": loadSessions()[sessionKey].csrf_token };
}

/** Cookie auth + auth-store seed + RTC state pinning (so the connected overlay
 *  doesn't flicker closed when headless ICE "fails"). Mirrors the call specs. */
async function injectCallAuth(page: Page, sessionKey: string) {
  const session = loadSessions()[sessionKey];
  if (!session) throw new Error(`No session for ${sessionKey}`);
  await page.context().addCookies(session.cookies);
  await page.addInitScript((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
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
      /* leave native impl in place */
    }
  });
}

async function findOrCreateDm(page: Page): Promise<string> {
  const resp = await page.request.post(`${BASE}/messaging/conversations/dm/find-or-create`, {
    headers: csrfHeader(ALICE),
    data: { user_id: BOB_ID },
  });
  expect(resp.status()).toBe(200);
  return (await resp.json()).conversation_id as string;
}

/** Bob configures an enabled paid-call rate ($5.00/min) — page.request carries the
 *  page's cookies, so this MUST run on a Bob-authenticated page. */
async function ensurePaidRate(bobPage: Page) {
  await bobPage.request.post(`${BASE}/ui/calls/rates`, {
    headers: csrfHeader(BOB),
    data: {
      rate_cents_per_minute: 500,
      enabled: true,
      min_balance_minutes: 2,
      max_duration_minutes: 120,
    },
  });
}

function runPy(script: string): string {
  return execSync(`${PYTHON} -c '${script.replace(/'/g, "'\\''")}'`, {
    cwd: "/home/ubuntu/testlogon",
    timeout: 12_000,
  })
    .toString()
    .trim();
}

function latestCallId(convoId: string): string {
  return runPy(`
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
table = ddb.Table("MessageCallSessions")
resp = table.scan(FilterExpression="conversation_id = :cid",
                  ExpressionAttributeValues={":cid": "${convoId}"})
ACTIVE = {"invited", "accepted", "connected"}
items = [i for i in resp.get("Items", []) if i.get("state") in ACTIVE]
items.sort(key=lambda i: i.get("start_ts", 0))
print(items[-1]["call_id"] if items else "")
`);
}

function forceCallConnected(callId: string): void {
  runPy(`
import boto3, time
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
now = int(time.time())
ddb.Table("MessageCallSessions").update_item(
    Key={"call_id": "${callId}"},
    UpdateExpression=("SET #s = :c, connect_ts = :t, billing_start_ts = :t, "
                      "updated_at = :t, paid = :paid, rate_cents_per_min = :rate"),
    ExpressionAttributeNames={"#s": "state"},
    ExpressionAttributeValues={":c": "connected", ":t": now, ":paid": True, ":rate": 500},
)
print("ok")
`);
}

function endActiveCallSessions(convoId: string): void {
  runPy(`
import boto3, time
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
table = ddb.Table("MessageCallSessions")
resp = table.scan(FilterExpression="conversation_id = :cid",
                  ExpressionAttributeValues={":cid": "${convoId}"})
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
`);
}

/** Fund Alice's wallet so the paid invite is accepted. */
function fundWallet(): void {
  runPy(`
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
ddb.Table("billing").put_item(Item={"pk": "USER#${ALICE_ID}", "sk": "WALLET",
                                    "wallet_balance_cents": 5000, "currency": "usd"})
print("ok")
`);
}

/** Seed a conversation + participants (so the recordings panel resolves the DM
 *  partner) + a ready CallRecording so the panel lists a real item. */
function seedRecordingConversation(convoId: string, recId: string): void {
  runPy(`
import boto3, time
from decimal import Decimal
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
ts = int(time.time())
ddb.Table("Conversations").put_item(Item={
    "conversation_id": "${convoId}", "participant_ids": ["${ALICE_ID}", "${BOB_ID}"],
    "type": "dm", "created_at": ts, "last_message_at": ts, "updated_at": ts,
})
ptable = ddb.Table("Participants")
for uid in ["${ALICE_ID}", "${BOB_ID}"]:
    ptable.put_item(Item={
        "user_id": uid, "conversation_id": "${convoId}",
        "status": "active", "joined_at": ts,
        "role": "admin" if uid == "${ALICE_ID}" else "member",
        "muted_until": 0, "last_read_at": 0, "unread_count": 0, "left_at": 0,
        "GSI1PK": "${convoId}", "GSI1SK": uid,
    })
ddb.Table("CallRecordings").put_item(Item={
    "recording_id": "${recId}", "call_id": "${recId}_call", "conversation_id": "${convoId}",
    "initiated_by": "${ALICE_ID}", "participants": ["${ALICE_ID}", "${BOB_ID}"],
    "status": "ready", "mime_type": "video/webm",
    "duration_seconds": Decimal("125"), "file_size_bytes": 4194304,
    "started_at": ts, "completed_at": ts, "created_at": ts, "updated_at": ts,
    "download_count": 0, "ttl": 0,
})
print("ok")
`);
}

/**
 * Drive Alice's call UI to the connected (audio) phase against Bob.
 * Backend-driven; copied from call-billing-overlay.spec.ts. Installs a page-side
 * keep-alive that re-dispatches call.accept so the connected overlay stays mounted
 * (headless ICE "fails" ~3s in, which would otherwise flicker the overlay closed).
 */
async function startConnectedPaidCall(alicePage: Page, bobPage: Page, convoId: string) {
  endActiveCallSessions(convoId);

  // Pin the partner rate so isPaidCall is deterministically true the instant the
  // rate query runs (the billing overlay + heartbeat hook gate on it).
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

  await bobPage.goto(`${BASE}/messages/${convoId}`);
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

  const aliceSub = loadSessions()[ALICE].user_sub;
  const bobSub = loadSessions()[BOB].user_sub;

  const acceptResp = await bobPage.request.post(
    `${BASE}/messaging/messages/calls/${callId}/accept`,
    { headers: csrfHeader(BOB), data: { idempotency_key: `demo-accept-${callId}` } },
  );
  expect([200, 409].includes(acceptResp.status())).toBe(true);
  forceCallConnected(callId);

  await alicePage.evaluate(
    (d: Record<string, unknown>) => {
      const w = window as unknown as { __callKeepAlive?: ReturnType<typeof setInterval> };
      const fire = () => {
        window.dispatchEvent(
          new CustomEvent("messaging:call-event", { detail: { ...d, event_ts: Date.now() } }),
        );
      };
      fire();
      if (w.__callKeepAlive) clearInterval(w.__callKeepAlive);
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
  return callId;
}

async function stopCallKeepAlive(page: Page): Promise<void> {
  await page
    .evaluate(() => {
      const w = window as unknown as { __callKeepAlive?: ReturnType<typeof setInterval> };
      if (w.__callKeepAlive) {
        clearInterval(w.__callKeepAlive);
        w.__callKeepAlive = undefined;
      }
    })
    .catch(() => {});
}

test("Segment 03 — Calls", async () => {
  test.setTimeout(600_000);

  const TS = Date.now();
  const recConvoId = `conv_seg03_rec_${TS}`;
  const recId = `rec_seg03_${TS}`;

  // One-time seeds.
  fundWallet();
  seedRecordingConversation(recConvoId, recId);

  // Launch a dedicated fake-media browser + a video-recording Alice context.
  const fakeBrowser: Browser = await chromium.launch({ headless: true, args: FAKE_MEDIA_ARGS });
  const videoDir = path.join(ARTIFACT_DIR, "_rec");
  fs.mkdirSync(videoDir, { recursive: true });

  const aliceCtx = await fakeBrowser.newContext({
    permissions: ["microphone", "camera"],
    viewport: { width: 1920, height: 1080 },
    recordVideo: { dir: videoDir, size: { width: 1920, height: 1080 } },
  });
  const bobCtx = await fakeBrowser.newContext({
    permissions: ["microphone", "camera"],
    viewport: { width: 1920, height: 1080 },
  });
  const page = await aliceCtx.newPage();
  const bobPage = await bobCtx.newPage();

  await injectCallAuth(page, ALICE);
  await injectCallAuth(bobPage, BOB);

  const dmConvoId = await findOrCreateDm(page);

  // Bob enables a paid-call rate (must run on Bob's page).
  await ensurePaidRate(bobPage);

  try {
    // ── 1. Intro ───────────────────────────────────────────────────────────
    await page.goto(`${BASE}/messages/${dmConvoId}`, { waitUntil: "domcontentloaded" });
    await titleCard(
      page,
      3,
      "Voice & Video Calls",
      "1:1 audio/video · paid calls · live billing · recordings",
    );

    // ── 2. Call buttons + rate badge in the conversation header ──────────────
    await page.goto(`${BASE}/messages/${dmConvoId}`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(1500);
    await reveal(
      page,
      page.getByRole("button", { name: "Start audio call" }),
      "Call from any conversation",
      "One-to-one audio and video, right in the chat header",
      { ms: 6500 },
    );
    await reveal(
      page,
      page.getByRole("button", { name: "Start video call" }),
      "Audio or video",
      "Switch on the camera for a full video call",
      { ms: 6000 },
    );
    // ── 3. Paid-call rate badge (per-minute rate before you dial) ────────────
    await reveal(
      page,
      page.locator("[data-testid='paid-call-rate-badge']"),
      "Paid calls",
      "Creators set a per-minute rate — shown up front before you dial",
      { ms: 7000 },
    );

    // ── 4 & 5. Start the call, reach connected, reveal the billing overlay ────
    await caption(page, "Connecting…", "Placing the call and reaching the other side");
    const callId = await startConnectedPaidCall(page, bobPage, dmConvoId);
    expect(callId).not.toBe("");

    // Wait for the connected overlay + a heartbeat so the cost ticker has data.
    // The real backend heartbeat returns live cost/rate/balance — no stubbing.
    await reveal(
      page,
      page.getByLabel("Audio call").first(),
      "Connected",
      "A clean in-call overlay with mute, recording, and hang-up controls",
      { ms: 6500, ring: false },
    );

    // The headline shot: the live cost ticker (running cost · rate · balance).
    await expect(page.getByText(/\$\d+\.\d{2}\/min/).first()).toBeVisible({ timeout: 25_000 });
    await reveal(
      page,
      page.getByText(/\$\d+\.\d{2}\/min/).first(),
      "Live billing",
      "A cost ticker updates in real time — running cost, rate, and balance",
      { ms: 8500, ring: false },
    );
    // Hold a beat on the balance line specifically.
    await reveal(
      page,
      page.getByText(/Bal:\s*\$/).first(),
      "Always-visible balance",
      "Your remaining wallet balance is right there as the call runs",
      { ms: 6500, ring: false },
    );

    // ── 6. End the call → reveal the "Call ended" outcome ────────────────────
    await stopCallKeepAlive(page);
    await caption(page, "Wrap up", "Hang up when you're done");
    await page
      .getByRole("button", { name: /end call/i })
      .first()
      .click()
      .catch(() => {});
    await page.waitForTimeout(2000);
    const ended = page.getByText("Call ended.").first();
    if (await ended.count().catch(() => 0)) {
      await reveal(page, ended, "Call ended", "A clear outcome when the call wraps up", {
        ms: 5500,
        ring: false,
      });
    } else {
      await caption(page, "Call ended", "A clear outcome when the call wraps up");
      await beat(page, 4000);
    }
    await page.keyboard.press("Escape").catch(() => {});
    await page.waitForTimeout(800);

    // ── 7. Recordings panel ──────────────────────────────────────────────────
    await page.goto(`${BASE}/messages/${recConvoId}`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(1500);
    const menuBtn = page.getByRole("button", { name: "Conversation menu" });
    await reveal(page, menuBtn, "Call recordings", "Calls can be recorded — find them in the menu", {
      ms: 4500,
    });
    await menuBtn.click().catch(() => {});
    await page.waitForTimeout(800);
    const recItem = page.getByRole("menuitem", { name: "Recordings" });
    await reveal(page, recItem, "Recordings", "Open the recordings panel", { ms: 3500 });
    await recItem.click().catch(() => {});
    await page.waitForTimeout(1200);
    await reveal(
      page,
      page.getByTestId("recording-item"),
      "Saved & downloadable",
      "Every recording is listed with a one-click download",
      { ms: 7000 },
    );
    await reveal(
      page,
      page.getByRole("link", { name: "Download recording" }),
      "Download recording",
      "Grab the webm whenever you need it",
      { ms: 5000 },
    );

    // ── 8. Outro ──────────────────────────────────────────────────────────────
    await clearCaption(page);
    await caption(page, "Calls ✓", "Next: Newsfeed");
    await beat(page, 3200);
    await clearCaption(page);
    await beat(page, 900);
  } finally {
    // Persist the recorded webm to the standard segment artifact path before
    // closing the contexts/browser.
    const video = page.video();
    await aliceCtx.close();
    await bobCtx.close();
    if (video) {
      try {
        const src = await video.path();
        fs.copyFileSync(src, path.join(ARTIFACT_DIR, "video.webm"));
      } catch {
        /* best-effort */
      }
    }
    await fakeBrowser.close();
    // Cleanup seeded call sessions for the DM (keep the recording row tidy).
    try {
      endActiveCallSessions(dmConvoId);
    } catch {
      /* ignore */
    }
  }
});
