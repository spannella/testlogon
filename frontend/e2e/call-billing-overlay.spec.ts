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

/** Drive Alice's call UI to the connected (audio) phase against Bob. */
async function startConnectedPaidCall(alicePage: Page, bobPage: Page, convoId: string) {
  await alicePage.goto(`${BASE}/messages/${convoId}`);
  await bobPage.goto(`${BASE}/messages/${convoId}`);

  // Both ConversationViews must be mounted (call-event SSE listeners attached)
  // before Alice initiates, so the invite reaches Bob and the accept reaches Alice.
  await expect(alicePage.getByRole("button", { name: "Start audio call" })).toBeVisible({ timeout: 15_000 });
  await expect(bobPage.getByRole("button", { name: "Start audio call" })).toBeVisible({ timeout: 15_000 });

  await alicePage.getByRole("button", { name: "Start audio call" }).click();
  await bobPage.getByRole("button", { name: /accept/i }).click({ timeout: 30_000 });
  await expect(alicePage.getByLabel("Audio call")).toBeVisible({ timeout: 30_000 });
}

test.describe.serial("GAP-0147 — paid-call billing overlay renders in the call UI", () => {
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
    await expect(alicePage.getByText("$7.50")).toBeVisible({ timeout: 20_000 });
    await expect(alicePage.getByText("$5.00/min")).toBeVisible();
    await expect(alicePage.getByText(/Bal:\s*\$42\.50/)).toBeVisible();

    await alicePage.getByRole("button", { name: /end call/i }).click();
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

    await expect(alicePage.getByText(/Low balance/i)).toBeVisible({ timeout: 20_000 });
    await expect(alicePage.getByText(/0\.4 min remaining/i)).toBeVisible();

    await alicePage.getByRole("button", { name: /end call/i }).click();
    await alicePage.unroute("**/messaging/messages/calls/*/heartbeat");
  });
});
