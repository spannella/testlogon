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

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

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

/** Drive Alice's call UI to the connected phase against Bob and return the call_id. */
async function startConnectedPaidCall(alicePage: Page, bobPage: Page, convoId: string): Promise<string> {
  await alicePage.goto(`${BASE}/messages/${convoId}`);
  await bobPage.goto(`${BASE}/messages/${convoId}`);

  // Alice initiates an audio call.
  await alicePage.getByRole("button", { name: /audio call|call/i }).first().click();

  // Bob accepts the incoming call.
  await bobPage.getByRole("button", { name: /accept/i }).click({ timeout: 30_000 });

  // Wait for Alice's overlay to reach the connected (audio call) layout.
  await expect(alicePage.getByLabel("Audio call")).toBeVisible({ timeout: 30_000 });

  // Read the active call_id from the latest call session in the conversation.
  const script = `
import boto3, json
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
table = ddb.Table("MessageCallSessions")
resp = table.scan(
    FilterExpression="conversation_id = :cid",
    ExpressionAttributeValues={":cid": "${convoId}"},
)
items = sorted(resp.get("Items", []), key=lambda i: i.get("create_ts", 0))
print(items[-1]["call_id"] if items else "")
`;
  return execSync(`${PYTHON} -c '${script}'`, { cwd: "/home/ubuntu/testlogon", timeout: 10_000 })
    .toString()
    .trim();
}

test.describe.serial("GAP-0016 — paid-call billing heartbeat is sent from the UI", () => {
  let alicePage: Page;
  let bobPage: Page;
  let convoId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
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

    // The hook's onEndCall handler ends the call -> the connected overlay closes.
    await expect(alicePage.getByLabel("Audio call")).not.toBeVisible({ timeout: 20_000 });
    await alicePage.unroute("**/messaging/messages/calls/*/heartbeat");
  });
});
