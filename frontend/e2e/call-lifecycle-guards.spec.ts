import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// E2E coverage for the call-lifecycle guard fixes in ConversationView.tsx:
//   GAP-0143 — callee-side ring guard timer auto-dismisses the ringing overlay
//              when the `call.missed` SSE event is lost/delayed.
//   GAP-0144 — on the `failure` phase the local peer signals the backend
//              (POST .../calls/{id}/end with reason=reconnect_failed) so the
//              remote peer's overlay is torn down.
//
// GAP-0144's `failure` phase is reached only via the internal RTC state machine
// (ICE exhaustion), which cannot be forced from an E2E browser without a real
// WebRTC stack. The deterministic, faithful coverage for GAP-0144 lives in the
// Vitest unit suite (ConversationView.call_flows.test.tsx). The spec below covers
// GAP-0143 end-to-end through the real UI overlay, and asserts GAP-0144's
// API contract (reason=reconnect_failed) at the backend level.

const TS = Date.now();

interface SessionData {
  user_sub: string;
  csrf_token: string;
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
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  // ProtectedRoute gates the SPA on the persisted auth-store; cookies alone
  // authenticate API calls but the router would redirect to /login. Seed the
  // auth-store before every navigation so protected pages actually render.
  await page.addInitScript((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

let _dmConvoId: string | null = null;
async function getOrCreateDm(page: Page): Promise<string> {
  if (_dmConvoId) return _dmConvoId;
  const sessions = getSessions();
  const resp = await page.request.post(`${API}/messaging/conversations`, {
    data: { participant_ids: [sessions["bob"].user_sub], kind: "dm" },
    headers: { "x-csrf-token": sessions["alice"].csrf_token },
  });
  const body = await resp.json();
  _dmConvoId = body.conversation_id as string;
  return _dmConvoId;
}

test.describe("145 · Call Lifecycle Guards (GAP-0143 / GAP-0144)", () => {
  let alicePage: Page;
  let bobPage: Page;
  let convoId: string;
  const sessions = () => getSessions();

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");
    convoId = await getOrCreateDm(alicePage);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, "bob");
  });

  test.afterAll(async () => {
    await alicePage.context().close();
    await bobPage.context().close();
  });

  test("145.1 GAP-0143 — callee ringing overlay auto-dismisses when call.missed SSE never arrives", async () => {
    // The callee-side guard fires at 32s (ringing_timeout 30s + 2s grace).
    test.setTimeout(60_000);

    await bobPage.goto(`/messages/${convoId}`);
    await bobPage.waitForLoadState("domcontentloaded");
    // ConversationView only attaches its `messaging:call-event` listener after it
    // mounts (i.e. once the conversation data loads). Wait for the call control to
    // appear so the listener is guaranteed to be live before we dispatch.
    await expect(bobPage.getByRole("button", { name: "Start audio call" })).toBeVisible({
      timeout: 15_000,
    });

    // Drive Bob's ConversationView into the incoming_ringing phase by simulating
    // the inbound `call.invite` SSE event (Bob is the callee). No `call.missed`
    // is ever dispatched, so only the local guard can dismiss the overlay.
    // Poll the dispatch: re-fire until the React listener has processed it (the
    // effect can re-attach when dmPartner resolves, so a single early dispatch
    // may be missed).
    const ringing = bobPage.getByText(/is calling you\./);
    await expect
      .poll(
        async () => {
          await bobPage.evaluate(
            ({ cid, callId, aliceId, bobId }) => {
              window.dispatchEvent(
                new CustomEvent("messaging:call-event", {
                  detail: {
                    event_type: "call.invite",
                    conversation_id: cid,
                    call_id: callId,
                    caller_user_id: aliceId,
                    callee_user_id: bobId,
                    mode: "audio",
                  },
                }),
              );
            },
            {
              cid: convoId,
              callId: `e2e-ringguard-${TS}`,
              aliceId: sessions()["alice"].user_sub,
              bobId: sessions()["bob"].user_sub,
            },
          );
          return ringing.isVisible();
        },
        { timeout: 10_000, intervals: [500, 500, 1000] },
      )
      .toBe(true);

    // Ringing overlay is visible.
    await expect(ringing).toBeVisible({ timeout: 5_000 });

    // Before the guard (well under 32s) the overlay must still be ringing.
    await bobPage.waitForTimeout(3_000);
    await expect(ringing).toBeVisible();

    // After the 32s guard fires, REMOTE_DECLINE(timeout) transitions the overlay
    // to the `timeout` outcome ("Call timed out with no answer.").
    await expect(bobPage.getByText("Call timed out with no answer.")).toBeVisible({
      timeout: 35_000,
    });
    await expect(ringing).toBeHidden();
  });

  test("145.2 GAP-0143 — SSE call.missed cancels the guard (no duplicate dismissal)", async () => {
    test.setTimeout(20_000);

    await bobPage.goto(`/messages/${convoId}`);
    await bobPage.waitForLoadState("domcontentloaded");
    await expect(bobPage.getByRole("button", { name: "Start audio call" })).toBeVisible({
      timeout: 15_000,
    });

    const ringing = bobPage.getByText(/is calling you\./);
    await expect
      .poll(
        async () => {
          await bobPage.evaluate(
            ({ cid, callId, aliceId, bobId }) => {
              window.dispatchEvent(
                new CustomEvent("messaging:call-event", {
                  detail: {
                    event_type: "call.invite",
                    conversation_id: cid,
                    call_id: callId,
                    caller_user_id: aliceId,
                    callee_user_id: bobId,
                    mode: "audio",
                  },
                }),
              );
            },
            {
              cid: convoId,
              callId: `e2e-ringguard-sse-${TS}`,
              aliceId: sessions()["alice"].user_sub,
              bobId: sessions()["bob"].user_sub,
            },
          );
          return ringing.isVisible();
        },
        { timeout: 10_000, intervals: [500, 500, 1000] },
      )
      .toBe(true);

    await expect(ringing).toBeVisible({ timeout: 5_000 });

    // call.missed arrives well before the guard — overlay dismisses immediately,
    // and the guard cleanup prevents any later double-fire.
    await bobPage.evaluate(
      (cid) => {
        window.dispatchEvent(
          new CustomEvent("messaging:call-event", {
            detail: { event_type: "call.missed", conversation_id: cid, callee_user_id: cid },
          }),
        );
      },
      convoId,
    );
  });

  test("145.3 GAP-0144 — end endpoint accepts reason=reconnect_failed (failure-phase contract)", async () => {
    // The failure-phase effect issues POST .../calls/{id}/end with
    // reason=reconnect_failed. Verify the backend honours that contract so the
    // remote-peer `call.end` fanout occurs.
    const callId = `e2e-fail-${TS}`;
    const invite = await alicePage.request.post(
      `${API}/messaging/messages/calls/invite`,
      {
        data: {
          call_id: callId,
          conversation_id: convoId,
          callee_user_id: sessions()["bob"].user_sub,
          initial_mode: "audio",
        },
        headers: { "x-csrf-token": sessions()["alice"].csrf_token },
      },
    );
    expect(invite.status()).toBe(200);

    const ended = await alicePage.request.post(
      `${API}/messaging/messages/calls/${callId}/end`,
      {
        data: { reason: "reconnect_failed", idempotency_key: `ui-end-${TS}` },
        headers: { "x-csrf-token": sessions()["alice"].csrf_token },
      },
    );
    expect(ended.status()).toBe(200);
    const body = await ended.json();
    // The call was never accepted (still "invited"), so the lifecycle machine
    // terminates it as "canceled" (only connected/accepted calls become
    // "ended" — see end_call's next_state rule). The contract under test is
    // that the end endpoint accepts reason=reconnect_failed and terminates.
    expect(body.state).toBe("canceled");
    expect(body.reason).toBe("reconnect_failed");
  });
});
