import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const API = "http://localhost:8000";
const TS = Date.now();

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
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
}

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body: object,
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

let _dmConvoId: string | null = null;

async function getOrCreateDm(page: Page): Promise<string> {
  if (_dmConvoId) return _dmConvoId;
  const sessions = getSessions();
  const resp = await page.request.post(
    `${API}/messaging/conversations`,
    {
      data: {
        participant_ids: [sessions["bob"].user_sub],
        kind: "dm",
      },
      headers: { "x-csrf-token": sessions["alice"].csrf_token },
    },
  );
  const body = await resp.json();
  _dmConvoId = body.conversation_id as string;
  return _dmConvoId;
}

function callId(suffix: string): string {
  return `e2e-call-${TS}-${suffix}`;
}

/* ------------------------------------------------------------------ */
/*  Section 1 — Call Invite Flow                                       */
/* ------------------------------------------------------------------ */

test.describe("140 · WebRTC Call Lifecycle — Invite Flow", () => {
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

  test("140.1 Alice invites Bob — state=invited", async () => {
    const cid = callId("invite-1");
    const resp = await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
      initial_mode: "audio",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.call_id).toBe(cid);
    expect(body.state).toBe("invited");
    expect(body.caller_user_id).toBe(sessions()["alice"].user_sub);
    expect(body.callee_user_id).toBe(sessions()["bob"].user_sub);
    expect(body.initial_mode).toBe("audio");
    expect(body.start_ts).toBeGreaterThan(0);

    // Clean up — end the call
    await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/end`, {
      reason: "canceled",
    });
  });

  test("140.2 Duplicate call_id → 409", async () => {
    const cid = callId("invite-dup");
    // Create first
    const resp1 = await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });
    expect(resp1.status()).toBe(200);

    // Duplicate
    const resp2 = await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });
    expect(resp2.status()).toBe(409);
    const body = await resp2.json();
    expect(body.detail.code).toBe("duplicate_call_id");

    // Clean up
    await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/end`, {});
  });

  test("140.3 Non-participant → 403", async () => {
    // Charlie is not in Alice-Bob DM
    const charlieSessions = getSessions();
    const charlieCtx = await alicePage.context().browser()!.newContext();
    const charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, "charlie_admin");

    const cid = callId("invite-forbidden");
    const resp = await apiPost(charliePage, "charlie_admin", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: charlieSessions["bob"].user_sub,
    });
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.detail.code).toBe("forbidden");

    await charlieCtx.close();
  });

  test("140.4 Idempotent retry with same key → same result", async () => {
    const cid = callId("invite-idempotent");
    const idemKey = `idem-${TS}-invite`;
    const payload = {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
      idempotency_key: idemKey,
    };

    const resp1 = await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", payload);
    expect(resp1.status()).toBe(200);
    const body1 = await resp1.json();

    const resp2 = await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", payload);
    expect(resp2.status()).toBe(200);
    const body2 = await resp2.json();
    expect(body2.call_id).toBe(body1.call_id);
    expect(body2.state).toBe(body1.state);

    // Clean up
    await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/end`, {});
  });

  test("140.5 Video mode invite works", async () => {
    const cid = callId("invite-video");
    const resp = await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
      initial_mode: "video",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.initial_mode).toBe("video");

    // Clean up
    await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/end`, {});
  });
});

/* ------------------------------------------------------------------ */
/*  Section 2 — Accept / Decline Flow                                  */
/* ------------------------------------------------------------------ */

test.describe("141 · WebRTC Call Lifecycle — Accept & Decline", () => {
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

  test("141.1 Bob accepts invite → state=accepted", async () => {
    const cid = callId("accept-1");
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });

    const resp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/accept`, {});
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.state).toBe("accepted");
    expect(body.from_state).toBe("invited");
    expect(body.call_id).toBe(cid);

    // Clean up
    await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/end`, {});
  });

  test("141.2 Only callee can accept (Alice → 403)", async () => {
    const cid = callId("accept-forbidden");
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });

    // Alice (caller) tries to accept — should fail
    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/accept`, {});
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.detail.code).toBe("forbidden");

    // Clean up
    await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/end`, {});
  });

  test("141.3 Bob declines → state=declined", async () => {
    const cid = callId("decline-1");
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });

    const resp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/decline`, {
      reason: "declined",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.state).toBe("declined");
    expect(body.from_state).toBe("invited");
    expect(body.reason).toBe("declined");
  });

  test("141.4 Decline with reason=busy → state=busy", async () => {
    const cid = callId("decline-busy");
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });

    const resp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/decline`, {
      reason: "busy",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.state).toBe("busy");
    expect(body.reason).toBe("busy");
  });

  test("141.5 Accept already-declined call → 409", async () => {
    const cid = callId("accept-declined");
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });
    await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/decline`, {});

    const resp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/accept`, {});
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail.code).toBe("invalid_state_transition");
  });
});

/* ------------------------------------------------------------------ */
/*  Section 3 — End Call Flow                                          */
/* ------------------------------------------------------------------ */

test.describe("142 · WebRTC Call Lifecycle — End Call", () => {
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

  test("142.1 Either participant ends accepted call → state=ended", async () => {
    const cid = callId("end-accepted");
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });
    await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/accept`, {});

    // Alice ends the call
    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/end`, {
      reason: "ended",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.state).toBe("ended");
    expect(body.from_state).toBe("accepted");
    expect(body.reason).toBe("ended");
  });

  test("142.2 Bob ends accepted call → state=ended", async () => {
    const cid = callId("end-by-bob");
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });
    await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/accept`, {});

    const resp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/end`, {
      reason: "ended",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.state).toBe("ended");
  });

  test("142.3 End invited call (not yet accepted) → state=canceled", async () => {
    const cid = callId("end-invited");
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });

    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/end`, {
      reason: "canceled",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.state).toBe("canceled");
    expect(body.from_state).toBe("invited");
  });

  test("142.4 End already-ended call → 409", async () => {
    const cid = callId("end-double");
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });
    await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/accept`, {});
    await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/end`, {});

    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/end`, {});
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail.code).toBe("invalid_state_transition");
  });

  test("142.5 Non-participant cannot end call → 403", async () => {
    const cid = callId("end-forbidden");
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });

    const charlieCtx = await alicePage.context().browser()!.newContext();
    const charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, "charlie_admin");

    const resp = await apiPost(charliePage, "charlie_admin", `/messaging/messages/calls/${cid}/end`, {});
    expect(resp.status()).toBe(403);

    await charlieCtx.close();
    // Clean up
    await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/end`, {});
  });
});

/* ------------------------------------------------------------------ */
/*  Section 4 — Timeout Flow                                           */
/* ------------------------------------------------------------------ */

test.describe("143 · WebRTC Call Lifecycle — Timeout", () => {
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

  test("143.1 Caller timeouts invited call → state=missed", async () => {
    const cid = callId("timeout-1");
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });

    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/timeout`, {
      reason: "no_answer",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.state).toBe("missed");
    expect(body.from_state).toBe("invited");
    expect(body.reason).toBe("no_answer");
  });

  test("143.2 Timeout already-accepted → 409", async () => {
    const cid = callId("timeout-accepted");
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });
    await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/accept`, {});

    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/timeout`, {});
    expect(resp.status()).toBe(409);

    // Clean up
    await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/end`, {});
  });

  test("143.3 Non-existent call → 404", async () => {
    const resp = await apiPost(alicePage, "alice", "/messaging/messages/calls/nonexistent-call-xyz/timeout", {});
    expect(resp.status()).toBe(404);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 5 — Full Lifecycle (Happy Path)                            */
/* ------------------------------------------------------------------ */

test.describe("144 · WebRTC Call Lifecycle — Full Lifecycle", () => {
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

  test("144.1 invite → accept → end (happy path)", async () => {
    const cid = callId("lifecycle-happy");

    // 1. Alice invites Bob
    const inviteResp = await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });
    expect(inviteResp.status()).toBe(200);
    const invite = await inviteResp.json();
    expect(invite.state).toBe("invited");

    // 2. Bob accepts
    const acceptResp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/accept`, {});
    expect(acceptResp.status()).toBe(200);
    const accepted = await acceptResp.json();
    expect(accepted.state).toBe("accepted");
    expect(accepted.from_state).toBe("invited");

    // 3. Alice ends the call
    const endResp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/end`, {
      reason: "ended",
    });
    expect(endResp.status()).toBe(200);
    const ended = await endResp.json();
    expect(ended.state).toBe("ended");
    expect(ended.from_state).toBe("accepted");
  });

  test("144.2 invite → decline → verify terminal", async () => {
    const cid = callId("lifecycle-decline");

    const inviteResp = await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });
    expect(inviteResp.status()).toBe(200);

    const declineResp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/decline`, {
      reason: "declined",
    });
    expect(declineResp.status()).toBe(200);
    const declined = await declineResp.json();
    expect(declined.state).toBe("declined");

    // Verify terminal — cannot accept after decline
    const acceptResp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/accept`, {});
    expect(acceptResp.status()).toBe(409);

    // Cannot end either
    const endResp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/end`, {});
    expect(endResp.status()).toBe(409);
  });

  test("144.3 invite → cancel by caller → verify terminal", async () => {
    const cid = callId("lifecycle-cancel");

    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });

    const endResp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/end`, {
      reason: "canceled",
    });
    expect(endResp.status()).toBe(200);
    const body = await endResp.json();
    expect(body.state).toBe("canceled");

    // Cannot accept after cancel
    const acceptResp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/accept`, {});
    expect(acceptResp.status()).toBe(409);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 6 — TURN Credentials                                       */
/* ------------------------------------------------------------------ */

test.describe("145 · WebRTC TURN Credentials", () => {
  let alicePage: Page;
  let convoId: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, "alice");
    convoId = await getOrCreateDm(alicePage);
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("145.1 TURN credentials for a call participant → 200 with ICE servers", async () => {
    // With MESSAGING_WEBRTC_TURN_ENABLED + MESSAGING_WEBRTC_TURN_URLS configured
    // (CI/e2e parity), a valid participant of an active call gets real short-lived
    // TURN credentials. (When the feature is disabled the endpoint returns 403
    // feature_disabled — covered by the disabled-path tests in webrtc.spec.ts.)
    const cid = callId("turn-creds");
    const sessions = getSessions();
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions["bob"].user_sub,
    });

    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/turn-credentials`, {});
    // Enabled+configured -> 200; if the env has TURN off, tolerate 403 feature_disabled.
    expect([200, 403]).toContain(resp.status());
    const body = await resp.json();
    if (resp.status() === 200) {
      expect(Array.isArray(body.ice_servers)).toBe(true);
      expect(body.ice_servers.length).toBeGreaterThanOrEqual(1);
      expect(body.ice_servers[0].urls).toBeTruthy();
      expect(typeof body.ttl_seconds).toBe("number");
      expect(body.ttl_seconds).toBeGreaterThan(0);
    } else {
      expect(body.detail.code).toBe("feature_disabled");
    }

    // Clean up
    await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/end`, {});
  });

  test("145.2 TURN credentials endpoint exists (POST, not GET)", async () => {
    // GET should return 405 Method Not Allowed since the endpoint is POST-only
    const resp = await apiGet(alicePage, "/messaging/messages/calls/nonexistent-xyz/turn-credentials");
    expect(resp.status()).toBe(405);
  });
});
