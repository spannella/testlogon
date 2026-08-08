/**
 * CALL-002: WebRTC Peer Connection Management — E2E Tests
 *
 * Tests the signaling relay endpoint (POST /messages/calls/{call_id}/signal)
 * for offer/answer/ICE candidate exchange, validation, auth enforcement,
 * and error handling. WebRTC media tests are in webrtc-media.spec.ts.
 */
import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

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
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
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
  return `e2e-pc-${TS}-${suffix}`;
}

function nonce(): string {
  return `nonce-${Date.now()}-${Math.random().toString(36).slice(2, 12)}`;
}

function eventId(prefix: string): string {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 12)}`;
}

/** Create an accepted call between Alice and Bob. Returns the call_id. */
async function createAcceptedCall(
  alicePage: Page,
  bobPage: Page,
  convoId: string,
  suffix: string,
): Promise<string> {
  const sessions = getSessions();
  const cid = callId(suffix);
  await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
    call_id: cid,
    conversation_id: convoId,
    callee_user_id: sessions["bob"].user_sub,
  });
  await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/accept`, {});
  return cid;
}

/** End a call (best-effort cleanup). */
async function endCall(page: Page, identity: string, cid: string) {
  await apiPost(page, identity, `/messaging/messages/calls/${cid}/end`, {}).catch(() => {});
}

/* ------------------------------------------------------------------ */
/*  Section 146 — Signaling Relay: Offer / Answer / ICE                */
/* ------------------------------------------------------------------ */

test.describe("146 · Peer Connection — Signaling Relay", () => {
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

  test("146.1 Alice sends webrtc.offer after accept — delivered", async () => {
    const cid = await createAcceptedCall(alicePage, bobPage, convoId, "offer-1");

    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.offer",
      event_id: eventId("offer"),
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: {
        sdp: "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n",
        type: "offer",
      },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("delivered");
    expect(body.call_id).toBe(cid);
    expect(body.event_type).toBe("webrtc.offer");
    expect(body.delivered_to).toBe(sessions()["bob"].user_sub);

    await endCall(alicePage, "alice", cid);
  });

  test("146.2 Bob sends webrtc.answer — delivered", async () => {
    const cid = await createAcceptedCall(alicePage, bobPage, convoId, "answer-1");

    // Alice sends offer first (required before answer)
    await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.offer",
      event_id: eventId("offer"),
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: { sdp: "v=0\r\n", type: "offer" },
    });

    // Bob sends answer
    const resp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.answer",
      event_id: eventId("answer"),
      conversation_id: convoId,
      recipient_user_id: sessions()["alice"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: { sdp: "v=0\r\n", type: "answer" },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("delivered");
    expect(body.event_type).toBe("webrtc.answer");
    expect(body.delivered_to).toBe(sessions()["alice"].user_sub);

    await endCall(alicePage, "alice", cid);
  });

  test("146.3 Alice trickles ICE candidate — delivered", async () => {
    const cid = await createAcceptedCall(alicePage, bobPage, convoId, "ice-1");

    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.ice_candidate",
      event_id: eventId("ice"),
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: {
        candidate: "candidate:1 1 udp 2122260223 192.168.1.1 50000 typ host",
        sdpMid: "0",
        sdpMLineIndex: 0,
        usernameFragment: "abc123",
      },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("delivered");
    expect(body.event_type).toBe("webrtc.ice_candidate");

    await endCall(alicePage, "alice", cid);
  });

  test("146.4 Multiple ICE candidates trickled in sequence", async () => {
    const cid = await createAcceptedCall(alicePage, bobPage, convoId, "multi-ice");

    for (let i = 0; i < 3; i++) {
      const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
        type: "webrtc.ice_candidate",
        event_id: eventId(`ice-${i}`),
        conversation_id: convoId,
        recipient_user_id: sessions()["bob"].user_sub,
        nonce: nonce(),
        sent_at: Math.floor(Date.now() / 1000),
        payload: {
          candidate: `candidate:${i} 1 udp 2122260223 192.168.1.${i + 1} 5000${i} typ host`,
          sdpMid: "0",
          sdpMLineIndex: 0,
        },
      });
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      expect(body.status).toBe("delivered");
    }

    await endCall(alicePage, "alice", cid);
  });

  test("146.5 Empty payload for ICE end-of-candidates succeeds", async () => {
    const cid = await createAcceptedCall(alicePage, bobPage, convoId, "eoc");

    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.ice_candidate",
      event_id: eventId("ice-eoc"),
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: {},
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("delivered");

    await endCall(alicePage, "alice", cid);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 147 — Signaling Validation & Error Cases                    */
/* ------------------------------------------------------------------ */

test.describe("147 · Peer Connection — Signaling Errors", () => {
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

  test("147.1 Signal to non-existent call returns 404", async () => {
    const resp = await apiPost(alicePage, "alice", "/messaging/messages/calls/nonexistent-xyz-999/signal", {
      type: "webrtc.offer",
      event_id: eventId("offer"),
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: { sdp: "v=0\r\n", type: "offer" },
    });
    expect(resp.status()).toBe(404);
    const body = await resp.json();
    expect(body.detail.code).toBe("call_not_found");
  });

  test("147.2 webrtc.offer on invited call (before accept) returns 409", async () => {
    const cid = callId("sig-invited");
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });

    // Try webrtc.offer while state=invited (not accepted yet)
    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.offer",
      event_id: eventId("offer"),
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: { sdp: "v=0\r\n", type: "offer" },
    });
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail.code).toBe("invalid_state");

    await endCall(alicePage, "alice", cid);
  });

  test("147.3 Signal on ended call returns 409", async () => {
    const cid = await createAcceptedCall(alicePage, bobPage, convoId, "sig-ended");
    await endCall(alicePage, "alice", cid);

    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.offer",
      event_id: eventId("offer"),
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: { sdp: "v=0\r\n", type: "offer" },
    });
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail.code).toBe("invalid_state");
  });

  test("147.4 Replay nonce rejection returns 409", async () => {
    const cid = await createAcceptedCall(alicePage, bobPage, convoId, "sig-replay");

    const fixedNonce = nonce();
    const fixedEid = eventId("offer");
    const payload = {
      type: "webrtc.offer" as const,
      event_id: fixedEid,
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: fixedNonce,
      sent_at: Math.floor(Date.now() / 1000),
      payload: { sdp: "v=0\r\n", type: "offer" },
    };

    // First send succeeds
    const resp1 = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, payload);
    expect(resp1.status()).toBe(200);

    // Replay with same nonce returns 409
    const resp2 = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, payload);
    expect(resp2.status()).toBe(409);
    const body2 = await resp2.json();
    expect(body2.detail.code).toBe("replay_detected");

    await endCall(alicePage, "alice", cid);
  });

  test("147.5 Non-participant sends signal returns 403", async () => {
    const cid = await createAcceptedCall(alicePage, bobPage, convoId, "sig-forbidden");

    // Charlie is not in Alice-Bob DM
    const charlieCtx = await alicePage.context().browser()!.newContext();
    const charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, "charlie_admin");

    const resp = await apiPost(charliePage, "charlie_admin", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.offer",
      event_id: eventId("offer"),
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: { sdp: "v=0\r\n", type: "offer" },
    });
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.detail.code).toBe("forbidden");

    await charlieCtx.close();
    await endCall(alicePage, "alice", cid);
  });

  test("147.6 Stale timestamp returns 400", async () => {
    const cid = await createAcceptedCall(alicePage, bobPage, convoId, "sig-stale");

    // Send with timestamp 10 minutes in the past (beyond MAX_SIGNALING_SKEW_SECONDS=120)
    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.offer",
      event_id: eventId("offer"),
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000) - 600,
      payload: { sdp: "v=0\r\n", type: "offer" },
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail.code).toBe("stale_timestamp");

    await endCall(alicePage, "alice", cid);
  });

  test("147.7 Sender cannot target themselves", async () => {
    const cid = await createAcceptedCall(alicePage, bobPage, convoId, "sig-self");

    // Alice sends to herself
    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.offer",
      event_id: eventId("offer"),
      conversation_id: convoId,
      recipient_user_id: sessions()["alice"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: { sdp: "v=0\r\n", type: "offer" },
    });
    // Should be 400 (validation_error: sender and recipient must differ)
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail.code).toBe("validation_error");

    await endCall(alicePage, "alice", cid);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 148 — Full Signaling Exchange                               */
/* ------------------------------------------------------------------ */

test.describe("148 · Peer Connection — Full Signaling Exchange", () => {
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

  test("148.1 invite -> accept -> offer -> answer -> ICE -> end", async () => {
    const cid = await createAcceptedCall(alicePage, bobPage, convoId, "full-1");

    // 1. Alice sends offer
    const offerResp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.offer",
      event_id: eventId("offer"),
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: {
        sdp: "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n",
        type: "offer",
      },
    });
    expect(offerResp.status()).toBe(200);
    expect((await offerResp.json()).status).toBe("delivered");

    // 2. Bob sends answer
    const answerResp = await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.answer",
      event_id: eventId("answer"),
      conversation_id: convoId,
      recipient_user_id: sessions()["alice"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: {
        sdp: "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n",
        type: "answer",
      },
    });
    expect(answerResp.status()).toBe(200);
    expect((await answerResp.json()).status).toBe("delivered");

    // 3. Both send ICE candidates
    const aliceIce = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.ice_candidate",
      event_id: eventId("ice-a"),
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: {
        candidate: "candidate:1 1 udp 2122260223 10.0.0.1 50000 typ host",
        sdpMid: "0",
        sdpMLineIndex: 0,
      },
    });
    expect(aliceIce.status()).toBe(200);

    const bobIce = await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.ice_candidate",
      event_id: eventId("ice-b"),
      conversation_id: convoId,
      recipient_user_id: sessions()["alice"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: {
        candidate: "candidate:1 1 udp 2122260223 10.0.0.2 50001 typ host",
        sdpMid: "0",
        sdpMLineIndex: 0,
      },
    });
    expect(bobIce.status()).toBe(200);

    // 4. End call
    const endResp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/end`, {
      reason: "ended",
    });
    expect(endResp.status()).toBe(200);
    expect((await endResp.json()).state).toBe("ended");
  });

  test("148.2 Bidirectional ICE exchange (interleaved)", async () => {
    const cid = await createAcceptedCall(alicePage, bobPage, convoId, "bidir-ice");

    // Alice and Bob interleave ICE candidates
    for (let i = 0; i < 3; i++) {
      const aliceR = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
        type: "webrtc.ice_candidate",
        event_id: eventId(`a-ice-${i}`),
        conversation_id: convoId,
        recipient_user_id: sessions()["bob"].user_sub,
        nonce: nonce(),
        sent_at: Math.floor(Date.now() / 1000),
        payload: { candidate: `candidate:${i} 1 udp 2 10.0.0.1 500${i} typ host`, sdpMid: "0", sdpMLineIndex: 0 },
      });
      expect(aliceR.status()).toBe(200);

      const bobR = await apiPost(bobPage, "bob", `/messaging/messages/calls/${cid}/signal`, {
        type: "webrtc.ice_candidate",
        event_id: eventId(`b-ice-${i}`),
        conversation_id: convoId,
        recipient_user_id: sessions()["alice"].user_sub,
        nonce: nonce(),
        sent_at: Math.floor(Date.now() / 1000),
        payload: { candidate: `candidate:${i} 1 udp 2 10.0.0.2 600${i} typ host`, sdpMid: "0", sdpMLineIndex: 0 },
      });
      expect(bobR.status()).toBe(200);
    }

    await endCall(alicePage, "alice", cid);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 149 — Signaling Response Shape                              */
/* ------------------------------------------------------------------ */

test.describe("149 · Peer Connection — Response Shape Validation", () => {
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

  test("149.1 Signaling ack contains all required fields", async () => {
    const cid = await createAcceptedCall(alicePage, bobPage, convoId, "ack-shape");

    const eid = eventId("offer");
    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.offer",
      event_id: eid,
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: { sdp: "v=0\r\n", type: "offer" },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();

    // Validate every required field
    expect(body).toHaveProperty("event_id", eid);
    expect(body).toHaveProperty("call_id", cid);
    expect(body).toHaveProperty("conversation_id", convoId);
    expect(body).toHaveProperty("event_type", "webrtc.offer");
    expect(body).toHaveProperty("delivered_to", sessions()["bob"].user_sub);
    expect(body).toHaveProperty("status", "delivered");

    await endCall(alicePage, "alice", cid);
  });

  test("149.2 Error response has code and message", async () => {
    const resp = await apiPost(alicePage, "alice", "/messaging/messages/calls/nonexistent-abc/signal", {
      type: "webrtc.offer",
      event_id: eventId("offer"),
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: {},
    });
    expect(resp.status()).toBe(404);
    const body = await resp.json();
    expect(body.detail).toHaveProperty("code");
    expect(body.detail).toHaveProperty("message");
    expect(typeof body.detail.code).toBe("string");
    expect(typeof body.detail.message).toBe("string");
  });

  test("149.3 Duplicate event_id returns status=duplicate", async () => {
    const cid = await createAcceptedCall(alicePage, bobPage, convoId, "dup-eid");

    const eid = eventId("offer");
    // First send
    const resp1 = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.offer",
      event_id: eid,
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: { sdp: "v=0\r\n", type: "offer" },
    });
    expect(resp1.status()).toBe(200);
    expect((await resp1.json()).status).toBe("delivered");

    // Second send with same event_id but different nonce
    // The nonce dedup will reject this before the event_id dedup
    // since the nonce already consumed the conditional write slot
    const resp2 = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.offer",
      event_id: eid,
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(), // different nonce
      sent_at: Math.floor(Date.now() / 1000),
      payload: { sdp: "v=0\r\n", type: "offer" },
    });
    expect(resp2.status()).toBe(200);
    const body2 = await resp2.json();
    // The event_id conditional write detects the duplicate
    expect(body2.status).toBe("duplicate");

    await endCall(alicePage, "alice", cid);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 150 — Authentication Enforcement                            */
/* ------------------------------------------------------------------ */

test.describe("150 · Peer Connection — Auth Enforcement", () => {
  test("150.1 Unauthenticated signal request returns 401 or 403", async ({ page }) => {
    // No cookies injected — request is unauthenticated
    const resp = await page.request.post(
      `${API}/messaging/messages/calls/some-call-id/signal`,
      {
        data: {
          type: "webrtc.offer",
          event_id: "test-event",
          conversation_id: "test-convo",
          recipient_user_id: "test-user",
          nonce: "nonce12345678",
          sent_at: Math.floor(Date.now() / 1000),
          payload: {},
        },
      },
    );
    expect([401, 403]).toContain(resp.status());
  });

  test("150.2 Unauthenticated invite request returns 401 or 403", async ({ page }) => {
    const resp = await page.request.post(
      `${API}/messaging/messages/calls/invite`,
      {
        data: {
          call_id: "unauth-call",
          conversation_id: "some-convo",
          callee_user_id: "some-user",
        },
      },
    );
    expect([401, 403]).toContain(resp.status());
  });

  test("150.3 Unauthenticated TURN credentials request returns 401 or 403", async ({ page }) => {
    const resp = await page.request.post(
      `${API}/messaging/messages/calls/some-call/turn-credentials`,
      { data: {} },
    );
    expect([401, 403]).toContain(resp.status());
  });
});

/* ------------------------------------------------------------------ */
/*  Section 151 — Screen Share Signaling                                */
/* ------------------------------------------------------------------ */

test.describe("151 · Peer Connection — Screen Share Signals", () => {
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

  test("151.1 Screen share start in accepted state delivers", async () => {
    const cid = await createAcceptedCall(alicePage, bobPage, convoId, "ss-start");

    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.screen_share_start",
      event_id: eventId("ss-start"),
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: { track_id: "screen-track-1" },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("delivered");
    expect(body.event_type).toBe("webrtc.screen_share_start");

    await endCall(alicePage, "alice", cid);
  });

  test("151.2 Screen share stop delivers", async () => {
    const cid = await createAcceptedCall(alicePage, bobPage, convoId, "ss-stop");

    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.screen_share_stop",
      event_id: eventId("ss-stop"),
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: {},
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("delivered");
    expect(body.event_type).toBe("webrtc.screen_share_stop");

    await endCall(alicePage, "alice", cid);
  });

  test("151.3 Screen share in invited state returns 409", async () => {
    const cid = callId("ss-invited");
    await apiPost(alicePage, "alice", "/messaging/messages/calls/invite", {
      call_id: cid,
      conversation_id: convoId,
      callee_user_id: sessions()["bob"].user_sub,
    });

    // No accept — still in invited state
    const resp = await apiPost(alicePage, "alice", `/messaging/messages/calls/${cid}/signal`, {
      type: "webrtc.screen_share_start",
      event_id: eventId("ss-start"),
      conversation_id: convoId,
      recipient_user_id: sessions()["bob"].user_sub,
      nonce: nonce(),
      sent_at: Math.floor(Date.now() / 1000),
      payload: {},
    });
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail.code).toBe("invalid_state");

    await endCall(alicePage, "alice", cid);
  });
});
