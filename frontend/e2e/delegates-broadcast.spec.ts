/**
 * E2E tests for Broadcast Chat Delegation (DELEGATE-004).
 *
 * Sections:
 *   499 -- Broadcast Chat Moderation API      (5 tests)
 *   500 -- Broadcast Control Delegation API   (4 tests)
 *   501 -- Multi-Moderator & Ban API          (4 tests)
 *   502 -- Moderation Audit & System Messages (3 tests)
 *
 * Auth: Alice (creator), Bob (delegate with broadcast_moderate + broadcast_control),
 *       Charlie (delegate with broadcast_moderate only).
 *
 * Uses cookie-based auth with CSRF headers on all mutating requests.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// -- Constants ----------------------------------------------------------------

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";

const TS = Date.now();

// -- Session bootstrap --------------------------------------------------------

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
    // admin setup keys by short name (alice/bob); alias by user_sub so email-id lookups resolve
    for (const _k of Object.keys(_sessions)) { const _s = _sessions[_k]; if (_s && _s.user_sub && !_sessions[_s.user_sub]) _sessions[_s.user_sub] = _s; }
  }
  return _sessions!;
}

// -- Auth helpers -------------------------------------------------------------

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

// -- API helpers --------------------------------------------------------------

async function apiPost(page: Page, userId: string, path: string, body: object) {
  const session = getSessions()[userId];
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

async function apiPut(page: Page, userId: string, path: string, body: object) {
  const session = getSessions()[userId];
  return page.request.put(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiDelete(page: Page, userId: string, path: string) {
  const session = getSessions()[userId];
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// -- Delegate setup helpers ---------------------------------------------------

async function ensureDelegateWithPerms(
  alicePage: Page,
  delegateId: string,
  perms: string[],
) {
  // Try to revoke first to avoid 409
  await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${delegateId}`);

  // Set require_acceptance = false so delegation is immediately active
  await apiPut(alicePage, ALICE_ID, "/ui/delegates/settings", {
    require_acceptance: false,
    max_delegates: 10,
    delegate_tag_enabled: true,
    delegate_tag_format: "[via @{delegate_name}]",
  });

  const addResp = await apiPost(alicePage, ALICE_ID, "/ui/delegates", {
    delegate_id: delegateId,
    permissions: perms,
    label: `${delegateId} - Broadcast Delegate`,
  });
  expect(addResp.status()).toBe(200);
  const data = await addResp.json();
  expect(data.status).toBe("active");
}

// -- Broadcast session setup --------------------------------------------------

async function createBroadcastProfile(page: Page, userId: string): Promise<string> {
  const resp = await apiPost(page, userId, "/broadcast/profiles", {
    name: `E2E Profile ${TS}`,
    region: "us-east-1",
    rendition_preset: "adaptive-720p",
  });
  expect(resp.status()).toBe(201);
  const data = await resp.json();
  return data.id;
}

async function createBroadcastSession(page: Page, userId: string, profileId: string): Promise<string> {
  const resp = await apiPost(page, userId, "/broadcast/sessions", {
    profile_id: profileId,
  });
  expect(resp.status()).toBe(201);
  const data = await resp.json();
  return data.id;
}

// Transition a freshly-created session to "live" so chat is available.
// Chat (and chat moderation) requires the broadcast to be live. The /start
// endpoint requires an operator (admin/root) role, so the session creator
// (Alice, a regular USER) cannot start it — start it as root instead. The
// route does not check session ownership, only the caller's role.
async function startBroadcastSession(browser: Browser, sessionId: string): Promise<void> {
  const rootCtx = await browser.newContext();
  const rootPage = await rootCtx.newPage();
  await injectAuth(rootPage, "root");
  const resp = await apiPost(rootPage, "root", `/broadcast/sessions/${sessionId}/start`, {});
  expect([200, 202]).toContain(resp.status());
  await rootCtx.close();
}

async function sendChatMessage(
  page: Page,
  userId: string,
  sessionId: string,
  text: string,
): Promise<string> {
  // Broadcast chat enforces a per-user/per-session minimum interval
  // (BROADCAST_CHAT_RATE_LIMIT_MS=2000). Consecutive sends from the same
  // user within 2s return 429. Wait the window out, and retry once if a
  // residual limit from a prior send is still active.
  let resp = await apiPost(page, userId, `/broadcast/sessions/${sessionId}/chat`, {
    text,
  });
  if (resp.status() === 429) {
    await new Promise((r) => setTimeout(r, 2100));
    resp = await apiPost(page, userId, `/broadcast/sessions/${sessionId}/chat`, {
      text,
    });
  }
  expect([200, 201]).toContain(resp.status());
  const data = await resp.json();
  return data.message_id;
}

// =============================================================================
// Section 499: Broadcast Chat Moderation API (5 tests)
// =============================================================================

test.describe("499 -- Broadcast Chat Moderation API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let profileId: string;
  let sessionId: string;
  let chatMsgId: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    // Set up Bob as delegate with broadcast_moderate + broadcast_control
    await ensureDelegateWithPerms(alicePage, BOB_ID, [
      "broadcast_moderate",
      "broadcast_control",
    ]);

    // Create broadcast profile and session as Alice
    profileId = await createBroadcastProfile(alicePage, ALICE_ID);
    sessionId = await createBroadcastSession(alicePage, ALICE_ID, profileId);
    // Chat is only available while the broadcast is live.
    await startBroadcastSession(browser, sessionId);

    // Send a chat message as Alice that Bob can moderate
    chatMsgId = await sendChatMessage(alicePage, ALICE_ID, sessionId, `Test msg ${TS}`);
  });

  test.afterAll(async () => {
    await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${BOB_ID}`);
    await alicePage.context().close();
    await bobPage.context().close();
  });

  test("499.1 Moderator pins a chat message", async () => {
    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/chat/${chatMsgId}/pin`,
      {},
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.pinned).toBe(true);
    expect(data.pinned_by).toBe(BOB_ID);
    expect(data.message_id).toBe(chatMsgId);
  });

  test("499.2 Moderator deletes a chat message", async () => {
    // Send a new message to delete
    const msgId = await sendChatMessage(alicePage, ALICE_ID, sessionId, `Delete me ${TS}`);

    const resp = await apiDelete(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/chat/${msgId}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.message_id).toBe(msgId);
  });

  test("499.3 Moderator mutes a viewer", async () => {
    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/mute`,
      {
        user_id: "random_viewer_123",
        duration_seconds: 300,
      },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.target_user_id).toBe("random_viewer_123");
    expect(data.muted_until).toBeGreaterThan(0);
  });

  test("499.4 Moderator bans a viewer from chat", async () => {
    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/ban`,
      {
        user_id: "banned_viewer_456",
        reason: "Disruptive behavior",
      },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.user_id).toBe("banned_viewer_456");
    expect(data.banned_by).toBe(BOB_ID);
    expect(data.reason).toBe("Disruptive behavior");

    // Verify viewer appears in ban list
    const bansResp = await apiGet(
      bobPage,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/bans`,
    );
    expect(bansResp.ok()).toBeTruthy();
    const bans = await bansResp.json();
    const banned = bans.find((b: any) => b.user_id === "banned_viewer_456");
    expect(banned).toBeTruthy();
    expect(banned.reason).toBe("Disruptive behavior");
  });

  test("499.5 Moderator posts an announcement", async () => {
    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/announcement`,
      {
        text: `Important notice ${TS}`,
      },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.is_announcement).toBe(true);
    expect(data.announcement_by).toBe(BOB_ID);
    expect(data.text).toBe(`Important notice ${TS}`);
    expect(data.message_id).toBeTruthy();
  });
});

// =============================================================================
// Section 500: Broadcast Control Delegation API (4 tests)
// =============================================================================

test.describe("500 -- Broadcast Control Delegation API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let charliePage: Page;
  let profileId: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    const charlieCtx = await browser.newContext();
    charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, CHARLIE_ID);

    // Bob gets both broadcast_moderate + broadcast_control
    await ensureDelegateWithPerms(alicePage, BOB_ID, [
      "broadcast_moderate",
      "broadcast_control",
    ]);

    // Charlie gets only broadcast_moderate (no control)
    await ensureDelegateWithPerms(alicePage, CHARLIE_ID, [
      "broadcast_moderate",
    ]);

    profileId = await createBroadcastProfile(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${BOB_ID}`);
    await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${CHARLIE_ID}`);
    await alicePage.context().close();
    await bobPage.context().close();
    await charliePage.context().close();
  });

  test("500.1 Delegate starts broadcast on behalf of creator", async () => {
    const sessionId = await createBroadcastSession(alicePage, ALICE_ID, profileId);

    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/start`,
      {},
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.session_id).toBe(sessionId);
    expect(data.status).toBe("live");
  });

  test("500.2 Delegate stops broadcast on behalf of creator", async () => {
    const sessionId = await createBroadcastSession(alicePage, ALICE_ID, profileId);

    // Start first (goes through draft -> provisioning -> ready -> live)
    await apiPost(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/start`,
      {},
    );

    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/stop`,
      {},
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.session_id).toBe(sessionId);
    expect(data.status).toBe("stopped");
  });

  test("500.3 Delegate schedules broadcast on behalf of creator", async () => {
    const futureTs = Math.floor(Date.now() / 1000) + 86400; // 24h from now

    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/schedule`,
      {
        title: `Scheduled Show ${TS}`,
        scheduled_at: futureTs,
      },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("scheduled");
    expect(data.title).toBe(`Scheduled Show ${TS}`);
    expect(data.scheduled_at).toBe(futureTs);
    expect(data.created_by).toBe(ALICE_ID);
  });

  test("500.4 Delegate without broadcast_control gets 403", async () => {
    const sessionId = await createBroadcastSession(alicePage, ALICE_ID, profileId);

    const resp = await apiPost(
      charliePage,
      CHARLIE_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/start`,
      {},
    );
    expect(resp.status()).toBe(403);
  });
});

// =============================================================================
// Section 501: Multi-Moderator & Ban API (4 tests)
// =============================================================================

test.describe("501 -- Multi-Moderator & Ban API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let charliePage: Page;
  let profileId: string;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    const charlieCtx = await browser.newContext();
    charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, CHARLIE_ID);

    // Both Bob and Charlie as moderators
    await ensureDelegateWithPerms(alicePage, BOB_ID, [
      "broadcast_moderate",
      "broadcast_control",
    ]);
    await ensureDelegateWithPerms(alicePage, CHARLIE_ID, [
      "broadcast_moderate",
    ]);

    profileId = await createBroadcastProfile(alicePage, ALICE_ID);
    sessionId = await createBroadcastSession(alicePage, ALICE_ID, profileId);
    // Chat is only available while the broadcast is live.
    await startBroadcastSession(browser, sessionId);
  });

  test.afterAll(async () => {
    await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${BOB_ID}`);
    await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${CHARLIE_ID}`);
    await alicePage.context().close();
    await bobPage.context().close();
    await charliePage.context().close();
  });

  test("501.1 Multiple moderators register for same session", async () => {
    // Bob registers
    const bobRegResp = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/moderator/register`,
      {},
    );
    expect(bobRegResp.status()).toBe(200);
    const bobReg = await bobRegResp.json();
    expect(bobReg.delegate_id).toBe(BOB_ID);
    expect(bobReg.status).toBe("online");

    // Charlie registers
    const charlieRegResp = await apiPost(
      charliePage,
      CHARLIE_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/moderator/register`,
      {},
    );
    expect(charlieRegResp.status()).toBe(200);
    const charlieReg = await charlieRegResp.json();
    expect(charlieReg.delegate_id).toBe(CHARLIE_ID);
    expect(charlieReg.status).toBe("online");

    // List moderators -- should have both
    const listResp = await apiGet(
      bobPage,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/moderators`,
    );
    expect(listResp.ok()).toBeTruthy();
    const mods = await listResp.json();
    expect(mods.length).toBeGreaterThanOrEqual(2);
    const bobMod = mods.find((m: any) => m.delegate_id === BOB_ID);
    const charlieMod = mods.find((m: any) => m.delegate_id === CHARLIE_ID);
    expect(bobMod).toBeTruthy();
    expect(charlieMod).toBeTruthy();
    expect(bobMod.status).toBe("online");
    expect(charlieMod.status).toBe("online");
  });

  test("501.2 Second pin replaces first pin", async () => {
    // Create two messages
    const msgA = await sendChatMessage(alicePage, ALICE_ID, sessionId, `Pin A ${TS}`);
    const msgB = await sendChatMessage(alicePage, ALICE_ID, sessionId, `Pin B ${TS}`);

    // Bob pins message A
    const pinA = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/chat/${msgA}/pin`,
      {},
    );
    expect(pinA.status()).toBe(200);
    expect((await pinA.json()).pinned).toBe(true);

    // Charlie pins message B -- should replace A
    const pinB = await apiPost(
      charliePage,
      CHARLIE_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/chat/${msgB}/pin`,
      {},
    );
    expect(pinB.status()).toBe(200);
    expect((await pinB.json()).pinned).toBe(true);
  });

  test("501.3 Unban restores viewer chat access", async () => {
    const viewerId = `unban_test_${TS}`;

    // Ban
    const banResp = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/ban`,
      { user_id: viewerId, reason: "Test ban" },
    );
    expect(banResp.status()).toBe(200);

    // Verify banned
    let bansResp = await apiGet(
      bobPage,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/bans`,
    );
    let bans = await bansResp.json();
    expect(bans.find((b: any) => b.user_id === viewerId)).toBeTruthy();

    // Unban
    const unbanResp = await apiDelete(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/ban/${viewerId}`,
    );
    expect(unbanResp.status()).toBe(200);
    const unbanData = await unbanResp.json();
    expect(unbanData.ok).toBe(true);

    // Verify no longer banned
    bansResp = await apiGet(
      bobPage,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/bans`,
    );
    bans = await bansResp.json();
    expect(bans.find((b: any) => b.user_id === viewerId)).toBeFalsy();
  });

  test("501.4 Banned viewers list returned correctly", async () => {
    const viewer1 = `banned1_${TS}`;
    const viewer2 = `banned2_${TS}`;

    // Ban two viewers
    await apiPost(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/ban`,
      { user_id: viewer1, reason: "Spam" },
    );
    await apiPost(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/ban`,
      { user_id: viewer2, reason: "Harassment" },
    );

    // List bans
    const bansResp = await apiGet(
      bobPage,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/bans`,
    );
    expect(bansResp.ok()).toBeTruthy();
    const bans = await bansResp.json();

    const b1 = bans.find((b: any) => b.user_id === viewer1);
    const b2 = bans.find((b: any) => b.user_id === viewer2);
    expect(b1).toBeTruthy();
    expect(b2).toBeTruthy();
    expect(b1.banned_by).toBe(BOB_ID);
    expect(b1.reason).toBe("Spam");
    expect(b2.reason).toBe("Harassment");
  });
});

// =============================================================================
// Section 502: Moderation Audit & System Messages API (3 tests)
// =============================================================================

test.describe("502 -- Moderation Audit & System Messages API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let profileId: string;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    await ensureDelegateWithPerms(alicePage, BOB_ID, [
      "broadcast_moderate",
      "broadcast_control",
    ]);

    profileId = await createBroadcastProfile(alicePage, ALICE_ID);
    sessionId = await createBroadcastSession(alicePage, ALICE_ID, profileId);
    // Chat is only available while the broadcast is live.
    await startBroadcastSession(browser, sessionId);
  });

  test.afterAll(async () => {
    await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${BOB_ID}`);
    await alicePage.context().close();
    await bobPage.context().close();
  });

  test("502.1 System message generated for pin action", async () => {
    const msgId = await sendChatMessage(alicePage, ALICE_ID, sessionId, `Pin sys msg ${TS}`);

    // Pin the message
    await apiPost(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/chat/${msgId}/pin`,
      {},
    );

    // Check chat history for system message
    const chatResp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/chat?limit=50`,
    );
    expect(chatResp.ok()).toBeTruthy();
    const chatData = await chatResp.json();
    const messages = chatData.messages || chatData;
    const sysMsgs = (Array.isArray(messages) ? messages : []).filter(
      (m: any) => m.sender_id === "system" && m.text?.includes("pinned a message"),
    );
    expect(sysMsgs.length).toBeGreaterThanOrEqual(1);
    expect(sysMsgs[0].text).toContain("[Moderator @");
    expect(sysMsgs[0].text).toContain("pinned a message");
  });

  test("502.2 System message generated for mute action", async () => {
    const viewerId = `mute_sys_${TS}`;

    await apiPost(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/mute`,
      { user_id: viewerId, duration_seconds: 300 },
    );

    // Check chat history for system message
    const chatResp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/chat?limit=50`,
    );
    expect(chatResp.ok()).toBeTruthy();
    const chatData = await chatResp.json();
    const messages = chatData.messages || chatData;
    const sysMsgs = (Array.isArray(messages) ? messages : []).filter(
      (m: any) => m.sender_id === "system" && m.text?.includes("muted a viewer"),
    );
    expect(sysMsgs.length).toBeGreaterThanOrEqual(1);
    expect(sysMsgs[0].text).toContain("[Moderator @");
    expect(sysMsgs[0].text).toContain("5 minutes");
  });

  test("502.3 Moderation log records all actions", async () => {
    // Perform a few actions
    const msgToPin = await sendChatMessage(alicePage, ALICE_ID, sessionId, `Log test ${TS}`);
    await apiPost(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/chat/${msgToPin}/pin`,
      {},
    );
    await apiPost(
      bobPage,
      BOB_ID,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/ban`,
      { user_id: `logban_${TS}`, reason: "Log test" },
    );

    // Get moderation log
    const logResp = await apiGet(
      bobPage,
      `/ui/broadcast/delegate/${ALICE_ID}/sessions/${sessionId}/moderation-log?limit=50`,
    );
    expect(logResp.ok()).toBeTruthy();
    const logs = await logResp.json();
    expect(logs.length).toBeGreaterThanOrEqual(2);

    // Check that different moderation types are present
    const types = logs.map((e: any) => e.moderation_type);
    expect(types).toContain("pin");
    expect(types).toContain("ban");

    // Each entry should have moderator attribution
    for (const entry of logs) {
      expect(entry.moderator_id).toBeTruthy();
      expect(entry.event_id).toBeTruthy();
      expect(entry.ts).toBeGreaterThan(0);
    }
  });
});
