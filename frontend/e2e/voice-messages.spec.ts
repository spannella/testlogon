/**
 * E2E tests for MSG-002: Voice Messages
 *
 * Routes tested:
 *   POST /ui/messaging/conversations/{id}/voice-message/presign
 *   POST /ui/messaging/conversations/{id}/voice-message
 *   GET  /ui/messaging/conversations/{id}/messages
 *
 * Since Playwright cannot access the microphone or MediaRecorder API,
 * all tests use the API directly to upload a synthetic audio blob and
 * create voice messages, then verify UI rendering.
 *
 * Test users:
 *   Alice (e2e_alice@test.local) - primary actor
 *   Bob   (e2e_bob@test.local)   - DM partner
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ───────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API  = "http://localhost:8000";
const ALICE_ID   = "e2e_alice@test.local";
const BOB_ID     = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";

// ─── Session bootstrap ──────────────────────────────────────────────────────

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
      "python3 " + REPO_ROOT + "/e2e_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ────────────────────────────────────────────────────────────

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function apiPost(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiDelete(page: Page, path: string) {
  const session = getSessions()[ALICE_ID];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

type APIRequestContext = import("@playwright/test").APIRequestContext;
async function apiPostBearer(
  req: APIRequestContext,
  path: string,
  body: object,
  userId: string,
) {
  return req.post(`${API}${path}`, {
    data: body,
    headers: { Authorization: `Bearer ${userId}` },
  });
}

async function apiGetBearer(
  req: APIRequestContext,
  path: string,
  userId: string,
) {
  return req.get(`${API}${path}`, {
    headers: { Authorization: `Bearer ${userId}` },
  });
}

// ─── DM setup ────────────────────────────────────────────────────────────────

let _dmConvoId: string | null = null;

async function getOrCreateDm(page: Page): Promise<string> {
  if (_dmConvoId) return _dmConvoId;
  const bobSub = getSessions()[BOB_ID].user_sub;
  const resp = await apiPost(page, "/messaging/conversations", {
    participant_ids: [bobSub],
    type: "dm",
  });
  if (!resp.ok()) {
    const body = await resp.text().catch(() => "(unreadable)");
    throw new Error(`DM creation failed: HTTP ${resp.status()} - ${body}`);
  }
  const body = await resp.json();
  _dmConvoId = body.conversation_id as string;
  return _dmConvoId;
}

// ─── Helper: generate synthetic waveform data ─────────────────────────────────

function syntheticWaveform(count = 30): number[] {
  const wf: number[] = [];
  for (let i = 0; i < count; i++) {
    wf.push(+(Math.sin(i * 0.3) * 0.5 + 0.5).toFixed(3));
  }
  return wf;
}

// ─── Helper: create a voice message via API ───────────────────────────────────

async function createVoiceMessageViaApi(
  page: Page,
  convoId: string,
  opts?: {
    consumption_policy?: "none" | "listen_once";
    reply_to_message_id?: string | null;
    send_at?: number | null;
    duration_seconds?: number;
  },
) {
  // 1. Presign
  const presignResp = await apiPost(
    page,
    `/messaging/conversations/${convoId}/voice-message/presign`,
    {
      content_type: "audio/webm",
      size_bytes: 5000,
      duration_seconds: opts?.duration_seconds ?? 5.0,
    },
  );
  expect(presignResp.ok()).toBe(true);
  const presign = await presignResp.json();
  expect(presign.message_id).toBeTruthy();
  expect(presign.upload_url).toBeTruthy();
  expect(presign.s3_key).toBeTruthy();

  // 2. Upload a tiny synthetic blob
  const blob = Buffer.alloc(5000, 0x42); // fake audio data
  const uploadResp = await page.request.put(
    presign.upload_url.startsWith("/") ? `${BASE}${presign.upload_url}` : presign.upload_url,
    {
      data: blob,
      headers: { "Content-Type": "audio/webm" },
    },
  );
  expect(uploadResp.ok()).toBe(true);

  // 3. Create message
  const createResp = await apiPost(
    page,
    `/messaging/conversations/${convoId}/voice-message`,
    {
      message_id: presign.message_id,
      s3_key: presign.s3_key,
      content_type: "audio/webm",
      size_bytes: 5000,
      duration_seconds: opts?.duration_seconds ?? 5.0,
      waveform_data: syntheticWaveform(30),
      consumption_policy: opts?.consumption_policy ?? "none",
      reply_to_message_id: opts?.reply_to_message_id ?? null,
      send_at: opts?.send_at ?? null,
    },
  );
  expect(createResp.ok()).toBe(true);
  const msg = await createResp.json();
  return msg;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 1: Voice Message API (6 tests)
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("1 - Voice Message API", () => {
  let page: Page;
  let convoId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await getOrCreateDm(page);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("1.1 Presign voice message upload", async () => {
    const resp = await apiPost(
      page,
      `/messaging/conversations/${convoId}/voice-message/presign`,
      { content_type: "audio/webm", size_bytes: 10000, duration_seconds: 3.5 },
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.upload_url).toBeTruthy();
    expect(body.s3_key).toContain("voice-messages/");
    expect(body.message_id).toMatch(/^m_[a-f0-9]{32}$/);
  });

  test("1.2 Create voice message with waveform", async () => {
    const msg = await createVoiceMessageViaApi(page, convoId);
    expect(msg.kind).toBe("voice_message");
    expect(msg.voice_message).toBeTruthy();
    expect(msg.voice_message.duration_seconds).toBeCloseTo(5.0, 0);
    expect(msg.voice_message.waveform_data).toHaveLength(30);
    expect(msg.voice_message.audio_url).toContain("voice-messages/");
    expect(msg.voice_message.audio_content_type).toBe("audio/webm");
  });

  test("1.3 Reject duration over 300 seconds at presign", async () => {
    const resp = await apiPost(
      page,
      `/messaging/conversations/${convoId}/voice-message/presign`,
      { content_type: "audio/webm", size_bytes: 10000, duration_seconds: 600 },
    );
    expect(resp.status()).toBe(422);
  });

  test("1.4 Reject empty waveform data", async () => {
    // Presign first to get valid IDs
    const presignResp = await apiPost(
      page,
      `/messaging/conversations/${convoId}/voice-message/presign`,
      { content_type: "audio/webm", size_bytes: 5000, duration_seconds: 3.0 },
    );
    const presign = await presignResp.json();

    const resp = await apiPost(
      page,
      `/messaging/conversations/${convoId}/voice-message`,
      {
        message_id: presign.message_id,
        s3_key: presign.s3_key,
        content_type: "audio/webm",
        size_bytes: 5000,
        duration_seconds: 3.0,
        waveform_data: [],  // empty - should fail
        consumption_policy: "none",
      },
    );
    expect(resp.status()).toBe(422);
  });

  test("1.5 Voice message appears in conversation messages", async () => {
    // Send a voice message
    const msg = await createVoiceMessageViaApi(page, convoId);

    // Fetch messages
    const getResp = await apiGet(
      page,
      `/messaging/conversations/${convoId}/messages`,
    );
    expect(getResp.ok()).toBe(true);
    const messages = await getResp.json();
    const found = (messages as Array<Record<string, unknown>>).find(
      (m) => m.message_id === msg.message_id,
    );
    expect(found).toBeTruthy();
    expect(found!.kind).toBe("voice_message");
    expect((found as Record<string, unknown>).voice_message).toBeTruthy();
  });

  test("1.6 Voice message with listen-once policy", async () => {
    const msg = await createVoiceMessageViaApi(page, convoId, {
      consumption_policy: "listen_once",
    });
    expect(msg.consumption_policy).toBe("listen_once");
    expect(msg.media_kind).toBe("audio");
    expect(msg.consumption_state).toBe("pending");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 2: Voice Message in Chat (4 tests)
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("2 - Voice Message in Chat", () => {
  let page: Page;
  let convoId: string;
  let voiceMsg: Record<string, unknown>;
  const UNIQUE_MARKER = `vm_ui_${Date.now()}`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    // Create a fresh DM for this section (always new) to avoid clutter from other runs
    const bobSub = getSessions()[BOB_ID].user_sub;
    const dmResp = await apiPost(page, "/messaging/conversations", {
      participant_ids: [bobSub],
      type: "dm",
    });
    expect(dmResp.ok()).toBe(true);
    convoId = ((await dmResp.json()) as Record<string, string>).conversation_id;

    // Send a unique text marker so we can identify this DM in the sidebar
    await apiPost(page, `/messaging/conversations/${convoId}/messages`, {
      text: UNIQUE_MARKER,
    });

    // Create a voice message via API
    voiceMsg = await createVoiceMessageViaApi(page, convoId, {
      duration_seconds: 12.5,
    });
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("2.1 Voice message renders waveform in message bubble", async () => {
    test.setTimeout(45_000);

    // Re-inject auth (in case retry spawned new worker)
    await injectAuth(page, ALICE_ID);

    // Navigate to messages
    await page.goto(`${BASE}/messages`, { waitUntil: "load", timeout: 15000 });
    await page.waitForTimeout(1500);

    // The first "E2E Bob" entry is our freshly created DM (most recent by last_message_at).
    // Click the first E2E Bob conversation row
    const row = page.getByRole("button").filter({ hasText: "E2E Bob" }).first();
    await expect(row).toBeVisible({ timeout: 15000 });
    await row.click();

    // Wait for compose bar to confirm conversation loaded
    await expect(
      page.getByPlaceholder("Type a message...").or(
        page.getByPlaceholder("Type an encrypted message..."),
      ),
    ).toBeVisible({ timeout: 15000 });

    // Trigger refetch to load latest messages (including the voice message from beforeAll)
    await page.evaluate(() => window.dispatchEvent(new Event("online")));
    await page.waitForTimeout(2000);

    // Find the voice message bubble
    const voiceBubble = page.locator('[data-testid="voice-message-bubble"]').first();
    await expect(voiceBubble).toBeVisible({ timeout: 15000 });

    // Verify waveform player is rendered
    const waveformPlayer = voiceBubble.locator('[data-testid="waveform-player"]');
    await expect(waveformPlayer).toBeVisible();
  });

  test("2.2 Play button is visible", async () => {
    const voiceBubble = page.locator('[data-testid="voice-message-bubble"]').first();
    const playBtn = voiceBubble.getByRole("button", { name: /play voice message/i });
    await expect(playBtn).toBeVisible();
  });

  test("2.3 Duration label shows correct time", async () => {
    const voiceBubble = page.locator('[data-testid="voice-message-bubble"]').first();
    const duration = voiceBubble.locator('[data-testid="voice-duration"]');
    await expect(duration).toBeVisible();
    // 12.5s should display as "0:12"
    await expect(duration).toHaveText("0:12");
  });

  test("2.4 Speed toggle is visible", async () => {
    const voiceBubble = page.locator('[data-testid="voice-message-bubble"]').first();
    const speedToggle = voiceBubble.locator('[data-testid="speed-toggle"]');
    await expect(speedToggle).toBeVisible();
    await expect(speedToggle).toHaveText("1x");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 3: Scheduled Voice Messages (3 tests)
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("3 - Scheduled Voice Messages", () => {
  let page: Page;
  let convoId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await getOrCreateDm(page);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("3.1 Create scheduled voice message", async () => {
    const futureTs = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
    const msg = await createVoiceMessageViaApi(page, convoId, {
      send_at: futureTs,
    });
    expect(msg.scheduled).toBe(true);
    expect(msg.deliver_at).toBe(futureTs);
    expect(msg.kind).toBe("voice_message");
  });

  test("3.2 Scheduled voice message in scheduled list", async () => {
    const futureTs = Math.floor(Date.now() / 1000) + 7200; // 2 hours from now
    const msg = await createVoiceMessageViaApi(page, convoId, {
      send_at: futureTs,
    });

    const resp = await apiGet(
      page,
      `/messaging/conversations/${convoId}/messages/scheduled`,
    );
    expect(resp.ok()).toBe(true);
    const scheduled = await resp.json();
    const found = (scheduled as Array<Record<string, unknown>>).find(
      (m) => m.message_id === msg.message_id,
    );
    expect(found).toBeTruthy();
    expect(found!.kind).toBe("voice_message");
  });

  test("3.3 Cancel scheduled voice message", async () => {
    const futureTs = Math.floor(Date.now() / 1000) + 10800; // 3 hours from now
    const msg = await createVoiceMessageViaApi(page, convoId, {
      send_at: futureTs,
    });

    const delResp = await apiDelete(
      page,
      `/messaging/conversations/${convoId}/messages/${msg.message_id}/schedule`,
    );
    expect(delResp.ok()).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 4: Voice Message in Groups (2 tests)
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("4 - Voice Message in Groups", () => {
  let page: Page;
  let groupConvoId: string;
  // Manually created APIRequestContext (no cookies) for Bearer auth in tests
  let bearerReq: APIRequestContext;

  test.beforeAll(async ({ browser, playwright }) => {
    // Create a standalone APIRequestContext that lives across beforeAll + tests
    bearerReq = await playwright.request.newContext();
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    // Create a group conversation (needs 3 unique participants: creator + 2 others)
    const bobSub = getSessions()[BOB_ID].user_sub;
    const charlieSub = getSessions()[CHARLIE_ID].user_sub;
    const resp = await apiPost(page, "/messaging/conversations", {
      participant_ids: [bobSub, charlieSub],
      type: "group",
      title: `VM Test Group ${Date.now()}`,
    });
    if (!resp.ok()) {
      const body = await resp.text().catch(() => "(unreadable)");
      throw new Error(`Group creation failed: HTTP ${resp.status()} - ${body}`);
    }
    const body = await resp.json();
    groupConvoId = body.conversation_id as string;

    // Accept Bob and Charlie into the group
    for (const uid of [BOB_ID, CHARLIE_ID]) {
      const acceptResp = await apiPostBearer(
        bearerReq,
        `/messaging/conversations/${groupConvoId}/accept`,
        {},
        uid,
      );
      if (!acceptResp.ok()) {
        const t = await acceptResp.text().catch(() => "?");
        throw new Error(`Accept failed for ${uid}: ${acceptResp.status()} ${t}`);
      }
    }
  });

  test.afterAll(async () => {
    await page.close();
    await bearerReq.dispose();
  });

  test("4.1 Send voice message in group conversation", async () => {
    const msg = await createVoiceMessageViaApi(page, groupConvoId);
    expect(msg.kind).toBe("voice_message");
    expect(msg.conversation_id).toBe(groupConvoId);

    // Verify Bob can see it (use manually created request context — no cookies)
    const resp = await apiGetBearer(
      bearerReq,
      `/messaging/conversations/${groupConvoId}/messages`,
      BOB_ID,
    );
    expect(resp.ok()).toBe(true);
    const messages = await resp.json();
    const found = (messages as Array<Record<string, unknown>>).find(
      (m) => m.message_id === msg.message_id,
    );
    expect(found).toBeTruthy();
    expect(found!.kind).toBe("voice_message");
  });

  test("4.2 Voice message reply", async () => {
    // Send a text message first
    const textResp = await apiPost(
      page,
      `/messaging/conversations/${groupConvoId}/messages`,
      { text: `Reply target for voice ${Date.now()}` },
    );
    const textMsg = await textResp.json();

    // Send voice message as reply
    const msg = await createVoiceMessageViaApi(page, groupConvoId, {
      reply_to_message_id: textMsg.message_id,
    });
    expect(msg.kind).toBe("voice_message");
    expect(msg.reply_to_message_id).toBe(textMsg.message_id);
  });
});
