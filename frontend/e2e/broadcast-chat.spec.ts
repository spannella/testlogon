import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

/* ------------------------------------------------------------------ */
/*  Constants & helpers                                                */
/* ------------------------------------------------------------------ */

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

async function apiDelete(page: Page, identity: string, path: string) {
  const s = getSessions()[identity];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": s.csrf_token },
  });
}

/* ------------------------------------------------------------------ */
/*  Shared state: create a live broadcast session for chat tests       */
/* ------------------------------------------------------------------ */

let liveSessionId: string;
let profileId: string;

/* ------------------------------------------------------------------ */
/*  Section 96 — Chat send + history API                              */
/* ------------------------------------------------------------------ */

test.describe("Section 96 — Broadcast Chat send + history API", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, "root");

    // Create a profile
    const profResp = await apiPost(page, "root", "/broadcast/profiles", {
      name: `Chat Test Profile ${TS}`,
      region: "us-east-1",
      rendition_preset: "720p30",
    });
    expect(profResp.status()).toBe(201);
    const profBody = await profResp.json();
    profileId = profBody.id;

    // Create a session
    const sessResp = await apiPost(page, "root", "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(sessResp.status()).toBe(201);
    const sessBody = await sessResp.json();
    liveSessionId = sessBody.id;

    // Start the session (transitions to live)
    const startResp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/start`,
      { reason: "e2e-chat-test" },
    );
    expect(startResp.status()).toBe(202);
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("96.1 Send a chat message to a live session", async () => {
    const resp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat`,
      { text: `Hello Chat ${TS}` },
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.message_id).toMatch(/^cm_/);
    expect(body.text).toBe(`Hello Chat ${TS}`);
    expect(body.sender_id).toBe(getSessions().root.user_sub);
    expect(body.deleted).toBe(false);
    expect(body.created_at).toBeGreaterThan(0);
  });

  test("96.2 Reject empty text", async () => {
    const resp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat`,
      { text: "" },
    );
    expect(resp.status()).toBe(422);
  });

  test("96.3 Reject text over 280 chars", async () => {
    const longText = "x".repeat(281);
    const resp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat`,
      { text: longText },
    );
    expect(resp.status()).toBe(422);
  });

  test("96.4 Rate limit — 429 on rapid second send", async () => {
    // Wait for any previous rate limit to clear
    await new Promise((r) => setTimeout(r, 2200));

    // First send succeeds
    const r1 = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat`,
      { text: `Rate test A ${TS}` },
    );
    expect(r1.status()).toBe(201);

    // Immediate second send should be rate limited
    const r2 = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${liveSessionId}/chat`,
      { text: `Rate test B ${TS}` },
    );
    expect(r2.status()).toBe(429);
    const body = await r2.json();
    expect(body.detail.code).toBe("BROADCAST_CHAT_RATE_LIMITED");
  });

  test("96.5 Get chat history returns messages chronologically", async () => {
    // Wait for rate limit to clear
    await new Promise((r) => setTimeout(r, 2100));

    // Send a couple messages with delay
    await apiPost(page, "root", `/broadcast/sessions/${liveSessionId}/chat`, {
      text: `History A ${TS}`,
    });
    await new Promise((r) => setTimeout(r, 2100));
    await apiPost(page, "root", `/broadcast/sessions/${liveSessionId}/chat`, {
      text: `History B ${TS}`,
    });

    const resp = await apiGet(
      page,
      `/broadcast/sessions/${liveSessionId}/chat?limit=100`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.messages.length).toBeGreaterThanOrEqual(2);

    // Verify chronological order (created_at ascending)
    const timestamps = body.messages.map((m: { created_at: number }) => m.created_at);
    for (let i = 1; i < timestamps.length; i++) {
      expect(timestamps[i]).toBeGreaterThanOrEqual(timestamps[i - 1]);
    }
  });
});

/* ------------------------------------------------------------------ */
/*  Section 97 — Chat moderation (delete + mute)                      */
/* ------------------------------------------------------------------ */

test.describe("Section 97 — Broadcast Chat moderation API", () => {
  let broadcasterPage: Page;
  let viewerPage: Page;
  let viewerSessionId: string;

  test.beforeAll(async ({ browser }) => {
    const ctx1 = await browser.newContext();
    broadcasterPage = await ctx1.newPage();
    await injectAuth(broadcasterPage, "root");

    const ctx2 = await browser.newContext();
    viewerPage = await ctx2.newPage();
    await injectAuth(viewerPage, "alice");

    // Create a fresh session for moderation tests
    const profResp = await apiPost(broadcasterPage, "root", "/broadcast/profiles", {
      name: `Mod Test Profile ${TS}`,
      region: "us-east-1",
      rendition_preset: "720p30",
    });
    const profBody = await profResp.json();

    const sessResp = await apiPost(broadcasterPage, "root", "/broadcast/sessions", {
      profile_id: profBody.id,
    });
    const sessBody = await sessResp.json();
    viewerSessionId = sessBody.id;

    // Start it
    await apiPost(
      broadcasterPage,
      "root",
      `/broadcast/sessions/${viewerSessionId}/start`,
      { reason: "e2e-mod-test" },
    );
  });

  test.afterAll(async () => {
    await broadcasterPage.context().close();
    await viewerPage.context().close();
  });

  test("97.1 Viewer sends a message", async () => {
    const resp = await apiPost(
      viewerPage,
      "alice",
      `/broadcast/sessions/${viewerSessionId}/chat`,
      { text: `Viewer msg ${TS}` },
    );
    expect(resp.status()).toBe(201);
  });

  test("97.2 Broadcaster can delete any message", async () => {
    // Wait for rate limit
    await new Promise((r) => setTimeout(r, 2100));

    // Viewer sends another message
    const sendResp = await apiPost(
      viewerPage,
      "alice",
      `/broadcast/sessions/${viewerSessionId}/chat`,
      { text: `Delete me ${TS}` },
    );
    const msg = await sendResp.json();

    // Broadcaster deletes it
    const delResp = await apiDelete(
      broadcasterPage,
      "root",
      `/broadcast/sessions/${viewerSessionId}/chat/${msg.message_id}`,
    );
    expect(delResp.status()).toBe(200);
    const delBody = await delResp.json();
    expect(delBody.ok).toBe(true);
  });

  test("97.3 Regular viewer cannot delete messages", async () => {
    // Wait for rate limit
    await new Promise((r) => setTimeout(r, 2100));

    // Viewer sends a message
    const sendResp = await apiPost(
      viewerPage,
      "alice",
      `/broadcast/sessions/${viewerSessionId}/chat`,
      { text: `No delete ${TS}` },
    );
    const msg = await sendResp.json();

    // Viewer tries to delete it — should fail (not broadcaster/admin)
    const delResp = await apiDelete(
      viewerPage,
      "alice",
      `/broadcast/sessions/${viewerSessionId}/chat/${msg.message_id}`,
    );
    expect(delResp.status()).toBe(403);
  });

  test("97.4 Broadcaster can mute a viewer", async () => {
    const resp = await apiPost(
      broadcasterPage,
      "root",
      `/broadcast/sessions/${viewerSessionId}/chat/mute`,
      { target_user_id: getSessions().alice.user_sub, duration_seconds: 60 },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.target_user_id).toBe(getSessions().alice.user_sub);
    expect(body.muted_until).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  test("97.5 Muted viewer receives 403 BROADCAST_CHAT_MUTED", async () => {
    // Wait for rate limit
    await new Promise((r) => setTimeout(r, 2100));

    const resp = await apiPost(
      viewerPage,
      "alice",
      `/broadcast/sessions/${viewerSessionId}/chat`,
      { text: `I am muted ${TS}` },
    );
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.detail.code).toBe("BROADCAST_CHAT_MUTED");
  });
});

/* ------------------------------------------------------------------ */
/*  Section 98 — Chat SSE stream                                      */
/* ------------------------------------------------------------------ */

test.describe("Section 98 — Broadcast Chat SSE stream", () => {
  let page: Page;
  let sseSessionId: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, "root");

    // Create a live session for SSE tests
    const profResp = await apiPost(page, "root", "/broadcast/profiles", {
      name: `SSE Test Profile ${TS}`,
      region: "us-east-1",
      rendition_preset: "720p30",
    });
    const profBody = await profResp.json();

    const sessResp = await apiPost(page, "root", "/broadcast/sessions", {
      profile_id: profBody.id,
    });
    const sessBody = await sessResp.json();
    sseSessionId = sessBody.id;

    await apiPost(
      page,
      "root",
      `/broadcast/sessions/${sseSessionId}/start`,
      { reason: "e2e-sse-test" },
    );
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("98.1 SSE stream returns 403 for non-live session", async () => {
    // Create a draft session
    const profResp = await apiPost(page, "root", "/broadcast/profiles", {
      name: `SSE Draft ${TS}`,
      region: "us-east-1",
      rendition_preset: "720p30",
    });
    const profBody = await profResp.json();
    const sessResp = await apiPost(page, "root", "/broadcast/sessions", {
      profile_id: profBody.id,
    });
    const draftSession = await sessResp.json();

    const resp = await page.request.get(
      `${API}/broadcast/sessions/${draftSession.id}/chat/stream`,
    );
    expect(resp.status()).toBe(403);
  });

  test("98.2 Chat history API works for live session", async () => {
    const resp = await apiGet(
      page,
      `/broadcast/sessions/${sseSessionId}/chat?limit=10`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.messages)).toBe(true);
  });

  test("98.3 Send + retrieve confirms persistence", async () => {
    const uniqueText = `SSE verify ${TS} ${Math.random()}`;
    const sendResp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${sseSessionId}/chat`,
      { text: uniqueText },
    );
    expect(sendResp.status()).toBe(201);

    // Retrieve history and confirm message appears
    const histResp = await apiGet(
      page,
      `/broadcast/sessions/${sseSessionId}/chat?limit=50`,
    );
    const body = await histResp.json();
    const found = body.messages.find((m: { text: string }) => m.text === uniqueText);
    expect(found).toBeTruthy();
  });

  test("98.4 Deleted messages excluded from history", async () => {
    // Wait for rate limit
    await new Promise((r) => setTimeout(r, 2100));

    const uniqueText = `To delete SSE ${TS} ${Math.random()}`;
    const sendResp = await apiPost(
      page,
      "root",
      `/broadcast/sessions/${sseSessionId}/chat`,
      { text: uniqueText },
    );
    const msg = await sendResp.json();

    // Delete it
    await apiDelete(
      page,
      "root",
      `/broadcast/sessions/${sseSessionId}/chat/${msg.message_id}`,
    );

    // Verify excluded from history
    const histResp = await apiGet(
      page,
      `/broadcast/sessions/${sseSessionId}/chat?limit=100`,
    );
    const body = await histResp.json();
    const found = body.messages.find(
      (m: { message_id: string }) => m.message_id === msg.message_id,
    );
    expect(found).toBeFalsy();
  });
});

/* ------------------------------------------------------------------ */
/*  Section 99 — Chat UI in LivePlayer                                */
/* ------------------------------------------------------------------ */

test.describe("Section 99 — Broadcast Chat UI", () => {
  let page: Page;
  let uiSessionId: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, "root");

    // Create a live session for UI tests
    const profResp = await apiPost(page, "root", "/broadcast/profiles", {
      name: `UI Test Profile ${TS}`,
      region: "us-east-1",
      rendition_preset: "720p30",
    });
    const profBody = await profResp.json();

    const sessResp = await apiPost(page, "root", "/broadcast/sessions", {
      profile_id: profBody.id,
    });
    const sessBody = await sessResp.json();
    uiSessionId = sessBody.id;

    await apiPost(
      page,
      "root",
      `/broadcast/sessions/${uiSessionId}/start`,
      { reason: "e2e-ui-test" },
    );
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("99.1 Chat panel visible on live player page", async () => {
    // Set auth store in localStorage so LivePlayer sees isAuthenticated=true
    const s = getSessions().root;
    await page.goto("/login");
    await page.evaluate((userId) => {
      localStorage.setItem("auth-store", JSON.stringify({
        state: { userId, accessToken: "e2e", isAuthenticated: true, logoutReason: null },
        version: 0,
      }));
    }, s.user_sub);
    await page.goto(`/live/${uiSessionId}`);
    // Wait for the page to load and session to be recognized as live
    await expect(page.locator('[data-testid="chat-panel"]')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('[data-testid="chat-input"]')).toBeVisible();
    await expect(page.locator('[data-testid="chat-send-btn"]')).toBeVisible();
  });

  test("99.2 Chat toggle hides and shows chat", async () => {
    const s = getSessions().root;
    await page.goto("/login");
    await page.evaluate((userId) => {
      localStorage.setItem("auth-store", JSON.stringify({
        state: { userId, accessToken: "e2e", isAuthenticated: true, logoutReason: null },
        version: 0,
      }));
    }, s.user_sub);
    await page.goto(`/live/${uiSessionId}`);
    await expect(page.locator('[data-testid="chat-panel"]')).toBeVisible({ timeout: 15000 });

    // Click hide
    await page.locator('[data-testid="chat-toggle"]').click();
    await expect(page.locator('[data-testid="chat-panel"]')).not.toBeVisible();

    // Click show
    await page.locator('[data-testid="chat-toggle"]').click();
    await expect(page.locator('[data-testid="chat-panel"]')).toBeVisible();
  });

  test("99.3 Send button disabled when input empty", async () => {
    const s = getSessions().root;
    await page.goto("/login");
    await page.evaluate((userId) => {
      localStorage.setItem("auth-store", JSON.stringify({
        state: { userId, accessToken: "e2e", isAuthenticated: true, logoutReason: null },
        version: 0,
      }));
    }, s.user_sub);
    await page.goto(`/live/${uiSessionId}`);
    await expect(page.locator('[data-testid="chat-send-btn"]')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('[data-testid="chat-send-btn"]')).toBeDisabled();
  });

  test("99.4 Overlay toggle button works", async () => {
    const s = getSessions().root;
    await page.goto("/login");
    await page.evaluate((userId) => {
      localStorage.setItem("auth-store", JSON.stringify({
        state: { userId, accessToken: "e2e", isAuthenticated: true, logoutReason: null },
        version: 0,
      }));
    }, s.user_sub);
    await page.goto(`/live/${uiSessionId}`);
    await expect(page.locator('[data-testid="overlay-toggle"]')).toBeVisible({ timeout: 15000 });

    // Initially should say "Overlay Off"
    await expect(page.locator('[data-testid="overlay-toggle"]')).toContainText("Overlay Off");

    // Click to enable
    await page.locator('[data-testid="overlay-toggle"]').click();
    await expect(page.locator('[data-testid="overlay-toggle"]')).toContainText("Overlay On");

    // Click to disable
    await page.locator('[data-testid="overlay-toggle"]').click();
    await expect(page.locator('[data-testid="overlay-toggle"]')).toContainText("Overlay Off");
  });
});
