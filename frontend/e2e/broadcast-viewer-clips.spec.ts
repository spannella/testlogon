/**
 * E2E tests for Viewer Clip Sharing -- public shareable clip surface (ENGAGE-005).
 *
 * The auth-gated clip creation/gallery/management API is covered by
 * clip-sharing.spec.ts (sections 98-101). This spec covers the genuinely-new
 * public (no-auth) shareable clip-view surface added by this ticket:
 *
 *   Section 712 -- Viewer Clip Sharing: public clip view + lifecycle
 *
 * Covers:
 *   - viewer creates a clip from a seeded LIVE broadcast -> returns clip_id
 *   - range validation (<5s, >60s, start>=end, non-live broadcast)
 *   - clip appears in gallery
 *   - public clip-view works WITHOUT auth + shows broadcaster attribution
 *   - clip status transitions (processing/ready)
 *   - auth required for creation (401)
 *   - public view/share counters (no auth)
 *
 * Auth: Root for broadcast management (admin/root role required).
 *       Bob for clip creation (regular user).
 * Sessions from e2e_admin_session_setup.py.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ROOT_ID = "root";
const BOB_ID = "bob";
const TS = Date.now();

// --- Session bootstrap ---

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
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_admin_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string, { navigate = false } = {}) {
  const s = getSessions()[identity];
  if (!s) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(s.cookies);
  if (navigate) {
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await page.evaluate((uid: string) => {
      const state = { userId: uid, accessToken: null, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    }, s.user_sub);
  }
}

function userSub(identity: string): string {
  return getSessions()[identity].user_sub;
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": getSessions()[identity].csrf_token },
  });
}

async function createBroadcastSession(rootPage: Page): Promise<string> {
  const profileResp = await apiPost(rootPage, ROOT_ID, "/broadcast/profiles", {
    name: `VClip Profile ${TS}_${Math.random().toString(36).slice(2, 6)}`,
    region: "us-east-1",
    rendition_preset: "720p",
  });
  const profile = await profileResp.json();
  const sessionResp = await apiPost(rootPage, ROOT_ID, "/broadcast/sessions", {
    profile_id: profile.id,
  });
  expect(sessionResp.status()).toBe(201);
  const session = await sessionResp.json();
  return session.id;
}

async function startBroadcast(rootPage: Page, sessionId: string): Promise<void> {
  const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/start`, {
    reason: "e2e-viewer-clips",
  });
  expect(resp.status()).toBe(202);
}

async function withRootPage<T>(browser: any, fn: (p: Page) => Promise<T>): Promise<T> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await injectAuth(page, ROOT_ID);
  try {
    return await fn(page);
  } finally {
    await ctx.close();
  }
}

async function withUserPage<T>(
  browser: any,
  identity: string,
  fn: (p: Page) => Promise<T>,
  { ui }: { ui?: boolean } = {},
): Promise<T> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await injectAuth(page, identity, { navigate: !!ui });
  try {
    return await fn(page);
  } finally {
    await ctx.close();
  }
}

// ============================================================================
// Section 712: Viewer Clip Sharing -- public clip view + lifecycle
// ============================================================================

test.describe("712 — Viewer Clip Sharing (public clip view)", () => {
  let liveSessionId = "";
  let readyClipId = "";

  test.beforeAll(async ({ browser }) => {
    liveSessionId = await withRootPage(browser, async (rootPage) => {
      const id = await createBroadcastSession(rootPage);
      await startBroadcast(rootPage, id);
      return id;
    });
  });

  test("712.1 Viewer creates a clip from a live broadcast -> returns clip id", async ({ browser }) => {
    await withUserPage(browser, BOB_ID, async (page) => {
      const resp = await apiPost(page, BOB_ID, `/broadcast/sessions/${liveSessionId}/clips`, {
        start_seconds: 5,
        end_seconds: 35,
        title: `Viewer Clip ${TS}`,
      });
      expect(resp.status()).toBe(200);
      const clip = await resp.json();
      expect(clip.clip_id).toMatch(/^bclip_/);
      expect(clip.session_id).toBe(liveSessionId);
      expect(clip.creator_user_id).toBe(userSub(BOB_ID));
      expect(clip.broadcaster_user_id).toBeTruthy();
      readyClipId = clip.clip_id;
    });
  });

  test("712.2 Clip status transitions to ready (dev mode)", async ({ browser }) => {
    expect(readyClipId).toBeTruthy();
    await withUserPage(browser, BOB_ID, async (page) => {
      const resp = await apiPost(page, BOB_ID, `/broadcast/sessions/${liveSessionId}/clips`, {
        start_seconds: 0,
        end_seconds: 12,
        title: `Status Clip ${TS}`,
      });
      // May be rate-limited if run immediately after 712.1; tolerate that.
      if (resp.status() === 200) {
        const clip = await resp.json();
        // In dev mode the clip is marked ready synchronously.
        expect(["processing", "ready"]).toContain(clip.status);
      } else {
        expect(resp.status()).toBe(429);
      }
    });
  });

  test("712.3 Clip with duration < 5s rejected", async ({ browser }) => {
    await withUserPage(browser, BOB_ID, async (page) => {
      const resp = await apiPost(page, BOB_ID, `/broadcast/sessions/${liveSessionId}/clips`, {
        start_seconds: 10,
        end_seconds: 13,
      });
      expect(resp.status()).toBe(400);
      const body = await resp.json();
      expect(JSON.stringify(body.detail)).toContain("Minimum clip duration");
    });
  });

  test("712.4 Clip with duration > 60s rejected", async ({ browser }) => {
    await withUserPage(browser, BOB_ID, async (page) => {
      const resp = await apiPost(page, BOB_ID, `/broadcast/sessions/${liveSessionId}/clips`, {
        start_seconds: 0,
        end_seconds: 75,
      });
      expect(resp.status()).toBe(400);
      const body = await resp.json();
      expect(JSON.stringify(body.detail)).toContain("Maximum clip duration");
    });
  });

  test("712.5 Clip start_seconds >= end_seconds rejected", async ({ browser }) => {
    await withUserPage(browser, BOB_ID, async (page) => {
      const resp = await apiPost(page, BOB_ID, `/broadcast/sessions/${liveSessionId}/clips`, {
        start_seconds: 40,
        end_seconds: 20,
      });
      expect(resp.status()).toBe(400);
      const body = await resp.json();
      expect(JSON.stringify(body.detail)).toContain("start_seconds must be less than end_seconds");
    });
  });

  test("712.6 Clip from non-live broadcast (no recording) rejected", async ({ browser }) => {
    // A freshly created session that is never started is not live and has no recording.
    const idleSessionId = await withRootPage(browser, (rootPage) =>
      createBroadcastSession(rootPage),
    );
    await withUserPage(browser, BOB_ID, async (page) => {
      const resp = await apiPost(page, BOB_ID, `/broadcast/sessions/${idleSessionId}/clips`, {
        start_seconds: 0,
        end_seconds: 15,
      });
      expect(resp.status()).toBe(400);
      const body = await resp.json();
      expect(JSON.stringify(body.detail)).toContain("No recording available");
    });
  });

  test("712.7 Auth required for clip creation (401)", async ({ request }) => {
    // No cookies / no auth -> require_ui_session should reject.
    const resp = await request.post(`${API}/broadcast/sessions/${liveSessionId}/clips`, {
      data: { start_seconds: 0, end_seconds: 15 },
    });
    expect(resp.status()).toBe(401);
  });

  test("712.8 Clip appears in the gallery", async ({ browser }) => {
    expect(readyClipId).toBeTruthy();
    await withUserPage(browser, BOB_ID, async (page) => {
      const resp = await page.request.get(`${API}/ui/clips?sort=recent&limit=100`);
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      const ids = (body.clips as Array<{ clip_id: string }>).map((c) => c.clip_id);
      expect(ids).toContain(readyClipId);
    });
  });

  test("712.9 Public clip view works WITHOUT auth + shows attribution", async ({ request }) => {
    expect(readyClipId).toBeTruthy();
    // Bare request fixture carries no session cookies.
    const resp = await request.get(`${API}/broadcast/public/clips/${readyClipId}`);
    expect(resp.status()).toBe(200);
    const clip = await resp.json();
    expect(clip.clip_id).toBe(readyClipId);
    // Attribution fields present on the public payload.
    expect(clip).toHaveProperty("broadcaster_display_name");
    expect(clip).toHaveProperty("profile_id");
    expect(clip.broadcaster_user_id).toBeTruthy();
    expect(clip.creator_display_name).toBeTruthy();
  });

  test("712.10 Public view counter increments without auth", async ({ request }) => {
    expect(readyClipId).toBeTruthy();
    const before = await (
      await request.get(`${API}/broadcast/public/clips/${readyClipId}`)
    ).json();
    const viewResp = await request.post(`${API}/broadcast/public/clips/${readyClipId}/view`);
    expect(viewResp.status()).toBe(200);
    const viewBody = await viewResp.json();
    expect(viewBody.view_count).toBe(before.view_count + 1);
  });

  test("712.11 Public share counter + share_url without auth", async ({ request }) => {
    expect(readyClipId).toBeTruthy();
    const resp = await request.post(`${API}/broadcast/public/clips/${readyClipId}/share`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.share_count).toBeGreaterThanOrEqual(1);
    expect(body.share_url).toBe(`/clips/${readyClipId}`);
  });

  test("712.12 Public clip view 404 for non-existent clip", async ({ request }) => {
    const resp = await request.get(`${API}/broadcast/public/clips/bclip_doesnotexist${TS}`);
    expect(resp.status()).toBe(404);
  });

  test("712.13 Public clip page renders with attribution (no auth)", async ({ browser }) => {
    expect(readyClipId).toBeTruthy();
    // Fresh context with NO auth cookies -> the public /c/:clipId route must render.
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    try {
      await page.goto(`${BASE}/c/${readyClipId}`, { waitUntil: "domcontentloaded" });
      await expect(page.getByTestId("clip-attribution")).toBeVisible({ timeout: 15_000 });
      await expect(page.getByText(/Clipped from/i)).toBeVisible();
    } finally {
      await ctx.close();
    }
  });
});
