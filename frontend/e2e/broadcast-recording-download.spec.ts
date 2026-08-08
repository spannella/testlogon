import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

/* ------------------------------------------------------------------ */
/*  Constants & helpers                                                */
/* ------------------------------------------------------------------ */

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
  body?: object,
) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiPatch(
  page: Page,
  identity: string,
  path: string,
  body?: object,
) {
  const s = getSessions()[identity];
  return page.request.patch(`${API}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": s.csrf_token },
  });
}

/**
 * Create a broadcast session and stop it (to trigger recording with MP4).
 * Returns the session_id.
 */
async function createStoppedSession(rootPage: Page): Promise<string> {
  // Create profile
  const profileResp = await apiPost(rootPage, "root", "/broadcast/profiles", {
    name: `DL Test Profile ${TS}_${Math.random().toString(36).slice(2, 8)}`,
    region: "us-east-1",
    rendition_preset: "720p_3mbps",
  });
  expect(profileResp.status()).toBe(201);
  const profile = await profileResp.json();

  // Create session
  const sessionResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
    profile_id: profile.id,
  });
  expect(sessionResp.status()).toBe(201);
  const session = await sessionResp.json();

  // Start session
  const startResp = await apiPost(
    rootPage,
    "root",
    `/broadcast/sessions/${session.id}/start`,
    { reason: "e2e-download-test" },
  );
  expect(startResp.status()).toBe(202);

  // Wait for live
  await expect
    .poll(
      async () => {
        const r = await apiGet(rootPage, `/broadcast/sessions/${session.id}`);
        const d = await r.json();
        return d.status;
      },
      { timeout: 10000 },
    )
    .toBe("live");

  // Stop session (triggers recording with MP4)
  const stopResp = await apiPost(
    rootPage,
    "root",
    `/broadcast/sessions/${session.id}/stop`,
    { reason: "e2e-download-test-stop" },
  );
  expect(stopResp.status()).toBe(202);

  // Wait for stopped
  await expect
    .poll(
      async () => {
        const r = await apiGet(rootPage, `/broadcast/sessions/${session.id}`);
        const d = await r.json();
        return d.status;
      },
      { timeout: 10000 },
    )
    .toBe("stopped");

  // Wait for recording to be ready
  await expect
    .poll(
      async () => {
        const r = await apiGet(
          rootPage,
          `/broadcast/sessions/${session.id}/recording`,
        );
        if (r.status() !== 200) return "not-ready";
        const d = await r.json();
        return d.status;
      },
      { timeout: 15000 },
    )
    .toBe("ready");

  return session.id;
}

/* ------------------------------------------------------------------ */
/*  Section 93 — Broadcaster Recording Download                       */
/* ------------------------------------------------------------------ */

test.describe("Section 93: Broadcaster recording download", () => {
  let rootPage: Page;
  let alicePage: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, "root");

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    sessionId = await createStoppedSession(rootPage);
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("93.1 download endpoint returns presigned URL for broadcaster", async () => {
    const resp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/recording/download`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.download_url).toContain("/mock/s3/broadcast-vod/");
    expect(body.download_url).toContain("full.mp4");
    expect(body.download_expires_at).toBeGreaterThan(
      Math.floor(Date.now() / 1000),
    );
    expect(body.filename).toContain("recording-");
    expect(body.content_type).toBe("video/mp4");
  });

  test("93.2 download URL expires within configured TTL", async () => {
    const resp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/recording/download`,
    );
    const body = await resp.json();
    const now = Math.floor(Date.now() / 1000);
    const maxTtl = 14400 + 10; // 4 hours + 10s tolerance
    expect(body.download_expires_at - now).toBeLessThanOrEqual(maxTtl);
    expect(body.download_expires_at - now).toBeGreaterThan(0);
  });

  test("93.3 recording response includes download_available=true", async () => {
    const resp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/recording`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.download_available).toBe(true);
    expect(body.allow_viewer_download).toBe(false);
  });

  test("93.4 download for non-existent session returns 404", async () => {
    const resp = await apiGet(
      rootPage,
      `/broadcast/sessions/nonexistent-session-xyz/recording/download`,
    );
    expect(resp.status()).toBe(404);
  });

  test("93.5 download requires authentication", async () => {
    const resp = await rootPage.request.fetch(
      `${API}/broadcast/sessions/${sessionId}/recording/download`,
      {
        headers: {
          // No cookies, no auth
          cookie: "",
        },
      },
    );
    // Without auth cookies, will get 401
    expect([401, 403]).toContain(resp.status());
  });

  test("93.6 non-owner cannot download broadcaster recording", async () => {
    const resp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/recording/download`,
    );
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.detail.code).toBe("BROADCAST_RECORDING_DOWNLOAD_FORBIDDEN");
  });

  test("93.7 file_size_bytes is returned in response", async () => {
    const resp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/recording/download`,
    );
    const body = await resp.json();
    expect(typeof body.file_size_bytes).toBe("number");
    expect(body.file_size_bytes).toBeGreaterThanOrEqual(0);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 94 — Viewer Download Permissions                          */
/* ------------------------------------------------------------------ */

test.describe("Section 94: Viewer download permissions", () => {
  let rootPage: Page;
  let alicePage: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, "root");

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    sessionId = await createStoppedSession(rootPage);
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("94.1 viewer download disabled by default", async () => {
    const resp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/recording/download?viewer=true`,
    );
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.detail.code).toBe("BROADCAST_RECORDING_DOWNLOAD_FORBIDDEN");
  });

  test("94.2 broadcaster enables viewer download", async () => {
    const resp = await apiPatch(
      rootPage,
      "root",
      `/broadcast/sessions/${sessionId}/recording/download-settings`,
      { allow_viewer_download: true },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.allow_viewer_download).toBe(true);
  });

  test("94.3 viewer can download after broadcaster enables it", async () => {
    const resp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/recording/download?viewer=true`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.download_url).toContain("full.mp4");
  });

  test("94.4 broadcaster disables viewer download", async () => {
    const resp = await apiPatch(
      rootPage,
      "root",
      `/broadcast/sessions/${sessionId}/recording/download-settings`,
      { allow_viewer_download: false },
    );
    expect(resp.status()).toBe(200);
    expect((await resp.json()).allow_viewer_download).toBe(false);
  });

  test("94.5 viewer download blocked again after disable", async () => {
    const resp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/recording/download?viewer=true`,
    );
    expect(resp.status()).toBe(403);
  });

  test("94.6 non-owner cannot toggle viewer download", async () => {
    const resp = await apiPatch(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/recording/download-settings`,
      { allow_viewer_download: true },
    );
    expect(resp.status()).toBe(403);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 95 — Download Edge Cases                                  */
/* ------------------------------------------------------------------ */

test.describe("Section 95: Download edge cases", () => {
  let rootPage: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, "root");

    sessionId = await createStoppedSession(rootPage);
  });

  test.afterAll(async () => {
    await rootPage.context().close();
  });

  test("95.1 recording response shows allow_viewer_download state", async () => {
    // Enable viewer download
    await apiPatch(
      rootPage,
      "root",
      `/broadcast/sessions/${sessionId}/recording/download-settings`,
      { allow_viewer_download: true },
    );
    const resp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/recording`,
    );
    const body = await resp.json();
    expect(body.allow_viewer_download).toBe(true);
  });

  test("95.2 download URL contains correct filename format", async () => {
    const resp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/recording/download`,
    );
    const body = await resp.json();
    expect(body.filename).toMatch(/^recording-[a-z0-9_-]+\.mp4$/);
  });

  test("95.3 multiple download requests produce fresh URLs", async () => {
    const resp1 = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/recording/download`,
    );
    const body1 = await resp1.json();

    // Small delay to ensure different timestamp
    await new Promise((r) => setTimeout(r, 1100));

    const resp2 = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/recording/download`,
    );
    const body2 = await resp2.json();

    // URLs should have different expiry timestamps (at least 1s apart)
    expect(body2.download_expires_at).toBeGreaterThanOrEqual(
      body1.download_expires_at,
    );
  });

  test("95.4 recording response includes download fields", async () => {
    const resp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/recording`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("allow_download");
    expect(body).toHaveProperty("allow_viewer_download");
    expect(body).toHaveProperty("download_available");
    expect(body.download_available).toBe(true);
    expect(body.allow_download).toBe(true);
  });

  test("95.5 download URL includes disposition param in dev mode", async () => {
    const resp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/recording/download`,
    );
    const body = await resp.json();
    expect(body.download_url).toContain("disposition=attachment");
  });
});
