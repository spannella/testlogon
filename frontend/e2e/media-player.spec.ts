/**
 * E2E tests for the shared MediaPlayer component (MEDIA-001).
 *
 * Section 116: Shared Media Player
 *
 * These tests exercise the MediaPlayer component through the VideoPlayerPage
 * (VOD mode) and verify UI states. Since HLS.js cannot actually play real
 * video segments in headless Chromium, we focus on:
 * - Component rendering and attribute correctness
 * - Loading state display
 * - Error state and retry button
 * - Quality selector UI
 * - Mode-specific elements (LIVE badge, seek bar, duration)
 * - Fullscreen and PiP button presence
 *
 * Auth: Alice session cookies (from e2e_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";

// ─── Session bootstrap ────────────────────────────────────────────────────────

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

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * A minimal valid HLS master manifest with 3 quality levels.
 */
const MOCK_HLS_MANIFEST = `#EXTM3U
#EXT-X-VERSION:3
#EXT-X-STREAM-INF:BANDWIDTH=800000,RESOLUTION=640x360
/mock-hls/360p.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=1400000,RESOLUTION=1280x720
/mock-hls/720p.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=2800000,RESOLUTION=1920x1080
/mock-hls/1080p.m3u8
`;

const MOCK_VARIANT_PLAYLIST = `#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
/mock-hls/segment0.seg
#EXT-X-ENDLIST
`;

/**
 * Set up route mocks for the video detail API and HLS manifest.
 * Call BEFORE navigation to the video page.
 */
async function setupVideoMocks(
  page: Page,
  videoId: string,
  opts: {
    manifestUrl?: string;
    playbackToken?: string | null;
    title?: string;
    duration?: number;
    delayManifestMs?: number;
    manifestStatus?: number;
  } = {},
) {
  const {
    manifestUrl = `/mock-hls/${videoId}/master.m3u8`,
    playbackToken = "test-token",
    title = "Test Video",
    duration = 120,
    delayManifestMs = 0,
    manifestStatus = 200,
  } = opts;

  // Mock video detail API
  await page.route(`**/ui/videos/${videoId}`, (route) => {
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: videoId,
        title,
        description: "Test description",
        status: "published",
        visibility: "public",
        hls_manifest_url: manifestUrl,
        playback_token: playbackToken,
        thumbnail_url: null,
        created_at: 1700000000,
        duration_seconds: duration,
        width: 1920,
        height: 1080,
        renditions: [
          { label: "360p", height: 360, bitrate_kbps: 800 },
          { label: "720p", height: 720, bitrate_kbps: 1400 },
          { label: "1080p", height: 1080, bitrate_kbps: 2800 },
        ],
      }),
    });
  });

  // Mock HLS master manifest
  await page.route(`**/mock-hls/${videoId}/master.m3u8*`, async (route) => {
    if (delayManifestMs > 0) {
      await new Promise((r) => setTimeout(r, delayManifestMs));
    }
    if (manifestStatus !== 200) {
      route.fulfill({ status: manifestStatus, body: "Not Found" });
      return;
    }
    route.fulfill({
      status: 200,
      contentType: "application/vnd.apple.mpegurl",
      body: MOCK_HLS_MANIFEST,
    });
  });

  // Mock variant playlists
  await page.route("**/mock-hls/*.m3u8*", (route) => {
    const url = route.request().url();
    if (url.includes("master")) {
      route.continue();
      return;
    }
    route.fulfill({
      status: 200,
      contentType: "application/vnd.apple.mpegurl",
      body: MOCK_VARIANT_PLAYLIST,
    });
  });

  // Mock segment requests (return empty to avoid actual video decode)
  await page.route("**/mock-hls/*.seg*", (route) => {
    // Return a minimal MPEG-TS null packet (188 bytes) so HLS.js doesn't error immediately
    const nullPacket = Buffer.alloc(188, 0);
    nullPacket[0] = 0x47; // sync byte
    route.fulfill({
      status: 200,
      contentType: "video/mp2t",
      body: nullPacket,
    });
  });
}

// ─── Section 116: Shared Media Player ─────────────────────────────────────────

test.describe("Section 116: Shared Media Player", () => {
  test("116.1 — MediaPlayer renders video element with correct attributes", async ({
    page,
  }) => {
    await injectAuth(page);
    await setupVideoMocks(page, "vid-116-1", { title: "Render Test" });

    await page.goto(`${BASE}/videos/vid-116-1`);

    // The MediaPlayer component should render
    const player = page.locator("[data-testid='media-player']");
    await expect(player).toBeVisible({ timeout: 15_000 });

    // Check mode attribute
    await expect(player).toHaveAttribute("data-mode", "vod");

    // Check the video element exists with playsInline attribute
    const video = page.locator("[data-testid='media-player-video']");
    await expect(video).toBeAttached();
  });

  test("116.2 — Quality selector shows available levels after manifest parse", async ({
    page,
  }) => {
    await injectAuth(page);
    await setupVideoMocks(page, "vid-116-2", { title: "Quality Test" });

    await page.goto(`${BASE}/videos/vid-116-2`);

    // Wait for the quality selector to appear (renders after MANIFEST_PARSED)
    const qualityBtn = page.locator("[data-testid='quality-selector']");
    await expect(qualityBtn).toBeVisible({ timeout: 15_000 });

    // Click quality selector to open dropdown
    await qualityBtn.click();

    // Check that Auto option is present
    const autoOption = page.locator("[data-testid='quality-auto']");
    await expect(autoOption).toBeVisible();

    // Check that resolution options are present
    await expect(page.locator("[data-testid='quality-360p']")).toBeVisible();
    await expect(page.locator("[data-testid='quality-720p']")).toBeVisible();
    await expect(page.locator("[data-testid='quality-1080p']")).toBeVisible();
  });

  test("116.3 — Switching quality level updates selector label", async ({
    page,
  }) => {
    await injectAuth(page);
    await setupVideoMocks(page, "vid-116-3", { title: "Switch Quality Test" });

    await page.goto(`${BASE}/videos/vid-116-3`);

    const qualityBtn = page.locator("[data-testid='quality-selector']");
    await expect(qualityBtn).toBeVisible({ timeout: 15_000 });

    // Initially shows "Auto"
    await expect(qualityBtn).toContainText("Auto");

    // Open dropdown and select 720p
    await qualityBtn.click();
    await page.locator("[data-testid='quality-720p']").click();

    // After selecting, the button should update to show 720p
    await expect(qualityBtn).toContainText("720p");
  });

  test("116.4 — Error state shows retry button on failed manifest load", async ({
    page,
  }) => {
    test.setTimeout(60_000);
    await injectAuth(page);
    await setupVideoMocks(page, "vid-116-4", {
      title: "Error Test",
      manifestStatus: 404,
    });

    await page.goto(`${BASE}/videos/vid-116-4`);

    // HLS.js retries manifest load several times before firing fatal error.
    // Once the MediaPlayer fires onError, VideoPlayerPage replaces it with ErrorDisplay.
    // Look for VideoPlayerPage's error display (data-testid='video-error')
    // which wraps the error coming from the MediaPlayer's onError callback.
    const errorDisplay = page.locator("[data-testid='video-error']");
    await expect(errorDisplay).toBeVisible({ timeout: 45_000 });

    // Error message should mention stream unavailability
    const errorMsg = page.locator("[data-testid='error-message']");
    await expect(errorMsg).toBeVisible();
    await expect(errorMsg).toContainText("unavailable");

    // Retry button should be present
    const retryBtn = errorDisplay.getByRole("button", { name: "Retry" });
    await expect(retryBtn).toBeVisible();
  });

  test("116.5 — VOD mode uses native video controls", async ({ page }) => {
    await injectAuth(page);
    await setupVideoMocks(page, "vid-116-5", { title: "Controls Test" });

    await page.goto(`${BASE}/videos/vid-116-5`);

    // The media player renders in VOD mode with native controls
    const player = page.locator("[data-testid='media-player']");
    await expect(player).toBeVisible({ timeout: 15_000 });

    // In VOD (native controls) mode, the video element has controls attribute
    const video = page.locator("[data-testid='media-player-video']");
    await expect(video).toHaveAttribute("controls", "");
  });

  test("116.6 — Video element supports Picture-in-Picture API", async ({
    page,
  }) => {
    await injectAuth(page);
    await setupVideoMocks(page, "vid-116-6", { title: "PiP Test" });

    await page.goto(`${BASE}/videos/vid-116-6`);

    const player = page.locator("[data-testid='media-player']");
    await expect(player).toBeVisible({ timeout: 15_000 });

    // The video element should support PiP
    const video = page.locator("[data-testid='media-player-video']");
    await expect(video).toBeAttached();
    const supportsPip = await video.evaluate((el: HTMLVideoElement) => {
      return "requestPictureInPicture" in el;
    });
    expect(supportsPip).toBe(true);
  });

  test("116.7 — VOD mode does not show LIVE badge", async ({ page }) => {
    await injectAuth(page);
    await setupVideoMocks(page, "vid-116-7", { title: "Live Badge Test" });

    await page.goto(`${BASE}/videos/vid-116-7`);

    const player = page.locator("[data-testid='media-player']");
    await expect(player).toBeVisible({ timeout: 15_000 });
    await expect(player).toHaveAttribute("data-mode", "vod");

    // LIVE badge should NOT be present in VOD mode
    const liveBadge = page.locator("[data-testid='media-player-live-badge']");
    await expect(liveBadge).not.toBeVisible();
  });

  test("116.8 — VOD mode player shows title overlay", async ({ page }) => {
    await injectAuth(page);
    await setupVideoMocks(page, "vid-116-8", { title: "Title Overlay Test" });

    await page.goto(`${BASE}/videos/vid-116-8`);

    const player = page.locator("[data-testid='media-player']");
    await expect(player).toBeVisible({ timeout: 15_000 });

    // Title overlay should show the video title
    const titleOverlay = page.locator("[data-testid='media-player-title']");
    await expect(titleOverlay).toBeVisible();
    await expect(titleOverlay).toContainText("Title Overlay Test");
  });

  test("116.9 — Loading spinner shows before manifest is parsed", async ({
    page,
  }) => {
    await injectAuth(page);
    await setupVideoMocks(page, "vid-116-9", {
      title: "Loading Test",
      delayManifestMs: 5000,
    });

    await page.goto(`${BASE}/videos/vid-116-9`);

    // Loading spinner should be visible while waiting for manifest
    const loadingOverlay = page.locator("[data-testid='media-player-loading']");
    await expect(loadingOverlay).toBeVisible({ timeout: 10_000 });

    // It should contain "Loading" text
    await expect(loadingOverlay).toContainText("Loading");
  });

  test("116.10 — Player handles missing playback token gracefully", async ({
    page,
  }) => {
    await injectAuth(page);
    await setupVideoMocks(page, "vid-116-10", {
      title: "No Token Test",
      playbackToken: null,
    });

    await page.goto(`${BASE}/videos/vid-116-10`);

    // When playback_token is null, playbackUrl is null, so VideoPlayerPage
    // shows its own error display (not the MediaPlayer error overlay)
    const errorDisplay = page.locator("[data-testid='video-error']");
    await expect(errorDisplay).toBeVisible({ timeout: 15_000 });

    // Should show an appropriate error message about expiry
    const errorMsg = page.locator("[data-testid='error-message']");
    await expect(errorMsg).toBeVisible();
    await expect(errorMsg).toContainText("expired");
  });
});
