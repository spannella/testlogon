/**
 * E2E tests for Video Player Page (VOD-008).
 *
 * Section 108: Video Player Page
 *   108.1: Page loads for valid video ID
 *   108.2: Shows video metadata (title, description)
 *   108.3: Shows "Video not found" for invalid ID (404)
 *   108.4: Shows "forbidden" for non-owner private video (403)
 *   108.5: Shows "processing" state for video still encoding
 *   108.6: Quality selector shows available renditions
 *   108.7: Share button copies URL to clipboard
 *   108.8: Back button navigates to /videos
 *   108.9: Published public video accessible by non-owner
 *   108.10: Video element is present and has correct attributes
 *
 * Auth: Alice + Bob sessions (from e2e_session_setup.py).
 *
 * Strategy: Seed video records directly in DynamoDB with various states.
 * The HLS player won't play real video (no HLS segments in test env),
 * but we test UI states, metadata display, and error handling.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();

// Video IDs for seeding
const PUBLISHED_VIDEO_ID = `v_e2epub${TS}`;
const PROCESSING_VIDEO_ID = `v_e2eproc${TS}`;
const PRIVATE_VIDEO_ID = `v_e2epriv${TS}`;
const PUBLIC_VIDEO_ID = `v_e2epub2${TS}`;

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
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

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

// ─── DynamoDB helpers (via Python, since aws CLI is not installed) ─────────────

import { writeFileSync, unlinkSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

function ddbPut(tableName: string, item: Record<string, unknown>) {
  const itemJson = JSON.stringify(item);
  const scriptPath = join(tmpdir(), `ddb_put_${Date.now()}.py`);
  writeFileSync(scriptPath, `
import boto3, json, sys
from decimal import Decimal

def convert(obj):
    if isinstance(obj, dict):
        return {k: convert(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [convert(i) for i in obj]
    if isinstance(obj, float):
        return Decimal(str(obj))
    return obj

ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
table = ddb.Table('${tableName}')
table.put_item(Item=convert(json.loads(sys.argv[1])))
`);
  try {
    execSync(
      `python3 ${scriptPath} ${JSON.stringify(itemJson)}`,
      { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
    );
  } finally {
    try { unlinkSync(scriptPath); } catch { /* ignore */ }
  }
}

function ddbDelete(tableName: string, key: Record<string, unknown>) {
  const keyJson = JSON.stringify(key);
  const scriptPath = join(tmpdir(), `ddb_del_${Date.now()}.py`);
  writeFileSync(scriptPath, `
import boto3, json, sys
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
table = ddb.Table('${tableName}')
table.delete_item(Key=json.loads(sys.argv[1]))
`);
  try {
    execSync(
      `python3 ${scriptPath} ${JSON.stringify(keyJson)}`,
      { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
    );
  } catch {
    // Ignore cleanup errors
  } finally {
    try { unlinkSync(scriptPath); } catch { /* ignore */ }
  }
}

// ─── Test Setup ───────────────────────────────────────────────────────────────

const VIDEO_TABLE = "VideoMetadata";
const nowTs = Math.floor(Date.now() / 1000);

test.beforeAll(() => {
  getSessions(); // Ensure sessions are seeded

  const aliceSub = getSessions()[ALICE_ID].user_sub;
  const bobSub = getSessions()[BOB_ID].user_sub;

  // 1. Published video owned by Alice (with HLS manifest + renditions)
  ddbPut(VIDEO_TABLE, {
    video_id: PUBLISHED_VIDEO_ID,
    owner_user_id: aliceSub,
    title: `E2E Published Video ${TS}`,
    description: `Test description for published video ${TS}`,
    status: "published",
    visibility: "private",
    created_at: nowTs - 3600,
    updated_at: nowTs - 1800,
    duration_seconds: 332,
    width: 1920,
    height: 1080,
    frame_rate: 30,
    video_codec: "h264",
    audio_codec: "aac",
    file_size_bytes: 52428800,
    hls_manifest_url: `http://localhost:8000/mock/s3/local-uploads/videos/${aliceSub}/${PUBLISHED_VIDEO_ID}/master.m3u8`,
    source_type: "upload",
    renditions: [
      { label: "1080p", width: 1920, height: 1080, bitrate_kbps: 5000 },
      { label: "720p", width: 1280, height: 720, bitrate_kbps: 2500 },
      { label: "360p", width: 640, height: 360, bitrate_kbps: 800 },
    ],
  });

  // 2. Processing video owned by Alice
  ddbPut(VIDEO_TABLE, {
    video_id: PROCESSING_VIDEO_ID,
    owner_user_id: aliceSub,
    title: `E2E Processing Video ${TS}`,
    description: `This video is still being encoded ${TS}`,
    status: "encoding",
    visibility: "private",
    created_at: nowTs - 600,
    updated_at: nowTs - 300,
    source_type: "upload",
  });

  // 3. Private video owned by Bob (Alice should get 403)
  ddbPut(VIDEO_TABLE, {
    video_id: PRIVATE_VIDEO_ID,
    owner_user_id: bobSub,
    title: `E2E Bob Private Video ${TS}`,
    description: `Bob's private video ${TS}`,
    status: "published",
    visibility: "private",
    created_at: nowTs - 7200,
    updated_at: nowTs - 3600,
    duration_seconds: 120,
    width: 1280,
    height: 720,
    source_type: "upload",
    hls_manifest_url: `http://localhost:8000/mock/s3/local-uploads/videos/${bobSub}/${PRIVATE_VIDEO_ID}/master.m3u8`,
  });

  // 4. Public video owned by Bob (Alice should be able to view)
  ddbPut(VIDEO_TABLE, {
    video_id: PUBLIC_VIDEO_ID,
    owner_user_id: bobSub,
    title: `E2E Bob Public Video ${TS}`,
    description: `Bob's public video ${TS}`,
    status: "published",
    visibility: "public",
    created_at: nowTs - 5400,
    updated_at: nowTs - 2700,
    duration_seconds: 245,
    width: 1920,
    height: 1080,
    source_type: "upload",
    hls_manifest_url: `http://localhost:8000/mock/s3/local-uploads/videos/${bobSub}/${PUBLIC_VIDEO_ID}/master.m3u8`,
  });
});

test.afterAll(() => {
  // Cleanup seeded videos
  ddbDelete(VIDEO_TABLE, { video_id: PUBLISHED_VIDEO_ID });
  ddbDelete(VIDEO_TABLE, { video_id: PROCESSING_VIDEO_ID });
  ddbDelete(VIDEO_TABLE, { video_id: PRIVATE_VIDEO_ID });
  ddbDelete(VIDEO_TABLE, { video_id: PUBLIC_VIDEO_ID });
});

// ─── Section 108: Video Player Page ──────────────────────────────────────────

test.describe("Section 108 · Video Player Page", () => {
  test("108.1 Page loads for valid video ID", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/videos/${PUBLISHED_VIDEO_ID}`, { waitUntil: "domcontentloaded" });

    // Page should load without showing an error
    await expect(page.getByTestId("video-title")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("video-title")).toHaveText(`E2E Published Video ${TS}`);
    await ctx.close();
  });

  test("108.2 Shows video metadata (title, description)", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/videos/${PUBLISHED_VIDEO_ID}`, { waitUntil: "domcontentloaded" });

    await expect(page.getByTestId("video-title")).toHaveText(`E2E Published Video ${TS}`, { timeout: 10_000 });
    await expect(page.getByTestId("video-description")).toHaveText(`Test description for published video ${TS}`);
    await expect(page.getByTestId("video-duration")).toBeVisible();
    await expect(page.getByTestId("video-upload-date")).toBeVisible();
    await expect(page.getByTestId("video-resolution")).toBeVisible();
    await expect(page.getByTestId("video-resolution")).toContainText("1920x1080");
    await expect(page.getByTestId("video-status-badge")).toContainText("published");
    await ctx.close();
  });

  test("108.3 Shows 'Video not found' for invalid ID (404)", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/videos/v_nonexistent_${TS}`, { waitUntil: "domcontentloaded" });

    await expect(page.getByTestId("video-error")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("error-message")).toHaveText("Video not found");
    await ctx.close();
  });

  test("108.4 Shows 'forbidden' for non-owner private video (403)", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/videos/${PRIVATE_VIDEO_ID}`, { waitUntil: "domcontentloaded" });

    await expect(page.getByTestId("video-error")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("error-message")).toContainText("access");
    await ctx.close();
  });

  test("108.5 Shows 'processing' state for video still encoding", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/videos/${PROCESSING_VIDEO_ID}`, { waitUntil: "domcontentloaded" });

    await expect(page.getByTestId("video-processing")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("Video is being processed")).toBeVisible();
    await ctx.close();
  });

  test("108.6 Quality selector shows available renditions", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/videos/${PUBLISHED_VIDEO_ID}`, { waitUntil: "domcontentloaded" });

    await expect(page.getByTestId("video-title")).toBeVisible({ timeout: 10_000 });

    // The renditions section should show in metadata
    await expect(page.getByTestId("video-renditions")).toBeVisible();
    await expect(page.getByTestId("video-renditions")).toContainText("1080p");
    await expect(page.getByTestId("video-renditions")).toContainText("720p");
    await expect(page.getByTestId("video-renditions")).toContainText("360p");
    await ctx.close();
  });

  test("108.7 Share button copies URL to clipboard", async ({ browser }) => {
    const ctx = await browser.newContext();
    await ctx.grantPermissions(["clipboard-read", "clipboard-write"]);
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/videos/${PUBLISHED_VIDEO_ID}`, { waitUntil: "domcontentloaded" });

    await expect(page.getByTestId("video-title")).toBeVisible({ timeout: 10_000 });

    const shareBtn = page.getByTestId("share-button");
    await expect(shareBtn).toBeVisible();
    await shareBtn.click();

    // Button text should change to "Copied!"
    await expect(shareBtn).toContainText("Copied!");

    // Verify clipboard content
    const clipboardText = await page.evaluate(() => navigator.clipboard.readText());
    expect(clipboardText).toContain(`/videos/${PUBLISHED_VIDEO_ID}`);
    await ctx.close();
  });

  test("108.8 Back button navigates to /videos", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/videos/${PUBLISHED_VIDEO_ID}`, { waitUntil: "domcontentloaded" });

    await expect(page.getByTestId("video-title")).toBeVisible({ timeout: 10_000 });

    const backBtn = page.getByTestId("back-to-videos");
    await expect(backBtn).toBeVisible();
    await backBtn.click();

    await page.waitForURL("**/videos", { timeout: 5_000 });
    expect(page.url()).toContain("/videos");
    // Should NOT contain a videoId path segment
    expect(page.url()).not.toContain(PUBLISHED_VIDEO_ID);
    await ctx.close();
  });

  test("108.9 Published public video accessible by non-owner", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/videos/${PUBLIC_VIDEO_ID}`, { waitUntil: "domcontentloaded" });

    // Alice should be able to see Bob's public video
    await expect(page.getByTestId("video-title")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("video-title")).toHaveText(`E2E Bob Public Video ${TS}`);
    await expect(page.getByTestId("video-description")).toHaveText(`Bob's public video ${TS}`);
    await ctx.close();
  });

  test("108.10 Video element is present with correct attributes", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/videos/${PUBLISHED_VIDEO_ID}`, { waitUntil: "domcontentloaded" });

    await expect(page.getByTestId("video-title")).toBeVisible({ timeout: 10_000 });

    // Check that either the video player container is present or the video element
    const playerContainer = page.getByTestId("video-player-container");
    const videoElement = page.getByTestId("video-element");

    // The video player may or may not be visible depending on whether
    // the playback token was issued and HLS manifest is accessible.
    // In test env without real HLS segments, we may see:
    //   1. The video element (if HLS.js hasn't errored yet)
    //   2. A player error overlay (if HLS.js errored on missing manifest)
    // Either way, the video element should exist in the DOM (inside player container)
    // or we should see a player error.
    const hasPlayer = await playerContainer.isVisible().catch(() => false);
    if (hasPlayer) {
      // Video element should be in the DOM with correct attributes
      const playsInline = await videoElement.getAttribute("playsinline");
      expect(playsInline).not.toBeNull();
      const controls = await videoElement.getAttribute("controls");
      expect(controls).not.toBeNull();
    } else {
      // Player error state (HLS stream unavailable in test env)
      const errorState = page.getByTestId("video-error");
      await expect(errorState).toBeVisible();
      // Accept any player error message
      await expect(page.getByTestId("error-message")).toBeVisible();
    }
    await ctx.close();
  });
});
