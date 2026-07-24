/**
 * E2E tests for recommendation engagement signals (GAP-0160).
 *
 * Section 160: recordEngagement called from VideoPlayerPage
 *   160.1: fires engagement signal with watch_pct=100 when the video ends
 *   160.2: fires engagement signal at ~30% watch milestone (timeupdate)
 *
 * Background: POST /ui/recommendations/engagement is the data-intake layer for
 * the recommendation engine. Before the fix, VideoPlayerPage never called
 * recordEngagement, so compute_affinity_scores always received empty input.
 *
 * The fix wires onEnded + onProgress callbacks from MediaPlayer into
 * VideoPlayerPage, which call recordEngagement (React Query useMutation,
 * fire-and-forget).
 *
 * Strategy: seed a published video in DynamoDB, open the player, then dispatch
 * native `ended` / `timeupdate` events on the underlying <video> element and
 * assert the engagement POST fires with the expected body.
 *
 * Fails before fix: no POST /ui/recommendations/engagement is ever made.
 * Passes after fix: handleVideoEnded / handleVideoProgress fire the POST.
 *
 * Auth: Alice session (from e2e_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import { writeFileSync, unlinkSync } from "fs";
import { tmpdir } from "os";
import { join, resolve } from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

const ENGAGE_VIDEO_ID = `v_e2eengage${TS}`;
const VIDEO_TABLE = "VideoMetadata";
const ENGAGEMENT_URL = "/ui/recommendations/engagement";

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
    _sessions = loadSessions();
  }
  return _sessions!;
}

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

function ddbPut(tableName: string, item: Record<string, unknown>) {
  const itemJson = JSON.stringify(item);
  const scriptPath = join(tmpdir(), `ddb_put_${Date.now()}.py`);
  writeFileSync(
    scriptPath,
    `
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
`,
  );
  try {
    execSync(`python3 ${scriptPath} ${JSON.stringify(itemJson)}`, {
      cwd: REPO_ROOT,
      timeout: 10_000,
    });
  } finally {
    try {
      unlinkSync(scriptPath);
    } catch {
      /* ignore */
    }
  }
}

function ddbDelete(tableName: string, key: Record<string, unknown>) {
  const keyJson = JSON.stringify(key);
  const scriptPath = join(tmpdir(), `ddb_del_${Date.now()}.py`);
  writeFileSync(
    scriptPath,
    `
import boto3, json, sys
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
table = ddb.Table('${tableName}')
table.delete_item(Key=json.loads(sys.argv[1]))
`,
  );
  try {
    execSync(`python3 ${scriptPath} ${JSON.stringify(keyJson)}`, {
      cwd: REPO_ROOT,
      timeout: 10_000,
    });
  } catch {
    /* ignore cleanup errors */
  } finally {
    try {
      unlinkSync(scriptPath);
    } catch {
      /* ignore */
    }
  }
}

// ─── Test setup ───────────────────────────────────────────────────────────────

const nowTs = Math.floor(Date.now() / 1000);

// S3 key prefix for the seeded HLS manifests (served by the in-process moto
// mock through the backend's /mock/s3 proxy).
const MANIFEST_BUCKET = "local-uploads";
const aliceSubForKey = () => getSessions()[ALICE_ID].user_sub;
const manifestKeyPrefix = () =>
  `videos/${aliceSubForKey()}/${ENGAGE_VIDEO_ID}`;

test.beforeAll(() => {
  const aliceSub = getSessions()[ALICE_ID].user_sub;

  ddbPut(VIDEO_TABLE, {
    video_id: ENGAGE_VIDEO_ID,
    owner_user_id: aliceSub,
    title: `E2E Engagement Video ${TS}`,
    description: `Engagement-signal test video ${TS}`,
    status: "published",
    visibility: "private",
    created_at: nowTs - 3600,
    updated_at: nowTs - 1800,
    duration_seconds: 120,
    width: 1920,
    height: 1080,
    frame_rate: 30,
    video_codec: "h264",
    audio_codec: "aac",
    file_size_bytes: 52428800,
    // RELATIVE (same-origin) URL so the manifest is fetched through the Vite
    // proxy on :3000 (no cross-origin CORS rejection). hls.js fetches the
    // manifest from inside a blob-URL Web Worker, which Playwright's page.route
    // CANNOT intercept — so instead of stubbing the network we serve a real,
    // valid (empty-VOD) HLS manifest from the in-process moto S3 mock below.
    hls_manifest_url: `/mock/s3/${MANIFEST_BUCKET}/videos/${aliceSub}/${ENGAGE_VIDEO_ID}/master.m3u8`,
    source_type: "upload",
    renditions: [
      { label: "1080p", width: 1920, height: 1080, bitrate_kbps: 5000 },
    ],
  });
});

test.afterAll(() => {
  ddbDelete(VIDEO_TABLE, { video_id: ENGAGE_VIDEO_ID });
});

// ─── HLS manifest seeding ────────────────────────────────────────────────────
//
// The player's HLS manifest URL points at the in-process moto S3 mock served
// through the backend's `/mock/s3/{bucket}/{key}` proxy. We can't stub the
// network with `page.route`, because hls.js fetches the manifest from inside a
// blob-URL Web Worker which Playwright route interception does not see. Instead
// we PUT real, valid manifests into moto S3 so hls.js fires MANIFEST_PARSED and
// VideoPlayerPage mounts the `video-player` wrapper (with the <video> element).
//
// These tests never need real playback — they dispatch synthetic
// `ended` / `timeupdate` events — so the media playlist is a valid *empty* VOD
// playlist (no segments). That parses cleanly (player ready, no error) without
// triggering any segment-load MEDIA_ERROR that would unmount the wrapper.
//
// Idempotent + best-effort: seeding the same key twice is harmless.
async function seedHlsManifests(request: import("@playwright/test").APIRequestContext) {
  const MASTER =
    "#EXTM3U\n" +
    "#EXT-X-STREAM-INF:BANDWIDTH=5000000,RESOLUTION=1920x1080\n" +
    "media.m3u8\n";
  const MEDIA =
    "#EXTM3U\n" +
    "#EXT-X-VERSION:3\n" +
    "#EXT-X-TARGETDURATION:10\n" +
    "#EXT-X-MEDIA-SEQUENCE:0\n" +
    "#EXT-X-PLAYLIST-TYPE:VOD\n" +
    "#EXT-X-ENDLIST\n";
  const base = `http://localhost:8000/mock/s3/${MANIFEST_BUCKET}/${manifestKeyPrefix()}`;
  await request.put(`${base}/master.m3u8`, {
    headers: { "content-type": "application/vnd.apple.mpegurl" },
    data: MASTER,
  });
  await request.put(`${base}/media.m3u8`, {
    headers: { "content-type": "application/vnd.apple.mpegurl" },
    data: MEDIA,
  });
}

// ─── Section 160 ──────────────────────────────────────────────────────────────

test.describe("Section 160 · GAP-0160 engagement signals", () => {
  test("160.1 fires watch_pct=100 engagement signal when video ends", async ({ browser, request }) => {
    await seedHlsManifests(request);
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    // Player wrapper renders only when hls.js fires MANIFEST_PARSED. Under
    // full-suite load the first init can race the route stub / token fetch, so
    // retry the navigation until the wrapper mounts (no playerError).
    let playerVisible = false;
    for (let attempt = 0; attempt < 3 && !playerVisible; attempt++) {
      await page.goto(`${BASE}/videos/${ENGAGE_VIDEO_ID}`, { waitUntil: "domcontentloaded" });
      playerVisible = await page
        .getByTestId("video-player")
        .isVisible({ timeout: 10_000 })
        .catch(() => false);
    }
    await expect(page.getByTestId("video-player")).toBeVisible({ timeout: 10_000 });
    const video = page.getByTestId("media-player-video");
    await expect(video).toBeAttached();

    const engagementPromise = page.waitForRequest(
      (req) => req.url().includes(ENGAGEMENT_URL) && req.method() === "POST",
      { timeout: 10_000 },
    );

    // Simulate the video reaching its natural end.
    await page.evaluate(() => {
      const v = document.querySelector('[data-testid="media-player-video"]') as HTMLVideoElement | null;
      if (!v) throw new Error("video element not found");
      Object.defineProperty(v, "duration", { value: 120, configurable: true });
      Object.defineProperty(v, "currentTime", { value: 120, configurable: true });
      v.dispatchEvent(new Event("ended"));
    });

    const req = await engagementPromise;
    const body = req.postDataJSON();
    expect(body.video_id).toBe(ENGAGE_VIDEO_ID);
    expect(body.watch_pct).toBe(100);

    await ctx.close();
  });

  test("160.2 fires engagement signal at ~30% watch milestone", async ({ browser, request }) => {
    await seedHlsManifests(request);
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    // Player wrapper renders only when hls.js fires MANIFEST_PARSED. Under
    // load the first init can race the route stub / token fetch, so retry the
    // navigation until the wrapper mounts (no playerError) — same as 160.1.
    let playerVisible = false;
    for (let attempt = 0; attempt < 3 && !playerVisible; attempt++) {
      await page.goto(`${BASE}/videos/${ENGAGE_VIDEO_ID}`, { waitUntil: "domcontentloaded" });
      playerVisible = await page
        .getByTestId("video-player")
        .isVisible({ timeout: 10_000 })
        .catch(() => false);
    }
    await expect(page.getByTestId("video-player")).toBeVisible({ timeout: 10_000 });
    const video = page.getByTestId("media-player-video");
    await expect(video).toBeAttached();

    const engagementPromise = page.waitForRequest(
      (req) => req.url().includes(ENGAGEMENT_URL) && req.method() === "POST",
      { timeout: 10_000 },
    );

    // Simulate timeupdate crossing the 30% milestone (36s of a 120s video).
    await page.evaluate(() => {
      const v = document.querySelector('[data-testid="media-player-video"]') as HTMLVideoElement | null;
      if (!v) throw new Error("video element not found");
      Object.defineProperty(v, "duration", { value: 120, configurable: true });
      Object.defineProperty(v, "currentTime", { value: 36, configurable: true });
      v.dispatchEvent(new Event("timeupdate"));
    });

    const req = await engagementPromise;
    const body = req.postDataJSON();
    expect(body.video_id).toBe(ENGAGE_VIDEO_ID);
    expect(body.watch_pct).toBeGreaterThanOrEqual(30);

    await ctx.close();
  });
});
