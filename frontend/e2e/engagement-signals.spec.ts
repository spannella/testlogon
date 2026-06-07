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
import { join } from "path";

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
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
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
      cwd: "/home/ubuntu/testlogon",
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
      cwd: "/home/ubuntu/testlogon",
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
    hls_manifest_url: `http://localhost:8000/mock/s3/local-uploads/videos/${aliceSub}/${ENGAGE_VIDEO_ID}/master.m3u8`,
    source_type: "upload",
    renditions: [
      { label: "1080p", width: 1920, height: 1080, bitrate_kbps: 5000 },
    ],
  });
});

test.afterAll(() => {
  ddbDelete(VIDEO_TABLE, { video_id: ENGAGE_VIDEO_ID });
});

// ─── HLS stub ──────────────────────────────────────────────────────────────
//
// The mock S3 manifest URL (`/mock/s3/.../master.m3u8`) does not serve a real
// HLS stream, so hls.js raises a fatal `manifestLoadError` and VideoPlayerPage
// sets `playerError`, which unmounts the `video-player` wrapper (and the
// underlying <video> element). These tests don't need real playback — they
// dispatch synthetic `ended` / `timeupdate` events on the <video> — they only
// need the player wrapper to mount. Serving a minimal, valid VOD manifest makes
// hls.js fire MANIFEST_PARSED (player ready, no error) so the wrapper renders.
// Segment loads may 404, but a frag error is recoverable (hls.startLoad), not a
// `manifestLoadError`, so it never sets playerError.
async function stubHls(page: Page) {
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
    "#EXTINF:10.0,\n" +
    "seg0.ts\n" +
    "#EXT-X-ENDLIST\n";
  await page.route(/master\.m3u8(\?.*)?$/, (route) =>
    route.fulfill({ status: 200, contentType: "application/vnd.apple.mpegurl", body: MASTER }),
  );
  await page.route(/media\.m3u8(\?.*)?$/, (route) =>
    route.fulfill({ status: 200, contentType: "application/vnd.apple.mpegurl", body: MEDIA }),
  );
  await page.route(/seg\d+\.ts(\?.*)?$/, (route) =>
    route.fulfill({ status: 200, contentType: "video/mp2t", body: "" }),
  );
}

// ─── Section 160 ──────────────────────────────────────────────────────────────

test.describe("Section 160 · GAP-0160 engagement signals", () => {
  test("160.1 fires watch_pct=100 engagement signal when video ends", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await stubHls(page);
    await page.goto(`${BASE}/videos/${ENGAGE_VIDEO_ID}`, { waitUntil: "domcontentloaded" });

    // Player wrapper renders only when a playback URL is available.
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

  test("160.2 fires engagement signal at ~30% watch milestone", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await stubHls(page);
    await page.goto(`${BASE}/videos/${ENGAGE_VIDEO_ID}`, { waitUntil: "domcontentloaded" });

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
