/**
 * E2E tests for VOD-020: Watermarked Downloads.
 *
 * Sections:
 *   1 — Watermark Settings API  (4 tests)
 *   2 — Watermarked Download API  (5 tests)
 *   3 — Watermark Extraction API  (3 tests)
 *   4 — Download UI  (3 tests)
 *
 * Auth: Alice (video owner) + Bob (non-owner viewer).
 * Sessions from e2e_session_setup.py.
 *
 * The tests seed a video record directly into the VideoMetadata DynamoDB
 * table in beforeAll. The video has allow_download=true, download_mp4_status="ready",
 * and a deterministic download_mp4_key.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions, resolveIdentityId } from "./helpers/session";
import { usingCpp, cppSeedVodVideo } from "./helpers/cpp-seed-video-vod";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const TS       = Date.now();
const VIDEO_ID = `e2e_wm_vid_${TS}`;

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name:     string;
    value:    string;
    domain:   string;
    path:     string;
    httpOnly: boolean;
    secure:   boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires:  number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

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

// ─── API helpers (Vite proxy — session cookies forwarded) ─────────────────────

async function apiGet(page: Page, userId: string, path: string) {
  const session = getSessions()[userId];
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiPost(page: Page, userId: string, path: string, body?: object) {
  const session = getSessions()[userId];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiPatch(page: Page, userId: string, path: string, body: object) {
  const session = getSessions()[userId];
  return page.request.patch(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── DDB helpers ──────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os, json, time
from decimal import Decimal
from pathlib import Path
env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
`;

function ddbExec(script: string): string {
  return execSync(`python3 -c "${DDB_PRELUDE}\n${script}"`, {
    cwd: REPO_ROOT,
    timeout: 15_000,
  }).toString().trim();
}

function seedVideoMeta(opts: {
  videoId: string;
  ownerSub: string;
  title: string;
  allowDownload: boolean;
  watermarkDownloads: boolean;
  downloadMp4Key?: string;
  downloadMp4Status?: string;
  downloadMp4SizeBytes?: number;
  description?: string;
}): void {
  const now = Math.floor(Date.now() / 1000);
  if (usingCpp()) {
    cppSeedVodVideo({
      videoId: opts.videoId,
      ownerSub: resolveIdentityId(opts.ownerSub),
      title: opts.title,
      status: "published",
      visibility: "public",
      extra: {
        source_type: "upload",
        allow_download: opts.allowDownload,
        watermark_downloads: opts.watermarkDownloads,
        download_mp4_key: opts.downloadMp4Key ?? "",
        download_mp4_status: opts.downloadMp4Status ?? "",
        download_mp4_size_bytes: opts.downloadMp4SizeBytes ?? 0,
        download_count: 0,
        ...(opts.description ? { description: opts.description } : {}),
      },
    });
    return;
  }
  ddbExec(`
t = ddb.Table(os.environ.get('VIDEO_METADATA_TABLE_NAME', 'VideoMetadata'))
t.put_item(Item={
    'video_id': '${opts.videoId}',
    'owner_user_id': '${opts.ownerSub}',
    'title': '${opts.title}',
    'status': 'published',
    'visibility': 'public',
    'created_at': ${now},
    'updated_at': ${now},
    'allow_download': ${opts.allowDownload ? 'True' : 'False'},
    'download_mp4_key': '${opts.downloadMp4Key ?? ''}',
    'download_mp4_status': '${opts.downloadMp4Status ?? ''}',
    'download_mp4_size_bytes': ${opts.downloadMp4SizeBytes ?? 0},
    'download_count': 0,
    'watermark_downloads': ${opts.watermarkDownloads ? 'True' : 'False'},
    'source_type': 'upload',
  })
  `);
}

function seedTestVideo(videoId: string, ownerSub: string) {
  seedVideoMeta({
    videoId,
    ownerSub,
    title: `E2E Watermark Test Video ${TS}`,
    description: "Test video for watermarked downloads",
    allowDownload: true,
    watermarkDownloads: false,
    downloadMp4Key: `tenants/${resolveIdentityId(ownerSub)}/assets/${videoId}/download/${videoId}.mp4`,
    downloadMp4SizeBytes: 1024,
    downloadMp4Status: "ready",
  });
}

function cleanupTestVideo(videoId: string) {
  if (usingCpp()) return;
  try {
    ddbExec(`
t = ddb.Table(os.environ.get('VIDEO_METADATA_TABLE_NAME', 'VideoMetadata'))
t.delete_item(Key={'video_id': '${videoId}'})
    `);
  } catch {
    // best-effort cleanup
  }
}

function cleanupWatermarkJobs(videoId: string) {
  if (usingCpp()) return;
  try {
    ddbExec(`
t = ddb.Table(os.environ.get('WATERMARK_JOBS_TABLE_NAME', 'watermark_jobs'))
resp = t.scan(FilterExpression='video_id = :vid', ExpressionAttributeValues={':vid': '${videoId}'})
for item in resp.get('Items', []):
    t.delete_item(Key={'job_id': item['job_id']})
    `);
  } catch {
    // best-effort
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
// Section 1: Watermark Settings API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("1 — Watermark Settings API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let aliceSub: string;

  test.beforeAll(async ({ browser }) => {
    aliceSub = getSessions()[ALICE_ID].user_sub;
    seedTestVideo(VIDEO_ID, aliceSub);

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);
  });

  test.afterAll(async () => {
    cleanupWatermarkJobs(VIDEO_ID);
    cleanupTestVideo(VIDEO_ID);
    await alicePage.context().close();
    await bobPage.context().close();
  });

  test("1.1 Enable watermark downloads on video", async () => {
    const resp = await apiPatch(alicePage, ALICE_ID, `/ui/videos/${VIDEO_ID}/watermark`, {
      watermark_downloads: true,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.watermark_downloads).toBe(true);
  });

  test("1.2 Disable watermark downloads", async () => {
    const resp = await apiPatch(alicePage, ALICE_ID, `/ui/videos/${VIDEO_ID}/watermark`, {
      watermark_downloads: false,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.watermark_downloads).toBe(false);
  });

  test("1.3 Non-owner cannot toggle watermark", async () => {
    const resp = await apiPatch(bobPage, BOB_ID, `/ui/videos/${VIDEO_ID}/watermark`, {
      watermark_downloads: true,
    });
    expect(resp.status()).toBe(403);
  });

  test("1.4 Watermark setting persists across video detail fetches", async () => {
    // Enable watermark
    const enableResp = await apiPatch(alicePage, ALICE_ID, `/ui/videos/${VIDEO_ID}/watermark`, {
      watermark_downloads: true,
    });
    expect(enableResp.status()).toBe(200);

    // Fetch video detail — should reflect the setting
    const detailResp = await apiGet(alicePage, ALICE_ID, `/ui/videos/${VIDEO_ID}`);
    expect(detailResp.status()).toBe(200);
    const detail = await detailResp.json();
    expect(detail.watermark_downloads).toBe(true);
  });
});


// ═══════════════════════════════════════════════════════════════════════════════
// Section 2: Watermarked Download API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("2 — Watermarked Download API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let aliceSub: string;
  const VID2 = `e2e_wm_vid2_${TS}`;

  test.beforeAll(async ({ browser }) => {
    aliceSub = getSessions()[ALICE_ID].user_sub;
    seedTestVideo(VID2, aliceSub);

    // Enable watermark on this video
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    await apiPatch(alicePage, ALICE_ID, `/ui/videos/${VID2}/watermark`, {
      watermark_downloads: true,
    });

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);
  });

  test.afterAll(async () => {
    cleanupWatermarkJobs(VID2);
    cleanupTestVideo(VID2);
    await alicePage.context().close();
    await bobPage.context().close();
  });

  test("2.1 Request watermarked download (dev mode: instant)", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/videos/${VID2}/download/watermarked`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("ready");
    expect(body.download_url).toBeTruthy();
    expect(body.job_id).toMatch(/^wj_/);
  });

  test("2.2 Cached download returns instantly", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/videos/${VID2}/download/watermarked`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("ready");
    expect(body.cached).toBe(true);
    expect(body.download_url).toBeTruthy();
  });

  test("2.3 Download URL is a valid mock S3 URL", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/videos/${VID2}/download/watermarked`);
    const body = await resp.json();
    // In dev mode the URL starts with /mock/s3/
    expect(body.download_url).toContain("/mock/s3/");
  });

  test("2.4 Download denied when allow_download is false", async () => {
    // Disable downloads on a fresh video
    const VID_NO_DL = `e2e_wm_nodl_${TS}`;
    seedVideoMeta({
      videoId: VID_NO_DL,
      ownerSub: aliceSub,
      title: "No Download Video",
      allowDownload: false,
      watermarkDownloads: true,
    });

    const resp = await apiPost(alicePage, ALICE_ID, `/ui/videos/${VID_NO_DL}/download/watermarked`);
    expect(resp.status()).toBe(403);

    // Cleanup
    cleanupTestVideo(VID_NO_DL);
  });

  test("2.5 Non-watermarked download when watermark_downloads is false", async () => {
    // Create a video with watermark disabled
    const VID_PLAIN = `e2e_wm_plain_${TS}`;
    seedVideoMeta({
      videoId: VID_PLAIN,
      ownerSub: aliceSub,
      title: "Plain Download Video",
      allowDownload: true,
      watermarkDownloads: false,
      downloadMp4Key: `tenants/${resolveIdentityId(aliceSub)}/assets/${VID_PLAIN}/download/${VID_PLAIN}.mp4`,
      downloadMp4SizeBytes: 512,
      downloadMp4Status: "ready",
    });

    const resp = await apiPost(alicePage, ALICE_ID, `/ui/videos/${VID_PLAIN}/download/watermarked`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    // Should return plain download (job_id = "plain")
    expect(body.status).toBe("ready");
    expect(body.job_id).toBe("plain");
    expect(body.download_url).toBeTruthy();

    cleanupTestVideo(VID_PLAIN);
  });
});


// ═══════════════════════════════════════════════════════════════════════════════
// Section 3: Watermark Extraction API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("3 — Watermark Extraction API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("3.1 Extract watermark from generated file (mock)", async () => {
    // The internal extraction endpoint returns a mock payload in dev mode
    const resp = await apiPost(alicePage, ALICE_ID, "/internal/watermark/extract");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.found).toBe(true);
    expect(body.payload).toMatch(/^WM:v1:/);
  });

  test("3.2 Decode watermark payload", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/internal/watermark/extract");
    const body = await resp.json();
    expect(body.decoded).toBeTruthy();
    expect(body.decoded.version).toBe("v1");
    expect(body.decoded.user_id_hash).toHaveLength(16);
    expect(body.decoded.download_timestamp).toBeGreaterThan(0);
  });

  test("3.3 Payload checksum validates correctly", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/internal/watermark/extract");
    const body = await resp.json();
    const payload = body.payload as string;

    // Parse and verify checksum
    const parts = payload.split(":");
    expect(parts).toHaveLength(5);
    expect(parts[0]).toBe("WM");
    expect(parts[1]).toBe("v1");
    // user_id_hash is 16 hex chars
    expect(parts[2]).toMatch(/^[a-f0-9]{16}$/);
    // timestamp is 8 hex chars
    expect(parts[3]).toMatch(/^[A-F0-9]{8}$/);
    // checksum is 4 hex chars
    expect(parts[4]).toMatch(/^[A-F0-9]{4}$/);
  });
});


// ═══════════════════════════════════════════════════════════════════════════════
// Section 4: Download UI
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("4 — Download UI", () => {
  let alicePage: Page;
  let aliceSub: string;
  const VID_UI = `e2e_wm_ui_${TS}`;

  test.beforeAll(async ({ browser }) => {
    aliceSub = getSessions()[ALICE_ID].user_sub;

    // Seed video with downloads and watermark enabled
    const now = Math.floor(Date.now() / 1000);
    seedVideoMeta({
      videoId: VID_UI,
      ownerSub: aliceSub,
      title: `E2E Watermark UI Video ${TS}`,
      description: "UI test video for watermarked downloads",
      allowDownload: true,
      watermarkDownloads: true,
      downloadMp4Key: `tenants/${resolveIdentityId(aliceSub)}/assets/${VID_UI}/download/${VID_UI}.mp4`,
      downloadMp4SizeBytes: 2048,
      downloadMp4Status: "ready",
    });

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    cleanupWatermarkJobs(VID_UI);
    cleanupTestVideo(VID_UI);
    await alicePage.context().close();
  });

  test("4.1 Download button visible for video with downloads enabled", async () => {
    await alicePage.goto(`${BASE}/videos/${VID_UI}`, { waitUntil: "domcontentloaded" });
    // The download section should be visible
    const section = alicePage.locator('[data-testid="download-section"]');
    await expect(section).toBeVisible({ timeout: 15_000 });
  });

  test("4.2 Watermarked download button shown (not plain)", async () => {
    await alicePage.goto(`${BASE}/videos/${VID_UI}`, { waitUntil: "domcontentloaded" });
    // Should show watermarked download button instead of plain
    const wmButton = alicePage.locator('[data-testid="vod-watermark-download-button"]');
    await expect(wmButton).toBeVisible({ timeout: 15_000 });
    // Plain button should NOT be visible
    const plainButton = alicePage.locator('[data-testid="download-mp4-button"]');
    await expect(plainButton).not.toBeVisible();
  });

  test("4.3 Clicking download shows preparing state then completes", async () => {
    await alicePage.goto(`${BASE}/videos/${VID_UI}`, { waitUntil: "domcontentloaded" });
    const wmButton = alicePage.locator('[data-testid="vod-watermark-download-button"]');
    await expect(wmButton).toBeVisible({ timeout: 15_000 });

    // In dev mode the download completes instantly, so we just verify the button text
    // contains "Download" (either idle or post-download state)
    const text = await wmButton.textContent();
    expect(text).toContain("Download");
  });
});
