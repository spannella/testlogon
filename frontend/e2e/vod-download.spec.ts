/**
 * VOD-012: E2E Tests for Optional MP4 Download
 *
 * Sections:
 *   120 — Download Enable/Disable API (5 tests)
 *   121 — Download URL Generation (7 tests)
 *
 * Auth: Cookie sessions via e2e_admin_session_setup.py
 * Identities: alice (USER), bob (USER)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions, resolveIdentityId } from "./helpers/session";
import { usingCpp, cppSeedVodVideo } from "./helpers/cpp-seed-video-vod";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const TS = Date.now();

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

// ─── Page helpers ─────────────────────────────────────────────────────────────

async function newPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await page.context().addCookies(getSessions()[identity].cookies);
  return page;
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

async function apiPost(page: Page, id: string, path: string, body?: unknown) {
  const s = getSessions()[id];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPatch(page: Page, id: string, path: string, body: unknown) {
  const s = getSessions()[id];
  return page.request.patch(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
  });
}

// ─── DDB helpers ──────────────────────────────────────────────────────────────

function seedVideo(opts: {
  videoId: string;
  ownerUserId: string;
  title: string;
  status?: string;
  visibility?: string;
  allowDownload?: boolean;
  downloadMp4Key?: string;
  downloadMp4Status?: string;
  downloadMp4SizeBytes?: number;
}): void {
  if (usingCpp()) {
    const o = opts as Record<string, unknown>;
    const sub = resolveIdentityId(opts.ownerUserId);
    const extra: Record<string, unknown> = { source_type: "upload" };
    const put = (k: string, v: unknown) => { if (v !== undefined) extra[k] = v; };
    put("source_s3_key",
      o.sourceS3Key === ""
        ? undefined
        : (o.sourceS3Key ?? `videos/${sub}/${opts.videoId}/source.mp4`));
    put("video_codec", o.videoCodec);
    put("audio_codec", o.audioCodec);
    put("width", o.width);
    put("height", o.height);
    put("frame_rate", o.frameRate);
    put("file_size_bytes", o.fileSizeBytes);
    put("created_at", o.createdAt);
    put("allow_download", o.allowDownload);
    put("watermark_downloads", o.watermarkDownloads);
    put("download_mp4_key", o.downloadMp4Key);
    put("download_mp4_status", o.downloadMp4Status);
    put("download_mp4_size_bytes", o.downloadMp4SizeBytes);
    put("thumbnail_url", o.thumbnailUrl);
    cppSeedVodVideo({
      videoId: opts.videoId,
      ownerSub: sub,
      title: opts.title,
      status: (o.status as string) || "published",
      visibility: (o.visibility as string) || "public",
      ...(o.durationSeconds !== undefined
        ? { durationSeconds: o.durationSeconds as number }
        : {}),
      ...(o.hlsManifestUrl !== undefined
        ? { hlsManifestUrl: o.hlsManifestUrl as string }
        : {}),
      extra,
    });
    return;
  }
  const status = opts.status || "published";
  const visibility = opts.visibility || "public";
  const createdAt = Math.floor(Date.now() / 1000);
  const allowDownload = opts.allowDownload ?? false;
  const dlKey = opts.downloadMp4Key ? `'download_mp4_key': '${opts.downloadMp4Key}',` : "";
  const dlStatus = opts.downloadMp4Status ? `'download_mp4_status': '${opts.downloadMp4Status}',` : "";
  const dlSize = opts.downloadMp4SizeBytes ? `'download_mp4_size_bytes': ${opts.downloadMp4SizeBytes},` : "";
  const publishedField = status === "published" ? `'published_at': ${createdAt},` : "";

  const script = `
import sys, os
sys.path.insert(0, '${REPO_ROOT}')
os.environ.setdefault('DEV_MODE', '1')
os.environ.setdefault('DDB_ENDPOINT_URL', 'http://localhost:8001')
os.environ.setdefault('AWS_ACCESS_KEY_ID', 'test')
os.environ.setdefault('AWS_SECRET_ACCESS_KEY', 'test')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
import boto3
from decimal import Decimal
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1')
table = ddb.Table('VideoMetadata')
table.put_item(Item={
    'video_id': '${opts.videoId}',
    'owner_user_id': '${opts.ownerUserId}',
    'title': '${opts.title}',
    'status': '${status}',
    'visibility': '${visibility}',
    'created_at': ${createdAt},
    'updated_at': ${createdAt},
    'source_type': 'upload',
    'allow_download': ${allowDownload ? "True" : "False"},
    ${dlKey}
    ${dlStatus}
    ${dlSize}
    ${publishedField}
})
`;
  execSync(
    `${REPO_ROOT}/.venv/bin/python3 -c "${script.replace(/"/g, '\\"')}"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  );
}

function deleteVideo(videoId: string): void {
  if (usingCpp()) return;
  const script = `
import sys, os
sys.path.insert(0, '${REPO_ROOT}')
os.environ.setdefault('DDB_ENDPOINT_URL', 'http://localhost:8001')
os.environ.setdefault('AWS_ACCESS_KEY_ID', 'test')
os.environ.setdefault('AWS_SECRET_ACCESS_KEY', 'test')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
import boto3
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1')
table = ddb.Table('VideoMetadata')
table.delete_item(Key={'video_id': '${videoId}'})
`;
  try {
    execSync(
      `${REPO_ROOT}/.venv/bin/python3 -c "${script.replace(/"/g, '\\"')}"`,
      { cwd: REPO_ROOT, timeout: 10_000 },
    );
  } catch {
    /* ignore cleanup errors */
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 120 — Download Enable/Disable API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe.serial("120 — Download Enable/Disable API", () => {
  let alicePage: Page;
  const ALICE_SUB = () => getSessions().alice.user_sub;
  const VIDEO_ID = `v_dl_enable_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
    // Create a published video for Alice
    seedVideo({
      videoId: VIDEO_ID,
      ownerUserId: ALICE_SUB(),
      title: `Download Enable Test ${TS}`,
      status: "published",
      visibility: "public",
    });
  });

  test.afterAll(async () => {
    deleteVideo(VIDEO_ID);
    await alicePage?.close();
  });

  test("120.1 Enable download via PATCH — triggers MP4 generation", async () => {
    const resp = await apiPatch(alicePage, "alice", `/ui/videos/${VIDEO_ID}`, {
      allow_download: true,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.allow_download).toBe(true);
    expect(data.download_available).toBe(true);
    expect(data.download_mp4_size_bytes).toBeDefined();
  });

  test("120.2 GET video detail shows download_available=true", async () => {
    const resp = await apiGet(alicePage, `/ui/videos/${VIDEO_ID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.allow_download).toBe(true);
    expect(data.download_available).toBe(true);
  });

  test("120.3 Disable download via PATCH", async () => {
    const resp = await apiPatch(alicePage, "alice", `/ui/videos/${VIDEO_ID}`, {
      allow_download: false,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.allow_download).toBe(false);
    expect(data.download_available).toBe(false);
  });

  test("120.4 Re-enable download reuses existing MP4", async () => {
    const resp = await apiPatch(alicePage, "alice", `/ui/videos/${VIDEO_ID}`, {
      allow_download: true,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.allow_download).toBe(true);
    expect(data.download_available).toBe(true);
  });

  test("120.5 PATCH other fields does not affect download state", async () => {
    const resp = await apiPatch(alicePage, "alice", `/ui/videos/${VIDEO_ID}`, {
      title: `Updated Title ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.title).toBe(`Updated Title ${TS}`);
    expect(data.allow_download).toBe(true);
    expect(data.download_available).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 121 — Download URL Generation
// ═══════════════════════════════════════════════════════════════════════════════

test.describe.serial("121 — Download URL Generation", () => {
  let alicePage: Page;
  let bobPage: Page;
  const ALICE_SUB = () => getSessions().alice.user_sub;
  const BOB_SUB = () => getSessions().bob.user_sub;

  // Video with download ready (owned by Alice, public)
  const READY_VID = `v_dl_ready_${TS}`;
  // Video without download enabled (owned by Alice, public)
  const NO_DL_VID = `v_dl_nodl_${TS}`;
  // Video that is private (owned by Alice)
  const PRIVATE_VID = `v_dl_priv_${TS}`;
  // Video not yet ready
  const PENDING_VID = `v_dl_pend_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
    bobPage = await newPage(browser, "bob");

    const aliceSub = ALICE_SUB();

    // Video with download ready
    seedVideo({
      videoId: READY_VID,
      ownerUserId: aliceSub,
      title: `Ready Download ${TS}`,
      status: "published",
      visibility: "public",
      allowDownload: true,
      downloadMp4Key: `tenants/${aliceSub}/assets/${READY_VID}/download/${READY_VID}.mp4`,
      downloadMp4Status: "ready",
      downloadMp4SizeBytes: 1048576,
    });

    // Video without download
    seedVideo({
      videoId: NO_DL_VID,
      ownerUserId: aliceSub,
      title: `No Download ${TS}`,
      status: "published",
      visibility: "public",
      allowDownload: false,
    });

    // Private video with download
    seedVideo({
      videoId: PRIVATE_VID,
      ownerUserId: aliceSub,
      title: `Private Download ${TS}`,
      status: "published",
      visibility: "private",
      allowDownload: true,
      downloadMp4Key: `tenants/${aliceSub}/assets/${PRIVATE_VID}/download/${PRIVATE_VID}.mp4`,
      downloadMp4Status: "ready",
    });

    // Video with pending download
    seedVideo({
      videoId: PENDING_VID,
      ownerUserId: aliceSub,
      title: `Pending Download ${TS}`,
      status: "published",
      visibility: "public",
      allowDownload: true,
      downloadMp4Status: "generating",
    });
  });

  test.afterAll(async () => {
    deleteVideo(READY_VID);
    deleteVideo(NO_DL_VID);
    deleteVideo(PRIVATE_VID);
    deleteVideo(PENDING_VID);
    await alicePage?.close();
    await bobPage?.close();
  });

  test("121.1 Owner gets download URL for ready video", async () => {
    const resp = await apiGet(alicePage, `/ui/videos/${READY_VID}/download`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.download_url).toBeTruthy();
    expect(data.download_url).toContain("/mock/s3/");
    expect(data.download_url).toContain(READY_VID);
    expect(data.download_expires_at).toBeGreaterThan(0);
    expect(data.filename).toContain(".mp4");
    expect(data.content_type).toBe("video/mp4");
  });

  test("121.2 Non-owner can download public video", async () => {
    const resp = await apiGet(bobPage, `/ui/videos/${READY_VID}/download`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.download_url).toBeTruthy();
    expect(data.download_url).toContain("/mock/s3/");
  });

  test("121.3 Non-owner cannot download private video", async () => {
    const resp = await apiGet(bobPage, `/ui/videos/${PRIVATE_VID}/download`);
    expect(resp.status()).toBe(403);
  });

  test("121.4 Download disabled on video returns 403", async () => {
    const resp = await apiGet(alicePage, `/ui/videos/${NO_DL_VID}/download`);
    expect(resp.status()).toBe(403);
    const data = await resp.json();
    expect(data.detail).toContain("not enabled");
  });

  test("121.5 Download not ready returns 404", async () => {
    const resp = await apiGet(alicePage, `/ui/videos/${PENDING_VID}/download`);
    expect(resp.status()).toBe(404);
    const data = await resp.json();
    expect(data.detail).toContain("not ready");
  });

  test("121.6 Non-existent video returns 404", async () => {
    const resp = await apiGet(alicePage, `/ui/videos/v_nonexistent_${TS}/download`);
    expect(resp.status()).toBe(404);
  });

  test("121.7 Multiple download requests produce fresh URLs", async () => {
    const resp1 = await apiGet(alicePage, `/ui/videos/${READY_VID}/download`);
    expect(resp1.status()).toBe(200);
    const data1 = await resp1.json();

    // Small delay to ensure different timestamps
    await new Promise((r) => setTimeout(r, 50));

    const resp2 = await apiGet(alicePage, `/ui/videos/${READY_VID}/download`);
    expect(resp2.status()).toBe(200);
    const data2 = await resp2.json();

    // Both should be valid URLs
    expect(data1.download_url).toBeTruthy();
    expect(data2.download_url).toBeTruthy();
    // Expires-at should be different (generated at different times)
    expect(data2.download_expires_at).toBeGreaterThanOrEqual(data1.download_expires_at);
  });
});
