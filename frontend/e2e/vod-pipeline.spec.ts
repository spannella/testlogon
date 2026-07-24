/**
 * VOD-011: E2E Tests for Video Upload and Playback Pipeline
 *
 * Sections:
 *   110 — Full Pipeline Happy Path (5 tests)
 *   111 — Upload Error Paths (4 tests)
 *   112 — Video Management (5 tests)
 *   113 — Public Discovery (4 tests)
 *   114 — Playback Entitlements (4 tests)
 *   115 — Admin Operations (3 tests)
 *
 * Auth: Cookie sessions via e2e_admin_session_setup.py
 * Identities: alice (USER), bob (USER), root (ROOT)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const TS = Date.now();
const VIDEO_TABLE = "VideoMetadata";

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

async function apiDelete(page: Page, id: string, path: string) {
  const s = getSessions()[id];
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": s.csrf_token },
  });
}

// ─── DDB helpers ──────────────────────────────────────────────────────────────

function seedVideo(opts: {
  videoId: string;
  ownerUserId: string;
  title: string;
  status?: string;
  visibility?: string;
  createdAt?: number;
  hlsManifestUrl?: string;
  durationSeconds?: number;
  width?: number;
  height?: number;
}): void {
  const status = opts.status || "created";
  const visibility = opts.visibility || "private";
  const createdAt = opts.createdAt || Math.floor(Date.now() / 1000);
  const hlsField = opts.hlsManifestUrl
    ? `'hls_manifest_url': '${opts.hlsManifestUrl}',`
    : "";
  const publishedField = status === "published" ? `'published_at': ${createdAt},` : "";
  const durationField = opts.durationSeconds
    ? `'duration_seconds': Decimal('${opts.durationSeconds}'),`
    : "";
  const widthField = opts.width ? `'width': ${opts.width},` : "";
  const heightField = opts.height ? `'height': ${opts.height},` : "";

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
    ${hlsField}
    ${publishedField}
    ${durationField}
    ${widthField}
    ${heightField}
})
`;
  execSync(
    `${REPO_ROOT}/.venv/bin/python3 -c "${script.replace(/"/g, '\\"')}"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  );
}

function deleteVideo(videoId: string): void {
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
// Section 110 — Full Pipeline Happy Path
// ═══════════════════════════════════════════════════════════════════════════════

test.describe.serial("110 — Full Pipeline Happy Path", () => {
  let alicePage: Page;
  let videoId: string;
  let presignedUrl: string;
  let s3Key: string;
  const ALICE_SUB = () => getSessions().alice.user_sub;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
  });

  test.afterAll(async () => {
    if (videoId) {
      deleteVideo(videoId);
    }
    await alicePage?.close();
  });

  test("110.1 Presign upload returns valid URL and ticket", async () => {
    const resp = await apiPost(alicePage, "alice", "/ui/videos/upload/presign", {
      filename: `pipeline_test_${TS}.mp4`,
      content_type: "video/mp4",
      size_bytes: 1024 * 512, // 512 KB
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_id).toBeTruthy();
    expect(data.video_id).toMatch(/^v_/);
    expect(data.presigned_url).toBeTruthy();
    expect(data.s3_key).toContain(`pipeline_test_${TS}.mp4`);
    expect(data.expires_in_seconds).toBeGreaterThan(0);
    videoId = data.video_id;
    presignedUrl = data.presigned_url;
    s3Key = data.s3_key;
  });

  test("110.2 PUT to presigned URL succeeds with video content", async () => {
    // Minimal valid MP4 header (ftyp box) + padding
    const fakeVideo = Buffer.alloc(512, 0x00);
    // Write ftyp box header: size (32) + 'ftyp' + 'isom' + version
    fakeVideo.writeUInt32BE(32, 0);
    fakeVideo.write("ftypisom", 4, "ascii");
    fakeVideo.writeUInt32BE(0x00000200, 12);
    fakeVideo.write("isomiso2mp41", 16, "ascii");

    const uploadResp = await alicePage.request.put(presignedUrl, {
      headers: { "Content-Type": "video/mp4" },
      data: fakeVideo,
    });
    // moto S3 mock accepts any PUT to the presigned URL
    expect(uploadResp.status()).toBeLessThan(400);
  });

  test("110.3 Complete upload creates video with status upload_complete", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/videos/${videoId}/upload/complete`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_id).toBe(videoId);
    expect(data.status).toBe("upload_complete");
  });

  test("110.4 Video appears in user's listing after creation", async () => {
    const resp = await apiGet(alicePage, "/ui/videos");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeInstanceOf(Array);
    const found = data.items.find(
      (v: { video_id: string }) => v.video_id === videoId,
    );
    expect(found).toBeTruthy();
    expect(found.title).toContain(`pipeline_test_${TS}`);
  });

  test("110.5 Video detail endpoint returns all metadata fields", async () => {
    const resp = await apiGet(alicePage, `/ui/videos/${videoId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_id).toBe(videoId);
    expect(data.owner_user_id).toBe(ALICE_SUB());
    expect(data.title).toContain(`pipeline_test_${TS}`);
    expect(data.status).toBeTruthy();
    expect(data.visibility).toBe("private");
    expect(data.created_at).toBeGreaterThan(0);
    expect(data.updated_at).toBeGreaterThan(0);
    // These optional fields should exist in the response shape (even if null)
    expect(data).toHaveProperty("description");
    expect(data).toHaveProperty("duration_seconds");
    expect(data).toHaveProperty("width");
    expect(data).toHaveProperty("height");
    expect(data).toHaveProperty("hls_manifest_url");
    expect(data).toHaveProperty("renditions");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 111 — Upload Error Paths
// ═══════════════════════════════════════════════════════════════════════════════

test.describe.serial("111 — Upload Error Paths", () => {
  let alicePage: Page;
  const createdVideoIds: string[] = [];

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
  });

  test.afterAll(async () => {
    for (const vid of createdVideoIds) {
      deleteVideo(vid);
    }
    await alicePage?.close();
  });

  test("111.1 Invalid content_type (not video/*) returns 422", async () => {
    const resp = await apiPost(alicePage, "alice", "/ui/videos/upload/presign", {
      filename: `bad_type_${TS}.txt`,
      content_type: "text/plain",
      size_bytes: 1024,
    });
    expect(resp.status()).toBe(422);
    const data = await resp.json();
    expect(data.detail).toContain("Invalid content type");
  });

  test("111.2 Presign with file_size_bytes exceeding limit returns 422", async () => {
    // MAX_SIZE_BYTES is 10 GB (10 * 1024 * 1024 * 1024)
    const resp = await apiPost(alicePage, "alice", "/ui/videos/upload/presign", {
      filename: `too_big_${TS}.mp4`,
      content_type: "video/mp4",
      size_bytes: 11 * 1024 * 1024 * 1024, // 11 GB, exceeds 10 GB limit
    });
    // Pydantic validation returns 422 for value > le constraint
    expect(resp.status()).toBe(422);
  });

  test("111.3 Complete with invalid video_id returns 404", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      `/ui/videos/v_nonexistent_${TS}/upload/complete`,
    );
    expect(resp.status()).toBe(404);
  });

  test("111.4 Complete with already-completed video returns 409", async () => {
    // Create a video via presign first
    const presignResp = await apiPost(alicePage, "alice", "/ui/videos/upload/presign", {
      filename: `double_complete_${TS}.mp4`,
      content_type: "video/mp4",
      size_bytes: 256,
    });
    expect(presignResp.status()).toBe(200);
    const presign = await presignResp.json();
    const vid = presign.video_id;
    createdVideoIds.push(vid);

    // Upload content
    const fakeContent = Buffer.alloc(256, 0x42);
    await alicePage.request.put(presign.presigned_url, {
      headers: { "Content-Type": "video/mp4" },
      data: fakeContent,
    });

    // First complete should succeed
    const firstComplete = await apiPost(alicePage, "alice", `/ui/videos/${vid}/upload/complete`);
    expect(firstComplete.status()).toBe(200);

    // Second complete should return 409 (status is no longer "created")
    const secondComplete = await apiPost(alicePage, "alice", `/ui/videos/${vid}/upload/complete`);
    expect(secondComplete.status()).toBe(409);
    const data = await secondComplete.json();
    expect(data.detail).toContain("expected 'created'");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 112 — Video Management
// ═══════════════════════════════════════════════════════════════════════════════

test.describe.serial("112 — Video Management", () => {
  let alicePage: Page;
  let bobPage: Page;
  const MANAGE_VIDEO = `v_mgmt_${TS}`;
  const DELETE_VIDEO = `v_mgmt_del_${TS}`;
  const ALICE_SUB = () => getSessions().alice.user_sub;
  const BOB_SUB = () => getSessions().bob.user_sub;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
    bobPage = await newPage(browser, "bob");

    // Seed videos for management tests
    seedVideo({
      videoId: MANAGE_VIDEO,
      ownerUserId: ALICE_SUB(),
      title: `Management Test ${TS}`,
      status: "published",
      visibility: "private",
      durationSeconds: 60,
      width: 1920,
      height: 1080,
      hlsManifestUrl: `http://localhost:8000/mock/s3/local-uploads/videos/${ALICE_SUB()}/${MANAGE_VIDEO}/master.m3u8`,
    });

    seedVideo({
      videoId: DELETE_VIDEO,
      ownerUserId: ALICE_SUB(),
      title: `Delete Test ${TS}`,
      status: "published",
      visibility: "public",
    });
  });

  test.afterAll(async () => {
    deleteVideo(MANAGE_VIDEO);
    deleteVideo(DELETE_VIDEO);
    await alicePage?.close();
    await bobPage?.close();
  });

  test("112.1 PATCH updates title successfully", async () => {
    const newTitle = `Updated Title ${TS}`;
    const resp = await apiPatch(alicePage, "alice", `/ui/videos/${MANAGE_VIDEO}`, {
      title: newTitle,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.title).toBe(newTitle);
    expect(data.video_id).toBe(MANAGE_VIDEO);
  });

  test("112.2 PATCH updates visibility", async () => {
    const resp = await apiPatch(alicePage, "alice", `/ui/videos/${MANAGE_VIDEO}`, {
      visibility: "public",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.visibility).toBe("public");
  });

  test("112.3 DELETE soft-deletes (video no longer in listing)", async () => {
    const resp = await apiDelete(alicePage, "alice", `/ui/videos/${DELETE_VIDEO}`);
    expect(resp.status()).toBe(204);

    // Verify it no longer appears in the owner's listing
    const listResp = await apiGet(alicePage, "/ui/videos");
    expect(listResp.status()).toBe(200);
    const listData = await listResp.json();
    const found = listData.items.find(
      (v: { video_id: string }) => v.video_id === DELETE_VIDEO,
    );
    expect(found).toBeUndefined();
  });

  test("112.4 GET deleted video by owner still returns details (with deleted status)", async () => {
    // Owner can still access the deleted video's detail
    const resp = await apiGet(alicePage, `/ui/videos/${DELETE_VIDEO}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_id).toBe(DELETE_VIDEO);
    expect(data.status).toBe("deleted");
  });

  test("112.5 Non-owner cannot PATCH or DELETE (403)", async () => {
    const patchResp = await apiPatch(bobPage, "bob", `/ui/videos/${MANAGE_VIDEO}`, {
      title: "Hacked by Bob",
    });
    expect(patchResp.status()).toBe(403);

    const deleteResp = await apiDelete(bobPage, "bob", `/ui/videos/${MANAGE_VIDEO}`);
    expect(deleteResp.status()).toBe(403);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 113 — Public Discovery
// ═══════════════════════════════════════════════════════════════════════════════

test.describe.serial("113 — Public Discovery", () => {
  let alicePage: Page;
  let bobPage: Page;
  const PUB_VIDEO = `v_disc_pub_${TS}`;
  const PRIV_VIDEO = `v_disc_priv_${TS}`;
  const ALICE_SUB = () => getSessions().alice.user_sub;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
    bobPage = await newPage(browser, "bob");

    // Alice: one published+public, one published+private
    seedVideo({
      videoId: PUB_VIDEO,
      ownerUserId: ALICE_SUB(),
      title: `Public Discovery ${TS}`,
      status: "published",
      visibility: "public",
      durationSeconds: 45,
      width: 1280,
      height: 720,
      hlsManifestUrl: `http://localhost:8000/mock/s3/local-uploads/videos/${ALICE_SUB()}/${PUB_VIDEO}/master.m3u8`,
    });

    seedVideo({
      videoId: PRIV_VIDEO,
      ownerUserId: ALICE_SUB(),
      title: `Private Discovery ${TS}`,
      status: "published",
      visibility: "private",
      durationSeconds: 30,
      width: 1920,
      height: 1080,
    });
  });

  test.afterAll(async () => {
    deleteVideo(PUB_VIDEO);
    deleteVideo(PRIV_VIDEO);
    await alicePage?.close();
    await bobPage?.close();
  });

  test("113.1 Published+public video appears in /ui/videos/public listing", async () => {
    const resp = await apiGet(bobPage, "/ui/videos/public");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find(
      (v: { video_id: string }) => v.video_id === PUB_VIDEO,
    );
    expect(found).toBeTruthy();
    expect(found.title).toBe(`Public Discovery ${TS}`);
    expect(found.visibility).toBe("public");
  });

  test("113.2 Private video does NOT appear in public listing", async () => {
    const resp = await apiGet(bobPage, "/ui/videos/public");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find(
      (v: { video_id: string }) => v.video_id === PRIV_VIDEO,
    );
    expect(found).toBeUndefined();
  });

  test("113.3 Non-owner can GET published+public video detail", async () => {
    const resp = await apiGet(bobPage, `/ui/videos/${PUB_VIDEO}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_id).toBe(PUB_VIDEO);
    expect(data.title).toBe(`Public Discovery ${TS}`);
    expect(data.owner_user_id).toBe(ALICE_SUB());
  });

  test("113.4 Non-owner cannot GET private video (403)", async () => {
    const resp = await apiGet(bobPage, `/ui/videos/${PRIV_VIDEO}`);
    expect(resp.status()).toBe(403);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 114 — Playback Entitlements
// ═══════════════════════════════════════════════════════════════════════════════

test.describe.serial("114 — Playback Entitlements", () => {
  let alicePage: Page;
  const PUB_HLS_VIDEO = `v_ent_pub_${TS}`;
  const PROCESSING_VIDEO = `v_ent_proc_${TS}`;
  const ALICE_SUB = () => getSessions().alice.user_sub;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");

    // Published video with HLS manifest (should get playback token)
    seedVideo({
      videoId: PUB_HLS_VIDEO,
      ownerUserId: ALICE_SUB(),
      title: `Entitlement Published ${TS}`,
      status: "published",
      visibility: "public",
      durationSeconds: 120,
      width: 1920,
      height: 1080,
      hlsManifestUrl: `http://localhost:8000/mock/s3/local-uploads/videos/${ALICE_SUB()}/${PUB_HLS_VIDEO}/master.m3u8`,
    });

    // Video still processing (should NOT get playback token)
    seedVideo({
      videoId: PROCESSING_VIDEO,
      ownerUserId: ALICE_SUB(),
      title: `Entitlement Processing ${TS}`,
      status: "encoding",
      visibility: "private",
    });
  });

  test.afterAll(async () => {
    deleteVideo(PUB_HLS_VIDEO);
    deleteVideo(PROCESSING_VIDEO);
    await alicePage?.close();
  });

  test("114.1 Video detail for published video includes playback_token", async () => {
    const resp = await apiGet(alicePage, `/ui/videos/${PUB_HLS_VIDEO}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_id).toBe(PUB_HLS_VIDEO);
    expect(data.status).toBe("published");
    expect(data.playback_token).toBeTruthy();
    expect(typeof data.playback_token).toBe("string");
    expect(data.playback_token.split(".")).toHaveLength(3); // JWT format: header.payload.signature
  });

  test("114.2 Playback token has valid expiry in the future", async () => {
    const resp = await apiGet(alicePage, `/ui/videos/${PUB_HLS_VIDEO}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.playback_expires_at).toBeTruthy();
    expect(data.playback_expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  test("114.3 Video in processing state has null playback_token", async () => {
    const resp = await apiGet(alicePage, `/ui/videos/${PROCESSING_VIDEO}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_id).toBe(PROCESSING_VIDEO);
    expect(data.status).toBe("encoding");
    expect(data.playback_token).toBeNull();
    expect(data.playback_expires_at).toBeNull();
  });

  test("114.4 Playback token audience matches expected value", async () => {
    const resp = await apiGet(alicePage, `/ui/videos/${PUB_HLS_VIDEO}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.playback_token).toBeTruthy();
    // Decode the JWT payload (base64url) to verify audience
    const parts = data.playback_token.split(".");
    expect(parts.length).toBe(3);
    const payloadB64 = parts[1];
    const payloadJson = Buffer.from(payloadB64, "base64url").toString("utf-8");
    const payload = JSON.parse(payloadJson);
    expect(payload.aud).toBe("playback");
    expect(payload.asset_id).toBe(PUB_HLS_VIDEO);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 115 — Admin Operations
// ═══════════════════════════════════════════════════════════════════════════════

test.describe.serial("115 — Admin Operations", () => {
  let rootPage: Page;
  let alicePage: Page;
  const ADMIN_VIDEO_1 = `v_adm_review_${TS}`;
  const ADMIN_VIDEO_2 = `v_adm_review2_${TS}`;
  const ROOT_SUB = () => getSessions().root.user_sub;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newPage(browser, "root");
    alicePage = await newPage(browser, "alice");

    // Seed videos with "pending_review" status for admin listing
    seedVideo({
      videoId: ADMIN_VIDEO_1,
      ownerUserId: ROOT_SUB(),
      title: `Admin Review 1 ${TS}`,
      status: "pending_review",
      visibility: "private",
    });

    seedVideo({
      videoId: ADMIN_VIDEO_2,
      ownerUserId: ROOT_SUB(),
      title: `Admin Review 2 ${TS}`,
      status: "pending_review",
      visibility: "private",
    });
  });

  test.afterAll(async () => {
    deleteVideo(ADMIN_VIDEO_1);
    deleteVideo(ADMIN_VIDEO_2);
    await rootPage?.close();
    await alicePage?.close();
  });

  test("115.1 Root can list videos by status", async () => {
    const resp = await apiGet(rootPage, "/ui/videos/admin/by-status/pending_review");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeDefined();
    expect(Array.isArray(data.items)).toBe(true);
    // Our seeded videos should be in the list
    const found1 = data.items.find(
      (v: { video_id: string }) => v.video_id === ADMIN_VIDEO_1,
    );
    const found2 = data.items.find(
      (v: { video_id: string }) => v.video_id === ADMIN_VIDEO_2,
    );
    expect(found1).toBeTruthy();
    expect(found2).toBeTruthy();
    expect(found1.status).toBe("pending_review");
  });

  test("115.2 Regular user gets 403 on admin listing", async () => {
    const resp = await apiGet(alicePage, "/ui/videos/admin/by-status/pending_review");
    expect(resp.status()).toBe(403);
  });

  test("115.3 Admin listing returns correct videos for queried status", async () => {
    const resp = await apiGet(rootPage, "/ui/videos/admin/by-status/pending_review");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // All items returned should have the queried status
    for (const item of data.items) {
      expect(item.status).toBe("pending_review");
    }
    // Items should have owner_user_id field (admin use case)
    if (data.items.length > 0) {
      expect(data.items[0]).toHaveProperty("owner_user_id");
      expect(data.items[0].owner_user_id).toBeTruthy();
    }
  });
});
