/**
 * Section 129: Video Concatenation API (VOD-016)
 *
 * Tests combining multiple videos via POST /ui/videos/combine.
 * Auth: Cookie sessions via e2e_admin_session_setup.py
 * Identities: alice (USER), bob (USER)
 */
import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const TS = Date.now();

const ALICE_KEY = "alice";
const BOB_KEY = "bob";
const ALICE_SUB = "e2e_alice@test.local";
const BOB_SUB = "e2e_bob@test.local";

// ── Session bootstrap ─────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
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

async function newPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await page.context().addCookies(getSessions()[identity].cookies);
  return page;
}

async function apiPost(page: Page, id: string, path: string, body?: unknown) {
  const s = getSessions()[id];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

// ── DDB seed helper ──────────────────────────────────────────────────────

function seedVideo(opts: {
  videoId: string;
  ownerUserId: string;
  title: string;
  status?: string;
  visibility?: string;
  durationSeconds?: number;
  sourceS3Key?: string;
  videoCodec?: string;
  audioCodec?: string;
  width?: number;
  height?: number;
  frameRate?: number;
  fileSizeBytes?: number;
}): void {
  const status = opts.status || "published";
  const visibility = opts.visibility || "public";
  const createdAt = Math.floor(Date.now() / 1000);
  const dur = opts.durationSeconds ?? 120;
  const s3Key = opts.sourceS3Key ?? `videos/${opts.ownerUserId}/${opts.videoId}/source.mp4`;
  const publishedField = status === "published" ? `'published_at': ${createdAt},` : "";
  const durField = dur > 0 ? `'duration_seconds': Decimal('${dur}'),` : "";
  const s3Field = s3Key ? `'source_s3_key': '${s3Key}',` : "";
  const vcField = opts.videoCodec ? `'video_codec': '${opts.videoCodec}',` : "";
  const acField = opts.audioCodec ? `'audio_codec': '${opts.audioCodec}',` : "";
  const wField = opts.width ? `'width': ${opts.width},` : "";
  const hField = opts.height ? `'height': ${opts.height},` : "";
  const frField = opts.frameRate ? `'frame_rate': Decimal('${opts.frameRate}'),` : "";
  const fsField = opts.fileSizeBytes ? `'file_size_bytes': ${opts.fileSizeBytes},` : "";

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
    ${durField}
    ${s3Field}
    ${publishedField}
    ${vcField}
    ${acField}
    ${wField}
    ${hField}
    ${frField}
    ${fsField}
    'drm_enabled': False,
    'allow_download': False,
})
`;
  execSync(`${REPO_ROOT}/.venv/bin/python3 -c "${script.replace(/"/g, '\\"')}"`, {
    cwd: REPO_ROOT,
    timeout: 10_000,
  });
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
    execSync(`${REPO_ROOT}/.venv/bin/python3 -c "${script.replace(/"/g, '\\"')}"`, {
      cwd: REPO_ROOT,
      timeout: 10_000,
    });
  } catch { /* ignore cleanup errors */ }
}

// ── Test data ────────────────────────────────────────────────────────────

const ALICE_V1 = `v_concat_a1_${TS}`;
const ALICE_V2 = `v_concat_a2_${TS}`;
const ALICE_V3 = `v_concat_a3_${TS}`;
const BOB_V1 = `v_concat_b1_${TS}`;
const ENCODING_V = `v_concat_enc_${TS}`;

// Track created concat video IDs for cleanup
const createdVideoIds: string[] = [];

// ── Test suite ───────────────────────────────────────────────────────────

test.describe("129 — Video Concatenation API (VOD-016)", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, ALICE_KEY);

    // Seed test videos
    seedVideo({
      videoId: ALICE_V1,
      ownerUserId: ALICE_SUB,
      title: `Concat V1 ${TS}`,
      status: "published",
      durationSeconds: 60,
      videoCodec: "h264",
      audioCodec: "aac",
      width: 1920,
      height: 1080,
      frameRate: 30,
      fileSizeBytes: 10_000_000,
    });

    seedVideo({
      videoId: ALICE_V2,
      ownerUserId: ALICE_SUB,
      title: `Concat V2 ${TS}`,
      status: "published",
      durationSeconds: 90,
      videoCodec: "h264",
      audioCodec: "aac",
      width: 1920,
      height: 1080,
      frameRate: 30,
      fileSizeBytes: 15_000_000,
    });

    seedVideo({
      videoId: ALICE_V3,
      ownerUserId: ALICE_SUB,
      title: `Concat V3 ${TS}`,
      status: "published",
      durationSeconds: 45,
      videoCodec: "vp9",
      audioCodec: "opus",
      width: 1280,
      height: 720,
      frameRate: 24,
      fileSizeBytes: 8_000_000,
    });

    seedVideo({
      videoId: BOB_V1,
      ownerUserId: BOB_SUB,
      title: `Bob Concat V1 ${TS}`,
      status: "published",
      durationSeconds: 30,
    });

    seedVideo({
      videoId: ENCODING_V,
      ownerUserId: ALICE_SUB,
      title: `Encoding Video ${TS}`,
      status: "encoding",
      durationSeconds: 50,
    });
  });

  test.afterAll(async () => {
    deleteVideo(ALICE_V1);
    deleteVideo(ALICE_V2);
    deleteVideo(ALICE_V3);
    deleteVideo(BOB_V1);
    deleteVideo(ENCODING_V);
    for (const id of createdVideoIds) {
      deleteVideo(id);
    }
    await alicePage?.close();
  });

  test("129.1 Creator combines 2 published videos", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/videos/combine", {
      source_video_ids: [ALICE_V1, ALICE_V2],
      title: `Combined ${TS}`,
    });
    expect(resp.status()).toBe(201);

    const body = await resp.json();
    expect(body.video_id).toBeTruthy();
    expect(body.video_id).not.toBe(ALICE_V1);
    expect(body.video_id).not.toBe(ALICE_V2);
    expect(body.source_video_ids).toEqual([ALICE_V1, ALICE_V2]);
    expect(body.created_via).toBe("concat");
    expect(body.concat_job_id).toBeTruthy();
    expect(body.title).toBe(`Combined ${TS}`);
    expect(body.status).toBe("created");
    expect(body.estimated_duration_seconds).toBe(150); // 60 + 90

    createdVideoIds.push(body.video_id);
  });

  test("129.2 Combine with single video returns 422", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/videos/combine", {
      source_video_ids: [ALICE_V1],
      title: `Single ${TS}`,
    });
    // Pydantic min_length=2 validation returns 422
    expect(resp.status()).toBe(422);
  });

  test("129.3 Combine with duplicate IDs returns 400", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/videos/combine", {
      source_video_ids: [ALICE_V1, ALICE_V1],
      title: `Dup ${TS}`,
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail).toContain("duplicates");
  });

  test("129.4 Combine with non-owned video returns 403", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/videos/combine", {
      source_video_ids: [ALICE_V1, BOB_V1],
      title: `Mixed owner ${TS}`,
    });
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.detail).toContain("not owned by you");
  });

  test("129.5 Combine with non-published video returns 409", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/videos/combine", {
      source_video_ids: [ALICE_V1, ENCODING_V],
      title: `Enc ${TS}`,
    });
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail).toContain("published or approved");
  });

  test("129.6 Created video has source_video_ids and created_via=concat", async () => {
    const combineResp = await apiPost(alicePage, ALICE_KEY, "/ui/videos/combine", {
      source_video_ids: [ALICE_V1, ALICE_V2, ALICE_V3],
      title: `Three-way ${TS}`,
    });
    expect(combineResp.status()).toBe(201);

    const combineBody = await combineResp.json();
    const newVideoId = combineBody.video_id;
    createdVideoIds.push(newVideoId);

    // The 201 response should include provenance
    expect(combineBody.source_video_ids).toEqual([ALICE_V1, ALICE_V2, ALICE_V3]);
    expect(combineBody.created_via).toBe("concat");

    // GET the new video detail to verify persisted provenance
    const detailResp = await apiGet(alicePage, `/ui/videos/${newVideoId}`);
    expect(detailResp.status()).toBe(200);

    const detail = await detailResp.json();
    expect(detail.source_video_ids).toEqual([ALICE_V1, ALICE_V2, ALICE_V3]);
    expect(detail.created_via).toBe("concat");
  });

  test("129.7 Estimated duration is sum of input durations", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/videos/combine", {
      source_video_ids: [ALICE_V1, ALICE_V3],
      title: `Duration check ${TS}`,
    });
    expect(resp.status()).toBe(201);

    const body = await resp.json();
    createdVideoIds.push(body.video_id);

    // ALICE_V1 = 60s, ALICE_V3 = 45s -> total = 105s
    expect(body.estimated_duration_seconds).toBe(105);
  });

  test("129.8 Compatible videos use demuxer method", async () => {
    // ALICE_V1 and ALICE_V2 have same codec/resolution/framerate -> demuxer
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/videos/combine", {
      source_video_ids: [ALICE_V1, ALICE_V2],
      title: `Demuxer check ${TS}`,
    });
    expect(resp.status()).toBe(201);

    const body = await resp.json();
    createdVideoIds.push(body.video_id);
    expect(body.concat_method).toBe("demuxer");
  });

  test("129.9 Incompatible videos use filter method", async () => {
    // ALICE_V1 (h264/1080p) and ALICE_V3 (vp9/720p) -> filter
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/videos/combine", {
      source_video_ids: [ALICE_V1, ALICE_V3],
      title: `Filter check ${TS}`,
    });
    expect(resp.status()).toBe(201);

    const body = await resp.json();
    createdVideoIds.push(body.video_id);
    expect(body.concat_method).toBe("filter");
  });
});
