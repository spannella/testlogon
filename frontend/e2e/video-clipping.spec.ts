/**
 * Section 127: Video Clipping API (VOD-015)
 *
 * Tests creating clips from published videos via POST /ui/videos/{video_id}/clip.
 * Auth: Cookie sessions via e2e_admin_session_setup.py
 * Identities: alice (USER), bob (USER)
 */
import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

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
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
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
}): void {
  const status = opts.status || "published";
  const visibility = opts.visibility || "public";
  const createdAt = Math.floor(Date.now() / 1000);
  const dur = opts.durationSeconds ?? 120;
  const s3Key = opts.sourceS3Key ?? `videos/${opts.ownerUserId}/${opts.videoId}/source.mp4`;
  const publishedField = status === "published" ? `'published_at': ${createdAt},` : "";
  const durField = dur > 0 ? `'duration_seconds': ${dur},` : "";
  const s3Field = s3Key ? `'source_s3_key': '${s3Key}',` : "";

  const script = `
import sys, os
sys.path.insert(0, '/home/ubuntu/testlogon')
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
    'drm_enabled': False,
    'allow_download': False,
})
`;
  execSync(`/home/ubuntu/testlogon/.venv/bin/python3 -c "${script.replace(/"/g, '\\"')}"`, {
    cwd: "/home/ubuntu/testlogon",
    timeout: 10_000,
  });
}

function deleteVideo(videoId: string): void {
  const script = `
import sys, os
sys.path.insert(0, '/home/ubuntu/testlogon')
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
    execSync(`/home/ubuntu/testlogon/.venv/bin/python3 -c "${script.replace(/"/g, '\\"')}"`, {
      cwd: "/home/ubuntu/testlogon",
      timeout: 10_000,
    });
  } catch { /* ignore cleanup errors */ }
}

// ── Test data ────────────────────────────────────────────────────────────

const ALICE_VIDEO = `v_cliptest_alice_${TS}`;
const BOB_VIDEO = `v_cliptest_bob_${TS}`;
const ENCODING_VIDEO = `v_cliptest_enc_${TS}`;
const NO_S3_VIDEO = `v_cliptest_nos3_${TS}`;

// Track created clip IDs for cleanup
const createdVideoIds: string[] = [];

// ── Test suite ───────────────────────────────────────────────────────────

test.describe("127 — Video Clipping API (VOD-015)", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, ALICE_KEY);

    // Seed test videos
    seedVideo({
      videoId: ALICE_VIDEO,
      ownerUserId: ALICE_SUB,
      title: `Clip Test Video ${TS}`,
      status: "published",
      durationSeconds: 120,
    });

    seedVideo({
      videoId: BOB_VIDEO,
      ownerUserId: BOB_SUB,
      title: `Bob Video ${TS}`,
      status: "published",
      durationSeconds: 60,
    });

    seedVideo({
      videoId: ENCODING_VIDEO,
      ownerUserId: ALICE_SUB,
      title: `Encoding Video ${TS}`,
      status: "encoding",
      durationSeconds: 90,
    });

    seedVideo({
      videoId: NO_S3_VIDEO,
      ownerUserId: ALICE_SUB,
      title: `No S3 Video ${TS}`,
      status: "published",
      durationSeconds: 60,
      sourceS3Key: "",
    });
  });

  test.afterAll(async () => {
    // Clean up seeded and created videos
    deleteVideo(ALICE_VIDEO);
    deleteVideo(BOB_VIDEO);
    deleteVideo(ENCODING_VIDEO);
    deleteVideo(NO_S3_VIDEO);
    for (const id of createdVideoIds) {
      deleteVideo(id);
    }
    await alicePage?.close();
  });

  test("127.1 Creator clips a published video with valid range", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/videos/${ALICE_VIDEO}/clip`, {
      start_seconds: 10,
      end_seconds: 40,
      title: `Alice Clip ${TS}`,
    });
    expect(resp.status()).toBe(201);

    const body = await resp.json();
    expect(body.video_id).toBeTruthy();
    expect(body.video_id).not.toBe(ALICE_VIDEO);
    expect(body.source_video_id).toBe(ALICE_VIDEO);
    expect(body.clip_start_seconds).toBe(10);
    expect(body.clip_end_seconds).toBe(40);
    expect(body.created_via).toBe("clip");
    expect(body.clip_job_id).toBeTruthy();
    expect(body.title).toBe(`Alice Clip ${TS}`);
    expect(body.status).toBe("created");

    createdVideoIds.push(body.video_id);
  });

  test("127.2 Clip with start >= end returns 400", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/videos/${ALICE_VIDEO}/clip`, {
      start_seconds: 60,
      end_seconds: 30,
    });
    expect(resp.status()).toBe(400);

    const body = await resp.json();
    expect(body.detail).toContain("start_seconds must be less than end_seconds");
  });

  test("127.3 Clip shorter than minimum duration returns 400", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/videos/${ALICE_VIDEO}/clip`, {
      start_seconds: 10,
      end_seconds: 10.5,
    });
    expect(resp.status()).toBe(400);

    const body = await resp.json();
    expect(body.detail).toContain("minimum clip length");
  });

  test("127.4 Clip end exceeding duration returns 400", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/videos/${ALICE_VIDEO}/clip`, {
      start_seconds: 10,
      end_seconds: 999,
    });
    expect(resp.status()).toBe(400);

    const body = await resp.json();
    expect(body.detail).toContain("end_seconds exceeds video duration");
  });

  test("127.5 Non-owner cannot clip another user's video", async ({ browser }) => {
    // Alice tries to clip Bob's video
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/videos/${BOB_VIDEO}/clip`, {
      start_seconds: 5,
      end_seconds: 30,
    });
    expect(resp.status()).toBe(403);

    const body = await resp.json();
    expect(body.detail).toBe("forbidden");
  });

  test("127.6 Clip from non-published video returns 400", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, `/ui/videos/${ENCODING_VIDEO}/clip`, {
      start_seconds: 10,
      end_seconds: 40,
    });
    expect(resp.status()).toBe(400);

    const body = await resp.json();
    expect(body.detail).toContain("published or approved");
  });

  test("127.7 Created video has source_video_id and created_via=clip", async () => {
    // Create another clip and verify provenance on the new video detail
    const clipResp = await apiPost(alicePage, ALICE_KEY, `/ui/videos/${ALICE_VIDEO}/clip`, {
      start_seconds: 0,
      end_seconds: 30,
    });
    expect(clipResp.status()).toBe(201);

    const clipBody = await clipResp.json();
    const newVideoId = clipBody.video_id;
    createdVideoIds.push(newVideoId);

    // Verify the default title
    expect(clipBody.title).toBe(`Clip Test Video ${TS} (clip)`);

    // GET the new video detail to verify provenance fields are persisted
    const detailResp = await apiGet(alicePage, `/ui/videos/${newVideoId}`);
    expect(detailResp.status()).toBe(200);

    const detail = await detailResp.json();
    expect(detail.source_video_id).toBe(ALICE_VIDEO);
    expect(detail.created_via).toBe("clip");
    expect(detail.clip_start_seconds).toBe(0);
    expect(detail.clip_end_seconds).toBe(30);
  });
});
