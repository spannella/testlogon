/**
 * VOD-020: E2E Tests for Watermarked Downloads (per-viewer render pipeline).
 *
 * Flow under test (distinct /ui/vod/watermark-download endpoints):
 *   - Owner enables watermark_downloads + download on a video.
 *   - Entitled viewer (owner) requests a watermarked download → status
 *     progresses to "ready" (deterministic in dev) → /mock/s3 URL returned.
 *   - Idempotent re-request returns the existing render (cached: true).
 *   - Non-entitled viewer → 403.
 *   - Download disabled → 403; MP4 not ready → 409.
 *   - Forensic payload extraction/decode.
 *   - UI: watermarked download button renders + transitions to ready.
 *
 * Sections:
 *   1 — Watermarked Download API (entitlement, render, idempotency)
 *   2 — Forensic Extraction API
 *   3 — Download UI
 *
 * Auth: Cookie sessions via e2e_admin_session_setup.py
 * Identities: alice (owner), bob (entitled/non-entitled viewer)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

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
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
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

// ─── DDB helpers ──────────────────────────────────────────────────────────────

function seedVideo(opts: {
  videoId: string;
  ownerUserId: string;
  title: string;
  status?: string;
  visibility?: string;
  allowDownload?: boolean;
  watermarkDownloads?: boolean;
  downloadMp4Key?: string;
  downloadMp4Status?: string;
  downloadMp4SizeBytes?: number;
}): void {
  const status = opts.status || "published";
  const visibility = opts.visibility || "public";
  const createdAt = Math.floor(Date.now() / 1000);
  const allowDownload = opts.allowDownload ?? false;
  const watermarkDownloads = opts.watermarkDownloads ?? false;
  const dlKey = opts.downloadMp4Key ? `'download_mp4_key': '${opts.downloadMp4Key}',` : "";
  const dlStatus = opts.downloadMp4Status ? `'download_mp4_status': '${opts.downloadMp4Status}',` : "";
  const dlSize = opts.downloadMp4SizeBytes ? `'download_mp4_size_bytes': ${opts.downloadMp4SizeBytes},` : "";
  const publishedField = status === "published" ? `'published_at': ${createdAt},` : "";

  const script = `
import sys, os
sys.path.insert(0, '/home/ubuntu/testlogon')
os.environ.setdefault('DEV_MODE', '1')
os.environ.setdefault('DDB_ENDPOINT_URL', 'http://localhost:8001')
os.environ.setdefault('AWS_ACCESS_KEY_ID', 'test')
os.environ.setdefault('AWS_SECRET_ACCESS_KEY', 'test')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
import boto3
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
    'watermark_downloads': ${watermarkDownloads ? "True" : "False"},
    ${dlKey}
    ${dlStatus}
    ${dlSize}
    ${publishedField}
})
`;
  execSync(
    `/home/ubuntu/testlogon/.venv/bin/python3 -c "${script.replace(/"/g, '\\"')}"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
  );
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
    execSync(
      `/home/ubuntu/testlogon/.venv/bin/python3 -c "${script.replace(/"/g, '\\"')}"`,
      { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
    );
  } catch {
    /* ignore cleanup errors */
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 1 — Watermarked Download API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe.serial("VOD-020 §1 — Watermarked Download API", () => {
  let alicePage: Page;
  let bobPage: Page;
  const ALICE_SUB = () => getSessions().alice.user_sub;

  const WM_VID = `v_wm_ready_${TS}`;
  const NO_DL_VID = `v_wm_nodl_${TS}`;
  const PENDING_VID = `v_wm_pend_${TS}`;
  const PUBLIC_WM_VID = `v_wm_public_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
    bobPage = await newPage(browser, "bob");
    const aliceSub = ALICE_SUB();

    // Owner video, download + watermark enabled, mp4 ready.
    seedVideo({
      videoId: WM_VID,
      ownerUserId: aliceSub,
      title: `Watermark Ready ${TS}`,
      allowDownload: true,
      watermarkDownloads: true,
      downloadMp4Key: `tenants/${aliceSub}/assets/${WM_VID}/download/${WM_VID}.mp4`,
      downloadMp4Status: "ready",
      downloadMp4SizeBytes: 1048576,
    });

    // Download disabled.
    seedVideo({
      videoId: NO_DL_VID,
      ownerUserId: aliceSub,
      title: `Watermark NoDL ${TS}`,
      allowDownload: false,
      watermarkDownloads: true,
    });

    // Download enabled but mp4 still generating.
    seedVideo({
      videoId: PENDING_VID,
      ownerUserId: aliceSub,
      title: `Watermark Pending ${TS}`,
      allowDownload: true,
      watermarkDownloads: true,
      downloadMp4Status: "generating",
    });

    // Public download-enabled video used to assert non-entitled viewer 403.
    seedVideo({
      videoId: PUBLIC_WM_VID,
      ownerUserId: aliceSub,
      title: `Watermark Public ${TS}`,
      visibility: "public",
      allowDownload: true,
      watermarkDownloads: true,
      downloadMp4Key: `tenants/${aliceSub}/assets/${PUBLIC_WM_VID}/download/${PUBLIC_WM_VID}.mp4`,
      downloadMp4Status: "ready",
      downloadMp4SizeBytes: 1048576,
    });
  });

  test.afterAll(async () => {
    deleteVideo(WM_VID);
    deleteVideo(NO_DL_VID);
    deleteVideo(PENDING_VID);
    deleteVideo(PUBLIC_WM_VID);
    await alicePage?.close();
    await bobPage?.close();
  });

  test("1.1 Owner requests watermarked download → ready with mock URL", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/vod/watermark-download/${WM_VID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("ready");
    expect(data.render_id).toBeTruthy();
    expect(data.render_id).not.toBe("plain");
    expect(data.download_url).toContain("/mock/s3/");
    expect(data.download_url).toContain("watermarked-downloads");
    expect(data.watermark_payload).toMatch(/^WM:v1:/);
  });

  test("1.2 Idempotent re-request returns existing render (cached)", async () => {
    const first = await apiPost(alicePage, "alice", `/ui/vod/watermark-download/${WM_VID}`);
    const firstData = await first.json();

    const second = await apiPost(alicePage, "alice", `/ui/vod/watermark-download/${WM_VID}`);
    expect(second.status()).toBe(200);
    const secondData = await second.json();
    expect(secondData.status).toBe("ready");
    expect(secondData.cached).toBe(true);
    expect(secondData.render_id).toBe(firstData.render_id);
  });

  test("1.3 Status endpoint reports ready with download URL", async () => {
    const resp = await apiGet(alicePage, `/ui/vod/watermark-download/${WM_VID}/status`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("ready");
    expect(data.render_id).toBeTruthy();
    expect(data.download_url).toContain("/mock/s3/");
  });

  test("1.4 Owner lists renders for video (forensic view)", async () => {
    const resp = await apiGet(alicePage, `/ui/vod/watermark-download/${WM_VID}/renders`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.items)).toBe(true);
    expect(data.items.length).toBeGreaterThanOrEqual(1);
    expect(data.items[0].watermark_payload).toMatch(/^WM:v1:/);
    expect(data.items[0].status).toBe("ready");
  });

  test("1.5 Download disabled on video returns 403", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/vod/watermark-download/${NO_DL_VID}`);
    expect(resp.status()).toBe(403);
  });

  test("1.6 MP4 not yet generated returns 409", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/vod/watermark-download/${PENDING_VID}`);
    expect(resp.status()).toBe(409);
  });

  test("1.7 Non-entitled viewer cannot request watermarked download (403)", async () => {
    const resp = await apiPost(bobPage, "bob", `/ui/vod/watermark-download/${PUBLIC_WM_VID}`);
    expect(resp.status()).toBe(403);
  });

  test("1.8 Non-existent video returns 404", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/vod/watermark-download/v_wm_missing_${TS}`);
    expect(resp.status()).toBe(404);
  });

  test("1.9 Request requires auth (401 without session)", async ({ request }) => {
    const resp = await request.post(`${BASE}/ui/vod/watermark-download/${WM_VID}`);
    expect([401, 403]).toContain(resp.status());
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 2 — Forensic Extraction API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe.serial("VOD-020 §2 — Forensic Extraction API", () => {
  let alicePage: Page;
  const WM_VID = `v_wm_extract_${TS}`;
  const ALICE_SUB = () => getSessions().alice.user_sub;
  let payload = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
    const aliceSub = ALICE_SUB();
    seedVideo({
      videoId: WM_VID,
      ownerUserId: aliceSub,
      title: `Watermark Extract ${TS}`,
      allowDownload: true,
      watermarkDownloads: true,
      downloadMp4Key: `tenants/${aliceSub}/assets/${WM_VID}/download/${WM_VID}.mp4`,
      downloadMp4Status: "ready",
    });
    const resp = await apiPost(alicePage, "alice", `/ui/vod/watermark-download/${WM_VID}`);
    const data = await resp.json();
    payload = data.watermark_payload;
  });

  test.afterAll(async () => {
    deleteVideo(WM_VID);
    await alicePage?.close();
  });

  test("2.1 Extract decodes a valid forensic payload", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/vod/watermark-download/extract`, {
      payload,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.found).toBe(true);
    expect(data.payload).toBe(payload);
    expect(data.decoded).toBeTruthy();
    expect(data.decoded.version).toBe("v1");
    expect(data.decoded.user_id_hash).toMatch(/^[a-f0-9]{16}$/);
    expect(data.decoded.download_timestamp).toBeGreaterThan(0);
  });

  test("2.2 Invalid payload returns found=false", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/vod/watermark-download/extract`, {
      payload: "not-a-real-watermark",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.found).toBe(false);
    expect(data.decoded).toBeNull();
  });

  test("2.3 Tampered checksum returns found=false", async () => {
    const tampered = payload.replace(/:[A-F0-9]{4}$/, ":0000");
    const resp = await apiPost(alicePage, "alice", `/ui/vod/watermark-download/extract`, {
      payload: tampered,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.found).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 3 — Download UI
// ═══════════════════════════════════════════════════════════════════════════════

test.describe.serial("VOD-020 §3 — Download UI", () => {
  let alicePage: Page;
  const WM_VID = `v_wm_ui_${TS}`;
  const ALICE_SUB = () => getSessions().alice.user_sub;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
    const aliceSub = ALICE_SUB();
    seedVideo({
      videoId: WM_VID,
      ownerUserId: aliceSub,
      title: `Watermark UI ${TS}`,
      allowDownload: true,
      watermarkDownloads: true,
      downloadMp4Key: `tenants/${aliceSub}/assets/${WM_VID}/download/${WM_VID}.mp4`,
      downloadMp4Status: "ready",
      downloadMp4SizeBytes: 1048576,
    });
  });

  test.afterAll(async () => {
    deleteVideo(WM_VID);
    await alicePage?.close();
  });

  test("3.1 Watermarked download button renders on video page", async () => {
    await alicePage.goto(`${BASE}/videos/${WM_VID}`);
    const btn = alicePage.getByTestId("vod-watermark-download-button");
    await expect(btn).toBeVisible({ timeout: 15_000 });
    await expect(btn).toContainText(/watermarked/i);
  });
});
