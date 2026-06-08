/**
 * VIDEO SEGMENT 14 — Video on Demand (VOD)  (~110-145s)
 *
 * A guided tour of the platform's VOD stack:
 *   - Video library (/videos): the creator's video grid with a ready/published
 *     title + status badge
 *   - Transcode pipeline: the admin Video Review Queue (/admin/video-review) with
 *     a video in a visible pipeline status (pending_review) waiting on approval —
 *     the surface where created→probing→pending_encoding→encoding→pending_review
 *     lands before publishing
 *   - Protected playback (/videos/{id}): the HLS player rendering REAL frames from
 *     a short HLS stream PUT into the in-process moto S3 (master + media playlist
 *     + TS segments), gated by a short-lived, per-session playback token
 *   - Forensic watermark: the WatermarkOverlay — a semi-transparent, repeating
 *     session-fingerprint + tenant identity drawn OVER the player
 *   - DRM: tenant-scoped AES-128 HLS key protection (the /v1/vod/drm/info + key
 *     server flow, narrated over the protected player)
 *   - Clips: the public, no-auth shareable clip page (/c/{clipId}) with broadcaster
 *     attribution
 *   - Watermarked download: the per-viewer forensic-watermarked MP4 download
 *     affordance on the player
 *
 * Pattern mirrors seg13-ads.demo.ts / seg09-files.demo.ts: ONE long test, paced
 * with beat() and narrated with caption()/titleCard(). Everything shown is brought
 * on-screen and PROVEN visible via reveal()'s toBeInViewport assertion.
 *
 * Cast (sessions seeded by e2e_admin_session_setup.py, loaded via loadSessions):
 *   - alice — the creator. Owns the published video (with the seeded HLS manifest),
 *     the pending-review video, and the clip.
 *   - root  — platform admin. Owns the review queue + the broadcast session the clip
 *     is cut from.
 *
 * Seeding (all off-camera, before any UI is shown):
 *   - A real short HLS stream (master.m3u8 + media playlist + TS segments, produced
 *     once by ffmpeg into /tmp/seg14_hls) is PUT into moto S3 under
 *     videos/{alice}/{vid}/… so the player + WatermarkOverlay render over REAL
 *     frames. The bucket is created first via PUT /mock/s3/{bucket}.
 *   - A published+downloadable video record is written to DynamoDB pointing at that
 *     manifest, with watermark_downloads + a ready download MP4 + DRM enabled.
 *   - A pending_review video record (Alice's) so the admin review queue shows a real
 *     pipeline item.
 *   - A clip: root creates + starts a broadcast session, alice cuts a clip; the
 *     public /c/{clipId} page needs no auth.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg14-vod.demo.ts
 */
import { test, expect, type APIResponse, type Page } from "@playwright/test";
import { execSync } from "child_process";
import { readFileSync } from "fs";
import {
  BASE,
  API,
  injectAuth,
  caption,
  clearCaption,
  titleCard,
  beat,
  reveal,
  loadSessions,
  type SessionData,
} from "./_demo";

const PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";
const ALICE = "alice";
const ROOT = "root";
const STAMP = Date.now();

const HLS_DIR = "/tmp/seg14_hls";

async function jsonOk(resp: APIResponse, what: string): Promise<any> {
  if (!resp.ok()) throw new Error(`${what} failed: ${resp.status()} ${await resp.text()}`);
  return resp.json();
}

/** CSRF-authenticated request helper bound to one identity's cookies/token. */
function reqs(page: Page, sess: SessionData) {
  return {
    post: (path: string, body?: unknown) =>
      page.request.post(`${API}${path}`, {
        headers: { "x-csrf-token": sess.csrf_token, "content-type": "application/json" },
        data: body ?? {},
      }),
    get: (path: string) => page.request.get(`${API}${path}`),
  };
}

/** Generate the short HLS stream once (idempotent) so the player has real media. */
function ensureHlsFixture(): void {
  execSync(
    `bash -c '
set -e
if [ ! -f ${HLS_DIR}/master.m3u8 ]; then
  rm -rf ${HLS_DIR} && mkdir -p ${HLS_DIR} && cd ${HLS_DIR}
  ffmpeg -hide_banner -loglevel error -f lavfi -i "color=c=0x1e3a5f:s=1280x720:d=8:r=15,format=yuv420p" \
    -f lavfi -i "sine=frequency=440:duration=8" \
    -vf "drawtext=text=VOD DEMO:fontcolor=white:fontsize=72:x=(w-text_w)/2:y=(h-text_h)/2" \
    -c:v libx264 -profile:v baseline -level 3.0 -pix_fmt yuv420p -g 15 -c:a aac -b:a 64k \
    -hls_time 2 -hls_playlist_type vod -hls_segment_filename "seg_%03d.ts" \
    -master_pl_name master.m3u8 -var_stream_map "v:0,a:0" out.m3u8
fi
'`,
    { timeout: 60_000 },
  );
}

/** Seed a video metadata row directly into DynamoDB. */
function seedVideo(item: Record<string, unknown>): void {
  const json = JSON.stringify(item);
  execSync(
    `${PYTHON} -c "
import boto3, os, json, sys
from decimal import Decimal
from pathlib import Path
env = Path('/home/ubuntu/testlogon/.env.local')
if env.exists():
    for line in env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
def conv(o):
    if isinstance(o, dict): return {k: conv(v) for k, v in o.items()}
    if isinstance(o, list): return [conv(i) for i in o]
    if isinstance(o, float): return Decimal(str(o))
    return o
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
ddb.Table('VideoMetadata').put_item(Item=conv(json.loads(sys.argv[1])))
print('seeded')
" ${JSON.stringify(json)}`,
    { cwd: "/home/ubuntu/testlogon", timeout: 20_000 },
  );
}

test("Segment 14 — Video on Demand", async ({ page }) => {
  test.setTimeout(600_000);
  const sessions = loadSessions();
  const alice: SessionData = sessions[ALICE];
  const root: SessionData = sessions[ROOT];
  const nowTs = Math.floor(Date.now() / 1000);

  const PUBLISHED_VIDEO = `v_seg14pub_${STAMP}`;
  const PENDING_VIDEO = `v_seg14pending_${STAMP}`;
  const bucket = "local-uploads";
  const prefix = `videos/${alice.user_sub}/${PUBLISHED_VIDEO}`;
  const manifestUrl = `${API}/mock/s3/${bucket}/${prefix}/master.m3u8`;
  const downloadKey = `${prefix}/download/source.mp4`;

  // ── Off-camera seeding ──────────────────────────────────────────────────────
  ensureHlsFixture();
  await injectAuth(page, ALICE);
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });

  // 1. PUT the real HLS stream into moto S3 (create bucket first), so the player
  //    parses a valid manifest and plays real frames under the watermark overlay.
  await page.request.put(`${API}/mock/s3/${bucket}`).catch(() => {});
  const hlsFiles: Array<{ name: string; ct: string }> = [
    { name: "master.m3u8", ct: "application/vnd.apple.mpegurl" },
    { name: "out.m3u8", ct: "application/vnd.apple.mpegurl" },
    { name: "seg_000.ts", ct: "video/mp2t" },
    { name: "seg_001.ts", ct: "video/mp2t" },
    { name: "seg_002.ts", ct: "video/mp2t" },
    { name: "seg_003.ts", ct: "video/mp2t" },
  ];
  for (const f of hlsFiles) {
    const put = await page.request.put(`${API}/mock/s3/${bucket}/${prefix}/${f.name}`, {
      headers: { "content-type": f.ct },
      data: readFileSync(`${HLS_DIR}/${f.name}`),
    });
    if (!put.ok()) throw new Error(`HLS PUT ${f.name} failed: ${put.status()}`);
  }
  // A tiny "download" MP4 object so the watermarked-download affordance is real.
  await page.request
    .put(`${API}/mock/s3/${bucket}/${downloadKey}`, {
      headers: { "content-type": "video/mp4" },
      data: readFileSync(`${HLS_DIR}/seg_000.ts`),
    })
    .catch(() => {});

  // 2. Published + downloadable + DRM-enabled video pointing at the seeded manifest.
  seedVideo({
    video_id: PUBLISHED_VIDEO,
    owner_user_id: alice.user_sub,
    title: `Behind the Build — Episode 1`,
    description: `A studio walkthrough rendered as adaptive-bitrate HLS.`,
    status: "published",
    visibility: "public",
    created_at: nowTs - 7200,
    updated_at: nowTs - 3600,
    published_at: nowTs - 3600,
    source_type: "upload",
    duration_seconds: 8,
    width: 1280,
    height: 720,
    frame_rate: 15,
    video_codec: "h264",
    audio_codec: "aac",
    file_size_bytes: 154_000,
    hls_manifest_url: manifestUrl,
    renditions: [
      { label: "720p", width: 1280, height: 720, bitrate_kbps: 2500 },
      { label: "360p", width: 640, height: 360, bitrate_kbps: 800 },
    ],
    drm_enabled: true,
    allow_download: true,
    watermark_downloads: true,
    download_mp4_key: downloadKey,
    download_mp4_status: "ready",
    download_mp4_size_bytes: 154_000,
  });

  // 3. A pending-review video so the admin queue shows a live pipeline item.
  seedVideo({
    video_id: PENDING_VIDEO,
    owner_user_id: alice.user_sub,
    title: `New Upload — Awaiting Review`,
    description: `Transcoded and queued for content review before it goes live.`,
    status: "pending_review",
    review_status: "pending_review",
    visibility: "private",
    created_at: nowTs - 600,
    updated_at: nowTs - 120,
    source_type: "upload",
    duration_seconds: 8,
    width: 1280,
    height: 720,
  });

  // 4. A clip: root creates + starts a broadcast session, alice cuts a clip. The
  //    public /c/{clipId} page is no-auth.
  const r = reqs(page, root);
  await injectAuth(page, ROOT);
  const prof = await jsonOk(
    (await r.post("/broadcast/profiles", {
      name: `VOD Demo Profile ${STAMP}`,
      region: "us-east-1",
      rendition_preset: "720p",
    })) as APIResponse,
    "create broadcast profile",
  );
  const bsess = await jsonOk(
    (await r.post("/broadcast/sessions", { profile_id: prof.id })) as APIResponse,
    "create broadcast session",
  );
  const startResp = await r.post(`/broadcast/sessions/${bsess.id}/start`, { reason: "seg14-demo" });
  if (startResp.status() !== 202) {
    throw new Error(`start broadcast failed: ${startResp.status()} ${await startResp.text()}`);
  }
  await injectAuth(page, ALICE);
  const a = reqs(page, alice);
  const clip = await jsonOk(
    (await a.post(`/broadcast/sessions/${bsess.id}/clips`, {
      start_seconds: 0,
      end_seconds: 20,
      title: `Best Moment — Episode 1`,
    })) as APIResponse,
    "create clip",
  );
  const clipId: string = clip.clip_id;

  // ── On-camera tour ──────────────────────────────────────────────────────────
  await injectAuth(page, ALICE);
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(800);

  // 1. Intro ───────────────────────────────────────────────────────────────────
  await titleCard(
    page,
    14,
    "Video on Demand",
    "Upload · transcode pipeline · protected playback · watermark · DRM · clips · downloads",
    4400,
  );

  // 2. Video library ─────────────────────────────────────────────────────────────
  await caption(page, "The video library", "Loading the creator's videos…");
  await page.goto(`${BASE}/videos`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Videos" })).toBeVisible({ timeout: 12_000 });
  await page.waitForResponse((rsp) => rsp.url().includes("/ui/videos") && rsp.status() === 200).catch(() => {});
  await page.waitForTimeout(1400);
  await reveal(
    page,
    page.getByRole("heading", { name: "Videos" }).first(),
    "Your video library",
    "Every upload, transcode, and publish lives here — a creator's full VOD catalog",
    { ms: 4600 },
  );
  await reveal(
    page,
    page.locator("h4").filter({ hasText: "Behind the Build" }).first(),
    "A published video",
    "Adaptive-bitrate HLS, ready to stream — with its live status at a glance",
    { ms: 5000 },
  );
  // The status badge on the card — the pipeline's terminal "Ready" state.
  await reveal(
    page,
    page.getByText("Ready", { exact: true }).first(),
    "Live status badges",
    "Each card surfaces its lifecycle state — uploading, encoding, in review, or ready",
    { ms: 4400 },
  );

  // 3. Transcode pipeline / review queue ──────────────────────────────────────────
  await caption(page, "The transcode pipeline", "Switching to the admin review queue…");
  await page.context().clearCookies();
  await injectAuth(page, ROOT);
  await page.goto(`${BASE}/admin/video-review`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Video Review Queue" })).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1400);
  await reveal(
    page,
    page.getByTestId("pending-count").first(),
    "Upload → transcode → review",
    "After upload, each video is probed, encoded to HLS renditions, then queued for review",
    { ms: 4200 },
  );
  await reveal(
    page,
    page.getByTestId(`review-card-${PENDING_VIDEO}`).first(),
    "A video in the pipeline",
    "This one finished transcoding and is pending review before it can publish",
    { ms: 4400 },
  );

  // 4. Protected playback ──────────────────────────────────────────────────────────
  await caption(page, "Protected playback", "Opening the video player…");
  await page.context().clearCookies();
  await injectAuth(page, ALICE);
  await page.goto(`${BASE}/videos/${PUBLISHED_VIDEO}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("video-title")).toBeVisible({ timeout: 12_000 });
  // The player div renders only when a manifest + a short-lived playback token exist.
  await expect(page.getByTestId("video-player")).toBeVisible({ timeout: 15_000 });
  await page.waitForTimeout(2200); // let HLS.js parse the manifest + start playing
  await reveal(
    page,
    page.getByTestId("video-player").first(),
    "Token-gated playback",
    "Playback is unlocked by a short-lived, per-session token that auto-refreshes mid-stream",
    { ms: 6000, ring: false },
  );
  // Adaptive renditions / quality selector.
  await reveal(
    page,
    page.getByTestId("video-renditions").first(),
    "Adaptive bitrate",
    "Multiple renditions are encoded per video so the stream adapts to the viewer's bandwidth",
    { ms: 4400 },
  );

  // 5. Forensic watermark ───────────────────────────────────────────────────────────
  await reveal(
    page,
    page.getByTestId("watermark-overlay").first(),
    "Forensic session watermark",
    "A repeating session + tenant fingerprint is drawn over every frame to deter re-recording",
    { ms: 7200, ring: false },
  );

  // 6. DRM ─────────────────────────────────────────────────────────────────────────
  // Pull the tenant-scoped DRM key info to narrate the key flow over the player.
  const drmInfo = await jsonOk(
    (await a.get(`/v1/vod/drm/info/${PUBLISHED_VIDEO}?tenant=${encodeURIComponent(alice.user_sub)}`)) as APIResponse,
    "drm info",
  );
  void drmInfo;
  await caption(
    page,
    "Tenant-scoped DRM",
    "HLS segments are AES-128 encrypted; keys are minted per-tenant and only released to a valid token",
  );
  await expect(page.getByTestId("video-player")).toBeInViewport({ ratio: 0.2, timeout: 12_000 });
  await beat(page, 8500);
  await caption(
    page,
    "Keys, not files",
    "Even a leaked segment is useless without a tenant key — issued only to an entitled session",
  );
  await beat(page, 8000);
  // The published/visibility status — entitlement and access are policy-driven.
  await reveal(
    page,
    page.getByTestId("video-status-badge").first(),
    "Entitlement-aware access",
    "Free, subscriber-only, or pay-per-view — access is checked before a token is ever minted",
    { ms: 4600 },
  );
  await clearCaption(page);
  await beat(page, 600);

  // 7. Clip ──────────────────────────────────────────────────────────────────────
  await caption(page, "Shareable clips", "Opening a public, no-login clip page…");
  await page.context().clearCookies(); // public page needs no auth
  await page.goto(`${BASE}/c/${clipId}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByText("Best Moment — Episode 1").first()).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1200);
  await reveal(
    page,
    page.getByText("Best Moment — Episode 1").first(),
    "A public clip",
    "Cut a highlight and share it anywhere — this page needs no login",
    { ms: 5200 },
  );
  await reveal(
    page,
    page.getByTestId("clip-attribution").first(),
    "Always attributed",
    "Every clip links back to the original broadcast and credits its creator",
    { ms: 4600 },
  );

  // 8. Watermarked download ────────────────────────────────────────────────────────
  await caption(page, "Forensic downloads", "Back to the player for the protected download…");
  await injectAuth(page, ALICE);
  await page.goto(`${BASE}/videos/${PUBLISHED_VIDEO}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("video-title")).toBeVisible({ timeout: 12_000 });
  await expect(page.getByTestId("download-section")).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1000);
  await reveal(
    page,
    page.getByTestId("vod-watermark-download-button").first(),
    "Watermarked download",
    "Downloads are minted on-demand with a per-viewer forensic watermark burned in",
    { ms: 5600 },
  );

  // 9. Outro ───────────────────────────────────────────────────────────────────────
  await caption(page, "VOD ✓", "Next: Remote Terminals");
  await beat(page, 4400);
  await clearCaption(page);
  await beat(page, 900);
});
