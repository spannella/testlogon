# VOD-011: E2E Tests for Video Upload and Playback Pipeline

**Ticket**: VOD-011
**Type**: Testing
**Priority**: P1
**Size**: M
**Status**: Implemented
**Author**: Engineering
**Date**: 2026-05-24

---

## 1. Overview & Motivation

### Purpose

This ticket defines a comprehensive Playwright E2E test suite that validates the complete VOD user journey: uploading a video file, observing transcode progress, viewing the processed video in the library, verifying playback entitlement issuance, and loading the player page with an HLS manifest. The suite also covers error paths (invalid file types, oversized uploads, deleted videos, expired entitlements) and admin operations (listing videos by status, force-transitioning state).

### Why E2E Tests for the VOD Pipeline

The VOD pipeline spans multiple layers that unit tests validate in isolation but never exercise together:

1. **Upload flow** (VOD-002): Presigned URL generation, direct S3 PUT via the `/mock/s3/` dev proxy, and the completion confirmation endpoint. Unit tests mock S3 entirely; E2E tests confirm the real moto-backed S3 mock accepts and serves the uploaded bytes.

2. **Transcode lifecycle** (VOD-003/004/005): The asyncio background worker picks up a newly-uploaded video, transitions it through `created -> probing -> pending_encoding -> encoding -> pending_review`, and writes HLS manifest URLs. Unit tests validate the state machine logic, but only E2E tests prove the background loop actually fires, the DynamoDB records update, and the API reflects the new state when polled.

3. **Listing and detail** (VOD-006): Pagination, owner-scoped queries, status filtering. E2E tests confirm that a freshly-uploaded video appears in the listing after processing completes.

4. **Playback entitlement** (VOD-010 + existing `playback_entitlements.py`): The player page fetches an entitlement token before loading the manifest. E2E tests prove the token issuance, manifest URL construction, and HLS.js initialization work end-to-end.

5. **Frontend integration** (VOD-007/008/009): Upload progress indicators, status polling, video grid, player page. E2E tests verify the React components render correctly and respond to backend state changes.

### Scope

| In scope | Out of scope |
|----------|--------------|
| Upload small fixture video (5s, 720p, ~500KB) | Real multi-GB uploads |
| Dev-mode transcode via mock/fast FFmpeg | Production SQS+Lambda workers |
| Status polling until "ready" | DRM decryption in Chromium |
| HLS manifest URL accessibility | Actual video playback quality |
| Video listing, detail, delete CRUD | Admin moderation review UI |
| Entitlement token issuance + validation | Key rotation and revocation TTL expiry |
| Error paths (invalid type, too large, 404) | Concurrent upload stress testing |
| Admin status queries | Production CloudFront signed URLs |

### Test Coverage Goals

- **Full pipeline**: Upload -> process -> list -> play -> delete (happy path)
- **Error handling**: Invalid MIME types, oversized files, non-existent videos, expired tickets
- **Admin operations**: Query by status, force-transition state
- **Entitlements**: Token issuance, validation, revocation for video assets
- **UI flows**: Upload progress, processing indicator, video grid, player page

---

## 2. Current State Analysis

### 2.1 Existing E2E Test Patterns

The project has 1070+ Playwright E2E tests across 37+ spec files. Three existing files provide direct patterns for VOD testing:

**`frontend/e2e/broadcast.spec.ts`** (712 lines, 8 sections, ~26 tests):
- Tests broadcast profile CRUD, session lifecycle, playback URL generation, deletion, audit trails, access control, and validation errors.
- Uses cookie-based session auth via `e2e_admin_session_setup.py`.
- API-only tests (no UI assertions) -- same pattern needed for VOD pipeline API sections.
- State machine testing: creates a resource, transitions it through states, asserts at each step.
- Cleanup via `afterAll` context close.

**`frontend/e2e/playback-entitlements.spec.ts`** (200 lines, section 104, 10 tests):
- Tests entitlement token issuance, validation via protected ping, revocation by JTI, revocation by session+tenant, and error paths.
- Uses `test.describe.serial()` for tests that depend on state from prior tests (issued token used in subsequent validation/revocation).
- Bearer-auth validation: `apiGetBearer(page, path, token)` helper.
- Clean, focused assertions on response structure.

**`frontend/e2e/webrtc.spec.ts`** (871 lines, sections 73-77):
- DynamoDB seeding via inline Python scripts in `execSync`.
- `seedCallSession()` / `deleteCallSession()` helpers write/delete items directly.
- Feature-flag detection: probes an endpoint to determine if a feature is enabled, then conditionally skips or adapts assertions.
- Two-context pattern for multi-user scenarios.

### 2.2 Session Bootstrap Pattern

All E2E test files share the same session bootstrap approach:

```typescript
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
```

This calls `e2e_admin_session_setup.py` which creates sessions for `root`, `alice`, `bob`, `charlie_admin`, and `charlie_scoped` with role-bearing JWT cookies. The script writes directly to the DynamoDB `sessions` table (port 8001) and returns a JSON dict with `user_sub`, `session_id`, `csrf_token`, `access_token`, and `cookies[]` for each identity.

### 2.3 API Helper Pattern

```typescript
async function apiPost(page: Page, identity: string, path: string, body: object) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiDelete(page: Page, identity: string, path: string) {
  const s = getSessions()[identity];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": s.csrf_token },
  });
}
```

### 2.4 DynamoDB Seeding Pattern

From `webrtc.spec.ts`, inline Python scripts executed via `execSync` seed DynamoDB directly:

```typescript
function seedCallSession(opts: { callId: string; ... }): void {
  const py = `
import json, sys, boto3, time
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
table = ddb.Table("SomeTable")
table.put_item(Item={...})
print("ok")
`;
  execSync(`python3 -c '${py.replace(/'/g, "'\\''")}'`, {
    cwd: "/home/ubuntu/testlogon",
    timeout: 10_000,
  });
}
```

This pattern is directly applicable for seeding video metadata records in specific transcode states (e.g., pre-seeding a video in `published` state to test playback without waiting for real processing).

### 2.5 Playwright Configuration

```typescript
// frontend/playwright.config.ts
export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  expect: { timeout: 8_000 },
  retries: 1,
  workers: 1,
  use: {
    baseURL: "http://localhost:3000",
    headless: true,
    viewport: { width: 1280, height: 800 },
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
    screenshot: "only-on-failure",
    video: "off",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
```

Key constraints:
- `workers: 1` -- all tests run sequentially (safe for shared DDB state).
- `retries: 1` -- each test gets one retry on failure.
- `timeout: 30_000` -- per-test default; pipeline polling tests will need `test.setTimeout(60_000)`.

### 2.6 Backend Infrastructure for VOD (Dependencies)

Once VOD-003 through VOD-009 are implemented, the following endpoints and services will exist:

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/v1/vod/upload/presign` | POST | UI session | Get presigned S3 URL + upload ticket |
| `/v1/vod/upload/complete` | POST | UI session | Confirm upload, create video record |
| `/ui/videos` | GET | UI session | List user's videos (paginated) |
| `/ui/videos/{id}` | GET | UI session | Video detail + playback URL |
| `/ui/videos/{id}` | PATCH | UI session | Update title/description |
| `/ui/videos/{id}` | DELETE | UI session | Soft-delete video |
| `/ui/videos/{id}/transition` | POST | Admin session | Force status transition |
| `/ui/videos/admin/by-status/{status}` | GET | Admin session | Admin query by status |
| `/v1/playback/entitlements/issue` | POST | UI session | Issue playback token |
| `/v1/playback/protected/ping` | GET | Bearer (entitlement token) | Validate entitlement |

The dev-mode transcode worker runs as an asyncio background task (same pattern as `start_scheduled_messages_task()`), polling DynamoDB every 5 seconds for videos in `created` state and processing them through the pipeline.

### 2.7 Mock FFmpeg in Dev Mode

In dev mode, the transcode worker uses one of two strategies (determined by VOD-004 implementation):

1. **Real FFmpeg with tiny fixture**: If FFmpeg is installed (`FFMPEG_BINARY_PATH` in settings), the worker runs a real (but fast) transcode of the 5-second 720p fixture. Output: real HLS segments on moto S3.

2. **Mock transcode**: If FFmpeg is unavailable or `VOD_MOCK_TRANSCODE=true`, the worker skips FFmpeg execution entirely -- it writes a synthetic `master.m3u8` manifest and a single `.ts` segment to moto S3, then transitions the video to `pending_review`/`approved`/`published`. This completes in <1 second.

For E2E tests, the mock transcode path is preferred for speed and CI reliability. The test will verify the video reaches `published` status regardless of which path ran.

---

## 3. Technical Design

### 3.1 Test File Structure

Create `frontend/e2e/video-upload.spec.ts` as specified in the VOD-011 deliverables. The file will be organized into 8 sections (numbered 108-115, continuing from the highest existing section number of 107):

```
frontend/e2e/video-upload.spec.ts
├── Imports + Constants
├── Session Bootstrap (getSessions / injectAuth)
├── API Helpers (apiPost, apiGet, apiDelete, apiPatch)
├── DDB Helpers (seedVideoRecord, deleteVideoRecord, getVideoFromDdb)
├── S3 Helpers (uploadFixtureToMockS3)
├── Polling Helpers (waitForVideoStatus)
├── Section 108: Video Upload — Presign + S3 PUT + Complete
├── Section 109: Video Processing — Status Polling Until Ready
├── Section 110: Video Listing — CRUD Operations
├── Section 111: Video Playback — Entitlement + Manifest
├── Section 112: Video Deletion — Soft Delete + Listing Removal
├── Section 113: Upload Validation — Error Paths
├── Section 114: Admin Operations — Status Query + Transitions
└── Section 115: Video Upload UI — Page Interactions
```

### 3.2 Test Sections Detail

#### Section 108 -- Video Upload: Presign + S3 PUT + Complete (5 tests)

Tests the three-step upload flow end-to-end.

| Test | Description |
|------|-------------|
| 108.1 | Request presigned URL returns upload_url, ticket_id, key |
| 108.2 | PUT fixture video to presigned URL succeeds (200/204) |
| 108.3 | Complete upload creates video record with status "created" |
| 108.4 | Returned video_id starts with "v_" and has valid metadata |
| 108.5 | Second complete with same ticket_id returns 409 (replay protection) |

#### Section 109 -- Video Processing: Status Polling (4 tests)

Tests that the background worker processes the uploaded video.

| Test | Description |
|------|-------------|
| 109.1 | Poll GET /ui/videos/{id} until status != "created" (max 60s) |
| 109.2 | Video reaches terminal "published" or "approved" status |
| 109.3 | Published video has non-null hls_manifest_url |
| 109.4 | Published video has non-null thumbnail_url and duration_seconds > 0 |

#### Section 110 -- Video Listing: CRUD (5 tests)

Tests the listing and detail endpoints.

| Test | Description |
|------|-------------|
| 110.1 | GET /ui/videos returns list containing the uploaded video |
| 110.2 | List response has correct pagination structure (items, cursor) |
| 110.3 | GET /ui/videos/{id} returns full video detail |
| 110.4 | PATCH /ui/videos/{id} updates title successfully |
| 110.5 | Bob cannot see Alice's videos (owner-scoped access) |

#### Section 111 -- Playback Entitlement + Manifest (4 tests)

Tests that a published video can be played.

| Test | Description |
|------|-------------|
| 111.1 | Issue playback entitlement for published video succeeds |
| 111.2 | Validate entitlement token via protected ping returns claims |
| 111.3 | HLS manifest URL returns valid m3u8 content |
| 111.4 | Expired/invalid entitlement token returns 401 on manifest |

#### Section 112 -- Video Deletion (3 tests)

Tests soft-delete behavior.

| Test | Description |
|------|-------------|
| 112.1 | DELETE /ui/videos/{id} returns 200 with status "deleted" |
| 112.2 | Deleted video no longer appears in GET /ui/videos listing |
| 112.3 | GET /ui/videos/{id} for deleted video returns 404 or status "deleted" |

#### Section 113 -- Upload Validation: Error Paths (5 tests)

Tests rejection of invalid uploads.

| Test | Description |
|------|-------------|
| 113.1 | Presign with invalid content_type (text/plain) returns 400/422 |
| 113.2 | Presign with file_size_bytes exceeding max returns 400/413 |
| 113.3 | Complete with non-existent ticket_id returns 404 |
| 113.4 | Complete with mismatched S3 key returns 400 |
| 113.5 | Presign without auth returns 401 |

#### Section 114 -- Admin Operations (4 tests)

Tests admin-only endpoints.

| Test | Description |
|------|-------------|
| 114.1 | Root queries videos by status "published" and finds test video |
| 114.2 | Root force-transitions video from "published" to "archived" |
| 114.3 | Alice (USER role) cannot call admin transition endpoint (403) |
| 114.4 | Admin list by status "encoding" returns empty when no videos processing |

#### Section 115 -- Video Upload UI (5 tests)

Tests the frontend page interactions (requires VOD-007/008/009).

| Test | Description |
|------|-------------|
| 115.1 | Navigate to /videos, page renders "My Videos" heading |
| 115.2 | Upload zone is visible and accepts file input |
| 115.3 | After upload, processing indicator appears |
| 115.4 | After processing completes, video thumbnail appears in grid |
| 115.5 | Click video thumbnail navigates to /videos/{id} player page |

### 3.3 Helper Functions

```typescript
// ─── Constants ────────────────────────────────────────────────────────────────

const API = "http://localhost:8000";
const BASE = "http://localhost:3000";
const TS = Date.now();
const FIXTURE_VIDEO_PATH = path.resolve(__dirname, "../fixtures/test-video-5s-720p.mp4");
const FIXTURE_CONTENT_TYPE = "video/mp4";
const FIXTURE_SIZE_BYTES = 512_000; // ~500KB

// ─── DDB Helpers ──────────────────────────────────────────────────────────────

/**
 * Seed a video metadata record directly in DynamoDB in a specific state.
 * Used to test listing/playback without waiting for real processing.
 */
function seedVideoRecord(opts: {
  videoId: string;
  ownerUserId: string;
  status: string;
  title: string;
  hlsManifestUrl?: string;
  thumbnailUrl?: string;
  durationSeconds?: number;
}): void {
  const py = `
import boto3, time, json
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
table = ddb.Table("VideoMetadata")
ts = int(time.time())
item = {
    "video_id": ${JSON.stringify(opts.videoId)},
    "owner_user_id": ${JSON.stringify(opts.ownerUserId)},
    "status": ${JSON.stringify(opts.status)},
    "title": ${JSON.stringify(opts.title)},
    "source_type": "upload",
    "visibility": "public",
    "created_at": ts,
    "updated_at": ts,
}
if ${JSON.stringify(opts.hlsManifestUrl || "")}:
    item["hls_manifest_url"] = ${JSON.stringify(opts.hlsManifestUrl || "")}
if ${JSON.stringify(opts.thumbnailUrl || "")}:
    item["thumbnail_url"] = ${JSON.stringify(opts.thumbnailUrl || "")}
if ${opts.durationSeconds ?? 0}:
    item["duration_seconds"] = ${JSON.stringify(opts.durationSeconds ?? 5.0)}
table.put_item(Item=item)
print("ok")
`;
  execSync(`python3 -c '${py.replace(/'/g, "'\\''")}'`, {
    cwd: "/home/ubuntu/testlogon",
    timeout: 10_000,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
  });
}

/**
 * Delete a video record from DynamoDB (cleanup).
 */
function deleteVideoRecord(videoId: string): void {
  const py = `
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
table = ddb.Table("VideoMetadata")
table.delete_item(Key={"video_id": ${JSON.stringify(videoId)}})
print("ok")
`;
  try {
    execSync(`python3 -c '${py.replace(/'/g, "'\\''")}'`, {
      cwd: "/home/ubuntu/testlogon",
      timeout: 10_000,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    });
  } catch { /* ignore cleanup errors */ }
}

/**
 * Read a video record directly from DynamoDB (for asserting state transitions
 * that may not be surfaced through the API).
 */
function getVideoFromDdb(videoId: string): any {
  const py = `
import boto3, json
from decimal import Decimal
class DecEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal): return int(o) if o == int(o) else float(o)
        return super().default(o)
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
table = ddb.Table("VideoMetadata")
resp = table.get_item(Key={"video_id": ${JSON.stringify(videoId)}})
print(json.dumps(resp.get("Item"), cls=DecEncoder))
`;
  const raw = execSync(`python3 -c '${py.replace(/'/g, "'\\''")}'`, {
    cwd: "/home/ubuntu/testlogon",
    timeout: 10_000,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
  }).toString().trim();
  return raw === "null" ? null : JSON.parse(raw);
}

// ─── S3 Upload Helper ─────────────────────────────────────────────────────────

/**
 * Upload the test fixture video to the mock S3 endpoint using the presigned
 * URL returned by the presign endpoint. In dev mode, presigned URLs point to
 * /mock/s3/{bucket}/{key} on the backend.
 */
async function uploadFixtureToMockS3(
  page: Page,
  uploadUrl: string,
  contentType: string,
): Promise<number> {
  const fixtureBuffer = fs.readFileSync(FIXTURE_VIDEO_PATH);
  const resp = await page.request.put(uploadUrl, {
    data: fixtureBuffer,
    headers: { "Content-Type": contentType },
  });
  return resp.status();
}

// ─── Polling Helper ───────────────────────────────────────────────────────────

/**
 * Poll the video detail endpoint until the status matches one of the target
 * statuses or timeout is reached.
 */
async function waitForVideoStatus(
  page: Page,
  videoId: string,
  targetStatuses: string[],
  timeoutMs = 60_000,
  intervalMs = 2_000,
): Promise<{ status: string; body: any }> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const resp = await page.request.get(`${API}/ui/videos/${videoId}`);
    if (resp.status() === 200) {
      const body = await resp.json();
      if (targetStatuses.includes(body.status)) {
        return { status: body.status, body };
      }
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(
    `Video ${videoId} did not reach status [${targetStatuses.join(", ")}] within ${timeoutMs}ms`,
  );
}
```

### 3.4 Test Fixture: Small Video File

The E2E suite requires a small video fixture to avoid slow uploads and long transcode times. The fixture is generated once during `scripts/setup_ubuntu.sh` (or a dedicated fixture setup script):

**Generation command** (FFmpeg):
```bash
ffmpeg -f lavfi -i testsrc=duration=5:size=1280x720:rate=30 \
       -f lavfi -i sine=frequency=440:duration=5 \
       -c:v libx264 -preset ultrafast -crf 28 \
       -c:a aac -b:a 64k \
       -movflags +faststart \
       -y frontend/fixtures/test-video-5s-720p.mp4
```

Properties:
- Duration: 5 seconds
- Resolution: 1280x720
- Codec: H.264 (ultrafast preset) + AAC audio
- Size: ~200-500KB
- Content: synthetic test pattern + 440Hz tone

**Fallback for CI without FFmpeg**: If the fixture does not exist, a minimal valid MP4 can be generated in JavaScript using a static byte array (the smallest valid MP4 is ~700 bytes with a single empty video frame). Alternatively, the test skips sections 108-109 and uses DDB-seeded records for sections 110-115.

### 3.5 Mock Transcode Strategy for Dev Mode

The E2E tests must not depend on FFmpeg being installed or working correctly. The test strategy uses a two-tier approach:

**Tier 1 -- Fast path (mock transcode enabled)**:

If `VOD_MOCK_TRANSCODE=true` in the backend environment (the default in dev mode), the transcode worker:
1. Skips FFmpeg execution entirely.
2. Writes a synthetic HLS manifest to moto S3:
   ```
   #EXTM3U
   #EXT-X-VERSION:3
   #EXT-X-TARGETDURATION:6
   #EXT-X-MEDIA-SEQUENCE:0
   #EXTINF:5.000,
   segment_000.ts
   #EXT-X-ENDLIST
   ```
3. Writes a 1KB dummy `.ts` segment.
4. Sets `hls_manifest_url`, `thumbnail_url`, `duration_seconds`, and transitions to `published`.
5. Total processing time: <2 seconds.

**Tier 2 -- Real FFmpeg path**:

If FFmpeg is available and `VOD_MOCK_TRANSCODE=false`, the worker runs a real (but fast) transcode of the 5-second fixture. With `--preset ultrafast`, this completes in 3-8 seconds. Tests use `waitForVideoStatus()` with a 60-second timeout to accommodate both tiers.

### 3.6 DynamoDB Seeding for Specific Transcode States

Some tests need videos in specific states without waiting for processing. The `seedVideoRecord()` helper writes directly to the `VideoMetadata` table:

| Test scenario | Seeded state | Additional fields |
|---------------|-------------|-------------------|
| Listing test (110.1-110.5) | `published` | hls_manifest_url, thumbnail_url, duration_seconds |
| Playback test (111.1-111.4) | `published` | hls_manifest_url, entitlement_sku |
| Admin status query (114.1) | `published` | -- |
| Admin transition (114.2) | `published` | -- |
| Deletion test (112.1-112.3) | `published` | -- |
| Encoding in progress (114.4) | `encoding` | encoding_started_at |
| Bob's video (110.5) | `published` | owner_user_id = bob.user_sub |

---

## 4. Implementation Plan

### 4.1 File Creation

<!-- NOTE: Multiple VOD E2E test files ALREADY EXIST:
     - frontend/e2e/video-upload.spec.ts
     - frontend/e2e/video-listing.spec.ts
     - frontend/e2e/video-player.spec.ts
     - frontend/e2e/video-review-queue.spec.ts
     - frontend/e2e/video-subtitles.spec.ts
     - frontend/e2e/video-clipping.spec.ts
     - frontend/e2e/video-concat.spec.ts
     - frontend/e2e/video-gallery.spec.ts
     - frontend/e2e/vod-pipeline.spec.ts
     - frontend/e2e/vod-drm.spec.ts
     - frontend/e2e/vod-download.spec.ts
     - frontend/e2e/vod-purchase.spec.ts
     - frontend/e2e/vod-purchase-tiers.spec.ts
     - frontend/e2e/vod-file-bridge.spec.ts
     - frontend/e2e/vod-ads.spec.ts
     - frontend/e2e/vod-broadcast-pricing.spec.ts
-->

| File | Purpose |
|------|---------|
| `frontend/e2e/video-upload.spec.ts` | Main E2E test file (~600-800 lines) |
| `frontend/fixtures/test-video-5s-720p.mp4` | Small video fixture for upload tests |
| `scripts/generate-test-fixtures.sh` | One-time script to generate video fixture if missing |

### 4.2 Test File Template

```typescript
/**
 * VOD-011: E2E tests for video upload and playback pipeline.
 *
 * Sections 108-115:
 *   108 — Video upload (presign + S3 PUT + complete)
 *   109 — Video processing (status polling until ready)
 *   110 — Video listing (CRUD operations)
 *   111 — Playback entitlement + manifest
 *   112 — Video deletion
 *   113 — Upload validation (error paths)
 *   114 — Admin operations (status queries + transitions)
 *   115 — Video upload UI (page interactions)
 *
 * Auth: Cookie sessions via e2e_admin_session_setup.py
 * Identities: alice (USER), bob (USER), root (ROOT)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

// ─── Constants ────────────────────────────────────────────────────────────────

const API = "http://localhost:8000";
const BASE = "http://localhost:3000";
const TS = Date.now();
const FIXTURE_DIR = path.resolve(__dirname, "../fixtures");
const FIXTURE_VIDEO = path.join(FIXTURE_DIR, "test-video-5s-720p.mp4");

// ... (session bootstrap, API helpers, DDB helpers as in Section 3.3)
```

### 4.3 Section 108 Implementation (Upload Flow)

```typescript
test.describe.serial("108 — Video Upload: presign + S3 PUT + complete", () => {
  let alicePage: Page;
  let uploadUrl: string;
  let ticketId: string;
  let s3Key: string;
  let videoId: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, "alice");
  });

  test.afterAll(async () => {
    if (videoId) deleteVideoRecord(videoId);
    await alicePage?.context().close();
  });

  test("108.1 Presign returns upload URL, ticket, and key", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/vod/upload/presign", {
      filename: `e2e_test_${TS}.mp4`,
      content_type: "video/mp4",
      file_size_bytes: fs.statSync(FIXTURE_VIDEO).size,
      title: `E2E Upload Test ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.upload_url).toBeTruthy();
    expect(data.ticket_id).toBeTruthy();
    expect(data.key).toBeTruthy();
    expect(data.content_type).toBe("video/mp4");
    uploadUrl = data.upload_url;
    ticketId = data.ticket_id;
    s3Key = data.key;
  });

  test("108.2 PUT fixture to presigned URL succeeds", async () => {
    const status = await uploadFixtureToMockS3(alicePage, uploadUrl, "video/mp4");
    expect([200, 204]).toContain(status);
  });

  test("108.3 Complete upload creates video record", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/vod/upload/complete", {
      ticket_id: ticketId,
      key: s3Key,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.video_id).toMatch(/^v_/);
    expect(data.status).toMatch(/^(created|processing|uploaded)$/);
    videoId = data.video_id;
  });

  test("108.4 Video detail shows correct initial metadata", async () => {
    const resp = await apiGet(alicePage, `/ui/videos/${videoId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_id).toBe(videoId);
    expect(data.owner_user_id).toBe(getSessions().alice.user_sub);
    expect(data.title).toBe(`E2E Upload Test ${TS}`);
    expect(data.source_type).toBe("upload");
  });

  test("108.5 Replay complete with same ticket returns 409", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/vod/upload/complete", {
      ticket_id: ticketId,
      key: s3Key,
    });
    expect([404, 409]).toContain(resp.status());
  });
});
```

### 4.4 Section 109 Implementation (Processing Poll)

```typescript
test.describe.serial("109 — Video Processing: status polling", () => {
  let alicePage: Page;
  let videoId: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, "alice");

    // Upload a fresh video to trigger processing
    const presignResp = await apiPost(alicePage, "alice", "/v1/vod/upload/presign", {
      filename: `e2e_process_${TS}.mp4`,
      content_type: "video/mp4",
      file_size_bytes: fs.statSync(FIXTURE_VIDEO).size,
      title: `E2E Process Test ${TS}`,
    });
    const presignData = await presignResp.json();
    await uploadFixtureToMockS3(alicePage, presignData.upload_url, "video/mp4");
    const completeResp = await apiPost(alicePage, "alice", "/v1/vod/upload/complete", {
      ticket_id: presignData.ticket_id,
      key: presignData.key,
    });
    videoId = (await completeResp.json()).video_id;
  });

  test.afterAll(async () => {
    if (videoId) deleteVideoRecord(videoId);
    await alicePage?.context().close();
  });

  test("109.1 Video status advances beyond 'created'", async () => {
    test.setTimeout(60_000);
    const { status } = await waitForVideoStatus(
      alicePage, videoId,
      ["probing", "pending_encoding", "encoding", "pending_review", "approved", "published"],
      55_000,
    );
    expect(status).not.toBe("created");
  });

  test("109.2 Video reaches terminal 'published' or 'approved' status", async () => {
    test.setTimeout(60_000);
    const { status } = await waitForVideoStatus(
      alicePage, videoId,
      ["published", "approved"],
      55_000,
    );
    expect(["published", "approved"]).toContain(status);
  });

  test("109.3 Published video has HLS manifest URL", async () => {
    const resp = await apiGet(alicePage, `/ui/videos/${videoId}`);
    const data = await resp.json();
    expect(data.hls_manifest_url).toBeTruthy();
    expect(data.hls_manifest_url).toContain(".m3u8");
  });

  test("109.4 Published video has thumbnail and duration", async () => {
    const resp = await apiGet(alicePage, `/ui/videos/${videoId}`);
    const data = await resp.json();
    expect(data.thumbnail_url).toBeTruthy();
    expect(data.duration_seconds).toBeGreaterThan(0);
  });
});
```

### 4.5 Fixture Generation Script

Create `scripts/generate-test-fixtures.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

FIXTURE_DIR="$(dirname "$0")/../frontend/fixtures"
mkdir -p "$FIXTURE_DIR"

VIDEO_FILE="$FIXTURE_DIR/test-video-5s-720p.mp4"

if [ -f "$VIDEO_FILE" ]; then
  echo "[fixtures] Video fixture already exists: $VIDEO_FILE"
  exit 0
fi

if ! command -v ffmpeg &>/dev/null; then
  echo "[fixtures] FFmpeg not found — generating minimal MP4 stub"
  # Write a minimal valid MP4 file (ftyp + moov atoms with no media data)
  # This is ~700 bytes and technically valid but has 0 duration
  python3 -c "
import struct, sys
# Minimal MP4: ftyp box + empty moov box
ftyp = b'\\x00\\x00\\x00\\x18ftypmp42\\x00\\x00\\x00\\x00mp42isom'
moov = b'\\x00\\x00\\x00\\x08moov'
sys.stdout.buffer.write(ftyp + moov)
" > "$VIDEO_FILE"
  echo "[fixtures] Created minimal MP4 stub: $VIDEO_FILE ($(stat -c%s "$VIDEO_FILE") bytes)"
  exit 0
fi

echo "[fixtures] Generating 5s 720p test video with FFmpeg..."
ffmpeg -f lavfi -i "testsrc=duration=5:size=1280x720:rate=30" \
       -f lavfi -i "sine=frequency=440:duration=5" \
       -c:v libx264 -preset ultrafast -crf 28 \
       -c:a aac -b:a 64k \
       -movflags +faststart \
       -y "$VIDEO_FILE" 2>/dev/null

echo "[fixtures] Created video fixture: $VIDEO_FILE ($(stat -c%s "$VIDEO_FILE") bytes)"
```

### 4.6 Integration with `just` Commands

Add to `justfile`:

```makefile
# Generate E2E test fixtures (video file for VOD tests)
fixtures:
    bash scripts/generate-test-fixtures.sh

# Run VOD E2E tests only
e2e-vod:
    cd frontend && npx playwright test e2e/video-upload.spec.ts
```

### 4.7 Environment Variables

The following variables affect test behavior (already in `.env.local` after VOD-003/004/005):

| Variable | Default | E2E Impact |
|----------|---------|------------|
| `VOD_MOCK_TRANSCODE` | `true` | When true, transcode completes in <2s (no FFmpeg needed) |
| `VOD_TRANSCODE_WORKER_ENABLED` | `true` | Must be true for section 109 tests |
| `VOD_TRANSCODE_POLL_INTERVAL_SECONDS` | `5` | How often worker polls (shorter = faster tests) |
| `PLAYBACK_ENTITLEMENT_SECRET` | set by setup | Required for section 111 |
| `DDB_VIDEO_METADATA` | `VideoMetadata` | Table name for video records |

---

## 5. Testing Strategy

### 5.1 Test Matrix

| Section | Depends on prior section? | Uses real upload? | Uses DDB seed? | Timeout override? |
|---------|--------------------------|-------------------|----------------|-------------------|
| 108 | No | Yes (fixture) | No | No (default 30s) |
| 109 | No (uploads own video) | Yes (fixture) | No | Yes (60s) |
| 110 | No | No | Yes (seedVideoRecord) | No |
| 111 | No | No | Yes (seedVideoRecord) | No |
| 112 | No | No | Yes (seedVideoRecord) | No |
| 113 | No | Partial (presign only) | No | No |
| 114 | No | No | Yes (seedVideoRecord) | No |
| 115 | No | No | Yes (seedVideoRecord) | No |

Each section is independently runnable via `--grep`:
```bash
npx playwright test e2e/video-upload.spec.ts --grep "108"
npx playwright test e2e/video-upload.spec.ts --grep "109"
```

### 5.2 Flakiness Prevention

**1. Unique identifiers per run**

All video titles, ticket IDs, and test data include the `TS` timestamp to prevent collisions across test runs:
```typescript
const TS = Date.now();
const TITLE = `E2E Upload Test ${TS}`;
```

**2. Generous polling timeouts for transcode**

The mock transcode path completes in <2s, but real FFmpeg may take 5-10s for the tiny fixture. Use 60-second timeout with 2-second poll interval:
```typescript
test.setTimeout(60_000);
await waitForVideoStatus(page, videoId, ["published", "approved"], 55_000, 2_000);
```

**3. Avoid `page.waitForTimeout()` -- use `setTimeout` + Promise**

```typescript
// GOOD: Non-blocking wait that doesn't depend on page context
await new Promise((r) => setTimeout(r, intervalMs));

// BAD: Depends on page context, can fail during teardown
await page.waitForTimeout(2000);
```

**4. Idempotent cleanup in afterAll**

```typescript
test.afterAll(async () => {
  // Cleanup regardless of test outcome
  if (videoId) {
    try { deleteVideoRecord(videoId); } catch { /* ignore */ }
  }
  await alicePage?.context().close();
});
```

**5. Independent test data per section**

Each `test.describe` block creates its own video record (either via upload or DDB seed). Tests within a serial block may share state (e.g., `videoId` from upload), but different sections never depend on each other.

**6. Retry-safe test design**

With `retries: 1`, a retried test runs in a fresh worker process. Module-level variables like `_sessions` are reset. The `getSessions()` function re-runs `e2e_admin_session_setup.py` on cache miss, so retries work transparently. DDB-seeded records use unique IDs (`v_e2e_${TS}_...`) that won't collide with the previous attempt.

**7. Fixture file existence check**

```typescript
test.beforeAll(async () => {
  if (!fs.existsSync(FIXTURE_VIDEO)) {
    // Try to generate it
    try {
      execSync("bash scripts/generate-test-fixtures.sh", {
        cwd: "/home/ubuntu/testlogon",
        timeout: 30_000,
      });
    } catch {
      test.skip(true, "Video fixture not available and cannot be generated");
    }
  }
});
```

### 5.3 CI Integration

**Prerequisites in CI pipeline**:
1. Dev stack running (`just up` or equivalent).
2. E2E sessions seeded (`e2e_admin_session_setup.py` called during `just up`).
3. `VideoMetadata` table created by `scripts/local-ddb-init.py`.
4. VOD transcode worker active (`VOD_TRANSCODE_WORKER_ENABLED=true`).
5. Playback entitlement secret configured (`PLAYBACK_ENTITLEMENT_SECRET` in `.env.local`).
6. Video fixture exists (generated by `scripts/generate-test-fixtures.sh` during `just up` or by the test `beforeAll`).

**CI run command**:
```bash
just fixtures  # ensure video fixture exists
just e2e       # runs all tests including video-upload.spec.ts
# or targeted:
just e2e-vod   # runs only VOD tests
```

**Expected execution time**:
- Sections 108-109 (real upload + processing poll): 10-65 seconds (depends on mock vs. real transcode)
- Sections 110-115 (DDB-seeded, no polling): 2-3 seconds each
- Total: 30-90 seconds

**Feature gate**: If the VOD endpoints are not yet deployed (dependencies VOD-003 through VOD-009 not implemented), the test file should gracefully skip:

```typescript
let _vodAvailable: boolean | null = null;

async function isVodAvailable(page: Page): Promise<boolean> {
  if (_vodAvailable !== null) return _vodAvailable;
  try {
    const resp = await page.request.post(`${API}/v1/vod/upload/presign`, {
      data: { filename: "probe.mp4", content_type: "video/mp4", file_size_bytes: 100 },
      headers: { "x-csrf-token": getSessions().alice.csrf_token },
    });
    // 400/422 means the endpoint exists but validation failed
    // 404 means the route does not exist
    _vodAvailable = resp.status() !== 404;
  } catch {
    _vodAvailable = false;
  }
  return _vodAvailable;
}
```

### 5.4 Parallel Test Considerations

The Playwright config uses `workers: 1`, so all tests run sequentially. However, the test design accounts for potential future parallelization:

1. **No shared mutable state between sections**: Each section creates/seeds its own video records with unique IDs.
2. **DDB cleanup is best-effort**: If a test creates a record and fails before cleanup, the record persists but does not interfere with subsequent runs (unique TS-based IDs).
3. **S3 mock is per-process**: With `workers: 1`, the moto S3 mock (in-process with uvicorn) maintains consistent state. If workers > 1 were used, S3 state would diverge (documented gotcha in CLAUDE.md).
4. **Transcode worker is singleton**: The asyncio background task processes one video at a time (dev mode concurrency = 1-2). With `workers: 1`, only one test can trigger processing at a time.

### 5.5 Debugging Failures

**Screenshot on failure** (global config): `screenshot: "only-on-failure"` captures page state for UI tests (section 115).

**Video record dump on failure**: Use `afterEach` to attach the DDB record state to the test report:

```typescript
test.afterEach(async ({ }, testInfo) => {
  if (testInfo.status !== "passed" && videoId) {
    const record = getVideoFromDdb(videoId);
    await testInfo.attach("video-ddb-record", {
      body: JSON.stringify(record, null, 2),
      contentType: "application/json",
    });
  }
});
```

**Transcode worker log inspection**: If section 109 times out, check backend logs for transcode errors:
```bash
grep -i "transcode\|video_transcode\|ffmpeg" .logs/uvicorn.log | tail -20
```

### 5.6 Success Criteria

The VOD-011 E2E test suite passes when:

- [ ] 35 tests across 8 sections (108-115) all pass on first attempt.
- [ ] Full pipeline test (upload -> process -> play) completes within 60 seconds with mock transcode.
- [ ] All CRUD operations verified (create, read, update, delete).
- [ ] Error paths tested (invalid type, too large, 404, 401, 409).
- [ ] Admin operations tested (status query, force transition, access control).
- [ ] Tests are idempotent (pass on retry without manual DDB cleanup).
- [ ] Existing 1070+ E2E tests remain unaffected (no changes to `playwright.config.ts`).
- [ ] CI execution time for the full VOD test file < 120 seconds.

---

## Appendix A: File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `frontend/e2e/video-upload.spec.ts` | New | 35 E2E tests across 8 sections (~700 lines) |
| `frontend/fixtures/test-video-5s-720p.mp4` | New | 5-second 720p test fixture (~500KB) |
| `scripts/generate-test-fixtures.sh` | New | Fixture generation script (FFmpeg or stub) |
| `justfile` | Modify | Add `fixtures` and `e2e-vod` targets |
| `scripts/setup_ubuntu.sh` | Modify | Call `generate-test-fixtures.sh` during setup |

## Appendix B: Dependency Chain

```
VOD-001 (metadata model) ─┐
VOD-002 (upload endpoint) ─┼─── VOD-006 (listing API) ─┐
VOD-003 (job queue) ───────┤                            │
VOD-004 (FFmpeg exec) ─────┤                            ├─── VOD-011 (E2E tests)
VOD-005 (S3 upload outputs)┘                            │
VOD-007 (upload UI) ────────────────────────────────────┤
VOD-008 (player page) ─────────────────────────────────┤
VOD-009 (routes/nav) ──────────────────────────────────┘
```

All dependencies (VOD-003 through VOD-009) must be implemented before VOD-011 can be fully executed. However, sections 110-114 can be partially developed and tested using DDB-seeded records even before the transcode worker (VOD-003/004/005) is complete.

## Appendix C: Section Number Allocation

| Section | Topic | Test Count |
|---------|-------|-----------|
| 108 | Upload: presign + S3 + complete | 5 |
| 109 | Processing: status polling | 4 |
| 110 | Listing: CRUD | 5 |
| 111 | Playback: entitlement + manifest | 4 |
| 112 | Deletion: soft delete | 3 |
| 113 | Validation: error paths | 5 |
| 114 | Admin: status + transitions | 4 |
| 115 | UI: page interactions | 5 |
| **Total** | | **35** |
