/**
 * FEED-001: E2E Tests for Video Posts in Newsfeed
 *
 * Sections:
 *   127 — Video Post CRUD API (6 tests)
 *   128 — Video Post in Feed (4 tests)
 *   129 — Locked Video Posts (4 tests)
 *   130 — Video Post Interactions (2 tests)
 *
 * Auth: Cookie sessions via e2e_session_setup.py (alice/bob)
 * Videos are seeded directly in DynamoDB. Posts are created via the
 * standard POST /posts endpoint with a video_id field.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const API = "http://localhost:8000";
const TS = Date.now();
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

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
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
}

async function postReq(page: Page, userId: string, path: string, body: object) {
  const s = getSessions()[userId];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function getReq(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

// ─── DynamoDB helpers ─────────────────────────────────────────────────────────

function seedVideo(opts: {
  videoId: string;
  ownerUserId: string;
  title: string;
  status?: string;
  visibility?: string;
  hlsManifestUrl?: string;
  thumbnailUrl?: string;
  durationSeconds?: number;
}): void {
  const status = opts.status ?? "published";
  const visibility = opts.visibility ?? "public";
  const createdAt = Math.floor(Date.now() / 1000);
  const hlsField = opts.hlsManifestUrl
    ? `'hls_manifest_url': '${opts.hlsManifestUrl}',`
    : "";
  const thumbField = opts.thumbnailUrl
    ? `'thumbnail_url': '${opts.thumbnailUrl}',`
    : "";
  const durField = opts.durationSeconds
    ? `'duration_seconds': Decimal('${opts.durationSeconds}'),`
    : "";
  const publishedField = status === "published" ? `'published_at': ${createdAt},` : "";

  const script = `
import sys, os
sys.path.insert(0, '/home/ubuntu/testlogon')
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
    ${thumbField}
    ${durField}
    ${publishedField}
})
print('ok')
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
ddb.Table('VideoMetadata').delete_item(Key={'video_id': '${videoId}'})
print('ok')
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

function injectPaymentMethod(userSub: string, pmId: string): void {
  const script = `
import sys, os
sys.path.insert(0, '/home/ubuntu/testlogon')
os.environ.setdefault('DDB_ENDPOINT_URL', 'http://localhost:8001')
os.environ.setdefault('AWS_ACCESS_KEY_ID', 'test')
os.environ.setdefault('AWS_SECRET_ACCESS_KEY', 'test')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
import boto3, time
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1')
tbl = ddb.Table('billing')
pk = 'USER#${userSub}'
pm_id = '${pmId}'
sk = 'PM#' + pm_id
tbl.put_item(Item={
    'pk': pk, 'sk': sk,
    'payment_method_id': pm_id,
    'provider': 'stripe',
    'provider_method_id': pm_id,
    'method_type': 'card',
    'label': 'Test Card ****4242',
    'brand': 'visa',
    'last4': '4242',
    'exp_month': 12, 'exp_year': 2099,
    'is_default': True, 'priority': 0,
    'created_at': int(time.time()),
})
tbl.put_item(Item={
    'pk': pk, 'sk': 'BILLING',
    'autopay_enabled': False, 'currency': 'usd',
    'default_payment_method_id': pm_id,
})
print('ok')
`;
  execSync(
    `/home/ubuntu/testlogon/.venv/bin/python3 -c "${script.replace(/"/g, '\\"')}"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
  );
}

// ─── Shared state ─────────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;

test.beforeAll(async ({ browser }) => {
  alicePage = await browser.newPage();
  await injectAuth(alicePage, ALICE_ID);

  bobPage = await browser.newPage();
  await injectAuth(bobPage, BOB_ID);
});

test.afterAll(async () => {
  await alicePage?.close();
  await bobPage?.close();
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 127 — Video Post CRUD API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("127 — Video Post CRUD API", () => {
  const ALICE_SUB = () => getSessions()[ALICE_ID].user_sub;
  const BOB_SUB = () => getSessions()[BOB_ID].user_sub;

  const PUB_VID_ID = `v_${TS.toString(16).padStart(13, "0")}a000000000000000000`;
  const DRAFT_VID_ID = `v_${TS.toString(16).padStart(13, "0")}b000000000000000000`;
  const BOB_VID_ID = `v_${TS.toString(16).padStart(13, "0")}c000000000000000000`;

  const createdPostIds: string[] = [];

  test.beforeAll(() => {
    // Alice's published video
    seedVideo({
      videoId: PUB_VID_ID,
      ownerUserId: ALICE_SUB(),
      title: `Feed Post Video ${TS}`,
      status: "published",
      visibility: "public",
      hlsManifestUrl: `https://cdn.example.com/hls/${PUB_VID_ID}/manifest.m3u8`,
      thumbnailUrl: `https://cdn.example.com/thumb/${PUB_VID_ID}.jpg`,
      durationSeconds: 95.5,
    });

    // Alice's draft (not published) video
    seedVideo({
      videoId: DRAFT_VID_ID,
      ownerUserId: ALICE_SUB(),
      title: `Feed Draft Video ${TS}`,
      status: "created",
      visibility: "private",
    });

    // Bob's published video
    seedVideo({
      videoId: BOB_VID_ID,
      ownerUserId: BOB_SUB(),
      title: `Bob Feed Video ${TS}`,
      status: "published",
      visibility: "public",
    });
  });

  test.afterAll(() => {
    deleteVideo(PUB_VID_ID);
    deleteVideo(DRAFT_VID_ID);
    deleteVideo(BOB_VID_ID);
  });

  test("127.1 Create post with published video_id → 200", async () => {
    const resp = await postReq(alicePage, ALICE_ID, "/posts", {
      body: `Video post test ${TS}`,
      video_id: PUB_VID_ID,
      visibility: "public",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.post_id).toBeTruthy();
    createdPostIds.push(data.post_id);
  });

  test("127.2 Create post with caption + video → both body and video_id stored", async () => {
    const caption = `Caption with video ${TS}`;
    const resp = await postReq(alicePage, ALICE_ID, "/posts", {
      body: caption,
      video_id: PUB_VID_ID,
      visibility: "public",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.body).toBeTruthy();
    expect(data.post_id).toBeTruthy();
    createdPostIds.push(data.post_id);

    // Confirm video embed in GET /posts/{id}
    const getResp = await getReq(alicePage, `/posts/${data.post_id}`);
    expect(getResp.status()).toBe(200);
    const getPost = await getResp.json();
    expect(getPost.video).toBeTruthy();
    expect(getPost.video.video_id).toBe(PUB_VID_ID);
  });

  test("127.3 Create post with non-existent video_id → 400", async () => {
    const resp = await postReq(alicePage, ALICE_ID, "/posts", {
      body: "Ghost video post",
      video_id: `v_${TS.toString(16).padStart(13, "0")}f000000000000000000`,
      visibility: "public",
    });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(JSON.stringify(data)).toContain("not found");
  });

  test("127.4 Create post with video not owned by poster → 403", async () => {
    // Alice tries to post Bob's video — should fail
    const resp = await postReq(alicePage, ALICE_ID, "/posts", {
      body: "Trying to post someone else's video",
      video_id: BOB_VID_ID,
      visibility: "public",
    });
    expect(resp.status()).toBe(403);
    const data = await resp.json();
    expect(JSON.stringify(data)).toContain("owned");
  });

  test("127.5 Create post with unpublished (draft) video → 400", async () => {
    const resp = await postReq(alicePage, ALICE_ID, "/posts", {
      body: "Draft video post",
      video_id: DRAFT_VID_ID,
      visibility: "public",
    });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(JSON.stringify(data)).toContain("published");
  });

  test("127.6 Create post with both image_urls and video_id → 400", async () => {
    const resp = await postReq(alicePage, ALICE_ID, "/posts", {
      body: "Both image and video",
      video_id: PUB_VID_ID,
      image_urls: ["https://example.com/img.jpg"],
      visibility: "public",
    });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(JSON.stringify(data)).toContain("mutually exclusive");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 128 — Video Post in Feed
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("128 — Video Post in Feed", () => {
  const ALICE_SUB = () => getSessions()[ALICE_ID].user_sub;

  const FEED_VID_ID = `v_${TS.toString(16).padStart(13, "0")}d000000000000000000`;
  const FEED_VID_TITLE = `Feed Embed Video ${TS}`;
  const FEED_THUMB_URL = `https://cdn.example.com/thumb/${FEED_VID_ID}.jpg`;
  const FEED_HLS_URL = `https://cdn.example.com/hls/${FEED_VID_ID}/manifest.m3u8`;

  let postId: string;

  test.beforeAll(async () => {
    seedVideo({
      videoId: FEED_VID_ID,
      ownerUserId: ALICE_SUB(),
      title: FEED_VID_TITLE,
      status: "published",
      visibility: "public",
      hlsManifestUrl: FEED_HLS_URL,
      thumbnailUrl: FEED_THUMB_URL,
      durationSeconds: 300.0,
    });

    // Create a post with this video
    const resp = await postReq(alicePage, ALICE_ID, "/posts", {
      body: `Feed video embed test ${TS}`,
      video_id: FEED_VID_ID,
      visibility: "public",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    postId = data.post_id;
  });

  test.afterAll(() => {
    deleteVideo(FEED_VID_ID);
  });

  test("128.1 GET /posts/{id} returns post with video embed", async () => {
    const resp = await getReq(alicePage, `/posts/${postId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video).toBeTruthy();
    expect(data.video.video_id).toBe(FEED_VID_ID);
  });

  test("128.2 Video embed has title and thumbnail_url", async () => {
    const resp = await getReq(alicePage, `/posts/${postId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video.title).toBe(FEED_VID_TITLE);
    expect(data.video.thumbnail_url).toBe(FEED_THUMB_URL);
  });

  test("128.3 POST /posts/{id}/video/entitlement returns playback_token", async () => {
    const resp = await postReq(alicePage, ALICE_ID, `/posts/${postId}/video/entitlement`, {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_id).toBe(FEED_VID_ID);
    expect(data.playback_token).toBeTruthy();
    expect(data.hls_manifest_url).toBe(FEED_HLS_URL);
    expect(data.playback_expires_at).toBeGreaterThan(0);
  });

  test("128.4 Entitlement on post with no video → 400", async () => {
    // Create a text-only post
    const textPostResp = await postReq(alicePage, ALICE_ID, "/posts", {
      body: `Text only post ${TS}`,
      visibility: "public",
    });
    expect(textPostResp.status()).toBe(200);
    const textPost = await textPostResp.json();

    const resp = await postReq(alicePage, ALICE_ID, `/posts/${textPost.post_id}/video/entitlement`, {});
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(JSON.stringify(data)).toContain("no video");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 129 — Locked Video Posts
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("129 — Locked Video Posts", () => {
  const ALICE_SUB = () => getSessions()[ALICE_ID].user_sub;
  const BOB_SUB = () => getSessions()[BOB_ID].user_sub;

  const LOCK_VID_ID = `v_${TS.toString(16).padStart(13, "0")}e000000000000000000`;
  const LOCK_VID_TITLE = `Lock Test Video ${TS}`;
  const LOCK_THUMB_URL = `https://cdn.example.com/thumb/${LOCK_VID_ID}.jpg`;
  const LOCK_HLS_URL = `https://cdn.example.com/hls/${LOCK_VID_ID}/manifest.m3u8`;
  const BOB_PM_ID = `pm_fplock_bob_${TS}`;

  let lockedPostId: string;

  test.beforeAll(async () => {
    seedVideo({
      videoId: LOCK_VID_ID,
      ownerUserId: ALICE_SUB(),
      title: LOCK_VID_TITLE,
      status: "published",
      visibility: "public",
      hlsManifestUrl: LOCK_HLS_URL,
      thumbnailUrl: LOCK_THUMB_URL,
      durationSeconds: 180.0,
    });

    // Inject a payment method for Bob so he can unlock
    injectPaymentMethod(BOB_SUB(), BOB_PM_ID);

    // Create a locked video post
    const resp = await postReq(alicePage, ALICE_ID, "/posts", {
      body: `Locked video post ${TS}`,
      video_id: LOCK_VID_ID,
      visibility: "public",
      unlock_price_cents: 999,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    lockedPostId = data.post_id;
  });

  test.afterAll(() => {
    deleteVideo(LOCK_VID_ID);
  });

  test("129.1 Locked video post hides hls_manifest_url for non-owner", async () => {
    const resp = await getReq(bobPage, `/posts/${lockedPostId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.locked).toBe(true);
    // hls_manifest_url should be null/undefined for non-owner on locked post
    expect(data.video?.hls_manifest_url ?? null).toBeNull();
  });

  test("129.2 Locked video post still returns thumbnail_url for non-owner", async () => {
    const resp = await getReq(bobPage, `/posts/${lockedPostId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.locked).toBe(true);
    // thumbnail should still be visible (teaser)
    expect(data.video).toBeTruthy();
    expect(data.video.thumbnail_url).toBe(LOCK_THUMB_URL);
  });

  test("129.3 Entitlement denied for locked video post (non-owner, not unlocked)", async () => {
    const resp = await postReq(bobPage, BOB_ID, `/posts/${lockedPostId}/video/entitlement`, {});
    expect(resp.status()).toBe(403);
    const data = await resp.json();
    expect(JSON.stringify(data)).toContain("locked");
  });

  test("129.4 Owner can get entitlement for their own locked video post", async () => {
    const resp = await postReq(alicePage, ALICE_ID, `/posts/${lockedPostId}/video/entitlement`, {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_id).toBe(LOCK_VID_ID);
    expect(data.playback_token).toBeTruthy();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 130 — Video Post Interactions
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("130 — Video Post Interactions", () => {
  const ALICE_SUB = () => getSessions()[ALICE_ID].user_sub;

  const INTERACT_VID_ID = `v_${TS.toString(16).padStart(13, "0")}ff00000000000000000`;
  let interactPostId: string;

  test.beforeAll(async () => {
    seedVideo({
      videoId: INTERACT_VID_ID,
      ownerUserId: ALICE_SUB(),
      title: `Interact Video ${TS}`,
      status: "published",
      visibility: "public",
      hlsManifestUrl: `https://cdn.example.com/hls/${INTERACT_VID_ID}/manifest.m3u8`,
      thumbnailUrl: `https://cdn.example.com/thumb/${INTERACT_VID_ID}.jpg`,
    });

    const resp = await postReq(alicePage, ALICE_ID, "/posts", {
      body: `Interaction video post ${TS}`,
      video_id: INTERACT_VID_ID,
      visibility: "public",
    });
    expect(resp.status()).toBe(200);
    interactPostId = (await resp.json()).post_id;
  });

  test.afterAll(() => {
    deleteVideo(INTERACT_VID_ID);
  });

  test("130.1 Comment on video post → 200", async () => {
    const resp = await postReq(bobPage, BOB_ID, `/posts/${interactPostId}/comments`, {
      body: `Great video! ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.comment_id).toBeTruthy();
    expect(data.body).toContain("Great video!");
  });

  test("130.2 React to video post → 200", async () => {
    const resp = await postReq(bobPage, BOB_ID, `/posts/${interactPostId}/reactions`, {
      emoji: "👍",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
  });
});
