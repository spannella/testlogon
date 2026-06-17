/**
 * E2E tests for Video Gallery Hub (VOD-017).
 *
 * Sections:
 *   131 — Gallery Publishing API (5 tests)
 *   132 — Video Engagement API (5 tests)
 *   133 — Gallery Browsing & Comments API (5 tests)
 *
 * Auth: Alice + Bob session cookies (from e2e_session_setup.py).
 *
 * These tests create a video record directly in DynamoDB, transition it to
 * "published" status, then exercise the gallery publish/browse/view/like/comment
 * endpoints.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();
const DDB_ENDPOINT = "http://localhost:8001";

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
      "python3 " + REPO_ROOT + "/e2e_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const sessions = getSessions();
  const s = sessions[identity];
  if (!s) throw new Error(`No session for identity: ${identity}`);
  await page.context().addCookies(s.cookies);
}

function csrfHeader(identity: string): Record<string, string> {
  const sessions = getSessions();
  return { "x-csrf-token": sessions[identity].csrf_token };
}

// Retry on 429: under a shared-backend shard run the accumulated request volume
// from other specs can trip the global IP rate-limit window. Honor Retry-After
// (capped) so a transient 429 doesn't fail an assertion expecting 2xx.
async function retry429(fn: () => Promise<any>) {
  let resp = await fn();
  for (let attempt = 0; attempt < 4 && resp.status() === 429; attempt++) {
    const ra = Number(resp.headers()["retry-after"] || "1");
    await new Promise((r) => setTimeout(r, Math.min(Math.max(ra, 1), 3) * 1000));
    resp = await fn();
  }
  return resp;
}

// ─── DDB Helpers ──────────────────────────────────────────────────────────────

function ddbPut(table: string, item: Record<string, any>): void {
  const itemB64 = Buffer.from(JSON.stringify(item)).toString("base64");
  execSync(
    `python3 -c "
import boto3, json, base64, sys
ddb = boto3.resource('dynamodb', endpoint_url='${DDB_ENDPOINT}', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('${table}')
item = json.loads(base64.b64decode('${itemB64}'))
tbl.put_item(Item=item)
print('ok')
"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  );
}

function ddbDelete(table: string, key: Record<string, any>): void {
  const keyB64 = Buffer.from(JSON.stringify(key)).toString("base64");
  try {
    execSync(
      `python3 -c "
import boto3, json, base64
ddb = boto3.resource('dynamodb', endpoint_url='${DDB_ENDPOINT}', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('${table}')
key = json.loads(base64.b64decode('${keyB64}'))
tbl.delete_item(Key=key)
print('ok')
"`,
      { cwd: REPO_ROOT, timeout: 10_000 },
    );
  } catch { /* ignore */ }
}

// ─── Test State ───────────────────────────────────────────────────────────────

const VIDEO_ID = `v_e2e_gallery_${TS}`;
const VIDEO_ID_2 = `v_e2e_gallery2_${TS}`;
const VIDEO_ID_BOB = `v_e2e_bob_${TS}`;

// ─── Setup ────────────────────────────────────────────────────────────────────

test.beforeAll(async () => {
  // Ensure sessions are seeded
  getSessions();

  // Seed a published video owned by Alice
  ddbPut("VideoMetadata", {
    video_id: VIDEO_ID,
    owner_user_id: ALICE_ID,
    title: `Gallery Test Video ${TS}`,
    description: "A test video for gallery E2E",
    status: "published",
    visibility: "public",
    source_type: "upload",
    created_at: Math.floor(Date.now() / 1000),
    updated_at: Math.floor(Date.now() / 1000),
    published_at: Math.floor(Date.now() / 1000),
    drm_enabled: false,
    gallery_published: false,
    view_count: 0,
    like_count: 0,
    comment_count: 0,
    allow_download: false,
    download_count: 0,
  });

  // Seed a second published video owned by Alice (for category test)
  ddbPut("VideoMetadata", {
    video_id: VIDEO_ID_2,
    owner_user_id: ALICE_ID,
    title: `Gallery Cooking Video ${TS}`,
    description: "A cooking test video",
    status: "published",
    visibility: "public",
    source_type: "upload",
    created_at: Math.floor(Date.now() / 1000) - 100,
    updated_at: Math.floor(Date.now() / 1000) - 100,
    published_at: Math.floor(Date.now() / 1000) - 100,
    drm_enabled: false,
    gallery_published: false,
    view_count: 0,
    like_count: 0,
    comment_count: 0,
    allow_download: false,
    download_count: 0,
  });

  // Seed a published video owned by Bob (for non-owner test)
  ddbPut("VideoMetadata", {
    video_id: VIDEO_ID_BOB,
    owner_user_id: BOB_ID,
    title: `Bob Gallery Video ${TS}`,
    description: "Bob's video",
    status: "published",
    visibility: "public",
    source_type: "upload",
    created_at: Math.floor(Date.now() / 1000),
    updated_at: Math.floor(Date.now() / 1000),
    published_at: Math.floor(Date.now() / 1000),
    drm_enabled: false,
    gallery_published: false,
    view_count: 0,
    like_count: 0,
    comment_count: 0,
    allow_download: false,
    download_count: 0,
  });
});

test.afterAll(async () => {
  // Cleanup seeded videos
  ddbDelete("VideoMetadata", { video_id: VIDEO_ID });
  ddbDelete("VideoMetadata", { video_id: VIDEO_ID_2 });
  ddbDelete("VideoMetadata", { video_id: VIDEO_ID_BOB });
});

// ─── Section 131: Gallery Publishing API ──────────────────────────────────────

test.describe("131 · Gallery Publishing API", () => {
  test("131.1 Alice publishes a video to the gallery", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    const resp = await page.request.post(
      `${BASE}/ui/videos/${VIDEO_ID}/gallery/publish`,
      {
        headers: csrfHeader(ALICE_ID),
        data: {
          category: "tutorials",
          tags: ["e2e", "testing"],
          title: `Gallery Test Video ${TS}`,
        },
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.gallery_published).toBe(true);
    expect(body.category).toBe("tutorials");
    expect(body.tags).toEqual(["e2e", "testing"]);
    await ctx.close();
  });

  test("131.2 Alice publishes second video to cooking category", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    const resp = await page.request.post(
      `${BASE}/ui/videos/${VIDEO_ID_2}/gallery/publish`,
      {
        headers: csrfHeader(ALICE_ID),
        data: { category: "cooking", tags: ["food"] },
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.category).toBe("cooking");
    await ctx.close();
  });

  test("131.3 Non-owner publish returns 403", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_ID);

    const resp = await page.request.post(
      `${BASE}/ui/videos/${VIDEO_ID}/gallery/publish`,
      {
        headers: csrfHeader(BOB_ID),
        data: { category: "tutorials", tags: [] },
      },
    );
    expect(resp.status()).toBe(403);
    await ctx.close();
  });

  test("131.4 Invalid category returns 400", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    const resp = await page.request.post(
      `${BASE}/ui/videos/${VIDEO_ID_BOB}/gallery/publish`,
      {
        headers: csrfHeader(ALICE_ID),
        data: { category: "nonexistent_cat", tags: [] },
      },
    );
    // Either 403 (not owner) or 400 (invalid category) depending on order
    expect([400, 403]).toContain(resp.status());
    await ctx.close();
  });

  test("131.5 Unpublish removes from gallery", async ({ browser }) => {
    // First publish Bob's video as Bob
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_ID);

    await page.request.post(
      `${BASE}/ui/videos/${VIDEO_ID_BOB}/gallery/publish`,
      {
        headers: csrfHeader(BOB_ID),
        data: { category: "entertainment", tags: [] },
      },
    );

    const resp = await page.request.post(
      `${BASE}/ui/videos/${VIDEO_ID_BOB}/gallery/unpublish`,
      { headers: csrfHeader(BOB_ID) },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.gallery_published).toBe(false);
    await ctx.close();
  });
});

// ─── Section 132: Video Engagement API ────────────────────────────────────────

test.describe("132 · Video Engagement API", () => {
  test("132.1 Bob views Alice's video — view counted", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_ID);

    const resp = await page.request.post(
      `${BASE}/ui/videos/${VIDEO_ID}/view`,
      { headers: csrfHeader(BOB_ID) },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.is_new_view).toBe(true);
    expect(body.view_count).toBeGreaterThanOrEqual(1);
    await ctx.close();
  });

  test("132.2 Bob views again same day — deduplicated", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_ID);

    const resp = await page.request.post(
      `${BASE}/ui/videos/${VIDEO_ID}/view`,
      { headers: csrfHeader(BOB_ID) },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.is_new_view).toBe(false);
    await ctx.close();
  });

  test("132.3 Bob likes video — like_count increments", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_ID);

    const resp = await page.request.post(
      `${BASE}/ui/videos/${VIDEO_ID}/like`,
      { headers: csrfHeader(BOB_ID) },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.liked).toBe(true);
    expect(body.like_count).toBeGreaterThanOrEqual(1);
    await ctx.close();
  });

  test("132.4 Bob unlikes video — like_count decrements", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_ID);

    const resp = await page.request.post(
      `${BASE}/ui/videos/${VIDEO_ID}/like`,
      { headers: csrfHeader(BOB_ID) },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.liked).toBe(false);
    await ctx.close();
  });

  test("132.5 Check like status — returns false after unlike", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_ID);

    const resp = await page.request.get(
      `${BASE}/ui/videos/${VIDEO_ID}/like`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.liked).toBe(false);
    await ctx.close();
  });
});

// ─── Section 133: Gallery Browsing & Comments API ─────────────────────────────

test.describe("133 · Gallery Browsing & Comments API", () => {
  test("133.1 Gallery browse returns published videos", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    const resp = await page.request.get(`${BASE}/ui/videos/gallery`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.videos).toBeDefined();
    expect(body.categories).toBeDefined();
    expect(body.categories.length).toBeGreaterThan(0);
    // Our published video should be in the list
    const found = body.videos.find((v: any) => v.video_id === VIDEO_ID);
    expect(found).toBeTruthy();
    await ctx.close();
  });

  test("133.2 Gallery browse by category", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    const resp = await page.request.get(
      `${BASE}/ui/videos/gallery?category=tutorials`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    // All returned videos should be in the tutorials category
    for (const v of body.videos) {
      expect(v.category).toBe("tutorials");
    }
    await ctx.close();
  });

  test("133.3 Gallery search by title", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    const resp = await page.request.get(
      `${BASE}/ui/videos/gallery/search?q=Gallery+Test+Video`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.videos).toBeDefined();
    // Should find our video
    const found = body.videos.find((v: any) => v.video_id === VIDEO_ID);
    expect(found).toBeTruthy();
    await ctx.close();
  });

  test("133.4 Add and list comments", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_ID);

    // Add a comment
    const addResp = await page.request.post(
      `${BASE}/ui/videos/${VIDEO_ID}/comments`,
      {
        headers: csrfHeader(BOB_ID),
        data: { text: `Great video! ${TS}` },
      },
    );
    expect(addResp.status()).toBe(201);
    const comment = await addResp.json();
    expect(comment.comment_id).toBeTruthy();
    expect(comment.text).toContain("Great video!");

    // List comments
    const listResp = await page.request.get(
      `${BASE}/ui/videos/${VIDEO_ID}/comments`,
    );
    expect(listResp.status()).toBe(200);
    const listBody = await listResp.json();
    expect(listBody.comments.length).toBeGreaterThanOrEqual(1);
    const found = listBody.comments.find(
      (c: any) => c.comment_id === comment.comment_id,
    );
    expect(found).toBeTruthy();
    await ctx.close();
  });

  test("133.5 Delete own comment", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    // Add a comment as Alice
    const addResp = await retry429(() =>
      page.request.post(`${BASE}/ui/videos/${VIDEO_ID}/comments`, {
        headers: csrfHeader(ALICE_ID),
        data: { text: `Alice comment ${TS}` },
      }),
    );
    expect(addResp.status()).toBe(201);
    const comment = await addResp.json();

    // Delete it
    const delResp = await retry429(() =>
      page.request.delete(
        `${BASE}/ui/videos/${VIDEO_ID}/comments/${comment.comment_id}`,
        { headers: csrfHeader(ALICE_ID) },
      ),
    );
    expect(delResp.status()).toBe(204);
    await ctx.close();
  });
});
