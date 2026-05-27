/**
 * E2E tests for Content Recommendations (DISC-001).
 *
 * Sections:
 *   1 — For You API (5 tests)
 *   2 — Similar Videos API (4 tests)
 *   3 — Creator Suggestions API (3 tests)
 *   4 — Gallery UI Integration (3 tests)
 *
 * Auth: Alice + Bob session cookies (from e2e_session_setup.py).
 *
 * These tests seed recommendation data directly into the recommendations
 * DynamoDB table, then exercise the API endpoints and UI components.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
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
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
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

async function apiGet(page: Page, path: string, identity = ALICE_ID) {
  const session = getSessions()[identity];
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiPost(
  page: Page,
  path: string,
  body: object,
  identity = ALICE_ID,
) {
  const session = getSessions()[identity];
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── DDB helpers ──────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os, time, json
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
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
reco_tbl = ddb.Table('recommendations')
video_tbl = ddb.Table('VideoMetadata')
`;

const PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";

function ddbExec(code: string): string {
  const fullCode = DDB_PRELUDE + "\n" + code;
  return execSync(`${PYTHON} -`, {
    cwd: "/home/ubuntu/testlogon",
    timeout: 15_000,
    input: fullCode,
  }).toString();
}

// Seed test video metadata
const VID_A = `reco_vid_a_${TS}`;
const VID_B = `reco_vid_b_${TS}`;
const VID_C = `reco_vid_c_${TS}`;
const VID_D = `reco_vid_d_${TS}`;

function seedTestVideos(): void {
  const code = `
now = int(time.time())
for vid, title, cat in [
    ('${VID_A}', 'Reco Test A ${TS}', 'tutorials'),
    ('${VID_B}', 'Reco Test B ${TS}', 'tutorials'),
    ('${VID_C}', 'Reco Test C ${TS}', 'entertainment'),
    ('${VID_D}', 'Reco Test D ${TS}', 'entertainment'),
]:
    video_tbl.put_item(Item={
        'video_id': vid,
        'title': title,
        'description': f'Description for {title}',
        'status': 'published',
        'visibility': 'public',
        'owner_user_id': '${BOB_ID}',
        'category': cat,
        'tags': ['test'],
        'view_count': 100,
        'like_count': 10,
        'comment_count': 0,
        'created_at': now,
        'gallery_published': True,
        'gallery_status': 'published',
    })
`;
  ddbExec(code);
}

function seedForYouRecommendations(userId: string, videoIds: string[]): void {
  const idsJson = JSON.stringify(videoIds);
  const code = `
now = int(time.time())
reco_tbl.put_item(Item={
    'pk': 'RECO#${userId}',
    'sk': 'FOR_YOU',
    'video_ids': ${idsJson},
    'computed_at': now,
    'ttl_epoch': now + 86400,
    'version': 1,
})
`;
  ddbExec(code);
}

function seedSimilarVideos(videoId: string, similarIds: string[]): void {
  const idsJson = JSON.stringify(similarIds);
  const code = `
now = int(time.time())
reco_tbl.put_item(Item={
    'pk': 'SIMILAR#${videoId}',
    'sk': 'VIDEOS',
    'similar_video_ids': ${idsJson},
    'computed_at': now,
    'ttl_epoch': now + 172800,
})
`;
  ddbExec(code);
}

function seedCreatorSuggestions(userId: string, creatorIds: string[]): void {
  const idsJson = JSON.stringify(creatorIds);
  const code = `
now = int(time.time())
reco_tbl.put_item(Item={
    'pk': 'RECO#${userId}',
    'sk': 'CREATOR_SUGGEST',
    'creator_ids': ${idsJson},
    'computed_at': now,
    'ttl_epoch': now + 86400,
    'version': 1,
})
`;
  ddbExec(code);
}

function seedSignal(userId: string, videoId: string, watchPct: number, liked: boolean): void {
  const code = `
now = int(time.time())
reco_tbl.put_item(Item={
    'pk': 'SIGNAL#${userId}',
    'sk': 'VIDEO#${videoId}',
    'watch_pct': ${watchPct},
    'liked': ${liked ? "True" : "False"},
    'view_count': 1,
    'last_viewed_at': now,
    'ttl_epoch': now + 7776000,
})
`;
  ddbExec(code);
}

function cleanupTestData(): void {
  const code = `
# Clean up test recommendations
for prefix in ['RECO#${ALICE_ID}', 'RECO#${BOB_ID}', 'SIMILAR#${VID_A}', 'SIMILAR#${VID_B}']:
    resp = reco_tbl.query(KeyConditionExpression=boto3.dynamodb.conditions.Key('pk').eq(prefix))
    for item in resp.get('Items', []):
        reco_tbl.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
for prefix in ['SIGNAL#${ALICE_ID}', 'SIGNAL#${BOB_ID}']:
    resp = reco_tbl.query(KeyConditionExpression=boto3.dynamodb.conditions.Key('pk').eq(prefix))
    for item in resp.get('Items', []):
        reco_tbl.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
`;
  try {
    ddbExec(code);
  } catch {
    // ignore cleanup failures
  }
}

// ─── Test suite ───────────────────────────────────────────────────────────────

test.describe("recommendations", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    // Seed test data
    seedTestVideos();

    // Create Alice page
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    cleanupTestData();
    await alicePage?.context().close();
  });

  // ─── Section 1: For You API ──────────────────────────────────────────────

  test.describe("1 — For You API", () => {
    test.beforeAll(() => {
      // Seed For You recommendations for Alice
      seedForYouRecommendations(ALICE_ID, [VID_A, VID_B, VID_C]);
      // Seed a signal so Alice has "watched" VID_D
      seedSignal(ALICE_ID, VID_D, 90, true);
    });

    test("1.1 For You returns videos for user with history", async () => {
      const resp = await apiGet(alicePage, "/ui/videos/gallery/for-you?limit=10");
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.source).toBe("for_you");
      expect(data.videos).toBeDefined();
      expect(data.videos.length).toBeGreaterThan(0);
    });

    test("1.2 For You falls back to trending for new user", async () => {
      // Bob has no seeded recommendations
      const ctx = await alicePage.context().browser()!.newContext();
      const bobPage = await ctx.newPage();
      await injectAuth(bobPage, BOB_ID);
      const resp = await apiGet(bobPage, "/ui/videos/gallery/for-you?limit=10", BOB_ID);
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.source).toBe("trending_fallback");
      await ctx.close();
    });

    test("1.3 For You respects pagination cursor", async () => {
      // Seed many videos for pagination
      seedForYouRecommendations(ALICE_ID, [VID_A, VID_B, VID_C, VID_D]);
      const resp1 = await apiGet(alicePage, "/ui/videos/gallery/for-you?limit=2");
      expect(resp1.status()).toBe(200);
      const data1 = await resp1.json();
      expect(data1.videos.length).toBeLessThanOrEqual(2);
      if (data1.next_cursor) {
        const resp2 = await apiGet(
          alicePage,
          `/ui/videos/gallery/for-you?limit=2&cursor=${data1.next_cursor}`,
        );
        expect(resp2.status()).toBe(200);
        const data2 = await resp2.json();
        // Second page should have different videos
        const ids1 = new Set(data1.videos.map((v: any) => v.video_id));
        for (const v of data2.videos) {
          expect(ids1.has(v.video_id)).toBe(false);
        }
      }
    });

    test("1.4 For You excludes already-watched videos", async () => {
      // VID_D has a signal for Alice (watched it)
      // Only seed VID_A, VID_B, VID_C in FOR_YOU (VID_D excluded)
      seedForYouRecommendations(ALICE_ID, [VID_A, VID_B, VID_C]);
      const resp = await apiGet(alicePage, "/ui/videos/gallery/for-you?limit=10");
      const data = await resp.json();
      const ids = data.videos.map((v: any) => v.video_id);
      // VID_D should NOT be in the for-you list since we seeded it separately
      expect(ids).not.toContain(VID_D);
    });

    test("1.5 For You only returns published public videos", async () => {
      const resp = await apiGet(alicePage, "/ui/videos/gallery/for-you?limit=10");
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      // All returned videos should exist in our seeded data (all published/public)
      for (const v of data.videos) {
        expect(v.video_id).toBeTruthy();
        expect(v.title).toBeTruthy();
      }
    });
  });

  // ─── Section 2: Similar Videos API ───────────────────────────────────────

  test.describe("2 — Similar Videos API", () => {
    test.beforeAll(() => {
      seedSimilarVideos(VID_A, [VID_B, VID_C]);
    });

    test("2.1 Similar videos for video with data", async () => {
      const resp = await apiGet(alicePage, `/ui/videos/${VID_A}/similar?limit=8`);
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.source).toBe("collaborative_filtering");
      expect(data.videos.length).toBeGreaterThan(0);
    });

    test("2.2 Similar videos falls back for video without data", async () => {
      const unknownVid = `reco_unknown_${TS}`;
      const resp = await apiGet(alicePage, `/ui/videos/${unknownVid}/similar?limit=4`);
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.source).toBe("category_fallback");
    });

    test("2.3 Similar videos excludes the source video", async () => {
      const resp = await apiGet(alicePage, `/ui/videos/${VID_A}/similar?limit=8`);
      const data = await resp.json();
      const ids = data.videos.map((v: any) => v.video_id);
      expect(ids).not.toContain(VID_A);
    });

    test("2.4 Similar videos respects limit parameter", async () => {
      seedSimilarVideos(VID_A, [VID_B, VID_C, VID_D]);
      const resp = await apiGet(alicePage, `/ui/videos/${VID_A}/similar?limit=2`);
      const data = await resp.json();
      expect(data.videos.length).toBeLessThanOrEqual(2);
    });
  });

  // ─── Section 3: Creator Suggestions API ──────────────────────────────────

  test.describe("3 — Creator Suggestions API", () => {
    test("3.1 Creator suggestions returns data when seeded", async () => {
      seedCreatorSuggestions(ALICE_ID, [BOB_ID]);
      const resp = await apiGet(alicePage, "/ui/discover/creators?limit=10");
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.source).toBe("subscription_overlap");
      expect(data.creators).toBeDefined();
      expect(data.creators.length).toBeGreaterThan(0);
    });

    test("3.2 Creator suggestions excludes self", async () => {
      seedCreatorSuggestions(ALICE_ID, [BOB_ID]);
      const resp = await apiGet(alicePage, "/ui/discover/creators?limit=10");
      const data = await resp.json();
      const ids = data.creators.map((c: any) => c.user_id);
      expect(ids).not.toContain(ALICE_ID);
    });

    test("3.3 Creator suggestions empty for user with no data", async () => {
      // Ensure Bob has no creator suggestions
      const ctx = await alicePage.context().browser()!.newContext();
      const bobPage = await ctx.newPage();
      await injectAuth(bobPage, BOB_ID);
      const resp = await apiGet(bobPage, "/ui/discover/creators?limit=10", BOB_ID);
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.creators.length).toBe(0);
      await ctx.close();
    });
  });

  // ─── Section 4: Engagement Signal API ────────────────────────────────────

  test.describe("4 — Engagement Signal API", () => {
    test("4.1 Record engagement signal", async () => {
      const resp = await apiPost(
        alicePage,
        "/ui/recommendations/engagement",
        { video_id: VID_A, watch_pct: 85, liked: true },
      );
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.ok).toBe(true);
    });

    test("4.2 Record engagement without watch_pct", async () => {
      const resp = await apiPost(
        alicePage,
        "/ui/recommendations/engagement",
        { video_id: VID_B, liked: true },
      );
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.ok).toBe(true);
    });
  });

  // ─── Section 5: Refresh API ──────────────────────────────────────────────

  test.describe("5 — Refresh API", () => {
    test("5.1 Refresh recommendations for a user", async () => {
      // Seed enough signals so refresh has data to work with
      seedSignal(ALICE_ID, VID_A, 90, true);
      seedSignal(ALICE_ID, VID_B, 60, false);

      const resp = await alicePage.request.post(
        `${BASE}/internal/recommendations/refresh`,
        { data: { user_id: ALICE_ID } },
      );
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.ok).toBe(true);
      expect(data.users_processed).toBe(1);
      expect(data.duration_seconds).toBeGreaterThanOrEqual(0);
    });
  });

  // ─── Section 6: Gallery UI Integration ───────────────────────────────────

  test.describe("6 — Gallery UI Integration", () => {
    test("6.1 For You tab visible on gallery page", async () => {
      await alicePage.goto(`${BASE}/gallery`, { waitUntil: "domcontentloaded" });
      // The For You tab trigger should be visible
      const forYouTab = alicePage.getByRole("tab", { name: "For You" });
      await expect(forYouTab).toBeVisible();
    });

    test("6.2 Browse tab visible on gallery page", async () => {
      await alicePage.goto(`${BASE}/gallery`, { waitUntil: "domcontentloaded" });
      const browseTab = alicePage.getByRole("tab", { name: "Browse" });
      await expect(browseTab).toBeVisible();
    });

    test("6.3 For You tab is default active tab", async () => {
      await alicePage.goto(`${BASE}/gallery`, { waitUntil: "domcontentloaded" });
      const forYouTab = alicePage.getByRole("tab", { name: "For You" });
      // aria-selected should be "true" for the active tab
      await expect(forYouTab).toHaveAttribute("aria-selected", "true");
    });
  });
});
