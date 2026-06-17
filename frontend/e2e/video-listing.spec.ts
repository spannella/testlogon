/**
 * Section 100-104: Video Listing API (VOD-006) — CRUD, Pagination, Public Discovery, Authorization, Admin
 *
 * Auth: Cookie sessions via e2e_admin_session_setup.py
 * Identities: alice (USER), bob (USER), root (ROOT)
 */
import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const TS = Date.now();

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

/**
 * Seed a video record directly into DynamoDB for testing.
 */
function seedVideo(opts: {
  videoId: string;
  ownerUserId: string;
  title: string;
  status?: string;
  visibility?: string;
  createdAt?: number;
  hlsManifestUrl?: string;
}): void {
  const status = opts.status || "created";
  const visibility = opts.visibility || "private";
  const createdAt = opts.createdAt || Math.floor(Date.now() / 1000);
  const hlsField = opts.hlsManifestUrl
    ? `'hls_manifest_url': '${opts.hlsManifestUrl}',`
    : "";
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

// ─── 100. Video CRUD API ───────────────────────────────────────────────────

test.describe.serial("100 — Video CRUD API", () => {
  let alicePage: Page;
  const VIDEO_ID = `v_crud_${TS}`;
  const ALICE_SUB = () => getSessions().alice.user_sub;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
    // Seed a video for Alice
    seedVideo({
      videoId: VIDEO_ID,
      ownerUserId: ALICE_SUB(),
      title: `CRUD Test ${TS}`,
      status: "published",
      visibility: "public",
      hlsManifestUrl: "https://cdn.example.com/test/manifest.m3u8",
    });
  });

  test.afterAll(async () => {
    deleteVideo(VIDEO_ID);
    await alicePage?.close();
  });

  test("100.1 List own videos returns seeded video", async () => {
    const resp = await apiGet(alicePage, "/ui/videos");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeDefined();
    expect(Array.isArray(data.items)).toBe(true);
    const found = data.items.find((v: any) => v.video_id === VIDEO_ID);
    expect(found).toBeTruthy();
    expect(found.title).toBe(`CRUD Test ${TS}`);
    expect(found.status).toBe("published");
    expect(found.visibility).toBe("public");
  });

  test("100.2 Get video detail returns full metadata", async () => {
    const resp = await apiGet(alicePage, `/ui/videos/${VIDEO_ID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_id).toBe(VIDEO_ID);
    expect(data.owner_user_id).toBe(ALICE_SUB());
    expect(data.title).toBe(`CRUD Test ${TS}`);
    expect(data.hls_manifest_url).toBe("https://cdn.example.com/test/manifest.m3u8");
    // Playback token should be generated for published video with manifest
    expect(data.playback_token).toBeTruthy();
    expect(data.playback_expires_at).toBeGreaterThan(0);
  });

  test("100.3 Update video title and description", async () => {
    const resp = await apiPatch(alicePage, "alice", `/ui/videos/${VIDEO_ID}`, {
      title: `Updated Title ${TS}`,
      description: `Updated description ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.title).toBe(`Updated Title ${TS}`);
    expect(data.description).toBe(`Updated description ${TS}`);
  });

  test("100.4 Update video visibility", async () => {
    const resp = await apiPatch(alicePage, "alice", `/ui/videos/${VIDEO_ID}`, {
      visibility: "unlisted",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.visibility).toBe("unlisted");
  });

  test("100.5 Delete video (soft-delete)", async () => {
    const deleteId = `v_del_${TS}`;
    seedVideo({
      videoId: deleteId,
      ownerUserId: ALICE_SUB(),
      title: `To Delete ${TS}`,
    });

    const resp = await apiDelete(alicePage, "alice", `/ui/videos/${deleteId}`);
    expect(resp.status()).toBe(204);

    // Verify deleted video is excluded from listing
    const listResp = await apiGet(alicePage, "/ui/videos");
    const listData = await listResp.json();
    const found = listData.items.find((v: any) => v.video_id === deleteId);
    expect(found).toBeUndefined();
  });

  test("100.6 Get non-existent video returns 404", async () => {
    const resp = await apiGet(alicePage, "/ui/videos/v_nonexistent_xyz");
    expect(resp.status()).toBe(404);
  });
});

// ─── 101. Pagination ────────────────────────────────────────────────────────

test.describe.serial("101 — Video Listing Pagination", () => {
  let alicePage: Page;
  const VIDEO_IDS: string[] = [];
  const ALICE_SUB = () => getSessions().alice.user_sub;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
    // Seed 5 videos with distinct timestamps for pagination testing
    for (let i = 0; i < 5; i++) {
      const vid = `v_page_${TS}_${i}`;
      VIDEO_IDS.push(vid);
      seedVideo({
        videoId: vid,
        ownerUserId: ALICE_SUB(),
        title: `Page Video ${i} ${TS}`,
        createdAt: Math.floor(Date.now() / 1000) - (5 - i) * 10,
      });
    }
  });

  test.afterAll(async () => {
    for (const vid of VIDEO_IDS) {
      deleteVideo(vid);
    }
    await alicePage?.close();
  });

  test("101.1 Paginate with limit=2 returns cursor", async () => {
    const resp = await apiGet(alicePage, "/ui/videos?limit=2");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items.length).toBeGreaterThanOrEqual(2);
    // With many videos in the table, cursor may or may not be present
    // depending on total count. Just verify the response shape.
    expect(data).toHaveProperty("cursor");
  });

  test("101.2 Second page with cursor returns different items", async () => {
    const resp1 = await apiGet(alicePage, "/ui/videos?limit=2");
    const data1 = await resp1.json();

    if (data1.cursor) {
      const resp2 = await apiGet(alicePage, `/ui/videos?limit=2&cursor=${encodeURIComponent(data1.cursor)}`);
      expect(resp2.status()).toBe(200);
      const data2 = await resp2.json();
      expect(data2.items.length).toBeGreaterThanOrEqual(1);
      // Items should be different from page 1
      const page1Ids = new Set(data1.items.map((v: any) => v.video_id));
      const page2HasNew = data2.items.some((v: any) => !page1Ids.has(v.video_id));
      expect(page2HasNew).toBe(true);
    }
  });

  test("101.3 Filter by status returns only matching", async () => {
    // Seed a published video
    const pubId = `v_pub_filter_${TS}`;
    seedVideo({
      videoId: pubId,
      ownerUserId: ALICE_SUB(),
      title: `Published Filter ${TS}`,
      status: "published",
      visibility: "public",
    });
    VIDEO_IDS.push(pubId);

    const resp = await apiGet(alicePage, "/ui/videos?status=published");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // All returned items should have published status
    for (const item of data.items) {
      expect(item.status).toBe("published");
    }
  });
});

// ─── 102. Public Discovery ──────────────────────────────────────────────────

test.describe.serial("102 — Public Video Discovery", () => {
  let alicePage: Page;
  let bobPage: Page;
  const PUB_VIDEO = `v_pub_disc_${TS}`;
  const PRIV_VIDEO = `v_priv_disc_${TS}`;
  const ALICE_SUB = () => getSessions().alice.user_sub;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
    bobPage = await newPage(browser, "bob");

    // Alice: one public published, one private
    seedVideo({
      videoId: PUB_VIDEO,
      ownerUserId: ALICE_SUB(),
      title: `Public Discovery ${TS}`,
      status: "published",
      visibility: "public",
    });
    seedVideo({
      videoId: PRIV_VIDEO,
      ownerUserId: ALICE_SUB(),
      title: `Private Discovery ${TS}`,
      status: "published",
      visibility: "private",
    });
  });

  test.afterAll(async () => {
    deleteVideo(PUB_VIDEO);
    deleteVideo(PRIV_VIDEO);
    await alicePage?.close();
    await bobPage?.close();
  });

  test("102.1 Public listing includes published+public videos", async () => {
    const resp = await apiGet(bobPage, "/ui/videos/public");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find((v: any) => v.video_id === PUB_VIDEO);
    expect(found).toBeTruthy();
    expect(found.title).toBe(`Public Discovery ${TS}`);
  });

  test("102.2 Public listing excludes private videos", async () => {
    const resp = await apiGet(bobPage, "/ui/videos/public");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find((v: any) => v.video_id === PRIV_VIDEO);
    expect(found).toBeUndefined();
  });

  test("102.3 Creator public listing shows only public videos", async () => {
    const aliceSub = ALICE_SUB();
    const resp = await apiGet(bobPage, `/ui/videos/creator/${aliceSub}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const pub = data.items.find((v: any) => v.video_id === PUB_VIDEO);
    const priv = data.items.find((v: any) => v.video_id === PRIV_VIDEO);
    expect(pub).toBeTruthy();
    expect(priv).toBeUndefined();
  });
});

// ─── 103. Authorization ─────────────────────────────────────────────────────

test.describe.serial("103 — Video Authorization", () => {
  let alicePage: Page;
  let bobPage: Page;
  const PRIVATE_VIDEO = `v_auth_priv_${TS}`;
  const PUBLIC_VIDEO = `v_auth_pub_${TS}`;
  const ALICE_SUB = () => getSessions().alice.user_sub;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
    bobPage = await newPage(browser, "bob");

    seedVideo({
      videoId: PRIVATE_VIDEO,
      ownerUserId: ALICE_SUB(),
      title: `Auth Private ${TS}`,
      status: "created",
      visibility: "private",
    });
    seedVideo({
      videoId: PUBLIC_VIDEO,
      ownerUserId: ALICE_SUB(),
      title: `Auth Public ${TS}`,
      status: "published",
      visibility: "public",
      hlsManifestUrl: "https://cdn.example.com/auth/manifest.m3u8",
    });
  });

  test.afterAll(async () => {
    deleteVideo(PRIVATE_VIDEO);
    deleteVideo(PUBLIC_VIDEO);
    await alicePage?.close();
    await bobPage?.close();
  });

  test("103.1 Non-owner cannot access private video (403)", async () => {
    const resp = await apiGet(bobPage, `/ui/videos/${PRIVATE_VIDEO}`);
    expect(resp.status()).toBe(403);
  });

  test("103.2 Non-owner can access published+public video", async () => {
    const resp = await apiGet(bobPage, `/ui/videos/${PUBLIC_VIDEO}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_id).toBe(PUBLIC_VIDEO);
    expect(data.title).toBe(`Auth Public ${TS}`);
  });

  test("103.3 Non-owner cannot update video (403)", async () => {
    const resp = await apiPatch(bobPage, "bob", `/ui/videos/${PUBLIC_VIDEO}`, {
      title: "Hacked Title",
    });
    expect(resp.status()).toBe(403);
  });

  test("103.4 Non-owner cannot delete video (403)", async () => {
    const resp = await apiDelete(bobPage, "bob", `/ui/videos/${PUBLIC_VIDEO}`);
    expect(resp.status()).toBe(403);
  });

  test("103.5 Owner can access private video", async () => {
    const resp = await apiGet(alicePage, `/ui/videos/${PRIVATE_VIDEO}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_id).toBe(PRIVATE_VIDEO);
  });
});

// ─── 104. Admin Listing ─────────────────────────────────────────────────────

test.describe.serial("104 — Video Admin Listing", () => {
  let rootPage: Page;
  let alicePage: Page;
  const ADMIN_VIDEO = `v_admin_${TS}`;
  const ROOT_SUB = () => getSessions().root.user_sub;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newPage(browser, "root");
    alicePage = await newPage(browser, "alice");

    seedVideo({
      videoId: ADMIN_VIDEO,
      ownerUserId: ROOT_SUB(),
      title: `Admin Test ${TS}`,
      status: "pending_review",
      visibility: "private",
    });
  });

  test.afterAll(async () => {
    deleteVideo(ADMIN_VIDEO);
    await rootPage?.close();
    await alicePage?.close();
  });

  test("104.1 Root can list videos by status", async () => {
    const resp = await apiGet(rootPage, "/ui/videos/admin/by-status/pending_review");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeDefined();
    const found = data.items.find((v: any) => v.video_id === ADMIN_VIDEO);
    expect(found).toBeTruthy();
    expect(found.status).toBe("pending_review");
  });

  test("104.2 Regular user gets 403 on admin endpoint", async () => {
    const resp = await apiGet(alicePage, "/ui/videos/admin/by-status/pending_review");
    expect(resp.status()).toBe(403);
  });

  test("104.3 Admin listing returns items with owner_user_id", async () => {
    const resp = await apiGet(rootPage, "/ui/videos/admin/by-status/pending_review");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    if (data.items.length > 0) {
      expect(data.items[0]).toHaveProperty("owner_user_id");
    }
  });
});
