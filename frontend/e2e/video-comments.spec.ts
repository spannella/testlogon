/**
 * E2E tests — Video comment parity with newsfeed comments.
 *
 * Features tested (all under /ui/videos/{video_id}/comments):
 *  - POST comment (text)
 *  - Reply (parent_comment_id)
 *  - React / unreact + counts (POST .../reactions, /unreact)
 *  - Edit — author gets 200, non-author gets 403 (PATCH .../comments/:cid)
 *  - GIF comment (kind=gif)
 *  - Image comment (kind=image + uploaded URL)
 *  - Report via /moderation/reports (content_type=video_comment + video_id)
 *  - Unknown comment → 404 on report
 *
 * UI affordances in VideoDetailPage.tsx:
 *  - video-comment-image-button / video-comment-image-input / video-comment-image-preview
 *  - data-testid="video-comment-image"
 *  - Reply button, reaction bar, edit/delete/report dropdown
 *
 * Video setup: create a video via presign → PATCH to published+public so
 * VideoDetailPage can render it.  All tests share one seeded video_id.
 */

import { tmpdir } from "os";
import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const PYTHON = REPO_ROOT + "/.venv/bin/python3";

// ─── Session bootstrap ─────────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None";
    expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;

function getAdminSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    const lastLine = raw.trim().split("\n").at(-1)!;
    _sessions = JSON.parse(lastLine);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getAdminSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  // Use addInitScript so auth-store is pre-seeded before the page loads
  await page.addInitScript((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
}

function apiPost(page: Page, path: string, body: object, identity = "alice") {
  const session = getAdminSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

function apiPatch(page: Page, path: string, body: object, identity = "alice") {
  const session = getAdminSessions()[identity];
  return page.request.patch(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function uploadTestImage(page: Page, identity = "alice"): Promise<string> {
  const session = getAdminSessions()[identity];
  const pngPath = `${tmpdir()}/e2e_vid_${Date.now()}.png`;
  execSync(
    `${PYTHON} -c "
import struct, zlib
def write_png(path):
    def chunk(name, data):
        c = struct.pack('>I', len(data)) + name + data
        return c + struct.pack('>I', zlib.crc32(name + data) & 0xffffffff)
    raw = b'\\x89PNG\\r\\n\\x1a\\n'
    raw += chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
    raw += chunk(b'IDAT', zlib.compress(b'\\x00\\xff\\x00\\x00'))
    raw += chunk(b'IEND', b'')
    open(path, 'wb').write(raw)
write_png('${pngPath}')
"`,
    { timeout: 5_000 },
  );
  const fileBytes = fs.readFileSync(pngPath);
  const resp = await page.request.post(`${API}/uploads/image`, {
    headers: { "x-csrf-token": session.csrf_token },
    multipart: {
      file: { name: "test.png", mimeType: "image/png", buffer: fileBytes },
    },
  });
  expect(resp.ok(), `Image upload failed: ${await resp.text()}`).toBe(true);
  const data = await resp.json() as { url: string };
  return data.url;
}

// ─── Video seeding ─────────────────────────────────────────────────────────────

/**
 * Seed a published public video owned by Alice.
 * Uses presign + PATCH to mark it published+public.
 * The video has no actual media bytes (just the metadata record).
 */
async function seedVideo(page: Page): Promise<string> {
  const session = getAdminSessions()["alice"];
  const headers = { "x-csrf-token": session.csrf_token };

  // Presign
  const presignResp = await page.request.post(`${API}/ui/videos/upload/presign`, {
    data: {
      filename: "e2e_test.mp4",
      content_type: "video/mp4",
      file_size_bytes: 1024,
    },
    headers,
  });
  expect(presignResp.ok(), `Presign failed: ${await presignResp.text()}`).toBe(true);
  const { video_id } = await presignResp.json() as { video_id: string };

  // Mark published + public
  const patchResp = await page.request.patch(`${API}/ui/videos/${video_id}`, {
    data: {
      title: `E2E Test Video ${Date.now()}`,
      description: "Created by E2E video-comments.spec",
      status: "published",
      visibility: "public",
    },
    headers,
  });
  expect(patchResp.ok(), `Patch failed: ${await patchResp.text()}`).toBe(true);
  return video_id;
}

// ─── 1. Video comment CRUD ─────────────────────────────────────────────────────

test.describe("1. Video comment CRUD", () => {
  let page: Page;
  let videoId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
    videoId = await seedVideo(page);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("POST comment returns 201 with comment_id", async () => {
    const resp = await apiPost(page, `/ui/videos/${videoId}/comments`, {
      text: "Hello video!",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json() as { comment_id: string; video_id: string; text: string };
    expect(data.comment_id).toBeTruthy();
    expect(data.video_id).toBe(videoId);
    expect(data.text).toBe("Hello video!");
  });

  test("GET comments returns the new comment", async () => {
    const createResp = await apiPost(page, `/ui/videos/${videoId}/comments`, {
      text: `Visible comment ${Date.now()}`,
    });
    expect(createResp.status()).toBe(201);
    const { comment_id } = await createResp.json() as { comment_id: string };

    const listResp = await apiGet(page, `/ui/videos/${videoId}/comments`);
    expect(listResp.status()).toBe(200);
    const data = await listResp.json() as { comments: Array<{ comment_id: string }> };
    expect(Array.isArray(data.comments)).toBe(true);
    const found = data.comments.find((c) => c.comment_id === comment_id);
    expect(found).toBeTruthy();
  });

  test("DELETE comment succeeds for author (204)", async () => {
    const createResp = await apiPost(page, `/ui/videos/${videoId}/comments`, {
      text: "To be deleted",
    });
    expect(createResp.status()).toBe(201);
    const { comment_id } = await createResp.json() as { comment_id: string };

    const session = getAdminSessions()["alice"];
    const delResp = await page.request.delete(
      `${API}/ui/videos/${videoId}/comments/${comment_id}`,
      { headers: { "x-csrf-token": session.csrf_token } },
    );
    expect(delResp.status()).toBe(204);
  });
});

// ─── 2. Reply threading ───────────────────────────────────────────────────────

test.describe("2. Reply threading", () => {
  let alicePage: Page;
  let bobPage: Page;
  let videoId: string;
  let parentId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, "alice");
    bobPage = await browser.newPage();
    await injectAuth(bobPage, "bob");

    videoId = await seedVideo(alicePage);

    const resp = await apiPost(alicePage, `/ui/videos/${videoId}/comments`, {
      text: "Parent comment",
    });
    expect(resp.status()).toBe(201);
    ({ comment_id: parentId } = await resp.json() as { comment_id: string });
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("reply sets parent_comment_id on the child", async () => {
    // Bob replies to Alice's comment using Bob's own page (carries Bob's cookies)
    const resp = await apiPost(
      bobPage,
      `/ui/videos/${videoId}/comments`,
      { text: "Reply comment", parent_comment_id: parentId },
      "bob",
    );
    expect(resp.status()).toBe(201);
    const data = await resp.json() as { comment_id: string; parent_comment_id: string };
    expect(data.parent_comment_id).toBe(parentId);
  });

  test("GET comments — reply appears with correct parent_comment_id", async () => {
    const replyResp = await apiPost(
      bobPage,
      `/ui/videos/${videoId}/comments`,
      { text: `Thread reply ${Date.now()}`, parent_comment_id: parentId },
      "bob",
    );
    expect(replyResp.status()).toBe(201);
    const { comment_id: replyId } = await replyResp.json() as { comment_id: string };

    const listResp = await apiGet(alicePage, `/ui/videos/${videoId}/comments`);
    const { comments } = await listResp.json() as {
      comments: Array<{ comment_id: string; parent_comment_id: string | null }>;
    };
    const reply = comments.find((c) => c.comment_id === replyId);
    expect(reply).toBeTruthy();
    expect(reply!.parent_comment_id).toBe(parentId);
  });
});

// ─── 3. Reactions ─────────────────────────────────────────────────────────────

test.describe("3. Comment reactions", () => {
  let page: Page;
  let videoId: string;
  let commentId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
    videoId = await seedVideo(page);

    const resp = await apiPost(page, `/ui/videos/${videoId}/comments`, {
      text: "Reaction target",
    });
    expect(resp.status()).toBe(201);
    ({ comment_id: commentId } = await resp.json() as { comment_id: string });
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("react → comment has reactions_counts and my_reactions", async () => {
    const resp = await apiPost(
      page,
      `/ui/videos/${videoId}/comments/${commentId}/reactions`,
      { emoji: "❤️" },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json() as {
      reactions_counts: Record<string, number>;
      my_reactions: string[];
    };
    expect(data.reactions_counts["❤️"]).toBeGreaterThanOrEqual(1);
    expect(data.my_reactions).toContain("❤️");
  });

  test("unreact removes the reaction", async () => {
    // Ensure reacted
    await apiPost(
      page,
      `/ui/videos/${videoId}/comments/${commentId}/reactions`,
      { emoji: "👍" },
    );
    const resp = await apiPost(
      page,
      `/ui/videos/${videoId}/comments/${commentId}/unreact`,
      { emoji: "👍" },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { reactions_counts: Record<string, number>; my_reactions: string[] };
    expect(data.my_reactions).not.toContain("👍");
    expect(data.reactions_counts["👍"] ?? 0).toBe(0);
  });

  test("all 5 allowed emojis are accepted", async () => {
    const allowed = ["👍", "❤️", "😂", "🔥", "😮"];
    for (const emoji of allowed) {
      const resp = await apiPost(
        page,
        `/ui/videos/${videoId}/comments/${commentId}/reactions`,
        { emoji },
      );
      expect(resp.status(), `${emoji} should be accepted`).toBe(200);
    }
  });

  test("invalid emoji → 422", async () => {
    const resp = await apiPost(
      page,
      `/ui/videos/${videoId}/comments/${commentId}/reactions`,
      { emoji: "🌚" },
    );
    expect(resp.status()).toBe(422);
  });

  test("Bob reacts — Bob sees my_reactions populated", async ({ browser }) => {
    const bobPage = await browser.newPage();
    await injectAuth(bobPage, "bob");

    const bobSession = getAdminSessions()["bob"];
    await bobPage.request.post(
      `${API}/ui/videos/${videoId}/comments/${commentId}/reactions`,
      {
        data: { emoji: "😮" },
        headers: { "x-csrf-token": bobSession.csrf_token },
      },
    );

    // GET list as Bob
    const listResp = await bobPage.request.get(
      `${API}/ui/videos/${videoId}/comments`,
    );
    const { comments } = await listResp.json() as {
      comments: Array<{ comment_id: string; my_reactions: string[] }>;
    };
    const cmt = comments.find((c) => c.comment_id === commentId);
    expect(cmt?.my_reactions).toContain("😮");

    await bobPage.close();
  });
});

// ─── 4. Edit — author only ─────────────────────────────────────────────────────

test.describe("4. Edit comment — author only", () => {
  let page: Page;
  let videoId: string;
  let commentId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
    videoId = await seedVideo(page);

    const resp = await apiPost(page, `/ui/videos/${videoId}/comments`, {
      text: "Original text",
    });
    expect(resp.status()).toBe(201);
    ({ comment_id: commentId } = await resp.json() as { comment_id: string });
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("author (Alice) can edit own comment", async () => {
    const resp = await apiPatch(
      page,
      `/ui/videos/${videoId}/comments/${commentId}`,
      { text: "Edited by author" },
      "alice",
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { text: string; edited_at: number };
    expect(data.text).toBe("Edited by author");
    expect(data.edited_at).toBeTruthy();
  });

  test("non-author (Bob) cannot edit Alice's comment → 403", async () => {
    const resp = await apiPatch(
      page,
      `/ui/videos/${videoId}/comments/${commentId}`,
      { text: "Bob tries to edit" },
      "bob",
    );
    expect(resp.status()).toBe(403);
  });
});

// ─── 5. GIF comment ───────────────────────────────────────────────────────────

test.describe("5. GIF comment", () => {
  let page: Page;
  let videoId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
    videoId = await seedVideo(page);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("POST kind=gif comment returns comment with gif_url", async () => {
    const resp = await apiPost(page, `/ui/videos/${videoId}/comments`, {
      kind: "gif",
      gif_url: "https://media.tenor.com/test.gif",
      gif_alt_text: "Test GIF",
      gif_width: 200,
      gif_height: 200,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json() as {
      kind: string;
      gif_url: string;
      gif_alt_text: string;
    };
    expect(data.kind).toBe("gif");
    expect(data.gif_url).toBe("https://media.tenor.com/test.gif");
    expect(data.gif_alt_text).toBe("Test GIF");
  });

  test("GIF comment appears in list with kind=gif", async () => {
    // Use an allowed GIF CDN domain (media.giphy.com, not i.giphy.com)
    const createResp = await apiPost(page, `/ui/videos/${videoId}/comments`, {
      kind: "gif",
      gif_url: "https://media.giphy.com/visible.gif",
      gif_alt_text: "Visible GIF",
      gif_width: 100,
      gif_height: 100,
    });
    expect(createResp.status()).toBe(201);
    const { comment_id } = await createResp.json() as { comment_id: string };

    const listResp = await apiGet(page, `/ui/videos/${videoId}/comments`);
    const { comments } = await listResp.json() as {
      comments: Array<{ comment_id: string; kind: string; gif_url: string | null }>;
    };
    const found = comments.find((c) => c.comment_id === comment_id);
    expect(found).toBeTruthy();
    expect(found!.kind).toBe("gif");
    expect(found!.gif_url).toBeTruthy();
  });
});

// ─── 6. Image comment ─────────────────────────────────────────────────────────

test.describe("6. Image comment", () => {
  let page: Page;
  let videoId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
    videoId = await seedVideo(page);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("POST kind=image comment with uploaded URL succeeds", async () => {
    const imageUrl = await uploadTestImage(page, "alice");
    const resp = await apiPost(page, `/ui/videos/${videoId}/comments`, {
      kind: "image",
      image_url: imageUrl,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json() as { kind: string; image_url: string };
    expect(data.kind).toBe("image");
    expect(data.image_url).toBe(imageUrl);
  });

  test("image comment appears in list with kind=image and image_url", async () => {
    const imageUrl = await uploadTestImage(page, "alice");
    const createResp = await apiPost(page, `/ui/videos/${videoId}/comments`, {
      kind: "image",
      image_url: imageUrl,
    });
    const { comment_id } = await createResp.json() as { comment_id: string };

    const listResp = await apiGet(page, `/ui/videos/${videoId}/comments`);
    const { comments } = await listResp.json() as {
      comments: Array<{ comment_id: string; kind: string; image_url: string | null }>;
    };
    const found = comments.find((c) => c.comment_id === comment_id);
    expect(found).toBeTruthy();
    expect(found!.kind).toBe("image");
    expect(found!.image_url).toBe(imageUrl);
  });

  test("kind=image without image_url → 422", async () => {
    const resp = await apiPost(page, `/ui/videos/${videoId}/comments`, {
      kind: "image",
    });
    expect(resp.status()).toBe(422);
  });
});

// ─── 7. Moderation report ─────────────────────────────────────────────────────

test.describe("7. Moderation report", () => {
  let page: Page;
  let videoId: string;
  let commentId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
    videoId = await seedVideo(page);

    const resp = await apiPost(page, `/ui/videos/${videoId}/comments`, {
      text: "Reportable comment",
    });
    expect(resp.status()).toBe(201);
    ({ comment_id: commentId } = await resp.json() as { comment_id: string });
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("Bob can report Alice's video comment (200 ok)", async () => {
    const bobSession = getAdminSessions()["bob"];
    const bobPage = await page.context().browser()!.newPage();
    await injectAuth(bobPage, "bob");

    const resp = await bobPage.request.post(`${API}/moderation/reports`, {
      data: {
        content_type: "video_comment",
        content_id: commentId,
        video_id: videoId,
        topics: ["spam"],
        reason_text: "This is spam content",
      },
      headers: { "x-csrf-token": bobSession.csrf_token },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ok: boolean; report_id: string };
    expect(data.ok).toBe(true);
    expect(data.report_id).toBeTruthy();

    await bobPage.close();
  });

  test("report with unknown comment_id → 404", async () => {
    const bobSession = getAdminSessions()["bob"];
    const bobPage = await page.context().browser()!.newPage();
    await injectAuth(bobPage, "bob");

    const resp = await bobPage.request.post(`${API}/moderation/reports`, {
      data: {
        content_type: "video_comment",
        content_id: "vc_nonexistent_xyz",
        video_id: videoId,
        topics: ["spam"],
        reason_text: "Reporting nonexistent comment",
      },
      headers: { "x-csrf-token": bobSession.csrf_token },
    });
    expect(resp.status()).toBe(404);

    await bobPage.close();
  });

  test("report requires video_id for video_comment content_type", async () => {
    const bobSession = getAdminSessions()["bob"];
    const bobPage = await page.context().browser()!.newPage();
    await injectAuth(bobPage, "bob");

    const resp = await bobPage.request.post(`${API}/moderation/reports`, {
      data: {
        content_type: "video_comment",
        content_id: commentId,
        // no video_id
        topics: ["spam"],
        reason_text: "Missing video_id",
      },
      headers: { "x-csrf-token": bobSession.csrf_token },
    });
    expect(resp.status()).toBe(400);

    await bobPage.close();
  });

  test("duplicate report is accepted (deduplicated status)", async () => {
    // First report already done; re-reporting same comment should get deduplicated
    const bobSession = getAdminSessions()["bob"];
    const bobPage = await page.context().browser()!.newPage();
    await injectAuth(bobPage, "bob");

    const resp = await bobPage.request.post(`${API}/moderation/reports`, {
      data: {
        content_type: "video_comment",
        content_id: commentId,
        video_id: videoId,
        topics: ["spam"],
        reason_text: "Duplicate report",
      },
      headers: { "x-csrf-token": bobSession.csrf_token },
    });
    // Either 200 ok=true with status=deduplicated or status=submitted
    expect([200, 202].includes(resp.status())).toBe(true);
    const data = await resp.json() as { ok: boolean; status: string };
    expect(data.ok).toBe(true);

    await bobPage.close();
  });
});

// ─── 8. VideoDetailPage UI ────────────────────────────────────────────────────

test.describe("8. VideoDetailPage UI affordances", () => {
  let page: Page;
  let videoId: string;
  let commentId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
    videoId = await seedVideo(page);

    // Seed a comment via API
    const resp = await apiPost(page, `/ui/videos/${videoId}/comments`, {
      text: `UI test comment ${Date.now()}`,
    });
    expect(resp.status()).toBe(201);
    ({ comment_id: commentId } = await resp.json() as { comment_id: string });
  });

  test.afterAll(async () => {
    await page.close();
  });

  async function gotoVideoDetail(browser: import("@playwright/test").Browser): Promise<Page> {
    const p = await browser.newPage();
    const session = getAdminSessions()["alice"];
    // Pre-seed cookies and auth-store via initScript (runs before page load)
    await p.context().addCookies(session.cookies);
    await p.addInitScript((uid: string) => {
      const state = { userId: uid, accessToken: null, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    }, session.user_sub);
    // Navigate directly to the gallery video detail page (App.tsx path="gallery/:videoId")
    await p.goto(`${BASE}/gallery/${videoId}`, { waitUntil: "load" });
    await p.waitForTimeout(3000);
    return p;
  }

  test("VideoDetailPage loads with comment section", async ({ browser }) => {
    const uiPage = await gotoVideoDetail(browser);
    // The page should have a comment input (Add a comment... placeholder)
    const commentInput = uiPage.locator("input[placeholder*='comment' i]").first();
    await expect(commentInput).toBeVisible({ timeout: 10_000 });
    await uiPage.close();
  });

  test("video-comment-image-button is visible", async ({ browser }) => {
    const uiPage = await gotoVideoDetail(browser);
    const imgBtn = uiPage.locator("[data-testid='video-comment-image-button']").first();
    await expect(imgBtn).toBeVisible({ timeout: 8_000 });
    await uiPage.close();
  });

  test("video-comment-image-input exists in DOM", async ({ browser }) => {
    const uiPage = await gotoVideoDetail(browser);
    const imgInput = uiPage.locator("[data-testid='video-comment-image-input']");
    expect(await imgInput.count()).toBeGreaterThan(0);
    await uiPage.close();
  });

  test("comment reaction buttons show emojis", async ({ browser }) => {
    const uiPage = await gotoVideoDetail(browser);
    // Wait for comments section to load
    await expect(uiPage.locator("input[placeholder*='comment' i]").first()).toBeVisible({ timeout: 10_000 });
    await uiPage.waitForTimeout(1000);
    // Reaction buttons should be visible within the comment area
    const emojis = ["👍", "❤️"];
    for (const emoji of emojis) {
      const btn = uiPage.locator("button").filter({ hasText: emoji }).first();
      await expect(btn).toBeVisible({ timeout: 8_000 });
    }
    await uiPage.close();
  });

  test("Reply button is visible on comments", async ({ browser }) => {
    const uiPage = await gotoVideoDetail(browser);
    // Wait for comment input to load
    await expect(uiPage.locator("input[placeholder*='comment' i]").first()).toBeVisible({ timeout: 10_000 });
    // Scroll to bottom so comment rows become visible (video may push them below fold)
    await uiPage.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await uiPage.waitForTimeout(2000);
    // The reply button is a plain <button> containing "Reply" text (with a Reply icon SVG)
    // Use contains-text match (not exact) since SVG icon + text gives " Reply" with whitespace
    const replyBtn = uiPage.locator("button").filter({ hasText: /Reply/ }).first();
    await expect(replyBtn).toBeVisible({ timeout: 10_000 });
    await uiPage.close();
  });

  test("uploading an image shows video-comment-image-preview", async ({ browser }) => {
    const pngPath = `${tmpdir()}/vid_ui_prev_${Date.now()}.png`;
    execSync(
      `${PYTHON} -c "
import struct, zlib
def write_png(path):
    def chunk(name, data):
        c = struct.pack('>I', len(data)) + name + data
        return c + struct.pack('>I', zlib.crc32(name + data) & 0xffffffff)
    raw = b'\\x89PNG\\r\\n\\x1a\\n'
    raw += chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
    raw += chunk(b'IDAT', zlib.compress(b'\\x00\\xff\\x00\\x00'))
    raw += chunk(b'IEND', b'')
    open(path, 'wb').write(raw)
write_png('${pngPath}')
"`,
      { timeout: 5_000 },
    );

    const uiPage = await gotoVideoDetail(browser);

    const [fileChooser] = await Promise.all([
      uiPage.waitForEvent("filechooser"),
      uiPage.locator("[data-testid='video-comment-image-button']").first().click(),
    ]);
    await fileChooser.setFiles(pngPath);

    const preview = uiPage.locator("[data-testid='video-comment-image-preview']").first();
    await expect(preview).toBeVisible({ timeout: 10_000 });

    await uiPage.close();
  });

  test("submitting image comment renders video-comment-image", async ({ browser }) => {
    const pngPath = `${tmpdir()}/vid_img_sub_${Date.now()}.png`;
    execSync(
      `${PYTHON} -c "
import struct, zlib
def write_png(path):
    def chunk(name, data):
        c = struct.pack('>I', len(data)) + name + data
        return c + struct.pack('>I', zlib.crc32(name + data) & 0xffffffff)
    raw = b'\\x89PNG\\r\\n\\x1a\\n'
    raw += chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
    raw += chunk(b'IDAT', zlib.compress(b'\\x00\\xff\\x00\\x00'))
    raw += chunk(b'IEND', b'')
    open(path, 'wb').write(raw)
write_png('${pngPath}')
"`,
      { timeout: 5_000 },
    );

    const uiPage = await gotoVideoDetail(browser);

    const [fileChooser] = await Promise.all([
      uiPage.waitForEvent("filechooser"),
      uiPage.locator("[data-testid='video-comment-image-button']").first().click(),
    ]);
    await fileChooser.setFiles(pngPath);

    // Wait for preview
    await expect(
      uiPage.locator("[data-testid='video-comment-image-preview']").first(),
    ).toBeVisible({ timeout: 10_000 });

    // Submit
    const [waitPost] = [
      uiPage.waitForResponse((r) =>
        r.url().includes(`/ui/videos/${videoId}/comments`) &&
        r.request().method() === "POST",
      ),
    ];
    const postBtn = uiPage.getByRole("button", { name: /Post image/i }).first();
    await postBtn.click();
    await waitPost;

    // Rendered image element should appear
    const imgEl = uiPage.locator("[data-testid='video-comment-image']").first();
    await expect(imgEl).toBeVisible({ timeout: 8_000 });

    await uiPage.close();
  });
});
