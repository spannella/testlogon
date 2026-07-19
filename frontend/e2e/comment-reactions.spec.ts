/**
 * E2E tests — Newsfeed comment reactions + uploaded-image comments.
 *
 * Features tested:
 *  A) Comment emoji reactions (POST /posts/:id/comments/:cid/reactions + /unreact)
 *     - reactions_counts / my_reactions in API response
 *     - reaction bar in CommentsThread UI (highlight + count)
 *     - invalid emoji → 422
 *  B) Image comment (kind="image" + image_url via POST /uploads/image)
 *     - via API: upload then create image comment; verifies <img data-testid="comment-image">
 *     - via UI: click comment-image-button → file-input → preview → post → img renders
 *     - non-image kind=text with image_url rejected (422)
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
    // Admin setup prints per-create lines then JSON blob on last line
    const lastLine = raw.trim().split("\n").at(-1)!;
    _sessions = JSON.parse(lastLine);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

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

async function gotoFeed(page: Page, identity = "alice") {
  await injectAuth(page, identity);
  await page.goto(`${BASE}/`, { waitUntil: "load" });
  await page.waitForTimeout(600);
  await page.locator('a[href="/feed"]').first().click();
  await page.waitForTimeout(1200);
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

function apiDelete(page: Page, path: string, identity = "alice") {
  const session = getAdminSessions()[identity];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// Upload a tiny PNG via the /uploads/image endpoint
async function uploadTestImage(page: Page, identity = "alice"): Promise<string> {
  const session = getAdminSessions()[identity];
  // Create a minimal 1x1 PNG in /tmp
  const pngPath = `${tmpdir()}/e2e_test_${Date.now()}.png`;
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
print('ok')
"`,
    { timeout: 5_000 },
  );

  // Upload via multipart
  const fileBytes = fs.readFileSync(pngPath);
  const resp = await page.request.post(`${API}/uploads/image`, {
    headers: {
      "x-csrf-token": session.csrf_token,
    },
    multipart: {
      file: {
        name: "test.png",
        mimeType: "image/png",
        buffer: fileBytes,
      },
    },
  });
  expect(resp.ok(), `Upload failed: ${await resp.text()}`).toBe(true);
  const data = await resp.json() as { url: string };
  return data.url;
}

// ─── 1. Comment reaction API ──────────────────────────────────────────────────

test.describe("1. Comment reaction API", () => {
  let page: Page;
  let postId: string;
  let commentId: string;
  const MARKER = `E2E comment react ${Date.now()}`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");

    // Create a post
    const postResp = await apiPost(page, "/posts", { body: MARKER });
    expect(postResp.ok()).toBe(true);
    ({ post_id: postId } = await postResp.json());

    // Create a comment
    const cmtResp = await apiPost(page, `/posts/${postId}/comments`, { body: "React to me" });
    expect(cmtResp.ok()).toBe(true);
    ({ comment_id: commentId } = await cmtResp.json());
  });

  test.afterAll(async () => {
    if (postId) await apiDelete(page, `/posts/${postId}`);
    await page.close();
  });

  test("react to a comment returns ok=true", async () => {
    const resp = await apiPost(
      page,
      `/posts/${postId}/comments/${commentId}/reactions`,
      { emoji: "👍" },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { ok: boolean };
    expect(body.ok).toBe(true);
  });

  test("GET /posts/:id/comments — reactions_counts and my_reactions populated", async () => {
    const resp = await apiGet(page, `/posts/${postId}/comments`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { items: Array<{ comment_id: string; reactions_counts: Record<string, number>; my_reactions: string[] }> };
    const cmt = data.items.find((c) => c.comment_id === commentId);
    expect(cmt).toBeTruthy();
    expect(cmt!.reactions_counts["👍"]).toBeGreaterThanOrEqual(1);
    expect(cmt!.my_reactions).toContain("👍");
  });

  test("react with multiple emojis accumulates counts", async () => {
    await apiPost(page, `/posts/${postId}/comments/${commentId}/reactions`, { emoji: "❤️" });
    await apiPost(page, `/posts/${postId}/comments/${commentId}/reactions`, { emoji: "🔥" });

    const resp = await apiGet(page, `/posts/${postId}/comments`);
    const data = await resp.json() as { items: Array<{ comment_id: string; reactions_counts: Record<string, number> }> };
    const cmt = data.items.find((c) => c.comment_id === commentId)!;
    expect(cmt.reactions_counts["👍"]).toBeGreaterThanOrEqual(1);
    expect(cmt.reactions_counts["❤️"]).toBeGreaterThanOrEqual(1);
    expect(cmt.reactions_counts["🔥"]).toBeGreaterThanOrEqual(1);
  });

  test("unreact removes the emoji from my_reactions", async () => {
    // First ensure 👍 is reacted
    await apiPost(page, `/posts/${postId}/comments/${commentId}/reactions`, { emoji: "👍" });

    // Unreact
    const unreactResp = await apiPost(
      page,
      `/posts/${postId}/comments/${commentId}/unreact`,
      { emoji: "👍" },
    );
    expect(unreactResp.status()).toBe(200);
    const body = await unreactResp.json() as { ok: boolean };
    expect(body.ok).toBe(true);

    // Verify removed from my_reactions and count is 0
    const getResp = await apiGet(page, `/posts/${postId}/comments`);
    const data = await getResp.json() as { items: Array<{ comment_id: string; reactions_counts: Record<string, number>; my_reactions: string[] }> };
    const cmt = data.items.find((c) => c.comment_id === commentId)!;
    expect(cmt.my_reactions).not.toContain("👍");
    expect(cmt.reactions_counts["👍"] ?? 0).toBe(0);
  });

  test("invalid emoji → 422", async () => {
    const resp = await apiPost(
      page,
      `/posts/${postId}/comments/${commentId}/reactions`,
      { emoji: "🌚" },
    );
    expect(resp.status()).toBe(422);
  });

  test("all 5 allowed emojis are accepted", async () => {
    const allowed = ["👍", "❤️", "😂", "🔥", "😮"];
    for (const emoji of allowed) {
      const resp = await apiPost(
        page,
        `/posts/${postId}/comments/${commentId}/reactions`,
        { emoji },
      );
      expect(resp.status(), `emoji ${emoji} should be accepted`).toBe(200);
    }
  });

  test("Bob reacts to Alice comment — Bob's my_reactions populated", async () => {
    const bobPage = await page.context().browser()!.newPage();
    await injectAuth(bobPage, "bob");

    const bobSession = getAdminSessions()["bob"];
    const resp = await bobPage.request.post(
      `${API}/posts/${postId}/comments/${commentId}/reactions`,
      {
        data: { emoji: "😮" },
        headers: { "x-csrf-token": bobSession.csrf_token },
      },
    );
    expect(resp.status()).toBe(200);

    // Bob sees my_reactions containing 😮
    const getResp = await bobPage.request.get(
      `${API}/posts/${postId}/comments`,
    );
    const data = await getResp.json() as { items: Array<{ comment_id: string; my_reactions: string[] }> };
    const cmt = data.items.find((c) => c.comment_id === commentId)!;
    expect(cmt.my_reactions).toContain("😮");

    await bobPage.close();
  });
});

// ─── 2. Comment reaction UI ───────────────────────────────────────────────────

test.describe("2. Comment reaction UI", () => {
  let page: Page;
  let postId: string;
  let commentId: string;
  const POST_BODY = `E2E UI reaction test ${Date.now()}`;
  const CMT_BODY = `Reaction UI comment ${Date.now()}`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");

    const postResp = await apiPost(page, "/posts", { body: POST_BODY });
    expect(postResp.ok()).toBe(true);
    ({ post_id: postId } = await postResp.json() as { post_id: string });

    const cmtResp = await apiPost(page, `/posts/${postId}/comments`, { body: CMT_BODY });
    expect(cmtResp.ok()).toBe(true);
    ({ comment_id: commentId } = await cmtResp.json() as { comment_id: string });
  });

  test.afterAll(async () => {
    if (postId) await apiDelete(page, `/posts/${postId}`);
    await page.close();
  });

  // Helper: navigate to feed, wait for any post to show, then open its comment section
  async function openFirstCommentSection(browser: import("@playwright/test").Browser): Promise<Page> {
    const uiPage = await browser.newPage();
    await gotoFeed(uiPage);
    await uiPage.waitForTimeout(2500);
    await uiPage.evaluate(() => window.scrollTo(0, 600));
    await uiPage.waitForTimeout(1000);

    // Same strategy as openCommentForm: click the 2nd action button (comment toggle)
    await uiPage.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll<HTMLButtonElement>("button"));
      const actionBtns = buttons.filter(btn => {
        const children = Array.from(btn.children);
        return children.some(c => c.tagName === "svg") &&
               children.some(c => c.tagName === "SPAN" && /^\d+$/.test((c.textContent || "").trim()));
      });
      if (actionBtns.length > 1) {
        actionBtns[1].click();
        return true;
      }
      return false;
    });
    await uiPage.waitForTimeout(1200);
    return uiPage;
  }

  test("comment reaction bar shows 5 emoji buttons", async ({ browser }) => {
    const uiPage = await openFirstCommentSection(browser);

    // Reaction bar should have emoji buttons — they appear in the comment rows
    const emojis = ["👍", "❤️", "😂", "🔥", "😮"];
    for (const emoji of emojis) {
      const btn = uiPage.locator("button").filter({ hasText: emoji }).first();
      await expect(btn).toBeVisible({ timeout: 8_000 });
    }

    await uiPage.close();
  });

  test("clicking a reaction emoji sends reaction and highlights button", async ({ browser }) => {
    const uiPage = await openFirstCommentSection(browser);

    // Find the 👍 button within the comments area
    const thumbsUpBtns = uiPage.locator("button").filter({ hasText: "👍" });
    const count = await thumbsUpBtns.count();
    expect(count).toBeGreaterThan(0);

    // Click the first 👍 comment reaction
    const waitForReact = uiPage.waitForResponse(
      (r) => r.url().includes("/reactions") && r.request().method() === "POST",
      { timeout: 5_000 },
    ).catch(() => null);

    const thumbsBtn = thumbsUpBtns.first();
    await thumbsBtn.click();
    await waitForReact;

    // The button should now show highlighted class (bg-primary/10)
    await expect(thumbsBtn).toHaveClass(/bg-primary\/10/, { timeout: 5_000 });

    await uiPage.close();
  });
});

// ─── 3. Image comment API ─────────────────────────────────────────────────────

test.describe("3. Image comment API", () => {
  let page: Page;
  let postId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");

    const postResp = await apiPost(page, "/posts", {
      body: `Image comment post ${Date.now()}`,
    });
    expect(postResp.ok()).toBe(true);
    ({ post_id: postId } = await postResp.json() as { post_id: string });
  });

  test.afterAll(async () => {
    if (postId) await apiDelete(page, `/posts/${postId}`);
    await page.close();
  });

  test("upload image returns a /uploads/object URL", async () => {
    const url = await uploadTestImage(page, "alice");
    expect(url).toMatch(/^\/uploads\/object\?s3_key=/);
  });

  test("create kind=image comment with uploaded URL succeeds", async () => {
    const imageUrl = await uploadTestImage(page, "alice");
    const resp = await apiPost(page, `/posts/${postId}/comments`, {
      kind: "image",
      image_url: imageUrl,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as {
      comment_id: string;
      kind: string;
      image_url: string;
    };
    expect(data.kind).toBe("image");
    expect(data.image_url).toBe(imageUrl);
    expect(data.comment_id).toBeTruthy();
  });

  test("image comment appears in GET /posts/:id/comments with image_url", async () => {
    const imageUrl = await uploadTestImage(page, "alice");
    const createResp = await apiPost(page, `/posts/${postId}/comments`, {
      kind: "image",
      image_url: imageUrl,
    });
    expect(createResp.ok()).toBe(true);
    const { comment_id: newCmtId } = await createResp.json() as { comment_id: string };

    const getResp = await apiGet(page, `/posts/${postId}/comments`);
    expect(getResp.ok()).toBe(true);
    const data = await getResp.json() as { items: Array<{ comment_id: string; kind: string; image_url: string | null }> };
    const found = data.items.find((c) => c.comment_id === newCmtId);
    expect(found).toBeTruthy();
    expect(found!.kind).toBe("image");
    expect(found!.image_url).toBe(imageUrl);
  });

  test("kind=text comment with image_url field → 422 (body text required)", async () => {
    const imageUrl = await uploadTestImage(page, "alice");
    // Sending kind=text without body/body_plain → validation error
    const resp = await apiPost(page, `/posts/${postId}/comments`, {
      kind: "text",
      image_url: imageUrl,
    });
    expect(resp.status()).toBe(422);
  });

  test("kind=image comment without image_url → 422", async () => {
    const resp = await apiPost(page, `/posts/${postId}/comments`, {
      kind: "image",
      // no image_url
    });
    expect(resp.status()).toBe(422);
  });

  test("kind=image with plain http (not https) URL → 422 (rejected scheme)", async () => {
    const resp = await apiPost(page, `/posts/${postId}/comments`, {
      kind: "image",
      image_url: "http://external.example.com/image.png",
    });
    // Validator rejects non-https external URLs
    expect(resp.status()).toBe(422);
  });

  test("kind=image with external https URL is accepted (CDN support)", async () => {
    // The validator intentionally allows https:// CDN URLs in addition to /uploads/object paths
    const resp = await apiPost(page, `/posts/${postId}/comments`, {
      kind: "image",
      image_url: "https://external.example.com/image.png",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { kind: string; image_url: string };
    expect(data.kind).toBe("image");
  });
});

// ─── 4. Image comment UI ─────────────────────────────────────────────────────

test.describe("4. Image comment UI", () => {
  let page: Page;
  let postId: string;
  const POST_BODY = `Image UI comment post ${Date.now()}`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
    const resp = await apiPost(page, "/posts", { body: POST_BODY });
    expect(resp.ok()).toBe(true);
    ({ post_id: postId } = await resp.json() as { post_id: string });
  });

  test.afterAll(async () => {
    if (postId) await apiDelete(page, `/posts/${postId}`);
    await page.close();
  });

  // Helper: go to feed, open a comment section, return page
  async function openCommentForm(browser: import("@playwright/test").Browser): Promise<Page> {
    const uiPage = await browser.newPage();
    await gotoFeed(uiPage);
    await uiPage.waitForTimeout(2500);
    // Scroll down to see posts below the CreatePost composer
    await uiPage.evaluate(() => window.scrollTo(0, 600));
    await uiPage.waitForTimeout(1000);

    // Strategy: find the 2nd "svg+span(digit)" button per post, which is the comment toggle.
    // In PostCard the action row order is: [like svg+span] [comment svg+span] [tip svg] [repost] ...
    // We find all pairs (likeBtn, commentBtn) by looking for buttons with SVG+digit-span siblings.
    const opened = await uiPage.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll<HTMLButtonElement>("button"));
      // Collect buttons that have (svg sibling, digit-span sibling) = action buttons
      const actionBtns = buttons.filter(btn => {
        const children = Array.from(btn.children);
        return children.some(c => c.tagName === "svg") &&
               children.some(c => c.tagName === "SPAN" && /^\d+$/.test((c.textContent || "").trim()));
      });
      // Skip the first one per "group" — it's the Like button.
      // The comment button is the 2nd one in a group. Skip even-indexed ones (0-based like btns).
      // Groups: for each post there are 2 such buttons: like + comment (repost also has span count)
      // So click index=1, 4, 7 etc. (every 3rd or so... structure varies)
      // Simplest: click the SECOND action button we find (index 1).
      if (actionBtns.length > 1) {
        actionBtns[1].click();
        return true;
      }
      return false;
    });

    if (opened) {
      await uiPage.waitForTimeout(1200);
    }
    return uiPage;
  }

  test("comment-image-button is rendered in the composer", async ({ browser }) => {
    const uiPage = await openCommentForm(browser);
    const imgBtn = uiPage.locator("[data-testid='comment-image-button']").first();
    await expect(imgBtn).toBeVisible({ timeout: 8_000 });
    await uiPage.close();
  });

  test("comment-image-input exists hidden in DOM", async ({ browser }) => {
    const uiPage = await openCommentForm(browser);
    const imgInput = uiPage.locator("[data-testid='comment-image-input']");
    expect(await imgInput.count()).toBeGreaterThan(0);
    await uiPage.close();
  });

  test("selecting an image shows comment-image-preview", async ({ browser }) => {
    // Create a small PNG for the file chooser
    const pngPath = `${tmpdir()}/ui_comment_${Date.now()}.png`;
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

    const uiPage = await openCommentForm(browser);

    // Use filechooser to feed a file
    const [fileChooser] = await Promise.all([
      uiPage.waitForEvent("filechooser"),
      uiPage.locator("[data-testid='comment-image-button']").first().click(),
    ]);
    await fileChooser.setFiles(pngPath);

    // Image preview should appear after upload
    const preview = uiPage.locator("[data-testid='comment-image-preview']").first();
    await expect(preview).toBeVisible({ timeout: 10_000 });

    await uiPage.close();
  });

  test("submitting image comment renders <img data-testid='comment-image'>", async ({
    browser,
  }) => {
    const pngPath = `${tmpdir()}/ui_img_submit_${Date.now()}.png`;
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

    const uiPage = await openCommentForm(browser);

    // Upload image via file chooser
    const [fileChooser] = await Promise.all([
      uiPage.waitForEvent("filechooser"),
      uiPage.locator("[data-testid='comment-image-button']").first().click(),
    ]);
    await fileChooser.setFiles(pngPath);

    // Wait for preview to appear (upload is async)
    await expect(
      uiPage.locator("[data-testid='comment-image-preview']").first(),
    ).toBeVisible({ timeout: 10_000 });

    // Submit the comment — the form has a "Post" button with Send icon
    const waitPost = uiPage.waitForResponse(
      (r) => r.url().includes("/comments") && r.request().method() === "POST",
      { timeout: 10_000 },
    );
    const submitBtn = uiPage.locator("button").filter({ hasText: /^Post$/ }).last();
    await submitBtn.click();
    await waitPost;

    // After submission the preview disappears and the image comment renders
    const imgEl = uiPage.locator("[data-testid='comment-image']").first();
    await expect(imgEl).toBeVisible({ timeout: 8_000 });

    await uiPage.close();
  });
});
