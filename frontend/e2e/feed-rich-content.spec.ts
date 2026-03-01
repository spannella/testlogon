/**
 * NFR-503 — E2E scenarios for newsfeed markdown/rich author + viewer journeys.
 */
import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import path from "path";

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

interface SessionData {
  user_sub: string;
  csrf_token: string;
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
    const repoRoot = process.cwd().includes("/frontend") ? path.resolve(process.cwd(), "..") : process.cwd();
    const setupScript = path.join(repoRoot, "e2e_session_setup.py");
    const raw = execSync(`python3 ${setupScript}`, { cwd: repoRoot, timeout: 30_000 }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function apiPost(page: Page, userId: string, endpoint: string, data: object) {
  const session = getSessions()[userId];
  return page.request.post(`${API}${endpoint}`, {
    data,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiPatch(page: Page, userId: string, endpoint: string, data: object) {
  const session = getSessions()[userId];
  return page.request.patch(`${API}${endpoint}`, {
    data,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGet(page: Page, userId: string, endpoint: string) {
  const session = getSessions()[userId];
  return page.request.get(`${API}${endpoint}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiDelete(page: Page, userId: string, endpoint: string) {
  const session = getSessions()[userId];
  return page.request.delete(`${API}${endpoint}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

test.describe("NFR-503: newsfeed rich content e2e journeys", () => {
  test("author publish + viewer render for markdown post/comment create-edit-get", async ({ browser }) => {
    const author = await browser.newPage();
    const viewer = await browser.newPage();
    await injectAuth(author, ALICE_ID);
    await injectAuth(viewer, BOB_ID);

    let postId: string | null = null;

    try {
      const createPost = await apiPost(author, ALICE_ID, "/posts", {
        body_plain: "Markdown title",
        body_markdown: "# Markdown title\n\n- one\n- two",
        body_format: "markdown",
        visibility: "followers",
      });
      expect(createPost.ok()).toBeTruthy();
      const created = await createPost.json();
      postId = created.post_id;
      expect(created.body_format).toBe("markdown");
      expect(created.body_markdown).toContain("# Markdown title");

      const createComment = await apiPost(author, ALICE_ID, `/posts/${postId}/comments`, {
        body_plain: "Markdown comment",
        body_markdown: "**Markdown comment**",
        body_format: "markdown",
      });
      expect(createComment.ok()).toBeTruthy();
      const comment = await createComment.json();
      expect(comment.body_format).toBe("markdown");

      const editPost = await apiPatch(author, ALICE_ID, `/posts/${postId}`, {
        body_plain: "Markdown title edited",
        body_markdown: "## Markdown title edited",
        body_format: "markdown",
      });
      expect(editPost.ok()).toBeTruthy();

      const editComment = await apiPatch(author, ALICE_ID, `/posts/${postId}/comments/${comment.comment_id}`, {
        body_plain: "Markdown comment edited",
        body_markdown: "*Markdown comment edited*",
        body_format: "markdown",
        expected_version: comment.version,
      });
      expect(editComment.ok()).toBeTruthy();

      const viewerPost = await apiGet(viewer, BOB_ID, `/posts/${postId}`);
      expect(viewerPost.ok()).toBeTruthy();
      const viewerPostJson = await viewerPost.json();
      expect(viewerPostJson.body_format).toBe("markdown");
      expect(viewerPostJson.body_markdown).toContain("Markdown title edited");

      const viewerComments = await apiGet(viewer, BOB_ID, `/posts/${postId}/comments`);
      expect(viewerComments.ok()).toBeTruthy();
      const viewerCommentsJson = await viewerComments.json();
      const editedComment = viewerCommentsJson.items.find((c: any) => c.comment_id === comment.comment_id);
      expect(editedComment).toBeTruthy();
      expect(editedComment.body_format).toBe("markdown");
      expect(editedComment.body_markdown).toContain("Markdown comment edited");
    } finally {
      if (postId) await apiDelete(author, ALICE_ID, `/posts/${postId}`);
      await author.close();
      await viewer.close();
    }
  });

  test("author publish + viewer render for rich post/comment create-edit-get", async ({ browser }) => {
    const author = await browser.newPage();
    const viewer = await browser.newPage();
    await injectAuth(author, ALICE_ID);
    await injectAuth(viewer, BOB_ID);

    let postId: string | null = null;

    try {
      const richDoc = {
        type: "doc",
        content: [{ type: "paragraph", content: [{ type: "text", text: "Rich post text" }] }],
      };
      const richCommentDoc = {
        type: "doc",
        content: [{ type: "paragraph", content: [{ type: "text", text: "Rich comment text" }] }],
      };

      const createPost = await apiPost(author, ALICE_ID, "/posts", {
        body_plain: "Rich post text",
        body_rich: richDoc,
        body_format: "rich",
        visibility: "followers",
      });
      expect(createPost.ok()).toBeTruthy();
      const created = await createPost.json();
      postId = created.post_id;
      expect(created.body_format).toBe("rich");
      expect(created.body_rich?.type).toBe("doc");

      const createComment = await apiPost(author, ALICE_ID, `/posts/${postId}/comments`, {
        body_plain: "Rich comment text",
        body_rich: richCommentDoc,
        body_format: "rich",
      });
      expect(createComment.ok()).toBeTruthy();
      const comment = await createComment.json();

      const editPostDoc = {
        type: "doc",
        content: [{ type: "paragraph", content: [{ type: "text", text: "Rich post edited" }] }],
      };
      const editPost = await apiPatch(author, ALICE_ID, `/posts/${postId}`, {
        body_plain: "Rich post edited",
        body_rich: editPostDoc,
        body_format: "rich",
      });
      expect(editPost.ok()).toBeTruthy();

      const editCommentDoc = {
        type: "doc",
        content: [{ type: "paragraph", content: [{ type: "text", text: "Rich comment edited" }] }],
      };
      const editComment = await apiPatch(author, ALICE_ID, `/posts/${postId}/comments/${comment.comment_id}`, {
        body_plain: "Rich comment edited",
        body_rich: editCommentDoc,
        body_format: "rich",
        expected_version: comment.version,
      });
      expect(editComment.ok()).toBeTruthy();

      const viewerPost = await apiGet(viewer, BOB_ID, `/posts/${postId}`);
      expect(viewerPost.ok()).toBeTruthy();
      const viewerPostJson = await viewerPost.json();
      expect(viewerPostJson.body_format).toBe("rich");
      expect(viewerPostJson.body_plain).toContain("Rich post edited");
      expect(viewerPostJson.body_rich?.type).toBe("doc");

      const viewerComments = await apiGet(viewer, BOB_ID, `/posts/${postId}/comments`);
      expect(viewerComments.ok()).toBeTruthy();
      const viewerCommentsJson = await viewerComments.json();
      const editedComment = viewerCommentsJson.items.find((c: any) => c.comment_id === comment.comment_id);
      expect(editedComment).toBeTruthy();
      expect(editedComment.body_format).toBe("rich");
      expect(editedComment.body_plain).toContain("Rich comment edited");
      expect(editedComment.body_rich?.type).toBe("doc");
    } finally {
      if (postId) await apiDelete(author, ALICE_ID, `/posts/${postId}`);
      await author.close();
      await viewer.close();
    }
  });

  test("malicious payload attempts are sanitized or rejected", async ({ browser }) => {
    const author = await browser.newPage();
    const viewer = await browser.newPage();
    await injectAuth(author, ALICE_ID);
    await injectAuth(viewer, BOB_ID);

    let postId: string | null = null;

    try {
      const maliciousMarkdown = '<script>window.__pwned = true</script> [bad](javascript:alert(1)) safe';
      const createPost = await apiPost(author, ALICE_ID, "/posts", {
        body_plain: "safe",
        body_markdown: maliciousMarkdown,
        body_format: "markdown",
        visibility: "followers",
      });
      expect(createPost.ok()).toBeTruthy();
      const created = await createPost.json();
      postId = created.post_id;

      const viewerPost = await apiGet(viewer, BOB_ID, `/posts/${postId}`);
      expect(viewerPost.ok()).toBeTruthy();
      const viewerPostJson = await viewerPost.json();
      expect(viewerPostJson.body_markdown_html).not.toContain("<script>");
      expect(viewerPostJson.body_markdown_html).not.toContain("javascript:");

      // Ensure UI render does not execute injected script when opening feed route.
      await viewer.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
      await viewer.locator('a[href="/feed"]').first().click();
      await viewer.waitForTimeout(1200);
      const pwned = await viewer.evaluate(() => (window as any).__pwned === true);
      expect(pwned).toBeFalsy();

      const maliciousRich = await apiPost(author, ALICE_ID, "/posts", {
        body_plain: "x",
        body_rich: { type: "doc", content: [{ type: "rawHtml", content: [] }] },
        body_format: "rich",
      });
      expect(maliciousRich.ok()).toBeFalsy();
      expect(maliciousRich.status()).toBeGreaterThanOrEqual(400);
      expect(maliciousRich.status()).toBeLessThan(500);
    } finally {
      if (postId) await apiDelete(author, ALICE_ID, `/posts/${postId}`);
      await author.close();
      await viewer.close();
    }
  });
});
