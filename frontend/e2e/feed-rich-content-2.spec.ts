/**
 * NFR-503 Section 73-74 — Comprehensive E2E coverage for newsfeed markdown/rich-text.
 *
 * Sections:
 *   73 — Post content envelope API (plain/markdown/rich create, edit, get, validation, telemetry)
 *   74 — Comment content API (create, edit, delete, format round-trip, validation)
 *
 * Prerequisites:
 *   NEWSFEED_MARKDOWN_ENABLED=true  (in .env.local)
 *   NEWSFEED_RICHTEXT_ENABLED=true  (in .env.local)
 *   Backend running on port 8000 / Vite proxy on port 3000
 *   e2e_session_setup.py has been run (or auto-runs on first getSessions() call)
 *
 * Auth: all newsfeed endpoints use require_ui_session (session cookies + x-csrf-token)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API      = "http://localhost:8000";
const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const TS       = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub:   string;
  csrf_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
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

// ─── API helpers ──────────────────────────────────────────────────────────────

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

// ─── Fixtures ─────────────────────────────────────────────────────────────────

function simpleRichDoc(text: string) {
  return {
    type: "doc",
    content: [{ type: "paragraph", content: [{ type: "text", text }] }],
  };
}

// ═════════════════════════════════════════════════════════════════════════════
// Section 73 — Post content envelope API
// ═════════════════════════════════════════════════════════════════════════════

test.describe("Section 73: Post content envelope API", () => {
  let alicePage: Page;
  let bobPage:   Page;

  // Shared posts re-used by read-only tests
  let mdPostId:   string;
  let richPostId: string;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await browser.newPage();
    bobPage   = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage,   BOB_ID);

    // Shared markdown post
    const mdResp = await apiPost(alicePage, ALICE_ID, "/posts", {
      body_plain:    `Section73 md ${TS}`,
      body_markdown: `# Section73 Heading ${TS}\n\n- item one\n- item two\n\n> blockquote line`,
      body_format:   "markdown",
      visibility:    "followers",
    });
    expect(mdResp.ok()).toBeTruthy();
    mdPostId = (await mdResp.json()).post_id;

    // Shared rich post
    const richResp = await apiPost(alicePage, ALICE_ID, "/posts", {
      body_plain:  `Section73 rich ${TS}`,
      body_rich:   simpleRichDoc(`Section73 rich ${TS}`),
      body_format: "rich",
      visibility:  "followers",
    });
    expect(richResp.ok()).toBeTruthy();
    richPostId = (await richResp.json()).post_id;
  });

  test.afterAll(async () => {
    if (mdPostId)   await apiDelete(alicePage, ALICE_ID, `/posts/${mdPostId}`);
    if (richPostId) await apiDelete(alicePage, ALICE_ID, `/posts/${richPostId}`);
    await alicePage.close();
    await bobPage.close();
  });

  // ── Plain text ─────────────────────────────────────────────────────────────

  test("73.1 legacy body field → body_format: plain, no markdown/rich fields", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/posts", {
      body:       `Legacy plain ${TS}`,
      visibility: "followers",
    });
    expect(resp.ok()).toBeTruthy();
    const post = await resp.json();
    try {
      expect(post.body_format).toBe("plain");
      expect(post.body).toContain("Legacy plain");
      expect(post.body_plain).toContain("Legacy plain");
      expect(post.body_markdown).toBeNull();
      expect(post.body_rich).toBeNull();
    } finally {
      await apiDelete(alicePage, ALICE_ID, `/posts/${post.post_id}`);
    }
  });

  test("73.2 body_plain only → body_format: plain, no markdown/rich fields", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/posts", {
      body_plain:  `Plain only ${TS}`,
      visibility: "followers",
    });
    expect(resp.ok()).toBeTruthy();
    const post = await resp.json();
    try {
      expect(post.body_format).toBe("plain");
      expect(post.body_plain).toContain("Plain only");
      expect(post.body_markdown).toBeNull();
      expect(post.body_rich).toBeNull();
    } finally {
      await apiDelete(alicePage, ALICE_ID, `/posts/${post.post_id}`);
    }
  });

  // ── Markdown ───────────────────────────────────────────────────────────────

  test("73.3 body_format auto-inferred as markdown when only body_markdown provided", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/posts", {
      body_markdown: `**Inferred markdown** ${TS}`,
      visibility:    "followers",
    });
    expect(resp.ok()).toBeTruthy();
    const post = await resp.json();
    try {
      expect(post.body_format).toBe("markdown");
      expect(post.body_markdown).toContain("Inferred markdown");
      // body_plain auto-filled from body_markdown when not supplied
      expect(post.body_plain).toBeTruthy();
    } finally {
      await apiDelete(alicePage, ALICE_ID, `/posts/${post.post_id}`);
    }
  });

  test("73.4 body_markdown_html contains rendered HTML: ul/li, blockquote, strong, em, code", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/posts", {
      body_plain:    `Html elements ${TS}`,
      body_markdown: `**bold** *italic* \`inline code\`\n\n- list item\n\n> quoted line`,
      body_format:   "markdown",
      visibility:    "followers",
    });
    expect(resp.ok()).toBeTruthy();
    const post = await resp.json();
    try {
      const html = post.body_markdown_html as string;
      expect(html).toContain("<strong>");
      expect(html).toContain("<em>");
      expect(html).toContain("<code>");
      expect(html).toContain("<ul>");
      expect(html).toContain("<li>");
      expect(html).toContain("<blockquote>");
    } finally {
      await apiDelete(alicePage, ALICE_ID, `/posts/${post.post_id}`);
    }
  });

  test("73.5 https:// link in markdown → preserved with rel=nofollow in body_markdown_html", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/posts", {
      body_plain:    "See the link",
      body_markdown: "[the link](https://example.com/page)",
      body_format:   "markdown",
      visibility:    "followers",
    });
    expect(resp.ok()).toBeTruthy();
    const post = await resp.json();
    try {
      const html = post.body_markdown_html as string;
      expect(html).toContain('href="https://example.com/page"');
      expect(html).toContain("the link");
      expect(html).toContain('rel="nofollow noopener noreferrer"');
    } finally {
      await apiDelete(alicePage, ALICE_ID, `/posts/${post.post_id}`);
    }
  });

  test("73.6 http:// link in markdown → href stripped, link text preserved", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/posts", {
      body_plain:    "Unsafe link text",
      body_markdown: "[Unsafe link text](http://example.com)",
      body_format:   "markdown",
      visibility:    "followers",
    });
    expect(resp.ok()).toBeTruthy();
    const post = await resp.json();
    try {
      // Only https:// and mailto: are allowed; http:// is blocked
      expect(post.body_markdown_html).not.toContain("<a ");
      expect(post.body_markdown_html).not.toContain("href=");
      expect(post.body_markdown_html).toContain("Unsafe link text");
    } finally {
      await apiDelete(alicePage, ALICE_ID, `/posts/${post.post_id}`);
    }
  });

  test("73.7 GET markdown post → all body fields round-tripped correctly", async () => {
    const get = await apiGet(alicePage, ALICE_ID, `/posts/${mdPostId}`);
    expect(get.ok()).toBeTruthy();
    const post = await get.json();
    expect(post.body_format).toBe("markdown");
    expect(post.body_markdown).toContain(`Section73 Heading ${TS}`);
    expect(post.body_markdown_html).toContain("<ul>");
    expect(post.body_markdown_html).toContain("<blockquote>");
    expect(post.body_plain).toBeTruthy();
    expect(post.body_rich).toBeNull();
  });

  // ── Rich text ──────────────────────────────────────────────────────────────

  test("73.8 GET rich post as author → body_rich.type=doc, body_plain present, no body_markdown", async () => {
    const get = await apiGet(alicePage, ALICE_ID, `/posts/${richPostId}`);
    expect(get.ok()).toBeTruthy();
    const post = await get.json();
    expect(post.body_format).toBe("rich");
    expect(post.body_rich?.type).toBe("doc");
    expect(post.body_plain).toContain(`Section73 rich ${TS}`);
    expect(post.body_markdown).toBeNull();
  });

  test("73.9 GET rich post as viewer (Bob) → same rich fields returned", async () => {
    const get = await apiGet(bobPage, BOB_ID, `/posts/${richPostId}`);
    expect(get.ok()).toBeTruthy();
    const post = await get.json();
    expect(post.body_format).toBe("rich");
    expect(post.body_rich?.type).toBe("doc");
    expect(post.body_plain).toBeTruthy();
  });

  // ── Format switching on edit ───────────────────────────────────────────────

  test("73.10 edit post format switching: plain → markdown → rich", async () => {
    const create = await apiPost(alicePage, ALICE_ID, "/posts", {
      body_plain:  `Edit switch ${TS}`,
      visibility: "followers",
    });
    expect(create.ok()).toBeTruthy();
    const { post_id } = await create.json();

    try {
      // plain → markdown
      const toMd = await apiPatch(alicePage, ALICE_ID, `/posts/${post_id}`, {
        body_plain:    "Switched to markdown",
        body_markdown: "**Switched to markdown**",
        body_format:   "markdown",
      });
      expect(toMd.ok()).toBeTruthy();
      const mdPost = await toMd.json();
      expect(mdPost.body_format).toBe("markdown");
      expect(mdPost.body_markdown).toContain("Switched to markdown");
      expect(mdPost.body_markdown_html).toContain("<strong>");

      // markdown → rich
      const toRich = await apiPatch(alicePage, ALICE_ID, `/posts/${post_id}`, {
        body_plain:  "Switched to rich",
        body_rich:   simpleRichDoc("Switched to rich"),
        body_format: "rich",
      });
      expect(toRich.ok()).toBeTruthy();
      const richPost = await toRich.json();
      expect(richPost.body_format).toBe("rich");
      expect(richPost.body_rich?.type).toBe("doc");
      expect(richPost.body_plain).toBe("Switched to rich");
    } finally {
      await apiDelete(alicePage, ALICE_ID, `/posts/${post_id}`);
    }
  });

  // ── Locked post body masking ───────────────────────────────────────────────

  test("73.11 locked rich post: author sees body_rich; viewer sees [Locked content] with body_format=plain", async () => {
    const create = await apiPost(alicePage, ALICE_ID, "/posts", {
      body_plain:         `Locked rich ${TS}`,
      body_rich:          simpleRichDoc(`Locked rich ${TS}`),
      body_format:        "rich",
      visibility:         "followers",
      unlock_price_cents: 300,
    });
    expect(create.ok()).toBeTruthy();
    const { post_id } = await create.json();

    try {
      // Author always sees full content
      const authorGet = await apiGet(alicePage, ALICE_ID, `/posts/${post_id}`);
      const authorPost = await authorGet.json();
      expect(authorPost.locked).toBe(true);
      expect(authorPost.body_format).toBe("rich");
      expect(authorPost.body_rich?.type).toBe("doc");

      // Bob has not unlocked → body masked
      const viewerGet = await apiGet(bobPage, BOB_ID, `/posts/${post_id}`);
      const viewerPost = await viewerGet.json();
      expect(viewerPost.locked).toBe(true);
      expect(viewerPost.body).toBe("[Locked content]");
      expect(viewerPost.body_format).toBe("plain");
      expect(viewerPost.body_rich).toBeNull();
      expect(viewerPost.body_markdown).toBeNull();
    } finally {
      await apiDelete(alicePage, ALICE_ID, `/posts/${post_id}`);
    }
  });

  // ── Validation errors ──────────────────────────────────────────────────────

  test("73.12 rich post without body_plain → 422 (body_plain required for rich format)", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/posts", {
      body_rich:   simpleRichDoc("No plain fallback"),
      body_format: "rich",
      visibility:  "followers",
      // body_plain intentionally omitted
    });
    expect(resp.ok()).toBeFalsy();
    expect(resp.status()).toBe(422);
  });

  test("73.13 rich post with unsupported node type (table) → 422", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/posts", {
      body_plain:  "x",
      body_rich:   {
        type: "doc",
        content: [{ type: "table", content: [] }],
      },
      body_format: "rich",
      visibility:  "followers",
    });
    expect(resp.ok()).toBeFalsy();
    expect(resp.status()).toBe(422);
  });

  test("73.14 rich mark with javascript: href → 422 (unsafe link protocol)", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/posts", {
      body_plain:  "x",
      body_rich:   {
        type: "doc",
        content: [{
          type: "paragraph",
          content: [{
            type: "text",
            text: "click me",
            marks: [{ type: "link", attrs: { href: "javascript:alert(1)" } }],
          }],
        }],
      },
      body_format: "rich",
      visibility:  "followers",
    });
    expect(resp.ok()).toBeFalsy();
    expect(resp.status()).toBe(422);
  });

  // ── Telemetry ──────────────────────────────────────────────────────────────

  test("73.15 telemetry content-render endpoint returns {ok: true} for both reason codes", async () => {
    const r1 = await apiPost(alicePage, ALICE_ID, "/telemetry/content-render", {
      reason:      "unsupported_format",
      body_format: "markdown",
      surface:     "post",
    });
    expect(r1.ok()).toBeTruthy();
    expect((await r1.json()).ok).toBe(true);

    const r2 = await apiPost(alicePage, ALICE_ID, "/telemetry/content-render", {
      reason:  "render_exception",
      surface: "comment",
    });
    expect(r2.ok()).toBeTruthy();
    expect((await r2.json()).ok).toBe(true);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Section 74 — Comment content API
// ═════════════════════════════════════════════════════════════════════════════

test.describe("Section 74: Comment content API", () => {
  let alicePage: Page;
  let bobPage:   Page;
  let postId:    string;   // shared host post

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await browser.newPage();
    bobPage   = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage,   BOB_ID);

    // Create the post that all comment tests attach to
    const resp = await apiPost(alicePage, ALICE_ID, "/posts", {
      body_plain:  `Section74 host ${TS}`,
      visibility: "followers",
    });
    expect(resp.ok()).toBeTruthy();
    postId = (await resp.json()).post_id;
  });

  test.afterAll(async () => {
    if (postId) await apiDelete(alicePage, ALICE_ID, `/posts/${postId}`);
    await alicePage.close();
    await bobPage.close();
  });

  // ── Plain ──────────────────────────────────────────────────────────────────

  test("74.1 legacy body field on comment → body_format: plain", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/posts/${postId}/comments`, {
      body: `Legacy comment ${TS}`,
    });
    expect(resp.ok()).toBeTruthy();
    const comment = await resp.json();
    expect(comment.body_format).toBe("plain");
    expect(comment.body).toContain("Legacy comment");
    expect(comment.body_markdown).toBeNull();
    expect(comment.body_rich).toBeNull();
  });

  test("74.2 body_plain only on comment → body_format: plain", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/posts/${postId}/comments`, {
      body_plain: `Plain comment ${TS}`,
    });
    expect(resp.ok()).toBeTruthy();
    const comment = await resp.json();
    expect(comment.body_format).toBe("plain");
    expect(comment.body_plain).toContain("Plain comment");
    expect(comment.body_rich).toBeNull();
  });

  // ── Markdown ───────────────────────────────────────────────────────────────

  test("74.3 markdown comment: body_markdown_html rendered, body_format=markdown", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/posts/${postId}/comments`, {
      body_plain:    `Markdown comment ${TS}`,
      body_markdown: `**Markdown comment** ${TS}\n\n- one\n- two`,
      body_format:   "markdown",
    });
    expect(resp.ok()).toBeTruthy();
    const comment = await resp.json();
    expect(comment.body_format).toBe("markdown");
    expect(comment.body_markdown).toContain("**Markdown comment**");
    expect(comment.body_markdown_html).toContain("<strong>");
    expect(comment.body_markdown_html).toContain("<ul>");
    expect(comment.body_markdown_html).toContain("<li>");
  });

  // ── Rich ───────────────────────────────────────────────────────────────────

  test("74.4 rich comment: body_rich populated, body_format=rich, body_plain present", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/posts/${postId}/comments`, {
      body_plain:  `Rich comment ${TS}`,
      body_rich:   simpleRichDoc(`Rich comment ${TS}`),
      body_format: "rich",
    });
    expect(resp.ok()).toBeTruthy();
    const comment = await resp.json();
    expect(comment.body_format).toBe("rich");
    expect(comment.body_rich?.type).toBe("doc");
    expect(comment.body_plain).toContain(`Rich comment ${TS}`);
    expect(comment.body_markdown).toBeNull();
  });

  // ── List view ──────────────────────────────────────────────────────────────

  test("74.5 GET comments list includes body_markdown_html and body_rich from viewer", async () => {
    // Create a markdown and a rich comment
    const mdCreate = await apiPost(alicePage, ALICE_ID, `/posts/${postId}/comments`, {
      body_plain:    `List md ${TS}`,
      body_markdown: `*List md* ${TS}`,
      body_format:   "markdown",
    });
    const { comment_id: mdId } = await mdCreate.json();

    const richCreate = await apiPost(alicePage, ALICE_ID, `/posts/${postId}/comments`, {
      body_plain:  `List rich ${TS}`,
      body_rich:   simpleRichDoc(`List rich ${TS}`),
      body_format: "rich",
    });
    const { comment_id: richId } = await richCreate.json();

    // Bob reads the list
    const list = await apiGet(bobPage, BOB_ID, `/posts/${postId}/comments`);
    expect(list.ok()).toBeTruthy();
    const { items } = await list.json();

    const mdComment = items.find((c: any) => c.comment_id === mdId);
    expect(mdComment).toBeTruthy();
    expect(mdComment.body_format).toBe("markdown");
    expect(mdComment.body_markdown_html).toContain("<em>");

    const richComment = items.find((c: any) => c.comment_id === richId);
    expect(richComment).toBeTruthy();
    expect(richComment.body_format).toBe("rich");
    expect(richComment.body_rich?.type).toBe("doc");
  });

  // ── Edit ───────────────────────────────────────────────────────────────────

  test("74.6 edit comment: markdown → rich format", async () => {
    const create = await apiPost(alicePage, ALICE_ID, `/posts/${postId}/comments`, {
      body_plain:    `Edit to rich ${TS}`,
      body_markdown: `*Edit to rich* ${TS}`,
      body_format:   "markdown",
    });
    const comment = await create.json();

    const edit = await apiPatch(alicePage, ALICE_ID, `/posts/${postId}/comments/${comment.comment_id}`, {
      body_plain:       `Edited as rich ${TS}`,
      body_rich:        simpleRichDoc(`Edited as rich ${TS}`),
      body_format:      "rich",
      expected_version: comment.version,
    });
    expect(edit.ok()).toBeTruthy();
    const edited = await edit.json();
    expect(edited.body_format).toBe("rich");
    expect(edited.body_rich?.type).toBe("doc");
    expect(edited.body_markdown).toBeNull();
    expect(edited.body_plain).toContain(`Edited as rich ${TS}`);
  });

  test("74.7 edit comment: rich → plain format", async () => {
    const create = await apiPost(alicePage, ALICE_ID, `/posts/${postId}/comments`, {
      body_plain:  `Rich to plain ${TS}`,
      body_rich:   simpleRichDoc(`Rich to plain ${TS}`),
      body_format: "rich",
    });
    const comment = await create.json();

    const edit = await apiPatch(alicePage, ALICE_ID, `/posts/${postId}/comments/${comment.comment_id}`, {
      body_plain:       `Now plain ${TS}`,
      body_format:      "plain",
      expected_version: comment.version,
    });
    expect(edit.ok()).toBeTruthy();
    const edited = await edit.json();
    expect(edited.body_format).toBe("plain");
    expect(edited.body_rich).toBeNull();
    expect(edited.body_markdown).toBeNull();
    expect(edited.body_plain).toContain("Now plain");
  });

  // ── Delete ─────────────────────────────────────────────────────────────────

  test("74.8 delete comment → deleted=true, all body fields null in list", async () => {
    const create = await apiPost(alicePage, ALICE_ID, `/posts/${postId}/comments`, {
      body_plain:    `To delete ${TS}`,
      body_markdown: `**To delete** ${TS}`,
      body_format:   "markdown",
    });
    const { comment_id } = await create.json();

    const del = await apiDelete(alicePage, ALICE_ID, `/posts/${postId}/comments/${comment_id}`);
    expect(del.ok()).toBeTruthy();

    const list = await apiGet(alicePage, ALICE_ID, `/posts/${postId}/comments`);
    const { items } = await list.json();
    const found = items.find((c: any) => c.comment_id === comment_id);
    expect(found).toBeTruthy();
    expect(found.deleted).toBe(true);
    expect(found.body).toBeNull();
    expect(found.body_plain).toBeNull();
    expect(found.body_markdown).toBeNull();
    expect(found.body_rich).toBeNull();
  });

  // ── Validation errors ──────────────────────────────────────────────────────

  test("74.9 comment with no body fields → 422", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/posts/${postId}/comments`, {
      parent_comment_id: null,
      // all body fields intentionally omitted
    });
    expect(resp.ok()).toBeFalsy();
    expect(resp.status()).toBe(422);
  });
});
