/**
 * E2E tests for Newsfeed Delegation (DELEGATE-003).
 *
 * Sections:
 *   495 -- Delegated Post Creation API      (5 tests)
 *   496 -- Draft Approval Workflow API      (4 tests)
 *   497 -- Comment Moderation API           (4 tests)
 *   498 -- Feed Analytics & Audit API       (3 tests)
 *
 * Auth: Alice (creator), Bob (delegate), Charlie (restricted delegate).
 * Uses cookie-based auth with CSRF headers on all mutating requests.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions, resolveIdentityId } from "./helpers/session";
import { cppSeedDelegateGrant } from "./helpers/cpp-seed";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// -- Constants ----------------------------------------------------------------

const BASE = "http://localhost:3000";
const ALICE_ID = resolveIdentityId("e2e_alice@test.local");
const BOB_ID = resolveIdentityId("e2e_bob@test.local");
const CHARLIE_ID = resolveIdentityId("e2e_charlie@test.local");

const TS = Date.now();

// -- Session bootstrap --------------------------------------------------------

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
    _sessions = loadSessions();
    // admin setup keys by short name (alice/bob); alias by user_sub so email-id lookups resolve
    for (const _k of Object.keys(_sessions)) { const _s = _sessions[_k]; if (_s && _s.user_sub && !_sessions[_s.user_sub]) _sessions[_s.user_sub] = _s; }
  }
  return _sessions!;
}

// -- Auth helpers -------------------------------------------------------------

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

// -- API helpers --------------------------------------------------------------

// Under a busy shard the shared backend can return 429 (rate limit). Retry a
// few times with backoff so creation/mutation calls that later tests depend on
// (e.g. createdPostId) don't fail spuriously and leave dependents undefined.
async function withRetry429(fn: () => Promise<any>) {
  let resp = await fn();
  for (let i = 0; i < 4 && resp.status() === 429; i++) {
    await new Promise((r) => setTimeout(r, 400 * (i + 1)));
    resp = await fn();
  }
  return resp;
}

async function apiPost(page: Page, userId: string, path: string, body: object) {
  const session = getSessions()[userId];
  return withRetry429(() =>
    page.request.post(`${BASE}${path}`, {
      data: body,
      headers: { "x-csrf-token": session.csrf_token },
    }),
  );
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return withRetry429(() => page.request.get(`${BASE}${path}`, params ? { params } : undefined));
}

async function apiPut(page: Page, userId: string, path: string, body: object) {
  const session = getSessions()[userId];
  return withRetry429(() =>
    page.request.put(`${BASE}${path}`, {
      data: body,
      headers: { "x-csrf-token": session.csrf_token },
    }),
  );
}

async function apiDelete(page: Page, userId: string, path: string) {
  const session = getSessions()[userId];
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// -- Delegate setup helpers ---------------------------------------------------

async function ensureBobIsDelegateWithPerms(
  alicePage: Page,
  perms: string[],
) {
  // Try to revoke first to avoid 409
  await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${BOB_ID}`);

  // Set require_acceptance = false so delegation is immediately active
  await apiPut(alicePage, ALICE_ID, "/ui/delegates/settings", {
    require_acceptance: false,
    max_delegates: 10,
    delegate_tag_enabled: true,
    delegate_tag_format: "[via @{delegate_name}]",
  });

  const addResp = await apiPost(alicePage, ALICE_ID, "/ui/delegates", {
    delegate_id: BOB_ID,
    permissions: perms,
    label: "Bob - Feed Delegate",
  });
  expect(addResp.ok()).toBeTruthy();
  // cpp does not port /ui/delegates grant-CRUD into tlc_delegates, which the
  // newsfeed-delegate feed reads; seed the active grant directly so feed_read/
  // feed_post/feed_moderate authorize (the POST above is a no-op on cpp).
  cppSeedDelegateGrant(ALICE_ID, BOB_ID, perms, "Bob - Feed Delegate");
}

async function ensureCharlieIsDelegateWithPerms(
  alicePage: Page,
  perms: string[],
) {
  await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${CHARLIE_ID}`);

  await apiPut(alicePage, ALICE_ID, "/ui/delegates/settings", {
    require_acceptance: false,
    max_delegates: 10,
    delegate_tag_enabled: true,
    delegate_tag_format: "[via @{delegate_name}]",
  });

  const addResp = await apiPost(alicePage, ALICE_ID, "/ui/delegates", {
    delegate_id: CHARLIE_ID,
    permissions: perms,
    label: "Charlie - Limited",
  });
  expect(addResp.ok()).toBeTruthy();
  cppSeedDelegateGrant(ALICE_ID, CHARLIE_ID, perms, "Charlie - Limited");
}

// =============================================================================
// Section 495: Delegated Post Creation API (5 tests)
// =============================================================================

test.describe("495 -- Delegated Post Creation API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let charliePage: Page;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    const charlieCtx = await browser.newContext();
    charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, CHARLIE_ID);

    // Reset feed delegation settings: no approval required
    await apiPut(alicePage, ALICE_ID, `/ui/newsfeed/delegate/${ALICE_ID}/settings`, {
      require_post_approval: false,
      allow_delegate_scheduling: true,
      allow_delegate_locking: false,
      delegate_tag_on_posts: false,
    });

    // Bob gets feed_post + feed_read + feed_moderate
    await ensureBobIsDelegateWithPerms(alicePage, [
      "feed_post",
      "feed_read",
      "feed_moderate",
    ]);

    // Charlie gets only chat_read (no feed permissions)
    await ensureCharlieIsDelegateWithPerms(alicePage, ["chat_read"]);
  });

  test.afterAll(async () => {
    // Cleanup: revoke delegates
    await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${BOB_ID}`);
    await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${CHARLIE_ID}`);
    await alicePage.context().close();
    await bobPage.context().close();
    await charliePage.context().close();
  });

  test("495.1 Delegate creates a post on creator's feed", async () => {
    const text = `Delegated post ${TS}`;
    const resp = await apiPost(bobPage, BOB_ID, `/ui/newsfeed/delegate/${ALICE_ID}/posts`, {
      text,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.author_id).toBe(ALICE_ID);
    expect(data.posted_by_delegate).toBe(BOB_ID);
    expect(data.text).toBe(text);
    expect(data.status).toBe("published");
    expect(data.approval_status).toBe("approved");
    expect(typeof data.post_id).toBe("string");
  });

  test("495.2 Post appears in creator's post list", async () => {
    // Self-contained: create our own post here rather than depending on a
    // describe-scope variable set by 495.1. On a busy shard a retry can spawn a
    // fresh worker process (resetting `createdPostId`), and the GET can be
    // transiently non-ok; create+poll makes this test robust to both.
    const text = `List-check post ${TS}_${Math.random().toString(36).slice(2, 7)}`;
    const cResp = await apiPost(bobPage, BOB_ID, `/ui/newsfeed/delegate/${ALICE_ID}/posts`, { text });
    expect(cResp.status()).toBe(201);
    const myPostId = (await cResp.json()).post_id as string;

    // Retry the whole GET — under full-suite load the list endpoint can return
    // a transient non-ok (e.g. delegate-row read lag) before the post is
    // visible, so don't hard-fail on a single non-ok response.
    let found: any = undefined;
    let lastOk = false;
    for (let attempt = 0; attempt < 8 && !found; attempt++) {
      const resp = await apiGet(bobPage, `/ui/newsfeed/delegate/${ALICE_ID}/posts`, { limit: "200" });
      lastOk = resp.ok();
      if (lastOk) {
        const data = await resp.json();
        found = data.find((p: any) => p.post_id === myPostId);
      }
      if (!found) await new Promise((r) => setTimeout(r, 300 * (attempt + 1)));
    }
    expect(lastOk).toBeTruthy();
    expect(found).toBeTruthy();
    expect(found.author_id).toBe(ALICE_ID);
  });

  test("495.3 Delegate tag appended when enabled", async () => {
    // Enable delegate tag
    await apiPut(alicePage, ALICE_ID, `/ui/newsfeed/delegate/${ALICE_ID}/settings`, {
      require_post_approval: false,
      delegate_tag_on_posts: true,
      delegate_tag_format: "[posted by @{delegate_name}]",
    });

    const text = `Tagged post ${TS}`;
    const resp = await apiPost(bobPage, BOB_ID, `/ui/newsfeed/delegate/${ALICE_ID}/posts`, {
      text,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.delegate_tag).toContain("posted by @");

    // Reset
    await apiPut(alicePage, ALICE_ID, `/ui/newsfeed/delegate/${ALICE_ID}/settings`, {
      require_post_approval: false,
      delegate_tag_on_posts: false,
    });
  });

  test("495.4 Delegate without feed_post gets 403", async () => {
    const resp = await apiPost(charliePage, CHARLIE_ID, `/ui/newsfeed/delegate/${ALICE_ID}/posts`, {
      text: "Should fail",
    });
    expect(resp.status()).toBe(403);
  });

  test("495.5 Delegate edits creator's post", async () => {
    // Self-contained: create the post we edit in this test so the edit target
    // is valid even when a retry runs in a fresh worker (where the describe-scope
    // `createdPostId` from 495.1 would be undefined → PUT /posts/undefined → 404).
    const cResp = await apiPost(bobPage, BOB_ID, `/ui/newsfeed/delegate/${ALICE_ID}/posts`, {
      text: `Post to edit ${TS}_${Math.random().toString(36).slice(2, 7)}`,
    });
    expect(cResp.status()).toBe(201);
    const editPostId = (await cResp.json()).post_id as string;

    const updatedText = `Edited delegated post ${TS}`;
    const resp = await apiPut(bobPage, BOB_ID, `/ui/newsfeed/delegate/${ALICE_ID}/posts/${editPostId}`, {
      text: updatedText,
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.text).toBe(updatedText);
    expect(data.posted_by_delegate).toBe(BOB_ID);
  });
});

// =============================================================================
// Section 496: Draft Approval Workflow API (4 tests)
// =============================================================================

test.describe("496 -- Draft Approval Workflow API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let draftPostId: string;
  let rejectDraftId: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    // Bob gets feed_post + feed_read
    await ensureBobIsDelegateWithPerms(alicePage, [
      "feed_post",
      "feed_read",
    ]);

    // Enable approval requirement
    await apiPut(alicePage, ALICE_ID, `/ui/newsfeed/delegate/${ALICE_ID}/settings`, {
      require_post_approval: true,
      delegate_tag_on_posts: false,
    });
  });

  test.afterAll(async () => {
    // Reset settings
    await apiPut(alicePage, ALICE_ID, `/ui/newsfeed/delegate/${ALICE_ID}/settings`, {
      require_post_approval: false,
    });
    await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${BOB_ID}`);
    await alicePage.context().close();
    await bobPage.context().close();
  });

  test("496.1 Delegate post saved as draft when approval required", async () => {
    const text = `Draft for approval ${TS}`;
    const resp = await apiPost(bobPage, BOB_ID, `/ui/newsfeed/delegate/${ALICE_ID}/posts`, {
      text,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.status).toBe("draft");
    expect(data.approval_status).toBe("pending");
    expect(data.posted_by_delegate).toBe(BOB_ID);
    draftPostId = data.post_id;

    // Create another for reject test
    const resp2 = await apiPost(bobPage, BOB_ID, `/ui/newsfeed/delegate/${ALICE_ID}/posts`, {
      text: `Reject candidate ${TS}`,
    });
    expect(resp2.status()).toBe(201);
    rejectDraftId = (await resp2.json()).post_id;
  });

  test("496.2 Pending drafts appear in creator's queue", async () => {
    const resp = await apiGet(alicePage, `/ui/newsfeed/delegate/${ALICE_ID}/drafts`);
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    const found = data.find((d: any) => d.post_id === draftPostId);
    expect(found).toBeTruthy();
    expect(found.approval_status).toBe("pending");
  });

  test("496.3 Creator approves draft and it publishes", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/newsfeed/delegate/${ALICE_ID}/drafts/${draftPostId}/approve`, {
      note: "Looks good!",
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.status).toBe("published");
    expect(data.approval_status).toBe("approved");
  });

  test("496.4 Creator rejects draft with note", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/newsfeed/delegate/${ALICE_ID}/drafts/${rejectDraftId}/reject`, {
      note: "Not on brand",
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.approval_status).toBe("rejected");
    expect(data.approval_note).toBe("Not on brand");

    // Verify removed from draft queue
    const queueResp = await apiGet(alicePage, `/ui/newsfeed/delegate/${ALICE_ID}/drafts`);
    const queue = await queueResp.json();
    const stillInQueue = queue.find((d: any) => d.post_id === rejectDraftId);
    expect(stillInQueue).toBeFalsy();
  });
});

// =============================================================================
// Section 497: Comment Moderation API (4 tests)
// =============================================================================

test.describe("497 -- Comment Moderation API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let charliePage: Page;
  let postId: string;
  let commentId: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    const charlieCtx = await browser.newContext();
    charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, CHARLIE_ID);

    // Reset settings
    await apiPut(alicePage, ALICE_ID, `/ui/newsfeed/delegate/${ALICE_ID}/settings`, {
      require_post_approval: false,
      delegate_tag_on_posts: false,
    });

    // Bob gets feed_moderate + feed_post + feed_read
    await ensureBobIsDelegateWithPerms(alicePage, [
      "feed_post",
      "feed_read",
      "feed_moderate",
    ]);

    // Charlie gets only feed_post (no feed_moderate)
    await ensureCharlieIsDelegateWithPerms(alicePage, ["feed_post"]);

    // Alice creates a post directly (as the creator) for comments.
    // Make it public so Bob (a regular, non-following user) can comment on it —
    // the default "followers" visibility would 403 his comment via can_view_post.
    const postResp = await apiPost(alicePage, ALICE_ID, "/posts", {
      body: `Moderation test post ${TS}`,
      visibility: "public",
    });
    expect(postResp.ok()).toBeTruthy();
    const postData = await postResp.json();
    postId = postData.post_id;

    // Bob writes a comment on it (as a regular user, not delegate)
    const commentResp = await apiPost(bobPage, BOB_ID, `/posts/${postId}/comments`, {
      body: `Comment to moderate ${TS}`,
    });
    expect(commentResp.ok()).toBeTruthy();
    const commentData = await commentResp.json();
    commentId = commentData.comment_id;
  });

  test.afterAll(async () => {
    await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${BOB_ID}`);
    await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${CHARLIE_ID}`);
    await alicePage.context().close();
    await bobPage.context().close();
    await charliePage.context().close();
  });

  test("497.1 Delegate hides a comment", async () => {
    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/newsfeed/delegate/${ALICE_ID}/posts/${postId}/comments/${commentId}/moderate`,
      { action: "hide" },
    );
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.moderation_action).toBe("hidden");
    expect(data.moderated_by).toBe(BOB_ID);
  });

  test("497.2 Delegate pins a comment", async () => {
    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/newsfeed/delegate/${ALICE_ID}/posts/${postId}/comments/${commentId}/moderate`,
      { action: "pin" },
    );
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.moderation_action).toBe("pinned");
  });

  test("497.3 Delegate deletes a comment", async () => {
    // Create a new comment to delete (since we need a non-hidden one)
    const newCommentResp = await apiPost(bobPage, BOB_ID, `/posts/${postId}/comments`, {
      body: `Comment to delete ${TS}`,
    });
    expect(newCommentResp.ok()).toBeTruthy();
    const newComment = await newCommentResp.json();

    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/newsfeed/delegate/${ALICE_ID}/posts/${postId}/comments/${newComment.comment_id}/moderate`,
      { action: "delete" },
    );
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.moderation_action).toBe("deleted");
  });

  test("497.4 Delegate without feed_moderate gets 403 on moderation", async () => {
    const resp = await apiPost(
      charliePage,
      CHARLIE_ID,
      `/ui/newsfeed/delegate/${ALICE_ID}/posts/${postId}/comments/${commentId}/moderate`,
      { action: "hide" },
    );
    expect(resp.status()).toBe(403);
  });
});

// =============================================================================
// Section 498: Feed Analytics & Audit API (3 tests)
// =============================================================================

test.describe("498 -- Feed Analytics & Audit API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let charliePage: Page;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    const charlieCtx = await browser.newContext();
    charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, CHARLIE_ID);

    // Reset settings
    await apiPut(alicePage, ALICE_ID, `/ui/newsfeed/delegate/${ALICE_ID}/settings`, {
      require_post_approval: false,
      delegate_tag_on_posts: false,
    });

    // Bob gets feed_read + feed_post + feed_moderate
    await ensureBobIsDelegateWithPerms(alicePage, [
      "feed_post",
      "feed_read",
      "feed_moderate",
    ]);

    // Charlie gets only feed_post (no feed_read)
    await ensureCharlieIsDelegateWithPerms(alicePage, ["feed_post"]);

    // Bob creates a post to generate audit data
    await apiPost(bobPage, BOB_ID, `/ui/newsfeed/delegate/${ALICE_ID}/posts`, {
      text: `Analytics test post ${TS}`,
    });
  });

  test.afterAll(async () => {
    await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${BOB_ID}`);
    await apiDelete(alicePage, ALICE_ID, `/ui/delegates/${CHARLIE_ID}`);
    await alicePage.context().close();
    await bobPage.context().close();
    await charliePage.context().close();
  });

  test("498.1 Delegate views creator's feed analytics", async () => {
    const resp = await apiGet(bobPage, `/ui/newsfeed/delegate/${ALICE_ID}/analytics`);
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.total_posts).toBeGreaterThanOrEqual(0);
    expect(typeof data.delegate_post_count).toBe("number");
    expect(data.period).toBe("30d");
  });

  test("498.2 Delegate without feed_read gets 403 on analytics", async () => {
    const resp = await apiGet(charliePage, `/ui/newsfeed/delegate/${ALICE_ID}/analytics`);
    expect(resp.status()).toBe(403);
  });

  test("498.3 Creator audit log records delegate actions", async () => {
    const resp = await apiGet(alicePage, `/ui/newsfeed/delegate/${ALICE_ID}/audit`);
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    // Should have at least one feed action
    const feedActions = data.filter((e: any) =>
      e.action.startsWith("feed_"),
    );
    expect(feedActions.length).toBeGreaterThanOrEqual(1);
    // Check structure
    const entry = feedActions[0];
    expect(entry.event_id).toBeTruthy();
    expect(entry.delegate_id).toBeTruthy();
    expect(entry.action).toBeTruthy();
    expect(entry.ts).toBeGreaterThan(0);
  });
});
