/**
 * E2E tests for Group Page & Newsfeed (GROUP-002).
 *
 * Depends on GROUP-001 (User Groups) infrastructure.
 *
 * Sections:
 *   451 — Group Post Creation API        (4 tests)
 *   452 — Group Feed Query API           (4 tests)
 *   453 — Pin & Moderation API           (4 tests)
 *   454 — Group Page UI                  (4 tests)
 *   455 — Edge Cases & Negative Tests    (4 tests)
 *   456 — Pagination & Audience Filter   (4 tests)
 *
 * Auth: Alice (admin), Bob (member), Charlie (non-member).
 * Sessions from e2e_session_setup.py.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";
const TS = Date.now();

// ─── Session bootstrap ───────────────────────────────────────────────────────

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
  // ProtectedRoute gates on the persisted auth-store; cookies alone are not
  // enough for UI navigation. Seed the zustand auth-store so UI routes render.
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    ({ uid, token }: { uid: string; token: string }) => {
      const state = { userId: uid, accessToken: token, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    { uid: userId, token: session.access_token },
  );
}

function csrfHeader(userId: string) {
  return { "x-csrf-token": getSessions()[userId].csrf_token };
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, userId: string, path: string, data?: any) {
  return page.request.post(`${BASE}${path}`, {
    headers: { ...csrfHeader(userId), "content-type": "application/json" },
    data,
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  const url = new URL(`${BASE}${path}`);
  if (params) {
    Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
  }
  return page.request.get(url.toString());
}

async function apiDelete(page: Page, userId: string, path: string) {
  return page.request.delete(`${BASE}${path}`, {
    headers: csrfHeader(userId),
  });
}

async function apiPatch(page: Page, userId: string, path: string, data?: any) {
  return page.request.patch(`${BASE}${path}`, {
    headers: { ...csrfHeader(userId), "content-type": "application/json" },
    data,
  });
}

// ─── Shared state ─────────────────────────────────────────────────────────────

let groupId: string;
let publicPostId: string;
let membersOnlyPostId: string;
let pinnedPostId: string;
let alicePage: Page;
let bobPage: Page;
let charliePage: Page;
const GROUP_NAME = `E2E Feed Group ${TS}`;

// ─── Setup ────────────────────────────────────────────────────────────────────

test.beforeAll(async ({ browser }) => {
  // Create pages for each identity
  alicePage = await browser.newPage();
  bobPage = await browser.newPage();
  charliePage = await browser.newPage();

  await injectAuth(alicePage, ALICE_ID);
  await injectAuth(bobPage, BOB_ID);
  await injectAuth(charliePage, CHARLIE_ID);

  // Create a test group (Alice is admin)
  const createResp = await apiPost(alicePage, ALICE_ID, "/ui/groups", {
    name: GROUP_NAME,
    description: `Test group for feed E2E ${TS}`,
    visibility: "public",
    topic: "testing",
  });
  expect(createResp.status()).toBe(201);
  const groupData = await createResp.json();
  groupId = groupData.group_id;

  // Bob joins the group
  const joinResp = await apiPost(bobPage, BOB_ID, `/ui/groups/${groupId}/join`);
  expect(joinResp.status()).toBe(200);
});

test.afterAll(async () => {
  await alicePage?.close();
  await bobPage?.close();
  await charliePage?.close();
});

// ─── Section 451: Group Post Creation API ─────────────────────────────────────

test.describe("451 — Group Post Creation API", () => {
  test("451.1 Member creates public post", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/groups/${groupId}/posts`, {
      text: `Public post ${TS}`,
      audience: "public",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.group_id).toBe(groupId);
    expect(data.audience).toBe("public");
    expect(data.post_id).toBeTruthy();
    publicPostId = data.post_id;
  });

  test("451.2 Member creates members-only post", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/groups/${groupId}/posts`, {
      text: `Members only post ${TS}`,
      audience: "members_only",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.audience).toBe("members_only");
    membersOnlyPostId = data.post_id;
  });

  test("451.3 Non-member cannot create post", async () => {
    const resp = await apiPost(charliePage, CHARLIE_ID, `/ui/groups/${groupId}/posts`, {
      text: "Should fail",
      audience: "public",
    });
    expect(resp.status()).toBe(403);
  });

  test("451.4 Post appears in group feed", async () => {
    const resp = await apiGet(alicePage, `/ui/groups/${groupId}/feed`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const postIds = data.posts.map((p: any) => p.post_id);
    expect(postIds).toContain(publicPostId);
  });
});

// ─── Section 452: Group Feed Query API ────────────────────────────────────────

test.describe("452 — Group Feed Query API", () => {
  test("452.1 Member sees all posts", async () => {
    const resp = await apiGet(bobPage, `/ui/groups/${groupId}/feed`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const postIds = data.posts.map((p: any) => p.post_id);
    expect(postIds).toContain(publicPostId);
    expect(postIds).toContain(membersOnlyPostId);
  });

  test("452.2 Non-member sees only public posts", async () => {
    const resp = await apiGet(charliePage, `/ui/groups/${groupId}/feed`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const audiences = data.posts.map((p: any) => p.audience);
    expect(audiences).not.toContain("members_only");
    const postIds = data.posts.map((p: any) => p.post_id);
    expect(postIds).toContain(publicPostId);
  });

  test("452.3 Public feed endpoint returns public only", async () => {
    // Hit backend directly for public endpoint (no auth, no Vite proxy needed)
    const resp = await alicePage.request.get(
      `http://localhost:8000/public/groups/${groupId}/feed`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    for (const post of data.posts) {
      expect(post.audience).toBe("public");
    }
  });

  test("452.4 Pinned post appears first", async () => {
    // Create a post to pin
    const createResp = await apiPost(alicePage, ALICE_ID, `/ui/groups/${groupId}/posts`, {
      text: `Pinnable post ${TS}`,
      audience: "public",
    });
    expect(createResp.status()).toBe(201);
    pinnedPostId = (await createResp.json()).post_id;

    // Pin it
    const pinResp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/groups/${groupId}/posts/${pinnedPostId}/pin`,
    );
    expect(pinResp.status()).toBe(200);

    // Check feed — pinned should be first
    const feedResp = await apiGet(alicePage, `/ui/groups/${groupId}/feed`);
    const feedData = await feedResp.json();
    expect(feedData.posts[0].post_id).toBe(pinnedPostId);
    expect(feedData.posts[0].pinned).toBe(true);
  });
});

// ─── Section 453: Pin & Moderation API ────────────────────────────────────────

test.describe("453 — Pin & Moderation API", () => {
  let modPostId: string;

  test("453.1 Admin pins a post", async () => {
    // Create a new post to pin
    const createResp = await apiPost(alicePage, ALICE_ID, `/ui/groups/${groupId}/posts`, {
      text: `Pin test post ${TS}`,
      audience: "public",
    });
    const postData = await createResp.json();
    modPostId = postData.post_id;

    const pinResp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/groups/${groupId}/posts/${modPostId}/pin`,
    );
    expect(pinResp.status()).toBe(200);
    const pinData = await pinResp.json();
    expect(pinData.pinned).toBe(true);
    expect(pinData.pinned_at).toBeTruthy();
  });

  test("453.2 Pinned post first in feed", async () => {
    const resp = await apiGet(alicePage, `/ui/groups/${groupId}/feed`);
    const data = await resp.json();
    // All pinned posts should be at the top
    const pinnedPosts = data.posts.filter((p: any) => p.pinned);
    expect(pinnedPosts.length).toBeGreaterThanOrEqual(1);
    // First post should be pinned
    expect(data.posts[0].pinned).toBe(true);
  });

  test("453.3 Admin unpins a post", async () => {
    const unpinResp = await apiDelete(
      alicePage,
      ALICE_ID,
      `/ui/groups/${groupId}/posts/${modPostId}/pin`,
    );
    expect(unpinResp.status()).toBe(200);
    const data = await unpinResp.json();
    expect(data.pinned).toBe(false);
  });

  test("453.4 Author deletes own post", async () => {
    // Bob creates a post
    const createResp = await apiPost(bobPage, BOB_ID, `/ui/groups/${groupId}/posts`, {
      text: `Deletable post ${TS}`,
      audience: "public",
    });
    const postData = await createResp.json();
    const deletePostId = postData.post_id;

    // Bob deletes it
    const delResp = await apiDelete(
      bobPage,
      BOB_ID,
      `/ui/groups/${groupId}/posts/${deletePostId}`,
    );
    expect(delResp.status()).toBe(200);
    const delData = await delResp.json();
    expect(delData.ok).toBe(true);

    // Verify gone from feed
    const feedResp = await apiGet(alicePage, `/ui/groups/${groupId}/feed`);
    const feedData = await feedResp.json();
    const postIds = feedData.posts.map((p: any) => p.post_id);
    expect(postIds).not.toContain(deletePostId);
  });
});

// ─── Section 454: Group Page UI ───────────────────────────────────────────────

test.describe("454 — Group Page UI", () => {
  test("454.1 Group page displays info", async () => {
    await alicePage.goto(`${BASE}/groups/${groupId}`);
    await expect(alicePage.locator("[data-testid='group-page']")).toBeVisible();
    await expect(alicePage.getByText(GROUP_NAME)).toBeVisible();
  });

  test("454.2 Member sees composer", async () => {
    await alicePage.goto(`${BASE}/groups/${groupId}`);
    await expect(
      alicePage.locator("[data-testid='group-post-composer']"),
    ).toBeVisible();
  });

  test("454.3 Non-member sees CTA", async () => {
    // Charlie is not a member
    await charliePage.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await charliePage.evaluate((uid: string) => {
      const state = { userId: uid, accessToken: null, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    }, CHARLIE_ID);
    await charliePage.goto(`${BASE}/groups/${groupId}`);
    await expect(
      charliePage.getByText("Join to see all posts"),
    ).toBeVisible();
  });

  test("454.4 Pin badge displayed", async () => {
    // Pin a fresh post here rather than relying on pinnedPostId staying pinned
    // across earlier sections. Make room first if the group is already at the
    // 3-pin cap (backend rejects a 4th pin with 409).
    const feedResp = await apiGet(alicePage, `/ui/groups/${groupId}/feed`);
    const feedData = await feedResp.json();
    const pinnedNow: string[] = (feedData.posts || [])
      .filter((p: any) => p.pinned)
      .map((p: any) => p.post_id);
    if (pinnedNow.length >= 3) {
      await apiDelete(alicePage, ALICE_ID, `/ui/groups/${groupId}/posts/${pinnedNow[0]}/pin`);
    }
    const createResp = await apiPost(alicePage, ALICE_ID, `/ui/groups/${groupId}/posts`, {
      text: `Badge pin post ${TS}`,
      audience: "public",
    });
    const badgePostId = (await createResp.json()).post_id;
    const pinResp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/groups/${groupId}/posts/${badgePostId}/pin`,
    );
    expect(pinResp.status()).toBe(200);

    // Confirm via the API that the post is pinned and surfaces on the first
    // feed page (the backend keeps pinned posts on page 1 regardless of age).
    await expect
      .poll(async () => {
        const fr = await apiGet(alicePage, `/ui/groups/${groupId}/feed`);
        const fd = await fr.json();
        const found = (fd.posts || []).find((p: any) => p.post_id === badgePostId);
        return !!(found && found.pinned);
      }, { timeout: 8_000 })
      .toBe(true);

    // Navigate fresh and confirm the feed actually rendered THIS post (the
    // group-feed query has a 30s staleTime + is reused across 454.x tests, so a
    // stale-empty render can otherwise win). Retry the full reload until the
    // post's text is on screen, then assert the Pinned badge.
    let postRendered = false;
    for (let attempt = 0; attempt < 3 && !postRendered; attempt++) {
      await alicePage.goto(`${BASE}/groups/${groupId}`, { waitUntil: "load" });
      await alicePage.getByTestId("group-page").waitFor({ timeout: 10_000 }).catch(() => {});
      postRendered = await alicePage
        .getByText(`Badge pin post ${TS}`)
        .first()
        .isVisible({ timeout: 10_000 })
        .catch(() => false);
    }
    await expect(alicePage.getByText(`Badge pin post ${TS}`).first()).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.getByText("Pinned").first()).toBeVisible({ timeout: 10_000 });
  });
});

// ─── Section 455: Edge Cases & Negative Tests ─────────────────────────────────

test.describe("455 — Edge Cases & Negative Tests", () => {
  test("455.1 Create post with empty text fails", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/groups/${groupId}/posts`, {
      text: "   ",
      audience: "public",
    });
    expect(resp.status()).toBe(422);
  });

  test("455.2 Pin more than 3 posts fails", async () => {
    // Make this self-contained instead of relying on a specific pin count
    // carried over from earlier sections (cross-section pin state is fragile):
    // first unpin everything currently pinned, then pin exactly 3, then assert
    // the 4th is rejected with 409 (backend cap is 3 — see _MAX_PINNED).
    const feedResp = await apiGet(alicePage, `/ui/groups/${groupId}/feed`);
    const feedData = await feedResp.json();
    const alreadyPinned: string[] = (feedData.posts || [])
      .filter((p: any) => p.pinned)
      .map((p: any) => p.post_id);
    for (const id of alreadyPinned) {
      await apiDelete(alicePage, ALICE_ID, `/ui/groups/${groupId}/posts/${id}/pin`);
    }

    // Create and pin exactly 3 posts (each must succeed).
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) {
      const createResp = await apiPost(alicePage, ALICE_ID, `/ui/groups/${groupId}/posts`, {
        text: `Extra pin post ${i} ${TS}`,
        audience: "public",
      });
      const data = await createResp.json();
      ids.push(data.post_id);
      const pinResp = await apiPost(
        alicePage,
        ALICE_ID,
        `/ui/groups/${groupId}/posts/${data.post_id}/pin`,
      );
      expect(pinResp.status()).toBe(200);
    }

    // Attempt a 4th pin (should fail with 409)
    const createResp = await apiPost(alicePage, ALICE_ID, `/ui/groups/${groupId}/posts`, {
      text: `Fourth pin ${TS}`,
      audience: "public",
    });
    const data = await createResp.json();
    const pinResp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/groups/${groupId}/posts/${data.post_id}/pin`,
    );
    expect(pinResp.status()).toBe(409);

    // Cleanup: unpin the extras
    for (const id of ids) {
      await apiDelete(alicePage, ALICE_ID, `/ui/groups/${groupId}/posts/${id}/pin`);
    }
  });

  test("455.3 Delete non-existent post returns 404", async () => {
    const resp = await apiDelete(
      alicePage,
      ALICE_ID,
      `/ui/groups/${groupId}/posts/post_nonexistent_xyz`,
    );
    expect(resp.status()).toBe(404);
  });

  test("455.4 Feed for dissolved group returns 410", async () => {
    // Create a temporary group and dissolve it
    const createResp = await apiPost(alicePage, ALICE_ID, "/ui/groups", {
      name: `Dissolve Test ${TS}`,
      description: "Will be dissolved",
      visibility: "public",
    });
    const tempGroup = await createResp.json();
    const tempId = tempGroup.group_id;

    // Dissolve
    const dissolveResp = await apiDelete(alicePage, ALICE_ID, `/ui/groups/${tempId}`);
    expect(dissolveResp.status()).toBe(200);

    // Try to read feed
    const feedResp = await apiGet(alicePage, `/ui/groups/${tempId}/feed`);
    expect(feedResp.status()).toBe(410);
  });
});

// ─── Section 456: Pagination & Audience Filtering ─────────────────────────────

test.describe("456 — Pagination & Audience Filtering", () => {
  let paginationGroupId: string;

  test.beforeAll(async () => {
    // Create a separate group for pagination tests
    const createResp = await apiPost(alicePage, ALICE_ID, "/ui/groups", {
      name: `Pagination Group ${TS}`,
      description: "For pagination tests",
      visibility: "public",
    });
    const data = await createResp.json();
    paginationGroupId = data.group_id;
  });

  test("456.1 Pagination returns correct page size", async () => {
    // Create 15 posts
    for (let i = 0; i < 15; i++) {
      const resp = await apiPost(
        alicePage,
        ALICE_ID,
        `/ui/groups/${paginationGroupId}/posts`,
        { text: `Pagination post ${i} ${TS}`, audience: "public" },
      );
      expect(resp.status()).toBe(201);
    }

    const resp = await apiGet(alicePage, `/ui/groups/${paginationGroupId}/feed`, {
      limit: "10",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.posts.length).toBe(10);
    expect(data.has_more).toBe(true);
  });

  test("456.2 Cursor continues from last page", async () => {
    const resp1 = await apiGet(alicePage, `/ui/groups/${paginationGroupId}/feed`, {
      limit: "10",
    });
    const data1 = await resp1.json();
    expect(data1.cursor).toBeTruthy();

    const resp2 = await apiGet(alicePage, `/ui/groups/${paginationGroupId}/feed`, {
      limit: "10",
      cursor: data1.cursor,
    });
    const data2 = await resp2.json();
    expect(data2.posts.length).toBeGreaterThanOrEqual(1);
    // Pages should have different posts
    const ids1 = new Set(data1.posts.map((p: any) => p.post_id));
    for (const p of data2.posts) {
      expect(ids1.has(p.post_id)).toBe(false);
    }
  });

  test("456.3 Members-only posts excluded from public feed", async () => {
    // Create both public and members-only posts
    for (let i = 0; i < 3; i++) {
      await apiPost(alicePage, ALICE_ID, `/ui/groups/${paginationGroupId}/posts`, {
        text: `Public paginated ${i} ${TS}`,
        audience: "public",
      });
      await apiPost(alicePage, ALICE_ID, `/ui/groups/${paginationGroupId}/posts`, {
        text: `Members only paginated ${i} ${TS}`,
        audience: "members_only",
      });
    }

    // Public feed should only have public posts
    const publicResp = await alicePage.request.get(
      `${BASE}/public/groups/${paginationGroupId}/feed?limit=50`,
    );
    const publicData = await publicResp.json();
    for (const post of publicData.posts) {
      expect(post.audience).toBe("public");
    }
  });

  test("456.4 Locked post visible but text hidden for non-author", async () => {
    // Bob joins the pagination group
    await apiPost(bobPage, BOB_ID, `/ui/groups/${paginationGroupId}/join`);

    // Alice creates a locked post
    const createResp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/groups/${paginationGroupId}/posts`,
      {
        text: `Locked content ${TS}`,
        audience: "public",
        unlock_price_cents: 500,
      },
    );
    expect(createResp.status()).toBe(201);
    const lockedPost = await createResp.json();

    // Bob sees the post but text is null and unlocked is false
    const feedResp = await apiGet(bobPage, `/ui/groups/${paginationGroupId}/feed`);
    const feedData = await feedResp.json();
    const found = feedData.posts.find((p: any) => p.post_id === lockedPost.post_id);
    expect(found).toBeTruthy();
    expect(found.text).toBeNull();
    expect(found.unlocked).toBe(false);
  });
});
