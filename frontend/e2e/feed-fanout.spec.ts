/**
 * E2E tests for SOC-002: Feed Fan-Out on Write
 *
 * Section 115: Fan-out API (8 tests)
 * Section 116: Source attribution API (4 tests)
 * Section 117: Feed Timeline UI (3 tests)
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";
const BASE = "http://localhost:3000";
const TS = Date.now();

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
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

function csrf(identity: string): Record<string, string> {
  return { "x-csrf-token": getSessions()[identity].csrf_token };
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { ...csrf(identity), "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, identity: string, path: string) {
  return page.request.get(`${API}${path}`, { headers: csrf(identity) });
}

async function apiDelete(page: Page, identity: string, path: string) {
  return page.request.delete(`${API}${path}`, { headers: csrf(identity) });
}

const ALICE = "alice";
const BOB = "bob";
const ALICE_SUB = "e2e_alice@test.local";
const BOB_SUB = "e2e_bob@test.local";

test.describe("Section 115 - Feed Fan-Out API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let alicePostId: string;
  let alicePostId2: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB);

    // Ensure Bob unfollows Alice first (clean slate)
    await apiPost(bobPage, BOB, "/ui/social/unfollow", { target_user_id: ALICE_SUB });
  });

  test("115.1 Bob's feed does not contain Alice's posts before following", async () => {
    // Alice creates a public post
    const postResp = await apiPost(alicePage, ALICE, "/posts", {
      body: `Fanout test pre-follow ${TS}`,
      visibility: "public",
    });
    expect(postResp.status()).toBe(200);
    const postData = await postResp.json();
    alicePostId = postData.post_id;

    // Bob's feed should NOT contain Alice's post
    const feedResp = await apiGet(bobPage, BOB, "/feed?limit=50");
    expect(feedResp.status()).toBe(200);
    const feedData = await feedResp.json();
    const found = feedData.items.find((p: any) => p.post_id === alicePostId);
    expect(found).toBeFalsy();
  });

  test("115.2 Bob follows Alice and gets backfill of recent posts", async () => {
    const followResp = await apiPost(bobPage, BOB, "/ui/social/follow", { target_user_id: ALICE_SUB });
    expect(followResp.status()).toBe(200);
    const followData = await followResp.json();
    expect(followData.status).toBe("followed");

    // Bob's feed should now contain Alice's post (backfilled)
    const feedResp = await apiGet(bobPage, BOB, "/feed?limit=50");
    expect(feedResp.status()).toBe(200);
    const feedData = await feedResp.json();
    const found = feedData.items.find((p: any) => p.post_id === alicePostId);
    expect(found).toBeTruthy();
  });

  test("115.3 New post by Alice appears in Bob's feed via fan-out", async () => {
    const postResp = await apiPost(alicePage, ALICE, "/posts", {
      body: `Fanout test new post ${TS}`,
      visibility: "public",
    });
    expect(postResp.status()).toBe(200);
    const postData = await postResp.json();
    alicePostId2 = postData.post_id;

    // Bob's feed should contain the new post
    const feedResp = await apiGet(bobPage, BOB, "/feed?limit=50");
    expect(feedResp.status()).toBe(200);
    const feedData = await feedResp.json();
    const found = feedData.items.find((p: any) => p.post_id === alicePostId2);
    expect(found).toBeTruthy();
    expect(found.author_id).toBe(ALICE_SUB);
  });

  test("115.4 Alice's feed still contains her own posts", async () => {
    const feedResp = await apiGet(alicePage, ALICE, "/feed?limit=50");
    expect(feedResp.status()).toBe(200);
    const feedData = await feedResp.json();
    const found = feedData.items.find((p: any) => p.post_id === alicePostId2);
    expect(found).toBeTruthy();
  });

  test("115.5 Delete post removes from follower's feed", async () => {
    const delResp = await apiDelete(alicePage, ALICE, `/posts/${alicePostId2}`);
    expect(delResp.status()).toBe(200);

    // Bob's feed should no longer contain the deleted post
    const feedResp = await apiGet(bobPage, BOB, "/feed?limit=50");
    expect(feedResp.status()).toBe(200);
    const feedData = await feedResp.json();
    const found = feedData.items.find((p: any) => p.post_id === alicePostId2);
    expect(found).toBeFalsy();
  });

  test("115.6 Unfollow removes fan-out refs from feed", async () => {
    const unfollowResp = await apiPost(bobPage, BOB, "/ui/social/unfollow", { target_user_id: ALICE_SUB });
    expect(unfollowResp.status()).toBe(200);

    // Bob's feed should no longer contain Alice's remaining post
    const feedResp = await apiGet(bobPage, BOB, "/feed?limit=50");
    expect(feedResp.status()).toBe(200);
    const feedData = await feedResp.json();
    const found = feedData.items.find((p: any) => p.post_id === alicePostId);
    expect(found).toBeFalsy();
  });

  test("115.7 Re-follow triggers fresh backfill", async () => {
    // Re-follow Alice
    const followResp = await apiPost(bobPage, BOB, "/ui/social/follow", { target_user_id: ALICE_SUB });
    expect(followResp.status()).toBe(200);

    // The pre-follow post should be backfilled again
    const feedResp = await apiGet(bobPage, BOB, "/feed?limit=50");
    expect(feedResp.status()).toBe(200);
    const feedData = await feedResp.json();
    const found = feedData.items.find((p: any) => p.post_id === alicePostId);
    expect(found).toBeTruthy();
  });

  test("115.8 Bob's own posts still appear in his feed alongside followed posts", async () => {
    const postResp = await apiPost(bobPage, BOB, "/posts", {
      body: `Bob's own post ${TS}`,
      visibility: "public",
    });
    expect(postResp.status()).toBe(200);
    const bobPostId = (await postResp.json()).post_id;

    const feedResp = await apiGet(bobPage, BOB, "/feed?limit=50");
    expect(feedResp.status()).toBe(200);
    const feedData = await feedResp.json();

    // Bob's feed should contain both his own post and Alice's
    const bobPost = feedData.items.find((p: any) => p.post_id === bobPostId);
    const alicePost = feedData.items.find((p: any) => p.post_id === alicePostId);
    expect(bobPost).toBeTruthy();
    expect(alicePost).toBeTruthy();

    // Clean up
    await apiDelete(bobPage, BOB, `/posts/${bobPostId}`);
    await apiPost(bobPage, BOB, "/ui/social/unfollow", { target_user_id: ALICE_SUB });
  });
});

test.describe("Section 116 - Feed Source Attribution API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let aliceSourcePostId: string;
  let bobOwnPostId: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB);

    // Clean slate: unfollow then follow
    await apiPost(bobPage, BOB, "/ui/social/unfollow", { target_user_id: ALICE_SUB });
    await apiPost(bobPage, BOB, "/ui/social/follow", { target_user_id: ALICE_SUB });

    // Alice creates a post for fan-out
    const postResp = await apiPost(alicePage, ALICE, "/posts", {
      body: `Source test alice post ${TS}`,
      visibility: "public",
    });
    const postData = await postResp.json();
    aliceSourcePostId = postData.post_id;

    // Bob creates his own post
    const bobPostResp = await apiPost(bobPage, BOB, "/posts", {
      body: `Source test bob own post ${TS}`,
      visibility: "public",
    });
    const bobPostData = await bobPostResp.json();
    bobOwnPostId = bobPostData.post_id;
  });

  test("116.1 Fan-out post has source='following' in Bob's feed", async () => {
    const feedResp = await apiGet(bobPage, BOB, "/feed?limit=50");
    expect(feedResp.status()).toBe(200);
    const feedData = await feedResp.json();
    const alicePost = feedData.items.find((p: any) => p.post_id === aliceSourcePostId);
    expect(alicePost).toBeTruthy();
    expect(alicePost.source).toBe("following");
  });

  test("116.2 Own post has source='own' in Bob's feed", async () => {
    const feedResp = await apiGet(bobPage, BOB, "/feed?limit=50");
    expect(feedResp.status()).toBe(200);
    const feedData = await feedResp.json();
    const bobPost = feedData.items.find((p: any) => p.post_id === bobOwnPostId);
    expect(bobPost).toBeTruthy();
    expect(bobPost.source).toBe("own");
  });

  test("116.3 Alice sees her own post with source='own'", async () => {
    const feedResp = await apiGet(alicePage, ALICE, "/feed?limit=50");
    expect(feedResp.status()).toBe(200);
    const feedData = await feedResp.json();
    const alicePost = feedData.items.find((p: any) => p.post_id === aliceSourcePostId);
    expect(alicePost).toBeTruthy();
    expect(alicePost.source).toBe("own");
  });

  test("116.4 Author filter feed does not include source field", async () => {
    // When filtering by author, source is not relevant
    const feedResp = await apiGet(bobPage, BOB, `/feed?author_id=${ALICE_SUB}&limit=50`);
    expect(feedResp.status()).toBe(200);
    const feedData = await feedResp.json();
    const alicePost = feedData.items.find((p: any) => p.post_id === aliceSourcePostId);
    expect(alicePost).toBeTruthy();
    // source should be undefined when author_filter is set
    expect(alicePost.source).toBeUndefined();

    // Clean up
    await apiDelete(alicePage, ALICE, `/posts/${aliceSourcePostId}`);
    await apiDelete(bobPage, BOB, `/posts/${bobOwnPostId}`);
    await apiPost(bobPage, BOB, "/ui/social/unfollow", { target_user_id: ALICE_SUB });
  });
});

test.describe("Section 117 - Feed Timeline UI", () => {
  let alicePage: Page;
  let bobPage: Page;
  let aliceUIPostId: string;
  let bobUIPostId: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB);

    // Clean slate
    await apiPost(bobPage, BOB, "/ui/social/unfollow", { target_user_id: ALICE_SUB });
    await apiPost(bobPage, BOB, "/ui/social/follow", { target_user_id: ALICE_SUB });

    // Alice creates a post
    const postResp = await apiPost(alicePage, ALICE, "/posts", {
      body: `UI fanout test alice ${TS}`,
      visibility: "public",
    });
    aliceUIPostId = (await postResp.json()).post_id;

    // Bob creates his own post
    const bobResp = await apiPost(bobPage, BOB, "/posts", {
      body: `UI fanout test bob ${TS}`,
      visibility: "public",
    });
    bobUIPostId = (await bobResp.json()).post_id;
  });

  test("117.1 Following posts show author attribution in feed UI", async () => {
    // Navigate to feed page
    await bobPage.goto(BASE + "/", { waitUntil: "domcontentloaded" });
    // Click Feed in sidebar
    await bobPage.getByRole("link", { name: "Feed" }).first().click();
    await bobPage.waitForResponse((r) => r.url().includes("/feed") && r.status() === 200);

    // Look for the following-attribution label for Alice's post
    const attribution = bobPage.locator('[data-testid="following-attribution"]').filter({
      hasText: ALICE_SUB,
    });
    await expect(attribution.first()).toBeVisible({ timeout: 10_000 });
  });

  test("117.2 Own posts do not show following attribution", async () => {
    // Bob's own post text should be visible
    await expect(bobPage.getByText(`UI fanout test bob ${TS}`).first()).toBeVisible({ timeout: 5_000 });

    // There should be no following-attribution for Bob's own post
    // Get all following attributions and verify none mention Bob
    const attributions = bobPage.locator('[data-testid="following-attribution"]');
    const count = await attributions.count();
    for (let i = 0; i < count; i++) {
      const text = await attributions.nth(i).textContent();
      expect(text).not.toContain(BOB_SUB);
    }
  });

  test("117.3 Feed loads both own and followed posts", async () => {
    // Both posts should appear in the feed
    await expect(bobPage.getByText(`UI fanout test alice ${TS}`).first()).toBeVisible({ timeout: 5_000 });
    await expect(bobPage.getByText(`UI fanout test bob ${TS}`).first()).toBeVisible({ timeout: 5_000 });

    // Clean up
    await apiDelete(alicePage, ALICE, `/posts/${aliceUIPostId}`);
    await apiDelete(bobPage, BOB, `/posts/${bobUIPostId}`);
    await apiPost(bobPage, BOB, "/ui/social/unfollow", { target_user_id: ALICE_SUB });
  });
});
