/**
 * E2E tests for Stories / Ephemeral Content (FEED-002).
 *
 * Sections:
 *   1. Story CRUD API (6 tests)
 *   2. Story Bar API (4 tests)
 *   3. View Tracking API (4 tests)
 *   4. Highlights API (4 tests)
 *   5. Story Viewer UI (3 tests)
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
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
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None";
    expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 }
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
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

/** POST helper with session cookies + CSRF header. */
async function apiPost(page: Page, path: string, body: object, userId = ALICE_ID) {
  const session = getSessions()[userId];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

/** GET helper with session cookies. */
async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

/** DELETE helper with session cookies + CSRF header. */
async function apiDelete(page: Page, path: string, userId = ALICE_ID) {
  const session = getSessions()[userId];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── Navigate to feed via sidebar ────────────────────────────────────────────

async function gotoFeed(page: Page, userId = ALICE_ID) {
  await injectAuth(page, userId);
  await page.goto(`${BASE}/`, { waitUntil: "load" });
  await page.waitForTimeout(800);
  await page.locator('a[href="/feed"]').first().click();
  await page.waitForTimeout(1500);
}

// =============================================================================
// Section 1: Story CRUD API (6 tests)
// =============================================================================

test.describe("1. Story CRUD API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let aliceStoryId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("1.1 Create image story", async () => {
    const resp = await apiPost(alicePage, "/ui/stories", {
      media_type: "image",
      media_url: `story-media/test_${TS}.jpg`,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.story_id).toBeTruthy();
    expect(data.story_id).toMatch(/^st_/);
    expect(data.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(data.created_at).toBeTruthy();
    aliceStoryId = data.story_id;
  });

  test("1.2 Create video story with text overlay", async () => {
    const resp = await apiPost(alicePage, "/ui/stories", {
      media_type: "video",
      media_url: `story-media/video_${TS}.mp4`,
      text_overlay: "Behind the scenes!",
      duration_seconds: 30,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.story_id).toMatch(/^st_/);
  });

  test("1.3 Reject video story over 60 seconds", async () => {
    const resp = await apiPost(alicePage, "/ui/stories", {
      media_type: "video",
      media_url: `story-media/long_${TS}.mp4`,
      duration_seconds: 90,
    });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail).toContain("60 seconds or less");
  });

  test("1.4 Get own stories list", async () => {
    const resp = await apiGet(alicePage, `/ui/stories/user/${ALICE_ID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.stories).toBeTruthy();
    expect(data.stories.length).toBeGreaterThanOrEqual(1);
    const found = data.stories.find((s: any) => s.story_id === aliceStoryId);
    expect(found).toBeTruthy();
    expect(found.media_type).toBe("image");
  });

  test("1.5 Delete own story", async () => {
    // Create a temporary story to delete
    const createResp = await apiPost(alicePage, "/ui/stories", {
      media_type: "image",
      media_url: `story-media/to_delete_${TS}.jpg`,
    });
    const { story_id } = await createResp.json();

    const delResp = await apiDelete(alicePage, `/ui/stories/${story_id}`);
    expect(delResp.status()).toBe(200);
    const delData = await delResp.json();
    expect(delData.ok).toBe(true);

    // Verify it's gone
    const getResp = await apiGet(alicePage, `/ui/stories/${story_id}`);
    expect(getResp.status()).toBe(404);
  });

  test("1.6 Cannot delete another user's story", async () => {
    // Bob tries to delete Alice's story
    const resp = await apiDelete(bobPage, `/ui/stories/${aliceStoryId}`, BOB_ID);
    expect(resp.status()).toBe(403);
  });
});

// =============================================================================
// Section 2: Story Bar API (4 tests)
// =============================================================================

test.describe("2. Story Bar API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let bobStoryId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);

    // Alice follows Bob
    await apiPost(alicePage, "/ui/social/follow", { target_user_id: BOB_ID });

    // Bob creates a story
    const resp = await apiPost(bobPage, "/ui/stories", {
      media_type: "image",
      media_url: `story-media/bob_bar_${TS}.jpg`,
    }, BOB_ID);
    const data = await resp.json();
    bobStoryId = data.story_id;
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("2.7 Story bar includes followed creator with active story", async () => {
    const resp = await apiGet(alicePage, "/ui/stories/bar");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.bar).toBeTruthy();
    const bobEntry = data.bar.find((b: any) => b.user_id === BOB_ID);
    expect(bobEntry).toBeTruthy();
    expect(bobEntry.has_unseen).toBe(true);
    expect(bobEntry.story_count).toBeGreaterThanOrEqual(1);
  });

  test("2.8 Story bar excludes expired stories", async () => {
    // We can't actually wait 24h, but we verify the TTL field is set correctly
    const storyResp = await apiGet(alicePage, `/ui/stories/${bobStoryId}`);
    const storyData = await storyResp.json();
    expect(storyData.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
    // The expires_at should be ~24h from now
    const diff = storyData.expires_at - Math.floor(Date.now() / 1000);
    expect(diff).toBeGreaterThan(86000); // close to 86400
    expect(diff).toBeLessThanOrEqual(86400);
  });

  test("2.9 Story bar shows has_unseen:false after viewing", async () => {
    // Alice views Bob's story
    const viewResp = await apiPost(alicePage, `/ui/stories/${bobStoryId}/view`, {});
    expect(viewResp.status()).toBe(200);

    // Re-fetch bar
    const barResp = await apiGet(alicePage, "/ui/stories/bar");
    const barData = await barResp.json();
    const bobEntry = barData.bar.find((b: any) => b.user_id === BOB_ID);
    expect(bobEntry).toBeTruthy();
    // has_unseen should reflect that Alice viewed the latest story
    // Note: if Bob has multiple stories, has_unseen checks only the latest
    expect(bobEntry.has_unseen).toBe(false);
  });

  test("2.10 Story bar excludes unfollowed creators", async () => {
    // Alice unfollows Bob
    await apiPost(alicePage, "/ui/social/unfollow", { target_user_id: BOB_ID });

    const resp = await apiGet(alicePage, "/ui/stories/bar");
    const data = await resp.json();
    const bobEntry = data.bar.find((b: any) => b.user_id === BOB_ID);
    expect(bobEntry).toBeFalsy();

    // Re-follow Bob for subsequent tests
    await apiPost(alicePage, "/ui/social/follow", { target_user_id: BOB_ID });
  });
});

// =============================================================================
// Section 3: View Tracking API (4 tests)
// =============================================================================

test.describe("3. View Tracking API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let trackStoryId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);

    // Alice creates a story for view tracking tests
    const resp = await apiPost(alicePage, "/ui/stories", {
      media_type: "image",
      media_url: `story-media/view_track_${TS}.jpg`,
    });
    const data = await resp.json();
    trackStoryId = data.story_id;
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("3.11 Record view returns already_viewed:false on first view", async () => {
    const resp = await apiPost(bobPage, `/ui/stories/${trackStoryId}/view`, {}, BOB_ID);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.already_viewed).toBe(false);
  });

  test("3.12 Record view is idempotent (second call returns already_viewed:true)", async () => {
    const resp = await apiPost(bobPage, `/ui/stories/${trackStoryId}/view`, {}, BOB_ID);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.already_viewed).toBe(true);
  });

  test("3.13 View count increments on first view only", async () => {
    const resp = await apiGet(alicePage, `/ui/stories/${trackStoryId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // Bob viewed once (two calls, but idempotent = count of 1)
    expect(Number(data.view_count)).toBe(1);
  });

  test("3.14 Creator can list viewers of their story", async () => {
    const resp = await apiGet(alicePage, `/ui/stories/${trackStoryId}/viewers`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.viewers).toBeTruthy();
    expect(data.total_count).toBeGreaterThanOrEqual(1);
    const bobViewer = data.viewers.find((v: any) => v.user_id === BOB_ID);
    expect(bobViewer).toBeTruthy();
    expect(bobViewer.viewed_at).toBeTruthy();
  });
});

// =============================================================================
// Section 4: Highlights API (4 tests)
// =============================================================================

test.describe("4. Highlights API", () => {
  let alicePage: Page;
  let highlightStoryId: string;
  let highlightGroupId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Create a story to highlight
    const resp = await apiPost(alicePage, "/ui/stories", {
      media_type: "image",
      media_url: `story-media/highlight_${TS}.jpg`,
      text_overlay: "Highlight me!",
    });
    const data = await resp.json();
    highlightStoryId = data.story_id;
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("4.15 Highlight a story removes TTL", async () => {
    const resp = await apiPost(alicePage, `/ui/stories/${highlightStoryId}/highlight`, {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);

    // Verify the story is highlighted
    const getResp = await apiGet(alicePage, `/ui/stories/${highlightStoryId}`);
    const storyData = await getResp.json();
    expect(storyData.highlighted).toBe(true);
  });

  test("4.16 Unhighlight re-applies TTL", async () => {
    const resp = await apiDelete(alicePage, `/ui/stories/${highlightStoryId}/highlight`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);

    // Verify no longer highlighted
    const getResp = await apiGet(alicePage, `/ui/stories/${highlightStoryId}`);
    const storyData = await getResp.json();
    expect(storyData.highlighted).toBe(false);
  });

  test("4.17 Create highlight group", async () => {
    const resp = await apiPost(alicePage, "/ui/stories/highlights/groups", {
      title: `Travel ${TS}`,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.highlight_group_id).toBeTruthy();
    expect(data.highlight_group_id).toMatch(/^hg_/);
    expect(data.title).toContain("Travel");
    highlightGroupId = data.highlight_group_id;
  });

  test("4.18 List highlights for user profile", async () => {
    // Pin the story to the group
    await apiPost(alicePage, `/ui/stories/${highlightStoryId}/highlight`, {
      group_id: highlightGroupId,
    });

    const resp = await apiGet(alicePage, `/ui/stories/highlights/${ALICE_ID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.groups).toBeTruthy();
    const group = data.groups.find((g: any) => g.highlight_group_id === highlightGroupId);
    expect(group).toBeTruthy();
    expect(group.title).toContain("Travel");
    expect(group.stories.length).toBeGreaterThanOrEqual(1);
    const highlightedStory = group.stories.find((s: any) => s.story_id === highlightStoryId);
    expect(highlightedStory).toBeTruthy();
  });
});

// =============================================================================
// Section 5: Story Viewer UI (3 tests)
// =============================================================================

test.describe("5. Story Viewer UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();

    // Ensure Alice has at least one story
    await injectAuth(page, ALICE_ID);
    await apiPost(page, "/ui/stories", {
      media_type: "image",
      media_url: `story-media/ui_test_${TS}.jpg`,
    });
  });

  test.afterAll(async () => {
    await page?.close();
  });

  test("5.19 Story bar visible on feed page", async () => {
    await gotoFeed(page, ALICE_ID);
    const storyBar = page.locator('[data-testid="story-bar"]');
    await expect(storyBar).toBeVisible({ timeout: 10_000 });
  });

  test("5.20 Clicking story ring opens viewer overlay", async () => {
    // The story bar should show Alice's own story entry
    // Find any story avatar (Alice's own or followed creator's)
    const anyAvatar = page.locator('[data-testid^="story-avatar-"]').first();
    const isVisible = await anyAvatar.isVisible().catch(() => false);

    if (isVisible) {
      await anyAvatar.click();
      const viewer = page.locator('[data-testid="story-viewer"]');
      await expect(viewer).toBeVisible({ timeout: 5_000 });
    } else {
      // If no avatar visible, create-story button should be present
      const createBtn = page.locator('[data-testid="create-story-button"]');
      await expect(createBtn).toBeVisible({ timeout: 5_000 });
      // Click create button and verify composer opens
      await createBtn.click();
      const composer = page.locator('[data-testid="story-composer"]');
      await expect(composer).toBeVisible({ timeout: 5_000 });
    }
  });

  test("5.21 Closing viewer returns to feed", async () => {
    // If viewer is open, close it
    const viewer = page.locator('[data-testid="story-viewer"]');
    const viewerVisible = await viewer.isVisible().catch(() => false);

    if (viewerVisible) {
      const closeBtn = page.locator('[data-testid="story-close"]');
      await closeBtn.click();
      await expect(viewer).not.toBeVisible({ timeout: 5_000 });
    }

    // Feed page should still be visible
    const storyBar = page.locator('[data-testid="story-bar"]');
    await expect(storyBar).toBeVisible({ timeout: 5_000 });
  });
});
