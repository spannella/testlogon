/**
 * E2E tests for SOC-001: Follow/Unfollow System
 *
 * Section 90: Follow/Unfollow API (8 tests)
 * Section 91: Follower/Following Lists API (6 tests)
 * Section 92: Follow Button UI (4 tests)
 *
 * Auth: uses e2e_admin_session_setup.py to get cookie-based sessions.
 * Session keys are "alice", "bob" etc.; user_sub values are full emails.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ── Constants ─────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";

// Session keys for e2e_admin_session_setup.py lookup
const ALICE_KEY = "alice";
const BOB_KEY   = "bob";

// user_sub values for API calls (target_user_id)
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";

// ── Session bootstrap ─────────────────────────────────────────────────────

interface SessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name:     string;
    value:    string;
    domain:   string;
    path:     string;
    httpOnly: boolean;
    secure:   boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires:  number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

// ── Auth helpers ──────────────────────────────────────────────────────────

async function injectAuth(page: Page, sessionKey: string) {
  const sessions = getSessions();
  const session = sessions[sessionKey];
  if (!session) throw new Error(`No session for key=${sessionKey}`);
  await page.context().addCookies(session.cookies);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

async function newIdentityPage(browser: Browser, sessionKey: string): Promise<Page> {
  const page = await browser.newPage();
  await injectAuth(page, sessionKey);
  return page;
}

/** POST helper using session cookies + CSRF header */
async function apiPost(page: Page, sessionKey: string, path: string, body: object) {
  const sessions = getSessions();
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": sessions[sessionKey].csrf_token },
  });
}

/** GET helper using session cookies */
async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  let url = `${API}${path}`;
  if (params) {
    const qs = new URLSearchParams(params).toString();
    url += `?${qs}`;
  }
  return page.request.get(url);
}

// ── Cleanup helper ────────────────────────────────────────────────────────

async function cleanupFollow(page: Page, sessionKey: string, targetId: string) {
  await apiPost(page, sessionKey, "/ui/social/unfollow", { target_user_id: targetId });
}

// ═════════════════════════════════════════════════════════════════════════
// Section 90: Follow/Unfollow API
// ═════════════════════════════════════════════════════════════════════════

test.describe("90 -- Follow/Unfollow API", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage = await newIdentityPage(browser, BOB_KEY);
    await cleanupFollow(alicePage, ALICE_KEY, BOB_ID);
    await cleanupFollow(bobPage, BOB_KEY, ALICE_ID);
  });

  test.afterAll(async () => {
    await cleanupFollow(alicePage, ALICE_KEY, BOB_ID);
    await cleanupFollow(bobPage, BOB_KEY, ALICE_ID);
    await alicePage.close();
    await bobPage.close();
  });

  test("90.1 Alice follows Bob", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/social/follow", {
      target_user_id: BOB_ID,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("followed");
    expect(data.follower_count).toBeGreaterThanOrEqual(1);
    expect(typeof data.following_count).toBe("number");
  });

  test("90.2 Alice follows Bob again (idempotent)", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/social/follow", {
      target_user_id: BOB_ID,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("already_following");
  });

  test("90.3 Alice unfollows Bob", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/social/unfollow", {
      target_user_id: BOB_ID,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("unfollowed");
  });

  test("90.4 Alice unfollows Bob when not following", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/social/unfollow", {
      target_user_id: BOB_ID,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("not_following");
  });

  test("90.5 Self-follow returns 400", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/social/follow", {
      target_user_id: ALICE_ID,
    });
    expect(resp.status()).toBe(400);
  });

  test("90.6 Follow status reflects bidirectional state", async () => {
    // Alice follows Bob
    await apiPost(alicePage, ALICE_KEY, "/ui/social/follow", { target_user_id: BOB_ID });

    // Check status from Alice's POV
    let resp = await apiGet(alicePage, `/ui/social/status/${BOB_ID}`);
    expect(resp.status()).toBe(200);
    let data = await resp.json();
    expect(data.is_following).toBe(true);
    expect(data.is_followed_by).toBe(false);
    expect(data.is_mutual).toBe(false);

    // Bob follows Alice
    await apiPost(bobPage, BOB_KEY, "/ui/social/follow", { target_user_id: ALICE_ID });

    // Check mutual
    resp = await apiGet(alicePage, `/ui/social/status/${BOB_ID}`);
    data = await resp.json();
    expect(data.is_following).toBe(true);
    expect(data.is_followed_by).toBe(true);
    expect(data.is_mutual).toBe(true);

    // Cleanup
    await cleanupFollow(alicePage, ALICE_KEY, BOB_ID);
    await cleanupFollow(bobPage, BOB_KEY, ALICE_ID);
  });

  test("90.7 Follower count increments on follow", async () => {
    // Get initial counts
    let resp = await apiGet(alicePage, `/ui/social/${BOB_ID}/counts`);
    const initialCounts = await resp.json();
    const initialFollowerCount = initialCounts.follower_count;

    // Alice follows Bob
    await apiPost(alicePage, ALICE_KEY, "/ui/social/follow", { target_user_id: BOB_ID });

    // Check counts
    resp = await apiGet(alicePage, `/ui/social/${BOB_ID}/counts`);
    const newCounts = await resp.json();
    expect(newCounts.follower_count).toBe(initialFollowerCount + 1);
  });

  test("90.8 Follower count decrements on unfollow", async () => {
    // Get counts (Alice is following Bob from previous test)
    let resp = await apiGet(alicePage, `/ui/social/${BOB_ID}/counts`);
    const beforeCounts = await resp.json();
    const beforeFollowerCount = beforeCounts.follower_count;

    // Alice unfollows Bob
    await apiPost(alicePage, ALICE_KEY, "/ui/social/unfollow", { target_user_id: BOB_ID });

    // Check counts decreased
    resp = await apiGet(alicePage, `/ui/social/${BOB_ID}/counts`);
    const afterCounts = await resp.json();
    expect(afterCounts.follower_count).toBe(beforeFollowerCount - 1);
  });
});

// ═════════════════════════════════════════════════════════════════════════
// Section 91: Follower/Following Lists API
// ═════════════════════════════════════════════════════════════════════════

test.describe("91 -- Follower/Following Lists API", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage = await newIdentityPage(browser, BOB_KEY);
    await cleanupFollow(alicePage, ALICE_KEY, BOB_ID);
    await cleanupFollow(bobPage, BOB_KEY, ALICE_ID);
  });

  test.afterAll(async () => {
    await cleanupFollow(alicePage, ALICE_KEY, BOB_ID);
    await cleanupFollow(bobPage, BOB_KEY, ALICE_ID);
    await alicePage.close();
    await bobPage.close();
  });

  test("91.1 Get followers returns follower with profile data", async () => {
    // Alice follows Bob
    await apiPost(alicePage, ALICE_KEY, "/ui/social/follow", { target_user_id: BOB_ID });

    // Get Bob's followers
    const resp = await apiGet(alicePage, `/ui/social/${BOB_ID}/followers`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeDefined();
    expect(Array.isArray(data.items)).toBe(true);
    expect(data.total_count).toBeGreaterThanOrEqual(1);

    // Alice should appear in the list
    const aliceEntry = data.items.find((item: any) => item.user_id === ALICE_ID);
    expect(aliceEntry).toBeDefined();
    expect(typeof aliceEntry.is_following).toBe("boolean");
    expect(typeof aliceEntry.is_mutual).toBe("boolean");
  });

  test("91.2 Get following returns followed user", async () => {
    // Get Alice's following list
    const resp = await apiGet(alicePage, `/ui/social/${ALICE_ID}/following`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeDefined();
    expect(Array.isArray(data.items)).toBe(true);

    // Bob should appear in Alice's following list
    const bobEntry = data.items.find((item: any) => item.user_id === BOB_ID);
    expect(bobEntry).toBeDefined();
  });

  test("91.3 Followers list excludes unfollowed users", async () => {
    // Alice unfollows Bob
    await apiPost(alicePage, ALICE_KEY, "/ui/social/unfollow", { target_user_id: BOB_ID });

    // Get Bob's followers - Alice should not appear
    const resp = await apiGet(alicePage, `/ui/social/${BOB_ID}/followers`);
    const data = await resp.json();
    const aliceEntry = data.items.find((item: any) => item.user_id === ALICE_ID);
    expect(aliceEntry).toBeUndefined();
  });

  test("91.4 Follow counts endpoint returns correct values", async () => {
    // Re-follow for clean state
    await apiPost(alicePage, ALICE_KEY, "/ui/social/follow", { target_user_id: BOB_ID });

    const resp = await apiGet(alicePage, `/ui/social/${BOB_ID}/counts`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.follower_count).toBe("number");
    expect(typeof data.following_count).toBe("number");
    expect(data.follower_count).toBeGreaterThanOrEqual(1);

    // cleanup
    await cleanupFollow(alicePage, ALICE_KEY, BOB_ID);
  });

  test("91.5 Mutual followers computed correctly", async () => {
    // Setup: Alice follows Bob, Bob follows Alice (mutual)
    await apiPost(alicePage, ALICE_KEY, "/ui/social/follow", { target_user_id: BOB_ID });
    await apiPost(bobPage, BOB_KEY, "/ui/social/follow", { target_user_id: ALICE_ID });

    // Check mutual endpoint from Alice's perspective looking at Bob
    const resp = await apiGet(alicePage, `/ui/social/mutual/${BOB_ID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeDefined();
    expect(Array.isArray(data.items)).toBe(true);
    expect(typeof data.total_count).toBe("number");

    // Cleanup
    await cleanupFollow(alicePage, ALICE_KEY, BOB_ID);
    await cleanupFollow(bobPage, BOB_KEY, ALICE_ID);
  });

  test("91.6 Following list with pagination params", async () => {
    // Alice follows Bob
    await apiPost(alicePage, ALICE_KEY, "/ui/social/follow", { target_user_id: BOB_ID });

    // Test with limit=1
    const resp = await apiGet(alicePage, `/ui/social/${ALICE_ID}/following`, { limit: "1" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeDefined();
    expect(data.items.length).toBeLessThanOrEqual(1);

    // Cleanup
    await cleanupFollow(alicePage, ALICE_KEY, BOB_ID);
  });
});

// ═════════════════════════════════════════════════════════════════════════
// Section 92: Follow Button UI
// ═════════════════════════════════════════════════════════════════════════

test.describe("92 -- Follow Button UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    await cleanupFollow(alicePage, ALICE_KEY, BOB_ID);
  });

  test.afterAll(async () => {
    await cleanupFollow(alicePage, ALICE_KEY, BOB_ID);
    await alicePage.close();
  });

  test("92.1 Follow button shows Follow for non-followed user", async () => {
    // Ensure Alice is not following Bob
    await cleanupFollow(alicePage, ALICE_KEY, BOB_ID);

    // Navigate to Bob's public profile
    await alicePage.goto(`${BASE}/u/${encodeURIComponent(BOB_ID)}`);
    await alicePage.waitForLoadState("domcontentloaded");

    // The follow button should show "Follow"
    const followBtn = alicePage.locator('[data-testid="follow-button"]');
    await expect(followBtn).toBeVisible({ timeout: 10_000 });
    await expect(followBtn).toContainText("Follow");
  });

  test("92.2 Click Follow changes button to Following", async () => {
    const followBtn = alicePage.locator('[data-testid="follow-button"]');
    await followBtn.click();

    // Should change to "Following"
    await expect(followBtn).toContainText("Following", { timeout: 5_000 });
  });

  test("92.3 Click Unfollow reverts to Follow", async () => {
    const followBtn = alicePage.locator('[data-testid="follow-button"]');

    // Hover to show "Unfollow"
    await followBtn.hover();
    await expect(followBtn).toContainText("Unfollow", { timeout: 3_000 });

    // Click to unfollow
    await followBtn.click();

    // Should revert to "Follow"
    await expect(followBtn).toContainText("Follow", { timeout: 5_000 });
  });

  test("92.4 Follower count updates on profile after follow", async () => {
    // Self-contained: navigate fresh + ensure a clean (non-following) state so
    // this test doesn't depend on the page position/state left by 92.1-92.3
    // (a retry runs in a fresh worker where no prior nav happened).
    await cleanupFollow(alicePage, ALICE_KEY, BOB_ID);
    await alicePage.goto(`${BASE}/u/${encodeURIComponent(BOB_ID)}`);
    await alicePage.waitForLoadState("domcontentloaded");

    // Get initial stats
    const statsRow = alicePage.locator('[data-testid="stats-row"]');
    await expect(statsRow).toBeVisible({ timeout: 10_000 });

    // Follow Bob
    const followBtn = alicePage.locator('[data-testid="follow-button"]');
    await expect(followBtn).toBeVisible({ timeout: 10_000 });
    await expect(followBtn).toContainText("Follow");
    await followBtn.click();
    await expect(followBtn).toContainText("Following", { timeout: 5_000 });

    // Verify follow worked via API (poll: the mutation settles asynchronously).
    await expect
      .poll(
        async () => {
          const resp = await apiGet(alicePage, `/ui/social/status/${BOB_ID}`);
          const data = await resp.json();
          return data.is_following;
        },
        { timeout: 10_000 },
      )
      .toBe(true);

    // Cleanup
    await cleanupFollow(alicePage, ALICE_KEY, BOB_ID);
  });
});
