/**
 * E2E tests for SOCIAL-006: Hashtags / Topics
 *
 * Tests cover:
 *  - Section 1: Hashtag API -- CRUD (7 tests)
 *  - Section 2: Hashtag Validation (4 tests)
 *  - Section 3: Hashtag UI -- CreatePost (4 tests)
 *  - Section 4: Hashtag UI -- PostCard & Navigation (4 tests)
 *
 * Auth: Cookie-based sessions via e2e_session_setup.py
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now().toString(36);

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

function csrfHeader(userId: string): Record<string, string> {
  return { "x-csrf-token": getSessions()[userId].csrf_token };
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, userId: string, path: string, body: unknown) {
  return page.request.post(`${BASE}${path}`, {
    headers: { ...csrfHeader(userId), "Content-Type": "application/json" },
    data: body,
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  const url = new URL(`${BASE}${path}`);
  if (params) {
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  }
  return page.request.get(url.toString());
}

// ─── Navigate to feed page using client-side routing ──────────────────────────

async function gotoFeed(page: Page) {
  await page.goto(`${BASE}/`, { waitUntil: "load" });
  await page.waitForTimeout(800);
  await page.locator('a[href="/feed"]').first().click();
  await page.waitForTimeout(1500);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 1: Hashtag API -- CRUD
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 1: Hashtag API", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("1. Create post with explicit tags -- tags stored and returned", async () => {
    const resp = await apiPost(page, ALICE_ID, "/posts", {
      body_plain: `Explicit tags test ${TS}`,
      tags: ["tagone", "tagtwo"],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.tags).toContain("tagone");
    expect(data.tags).toContain("tagtwo");
  });

  test("2. Create post with body hashtags auto-extracted", async () => {
    const resp = await apiPost(page, ALICE_ID, "/posts", {
      body_plain: `Hello world #autoextract${TS} check it out`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.tags).toContain(`autoextract${TS}`.toLowerCase());
  });

  test("3. Explicit + body tags are merged and deduped", async () => {
    const resp = await apiPost(page, ALICE_ID, "/posts", {
      body_plain: `Merged test #mergetag${TS} here`,
      tags: [`mergetag${TS}`, `extratag${TS}`],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // mergetag appears once (deduped), extratag also present
    const tagOccurrences = data.tags.filter((t: string) => t === `mergetag${TS}`.toLowerCase());
    expect(tagOccurrences.length).toBe(1);
    expect(data.tags).toContain(`extratag${TS}`.toLowerCase());
  });

  test("4. GET /ui/discover/tags/{tag} returns matching post", async () => {
    const resp = await apiGet(page, `/ui/discover/tags/tagone`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.tag).toBe("tagone");
    expect(data.posts.length).toBeGreaterThanOrEqual(1);
    const found = data.posts.some((p: { tags?: string[] }) => (p.tags ?? []).includes("tagone"));
    expect(found).toBe(true);
  });

  test("5. GET /ui/discover/tags/{tag} paginates", async () => {
    // Create multiple posts with a unique tag
    const paginationTag = `pag${TS}`;
    for (let i = 0; i < 4; i++) {
      await apiPost(page, ALICE_ID, "/posts", {
        body_plain: `Pagination post ${i} ${TS}`,
        tags: [paginationTag],
      });
    }

    const resp = await apiGet(page, `/ui/discover/tags/${paginationTag}`, { limit: "2" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.posts.length).toBe(2);
    // There should be a next_cursor since we have 4 posts but requested 2
    expect(data.next_cursor).toBeTruthy();

    // Fetch next page
    const resp2 = await apiGet(page, `/ui/discover/tags/${paginationTag}`, {
      limit: "2",
      cursor: data.next_cursor,
    });
    expect(resp2.status()).toBe(200);
    const data2 = await resp2.json();
    expect(data2.posts.length).toBe(2);
  });

  test("6. GET /ui/discover/trending-tags returns non-empty list", async () => {
    const resp = await apiGet(page, "/ui/discover/trending-tags");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.tags).toBeInstanceOf(Array);
    expect(data.tags.length).toBeGreaterThanOrEqual(1);
    // Each item has tag, count, last_used_at
    const first = data.tags[0];
    expect(first.tag).toBeTruthy();
    expect(typeof first.count).toBe("number");
    expect(first.count).toBeGreaterThan(0);
  });

  test("7. Unknown tag returns empty posts", async () => {
    const resp = await apiGet(page, "/ui/discover/tags/zzz_nonexistent_tag_xyz");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.tag).toBe("zzz_nonexistent_tag_xyz");
    expect(data.posts).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 2: Hashtag Validation
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 2: Hashtag Validation", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("8. Tag with leading # is stripped", async () => {
    const resp = await apiPost(page, ALICE_ID, "/posts", {
      body_plain: `Leading hash test ${TS}`,
      tags: ["#leadinghash"],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.tags).toContain("leadinghash");
    expect(data.tags).not.toContain("#leadinghash");
  });

  test("9. Tags are lowercased", async () => {
    const resp = await apiPost(page, ALICE_ID, "/posts", {
      body_plain: `Case test ${TS}`,
      tags: ["Photography", "TRAVEL"],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.tags).toContain("photography");
    expect(data.tags).toContain("travel");
    expect(data.tags).not.toContain("Photography");
  });

  test("10. Invalid tag characters are filtered out", async () => {
    const resp = await apiPost(page, ALICE_ID, "/posts", {
      body_plain: `Invalid tag test ${TS}`,
      tags: ["bad tag!", "123numeric", "valid_one"],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // "bad tag!" is invalid (spaces/special chars), "123numeric" starts with digit
    expect(data.tags).not.toContain("bad tag!");
    expect(data.tags).not.toContain("123numeric");
    expect(data.tags).toContain("valid_one");
  });

  test("11. Over 20 tags truncated to 20", async () => {
    const manyTags = Array.from({ length: 25 }, (_, i) => `overflow${i}${TS.slice(0, 4)}`);
    const resp = await apiPost(page, ALICE_ID, "/posts", {
      body_plain: `Overflow test ${TS}`,
      tags: manyTags,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.tags.length).toBeLessThanOrEqual(20);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 3: Hashtag UI -- CreatePost
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 3: Hashtag UI -- CreatePost", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await gotoFeed(page);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("12. Tag input visible in CreatePost form", async () => {
    await expect(page.getByPlaceholder("Add tag...")).toBeVisible();
  });

  test("13. Typing tag + Enter adds badge", async () => {
    const input = page.getByPlaceholder("Add tag...");
    await input.fill("mynewtag");
    await input.press("Enter");
    await expect(page.locator("text=#mynewtag").first()).toBeVisible();
  });

  test("14. Clicking X on badge removes tag", async () => {
    // Ensure the badge is visible first
    await expect(page.locator("text=#mynewtag").first()).toBeVisible();
    // Click the remove button (X icon) next to the tag
    await page.locator('[aria-label="Remove tag mynewtag"]').click();
    await expect(page.locator("text=#mynewtag")).not.toBeVisible();
  });

  test("15. Submit post sends tags to API", async () => {
    // Add a tag
    const input = page.getByPlaceholder("Add tag...");
    await input.fill(`uitag${TS.slice(0, 6)}`);
    await input.press("Enter");

    // Type body text
    await page.getByPlaceholder("What's on your mind?").fill(`UI tag post ${TS}`);

    // Intercept the POST request to verify tags are sent
    const [request] = await Promise.all([
      page.waitForRequest((req) => req.url().includes("/posts") && req.method() === "POST"),
      page.locator('button[type="submit"]').filter({ hasText: "Post" }).click(),
    ]);

    const body = request.postDataJSON();
    expect(body.tags).toContain(`uitag${TS.slice(0, 6)}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 4: Hashtag UI -- PostCard & Navigation
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 4: Hashtag UI -- PostCard & Navigation", () => {
  let page: Page;
  const uniqueTag = `navtag${TS}`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    // Create a post with a unique tag to test rendering
    await apiPost(page, ALICE_ID, "/posts", {
      body_plain: `Navigation test post ${TS}`,
      tags: [uniqueTag],
    });
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("16. Clickable hashtag link in PostCard", async () => {
    await gotoFeed(page);
    // Wait for the tagged post to appear
    await page.waitForTimeout(1000);
    // Look for the tag badge in the feed
    const tagLink = page.locator(`a[href="/discover/tags/${uniqueTag}"]`).first();
    await expect(tagLink).toBeVisible({ timeout: 10_000 });
  });

  test("17. Clicking hashtag navigates to tag page", async () => {
    const tagLink = page.locator(`a[href="/discover/tags/${uniqueTag}"]`).first();
    await tagLink.click();
    await page.waitForURL(`**/discover/tags/${uniqueTag}`);
    expect(page.url()).toContain(`/discover/tags/${uniqueTag}`);
  });

  test("18. Tag discovery page shows tagged posts", async () => {
    await page.goto(`${BASE}/discover/tags/${uniqueTag}`, { waitUntil: "load" });
    await page.waitForTimeout(2000);
    // Page should show the tag name as heading
    await expect(page.locator("h1").filter({ hasText: `#${uniqueTag}` })).toBeVisible();
    // Should show at least one post
    await expect(page.locator("text=Navigation test post").first()).toBeVisible({ timeout: 10_000 });
  });

  test("19. Trending tags section on Discover page", async () => {
    await page.goto(`${BASE}/discover`, { waitUntil: "load" });
    await page.waitForTimeout(2000);
    // "Trending Tags" heading should be visible if there are any tags
    await expect(page.locator("text=Trending Tags").first()).toBeVisible({ timeout: 10_000 });
  });
});
