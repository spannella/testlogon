/**
 * E2E tests for SOCIAL-004: User Blocking.
 *
 * Section 1: Block/Unblock API (7 tests)
 * Section 2: Blocked Users List API (3 tests)
 * Section 3: Messaging Enforcement (3 tests)
 * Section 4: Follow Status Extended (3 tests)
 * Section 5: Blocked Users UI (3 tests)
 */

import { test, expect, type Page, type Browser, type BrowserContext } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";

// ─── Session bootstrap ────────────────────────────────────────────────────────

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
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

// ─── Authenticated API helpers ────────────────────────────────────────────────

async function apiPostAs(page: Page, identity: string, path: string, body: object) {
  const session = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGetAs(page: Page, identity: string, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiPost(page: Page, path: string, body: object) {
  return apiPostAs(page, ALICE_ID, path, body);
}

async function apiGet(page: Page, path: string) {
  return apiGetAs(page, ALICE_ID, path);
}

/** Create a new browser context + page for a given identity. */
async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const ctx = await browser.newContext();
  const pg = await ctx.newPage();
  await injectAuth(pg, identity);
  return pg;
}

// ─── Cleanup helper ──────────────────────────────────────────────────────────

async function cleanupBlock(page: Page, blockerId: string, blockedId: string) {
  try {
    await apiPostAs(page, blockerId, "/ui/social/unblock", { target_user_id: blockedId });
  } catch {
    // ignore
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 1: Block/Unblock API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("1 — Block/Unblock API", () => {
  let page: Page;
  let _browser: Browser;

  test.beforeAll(async ({ browser }) => {
    _browser = browser;
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    // Clean up any leftover blocks from previous runs
    await cleanupBlock(page, ALICE_ID, BOB_ID);
  });

  test.afterAll(async () => {
    await cleanupBlock(page, ALICE_ID, BOB_ID);
    await page?.close();
  });

  test("1.1 Alice blocks Bob — 200", async () => {
    const resp = await apiPost(page, "/ui/social/block", { target_user_id: BOB_ID });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.status).toBe("blocked");
    expect(body.target_user_id).toBe(BOB_ID);
  });

  test("1.2 Duplicate block returns 409", async () => {
    const resp = await apiPost(page, "/ui/social/block", { target_user_id: BOB_ID });
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail).toContain("Already blocked");
  });

  test("1.3 Alice cannot block herself — 400", async () => {
    const resp = await apiPost(page, "/ui/social/block", { target_user_id: ALICE_ID });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail).toContain("Cannot block yourself");
  });

  test("1.4 Block status shows is_blocked_by_me=true", async () => {
    const resp = await apiGet(page, `/ui/social/block-status/${BOB_ID}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.is_blocked_by_me).toBe(true);
    expect(body.is_blocking_me).toBe(false);
  });

  test("1.5 Block status for non-blocked user — both false", async () => {
    const resp = await apiGet(page, `/ui/social/block-status/${ALICE_ID}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.is_blocked_by_me).toBe(false);
    expect(body.is_blocking_me).toBe(false);
  });

  test("1.6 Alice unblocks Bob — 200", async () => {
    const resp = await apiPost(page, "/ui/social/unblock", { target_user_id: BOB_ID });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.status).toBe("unblocked");
  });

  test("1.7 Block auto-unfollows both directions", async () => {
    // Setup: Alice follows Bob
    await apiPost(page, "/ui/social/follow", { target_user_id: BOB_ID });

    // Bob follows Alice using a separate context
    const bobPage = await newIdentityPage(_browser, BOB_ID);
    await apiPostAs(bobPage, BOB_ID, "/ui/social/follow", { target_user_id: ALICE_ID });

    // Verify both follow each other
    let statusResp = await apiGet(page, `/ui/social/status/${BOB_ID}`);
    let status = await statusResp.json();
    expect(status.is_following).toBe(true);
    expect(status.is_followed_by).toBe(true);

    // Alice blocks Bob
    const blockResp = await apiPost(page, "/ui/social/block", { target_user_id: BOB_ID });
    expect(blockResp.status()).toBe(200);

    // Verify follows are removed
    statusResp = await apiGet(page, `/ui/social/status/${BOB_ID}`);
    status = await statusResp.json();
    expect(status.is_following).toBe(false);
    expect(status.is_followed_by).toBe(false);

    // Cleanup
    await apiPost(page, "/ui/social/unblock", { target_user_id: BOB_ID });
    await bobPage.context().close();
  });
});


// ═══════════════════════════════════════════════════════════════════════════════
// Section 2: Blocked Users List API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("2 — Blocked Users List API", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await cleanupBlock(page, ALICE_ID, BOB_ID);
  });

  test.afterAll(async () => {
    await cleanupBlock(page, ALICE_ID, BOB_ID);
    await page?.close();
  });

  test("2.1 Blocked list contains blocked user", async () => {
    await apiPost(page, "/ui/social/block", { target_user_id: BOB_ID });

    const resp = await apiGet(page, "/ui/social/blocked?limit=20");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.blocked_users).toBeInstanceOf(Array);
    expect(body.blocked_users.length).toBeGreaterThanOrEqual(1);
    const bobEntry = body.blocked_users.find((u: { user_id: string }) => u.user_id === BOB_ID);
    expect(bobEntry).toBeTruthy();
    expect(bobEntry.display_name).toBeTruthy();
    expect(bobEntry.blocked_at).toBeTruthy();
  });

  test("2.2 Blocked list empty after unblock", async () => {
    await apiPost(page, "/ui/social/unblock", { target_user_id: BOB_ID });

    const resp = await apiGet(page, "/ui/social/blocked?limit=20");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const bobEntry = body.blocked_users.find((u: { user_id: string }) => u.user_id === BOB_ID);
    expect(bobEntry).toBeUndefined();
  });

  test("2.3 Block status after unblock — both false", async () => {
    const resp = await apiGet(page, `/ui/social/block-status/${BOB_ID}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.is_blocked_by_me).toBe(false);
    expect(body.is_blocking_me).toBe(false);
  });
});


// ═══════════════════════════════════════════════════════════════════════════════
// Section 3: Messaging Enforcement
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("3 — Messaging Enforcement", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await newIdentityPage(browser, BOB_ID);
    // Clean up any leftover blocks
    await cleanupBlock(alicePage, ALICE_ID, BOB_ID);
  });

  test.afterAll(async () => {
    await cleanupBlock(alicePage, ALICE_ID, BOB_ID);
    await alicePage?.close();
    await bobPage?.context().close();
  });

  test("3.1 DM creation fails when blocked — 403", async () => {
    // Alice blocks Bob
    const blockResp = await apiPostAs(alicePage, ALICE_ID, "/ui/social/block", { target_user_id: BOB_ID });
    expect(blockResp.status()).toBe(200);

    // Bob tries to create DM with Alice
    const dmResp = await apiPostAs(bobPage, BOB_ID, "/messaging/conversations/dm/find-or-create", { user_id: ALICE_ID });
    expect(dmResp.status()).toBe(403);
    const body = await dmResp.json();
    expect(body.detail).toContain("Cannot message this user");
  });

  test("3.2 Blocker also cannot create DM with blocked user — 403", async () => {
    // Alice (the blocker) tries to create DM with Bob
    const dmResp = await apiPostAs(alicePage, ALICE_ID, "/messaging/conversations/dm/find-or-create", { user_id: BOB_ID });
    expect(dmResp.status()).toBe(403);
    const body = await dmResp.json();
    expect(body.detail).toContain("Cannot message this user");
  });

  test("3.3 After unblock, DM creation works", async () => {
    // Alice unblocks Bob
    const unblockResp = await apiPostAs(alicePage, ALICE_ID, "/ui/social/unblock", { target_user_id: BOB_ID });
    expect(unblockResp.status()).toBe(200);

    // Bob can now create DM with Alice
    const dmResp = await apiPostAs(bobPage, BOB_ID, "/messaging/conversations/dm/find-or-create", { user_id: ALICE_ID });
    expect(dmResp.status()).toBe(200);
  });
});


// ═══════════════════════════════════════════════════════════════════════════════
// Section 4: Follow Status Extended
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("4 — Follow Status Extended", () => {
  let page: Page;
  let _browser: Browser;

  test.beforeAll(async ({ browser }) => {
    _browser = browser;
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await cleanupBlock(page, ALICE_ID, BOB_ID);
  });

  test.afterAll(async () => {
    await cleanupBlock(page, ALICE_ID, BOB_ID);
    await page?.close();
  });

  test("4.1 Follow status includes block fields", async () => {
    const resp = await apiGet(page, `/ui/social/status/${BOB_ID}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect("is_blocked_by_me" in body).toBe(true);
    expect("is_blocking_me" in body).toBe(true);
  });

  test("4.2 Follow blocked user returns 403", async () => {
    // Alice blocks Bob
    await apiPost(page, "/ui/social/block", { target_user_id: BOB_ID });

    // Bob tries to follow Alice using a separate context
    const bobPage = await newIdentityPage(_browser, BOB_ID);
    const followResp = await apiPostAs(bobPage, BOB_ID, "/ui/social/follow", { target_user_id: ALICE_ID });
    expect(followResp.status()).toBe(403);
    const body = await followResp.json();
    expect(body.detail).toContain("Unable to follow");

    // Cleanup
    await apiPost(page, "/ui/social/unblock", { target_user_id: BOB_ID });
    await bobPage.context().close();
  });

  test("4.3 Blocker also cannot follow blocked user", async () => {
    // Alice blocks Bob
    await apiPost(page, "/ui/social/block", { target_user_id: BOB_ID });

    // Alice tries to follow Bob
    const followResp = await apiPost(page, "/ui/social/follow", { target_user_id: BOB_ID });
    expect(followResp.status()).toBe(403);

    // Cleanup
    await apiPost(page, "/ui/social/unblock", { target_user_id: BOB_ID });
  });
});


// ═══════════════════════════════════════════════════════════════════════════════
// Section 5: Blocked Users UI
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("5 — Blocked Users UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await cleanupBlock(page, ALICE_ID, BOB_ID);
  });

  test.afterAll(async () => {
    await cleanupBlock(page, ALICE_ID, BOB_ID);
    await page?.close();
  });

  test("5.1 Blocked users page loads with empty state", async () => {
    await page.goto(`${BASE}/settings/blocked`, { waitUntil: "load" });
    await expect(page.getByRole("heading", { name: "Blocked Users", exact: true })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("You haven't blocked anyone")).toBeVisible();
  });

  test("5.2 Blocked user appears in list after blocking", async () => {
    // Block Bob via API
    await apiPost(page, "/ui/social/block", { target_user_id: BOB_ID });

    // Reload the blocked users page
    await page.goto(`${BASE}/settings/blocked`, { waitUntil: "load" });
    await expect(page.getByRole("heading", { name: "Blocked Users", exact: true })).toBeVisible({ timeout: 10_000 });

    // Bob should appear in the list with an "Unblock" button
    await expect(page.getByRole("button", { name: "Unblock" })).toBeVisible({ timeout: 5_000 });
  });

  test("5.3 Unblock from list works and shows empty state", async () => {
    // Ensure we're on the blocked page and Bob is in the list
    await page.goto(`${BASE}/settings/blocked`, { waitUntil: "load" });
    await expect(page.getByRole("button", { name: "Unblock" })).toBeVisible({ timeout: 5_000 });

    // Click Unblock
    await page.getByRole("button", { name: "Unblock" }).click();

    // Wait for the list to update
    await expect(page.getByText("You haven't blocked anyone")).toBeVisible({ timeout: 5_000 });
  });
});
