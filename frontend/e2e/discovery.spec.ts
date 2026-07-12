/**
 * E2E tests for SOC-003: User Search & Discovery
 *
 * Section 116: Discovery API — search, trending, suggested, profile, reindex (9 tests)
 * Section 117: Discover Page UI (4 tests)
 *
 * Auth: uses e2e_admin_session_setup.py cookie-based sessions.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ── Constants ─────────────────────────────────────────────────────────────

const API  = "http://localhost:8000";
const BASE = "http://localhost:3000";

const ALICE_KEY = "alice";
const BOB_KEY   = "bob";
const ALICE_SUB = "e2e_alice@test.local";
const BOB_SUB   = "e2e_bob@test.local";

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
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
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

async function apiPost(page: Page, sessionKey: string, path: string, body: object) {
  const sessions = getSessions();
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": sessions[sessionKey].csrf_token },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  let url = `${API}${path}`;
  if (params) {
    const qs = new URLSearchParams(params).toString();
    url += `?${qs}`;
  }
  return page.request.get(url);
}

async function apiPatch(page: Page, sessionKey: string, path: string, body: object) {
  const sessions = getSessions();
  return page.request.patch(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": sessions[sessionKey].csrf_token },
  });
}

// ═════════════════════════════════════════════════════════════════════════
// Section 116: Discovery API
// ═════════════════════════════════════════════════════════════════════════

test.describe("116 · Discovery API", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage   = await newIdentityPage(browser, BOB_KEY);

    // Set display names on profiles so reindex has something to work with
    await apiPatch(alicePage, ALICE_KEY, "/ui/profile", {
      display_name: "Alice E2E Discovery",
      title: "Testing discovery",
    });
    await apiPatch(bobPage, BOB_KEY, "/ui/profile", {
      display_name: "Bob E2E Discovery",
      title: "Testing discovery too",
    });
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("116.1 reindex Alice into discovery index", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/discover/reindex", {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.tokens_indexed).toBeGreaterThan(0);
  });

  test("116.2 reindex Bob into discovery index", async () => {
    const resp = await apiPost(bobPage, BOB_KEY, "/ui/discover/reindex", {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.tokens_indexed).toBeGreaterThan(0);
  });

  test("116.3 search for Alice by name prefix", async () => {
    const resp = await apiGet(bobPage, "/ui/discover/search", { q: "alice", limit: "10" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeDefined();
    const alice = data.items.find((u: any) => u.user_id === ALICE_SUB);
    expect(alice).toBeTruthy();
    expect(alice.display_name).toContain("Alice");
    expect(alice.is_following).toBe(false);
  });

  test("116.4 search for Bob by name prefix", async () => {
    const resp = await apiGet(alicePage, "/ui/discover/search", { q: "bob", limit: "10" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const bob = data.items.find((u: any) => u.user_id === BOB_SUB);
    expect(bob).toBeTruthy();
    expect(bob.display_name).toContain("Bob");
  });

  test("116.5 search excludes self", async () => {
    const resp = await apiGet(alicePage, "/ui/discover/search", { q: "alice", limit: "10" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const self = data.items.find((u: any) => u.user_id === ALICE_SUB);
    expect(self).toBeFalsy();
  });

  test("116.6 search with no results returns empty", async () => {
    const resp = await apiGet(alicePage, "/ui/discover/search", { q: "zzzznonexistent999", limit: "10" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toHaveLength(0);
  });

  test("116.7 trending endpoint returns array", async () => {
    const resp = await apiGet(alicePage, "/ui/discover/trending", { limit: "20" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.items)).toBe(true);
  });

  test("116.8 suggested endpoint returns array", async () => {
    const resp = await apiGet(alicePage, "/ui/discover/suggested", { limit: "12" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.items)).toBe(true);
  });

  test("116.9 profile endpoint returns user profile", async () => {
    const resp = await apiGet(alicePage, `/ui/discover/profile/${BOB_SUB}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.user_id).toBe(BOB_SUB);
    expect(data.display_name).toContain("Bob");
    expect(typeof data.follower_count).toBe("number");
    expect(typeof data.following_count).toBe("number");
    expect(typeof data.is_following).toBe("boolean");
  });
});

// ═════════════════════════════════════════════════════════════════════════
// Section 117: Discover Page UI
// ═════════════════════════════════════════════════════════════════════════

test.describe("117 · Discover Page UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_KEY);

    // Ensure Alice is indexed
    await apiPost(alicePage, ALICE_KEY, "/ui/discover/reindex", {});
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("117.1 Discover page loads with heading and search", async () => {
    await alicePage.goto(BASE + "/discover", { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByRole("heading", { name: "Discover" })).toBeVisible();
    await expect(alicePage.getByPlaceholder("Search users...")).toBeVisible();
  });

  test("117.2 Discover shows Suggested and Trending sections by default", async () => {
    await alicePage.goto(BASE + "/discover", { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText("Suggested For You")).toBeVisible();
    await expect(alicePage.getByText("Trending Creators", { exact: true })).toBeVisible();
  });

  test("117.3 typing in search shows search results section", async () => {
    await alicePage.goto(BASE + "/discover", { waitUntil: "domcontentloaded" });
    const searchInput = alicePage.getByPlaceholder("Search users...");
    await searchInput.fill("bob");
    await expect(alicePage.getByText("Search Results")).toBeVisible({ timeout: 5000 });
  });

  test("117.4 clearing search returns to Suggested/Trending", async () => {
    await alicePage.goto(BASE + "/discover", { waitUntil: "domcontentloaded" });
    const searchInput = alicePage.getByPlaceholder("Search users...");
    await searchInput.fill("bob");
    await expect(alicePage.getByText("Search Results")).toBeVisible({ timeout: 5000 });
    await searchInput.fill("");
    await expect(alicePage.getByText("Suggested For You")).toBeVisible({ timeout: 5000 });
    await expect(alicePage.getByText("Trending Creators", { exact: true })).toBeVisible({ timeout: 5000 });
  });
});
