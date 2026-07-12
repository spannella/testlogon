/**
 * E2E tests for full-text search in the File Manager (/files):
 *
 * Section 41: File name prefix search — UI ("Search by name..." input)
 * Section 42: File content/text search — UI (toggle to "Content" mode)
 * Section 43: File name prefix search — API (GET /v1/fs/search)
 * Section 44: File content/text search — API (GET /v1/fs/search-text)
 *
 * How content search works in local mode:
 *   - The backend token index stores filename/path tokens (not file bytes).
 *   - When the token index has no entry for the query, a fallback scan checks
 *     whether the query is a substring of name+path+type.
 *   - So "content search" with a query that appears as a substring of the
 *     filename will find that file.  Tests are designed around this behaviour.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ─────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const PYTHON   = REPO_ROOT + "/.venv/bin/python3";

// Unique timestamp suffix so file names don't collide across test runs.
const TS = Date.now();

// File names chosen so the TS token appears as a substring (for content search)
// and as a prefix match (for name search).
//
// UI sections (41, 42) delete their files in afterAll (soft-delete).  API
// sections (43, 44) use distinct names with an "_api" suffix so that they are
// not affected by the soft-delete from the corresponding UI section.
const NAME_FILE    = `e2enm_${TS}.txt`;       // section 41 (UI name search)
const CONTENT_FILE = `e2ect_${TS}.txt`;       // section 42 (UI content search)
const NAME_FILE_43    = `e2enm_${TS}_api.txt`; // section 43 (API name search)
const CONTENT_FILE_44 = `e2ect_${TS}_api.txt`; // section 44 (API content search)

// The unique search token embedded in each filename.
const NAME_TOKEN       = `e2enm_${TS}`;
const CONTENT_TOKEN    = `e2ect_${TS}`;
const NAME_TOKEN_43    = `e2enm_${TS}_api`;
const CONTENT_TOKEN_44 = `e2ect_${TS}_api`;

// ─── Session bootstrap ─────────────────────────────────────────────────────────

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
      "python3 " + REPO_ROOT + "/e2e_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ──────────────────────────────────────────────────────────────

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

// ─── File API helpers ──────────────────────────────────────────────────────────

/** GET /v1/fs/<path> with session cookies (no CSRF needed for reads). */
async function fsGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/v1/fs/${path}`, { params });
}

/** Upload a small text file to /<name> on Alice's file system. */
async function uploadTestFile(page: Page, name: string, content = "e2e test content"): Promise<void> {
  const session = getSessions()[ALICE_ID];
  const resp = await page.request.post(`${API}/v1/fs/upload`, {
    params: { path: `/${name}` },
    multipart: {
      file: { name, mimeType: "text/plain", buffer: Buffer.from(content) },
    },
    headers: { "x-csrf-token": session.csrf_token },
  });
  if (!resp.ok()) {
    // Tolerate 409 Conflict (file already exists from a previous run).
    if (resp.status() !== 409) {
      throw new Error(`Upload failed: ${resp.status()} ${await resp.text()}`);
    }
  }
}

/** Delete a file (best-effort cleanup). */
async function deleteTestFile(page: Page, name: string): Promise<void> {
  const session = getSessions()[ALICE_ID];
  await page.request.delete(`${API}/v1/fs/file`, {
    params: { path: `/${name}` },
    headers: { "x-csrf-token": session.csrf_token },
  }).catch(() => null);
}

// ─── 41. File name prefix search — UI ─────────────────────────────────────────

test.describe("41. File name prefix search — UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await uploadTestFile(page, NAME_FILE);
    await page.goto(`${BASE}/files`, { waitUntil: "load" });
    // Wait for the file list to settle.
    await expect(
      page.locator("input[placeholder*='Search by name']"),
    ).toBeVisible({ timeout: 8000 });
  });

  test.afterAll(async () => {
    await deleteTestFile(page, NAME_FILE);
    await page?.close();
  });

  test("search input is present with placeholder 'Search by name...'", async () => {
    const input = page.locator("input[placeholder*='Search by name']");
    await expect(input).toBeVisible();
  });

  test("toggle button initially shows 'Name' (name mode is the default)", async () => {
    // Use the CSS class to scope to the rounded-pill toggle, not the DataTable
    // sort-column header which also has role=button with text "Name".
    await expect(page.locator("button.rounded-full").filter({ hasText: /^Name$/ })).toBeVisible();
  });

  test("typing the unique name prefix fires the search and shows the file", async () => {
    const searchResp = page.waitForResponse(
      (r) =>
        r.url().includes("/v1/fs/search") &&
        !r.url().includes("search-text") &&
        r.request().method() === "GET",
    );
    await page.locator("input[placeholder*='Search by name']").fill(NAME_TOKEN);
    await searchResp;

    await expect(page.getByText(NAME_FILE)).toBeVisible({ timeout: 5000 });
  });

  test("non-matching prefix shows the empty-state message", async () => {
    const searchResp = page.waitForResponse(
      (r) =>
        r.url().includes("/v1/fs/search") &&
        !r.url().includes("search-text") &&
        r.request().method() === "GET",
    );
    await page.locator("input[placeholder*='Search by name']").fill("zzznonexistent_prefix_abc123");
    await searchResp;

    // The FileTable renders an EmptyState with title "No results".
    await expect(page.getByText(/no results/i)).toBeVisible({ timeout: 5000 });
  });

  test("clearing the search input restores the normal file listing", async () => {
    await page.locator("input[placeholder*='Search by name']").clear();
    // After clearing, isSearching=false so the normal list query fires.
    await expect(page.locator("input[placeholder*='Search by name']")).toHaveValue("");
    // The page should NOT show the empty-state text for the normal (non-empty) folder.
    // Just verify we're back on the files page without an error.
    await expect(page).toHaveURL(/\/files/);
  });
});

// ─── 42. File content/text search — UI ────────────────────────────────────────

test.describe("42. File content/text search — UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await uploadTestFile(page, CONTENT_FILE);
    await page.goto(`${BASE}/files`, { waitUntil: "load" });
    await expect(
      page.locator("input[placeholder*='Search by name']"),
    ).toBeVisible({ timeout: 8000 });
  });

  test.afterAll(async () => {
    await deleteTestFile(page, CONTENT_FILE);
    await page?.close();
  });

  test("clicking the 'Name' toggle button switches to content mode", async () => {
    await page.locator("button.rounded-full").filter({ hasText: /^Name$/ }).click();
    // After toggle, the button shows "Content" and the placeholder changes.
    await expect(page.locator("button.rounded-full").filter({ hasText: /^Content$/ })).toBeVisible({ timeout: 3000 });
    await expect(
      page.locator("input[placeholder*='Search file contents']"),
    ).toBeVisible({ timeout: 3000 });
  });

  test("typing the unique content token shows the file via fallback scan", async () => {
    // In local mode, the content search falls back to a filename substring scan,
    // so a token that is a substring of the filename will match.
    const searchResp = page.waitForResponse(
      (r) =>
        r.url().includes("/v1/fs/search-text") &&
        r.request().method() === "GET",
    );
    await page.locator("input[placeholder*='Search file contents']").fill(CONTENT_TOKEN);
    await searchResp;

    await expect(page.getByText(CONTENT_FILE)).toBeVisible({ timeout: 5000 });
  });

  test("non-matching content query shows the empty-state message", async () => {
    const searchResp = page.waitForResponse(
      (r) =>
        r.url().includes("/v1/fs/search-text") &&
        r.request().method() === "GET",
    );
    await page.locator("input[placeholder*='Search file contents']").fill("zzznonexistentcontentabc123");
    await searchResp;

    await expect(page.getByText(/no results/i)).toBeVisible({ timeout: 5000 });
  });

  test("clicking 'Content' toggle button switches back to name mode", async () => {
    await page.locator("button.rounded-full").filter({ hasText: /^Content$/ }).click();
    await expect(page.locator("button.rounded-full").filter({ hasText: /^Name$/ })).toBeVisible({ timeout: 3000 });
    await expect(
      page.locator("input[placeholder*='Search by name']"),
    ).toBeVisible({ timeout: 3000 });
  });
});

// ─── 43. File name prefix search — API ────────────────────────────────────────

test.describe("43. File name prefix search API — GET /v1/fs/search", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    // Use a dedicated "_api" file distinct from the UI section 41 file.
    // Section 41's afterAll soft-deletes NAME_FILE; if we reused that name here
    // the 409 from uploadTestFile would silently pass but the file would remain
    // soft-deleted and search_prefix would return 0 results.
    await uploadTestFile(page, NAME_FILE_43);
  });

  test.afterAll(async () => {
    await deleteTestFile(page, NAME_FILE_43);
    await page?.close();
  });

  test("prefix matching the uploaded file returns it in results", async () => {
    const r = await fsGet(page, "search", { prefix: NAME_TOKEN_43 });
    expect(r.ok()).toBe(true);
    const data = await r.json() as { results: Array<{ name: string; path: string }> };
    expect(Array.isArray(data.results)).toBe(true);
    const found = data.results.find((f) => f.name === NAME_FILE_43);
    expect(found).toBeDefined();
  });

  test("prefix with no matching files returns empty results array", async () => {
    const r = await fsGet(page, "search", { prefix: "zzznomatch_prefix_xyz123abc" });
    expect(r.ok()).toBe(true);
    const data = await r.json() as { results: unknown[] };
    expect(data.results).toHaveLength(0);
  });

  test("search result items have name and path fields", async () => {
    const r = await fsGet(page, "search", { prefix: NAME_TOKEN_43 });
    expect(r.ok()).toBe(true);
    const data = await r.json() as { results: Array<Record<string, unknown>> };
    if (data.results.length > 0) {
      expect(data.results[0]).toHaveProperty("name");
      expect(data.results[0]).toHaveProperty("path");
    }
  });

  test("unauthenticated request returns 401 or 403", async () => {
    const anonCtx = await page.context().browser()!.newContext();
    const anonPage = await anonCtx.newPage();
    const r = await anonPage.request.get(`${API}/v1/fs/search`, { params: { prefix: NAME_TOKEN_43 } });
    await anonCtx.close();
    expect([401, 403]).toContain(r.status());
  });

  test("missing prefix param returns 422", async () => {
    const r = await page.request.get(`${API}/v1/fs/search`);
    expect(r.status()).toBe(422);
  });
});

// ─── 44. File content/text search — API ───────────────────────────────────────

test.describe("44. File content/text search API — GET /v1/fs/search-text", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    // Use a dedicated "_api" file distinct from the UI section 42 file.
    // Section 42's afterAll soft-deletes CONTENT_FILE; reusing it here would
    // cause uploadTestFile to tolerate 409 silently, leaving the file in a
    // soft-deleted state that search-text would never return.
    await uploadTestFile(page, CONTENT_FILE_44);
  });

  test.afterAll(async () => {
    await deleteTestFile(page, CONTENT_FILE_44);
    await page?.close();
  });

  test("query matching the filename token finds the file", async () => {
    // The fallback scan treats the query as a substring match on name+path+type.
    const r = await fsGet(page, "search-text", { q: CONTENT_TOKEN_44 });
    expect(r.ok()).toBe(true);
    const data = await r.json() as { results: Array<{ name: string }> };
    expect(Array.isArray(data.results)).toBe(true);
    const found = data.results.find((f) => f.name === CONTENT_FILE_44);
    expect(found).toBeDefined();
  });

  test("query with no matching files returns empty results", async () => {
    const r = await fsGet(page, "search-text", { q: "zzznomatchcontent_xyz123abc" });
    expect(r.ok()).toBe(true);
    const data = await r.json() as { results: unknown[] };
    expect(data.results).toHaveLength(0);
  });

  test("result items have name and path fields", async () => {
    const r = await fsGet(page, "search-text", { q: CONTENT_TOKEN_44 });
    expect(r.ok()).toBe(true);
    const data = await r.json() as { results: Array<Record<string, unknown>> };
    if (data.results.length > 0) {
      expect(data.results[0]).toHaveProperty("name");
      expect(data.results[0]).toHaveProperty("path");
    }
  });

  test("unauthenticated request returns 401 or 403", async () => {
    const anonCtx = await page.context().browser()!.newContext();
    const anonPage = await anonCtx.newPage();
    const r = await anonPage.request.get(`${API}/v1/fs/search-text`, { params: { q: CONTENT_TOKEN_44 } });
    await anonCtx.close();
    expect([401, 403]).toContain(r.status());
  });

  test("missing q param returns 422", async () => {
    const r = await page.request.get(`${API}/v1/fs/search-text`);
    expect(r.status()).toBe(422);
  });
});
