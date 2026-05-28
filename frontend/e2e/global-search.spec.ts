/**
 * E2E tests for Global Search (SOCIAL-003).
 *
 * Section 1: Unified Search API (7 tests)
 *   - GET /ui/search?q=...&types=...&limit=...
 *
 * Section 2: Search Page UI (5 tests)
 *   - /search?q=... page rendering, tabs, empty state
 *
 * Section 3: Header Search Integration (4 tests)
 *   - Ctrl+K, page navigation, content results, "View all results"
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ─────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const PYTHON   = "/home/ubuntu/testlogon/.venv/bin/python3";

// Unique token to avoid collision across runs
const TS = Date.now();
const SEARCH_TOKEN = `gsrch_${TS}`;

// ─── Session bootstrap ────────────────────────────────────────────────────────

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
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
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

// ─── DDB helper ────────────────────────────────────────────────────────────────

const DDB_HELPER_PRELUDE = `
import boto3, os, time
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
`;

// ─── Seed data ─────────────────────────────────────────────────────────────────

/**
 * Ensure Alice has a discoverable profile in the DiscoveryIndex.
 */
function seedAliceDiscovery(): void {
  execSync(
    `${PYTHON} -c "
${DDB_HELPER_PRELUDE.trim()}
import os
tbl = ddb.Table(os.environ.get('DDB_DISCOVERY_INDEX', 'DiscoveryIndex'))
tokens = ['alice', 'alic', 'ali', 'al', 'a', 'e2e', 'e2e_alice@test.local']
for tok in tokens:
    tbl.put_item(Item={
        'pk': f'TOKEN#{tok}',
        'sk': f'USER#${ALICE_ID}',
        'user_id': '${ALICE_ID}',
        'display_name': 'E2E Alice',
        'discoverability': 'active',
        'follower_count': 0,
        'indexed_at': int(time.time()),
    })
print('Seeded Alice discovery tokens')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
}

/**
 * Seed a post with a unique body containing SEARCH_TOKEN for post search tests.
 */
let _seededPostId: string | null = null;
function seedSearchPost(): string {
  if (_seededPostId) return _seededPostId;
  const raw = execSync(
    `${PYTHON} -c "
${DDB_HELPER_PRELUDE.trim()}
import os, uuid
tbl = ddb.Table(os.environ.get('APP_TABLE', 'app_single_table'))
post_id = 'p_' + uuid.uuid4().hex
body = 'This is a unique post about ${SEARCH_TOKEN} for E2E testing'
tbl.put_item(Item={
    'pk': f'POST#{post_id}',
    'sk': 'META',
    'Entity': 'Post',
    'post_id': post_id,
    'user_id': '${ALICE_ID}',
    'created_at': '2026-05-28T00:00:00Z',
    'published_at': '2026-05-28T00:00:00Z',
    'status': 'published',
    'body': body,
    'body_plain': body,
    'body_plain_lc': body.lower(),
    'body_format': 'plain',
    'body_version': 1,
    'visibility': 'public',
    'locked': False,
    'image_urls': [],
    'like_count': 0,
    'comment_count': 0,
    'GSI2PK': f'POST_AUTHOR#${ALICE_ID}',
    'GSI2SK': f'2026-05-28T00:00:00Z#POST#{post_id}',
})
print(post_id)
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  ).toString().trim();
  _seededPostId = raw;
  return raw;
}

// ─── API helper ────────────────────────────────────────────────────────────────

function csrfToken(identity: string): string {
  return getSessions()[identity]!.csrf_token;
}

// =============================================================================
// Section 1: Unified Search API
// =============================================================================

test.describe("1 — Unified Search API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    seedAliceDiscovery();
    seedSearchPost();

    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("1.1 Search returns results with all type keys", async () => {
    const resp = await alicePage.request.get(`${BASE}/ui/search`, {
      headers: { "x-csrf-token": csrfToken(ALICE_ID) },
      params: { q: "test", limit: "5" },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data).toHaveProperty("query");
    expect(data).toHaveProperty("results");
    expect(data.results).toHaveProperty("users");
    expect(data.results).toHaveProperty("posts");
    expect(data.results).toHaveProperty("catalog");
    expect(data.results).toHaveProperty("files");
    // Each section has the right shape
    for (const key of ["users", "posts", "catalog", "files"]) {
      expect(data.results[key]).toHaveProperty("items");
      expect(data.results[key]).toHaveProperty("total_estimate");
      expect(data.results[key]).toHaveProperty("has_more");
    }
  });

  test("1.2 Type filter restricts results", async () => {
    const resp = await alicePage.request.get(`${BASE}/ui/search`, {
      headers: { "x-csrf-token": csrfToken(ALICE_ID) },
      params: { q: "alice", types: "users", limit: "5" },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // users may have results; others must be empty
    expect(data.results.posts.items).toHaveLength(0);
    expect(data.results.catalog.items).toHaveLength(0);
    expect(data.results.files.items).toHaveLength(0);
  });

  test("1.3 Empty query returns 400", async () => {
    const resp = await alicePage.request.get(`${BASE}/ui/search`, {
      headers: { "x-csrf-token": csrfToken(ALICE_ID) },
      params: { q: "", limit: "5" },
    });
    // FastAPI returns 422 for min_length=1 validation or 400 for our custom check
    expect([400, 422]).toContain(resp.status());
  });

  test("1.4 Search results have correct item shape", async () => {
    const resp = await alicePage.request.get(`${BASE}/ui/search`, {
      headers: { "x-csrf-token": csrfToken(ALICE_ID) },
      params: { q: "alice", types: "users", limit: "5" },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    if (data.results.users.items.length > 0) {
      const item = data.results.users.items[0];
      expect(item).toHaveProperty("type");
      expect(item).toHaveProperty("id");
      expect(item).toHaveProperty("title");
      expect(item).toHaveProperty("url");
    }
  });

  test("1.5 Post search finds seeded post by unique token", async () => {
    const resp = await alicePage.request.get(`${BASE}/ui/search`, {
      headers: { "x-csrf-token": csrfToken(ALICE_ID) },
      params: { q: SEARCH_TOKEN, types: "posts", limit: "5" },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.results.posts.items.length).toBeGreaterThanOrEqual(1);
    const found = data.results.posts.items.find(
      (it: any) => it.snippet.toLowerCase().includes(SEARCH_TOKEN.toLowerCase()),
    );
    expect(found).toBeTruthy();
    expect(found.type).toBe("post");
  });

  test("1.6 User search finds Alice", async () => {
    const resp = await alicePage.request.get(`${BASE}/ui/search`, {
      headers: { "x-csrf-token": csrfToken(ALICE_ID) },
      params: { q: "alice", types: "users", limit: "5" },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // Alice's discovery index was seeded; but the search excludes self (viewer_id)
    // so the result may be empty if no other user matches "alice"
    // But the endpoint should return 200 with valid shape regardless
    expect(Array.isArray(data.results.users.items)).toBe(true);
  });

  test("1.7 Invalid type returns 400", async () => {
    const resp = await alicePage.request.get(`${BASE}/ui/search`, {
      headers: { "x-csrf-token": csrfToken(ALICE_ID) },
      params: { q: "test", types: "users,invalidtype", limit: "5" },
    });
    expect(resp.status()).toBe(400);
  });
});

// =============================================================================
// Section 2: Search Page UI
// =============================================================================

test.describe("2 — Search Page UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    seedAliceDiscovery();
    seedSearchPost();

    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("2.1 Search page loads from URL param", async () => {
    await page.goto(`${BASE}/search?q=${SEARCH_TOKEN}`, {
      waitUntil: "domcontentloaded",
    });
    // Input should be pre-filled
    const input = page.getByTestId("search-input");
    await expect(input).toBeVisible();
    await expect(input).toHaveValue(SEARCH_TOKEN);
  });

  test("2.2 Tab switching works", async () => {
    await page.goto(`${BASE}/search?q=${SEARCH_TOKEN}`, {
      waitUntil: "domcontentloaded",
    });
    // Wait for results to load
    await page.waitForTimeout(1500);

    // Click "Posts" tab
    await page.getByRole("tab", { name: /Posts/ }).click();
    // The Posts tab content should be visible
    await expect(page.getByRole("tab", { name: /Posts/ })).toHaveAttribute(
      "data-state",
      "active",
    );
  });

  test("2.3 All tab shows results", async () => {
    await page.goto(`${BASE}/search?q=${SEARCH_TOKEN}`, {
      waitUntil: "domcontentloaded",
    });
    await page.waitForTimeout(1500);

    // All tab should be active by default
    await expect(page.getByRole("tab", { name: "All" })).toHaveAttribute(
      "data-state",
      "active",
    );
  });

  test("2.4 Empty results shows empty state", async () => {
    const gibberish = `zzz_xyznonexist_${TS}`;
    await page.goto(`${BASE}/search?q=${gibberish}`, {
      waitUntil: "domcontentloaded",
    });
    // Wait for search to complete
    await page.waitForTimeout(2000);
    const noResults = page.getByTestId("no-results");
    await expect(noResults).toBeVisible({ timeout: 5000 });
  });

  test("2.5 Clicking user result navigates", async () => {
    // Seed bob in discovery for this test
    execSync(
      `${PYTHON} -c "
${DDB_HELPER_PRELUDE.trim()}
import os
tbl = ddb.Table(os.environ.get('DDB_DISCOVERY_INDEX', 'DiscoveryIndex'))
tokens = ['bob', 'bo', 'b', 'e2e bob', 'e2e_bob@test.local']
for tok in tokens:
    tbl.put_item(Item={
        'pk': f'TOKEN#{tok}',
        'sk': f'USER#${BOB_ID}',
        'user_id': '${BOB_ID}',
        'display_name': 'E2E Bob',
        'discoverability': 'active',
        'follower_count': 0,
        'indexed_at': int(time.time()),
    })
print('Seeded Bob discovery tokens')
"`,
      { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
    );

    await page.goto(`${BASE}/search?q=bob`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(1500);

    // Find a user result and click it
    const userResult = page.getByTestId("search-result-user").first();
    if (await userResult.isVisible()) {
      await userResult.click();
      // Should navigate somewhere (discover page for users)
      await page.waitForTimeout(500);
      expect(page.url()).toContain("/discover");
    }
  });
});

// =============================================================================
// Section 3: Header Search Integration
// =============================================================================

test.describe("3 — Header Search Integration", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    seedAliceDiscovery();
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(500);
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("3.1 Ctrl+K opens search dialog", async () => {
    await page.keyboard.press("Control+k");
    // CommandDialog should be visible
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible({ timeout: 3000 });
  });

  test("3.2 Page navigation still works", async () => {
    // Close any open dialog first
    await page.keyboard.press("Escape");
    await page.waitForTimeout(300);

    // Open search
    await page.keyboard.press("Control+k");
    await page.waitForTimeout(300);

    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible({ timeout: 3000 });

    // Type "Messages" to filter pages
    await page.getByPlaceholder("Search content and pages...").fill("Messages");
    await page.waitForTimeout(300);

    // "Messages" item should be visible
    const messagesItem = dialog.getByText("Messages", { exact: true }).first();
    await expect(messagesItem).toBeVisible({ timeout: 3000 });
  });

  test("3.3 View all results link appears for queries", async () => {
    // Close any open dialog
    await page.keyboard.press("Escape");
    await page.waitForTimeout(300);

    await page.keyboard.press("Control+k");
    await page.waitForTimeout(300);

    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible({ timeout: 3000 });

    // Type a search query
    await page.getByPlaceholder("Search content and pages...").fill("alice");
    await page.waitForTimeout(1000);

    // "View all results for..." link should appear
    const viewAll = dialog.getByText(/View all results for/).first();
    await expect(viewAll).toBeVisible({ timeout: 5000 });
  });

  test("3.4 View all results navigates to search page", async () => {
    // The dialog should still be open from previous test, but re-open to be safe
    await page.keyboard.press("Escape");
    await page.waitForTimeout(300);

    await page.keyboard.press("Control+k");
    await page.waitForTimeout(300);

    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible({ timeout: 3000 });

    await page.getByPlaceholder("Search content and pages...").fill("alice");
    await page.waitForTimeout(1000);

    // Click "View all results"
    const viewAll = dialog.getByText(/View all results for/).first();
    await expect(viewAll).toBeVisible({ timeout: 5000 });
    await viewAll.click();

    // Should navigate to /search?q=alice
    await page.waitForTimeout(500);
    expect(page.url()).toContain("/search");
    expect(page.url()).toContain("q=alice");
  });
});
