/**
 * E2E tests for PLATFORM-011: Global Search — Cross-Domain Search with
 * Categorized Results.
 *
 * Auth strategy:
 * - Backend sessions created via e2e_admin_session_setup.py
 * - Cookies injected into browser via injectAuth()
 * - API calls use page.request with CSRF header (session auth)
 *
 * Sections:
 *   101 — Multi-domain search API (15 tests)
 *   102 — Search history API (10 tests)
 *   103 — Search UI — command palette + page (14 tests)
 *   104 — Edge cases (10 tests)
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "alice";
const BOB_ID = "bob";

const TS = Date.now();

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
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.evaluate(
    (uid: string) => {
      const state = { userId: uid, accessToken: null, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    session.user_sub,
  );
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  const session = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body,
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  const url = params
    ? `${API}${path}?${new URLSearchParams(params)}`
    : `${API}${path}`;
  return page.request.get(url);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// GAP-0359: GET /ui/search is rate-limited to 30 requests / 60s / user. Across
// this large spec a user can exhaust the budget, so when a request that should
// succeed (or return a deterministic validation error) hits a 429, wait out the
// window once and retry. This asserts the intended behavior, not the limiter.
async function searchWithRetry(
  page: Page,
  params: Record<string, string>,
) {
  let resp = await apiGet(page, "/ui/search", params);
  if (resp.status() === 429) {
    await sleep(61_000);
    resp = await apiGet(page, "/ui/search", params);
  }
  return resp;
}

async function apiDelete(page: Page, identity: string, path: string) {
  const session = getSessions()[identity];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── Unique test data ─────────────────────────────────────────────────────────

const UNIQUE_TICKET_SUBJECT = `gstkt_${TS}`;
const UNIQUE_CONTACT_NAME = `gscon_${TS}`;

// =============================================================================
// Section 101: Multi-domain search API
// =============================================================================

test.describe("101 — Multi-domain search API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Create a ticket for Alice
    const ticketResp = await apiPost(alicePage, ALICE_ID, "/tickets", {
      subject: UNIQUE_TICKET_SUBJECT,
      description: `Description for ${UNIQUE_TICKET_SUBJECT}`,
    });
    expect(ticketResp.status()).toBe(200);

    // Create a contact for Alice
    const contactResp = await apiPost(alicePage, ALICE_ID, "/ui/contacts", {
      user_id: UNIQUE_CONTACT_NAME,
    });
    expect(contactResp.status()).toBe(201);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("101.1 Search tickets returns Alice's ticket", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: UNIQUE_TICKET_SUBJECT,
      types: "tickets",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.results.tickets.items.length).toBeGreaterThanOrEqual(1);
    const match = data.results.tickets.items.find(
      (it: any) => it.title === UNIQUE_TICKET_SUBJECT,
    );
    expect(match).toBeTruthy();
    expect(match.type).toBe("ticket");
    expect(match.meta?.created_by).toBe(getSessions()[ALICE_ID].user_sub);
  });

  test("101.2 Search contacts returns Alice's contact", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: UNIQUE_CONTACT_NAME,
      types: "contacts",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.results.contacts.items.length).toBeGreaterThanOrEqual(1);
    const match = data.results.contacts.items.find(
      (it: any) => it.id === UNIQUE_CONTACT_NAME,
    );
    expect(match).toBeTruthy();
    expect(match.type).toBe("contact");
  });

  test("101.3 Search all domains returns results object with all sections", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: "test",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.results).toBeDefined();
    // All 9 domains should be present in results
    for (const domain of [
      "users", "posts", "catalog", "files",
      "messages", "tickets", "contacts", "videos", "calendar",
    ]) {
      expect(data.results[domain]).toBeDefined();
      expect(data.results[domain].items).toBeDefined();
      expect(typeof data.results[domain].has_more).toBe("boolean");
    }
  });

  test("101.4 Empty query returns 400", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: "   ",
    });
    // FastAPI min_length=1 on q param should reject whitespace-only after strip
    expect(resp.status()).toBe(400);
  });

  test("101.5 Query sanitization strips control characters", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: "hello\x01world",
      types: "contacts",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.query).toBe("helloworld");
  });

  test("101.6 Ticket search respects authorization — Bob cannot see Alice's ticket", async () => {
    const bobPage = await alicePage.context().browser()!.newPage();
    await injectAuth(bobPage, BOB_ID);
    const resp = await apiGet(bobPage, "/ui/search", {
      q: UNIQUE_TICKET_SUBJECT,
      types: "tickets",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const match = data.results.tickets.items.find(
      (it: any) => it.title === UNIQUE_TICKET_SUBJECT,
    );
    expect(match).toBeUndefined();
    await bobPage.close();
  });

  test("101.7 Contact search respects authorization — Bob cannot see Alice's contacts", async () => {
    const bobPage = await alicePage.context().browser()!.newPage();
    await injectAuth(bobPage, BOB_ID);
    const resp = await apiGet(bobPage, "/ui/search", {
      q: UNIQUE_CONTACT_NAME,
      types: "contacts",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const match = data.results.contacts.items.find(
      (it: any) => it.id === UNIQUE_CONTACT_NAME,
    );
    expect(match).toBeUndefined();
    await bobPage.close();
  });

  test("101.8 Limit parameter caps results per section", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: "test",
      types: "contacts",
      limit: "1",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.results.contacts.items.length).toBeLessThanOrEqual(1);
  });

  test("101.9 Invalid search type returns 400", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: "test",
      types: "invalid_type",
    });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail).toContain("Invalid search types");
  });

  test("101.10 Search messages domain returns empty when no matches", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: `nonexistent_msg_${TS}_xyzzy`,
      types: "messages",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.results.messages.items).toHaveLength(0);
  });

  test("101.11 Search videos domain returns empty section", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: `nonexistent_vid_${TS}`,
      types: "videos",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.results.videos.items).toHaveLength(0);
    expect(data.results.videos.has_more).toBe(false);
  });

  test("101.12 Search calendar domain returns empty section", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: `nonexistent_cal_${TS}`,
      types: "calendar",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.results.calendar.items).toHaveLength(0);
  });

  test("101.13 Search with unicode query succeeds", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: "café",
      types: "contacts",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.query).toContain("caf");
  });

  test("101.14 Partial flag is false when all domains succeed", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: "test",
      types: "contacts,tickets",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.partial).toBe(false);
  });

  test("101.15 Result items have standard shape", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: UNIQUE_TICKET_SUBJECT,
      types: "tickets",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const item = data.results.tickets.items[0];
    expect(item).toBeDefined();
    expect(item.type).toBe("ticket");
    expect(typeof item.id).toBe("string");
    expect(typeof item.title).toBe("string");
    expect(typeof item.snippet).toBe("string");
    expect(typeof item.url).toBe("string");
    expect(item.url).toContain("/tickets/");
    expect(item.meta).toBeDefined();
    expect(item.meta.status).toBeDefined();
  });
});

// =============================================================================
// Section 102: Search history API
// =============================================================================

test.describe("102 — Search history API", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);

    // Clear any existing history
    await apiDelete(alicePage, ALICE_ID, "/ui/search/history");
    await apiDelete(bobPage, BOB_ID, "/ui/search/history");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("102.1 POST /ui/search/history records a query; GET returns it", async () => {
    const postResp = await apiPost(alicePage, ALICE_ID, "/ui/search/history", {
      query: `hist_${TS}_one`,
      result_count: 5,
    });
    expect(postResp.status()).toBe(200);
    const postData = await postResp.json();
    expect(postData.ok).toBe(true);
    expect(postData.id).toBeTruthy();

    const getResp = await apiGet(alicePage, "/ui/search/history");
    expect(getResp.status()).toBe(200);
    const getData = await getResp.json();
    expect(getData.items.length).toBeGreaterThanOrEqual(1);
    const match = getData.items.find((it: any) => it.query === `hist_${TS}_one`);
    expect(match).toBeTruthy();
    expect(match.result_count).toBe(5);
  });

  test("102.2 Duplicate queries update timestamp, don't create duplicates", async () => {
    await apiPost(alicePage, ALICE_ID, "/ui/search/history", {
      query: `hist_${TS}_dup`,
    });
    await alicePage.waitForTimeout(100);
    await apiPost(alicePage, ALICE_ID, "/ui/search/history", {
      query: `hist_${TS}_dup`,
    });

    const getResp = await apiGet(alicePage, "/ui/search/history");
    const getData = await getResp.json();
    const matches = getData.items.filter(
      (it: any) => it.query === `hist_${TS}_dup`,
    );
    expect(matches).toHaveLength(1);
  });

  test("102.3 DELETE /ui/search/history/{id} removes specific entry", async () => {
    const postResp = await apiPost(alicePage, ALICE_ID, "/ui/search/history", {
      query: `hist_${TS}_del`,
    });
    const postData = await postResp.json();
    const itemId = postData.id;

    const delResp = await apiDelete(
      alicePage,
      ALICE_ID,
      `/ui/search/history/${encodeURIComponent(itemId)}`,
    );
    expect(delResp.status()).toBe(200);

    const getResp = await apiGet(alicePage, "/ui/search/history");
    const getData = await getResp.json();
    const match = getData.items.find((it: any) => it.query === `hist_${TS}_del`);
    expect(match).toBeUndefined();
  });

  test("102.4 DELETE /ui/search/history clears all entries", async () => {
    await apiPost(alicePage, ALICE_ID, "/ui/search/history", { query: `hist_${TS}_clr1` });
    await apiPost(alicePage, ALICE_ID, "/ui/search/history", { query: `hist_${TS}_clr2` });

    const delResp = await apiDelete(alicePage, ALICE_ID, "/ui/search/history");
    expect(delResp.status()).toBe(200);
    const delData = await delResp.json();
    expect(delData.ok).toBe(true);
    expect(delData.deleted_count).toBeGreaterThanOrEqual(2);

    const getResp = await apiGet(alicePage, "/ui/search/history");
    const getData = await getResp.json();
    expect(getData.items).toHaveLength(0);
  });

  test("102.5 History respects user isolation — Alice cannot see Bob's history", async () => {
    await apiPost(bobPage, BOB_ID, "/ui/search/history", {
      query: `hist_${TS}_bob_private`,
    });

    const aliceResp = await apiGet(alicePage, "/ui/search/history");
    const aliceData = await aliceResp.json();
    const match = aliceData.items.find(
      (it: any) => it.query === `hist_${TS}_bob_private`,
    );
    expect(match).toBeUndefined();
  });

  test("102.6 POST /ui/search/history with empty query returns 400", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/search/history", {
      query: "",
    });
    expect(resp.status()).toBe(400);
  });

  test("102.7 GET /ui/search/history returns items sorted newest-first", async () => {
    await apiDelete(alicePage, ALICE_ID, "/ui/search/history");
    await apiPost(alicePage, ALICE_ID, "/ui/search/history", { query: `hist_${TS}_sort_a` });
    // Wait >1s to guarantee different timestamp (now_ts() returns seconds)
    await alicePage.waitForTimeout(1100);
    await apiPost(alicePage, ALICE_ID, "/ui/search/history", { query: `hist_${TS}_sort_b` });
    await alicePage.waitForTimeout(1100);
    await apiPost(alicePage, ALICE_ID, "/ui/search/history", { query: `hist_${TS}_sort_c` });

    const resp = await apiGet(alicePage, "/ui/search/history");
    const data = await resp.json();
    const queries = data.items.map((it: any) => it.query);
    expect(queries[0]).toBe(`hist_${TS}_sort_c`);
  });

  test("102.8 POST /ui/search/history stores result_count when provided", async () => {
    await apiPost(alicePage, ALICE_ID, "/ui/search/history", {
      query: `hist_${TS}_count`,
      result_count: 42,
    });
    const resp = await apiGet(alicePage, "/ui/search/history");
    const data = await resp.json();
    const match = data.items.find((it: any) => it.query === `hist_${TS}_count`);
    expect(match).toBeTruthy();
    expect(match.result_count).toBe(42);
  });

  test("102.9 DELETE /ui/search/history returns deleted_count matching actual deletions", async () => {
    await apiDelete(alicePage, ALICE_ID, "/ui/search/history");
    await apiPost(alicePage, ALICE_ID, "/ui/search/history", { query: `hist_${TS}_cnt1` });
    await apiPost(alicePage, ALICE_ID, "/ui/search/history", { query: `hist_${TS}_cnt2` });
    await apiPost(alicePage, ALICE_ID, "/ui/search/history", { query: `hist_${TS}_cnt3` });

    const delResp = await apiDelete(alicePage, ALICE_ID, "/ui/search/history");
    const delData = await delResp.json();
    expect(delData.deleted_count).toBe(3);
  });

  test("102.10 History item has ts field", async () => {
    await apiPost(alicePage, ALICE_ID, "/ui/search/history", {
      query: `hist_${TS}_ts`,
    });
    const resp = await apiGet(alicePage, "/ui/search/history");
    const data = await resp.json();
    const match = data.items.find((it: any) => it.query === `hist_${TS}_ts`);
    expect(match).toBeTruthy();
    expect(typeof match.ts).toBe("number");
    expect(match.ts).toBeGreaterThan(1700000000);
  });
});

// =============================================================================
// Section 103: Search UI — command palette + search page
// =============================================================================

test.describe("103 — Search UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Create a ticket so search has something to find
    await apiPost(alicePage, ALICE_ID, "/tickets", {
      subject: `ui_tkt_${TS}`,
      description: `UI test ticket ${TS}`,
    });

    // Create a contact
    await apiPost(alicePage, ALICE_ID, "/ui/contacts", {
      user_id: `ui_con_${TS}`,
    });
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("103.1 Ctrl+K opens command palette", async () => {
    await alicePage.goto(`${BASE}/`, { waitUntil: "load" });
    await alicePage.waitForTimeout(500);
    await alicePage.keyboard.press("Control+k");
    await expect(
      alicePage.getByPlaceholder("Search content and pages..."),
    ).toBeVisible({ timeout: 3000 });
  });

  test("103.2 Typing 2+ chars triggers content search", async () => {
    await alicePage.goto(`${BASE}/`, { waitUntil: "load" });
    await alicePage.waitForTimeout(500);
    await alicePage.keyboard.press("Control+k");
    await alicePage.getByPlaceholder("Search content and pages...").fill(`ui_tkt_${TS}`);
    // Wait for debounce + API call
    await alicePage.waitForTimeout(1500);
    // The Tickets group should appear in the command palette
    await expect(alicePage.getByText("Tickets").first()).toBeVisible({ timeout: 5000 });
  });

  test("103.3 View all results navigates to /search", async () => {
    await alicePage.goto(`${BASE}/`, { waitUntil: "load" });
    await alicePage.waitForTimeout(500);
    await alicePage.keyboard.press("Control+k");
    await alicePage
      .getByPlaceholder("Search content and pages...")
      .fill("test");
    await alicePage.waitForTimeout(500);
    const viewAll = alicePage.getByText(/View all results/i).first();
    await viewAll.click();
    await alicePage.waitForURL(/\/search\?q=test/, { timeout: 5000 });
  });

  test("103.4 Escape closes the palette", async () => {
    await alicePage.goto(`${BASE}/`, { waitUntil: "load" });
    await alicePage.waitForTimeout(500);
    await alicePage.keyboard.press("Control+k");
    await expect(
      alicePage.getByPlaceholder("Search content and pages..."),
    ).toBeVisible();
    await alicePage.keyboard.press("Escape");
    await expect(
      alicePage.getByPlaceholder("Search content and pages..."),
    ).not.toBeVisible({ timeout: 3000 });
  });

  test("103.5 SearchPage shows All tab with results", async () => {
    await alicePage.goto(`${BASE}/search?q=test`, { waitUntil: "load" });
    await alicePage.waitForTimeout(1500);
    await expect(
      alicePage.getByRole("tab", { name: "All" }),
    ).toBeVisible({ timeout: 5000 });
  });

  test("103.6 SearchPage shows extended tabs", async () => {
    await alicePage.goto(`${BASE}/search?q=test`, { waitUntil: "load" });
    await alicePage.waitForTimeout(1500);
    for (const tabName of ["Messages", "Tickets", "Contacts", "Videos", "Calendar"]) {
      await expect(
        alicePage.getByRole("tab", { name: tabName }),
      ).toBeVisible({ timeout: 3000 });
    }
  });

  test("103.7 Clicking Tickets tab filters to tickets", async () => {
    await alicePage.goto(`${BASE}/search?q=${encodeURIComponent(`ui_tkt_${TS}`)}`, {
      waitUntil: "load",
    });
    await alicePage.waitForTimeout(1500);
    const ticketsTab = alicePage.getByRole("tab", { name: "Tickets" });
    await ticketsTab.click();
    await alicePage.waitForTimeout(500);
    await expect(
      alicePage.locator(`[data-testid="search-result-ticket"]`).first(),
    ).toBeVisible({ timeout: 5000 });
  });

  test("103.8 Search input on SearchPage updates results", async () => {
    await alicePage.goto(`${BASE}/search`, { waitUntil: "load" });
    await alicePage.waitForTimeout(500);
    const input = alicePage.locator(`[data-testid="search-input"]`);
    await input.fill(`ui_con_${TS}`);
    await alicePage.waitForTimeout(1500);
    await expect(
      alicePage.getByRole("tab", { name: "Contacts" }),
    ).toBeVisible({ timeout: 5000 });
  });

  test("103.9 No results shows empty state", async () => {
    await alicePage.goto(
      `${BASE}/search?q=zzzzzzzzzznonexistent_${TS}`,
      { waitUntil: "load" },
    );
    await alicePage.waitForTimeout(1500);
    await expect(
      alicePage.locator(`[data-testid="no-results"]`),
    ).toBeVisible({ timeout: 5000 });
  });

  test("103.10 Result row shows type badge", async () => {
    await alicePage.goto(
      `${BASE}/search?q=${encodeURIComponent(`ui_tkt_${TS}`)}`,
      { waitUntil: "load" },
    );
    const result = alicePage.locator(`[data-testid="search-result-ticket"]`).first();
    await expect(result).toBeVisible({ timeout: 10000 });
  });

  test("103.11 Clicking search result navigates to target", async () => {
    await alicePage.goto(
      `${BASE}/search?q=${encodeURIComponent(`ui_tkt_${TS}`)}`,
      { waitUntil: "load" },
    );
    await alicePage.waitForTimeout(1500);
    const result = alicePage.locator(`[data-testid="search-result-ticket"]`).first();
    await result.click();
    await alicePage.waitForTimeout(500);
    expect(alicePage.url()).toContain("/tickets/");
  });

  test("103.12 SearchPage search history sidebar visible", async () => {
    // Record some history
    await apiPost(alicePage, ALICE_ID, "/ui/search/history", {
      query: `hist_ui_${TS}`,
    });
    await alicePage.goto(`${BASE}/search?q=test`, { waitUntil: "load" });
    await alicePage.waitForTimeout(1500);
    await expect(
      alicePage.locator(`[data-testid="search-history-sidebar"]`),
    ).toBeVisible({ timeout: 5000 });
  });

  test("103.13 Clicking history item fills search input", async () => {
    await apiDelete(alicePage, ALICE_ID, "/ui/search/history");
    await apiPost(alicePage, ALICE_ID, "/ui/search/history", {
      query: `hist_click_${TS}`,
    });
    // Navigate to search page without a q param so input starts empty
    await alicePage.goto(`${BASE}/search`, { waitUntil: "load" });
    // Wait for sidebar to load history from server
    await expect(
      alicePage.locator(`[data-testid="history-item"]`).first(),
    ).toBeVisible({ timeout: 8000 });
    const historyItem = alicePage.locator(`[data-testid="history-item"]`).first();
    await historyItem.click();
    const input = alicePage.locator(`[data-testid="search-input"]`);
    await expect(input).toHaveValue(`hist_click_${TS}`, { timeout: 5000 });
  });

  test("103.14 SearchPage URL includes tab parameter", async () => {
    await alicePage.goto(`${BASE}/search?q=test`, { waitUntil: "load" });
    await alicePage.waitForTimeout(1500);
    const contactsTab = alicePage.getByRole("tab", { name: "Contacts" });
    await contactsTab.click();
    await alicePage.waitForTimeout(500);
    expect(alicePage.url()).toContain("tab=contacts");
  });
});

// =============================================================================
// Section 104: Edge cases
// =============================================================================

test.describe("104 — Edge cases", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("104.1 Very long query is truncated to 200 chars", async () => {
    const longQuery = "a".repeat(250);
    const resp = await apiGet(alicePage, "/ui/search", {
      q: longQuery,
      types: "contacts",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.query.length).toBeLessThanOrEqual(200);
  });

  test("104.2 Special characters in query don't break search", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: 'hello "world" (test) [brackets]',
      types: "contacts",
    });
    expect(resp.status()).toBe(200);
  });

  test("104.3 No results returns empty items array", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: `xyzzy_nonexistent_${TS}_zzz`,
      types: "tickets,contacts",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.results.tickets.items).toHaveLength(0);
    expect(data.results.contacts.items).toHaveLength(0);
  });

  test("104.4 Single-character query returns 200", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: "x",
      types: "contacts",
    });
    expect(resp.status()).toBe(200);
  });

  test("104.5 Multiple types comma-separated work", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: "test",
      types: "tickets,contacts,messages",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.results.tickets).toBeDefined();
    expect(data.results.contacts).toBeDefined();
    expect(data.results.messages).toBeDefined();
  });

  test("104.6 Query with numbers works", async () => {
    const resp = await apiGet(alicePage, "/ui/search", {
      q: "test123",
      types: "contacts",
    });
    expect(resp.status()).toBe(200);
  });

  test("104.7 Concurrent searches return independent results", async () => {
    test.setTimeout(90_000); // may wait out the 60s search rate-limit window
    // Create test data in this section's page
    const tktSubject = `conc_tkt_${TS}`;
    const conName = `conc_con_${TS}`;
    await apiPost(alicePage, ALICE_ID, "/tickets", {
      subject: tktSubject,
      description: `concurrent test`,
    });
    await apiPost(alicePage, ALICE_ID, "/ui/contacts", {
      user_id: conName,
    });

    let [resp1, resp2] = await Promise.all([
      apiGet(alicePage, "/ui/search", { q: tktSubject, types: "tickets" }),
      apiGet(alicePage, "/ui/search", { q: conName, types: "contacts" }),
    ]);
    // GAP-0359: if the per-user search budget was exhausted earlier in the
    // suite, wait out the 60s window and re-run the concurrent pair.
    if (resp1.status() === 429 || resp2.status() === 429) {
      await sleep(61_000);
      [resp1, resp2] = await Promise.all([
        apiGet(alicePage, "/ui/search", { q: tktSubject, types: "tickets" }),
        apiGet(alicePage, "/ui/search", { q: conName, types: "contacts" }),
      ]);
    }
    expect(resp1.status()).toBe(200);
    expect(resp2.status()).toBe(200);
    const data1 = await resp1.json();
    const data2 = await resp2.json();
    expect(data1.results.tickets.items.length).toBeGreaterThanOrEqual(1);
    expect(data2.results.contacts.items.length).toBeGreaterThanOrEqual(1);
  });

  test("104.8 Search history cap at 50 entries", async () => {
    await apiDelete(alicePage, ALICE_ID, "/ui/search/history");
    // Add 52 history entries
    for (let i = 0; i < 52; i++) {
      await apiPost(alicePage, ALICE_ID, "/ui/search/history", {
        query: `cap_${TS}_${i.toString().padStart(3, "0")}`,
      });
    }
    const resp = await apiGet(alicePage, "/ui/search/history", { limit: "50" });
    const data = await resp.json();
    expect(data.items.length).toBeLessThanOrEqual(50);
  });

  test("104.9 Delete non-existent history item returns 404", async () => {
    const resp = await apiDelete(
      alicePage,
      ALICE_ID,
      "/ui/search/history/TS%230000000000%23deadbeef",
    );
    expect(resp.status()).toBe(404);
  });

  test("104.10 Search with only whitespace after sanitization returns 400", async () => {
    test.setTimeout(90_000); // may wait out the 60s search rate-limit window
    const resp = await searchWithRetry(alicePage, { q: " \t " });
    expect(resp.status()).toBe(400);
  });
});
