/**
 * E2E tests simulating a normal user's day-to-day interactions with the app.
 *
 * These tests cover the real user journey end-to-end: landing on the dashboard,
 * reading and updating the profile, checking the notification inbox, navigating
 * the sidebar, composing a message, browsing the social feed, and adjusting
 * appearance settings.  All tests run as Alice (the primary test user).
 *
 * Sections:
 *   85 — Dashboard page renders and links to sub-pages
 *   86 — Profile: API (read/update/audit) + UI (tabs, form, save)
 *   87 — Alerts inbox: API (list/types/mark-read) + UI (tab switching)
 *   88 — Settings: Appearance theme selector
 *   89 — Sidebar navigation: move between major sections of the app
 *   90 — Compose and send a DM to Bob via the UI
 *   91 — Newsfeed: create a plain-text post and interact with it
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
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

/** Inject real DDB session cookies + localStorage auth for userId. */
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

/**
 * Navigate to a protected page. Waits for the conversations sidebar query to
 * settle (or ignores if already cached) so the AppShell is ready.
 */
async function gotoPage(page: Page, path: string) {
  const convsSettled = page.waitForResponse(
    (r) =>
      r.url().includes("/messaging/conversations") &&
      r.request().method() === "GET" &&
      !r.url().match(/\/conversations\/[^/]+$/),
    { timeout: 20_000 },
  );
  await page.goto(`${BASE}${path}`, { waitUntil: "load" });
  await convsSettled.catch(() => {}); // ignore if already cached
}

/** POST authenticated as Alice via browser-context cookies + CSRF. */
async function apiPost(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

/** PATCH authenticated as Alice via browser-context cookies + CSRF. */
async function apiPatch(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.patch(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

/** GET authenticated as Alice via browser-context cookies (no CSRF needed for GET). */
async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

// ─── 85. Dashboard ─────────────────────────────────────────────────────────────

test.describe("85. Dashboard", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    await gotoPage(page, "/");
  });

  test.afterAll(async () => {
    await page?.close();
  });

  test("85.1 Dashboard page has the 'Dashboard' heading", async () => {
    await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible({
      timeout: 8_000,
    });
  });

  test("85.2 Messages card is visible", async () => {
    await expect(page.getByText("Messages").first()).toBeVisible({ timeout: 5_000 });
  });

  test("85.3 Files card is visible", async () => {
    await expect(page.getByText("Files").first()).toBeVisible({ timeout: 5_000 });
  });

  test("85.4 Alerts card is visible", async () => {
    await expect(page.getByText("Alerts").first()).toBeVisible({ timeout: 5_000 });
  });

  test("85.5 Clicking the Messages card/link navigates to /messages", async () => {
    await page.getByRole("link", { name: /messages/i }).first().click();
    await expect(page).toHaveURL(/\/messages/, { timeout: 5_000 });
    // Compose bar or conversation list confirms the page rendered.
    await expect(
      page
        .getByPlaceholder("Type a message...")
        .or(page.getByPlaceholder("Search conversations...")),
    ).toBeVisible({ timeout: 8_000 });
  });
});

// ─── 86. Profile ───────────────────────────────────────────────────────────────

test.describe("86. Profile", () => {
  const TS      = Date.now();
  const NEW_BIO = `E2E test bio — updated at ${TS}`;

  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    // Pre-update the bio via API so the UI can verify it.
    const session = getSessions()[ALICE_ID];
    await page.request.patch(`${API}/ui/profile`, {
      data: { description: NEW_BIO },
      headers: { "x-csrf-token": session.csrf_token },
    });
    await gotoPage(page, "/profile");
  });

  test.afterAll(async () => {
    await page?.close();
  });

  // ── API ──────────────────────────────────────────────────────────────────────

  test("86.1 API: GET /ui/profile returns a profile object with at least one field", async () => {
    const resp = await apiGet(page, "/ui/profile");
    expect(resp.status()).toBe(200);
    // Response shape: { profile: { ... } }
    const body = await resp.json() as { profile: Record<string, unknown> };
    expect(typeof body.profile).toBe("object");
    expect(body.profile).not.toBeNull();
  });

  test("86.2 API: PATCH /ui/profile updates the description field", async () => {
    const resp = await apiPatch(page, "/ui/profile", { description: NEW_BIO });
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { profile: { description?: string } };
    expect(body.profile.description).toBe(NEW_BIO);
  });

  test("86.3 API: GET /ui/profile reflects the patched description", async () => {
    const resp = await apiGet(page, "/ui/profile");
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { profile: { description?: string } };
    expect(body.profile.description).toBe(NEW_BIO);
  });

  test("86.4 API: GET /ui/profile/audit returns a non-empty audit array", async () => {
    const resp = await apiGet(page, "/ui/profile/audit");
    expect(resp.status()).toBe(200);
    // Response shape: { audit: [...] }
    const body = await resp.json() as { audit: unknown[] };
    expect(Array.isArray(body.audit)).toBe(true);
    expect(body.audit.length).toBeGreaterThan(0);
  });

  // ── UI ───────────────────────────────────────────────────────────────────────

  test("86.5 UI: Profile page renders the 'Profile' heading", async () => {
    await expect(
      page.getByRole("heading", { name: "Profile", exact: true }),
    ).toBeVisible({ timeout: 8_000 });
  });

  test("86.6 UI: Profile page has three tabs — Profile, Addresses, Activity", async () => {
    await expect(page.getByRole("tab", { name: "Profile" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Addresses" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Activity" })).toBeVisible();
  });

  test("86.7 UI: Profile tab shows a form with a bio/description textarea", async () => {
    // The Profile tab is the default.
    const bio = page.getByLabel(/bio|description/i).first();
    await expect(bio).toBeVisible({ timeout: 8_000 });
    // The textarea is non-empty (populated from the API via React Query).
    await expect(bio).not.toHaveValue("", { timeout: 8_000 });
  });

  test("86.8 UI: Description textarea contains the bio we saved via API", async () => {
    // The PATCH was done in beforeAll before page navigation, so the form
    // hydrates with the latest value on initial load.
    const bio = page.getByLabel(/bio|description/i).first();
    await expect(bio).toHaveValue(NEW_BIO, { timeout: 8_000 });
  });

  test("86.9 UI: Activity tab shows the profile audit log", async () => {
    await page.getByRole("tab", { name: "Activity" }).click();
    // The audit log component renders — look for any audit-related text.
    await expect(
      page.getByText(/activity|audit|change|updated/i).first(),
    ).toBeVisible({ timeout: 5_000 });
  });

  test("86.10 UI: Addresses tab renders without error", async () => {
    await page.getByRole("tab", { name: "Addresses" }).click();
    // Either an address list or an "Add address" call-to-action renders.
    await expect(
      page.getByText(/address/i).first(),
    ).toBeVisible({ timeout: 5_000 });
  });
});

// ─── 87. Alerts inbox ──────────────────────────────────────────────────────────

test.describe("87. Alerts inbox", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    await gotoPage(page, "/alerts");
  });

  test.afterAll(async () => {
    await page?.close();
  });

  // ── API ──────────────────────────────────────────────────────────────────────

  test("87.1 API: GET /ui/alerts returns an alerts array", async () => {
    const resp = await apiGet(page, "/ui/alerts?limit=10");
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { alerts: unknown[] };
    expect(Array.isArray(body.alerts)).toBe(true);
  });

  test("87.2 API: GET /ui/alerts/types returns a non-empty list of event type strings", async () => {
    const resp = await apiGet(page, "/ui/alerts/types");
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { types: string[] };
    expect(Array.isArray(body.types)).toBe(true);
    expect(body.types.length).toBeGreaterThan(0);
    expect(typeof body.types[0]).toBe("string");
  });

  test("87.3 API: POST /ui/alerts/mark_read with empty list → 200", async () => {
    const resp = await apiPost(page, "/ui/alerts/mark_read", { alert_ids: [] });
    expect(resp.status()).toBe(200);
  });

  // ── UI ───────────────────────────────────────────────────────────────────────

  test("87.4 UI: Alerts page renders the 'Alerts' heading", async () => {
    await expect(
      page.getByRole("heading", { name: "Alerts", exact: true }),
    ).toBeVisible({ timeout: 8_000 });
  });

  test("87.5 UI: Alerts page has Notifications, Preferences, and Push Devices tabs", async () => {
    await expect(page.getByRole("tab", { name: "Notifications" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Preferences" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Push Devices" })).toBeVisible();
  });

  test("87.6 UI: Notifications tab shows the alert search input", async () => {
    // The Notifications tab (default) renders an AlertCenter with a search bar.
    await expect(
      page.getByRole("textbox", { name: /search alerts/i }),
    ).toBeVisible({ timeout: 8_000 });
  });

  test("87.7 UI: Preferences tab renders email and SMS sections", async () => {
    await page.getByRole("tab", { name: "Preferences" }).click();
    await expect(
      page.getByText(/email|sms|notification preference/i).first(),
    ).toBeVisible({ timeout: 5_000 });
  });

  test("87.8 UI: Clicking back to Notifications tab shows the search input", async () => {
    await page.getByRole("tab", { name: "Notifications" }).click();
    await expect(
      page.getByRole("textbox", { name: /search alerts/i }),
    ).toBeVisible({ timeout: 5_000 });
  });
});

// ─── 88. Settings — Appearance ─────────────────────────────────────────────────

test.describe("88. Settings — Appearance", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    await gotoPage(page, "/settings");
  });

  test.afterAll(async () => {
    await page?.close();
  });

  test("88.1 UI: Settings page renders the 'Settings' heading", async () => {
    await expect(
      page.getByRole("heading", { name: "Settings", exact: true }),
    ).toBeVisible({ timeout: 8_000 });
  });

  test("88.2 UI: Appearance section shows System, Light, and Dark theme buttons", async () => {
    // The theme buttons have aria-pressed and are inside the appearance card.
    // Use aria-pressed attribute to uniquely identify them among all buttons.
    await expect(
      page.locator("button[aria-pressed]", { hasText: /system/i }),
    ).toBeVisible({ timeout: 5_000 });
    await expect(page.locator("button[aria-pressed]", { hasText: /light/i })).toBeVisible();
    await expect(page.locator("button[aria-pressed]", { hasText: /dark/i })).toBeVisible();
  });

  test("88.3 UI: Selecting 'Dark' theme marks the button as pressed", async () => {
    const darkBtn = page.locator("button[aria-pressed]", { hasText: /dark/i });
    await darkBtn.click();
    await expect(darkBtn).toHaveAttribute("aria-pressed", "true", { timeout: 3_000 });
  });

  test("88.4 UI: Selecting 'Light' theme un-presses Dark and presses Light", async () => {
    const lightBtn = page.locator("button[aria-pressed]", { hasText: /light/i });
    const darkBtn  = page.locator("button[aria-pressed]", { hasText: /dark/i });
    await lightBtn.click();
    await expect(lightBtn).toHaveAttribute("aria-pressed", "true", { timeout: 3_000 });
    await expect(darkBtn).toHaveAttribute("aria-pressed", "false");
  });

  test("88.5 UI: Returning to 'System' theme works", async () => {
    const systemBtn = page.locator("button[aria-pressed]", { hasText: /system/i });
    await systemBtn.click();
    await expect(systemBtn).toHaveAttribute("aria-pressed", "true", { timeout: 3_000 });
  });
});

// ─── 89. Sidebar navigation ────────────────────────────────────────────────────

test.describe("89. Sidebar navigation", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    // Start on dashboard so the sidebar is fully mounted.
    await gotoPage(page, "/");
  });

  test.afterAll(async () => {
    await page?.close();
  });

  test("89.1 Sidebar Messages link navigates to /messages", async () => {
    await page.getByRole("link", { name: /messages/i }).first().click();
    await expect(page).toHaveURL(/\/messages/, { timeout: 5_000 });
  });

  test("89.2 Sidebar Feed link navigates to /feed", async () => {
    await page.getByRole("link", { name: /feed/i }).first().click();
    await expect(page).toHaveURL(/\/feed/, { timeout: 5_000 });
    await expect(page.getByRole("heading", { name: /feed/i })).toBeVisible({ timeout: 8_000 });
  });

  test("89.3 Sidebar Shop link navigates to /shop", async () => {
    await page.getByRole("link", { name: /shop/i }).first().click();
    await expect(page).toHaveURL(/\/shop/, { timeout: 5_000 });
    await expect(page.getByRole("heading", { name: /shop/i })).toBeVisible({ timeout: 8_000 });
  });

  test("89.4 Sidebar Contacts link navigates to /contacts", async () => {
    await page.getByRole("link", { name: /contacts/i }).first().click();
    await expect(page).toHaveURL(/\/contacts/, { timeout: 5_000 });
    await expect(page.getByRole("heading", { name: "Contacts", exact: true })).toBeVisible({ timeout: 8_000 });
  });

  test("89.5 Sidebar Files link navigates to /files", async () => {
    await page.getByRole("link", { name: /files/i }).first().click();
    await expect(page).toHaveURL(/\/files/, { timeout: 5_000 });
    await expect(page.getByRole("heading", { name: /files/i })).toBeVisible({ timeout: 8_000 });
  });

  test("89.6 Sidebar Billing link navigates to /billing", async () => {
    await page.getByRole("link", { name: /billing/i }).first().click();
    await expect(page).toHaveURL(/\/billing/, { timeout: 5_000 });
    await expect(page.getByRole("heading", { name: /billing/i })).toBeVisible({ timeout: 8_000 });
  });

  test("89.7 Sidebar Profile link navigates to /profile", async () => {
    await page.getByRole("link", { name: /profile/i }).first().click();
    await expect(page).toHaveURL(/\/profile/, { timeout: 5_000 });
    await expect(page.getByRole("heading", { name: /profile/i })).toBeVisible({ timeout: 8_000 });
  });

  test("89.8 Sidebar Alerts link navigates to /alerts", async () => {
    await page.getByRole("link", { name: /alerts/i }).first().click();
    await expect(page).toHaveURL(/\/alerts/, { timeout: 5_000 });
    await expect(page.getByRole("heading", { name: /alerts/i })).toBeVisible({ timeout: 8_000 });
  });
});

// ─── 90. Compose and send a DM ─────────────────────────────────────────────────

test.describe("90. Compose and send a DM", () => {
  const TS  = Date.now();
  const MSG = `Hello Bob, this is an E2E journey test — ${TS}`;

  let alicePage: Page;
  let dmConvoId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Create (or reuse) the Alice→Bob DM via session auth so it appears in
    // Alice's conversations sidebar.
    const session = getSessions()[ALICE_ID];
    const cr = await alicePage.request.post(`${API}/messaging/conversations`, {
      data: { type: "dm", participant_ids: [BOB_ID] },
      headers: { "x-csrf-token": session.csrf_token },
    });
    dmConvoId = ((await cr.json()) as { conversation_id: string }).conversation_id;

    // "Touch" the DM so it becomes the most-recent conversation (top of sidebar).
    await alicePage.request.post(
      `${API}/messaging/conversations/${dmConvoId}/messages`,
      { data: { text: `__touch__${TS}` }, headers: { "x-csrf-token": session.csrf_token } },
    );

    // Navigate to /messages and wait for the conversations list to load.
    const convsLoaded = alicePage.waitForResponse(
      (r) =>
        r.url().includes("/messaging/conversations") &&
        r.request().method() === "GET" &&
        !r.url().match(/\/conversations\/[^/]+$/),
      { timeout: 20_000 },
    );
    await alicePage.goto(`${BASE}/messages`, { waitUntil: "load" });
    await convsLoaded;
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("90.1 Alice sees the Bob DM in the sidebar", async () => {
    await expect(
      alicePage.getByRole("button").filter({ hasText: "E2E Bob" }).first(),
    ).toBeVisible({ timeout: 15_000 });
  });

  test("90.2 Alice opens the DM with Bob", async () => {
    const msgsLoaded = alicePage.waitForResponse(
      (r) =>
        r.url().includes(`/conversations/${dmConvoId}/messages`) &&
        r.request().method() === "GET",
      { timeout: 15_000 },
    );
    await alicePage.getByRole("button").filter({ hasText: "E2E Bob" }).first().click();
    await expect(
      alicePage
        .getByPlaceholder("Type a message...")
        .or(alicePage.getByPlaceholder("Type an encrypted message...")),
    ).toBeVisible({ timeout: 8_000 });
    await msgsLoaded;
  });

  test("90.3 Alice types and sends a message", async () => {
    const composer = alicePage
      .getByPlaceholder("Type a message...")
      .or(alicePage.getByPlaceholder("Type an encrypted message..."));
    await composer.fill(MSG);
    await expect(composer).toHaveValue(MSG);

    const postDone = alicePage.waitForResponse(
      (r) =>
        r.url().includes(`/conversations/${dmConvoId}/messages`) &&
        r.request().method() === "POST",
      { timeout: 10_000 },
    );
    await alicePage.getByRole("button", { name: /send message/i }).click();
    const postResp = await postDone;
    expect(postResp.status()).toBe(200);
  });

  test("90.4 The sent message appears in the conversation", async () => {
    await expect(
      alicePage.locator("p").filter({ hasText: MSG }),
    ).toBeVisible({ timeout: 8_000 });
  });

  test("90.5 Compose bar is cleared after sending", async () => {
    const composer = alicePage
      .getByPlaceholder("Type a message...")
      .or(alicePage.getByPlaceholder("Type an encrypted message..."));
    await expect(composer).toHaveValue("", { timeout: 3_000 });
  });
});

// ─── 91. Newsfeed — create post and interact ───────────────────────────────────
//
// NOTE: /feed at port 3000 is proxied by Vite to the backend API, so direct
// navigation returns JSON. All UI navigation uses client-side routing: navigate
// to / then click the sidebar Feed link.

test.describe("91. Newsfeed — create post and interact", () => {
  const TS        = Date.now();
  const POST_TEXT = `E2E journey post — ${TS}`;

  let page:    Page;
  let postId:  string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);

    // Create the test post via API in beforeAll so all tests (including retries)
    // have a valid postId, regardless of which specific test triggered the retry.
    const session = getSessions()[ALICE_ID];
    const resp = await page.request.post(`${API}/posts`, {
      data: { body: POST_TEXT, body_format: "plain" },
      headers: { "x-csrf-token": session.csrf_token },
    });
    const data = await resp.json() as { post_id: string };
    postId = data.post_id;

    // Navigate to the feed via client-side routing.
    await page.goto(`${BASE}/`, { waitUntil: "load" });
    await page.getByRole("link", { name: /feed/i }).first().click();
    await expect(page).toHaveURL(/\/feed/, { timeout: 5_000 });
  });

  test.afterAll(async () => {
    if (postId) {
      const session = getSessions()[ALICE_ID];
      await page.request
        .delete(`${API}/posts/${postId}`, {
          headers: { "x-csrf-token": session.csrf_token },
        })
        .catch(() => {});
    }
    await page?.close();
  });

  // ── API ──────────────────────────────────────────────────────────────────────

  test("91.1 API: POST /posts creates a plain-text post and returns post_id", async () => {
    // The post was already created in beforeAll; verify the postId is set.
    expect(postId).toBeTruthy();
    expect(typeof postId).toBe("string");
  });

  test("91.2 API: GET /feed returns items array containing the new post", async () => {
    const resp = await apiGet(page, "/feed");
    expect(resp.status()).toBe(200);
    // Response shape: { items: [...], next_cursor?: string }
    const body = await resp.json() as { items: Array<{ post_id: string; body: string }> };
    expect(Array.isArray(body.items)).toBe(true);
    const found = body.items.find((p) => p.post_id === postId);
    expect(found).toBeTruthy();
    expect(found!.body).toBe(POST_TEXT);
  });

  test("91.3 API: GET /posts/:id returns the post directly", async () => {
    const resp = await apiGet(page, `/posts/${postId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { post_id: string; body: string };
    expect(body.post_id).toBe(postId);
    expect(body.body).toBe(POST_TEXT);
  });

  test("91.4 API: POST /posts/:id/like → 200 ok", async () => {
    const resp = await apiPost(page, `/posts/${postId}/like`, {});
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { ok: boolean };
    expect(body.ok).toBe(true);
  });

  test("91.5 API: POST /posts/:id/unlike → 200", async () => {
    const resp = await apiPost(page, `/posts/${postId}/unlike`, {});
    expect(resp.status()).toBe(200);
  });

  test("91.6 API: POST /posts/:id/comments creates a comment", async () => {
    const resp = await apiPost(page, `/posts/${postId}/comments`, {
      body: `E2E comment on ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { comment_id: string; body: string };
    expect(body.comment_id).toBeTruthy();
    expect(body.body).toBe(`E2E comment on ${TS}`);
  });

  test("91.7 API: GET /posts/:id/comments returns the comment", async () => {
    const resp = await apiGet(page, `/posts/${postId}/comments`);
    expect(resp.status()).toBe(200);
    // Shape: { items: [...] } or { comments: [...] }
    const body = await resp.json() as { items?: Array<{ body: string }>; comments?: Array<{ body: string }> };
    const comments = body.items ?? body.comments ?? [];
    expect(Array.isArray(comments)).toBe(true);
    const found = comments.find((c) => c.body.includes(`${TS}`));
    expect(found).toBeTruthy();
  });

  // ── UI ───────────────────────────────────────────────────────────────────────

  test("91.8 UI: Feed page shows a compose area for creating posts", async () => {
    // The CreatePost component renders a textarea or "What's on your mind?" prompt.
    await expect(
      page.getByPlaceholder(/what.*mind|write.*post|share/i)
        .or(page.getByRole("button", { name: /create post|new post/i }).first()),
    ).toBeVisible({ timeout: 8_000 });
  });

  test("91.9 UI: The API-created post appears in the feed", async () => {
    // The feed was loaded in beforeAll (post was created before navigation).
    // If it isn't visible yet, trigger a refetch via the online event.
    const isVisible = await page.getByText(POST_TEXT, { exact: false }).isVisible().catch(() => false);
    if (!isVisible) {
      await page.evaluate(() => window.dispatchEvent(new Event("online")));
      await page.waitForTimeout(1_000);
    }
    await expect(page.getByText(POST_TEXT, { exact: false })).toBeVisible({ timeout: 10_000 });
  });

  test("91.10 UI: The feed page heading is visible", async () => {
    await expect(page.getByRole("heading", { name: /feed/i })).toBeVisible({ timeout: 5_000 });
  });
});
