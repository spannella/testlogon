/**
 * E2E tests — Offline action queue.
 *
 * Sections:
 *   84 — Offline queue behaviour: banner, message queuing, post queuing, flush (10 tests)
 *   85 — Offline queue UI: visual indicators, form state, toast messages (7 tests)
 *
 * Strategy: use page.evaluate() to dispatch window.offline / window.online events
 * (and patch navigator.onLine) rather than page.context().setOffline(), so the real
 * network stays up and route-mocked endpoints can still respond during flush tests.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ─────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const TS = Date.now();

const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

// ─── Session bootstrap ──────────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  csrf_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
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

function getCsrf(userId = ALICE_ID): string {
  return getSessions()[userId].csrf_token;
}

// ─── Offline simulation helpers ─────────────────────────────────────────────────

/** Simulates going offline: patches navigator.onLine + fires window.offline */
async function goOffline(page: Page) {
  await page.evaluate(() => {
    Object.defineProperty(navigator, "onLine", { value: false, configurable: true, writable: true });
    window.dispatchEvent(new Event("offline"));
  });
  // Give the Zustand store a moment to update
  await page.waitForTimeout(100);
}

/** Simulates coming back online: restores navigator.onLine + fires window.online */
async function goOnline(page: Page) {
  await page.evaluate(() => {
    Object.defineProperty(navigator, "onLine", { value: true, configurable: true, writable: true });
    window.dispatchEvent(new Event("online"));
  });
  await page.waitForTimeout(100);
}

/** Reads the persisted offline-store from localStorage */
async function getOfflineQueue(page: Page): Promise<Array<{ id: string; type: string }>> {
  return page.evaluate(() => {
    try {
      const raw = localStorage.getItem("offline-store");
      if (!raw) return [];
      const parsed = JSON.parse(raw) as { state?: { queue?: Array<{ id: string; type: string }> } };
      return parsed?.state?.queue ?? [];
    } catch {
      return [];
    }
  });
}

/** Clears the offline-store from localStorage */
async function clearOfflineQueue(page: Page) {
  await page.evaluate(() => {
    localStorage.removeItem("offline-store");
  });
}

// ─── Mock helpers ───────────────────────────────────────────────────────────────

/** Mock GET /messaging/conversations to return a list with one conversation */
async function mockConversationsList(page: Page, convoId: string) {
  await page.route("**/messaging/conversations**", (route, req) => {
    // Only intercept the list call (not per-conversation endpoints)
    if (req.method() === "GET" && !req.url().includes(`/${convoId}/`)) {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([{
          conversation_id: convoId,
          type: "dm",
          participants: [
            { user_id: ALICE_ID, display_name: "Alice", status: "active" },
            { user_id: BOB_ID, display_name: "Bob", status: "active" },
          ],
          unread_count: 0,
          last_message_at: Date.now() / 1000,
          created_at: Date.now() / 1000,
        }]),
      });
    } else {
      route.continue();
    }
  });
}

/** Mock GET messages for a conversation to return empty */
async function mockMessagesList(page: Page, convoId: string) {
  await page.route(`**/${convoId}/messages**`, (route) => {
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ messages: [], next_cursor: null }),
    });
  });
}

/** Mock GET /feed (API calls only — not the SPA navigation) to return empty feed */
async function mockFeed(page: Page) {
  // Use an exact pathname match to avoid catching Vite module requests like
  // /src/pages/feed/FeedPage.tsx whose URLs also contain "feed".
  await page.route(
    (url) => url.pathname === "/feed",
    (route, req) => {
      // Browser page navigations (Accept: text/html) need index.html from Vite
      if (req.isNavigationRequest()) {
        route.continue();
        return;
      }
      if (req.method() === "GET") {
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ items: [], next_cursor: null }),
        });
      } else {
        route.continue();
      }
    },
  );
}

// ─── Conversation setup helpers ─────────────────────────────────────────────────

/** Creates a DM between Alice and Bob via session auth, returns conversation_id */
async function createDm(page: Page): Promise<string> {
  const csrf = getCsrf(ALICE_ID);
  const resp = await page.request.post(`${BASE}/messaging/conversations`, {
    data: { type: "dm", participant_ids: [BOB_ID] },
    headers: { "x-csrf-token": csrf, "content-type": "application/json" },
  });
  const body = await resp.json() as { conversation_id: string };
  return body.conversation_id;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 84 — Offline queue behaviour
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("84 — Offline queue behaviour", () => {
  let page: Page;
  let convoId: string;

  test.beforeAll(async ({ browser }) => {
    const context = await browser.newContext();
    page = await context.newPage();
    await injectAuth(page);
    // Warmup navigation to / — loads the React app + all lazy chunks so
    // subsequent navigations to /messages and /feed are fast.
    await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(1000);
    // Create a real DM to navigate into
    convoId = await createDm(page);
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  // Reset route mocks, queue, and page state before each test
  test.beforeEach(async () => {
    // Remove accumulated route handlers from previous tests
    await page.unrouteAll({ behavior: "ignoreErrors" });
    // Clear offline queue from localStorage
    await page.evaluate(() => {
      localStorage.removeItem("offline-store");
      localStorage.setItem("offline-store", JSON.stringify({ state: { queue: [] }, version: 0 }));
    });
    // Navigate to / to reinitialize Zustand store from clean localStorage
    await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(300);
    // Ensure the store reflects online state
    await goOnline(page);
  });

  // ── 84.1: OfflineBanner is NOT visible when online ──────────────────────────

  test("84.1 — OfflineBanner hidden when online", async () => {
    await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
    const banner = page.locator("div").filter({ hasText: /you're offline/i }).first();
    await expect(banner).not.toBeVisible();
  });

  // ── 84.2: OfflineBanner appears when offline ────────────────────────────────

  test("84.2 — OfflineBanner appears when offline", async () => {
    await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
    await goOffline(page);
    await expect(page.getByText(/you're offline/i)).toBeVisible();
  });

  // ── 84.3: OfflineBanner disappears when back online ─────────────────────────

  test("84.3 — OfflineBanner hides when back online", async () => {
    await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
    await goOffline(page);
    await expect(page.getByText(/you're offline/i)).toBeVisible();
    await goOnline(page);
    await expect(page.getByText(/you're offline/i)).not.toBeVisible();
  });

  // ── 84.4: Sending a message offline queues it ───────────────────────────────

  test("84.4 — Message queued when offline", async () => {
    test.setTimeout(20_000);
    await mockMessagesList(page, convoId);
    await mockConversationsList(page, convoId);

    // Navigate to messages and open the conversation
    await page.goto(`${BASE}/messages`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(800);
    await page.locator("button").filter({ hasText: "Bob" }).first().click();
    // Wait for ConversationView + ComposeBar to render
    await page.waitForSelector('[placeholder="Type a message..."]', { timeout: 10_000 });

    await goOffline(page);

    // Type a message and send
    const msg = `offline-msg-${TS}`;
    await page.getByPlaceholder("Type a message...").fill(msg);
    await page.getByRole("button", { name: "Send message" }).click();

    // Should show banner badge confirming the item is queued
    await expect(page.locator("span").filter({ hasText: "1 queued" })).toBeVisible({ timeout: 5_000 });

    // Verify queue has one item
    const queue = await getOfflineQueue(page);
    expect(queue).toHaveLength(1);
    expect(queue[0]!.type).toBe("send_message");
  });

  // ── 84.5: Queue persists across navigation ──────────────────────────────────

  test("84.5 — Queue survives page navigation", async () => {
    test.setTimeout(20_000);
    await mockMessagesList(page, convoId);
    await mockConversationsList(page, convoId);

    await page.goto(`${BASE}/messages`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(800);
    await page.locator("button").filter({ hasText: "Bob" }).first().click();
    // Wait for ConversationView + ComposeBar to render
    await page.waitForSelector('[placeholder="Type a message..."]', { timeout: 10_000 });

    await goOffline(page);

    await page.getByPlaceholder("Type a message...").fill(`persist-test-${TS}`);
    await page.getByRole("button", { name: "Send message" }).click();
    await expect(page.locator("span").filter({ hasText: "1 queued" })).toBeVisible({ timeout: 5_000 });

    // Navigate away
    await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });

    const queue = await getOfflineQueue(page);
    expect(queue).toHaveLength(1);
    expect(queue[0]!.type).toBe("send_message");
  });

  // ── 84.6: Message queued offline is flushed on reconnect ────────────────────

  test("84.6 — Queued message sent when back online", async () => {
    test.setTimeout(25_000);
    await mockMessagesList(page, convoId);
    await mockConversationsList(page, convoId);

    await page.goto(`${BASE}/messages`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(800);
    await page.locator("button").filter({ hasText: "Bob" }).first().click();
    // Wait for ConversationView + ComposeBar to render
    await page.waitForSelector('[placeholder="Type a message..."]', { timeout: 10_000 });

    await goOffline(page);

    const msg = `flush-test-${TS}`;
    await page.getByPlaceholder("Type a message...").fill(msg);
    await page.getByRole("button", { name: "Send message" }).click();
    await expect(page.locator("span").filter({ hasText: "1 queued" })).toBeVisible({ timeout: 5_000 });

    // Set up listener for the send request before going online
    const sendReq = page.waitForRequest(
      (r) => r.method() === "POST" && r.url().includes("/messages"),
      { timeout: 10_000 },
    );

    await goOnline(page);

    // The flush hook fires; should call the real send endpoint
    const req = await sendReq;
    expect(req.postDataJSON()).toMatchObject({ text: msg });

    // Queue should now be empty — poll localStorage until flush persists
    await page.waitForFunction(
      () => {
        const raw = localStorage.getItem("offline-store");
        if (!raw) return true;
        const q = JSON.parse(raw)?.state?.queue ?? [];
        return q.length === 0;
      },
      { timeout: 8_000 },
    );
    const queue = await getOfflineQueue(page);
    expect(queue).toHaveLength(0);
  });

  // ── 84.7: Compose input clears after offline queue ──────────────────────────

  test("84.7 — Compose bar clears after offline queue", async () => {
    test.setTimeout(20_000);
    await mockMessagesList(page, convoId);
    await mockConversationsList(page, convoId);

    await page.goto(`${BASE}/messages`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(800);
    await page.locator("button").filter({ hasText: "Bob" }).first().click();
    // Wait for ConversationView + ComposeBar to render
    await page.waitForSelector('[placeholder="Type a message..."]', { timeout: 10_000 });

    await goOffline(page);

    const input = page.getByPlaceholder("Type a message...");
    await input.fill(`clear-test-${TS}`);
    await page.getByRole("button", { name: "Send message" }).click();
    await expect(page.locator("span").filter({ hasText: "1 queued" })).toBeVisible({ timeout: 5_000 });

    // The compose bar should be empty after queuing
    await expect(input).toHaveValue("");
  });

  // ── 84.8: Post queued when offline ──────────────────────────────────────────

  test("84.8 — Post queued when offline", async () => {
    test.setTimeout(30_000);
    await mockFeed(page);

    await page.goto(`${BASE}/feed`, { waitUntil: "domcontentloaded" });
    // Wait for CreatePost to render (requires feed query to resolve)
    await page.waitForSelector('[placeholder="What\'s on your mind?"]', { timeout: 15_000 });

    await goOffline(page);

    const postText = `offline-post-${TS}`;
    await page.getByPlaceholder("What's on your mind?").fill(postText);
    await page.getByRole("button", { name: /^post$/i }).click();

    await expect(page.locator("span").filter({ hasText: "1 queued" })).toBeVisible({ timeout: 5_000 });

    const queue = await getOfflineQueue(page);
    expect(queue).toHaveLength(1);
    expect(queue[0]!.type).toBe("create_post");
  });

  // ── 84.9: Post form resets after offline queue ───────────────────────────────

  test("84.9 — Post form resets after offline queue", async () => {
    test.setTimeout(30_000);
    await mockFeed(page);

    await page.goto(`${BASE}/feed`, { waitUntil: "domcontentloaded" });
    await page.waitForSelector('[placeholder="What\'s on your mind?"]', { timeout: 15_000 });

    await goOffline(page);

    const textarea = page.getByPlaceholder("What's on your mind?");
    await textarea.fill(`form-reset-post-${TS}`);
    await page.getByRole("button", { name: /^post$/i }).click();
    await expect(page.locator("span").filter({ hasText: "1 queued" })).toBeVisible({ timeout: 5_000 });

    // Textarea should be cleared
    await expect(textarea).toHaveValue("");
  });

  // ── 84.10: Queued post flushed on reconnect ──────────────────────────────────

  test("84.10 — Queued post sent when back online", async () => {
    test.setTimeout(35_000);
    await mockFeed(page);

    await page.goto(`${BASE}/feed`, { waitUntil: "domcontentloaded" });
    await page.waitForSelector('[placeholder="What\'s on your mind?"]', { timeout: 15_000 });

    await goOffline(page);

    const postText = `flush-post-${TS}`;
    await page.getByPlaceholder("What's on your mind?").fill(postText);
    await page.getByRole("button", { name: /^post$/i }).click();
    await expect(page.locator("span").filter({ hasText: "1 queued" })).toBeVisible({ timeout: 5_000 });

    // Intercept the flush POST before going online
    const postReq = page.waitForRequest(
      (r) => r.method() === "POST" && r.url().includes("/posts"),
      { timeout: 10_000 },
    );

    await goOnline(page);

    const req = await postReq;
    const body = req.postDataJSON() as { body?: string; body_plain?: string };
    const sentText = body.body_plain ?? body.body ?? "";
    expect(sentText).toContain(postText);

    // Poll localStorage until flush persists
    await page.waitForFunction(
      () => {
        const raw = localStorage.getItem("offline-store");
        if (!raw) return true;
        const q = JSON.parse(raw)?.state?.queue ?? [];
        return q.length === 0;
      },
      { timeout: 8_000 },
    );
    const queue = await getOfflineQueue(page);
    expect(queue).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 85 — Offline queue UI
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("85 — Offline queue UI", () => {
  let page: Page;
  let convoId: string;

  test.beforeAll(async ({ browser }) => {
    const context = await browser.newContext();
    page = await context.newPage();
    await injectAuth(page);
    // Warmup: load the React app at / so lazy chunks are cached
    await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(1000);
    convoId = await createDm(page);
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  // Reset route mocks, queue, and page state before each test
  test.beforeEach(async () => {
    await page.unrouteAll({ behavior: "ignoreErrors" });
    await page.evaluate(() => {
      localStorage.removeItem("offline-store");
      localStorage.setItem("offline-store", JSON.stringify({ state: { queue: [] }, version: 0 }));
    });
    await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(300);
    await goOnline(page);
  });

  // ── 85.1: Banner text includes "offline" and "reconnected" ──────────────────

  test("85.1 — OfflineBanner has correct text", async () => {
    await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
    await goOffline(page);
    const banner = page.getByText(/you're offline/i);
    await expect(banner).toBeVisible();
    await expect(banner).toContainText(/reconnected/i);
  });

  // ── 85.2: Banner shows queue count badge ────────────────────────────────────

  test("85.2 — OfflineBanner shows queue count after items queued", async () => {
    test.setTimeout(25_000);
    await mockMessagesList(page, convoId);
    await mockConversationsList(page, convoId);

    // Navigate to messages and open conversation
    await page.goto(`${BASE}/messages`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(800);
    await page.locator("button").filter({ hasText: "Bob" }).first().click();
    await page.waitForSelector('[placeholder="Type a message..."]', { timeout: 10_000 });

    await goOffline(page);

    // Queue first message
    await page.getByPlaceholder("Type a message...").fill(`badge-test-msg1-${TS}`);
    await page.getByRole("button", { name: "Send message" }).click();
    await expect(page.locator("span").filter({ hasText: "1 queued" })).toBeVisible({ timeout: 5_000 });

    // Queue second message (no page navigation — navigator.onLine stays patched to false)
    await page.getByPlaceholder("Type a message...").fill(`badge-test-msg2-${TS}`);
    await page.getByRole("button", { name: "Send message" }).click();

    // Banner should now show "2 queued"
    await expect(page.locator("span").filter({ hasText: "2 queued" })).toBeVisible({ timeout: 5_000 });
  });

  // ── 85.3: Success toast after flush ─────────────────────────────────────────

  test("85.3 — Success toast shown after queue flush", async () => {
    test.setTimeout(35_000);
    await mockFeed(page);

    await page.goto(`${BASE}/feed`, { waitUntil: "domcontentloaded" });
    await page.waitForSelector('[placeholder="What\'s on your mind?"]', { timeout: 15_000 });

    await goOffline(page);

    await page.getByPlaceholder("What's on your mind?").fill(`flush-toast-${TS}`);
    await page.getByRole("button", { name: /^post$/i }).click();
    await expect(page.locator("span").filter({ hasText: "1 queued" })).toBeVisible({ timeout: 5_000 });

    await goOnline(page);

    // Should see success or "sent" toast after flush
    await expect(page.getByText(/sent successfully/i)).toBeVisible({ timeout: 10_000 });
  });

  // ── 85.4: "Queued" toast text in ConversationView ───────────────────────────

  test("85.4 — Offline message shows 'queued' toast text", async () => {
    test.setTimeout(20_000);
    await mockMessagesList(page, convoId);
    await mockConversationsList(page, convoId);

    await page.goto(`${BASE}/messages`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(800);
    await page.locator("button").filter({ hasText: "Bob" }).first().click();
    // Wait for ConversationView + ComposeBar to render
    await page.waitForSelector('[placeholder="Type a message..."]', { timeout: 10_000 });

    await goOffline(page);

    await page.getByPlaceholder("Type a message...").fill(`toast-test-${TS}`);
    await page.getByRole("button", { name: "Send message" }).click();

    await expect(page.getByText(/message queued and will send/i)).toBeVisible({ timeout: 5_000 });
  });

  // ── 85.5: Offline banner disappears after full flush ────────────────────────

  test("85.5 — Queue count badge disappears after flush", async () => {
    test.setTimeout(35_000);
    await mockFeed(page);

    await page.goto(`${BASE}/feed`, { waitUntil: "domcontentloaded" });
    await page.waitForSelector('[placeholder="What\'s on your mind?"]', { timeout: 15_000 });

    await goOffline(page);

    await page.getByPlaceholder("What's on your mind?").fill(`badge-gone-${TS}`);
    await page.getByRole("button", { name: /^post$/i }).click();
    await expect(page.locator("span").filter({ hasText: "1 queued" })).toBeVisible({ timeout: 5_000 });

    await goOnline(page);

    // After flush the banner hides (we're online now and queue is empty)
    await expect(page.locator("span").filter({ hasText: /\d+ queued/ })).not.toBeVisible({ timeout: 8_000 });
  });

  // ── 85.6: Offline "Post" button still responds (not disabled) ───────────────

  test("85.6 — Post button not disabled when offline", async () => {
    test.setTimeout(30_000);
    await mockFeed(page);

    await page.goto(`${BASE}/feed`, { waitUntil: "domcontentloaded" });
    await page.waitForSelector('[placeholder="What\'s on your mind?"]', { timeout: 15_000 });

    await goOffline(page);

    await page.getByPlaceholder("What's on your mind?").fill(`button-enabled-${TS}`);
    const postBtn = page.getByRole("button", { name: /^post$/i });
    await expect(postBtn).not.toBeDisabled();
  });

  // ── 85.7: Queue count from localStorage matches badge ───────────────────────

  test("85.7 — localStorage queue count matches banner badge", async () => {
    test.setTimeout(30_000);
    await mockFeed(page);

    await page.goto(`${BASE}/feed`, { waitUntil: "domcontentloaded" });
    await page.waitForSelector('[placeholder="What\'s on your mind?"]', { timeout: 15_000 });

    await goOffline(page);

    await page.getByPlaceholder("What's on your mind?").fill(`ls-count-${TS}`);
    await page.getByRole("button", { name: /^post$/i }).click();
    await expect(page.locator("span").filter({ hasText: "1 queued" })).toBeVisible({ timeout: 5_000 });

    const queue = await getOfflineQueue(page);
    expect(queue).toHaveLength(1);

    // Banner badge should read "1 queued"
    await expect(page.locator("span").filter({ hasText: "1 queued" })).toBeVisible({ timeout: 3_000 });
  });
});
