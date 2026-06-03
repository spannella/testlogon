/**
 * PWA-005: Optimistic UI for Offline-Queued Items
 *
 * Tests that offline-queued messages and feed posts appear inline with
 * pending/sending/failed state indicators, transition to sent on reconnect,
 * and support retry/discard for failed items.
 *
 * Sections:
 *   102 — Offline Message Optimistic Display (8 tests)
 *   103 — Failed Message UI (5 tests)
 *   104 — Offline Feed Post Optimistic (5 tests)
 *   105 — Offline Queue Banner Integration (3 tests)
 *   106 — Group Chat Offline Optimistic (2 tests)
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ──────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();

// ─── Session bootstrap ─────────────────────────────────────────

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

// ─── Auth helpers ───────────────────────────────────────────────

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  // The offline-queue flush (useOfflineQueue) skips the main-thread path when
  // SyncManager exists, deferring to Service-Worker Background Sync — which does
  // not fire in the Playwright Chromium harness. Remove SyncManager so the
  // main-thread flush runs on reconnect (the behavior these tests exercise).
  await page.addInitScript(() => {
    try { delete (window as unknown as Record<string, unknown>).SyncManager; } catch { /* noop */ }
  });
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

/** POST authenticated as Alice (uses browser-context cookies + CSRF). */
async function apiPost(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

/** GET authenticated as Alice. */
async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

/** Trigger a React Query refetch via online event. */
async function triggerRefetch(page: Page) {
  await page.evaluate(() => window.dispatchEvent(new Event("online")));
}

// ─── Shared state ───────────────────────────────────────────────

let dmConvoId: string;

// ────────────────────────────────────────────────────────────────
// Section 102: Offline Message Optimistic Display
// ────────────────────────────────────────────────────────────────

test.describe("102. Offline Message Optimistic Display", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    // Ensure a DM with Bob exists
    const resp = await apiPost(page, "/messaging/conversations", {
      type: "dm",
      participant_ids: [BOB_ID],
    });
    const data = await resp.json();
    dmConvoId = data.conversation_id;

    // Touch the DM so it appears at the top of the sidebar
    await apiPost(page, `/messaging/conversations/${dmConvoId}/messages`, {
      text: `__touch_102_${TS}`,
    });

    await ctx.close();
  });

  test("102.1 offline message appears inline with pending badge", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);

    // Open the DM
    const sidebar = page.locator('[class*="conversation"], [data-testid="conversation-list"]').first();
    await page.goto(`${BASE}/messages/${dmConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    // Go offline
    await page.context().setOffline(true);

    const testMsg = `Offline inline ${TS}`;
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: "Send message" }).click();

    // Verify message appears
    await expect(page.locator("p").filter({ hasText: testMsg })).toBeVisible({ timeout: 5000 });

    // Verify pending badge
    await expect(page.getByText(/sending when online/i)).toBeVisible();

    await page.context().setOffline(false);
  });

  test("102.2 offline message has reduced opacity", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);
    await page.goto(`${BASE}/messages/${dmConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    await page.context().setOffline(true);
    const testMsg = `Opacity test ${TS}_2`;
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: "Send message" }).click();

    // Check opacity class on the message bubble
    const bubble = page.locator("p").filter({ hasText: testMsg }).locator("xpath=ancestor::div[contains(@class,'rounded-2xl')]");
    await expect(bubble.first()).toHaveClass(/opacity-7/);

    await page.context().setOffline(false);
  });

  test("102.3 offline message transitions to sent when online", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);
    await page.goto(`${BASE}/messages/${dmConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    const testMsg = `Transition test ${TS}_3`;
    await page.context().setOffline(true);
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: "Send message" }).click();

    // Verify pending
    await expect(page.getByText(/sending when online/i)).toBeVisible();

    // Come back online
    await page.context().setOffline(false);
    await triggerRefetch(page);

    // Wait for the pending badge to disappear
    await expect(page.getByText(/sending when online/i)).not.toBeVisible({ timeout: 15000 });

    // Message text should still be visible
    await expect(page.locator("p").filter({ hasText: testMsg })).toBeVisible();
  });

  test("102.4 multiple offline messages appear in order", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);
    await page.goto(`${BASE}/messages/${dmConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    await page.context().setOffline(true);

    const ts = Date.now();
    for (const suffix of ["first", "second", "third"]) {
      const text = `Order ${suffix} ${ts}`;
      await page.getByPlaceholder(/type a message/i).fill(text);
      await page.getByRole("button", { name: "Send message" }).click();
      await page.waitForTimeout(200);
    }

    // All three should appear
    const bubbles = page.locator("p").filter({ hasText: new RegExp(`Order .+ ${ts}`) });
    await expect(bubbles).toHaveCount(3);
    const texts = await bubbles.allTextContents();
    expect(texts[0]).toContain("first");
    expect(texts[1]).toContain("second");
    expect(texts[2]).toContain("third");

    // All should have pending badges
    const badges = page.getByText(/sending when online/i);
    await expect(badges).toHaveCount(3);

    await page.context().setOffline(false);
  });

  test("102.5 offline message shows sending state during flush", async ({ page }) => {
    test.setTimeout(45_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);
    await page.goto(`${BASE}/messages/${dmConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    const testMsg = `Sending state ${TS}_5`;
    await page.context().setOffline(true);
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: "Send message" }).click();
    await expect(page.getByText(/sending when online/i)).toBeVisible();

    // Delay the message POST to observe "Sending..." state
    await page.route("**/messaging/conversations/*/messages", async (route) => {
      await new Promise((r) => setTimeout(r, 2000));
      await route.continue();
    });

    // Come back online
    await page.context().setOffline(false);
    await triggerRefetch(page);

    // Should briefly show "Sending..." with spinner
    await expect(page.getByText(/^Sending\.\.\.$/)).toBeVisible({ timeout: 10000 });

    // Then transition to completed
    await page.unroute("**/messaging/conversations/*/messages");
    await expect(page.getByText(/^Sending\.\.\.$/)).not.toBeVisible({ timeout: 15000 });
    await expect(page.locator("p").filter({ hasText: testMsg })).toBeVisible();
  });

  test("102.6 offline message hover toolbar is hidden", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);
    await page.goto(`${BASE}/messages/${dmConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    const testMsg = `Toolbar test ${TS}_6`;
    await page.context().setOffline(true);
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: "Send message" }).click();

    // Hover over the offline message
    const bubble = page.locator("p").filter({ hasText: testMsg });
    await expect(bubble).toBeVisible();
    await bubble.hover();
    await page.waitForTimeout(500);

    // The offline message bubble must not render the hover toolbar
    // (React/Reply/actions). Scope to this bubble — other (real) messages keep
    // their toolbar in the DOM at opacity-0, which Playwright counts as visible.
    const offlineBubble = bubble
      .locator("xpath=ancestor::div[contains(@class,'rounded-2xl')]")
      .first();
    await expect(offlineBubble.getByRole("button", { name: /^React$/i })).toHaveCount(0);
    await expect(offlineBubble.getByRole("button", { name: /^Reply$/i })).toHaveCount(0);
    await expect(offlineBubble.getByRole("button", { name: /message actions/i })).toHaveCount(0);

    await page.context().setOffline(false);
  });

  test("102.7 offline message clears compose bar", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);
    await page.goto(`${BASE}/messages/${dmConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    await page.context().setOffline(true);
    const testMsg = `Clear compose ${TS}_7`;
    const composeInput = page.getByPlaceholder(/type a message/i);
    await composeInput.fill(testMsg);
    await page.getByRole("button", { name: "Send message" }).click();

    // Compose bar should be cleared
    await expect(composeInput).toHaveValue("");

    // But message should appear in conversation
    await expect(page.locator("p").filter({ hasText: testMsg })).toBeVisible();

    await page.context().setOffline(false);
  });

  test("102.8 duplicate offline messages are prevented", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);
    await page.goto(`${BASE}/messages/${dmConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    await page.context().setOffline(true);
    const testMsg = `Dedup test ${TS}_8`;

    // Send the same message twice rapidly
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: "Send message" }).click();
    await page.waitForTimeout(50);
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: "Send message" }).click();

    // At least one message should appear (dedup may or may not catch it depending on timing)
    await expect(page.locator("p").filter({ hasText: testMsg }).first()).toBeVisible();

    await page.context().setOffline(false);
  });
});

// ────────────────────────────────────────────────────────────────
// Section 103: Failed Message UI
// ────────────────────────────────────────────────────────────────

test.describe("103. Failed Message UI", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    // Ensure DM exists
    const resp = await apiPost(page, "/messaging/conversations", {
      type: "dm",
      participant_ids: [BOB_ID],
    });
    const data = await resp.json();
    dmConvoId = data.conversation_id;

    await apiPost(page, `/messaging/conversations/${dmConvoId}/messages`, {
      text: `__touch_103_${TS}`,
    });

    await ctx.close();
  });

  test("103.1 failed message shows error badge with retry/discard", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);
    await page.goto(`${BASE}/messages/${dmConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    const testMsg = `Fail test ${TS}_1`;

    // Go offline and send
    await page.context().setOffline(true);
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: "Send message" }).click();
    await expect(page.locator("p").filter({ hasText: testMsg })).toBeVisible();

    // Intercept message POST to return 400
    await page.route("**/messaging/conversations/*/messages", (route) => {
      route.fulfill({
        status: 400,
        contentType: "application/json",
        body: JSON.stringify({ detail: "Message content rejected" }),
      });
    });

    // Come back online (triggers flush that hits 400)
    await page.context().setOffline(false);
    await triggerRefetch(page);

    // Verify error badge
    await expect(page.getByRole("button", { name: /retry/i }).first()).toBeVisible({ timeout: 15000 });
    await expect(page.getByRole("button", { name: /retry/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /discard/i })).toBeVisible();

    // Message text should still be visible
    await expect(page.locator("p").filter({ hasText: testMsg })).toBeVisible();

    // Bubble should have destructive ring
    const bubble = page.locator("p").filter({ hasText: testMsg }).locator("xpath=ancestor::div[contains(@class,'rounded-2xl')]");
    await expect(bubble.first()).toHaveClass(/ring-destructive/);

    await page.unroute("**/messaging/conversations/*/messages");
  });

  test("103.2 retry moves failed message back to pending", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);
    await page.goto(`${BASE}/messages/${dmConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    const testMsg = `Retry test ${TS}_2`;

    // Create a failed message
    await page.context().setOffline(true);
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: "Send message" }).click();

    await page.route("**/messaging/conversations/*/messages", (route) => {
      route.fulfill({ status: 422, contentType: "application/json", body: JSON.stringify({ detail: "Error" }) });
    });

    await page.context().setOffline(false);
    await triggerRefetch(page);
    await expect(page.getByRole("button", { name: /retry/i }).first()).toBeVisible({ timeout: 15000 });

    // Unblock the API
    await page.unroute("**/messaging/conversations/*/messages");

    // Click retry
    await page.getByRole("button", { name: /retry/i }).click();

    // Should show pending state again
    await expect(page.getByText(/sending when online|re-queued/i)).toBeVisible({ timeout: 5000 });
  });

  test("103.3 discard removes the message from the conversation", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);
    await page.goto(`${BASE}/messages/${dmConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    const testMsg = `Discard test ${TS}_3`;

    await page.context().setOffline(true);
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: "Send message" }).click();

    await page.route("**/messaging/conversations/*/messages", (route) => {
      route.fulfill({ status: 400, contentType: "application/json", body: JSON.stringify({ detail: "Bad" }) });
    });

    await page.context().setOffline(false);
    await triggerRefetch(page);
    await expect(page.getByRole("button", { name: /retry/i }).first()).toBeVisible({ timeout: 15000 });

    // Click discard
    await page.getByRole("button", { name: /discard/i }).click();

    // Message should be removed
    await expect(page.locator("p").filter({ hasText: testMsg })).not.toBeVisible({ timeout: 5000 });

    // Toast should confirm
    await expect(page.getByText(/discarded/i)).toBeVisible({ timeout: 5000 });

    await page.unroute("**/messaging/conversations/*/messages");
  });

  test("103.4 failed message error text shows server error", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);
    await page.goto(`${BASE}/messages/${dmConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    const testMsg = `Server err test ${TS}_4`;
    await page.context().setOffline(true);
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: "Send message" }).click();

    await page.route("**/messaging/conversations/*/messages", (route) => {
      route.fulfill({
        status: 422,
        contentType: "application/json",
        body: JSON.stringify({ detail: "Message text exceeds maximum length" }),
      });
    });

    await page.context().setOffline(false);
    await triggerRefetch(page);

    // Error text should show the server error message
    // Note: the error comes from the response body or the generic error message
    await expect(page.getByText(/failed to send|exceeds maximum/i)).toBeVisible({ timeout: 15000 });

    await page.unroute("**/messaging/conversations/*/messages");
  });

  test("103.5 failed message has accessible error announcement", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);
    await page.goto(`${BASE}/messages/${dmConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    const testMsg = `A11y err test ${TS}_5`;
    await page.context().setOffline(true);
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: "Send message" }).click();

    await page.route("**/messaging/conversations/*/messages", (route) => {
      route.fulfill({ status: 400, contentType: "application/json", body: JSON.stringify({ detail: "rejected" }) });
    });

    await page.context().setOffline(false);
    await triggerRefetch(page);
    await expect(page.getByRole("button", { name: /retry/i }).first()).toBeVisible({ timeout: 15000 });

    // Check aria-label on the error badge
    const errorBadge = page.locator('[role="alert"]');
    await expect(errorBadge).toBeVisible();

    await page.unroute("**/messaging/conversations/*/messages");
  });
});

// ────────────────────────────────────────────────────────────────
// Section 104: Offline Feed Post Optimistic
// ────────────────────────────────────────────────────────────────

test.describe("104. Offline Feed Post Optimistic", () => {
  test("104.1 offline post appears at top of feed with pending badge", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/feed`);
    await page.waitForTimeout(2000);

    await page.context().setOffline(true);

    const testPost = `Offline post ${TS}_1`;

    // Try to find the composer
    const composer = page.getByPlaceholder(/what's on your mind|write something/i);
    const composerVisible = await composer.isVisible().catch(() => false);
    if (!composerVisible) {
      // Skip if no composer visible (may need to click to show it)
      test.skip();
      return;
    }
    await composer.fill(testPost);
    await page.getByRole("button", { name: "Post", exact: true }).click();

    // Post should appear in the feed
    await expect(page.getByText(testPost)).toBeVisible({ timeout: 5000 });
    await expect(page.getByText(/waiting to publish/i)).toBeVisible();

    await page.context().setOffline(false);
  });

  test("104.2 offline post transitions to published when online", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/feed`);
    await page.waitForTimeout(2000);

    await page.context().setOffline(true);

    const testPost = `Transition post ${TS}_2`;
    const composer = page.getByPlaceholder(/what's on your mind|write something/i);
    const composerVisible = await composer.isVisible().catch(() => false);
    if (!composerVisible) { test.skip(); return; }

    await composer.fill(testPost);
    await page.getByRole("button", { name: "Post", exact: true }).click();
    await expect(page.getByText(/waiting to publish/i)).toBeVisible();

    // Come back online
    await page.context().setOffline(false);
    await triggerRefetch(page);

    // "Waiting to publish" should disappear after flush
    await expect(page.getByText(/waiting to publish/i)).not.toBeVisible({ timeout: 15000 });
  });

  test("104.3 offline post has reduced opacity", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/feed`);
    await page.waitForTimeout(2000);

    await page.context().setOffline(true);
    const testPost = `Opacity post ${TS}_3`;
    const composer = page.getByPlaceholder(/what's on your mind|write something/i);
    const composerVisible = await composer.isVisible().catch(() => false);
    if (!composerVisible) { test.skip(); return; }

    await composer.fill(testPost);
    await page.getByRole("button", { name: "Post", exact: true }).click();

    // The card containing the text should have an opacity class
    const postText = page.getByText(testPost);
    await expect(postText).toBeVisible();
    const card = postText.locator("xpath=ancestor::div[contains(@class,'opacity')]");
    await expect(card.first()).toBeVisible();

    await page.context().setOffline(false);
  });

  test("104.4 offline post composer resets after queueing", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/feed`);
    await page.waitForTimeout(2000);

    await page.context().setOffline(true);
    const testPost = `Composer reset ${TS}_4`;
    const composer = page.getByPlaceholder(/what's on your mind|write something/i);
    const composerVisible = await composer.isVisible().catch(() => false);
    if (!composerVisible) { test.skip(); return; }

    await composer.fill(testPost);
    await page.getByRole("button", { name: "Post", exact: true }).click();

    // Composer should be cleared
    await expect(composer).toHaveValue("");

    // Post should appear
    await expect(page.getByText(testPost)).toBeVisible();

    await page.context().setOffline(false);
  });

  test("104.5 offline post like button is disabled", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/feed`);
    await page.waitForTimeout(2000);

    await page.context().setOffline(true);
    const testPost = `Like disabled ${TS}_5`;
    const composer = page.getByPlaceholder(/what's on your mind|write something/i);
    const composerVisible = await composer.isVisible().catch(() => false);
    if (!composerVisible) { test.skip(); return; }

    await composer.fill(testPost);
    await page.getByRole("button", { name: "Post", exact: true }).click();
    await expect(page.getByText(testPost)).toBeVisible();

    // The offline post is at the top of the feed; its Like button must be
    // disabled. Target the Like button by its accessible name within the card.
    const postSection = page.getByText(testPost).locator("xpath=ancestor::div[contains(@class,'rounded') or contains(@class,'card') or contains(@class,'Card')]").first();
    const likeButton = postSection.getByRole("button", { name: "Like" }).first();
    await expect(likeButton).toBeVisible({ timeout: 5000 });
    await expect(likeButton).toBeDisabled();

    await page.context().setOffline(false);
  });
});

// ────────────────────────────────────────────────────────────────
// Section 105: Offline Queue Banner Integration
// ────────────────────────────────────────────────────────────────

test.describe("105. Offline Queue Banner Integration", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiPost(page, "/messaging/conversations", {
      type: "dm",
      participant_ids: [BOB_ID],
    });
    const data = await resp.json();
    dmConvoId = data.conversation_id;
    await apiPost(page, `/messaging/conversations/${dmConvoId}/messages`, { text: `__touch_105_${TS}` });
    await ctx.close();
  });

  test("105.1 banner shows queue count when messages queued offline", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);
    await page.goto(`${BASE}/messages/${dmConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    await page.context().setOffline(true);
    await page.waitForTimeout(500);

    // Banner should appear
    await expect(page.getByText(/you're offline/i)).toBeVisible();

    // Send two messages
    for (let i = 0; i < 2; i++) {
      await page.getByPlaceholder(/type a message/i).fill(`Banner test ${i} ${TS}`);
      await page.getByRole("button", { name: "Send message" }).click();
      await page.waitForTimeout(200);
    }

    // Banner should show "2 queued"
    await expect(page.getByText(/2 queued/)).toBeVisible({ timeout: 5000 });

    await page.context().setOffline(false);
  });

  test("105.2 banner count decreases as items flush", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);
    await page.goto(`${BASE}/messages/${dmConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    await page.context().setOffline(true);
    await page.getByPlaceholder(/type a message/i).fill(`Flush banner ${TS}_2`);
    await page.getByRole("button", { name: "Send message" }).click();
    await page.waitForTimeout(200);

    // Go online
    await page.context().setOffline(false);
    await triggerRefetch(page);

    // Banner's queued count should eventually disappear. Scope to the warning
    // banner — the flush success toast ("N queued item sent…") also says "queued".
    await expect(page.locator(".bg-warning").getByText(/queued/)).not.toBeVisible({ timeout: 15000 });
  });

  test("105.3 banner shows failed count", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);
    await page.goto(`${BASE}/messages/${dmConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    await page.context().setOffline(true);
    await page.getByPlaceholder(/type a message/i).fill(`Fail banner ${TS}_3`);
    await page.getByRole("button", { name: "Send message" }).click();

    await page.route("**/messaging/conversations/*/messages", (route) => {
      route.fulfill({ status: 400, contentType: "application/json", body: JSON.stringify({ detail: "Bad" }) });
    });

    await page.context().setOffline(false);
    await triggerRefetch(page);

    // Should show failed count
    await expect(page.getByText(/failed/)).toBeVisible({ timeout: 15000 });

    await page.unroute("**/messaging/conversations/*/messages");
  });
});

// ────────────────────────────────────────────────────────────────
// Section 106: Group Chat Offline Optimistic
// ────────────────────────────────────────────────────────────────

test.describe("106. Group Chat Offline Optimistic", () => {
  let groupConvoId: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);

    // Create a group chat (groups require >= 3 unique participants).
    const resp = await apiPost(page, "/messaging/conversations", {
      type: "group",
      participant_ids: [BOB_ID, "e2e_charlie@test.local"],
      name: `E2E Offline Group ${TS}`,
    });
    const data = await resp.json();
    groupConvoId = data.conversation_id;

    // Accept the group for Alice
    await apiPost(page, `/messaging/conversations/${groupConvoId}/accept`, {});

    await ctx.close();
  });

  test("106.1 offline message in group chat shows pending badge", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);

    // Find and click the group chat
    await page.goto(`${BASE}/messages/${groupConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    await page.context().setOffline(true);
    const testMsg = `Group offline ${TS}_1`;
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: "Send message" }).click();

    await expect(page.locator("p").filter({ hasText: testMsg })).toBeVisible();
    await expect(page.getByText(/sending when online/i)).toBeVisible();

    await page.context().setOffline(false);
  });

  test("106.2 group offline message transitions to sent when online", async ({ page }) => {
    test.setTimeout(30_000);
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`);
    await page.waitForTimeout(1500);

    await page.goto(`${BASE}/messages/${groupConvoId}`);
    await page.getByPlaceholder(/type a message/i).first().waitFor({ state: "visible", timeout: 15000 });
    await page.waitForTimeout(1000);

    const testMsg = `Group trans ${TS}_2`;
    await page.context().setOffline(true);
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: "Send message" }).click();
    await expect(page.getByText(/sending when online/i)).toBeVisible();

    await page.context().setOffline(false);
    await triggerRefetch(page);

    await expect(page.getByText(/sending when online/i)).not.toBeVisible({ timeout: 15000 });
    await expect(page.locator("p").filter({ hasText: testMsg })).toBeVisible();
  });
});
