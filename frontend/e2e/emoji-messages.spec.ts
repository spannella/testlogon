/**
 * E2E tests for MSG-006: Emoji Messages.
 *
 * Routes tested:
 *   /messages — Messaging page (SPA, no URL per conversation)
 *
 * Features:
 *   - Emoji picker opens from ComposeBar; 9 category tabs render
 *   - Search filters emojis by keyword
 *   - Skin-tone selector
 *   - Selecting an emoji inserts it into the compose textarea
 *   - Emoji-only messages (1-3 emoji) render at 3x size (text-5xl)
 *   - 4+ emoji / mixed text renders at normal size
 *   - Shortcode replacement (:smile: → 😄) on send
 *   - Recently-used emoji appears in the Recent section
 *
 * Sections: 717 (picker UI), 718 (rendering), 719 (shortcodes + recents).
 *
 * Auth: cookie-based session injection (injectAuth). Test users Alice + Bob.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

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
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
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

async function apiPost(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── DM helpers (mirror messaging-features.spec.ts) ───────────────────────────

let _dmConvoId: string | null = null;
async function getOrCreateDm(page: Page): Promise<string> {
  if (_dmConvoId) return _dmConvoId;
  const bobSub = getSessions()[BOB_ID].user_sub;
  const resp = await apiPost(page, "/messaging/conversations", {
    participant_ids: [bobSub],
    type: "dm",
  });
  if (!resp.ok()) {
    const body = await resp.text().catch(() => "(unreadable)");
    throw new Error(`DM creation failed: HTTP ${resp.status()} — ${body}`);
  }
  const body = await resp.json();
  _dmConvoId = body.conversation_id as string;
  return _dmConvoId;
}

async function openDmWithBob(page: Page) {
  await injectAuth(page, ALICE_ID);
  const convoId = await getOrCreateDm(page);
  const session = getSessions()[ALICE_ID];
  await page.request
    .post(`${API}/messaging/conversations/${convoId}/messages`, {
      data: { text: `__touch__${Date.now()}` },
      headers: { "x-csrf-token": session.csrf_token },
    })
    .catch(() => {});
  await page.goto(`${BASE}/messages`, { waitUntil: "load" });
  await page.waitForTimeout(600);
  const row = page.getByRole("button").filter({ hasText: "E2E Bob" }).first();
  await expect(row).toBeVisible({ timeout: 12000 });
  await row.click();
  await expect(
    page.getByPlaceholder("Type a message...").or(page.getByPlaceholder("Type an encrypted message...")),
  ).toBeVisible({ timeout: 5000 });
}

/**
 * Send a message via API into the DM, then trigger a UI refetch and wait for the
 * message bubble containing `text` to appear. Returns the bubble <p> locator.
 */
async function sendAndRender(page: Page, convoId: string, text: string) {
  const session = getSessions()[ALICE_ID];
  await page.request.post(`${API}/messaging/conversations/${convoId}/messages`, {
    data: { text },
    headers: { "x-csrf-token": session.csrf_token },
  });
  // ConversationView listens for the 'online' event → invalidates queries.
  await page.evaluate(() => window.dispatchEvent(new Event("online")));
  const bubble = page.locator("p").filter({ hasText: text }).last();
  await expect(bubble).toBeVisible({ timeout: 8000 });
  return bubble;
}

// ─── 717. Emoji picker UI ─────────────────────────────────────────────────────

test.describe("717. Emoji Picker UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await openDmWithBob(page);
  });

  test.afterAll(async () => page?.close());

  test("717.1 Emoji picker opens from the ComposeBar emoji button", async () => {
    await page.getByTestId("emoji-button").click();
    await expect(page.getByTestId("emoji-picker")).toBeVisible({ timeout: 5000 });
    // Close again to reset for the next test.
    await page.keyboard.press("Escape");
  });

  test("717.2 Picker shows 9 category tabs", async () => {
    await page.getByTestId("emoji-button").click();
    await expect(page.getByTestId("emoji-picker")).toBeVisible({ timeout: 5000 });
    // 9 standard emoji categories. The picker also renders a separate "Custom"
    // (favorites/recents) tab with testid emoji-category-custom — exclude it here.
    const tabs = page.locator(
      '[data-testid^="emoji-category-"]:not([data-testid="emoji-category-custom"])',
    );
    await expect(tabs).toHaveCount(9);
    await page.keyboard.press("Escape");
  });

  test("717.3 Search filters emojis by keyword", async () => {
    await page.getByTestId("emoji-button").click();
    await expect(page.getByTestId("emoji-picker")).toBeVisible({ timeout: 5000 });
    await page.getByTestId("emoji-search").fill("fire");
    const results = page.getByTestId("emoji-search-results");
    await expect(results).toBeVisible({ timeout: 3000 });
    // The fire emoji must be present in the filtered results.
    await expect(results.locator('[data-emoji="🔥"]')).toBeVisible();
    // An unrelated emoji (cat) must NOT be present.
    await expect(results.locator('[data-emoji="🐱"]')).toHaveCount(0);
    await page.keyboard.press("Escape");
  });

  test("717.4 Search with no matches shows empty state", async () => {
    await page.getByTestId("emoji-button").click();
    await expect(page.getByTestId("emoji-picker")).toBeVisible({ timeout: 5000 });
    await page.getByTestId("emoji-search").fill("zzzqqqxyz");
    await expect(page.getByTestId("emoji-empty-state")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
  });

  test("717.5 Skin-tone selector opens and changes the active tone", async () => {
    await page.getByTestId("emoji-button").click();
    await expect(page.getByTestId("emoji-picker")).toBeVisible({ timeout: 5000 });
    await page.getByTestId("emoji-skin-tone-trigger").click();
    await expect(page.getByTestId("emoji-skin-tone-popover")).toBeVisible({ timeout: 3000 });
    // Select Medium-Dark tone.
    await page.locator('[data-tone="medium-dark"]').click();
    // Popover closes; the trigger now shows a skin-toned hand.
    await expect(page.getByTestId("emoji-skin-tone-trigger")).toContainText("\u{1F3FE}", { timeout: 3000 });
    await page.keyboard.press("Escape");
  });

  test("717.6 Selecting an emoji inserts it into the compose textarea", async () => {
    await page.getByTestId("emoji-button").click();
    await expect(page.getByTestId("emoji-picker")).toBeVisible({ timeout: 5000 });
    // Use search to reliably locate the party-popper emoji, then click it.
    await page.getByTestId("emoji-search").fill("tada");
    const results = page.getByTestId("emoji-search-results");
    await expect(results).toBeVisible({ timeout: 3000 });
    await results.locator('[data-emoji="🎉"]').first().click();
    const textarea = page.getByPlaceholder("Type a message...").or(
      page.getByPlaceholder("Type an encrypted message..."),
    );
    await expect(textarea).toHaveValue(/🎉/, { timeout: 3000 });
    // Clear the composer for cleanliness.
    await textarea.fill("");
  });
});

// ─── 718. Emoji message rendering ─────────────────────────────────────────────

test.describe("718. Emoji Message Rendering", () => {
  let page: Page;
  let convoId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await openDmWithBob(page);
    convoId = await getOrCreateDm(page);
  });

  test.afterAll(async () => page?.close());

  test("718.1 Single-emoji message renders at 3x (text-5xl)", async () => {
    const bubble = await sendAndRender(page, convoId, "😀");
    await expect(bubble).toHaveClass(/text-5xl/);
  });

  test("718.2 Two-emoji message renders at 3x (text-5xl)", async () => {
    const bubble = await sendAndRender(page, convoId, "😀🔥");
    await expect(bubble).toHaveClass(/text-5xl/);
  });

  test("718.3 Three-emoji message renders at 3x (text-5xl)", async () => {
    const bubble = await sendAndRender(page, convoId, "😀🔥❤️");
    await expect(bubble).toHaveClass(/text-5xl/);
  });

  test("718.4 Four-emoji message renders at normal size", async () => {
    const bubble = await sendAndRender(page, convoId, "😀🔥❤️👍");
    await expect(bubble).not.toHaveClass(/text-5xl/);
  });

  test("718.5 Mixed text + emoji renders at normal size", async () => {
    const text = `hello ${TS} 😀`;
    const bubble = await sendAndRender(page, convoId, text);
    await expect(bubble).not.toHaveClass(/text-5xl/);
  });
});

// ─── 719. Shortcode replacement & recents ─────────────────────────────────────

test.describe("719. Shortcode Replacement & Recents", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await openDmWithBob(page);
  });

  test.afterAll(async () => page?.close());

  async function typeAndSend(text: string) {
    const textarea = page.getByPlaceholder("Type a message...").or(
      page.getByPlaceholder("Type an encrypted message..."),
    );
    await textarea.fill(text);
    let postSent = false;
    const sent = page.waitForResponse(
      (r) => {
        if (r.url().includes("/messages") && r.request().method() === "POST") postSent = true;
        return postSent && r.url().includes("/messages") && r.request().method() === "POST";
      },
      { timeout: 10000 },
    );
    const refetch = page.waitForResponse(
      (r) =>
        postSent &&
        r.url().includes("/messages") &&
        r.request().method() === "GET" &&
        !r.url().includes("/scheduled"),
      { timeout: 10000 },
    );
    await page.getByRole("button", { name: "Send message" }).click();
    await sent;
    await refetch;
  }

  test("719.1 :smile: shortcode is replaced with 😄 on send", async () => {
    await typeAndSend(":smile:");
    await expect(page.locator("p").filter({ hasText: "😄" }).last()).toBeVisible({ timeout: 8000 });
  });

  test("719.2 Unknown shortcode is preserved as-is", async () => {
    const unknown = `:nonexistent_${TS}:`;
    await typeAndSend(unknown);
    await expect(page.locator("p").filter({ hasText: unknown }).last()).toBeVisible({ timeout: 8000 });
  });

  test("719.3 Mixed text with shortcodes is partially replaced", async () => {
    const marker = `mix${TS}`;
    await typeAndSend(`${marker} :fire: and :wave:`);
    const bubble = page.locator("p").filter({ hasText: marker }).last();
    await expect(bubble).toBeVisible({ timeout: 8000 });
    await expect(bubble).toContainText("🔥");
    await expect(bubble).toContainText("👋");
    await expect(bubble).not.toContainText(":fire:");
  });

  test("719.4 Recently-used emoji appears in the Recent section", async () => {
    // Open picker, select an emoji via search, reopen → it should be in Recent.
    await page.getByTestId("emoji-button").click();
    await expect(page.getByTestId("emoji-picker")).toBeVisible({ timeout: 5000 });
    await page.getByTestId("emoji-search").fill("rocket");
    const results = page.getByTestId("emoji-search-results");
    await expect(results).toBeVisible({ timeout: 3000 });
    await results.locator('[data-emoji="🚀"]').first().click();
    // Reopen the picker.
    await page.getByTestId("emoji-button").click();
    await expect(page.getByTestId("emoji-picker")).toBeVisible({ timeout: 5000 });
    const recent = page.getByTestId("emoji-recent-section");
    await expect(recent).toBeVisible({ timeout: 3000 });
    await expect(recent.locator('[data-emoji="🚀"]').first()).toBeVisible();
    await page.keyboard.press("Escape");
  });
});
