/**
 * E2E tests for UX-002: Keyboard Shortcuts / Command Palette
 *
 * Sections:
 *   73 — Command palette basics (4 tests)
 *   74 — Command palette actions (3 tests)
 *   75 — Shortcut overlay (3 tests)
 *   76 — Ctrl+Enter send in ComposeBar (1 test)
 *   77 — Command palette filtering (1 test)
 *
 * Auth: Alice session cookies (from e2e_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

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

// ─── Auth helpers ───────────────────────────────────────────────���─────────────

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    (uid: string) => {
      const state = { userId: uid, accessToken: null, isAuthenticated: true, logoutReason: null };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    userId,
  );
}

// ─── API helpers ────────────────────────────��───────────────────���─────────────

async function apiPost(page: Page, identity: string, path: string, body: unknown) {
  const session = getSessions()[identity];
  return page.request.post(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body,
  });
}

// ─── Section 73: Command palette basics ───────────────────────────────────────

test.describe("73 — Command palette basics", () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page, ALICE_ID);
    await page.goto(BASE, { waitUntil: "domcontentloaded" });
    // Wait for the page to be interactive
    await page.waitForSelector("header");
  });

  test("73.1 Ctrl+K opens command palette", async ({ page }) => {
    await page.keyboard.press("Control+k");
    await expect(
      page.getByPlaceholder("Search content and pages..."),
    ).toBeVisible();
  });

  test("73.2 Clicking search button opens command palette", async ({ page }) => {
    await page.locator("header").getByRole("button", { name: /search/i }).click();
    await expect(
      page.getByPlaceholder("Search content and pages..."),
    ).toBeVisible();
  });

  test("73.3 Command palette shows Actions group", async ({ page }) => {
    await page.keyboard.press("Control+k");
    await expect(page.getByPlaceholder("Search content and pages...")).toBeVisible();
    // The Actions group heading should be visible
    await expect(page.locator("[cmdk-group-heading]").filter({ hasText: "Actions" })).toBeVisible();
  });

  test("73.4 Escape closes command palette", async ({ page }) => {
    await page.keyboard.press("Control+k");
    const input = page.getByPlaceholder("Search content and pages...");
    await expect(input).toBeVisible();
    // Small wait for dialog animation to settle before pressing Escape
    await page.waitForTimeout(200);
    await page.keyboard.press("Escape");
    await expect(input).not.toBeVisible({ timeout: 5_000 });
  });
});

// ─── Section 74: Command palette actions ──────────────────────────────────────

test.describe("74 — Command palette actions", () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page, ALICE_ID);
    await page.goto(BASE, { waitUntil: "domcontentloaded" });
    await page.waitForSelector("header");
  });

  test("74.1 Toggle Dark Mode action changes theme", async ({ page }) => {
    // Clear any persisted theme by setting to light first
    await page.evaluate(() => {
      const stored = localStorage.getItem("ui-store");
      const parsed = stored ? JSON.parse(stored) : { state: {} };
      parsed.state = { ...parsed.state, theme: "light" };
      localStorage.setItem("ui-store", JSON.stringify(parsed));
    });
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.waitForSelector("header");

    // Open palette and select Toggle Dark Mode
    await page.keyboard.press("Control+k");
    await expect(page.getByPlaceholder("Search content and pages...")).toBeVisible();
    // Type to filter to the action
    await page.getByPlaceholder("Search content and pages...").fill("Toggle Dark");
    await page.getByRole("option", { name: /Toggle Dark Mode/i }).click();

    // The theme should now be dark
    await expect(page.locator("html")).toHaveClass(/dark/);
  });

  test("74.2 New Message action navigates to messages", async ({ page }) => {
    await page.keyboard.press("Control+k");
    await page.getByPlaceholder("Search content and pages...").fill("New Message");
    // Use first() to avoid strict mode violation from the "View all results" item
    await page.getByRole("option", { name: /New Message/i }).first().click();
    await expect(page).toHaveURL(/\/messages\?new=1/);
  });

  test("74.3 Keyboard Shortcuts action opens overlay", async ({ page }) => {
    await page.keyboard.press("Control+k");
    await page.getByPlaceholder("Search content and pages...").fill("Keyboard");
    await page.getByRole("option", { name: /Keyboard Shortcuts/i }).click();
    await expect(
      page.getByRole("heading", { name: "Keyboard Shortcuts" }),
    ).toBeVisible();
  });
});

// ─── Section 75: Shortcut overlay ───────────────────────────────���─────────────

test.describe("75 — Shortcut overlay", () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page, ALICE_ID);
    await page.goto(BASE, { waitUntil: "domcontentloaded" });
    await page.waitForSelector("header");
  });

  test("75.1 ? key opens shortcut help when not in input", async ({ page }) => {
    // Ensure no input is focused by clicking on the page body
    await page.locator("main").click();
    await page.keyboard.press("Shift+?");
    await expect(
      page.getByRole("heading", { name: "Keyboard Shortcuts" }),
    ).toBeVisible();
  });

  test("75.2 Escape closes shortcut help", async ({ page }) => {
    await page.locator("main").click();
    await page.keyboard.press("Shift+?");
    const heading = page.getByRole("heading", { name: "Keyboard Shortcuts" });
    await expect(heading).toBeVisible();
    // Small wait for dialog animation to settle
    await page.waitForTimeout(200);
    await page.keyboard.press("Escape");
    await expect(heading).not.toBeVisible({ timeout: 5_000 });
  });

  test("75.3 ? in input types character normally", async ({ page }) => {
    // Open command palette to get an input
    await page.keyboard.press("Control+k");
    const input = page.getByPlaceholder("Search content and pages...");
    await expect(input).toBeVisible();
    await input.type("?");
    await expect(input).toHaveValue("?");
    // The shortcut overlay should NOT be open
    await expect(
      page.getByRole("heading", { name: "Keyboard Shortcuts" }),
    ).not.toBeVisible();
  });
});

// ─── Section 76: Ctrl+Enter sends message ─────────────────────────────────────

test.describe("76 — Ctrl+Enter send in ComposeBar", () => {
  test("76.1 Ctrl+Enter sends a message", async ({ page }) => {
    test.setTimeout(60_000);
    await injectAuth(page, ALICE_ID);

    // Navigate to the messages list first
    await page.goto(`${BASE}/messages`, { waitUntil: "load" });
    await page.waitForSelector("header");

    // Create (or find) a DM with Bob and send a touch message so it appears at the top.
    // Hit the backend directly (not through Vite proxy) to avoid proxy flakiness.
    // Retry on 429 (rate limit) since rapid test reruns can trigger it.
    const BACKEND = "http://localhost:8000";
    const session = getSessions()[ALICE_ID];
    let dmConvoId = "";
    for (let attempt = 0; attempt < 5; attempt++) {
      const dmResp = await page.request.post(
        `${BACKEND}/messaging/conversations/dm/find-or-create`,
        {
          headers: { "x-csrf-token": session.csrf_token },
          data: { user_id: BOB_ID },
        },
      );
      if (dmResp.status() === 200) {
        const dmData = await dmResp.json() as { conversation_id: string };
        dmConvoId = dmData.conversation_id;
        break;
      }
      if (dmResp.status() === 429) {
        // Wait for rate limit to clear
        const body = await dmResp.json().catch(() => ({ detail: { retry_after: 3 } })) as { detail?: { retry_after?: number } };
        const wait = ((body.detail?.retry_after ?? 3) + 1) * 1000;
        await page.waitForTimeout(wait);
        continue;
      }
      const body = await dmResp.text();
      throw new Error(`DM create failed: status=${dmResp.status()} body=${body}`);
    }
    if (!dmConvoId) throw new Error("Failed to create DM with Bob after retries");
    await page.request.post(
      `${BACKEND}/messaging/conversations/${dmConvoId}/messages`,
      {
        headers: { "x-csrf-token": session.csrf_token },
        data: { text: `__touch_ctrl_enter__${Date.now()}` },
      },
    );

    // Trigger React Query refetch so the new DM appears in the sidebar
    await page.evaluate(() => window.dispatchEvent(new Event("online")));
    await page.waitForTimeout(500);

    // If conversations still don't appear, reload the page
    const bobRow = page.getByRole("button").filter({ hasText: /bob/i }).first();
    const isVisible = await bobRow.isVisible().catch(() => false);
    if (!isVisible) {
      await page.reload({ waitUntil: "load" });
    }

    // Click the first conversation in the sidebar (the DM with Bob we just touched)
    const convoRow = page.getByRole("button").filter({ hasText: /bob/i }).first();
    await expect(convoRow).toBeVisible({ timeout: 10_000 });
    await convoRow.click();

    // Wait for the compose bar textarea to appear
    const textarea = page.getByPlaceholder("Type a message...").or(
      page.getByPlaceholder("Type an encrypted message..."),
    );
    await expect(textarea).toBeVisible({ timeout: 10_000 });

    const msgText = `ctrl-enter-test-${Date.now()}`;
    await textarea.fill(msgText);

    // Listen for the POST message request BEFORE pressing Ctrl+Enter
    const postPromise = page.waitForResponse(
      (resp) => resp.url().includes("/messages") && resp.request().method() === "POST" && resp.status() === 200,
      { timeout: 10_000 },
    );

    // Use Ctrl+Enter to send
    await textarea.press("Control+Enter");

    // Wait for the message to be sent to the server
    await postPromise;

    // The message should appear in either the conversation view or the sidebar preview
    await expect(
      page.locator("p, span").filter({ hasText: msgText }).first(),
    ).toBeVisible({ timeout: 10_000 });
  });
});

// ─── Section 77: Command palette filtering ────────────────────────────────────

test.describe("77 — Command palette filtering", () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page, ALICE_ID);
    await page.goto(BASE, { waitUntil: "domcontentloaded" });
    await page.waitForSelector("header");
  });

  test("77.1 Typing filters results correctly", async ({ page }) => {
    await page.keyboard.press("Control+k");
    const input = page.getByPlaceholder("Search content and pages...");
    await expect(input).toBeVisible();

    // Type "mess" to filter
    await input.fill("mess");

    // "Messages" should be visible
    await expect(page.getByRole("option", { name: "Messages" })).toBeVisible();
    // "New Message" should also be visible (contains "mess")
    await expect(page.getByRole("option", { name: /New Message/i })).toBeVisible();
    // "Calendar" should NOT be visible
    await expect(page.getByRole("option", { name: "Calendar" })).not.toBeVisible();
  });
});
