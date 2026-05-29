/**
 * E2E tests for PLATFORM-014: Comprehensive Keyboard Shortcuts
 *
 * Sections:
 *   114 — Navigation chord shortcuts (12 tests)
 *
 * Auth: Alice session cookies (from e2e_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";

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
  await page.evaluate(
    (uid: string) => {
      const state = {
        userId: uid,
        accessToken: null,
        isAuthenticated: true,
        logoutReason: null,
      };
      localStorage.setItem(
        "auth-store",
        JSON.stringify({ state, version: 0 }),
      );
    },
    userId,
  );
}

// ─── Section 114: Navigation chord shortcuts ─────────────────────────────────

test.describe("114 — Navigation chord shortcuts", () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page, ALICE_ID);
    await page.goto(BASE, { waitUntil: "domcontentloaded" });
    await page.waitForSelector("header");
    // Click body to ensure no input is focused
    await page.locator("main").click();
  });

  test("114.1 g then m navigates to /messages", async ({ page }) => {
    await page.keyboard.press("g");
    await page.keyboard.press("m");
    await expect(page).toHaveURL(/\/messages/, { timeout: 5_000 });
  });

  test("114.2 g then f navigates to /feed", async ({ page }) => {
    await page.keyboard.press("g");
    await page.keyboard.press("f");
    await expect(page).toHaveURL(/\/feed/, { timeout: 5_000 });
  });

  test("114.3 g then c navigates to /calendar", async ({ page }) => {
    await page.keyboard.press("g");
    await page.keyboard.press("c");
    await expect(page).toHaveURL(/\/calendar/, { timeout: 5_000 });
  });

  test("114.4 Chord timeout: g then wait 2s then m does NOT navigate", async ({ page }) => {
    await page.keyboard.press("g");
    // Wait for chord timeout (1s) + buffer
    await page.waitForTimeout(2000);
    await page.keyboard.press("m");
    // Should still be on the dashboard
    await page.waitForTimeout(500);
    await expect(page).toHaveURL(new RegExp(`^${BASE}/?$`));
  });

  test("114.5 Shortcuts disabled when typing in input field", async ({ page }) => {
    // Open command palette to get an input focused
    await page.keyboard.press("Control+k");
    const input = page.getByPlaceholder("Search content and pages...");
    await expect(input).toBeVisible();

    // Type g then m in the input -- should type characters, not navigate
    await input.press("g");
    await input.press("m");
    await expect(input).toHaveValue("gm");

    // Close palette
    await page.keyboard.press("Escape");
    await page.waitForTimeout(300);

    // Should still be on the same page
    await expect(page).toHaveURL(new RegExp(`^${BASE}/?$`));
  });

  test("114.6 Chord indicator appears on first key", async ({ page }) => {
    await page.keyboard.press("g");
    const indicator = page.locator("[data-testid='chord-indicator']");
    await expect(indicator).toBeVisible({ timeout: 2_000 });
    // Wait for it to auto-dismiss after 1s
    await expect(indicator).not.toBeVisible({ timeout: 3_000 });
  });

  test("114.7 g then s navigates to /settings", async ({ page }) => {
    await page.keyboard.press("g");
    await page.keyboard.press("s");
    await expect(page).toHaveURL(/\/settings/, { timeout: 5_000 });
  });

  test("114.8 n then m opens new message", async ({ page }) => {
    await page.keyboard.press("n");
    await page.keyboard.press("m");
    await expect(page).toHaveURL(/\/messages\?new=1/, { timeout: 5_000 });
  });

  test("114.9 ? opens help dialog", async ({ page }) => {
    await page.keyboard.press("Shift+?");
    await expect(
      page.getByRole("heading", { name: "Keyboard Shortcuts" }),
    ).toBeVisible();
  });

  test("114.10 Escape closes help dialog", async ({ page }) => {
    await page.keyboard.press("Shift+?");
    const heading = page.getByRole("heading", { name: "Keyboard Shortcuts" });
    await expect(heading).toBeVisible();
    await page.waitForTimeout(200);
    await page.keyboard.press("Escape");
    await expect(heading).not.toBeVisible({ timeout: 5_000 });
  });

  test("114.11 Help dialog shows all chord shortcuts", async ({ page }) => {
    await page.keyboard.press("Shift+?");
    await expect(
      page.getByRole("heading", { name: "Keyboard Shortcuts" }),
    ).toBeVisible();

    // Check that navigation chords are displayed
    await expect(page.getByText("Go to Messages")).toBeVisible();
    await expect(page.getByText("Go to Feed")).toBeVisible();
    await expect(page.getByText("Go to Calendar")).toBeVisible();
    await expect(page.getByText("Go to Settings")).toBeVisible();
    await expect(page.getByText("Go to Tickets")).toBeVisible();
    await expect(page.getByText("Go to Files")).toBeVisible();

    // Check chord key display format (e.g., "G then M")
    await expect(page.getByText("G then M")).toBeVisible();
    await expect(page.getByText("G then F")).toBeVisible();
  });

  test("114.12 Ctrl+K still opens command palette (backward compat)", async ({ page }) => {
    await page.keyboard.press("Control+k");
    await expect(
      page.getByPlaceholder("Search content and pages..."),
    ).toBeVisible();
  });
});
