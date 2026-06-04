/**
 * E2E tests — Mobile UI responsiveness.
 *
 * Sections:
 *   82 — Mobile chrome: nav bar, sidebar, hamburger drawer, theme picker, overflow (10 tests)
 *   83 — Mobile page usability: panels, dialogs, forms, navigation (10 tests)
 *
 * Viewport: 390×844 (iPhone 14/15 logical pixels) for all tests.
 *
 * Auth: session cookie auth via injectAuth().
 * Mocks: conversations → [] (prevents stale DM accumulation in sidebar).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";

// iPhone 14 / 15 logical resolution
const MOBILE_VIEWPORT = { width: 390, height: 844 };

const ALICE_ID = "e2e_alice@test.local";

// ─── Session bootstrap ────────────────────────────────────────────────────────

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

// ─── Helper: mock conversations to avoid sidebar pollution ────────────────────

async function mockConversations(page: Page) {
  await page.route("**/messaging/conversations**", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: "[]" }),
  );
}

// ─── Helper: check no horizontal overflow ────────────────────────────────────

async function assertNoHorizontalOverflow(page: Page): Promise<void> {
  const overflow = await page.evaluate(() => {
    const overflowing: string[] = [];
    const vw = document.documentElement.clientWidth;

    function isInsideScrollableX(el: Element): boolean {
      let parent = el.parentElement;
      while (parent && parent !== document.body) {
        const style = window.getComputedStyle(parent);
        if (style.overflowX === "auto" || style.overflowX === "scroll") return true;
        parent = parent.parentElement;
      }
      return false;
    }

    document.querySelectorAll("*").forEach((el) => {
      const rect = (el as HTMLElement).getBoundingClientRect();
      if (rect.right > vw + 1 && !isInsideScrollableX(el)) {
        overflowing.push(`${el.tagName}.${[...(el as HTMLElement).classList].join(".")} right=${Math.round(rect.right)} > vw=${vw}`);
      }
    });
    return overflowing.slice(0, 5); // cap at 5 for readability
  });
  expect(overflow, `Horizontal overflow: ${overflow.join("\n")}`).toHaveLength(0);
}

// ─── Helper: navigate to a page and wait for it to settle ────────────────────

async function goTo(page: Page, path: string) {
  await page.goto(`${BASE}${path}`, { waitUntil: "domcontentloaded" });
  await page.waitForLoadState("domcontentloaded");
}

// ═════════════════════════════════════════════════════════════════════════════
// Section 82 — Mobile chrome
// ═════════════════════════════════════════════════════════════════════════════

test.describe("82 — Mobile chrome", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    const context = await browser.newContext({ viewport: MOBILE_VIEWPORT });
    page = await context.newPage();
    await mockConversations(page);
    await injectAuth(page);
    await goTo(page, "/");
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  // ── 82.1  Desktop sidebar hidden ─────────────────────────────────────────

  test("82.1 desktop sidebar is hidden at 390px width", async () => {
    // The Sidebar component renders with class "hidden md:flex"
    // At 390px it should not be visible
    const sidebar = page.locator("aside, nav").filter({ hasText: /dashboard/i }).first();
    // The desktop sidebar is conditionally hidden — check body scrollWidth didn't overflow
    // and that the sidebar element is not in the flow
    const sidebarEl = page.locator('[class*="hidden md:flex"]').first();
    // At mobile viewport, "hidden md:flex" means display:none
    await expect(sidebarEl).not.toBeVisible();
  });

  // ── 82.2  Mobile bottom nav is visible ───────────────────────────────────

  test("82.2 mobile bottom nav bar is visible", async () => {
    const nav = page.locator("nav.fixed.inset-x-0.bottom-0");
    await expect(nav).toBeVisible();
  });

  // ── 82.3  Mobile bottom nav has 4 primary tabs + More ────────────────────

  test("82.3 bottom nav contains 4 primary tabs and a More button", async () => {
    const nav = page.locator("nav.fixed.inset-x-0.bottom-0");
    // The Home tab renders its i18n label "nav.dashboard" → "Dashboard".
    await expect(nav.getByRole("link", { name: "Dashboard" })).toBeVisible();
    await expect(nav.getByRole("link", { name: "Messages" })).toBeVisible();
    await expect(nav.getByRole("link", { name: "Files" })).toBeVisible();
    await expect(nav.getByRole("link", { name: "Shop" })).toBeVisible();
    await expect(nav.getByRole("button", { name: "More" })).toBeVisible();
  });

  // ── 82.4  Hamburger button is visible in header ───────────────────────────

  test("82.4 hamburger menu button is visible in the header", async () => {
    // Header has a button with aria-label="Open menu" that is md:hidden
    const hamburger = page.getByRole("button", { name: "Open menu" });
    await expect(hamburger).toBeVisible();
  });

  // ── 82.5  Hamburger opens the slide-in drawer ─────────────────────────────

  test("82.5 tapping hamburger opens the slide-in nav drawer", async () => {
    const hamburger = page.getByRole("button", { name: "Open menu" });
    await hamburger.click();
    // Scope to the Sheet dialog to avoid matching hidden desktop sidebar elements.
    // Use an exact link match — plain getByText("Dashboard") also matches the
    // "Fleet Dashboard" / "Project Dashboard" nav links (strict-mode violation).
    const drawer = page.getByRole("dialog");
    await expect(
      drawer.getByRole("link", { name: "Dashboard", exact: true }),
    ).toBeVisible({ timeout: 5_000 });
    // Drawer should list navigation groups
    await expect(drawer.getByText("Messages")).toBeVisible();
  });

  // ── 82.6  Nav drawer item closes drawer and navigates ────────────────────

  test("82.6 tapping a drawer nav item navigates and closes the drawer", async () => {
    // Drawer should still be open from 82.5; if not, re-open it
    const hamburger = page.getByRole("button", { name: "Open menu" });
    const isOpen = await page.getByRole("dialog").isVisible().catch(() => false);
    if (!isOpen) await hamburger.click();

    // Click "Settings" in the drawer
    const settingsLink = page.getByRole("dialog").getByRole("link", { name: "Settings" });
    await settingsLink.click();
    await expect(page).toHaveURL(/\/settings/, { timeout: 8_000 });
    // Drawer should be closed
    await expect(page.getByRole("dialog")).not.toBeVisible({ timeout: 5_000 });
  });

  // ── 82.7  More sheet opens with extra links ───────────────────────────────

  test("82.7 tapping More opens bottom sheet with extra links", async () => {
    await goTo(page, "/");
    const moreBtn = page.locator("nav.fixed.inset-x-0.bottom-0").getByRole("button", { name: "More" });
    await moreBtn.click();
    // The bottom Sheet should appear with "More" as heading
    await expect(page.getByRole("dialog").getByRole("heading", { name: "More" })).toBeVisible({ timeout: 5_000 });
    // Should contain secondary links
    await expect(page.getByRole("dialog").getByRole("button", { name: "Feed" })).toBeVisible();
    await expect(page.getByRole("dialog").getByRole("button", { name: "Settings" })).toBeVisible();
    // Close it
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).not.toBeVisible({ timeout: 5_000 });
  });

  // ── 82.8  Theme dropdown opens and shows all three options ────────────────

  test("82.8 theme picker dropdown shows System / Light / Dark options", async () => {
    const themeBtn = page.getByRole("button", { name: /theme:/i });
    await themeBtn.click();
    await expect(page.getByRole("menuitem", { name: /system/i })).toBeVisible({ timeout: 5_000 });
    await expect(page.getByRole("menuitem", { name: /light/i })).toBeVisible();
    await expect(page.getByRole("menuitem", { name: /dark/i })).toBeVisible();
    // Close
    await page.keyboard.press("Escape");
  });

  // ── 82.9  Selecting Dark theme applies .dark class ────────────────────────

  test("82.9 selecting Dark theme applies .dark to <html>", async () => {
    const themeBtn = page.getByRole("button", { name: /theme:/i });
    await themeBtn.click();
    await page.getByRole("menuitem", { name: /dark/i }).click();
    const hasDark = await page.evaluate(() => document.documentElement.classList.contains("dark"));
    expect(hasDark).toBe(true);

    // Switch back to system
    await themeBtn.click();
    await page.getByRole("menuitem", { name: /system/i }).click();
  });

  // ── 82.10  No horizontal overflow on home page ────────────────────────────

  test("82.10 home page has no horizontal overflow at 390px", async () => {
    await goTo(page, "/");
    await page.waitForTimeout(500); // let layout settle
    await assertNoHorizontalOverflow(page);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Section 83 — Mobile page usability
// ═════════════════════════════════════════════════════════════════════════════

test.describe("83 — Mobile page usability", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    const context = await browser.newContext({ viewport: MOBILE_VIEWPORT });
    page = await context.newPage();
    await mockConversations(page);
    await injectAuth(page);
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  // ── 83.1  Messages — only one panel visible at a time ────────────────────

  test("83.1 Messages page shows conversation list panel full-width (no side-by-side)", async () => {
    await goTo(page, "/messages");
    // On mobile, only the conversation list should be visible (no ConversationView panel)
    // The conversation list panel should be full-width
    const listPanel = page.locator('[class*="md:w-72"], [class*="md:w-80"]').first();
    const box = await listPanel.boundingBox();
    if (box) {
      // On mobile this panel should fill the full viewport width (or near it)
      expect(box.width).toBeGreaterThan(300);
    }
    // No horizontal overflow
    await assertNoHorizontalOverflow(page);
  });

  // ── 83.2  Settings — Appearance card is visible ───────────────────────────

  test("83.2 Settings page shows Appearance card on mobile", async () => {
    await goTo(page, "/settings");
    await expect(page.getByText("Appearance")).toBeVisible({ timeout: 8_000 });
    await expect(page.getByText("Theme")).toBeVisible();
  });

  // ── 83.3  Appearance theme picker cards are all visible ──────────────────

  test("83.3 all three theme option cards fit in viewport without overflow", async () => {
    await goTo(page, "/settings");
    // Wait for Appearance section to render
    await expect(page.getByText("Theme")).toBeVisible({ timeout: 8_000 });

    // Each theme button should be visible
    await expect(page.getByRole("button", { name: /system/i }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: /light/i }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: /dark/i }).first()).toBeVisible();

    // No overflow
    await assertNoHorizontalOverflow(page);
  });

  // ── 83.4  Appearance picker — click Dark, check persisted ────────────────

  test("83.4 clicking Dark in Settings Appearance card applies and remembers theme", async () => {
    await goTo(page, "/settings");
    await expect(page.getByText("Theme")).toBeVisible({ timeout: 8_000 });

    // Click the "Dark" card button
    await page.getByRole("button", { name: /dark/i }).first().click();
    const hasDark = await page.evaluate(() => document.documentElement.classList.contains("dark"));
    expect(hasDark).toBe(true);

    // Check localStorage persisted it
    const stored = await page.evaluate(() => {
      const raw = localStorage.getItem("ui-store");
      return raw ? JSON.parse(raw) : null;
    });
    expect(stored?.state?.theme).toBe("dark");

    // Reset to system
    await page.getByRole("button", { name: /system/i }).first().click();
  });

  // ── 83.5  Add Address dialog — opens, scrollable, usable ─────────────────

  test("83.5 Add Address dialog opens fully visible and form fields are reachable", async () => {
    await page.route("**/ui/addresses**", (route) => {
      if (route.request().method() === "GET")
        route.fulfill({ status: 200, contentType: "application/json", body: "[]" });
      else route.fallback();
    });

    // Addresses are on /profile under the "Addresses" tab
    await goTo(page, "/profile");
    // Click the Addresses tab to reveal the Addresses component
    await page.getByRole("tab", { name: "Addresses" }).click();
    const addAddrBtn = page.getByRole("button", { name: /add address/i });
    await expect(addAddrBtn).toBeVisible({ timeout: 8_000 });
    await addAddrBtn.click();

    // DialogTitle should appear — use heading role which is more stable than dialog role
    const dialogTitle = page.getByRole("heading", { name: /add address/i });
    await expect(dialogTitle).toBeVisible({ timeout: 8_000 });

    // All key fields should be reachable (scroll into view if needed)
    const line1 = page.getByLabel(/address line 1/i);
    await line1.scrollIntoViewIfNeeded();
    await expect(line1).toBeVisible();

    const validateBtn = page.getByRole("button", { name: /validate address/i });
    await validateBtn.scrollIntoViewIfNeeded();
    await expect(validateBtn).toBeVisible();

    // Dialog content should not be wider than the viewport
    const dialogContent = page.locator('[role="dialog"]');
    if (await dialogContent.count() > 0) {
      const dialogBox = await dialogContent.first().boundingBox();
      if (dialogBox) {
        expect(dialogBox.width).toBeLessThanOrEqual(MOBILE_VIEWPORT.width + 2);
      }
    }

    // Close
    await page.keyboard.press("Escape");
    await expect(dialogTitle).not.toBeVisible({ timeout: 5_000 });
  });

  // ── 83.6  Shop — category sidebar hidden on mobile ───────────────────────

  test("83.6 Shop page hides category sidebar on mobile (no overflow)", async () => {
    await goTo(page, "/shop");
    await page.waitForTimeout(400);
    // The <aside class="hidden ... md:block"> should not be visible
    const aside = page.locator("aside.hidden");
    if (await aside.count() > 0) {
      await expect(aside.first()).not.toBeVisible();
    }
    await assertNoHorizontalOverflow(page);
  });

  // ── 83.7  Feed — loads without overflow ──────────────────────────────────

  test("83.7 Feed page loads without horizontal overflow", async () => {
    await goTo(page, "/feed");
    await page.waitForTimeout(400);
    await assertNoHorizontalOverflow(page);
  });

  // ── 83.8  Profile page — no overflow ─────────────────────────────────────

  test("83.8 Profile page loads without horizontal overflow", async () => {
    await goTo(page, "/profile");
    await page.waitForTimeout(400);
    await assertNoHorizontalOverflow(page);
  });

  // ── 83.9  Bottom nav primary tabs navigate correctly ─────────────────────

  test("83.9 tapping Files tab in bottom nav navigates to /files", async () => {
    await goTo(page, "/");
    const nav = page.locator("nav.fixed.inset-x-0.bottom-0");
    await nav.getByRole("link", { name: "Files" }).click();
    await expect(page).toHaveURL(/\/files/, { timeout: 8_000 });
  });

  // ── 83.10  More sheet — Settings link navigates ───────────────────────────

  test("83.10 More sheet Settings button navigates to /settings", async () => {
    await goTo(page, "/");
    const moreBtn = page.locator("nav.fixed.inset-x-0.bottom-0").getByRole("button", { name: "More" });
    await moreBtn.click();
    await expect(page.getByRole("dialog").getByRole("heading", { name: "More" })).toBeVisible({ timeout: 5_000 });
    await page.getByRole("dialog").getByRole("button", { name: "Settings" }).click();
    await expect(page).toHaveURL(/\/settings/, { timeout: 8_000 });
    // Sheet should be closed after navigation
    await expect(page.getByRole("dialog")).not.toBeVisible({ timeout: 5_000 });
  });
});
