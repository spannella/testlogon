/**
 * E2E tests for the theme switcher (Settings → Appearance + Header dropdown).
 *
 * Sections:
 *   96 — Theme switcher: color scheme changes, text visibility, and persistence
 *
 * What these tests verify (beyond the basic aria-pressed state tested in
 * user-journey.spec.ts §88):
 *   - The actual CSS class and computed color values change correctly
 *   - Text elements remain visible and have adequate contrast in every theme
 *   - The selected theme survives page reloads (localStorage persistence)
 *   - The selected theme survives client-side navigation between pages
 *   - The header dropdown and the Settings cards stay in sync with each other
 *   - System theme follows the OS dark-mode media query in real time
 *
 * Architecture note — Tailwind v4 `@theme inline`:
 *   Light-mode utility classes (e.g. bg-background) are compiled to STATIC
 *   HSL values; they don't use CSS custom properties at runtime in light mode.
 *   Dark-mode overrides are applied via `.dark { --color-xxx }` custom properties
 *   on <html>.  This means:
 *     • In DARK mode  → `--color-background` / `--color-foreground` ARE readable
 *       via getComputedStyle(html).getPropertyValue(...)
 *     • In LIGHT mode → those vars are absent at runtime; we instead inspect the
 *       body's computed backgroundColor / color which were inlined at build time.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub:    string;
  session_id:  string;
  csrf_token:  string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean;
    sameSite: "Lax" | "Strict" | "None"; expires: number;
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

// ─── Auth / page helpers ──────────────────────────────────────────────────────

/**
 * Prevent the server-side theme/preference fetches from clobbering the
 * client-set theme these tests rely on.
 *
 * These tests assert pure *client-side* (localStorage / uiStore) theme
 * persistence. Two product mechanisms otherwise override the local theme on a
 * fresh page load:
 *   - AppShell → loadServerPreferences() (`GET /ui/settings/preferences`)
 *     writes the server's saved theme into the store.
 *   - ThemeProvider → getThemeCustomization() (`GET /ui/theme`) applies the
 *     server's saved mode.
 * Because the whole suite shares the Alice user, earlier tests' debounced
 * server syncs leave a stale theme on the server that would otherwise win.
 * Stubbing both GETs to "no saved preference" makes the local-persistence
 * assertions deterministic without changing product behavior.
 */
async function stubServerTheme(page: Page) {
  await page.route("**/ui/settings/preferences", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ preferences: {} }),
      });
      return;
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
  });
  await page.route("**/ui/theme", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          theme: {
            mode: "system",
            accent_color: "blue",
            custom_accent_hex: null,
            font_scale: "default",
            density: "comfortable",
            preset: "default",
            high_contrast: false,
          },
        }),
      });
      return;
    }
    await route.continue();
  });
}

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await stubServerTheme(page);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function gotoSettings(page: Page) {
  const settled = page.waitForResponse(
    (r) =>
      r.url().includes("/messaging/conversations") &&
      r.request().method() === "GET" &&
      !r.url().match(/\/conversations\/[^/]+$/),
    { timeout: 20_000 },
  );
  await page.goto(`${BASE}/settings`, { waitUntil: "load" });
  await settled.catch(() => {});
  await expect(page.getByText("Theme").first()).toBeVisible({ timeout: 8_000 });
}

// ─── Color / visibility helpers ───────────────────────────────────────────────

/**
 * Return the current value of a CSS custom property on <html>.
 * In dark mode, .dark sets --color-background / --color-foreground.
 * In light mode these are empty (inlined via @theme inline at build time).
 */
async function getCSSVar(page: Page, name: string): Promise<string> {
  return page.evaluate(
    (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim(),
    name,
  );
}

/**
 * Parse the lightness percentage out of an HSL string like "hsl(222 84% 5%)".
 * HSL format: hsl(hue saturation% lightness%) — lightness is the THIRD number.
 * Returns -1 if the string is empty or unparseable.
 */
function hslLightness(hsl: string): number {
  if (!hsl) return -1;
  // Match all numbers (with optional decimal), grab the third one = lightness
  const nums = [...hsl.matchAll(/(\d+(?:\.\d+)?)/g)].map((m) => parseFloat(m[1]));
  // nums[0] = hue, nums[1] = saturation, nums[2] = lightness
  return nums.length >= 3 ? nums[2] : -1;
}

/** Parse "rgb(r, g, b)" → [r, g, b] integers. */
function parseRgb(rgb: string): [number, number, number] {
  const m = rgb.match(/\d+/g);
  if (!m || m.length < 3) throw new Error(`Cannot parse: ${rgb}`);
  return [parseInt(m[0]), parseInt(m[1]), parseInt(m[2])];
}

/** Perceived luminance 0–255 (standard formula). */
function luminance(r: number, g: number, b: number): number {
  return 0.299 * r + 0.587 * g + 0.114 * b;
}

/** True when <html> has the "dark" class. */
async function hasDarkClass(page: Page): Promise<boolean> {
  return page.evaluate(() => document.documentElement.classList.contains("dark"));
}

/** Read the persisted theme from localStorage. */
async function getStoredTheme(page: Page): Promise<string> {
  return page.evaluate(() => {
    const raw = localStorage.getItem("ui-store");
    if (!raw) return "";
    try { return JSON.parse(raw).state?.theme ?? ""; } catch { return ""; }
  });
}

/** Computed body background-color (RGB string). In light mode this reflects the inlined @theme value. */
async function getBodyBgRgb(page: Page): Promise<string> {
  return page.evaluate(() => getComputedStyle(document.body).backgroundColor);
}

/** Computed body color (foreground text). */
async function getBodyColorRgb(page: Page): Promise<string> {
  return page.evaluate(() => getComputedStyle(document.body).color);
}

// ─── Button helpers ───────────────────────────────────────────────────────────

const settingsBtn = (page: Page, label: string) =>
  page.locator("button[aria-pressed]", { hasText: new RegExp(label, "i") });

// ─── Section 96 ───────────────────────────────────────────────────────────────

test.describe("96. Theme switcher — color scheme, visibility, and persistence", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    page = await browser.newPage();
    await injectAuth(page);
    // Always start from a known state: explicit light theme so tests begin predictably.
    await page.evaluate(() => {
      const data = { state: { theme: "light" }, version: 0 };
      localStorage.setItem("ui-store", JSON.stringify(data));
    });
    await gotoSettings(page);
  });

  test.afterAll(async () => {
    // Reset to system so we don't leave a dark theme for subsequent test files.
    await page.evaluate(() => {
      try {
        const data = { state: { theme: "system" }, version: 0 };
        localStorage.setItem("ui-store", JSON.stringify(data));
      } catch { /* ignore */ }
    });
    await page.close().catch(() => {});
  });

  // ── 96.1  Dark mode: .dark class applied ─────────────────────────────────

  test("96.1 selecting Dark adds the 'dark' class to <html>", async () => {
    await settingsBtn(page, "dark").click();
    await expect(settingsBtn(page, "dark")).toHaveAttribute("aria-pressed", "true");
    expect(await hasDarkClass(page)).toBe(true);
  });

  // ── 96.2  Dark mode: --color-background is a dark HSL value ──────────────

  test("96.2 dark mode: --color-background CSS variable has low lightness (< 15%)", async () => {
    // In dark mode the .dark block sets --color-background: hsl(222 84% 5%).
    // The @theme inline mechanism makes this readable via getComputedStyle(html).
    const bgVar = await getCSSVar(page, "--color-background");
    expect(bgVar, "CSS var should be set in dark mode").toBeTruthy();
    const lightness = hslLightness(bgVar);
    // hsl(222 84% 5%) → lightness 5%, well below 15%
    expect(lightness).toBeGreaterThan(0);
    expect(lightness).toBeLessThan(15);
  });

  // ── 96.3  Dark mode: --color-foreground is a light HSL value ─────────────

  test("96.3 dark mode: --color-foreground CSS variable has high lightness (> 85%)", async () => {
    const fgVar = await getCSSVar(page, "--color-foreground");
    expect(fgVar, "Foreground CSS var should be set in dark mode").toBeTruthy();
    const lightness = hslLightness(fgVar);
    // hsl(210 40% 98%) → lightness 98%, well above 85%
    expect(lightness).toBeGreaterThan(85);
  });

  // ── 96.4  Dark mode: foreground and background have high contrast ─────────

  test("96.4 dark mode: foreground lightness and background lightness differ by ≥ 70%", async () => {
    const bgLightness = hslLightness(await getCSSVar(page, "--color-background"));
    const fgLightness = hslLightness(await getCSSVar(page, "--color-foreground"));
    // bg ≈ 5%,  fg ≈ 98%  → difference ≈ 93%
    expect(Math.abs(fgLightness - bgLightness)).toBeGreaterThanOrEqual(70);
  });

  // ── 96.5  Dark mode: key text elements are visible ───────────────────────

  test("96.5 dark mode: heading and navigation labels are visible", async () => {
    await expect(page.getByText("Theme", { exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Settings", exact: true })).toBeVisible();
    // Sidebar nav link
    await expect(page.getByRole("link", { name: /messages/i }).first()).toBeVisible();
  });

  // ── 96.6  Light mode: .dark class removed ────────────────────────────────

  test("96.6 selecting Light removes the 'dark' class from <html>", async () => {
    await settingsBtn(page, "light").click();
    await expect(settingsBtn(page, "light")).toHaveAttribute("aria-pressed", "true");
    expect(await hasDarkClass(page)).toBe(false);
  });

  // ── 96.7  Light mode: body background is pale / near-white ───────────────

  test("96.7 light mode: body background-color has high luminance (> 230 / 255)", async () => {
    // bg-background compiled to hsl(210 40% 98%) ≈ rgb(248, 250, 252)
    const rgb = await getBodyBgRgb(page);
    const [r, g, b] = parseRgb(rgb);
    expect(luminance(r, g, b)).toBeGreaterThan(230);
  });

  // ── 96.8  Light mode: body text colour is dark ────────────────────────────

  test("96.8 light mode: body text colour has low luminance (< 30 / 255)", async () => {
    // text-foreground compiled to hsl(222 84% 5%) ≈ rgb(2, 8, 23)
    const rgb = await getBodyColorRgb(page);
    const [r, g, b] = parseRgb(rgb);
    expect(luminance(r, g, b)).toBeLessThan(30);
  });

  // ── 96.9  Light mode: key text elements remain visible ───────────────────

  test("96.9 light mode: heading and navigation labels are visible", async () => {
    await expect(page.getByText("Theme", { exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Settings", exact: true })).toBeVisible();
    await expect(page.getByRole("link", { name: /messages/i }).first()).toBeVisible();
  });

  // ── 96.10  Persistence: dark theme survives page reload ──────────────────

  test("96.10 dark theme persists after a full page reload", async () => {
    // Switch to dark
    await settingsBtn(page, "dark").click();
    await expect(settingsBtn(page, "dark")).toHaveAttribute("aria-pressed", "true");

    // Reload and wait for the settings page to be ready again
    const settled = page.waitForResponse(
      (r) => r.url().includes("/messaging/conversations") && r.request().method() === "GET",
      { timeout: 20_000 },
    );
    await page.reload({ waitUntil: "load" });
    await settled.catch(() => {});
    await expect(page.getByText("Theme", { exact: true })).toBeVisible({ timeout: 8_000 });

    // All three invariants must hold after reload:
    expect(await hasDarkClass(page)).toBe(true);
    expect(await getStoredTheme(page)).toBe("dark");
    await expect(settingsBtn(page, "dark")).toHaveAttribute("aria-pressed", "true");
  });

  // ── 96.11  Persistence: dark theme survives navigation ───────────────────

  test("96.11 dark theme persists when navigating to another page and back", async () => {
    // dark mode is active from 96.10 — navigate to /profile
    await page.goto(`${BASE}/profile`, { waitUntil: "load" });
    await expect(page.getByText(/profile/i).first()).toBeVisible({ timeout: 10_000 });
    expect(await hasDarkClass(page)).toBe(true);

    // Navigate back to settings — theme must still be dark
    await page.goto(`${BASE}/settings`, { waitUntil: "load" });
    await expect(page.getByText("Theme", { exact: true })).toBeVisible({ timeout: 8_000 });
    expect(await hasDarkClass(page)).toBe(true);
    await expect(settingsBtn(page, "dark")).toHaveAttribute("aria-pressed", "true");
  });

  // ── 96.12  Header dropdown switches theme ────────────────────────────────

  test("96.12 header theme dropdown can switch to Light and removes .dark class", async () => {
    // Header button label reflects current theme: "Theme: dark"
    const themeBtn = page.getByRole("button", { name: /theme:/i });
    await expect(themeBtn).toBeVisible({ timeout: 5_000 });
    await themeBtn.click();
    await page.getByRole("menuitem", { name: /light/i }).click();

    expect(await hasDarkClass(page)).toBe(false);
    expect(await getStoredTheme(page)).toBe("light");
  });

  // ── 96.13  Header and Settings cards stay in sync ────────────────────────

  test("96.13 Settings appearance cards reflect a theme change made via the header dropdown", async () => {
    // Currently light (from 96.12). Switch to dark via header dropdown.
    const themeBtn = page.getByRole("button", { name: /theme:/i });
    await themeBtn.click();
    await page.getByRole("menuitem", { name: /dark/i }).click();

    // Settings page is still open — its cards must update immediately.
    await expect(settingsBtn(page, "dark")).toHaveAttribute("aria-pressed", "true", { timeout: 3_000 });
    await expect(settingsBtn(page, "light")).toHaveAttribute("aria-pressed", "false");
  });

  // ── 96.14  Header button label tracks the active theme ───────────────────

  test("96.14 header theme button aria-label updates when theme changes", async () => {
    // Switch to light via Settings card
    await settingsBtn(page, "light").click();
    await expect(settingsBtn(page, "light")).toHaveAttribute("aria-pressed", "true");
    const themeBtn = page.getByRole("button", { name: /theme:/i });
    // aria-label="Theme: light"
    await expect(themeBtn).toHaveAttribute("aria-label", /light/i, { timeout: 3_000 });

    // Switch to dark — label should say "Theme: dark"
    await settingsBtn(page, "dark").click();
    await expect(settingsBtn(page, "dark")).toHaveAttribute("aria-pressed", "true");
    await expect(themeBtn).toHaveAttribute("aria-label", /dark/i, { timeout: 3_000 });
  });

  // ── 96.15  System theme: applies dark class when OS prefers dark ─────────

  test("96.15 system theme applies .dark class when browser emulates dark color scheme", async ({
    browser,
  }) => {
    const ctx = await browser.newContext({ colorScheme: "dark" });
    const p   = await ctx.newPage();
    await injectAuth(p);
    await p.evaluate(() => {
      localStorage.setItem("ui-store", JSON.stringify({ state: { theme: "system" }, version: 0 }));
    });
    const settled = p.waitForResponse(
      (r) => r.url().includes("/messaging/conversations") && r.request().method() === "GET",
      { timeout: 20_000 },
    );
    await p.goto(`${BASE}/settings`, { waitUntil: "load" });
    await settled.catch(() => {});
    await expect(p.getByText("Theme", { exact: true })).toBeVisible({ timeout: 8_000 });

    expect(await hasDarkClass(p)).toBe(true);
    await expect(p.locator("button[aria-pressed]", { hasText: /system/i }))
      .toHaveAttribute("aria-pressed", "true");
    await ctx.close();
  });

  // ── 96.16  System theme: no dark class when OS prefers light ─────────────

  test("96.16 system theme does NOT apply .dark class when browser emulates light color scheme", async ({
    browser,
  }) => {
    const ctx = await browser.newContext({ colorScheme: "light" });
    const p   = await ctx.newPage();
    await injectAuth(p);
    await p.evaluate(() => {
      localStorage.setItem("ui-store", JSON.stringify({ state: { theme: "system" }, version: 0 }));
    });
    const settled = p.waitForResponse(
      (r) => r.url().includes("/messaging/conversations") && r.request().method() === "GET",
      { timeout: 20_000 },
    );
    await p.goto(`${BASE}/settings`, { waitUntil: "load" });
    await settled.catch(() => {});
    await expect(p.getByText("Theme", { exact: true })).toBeVisible({ timeout: 8_000 });

    expect(await hasDarkClass(p)).toBe(false);
    await expect(p.locator("button[aria-pressed]", { hasText: /system/i }))
      .toHaveAttribute("aria-pressed", "true");
    await ctx.close();
  });

  // ── 96.17  Dark/light CSS vars differ significantly ───────────────────────

  test("96.17 dark mode background lightness (5%) is drastically lower than light mode (98%)", async () => {
    // Switch to dark and read the CSS var lightness (available in dark mode)
    await settingsBtn(page, "dark").click();
    await expect(settingsBtn(page, "dark")).toHaveAttribute("aria-pressed", "true");
    const darkBgVar     = await getCSSVar(page, "--color-background");
    const darkLightness = hslLightness(darkBgVar); // hsl(222 84% 5%) → 5

    // Light mode body bg is compiled as hsl(210 40% 98%) ≈ rgb(248, 250, 252).
    // Convert RGB luminance to a comparable 0-100 scale.
    await settingsBtn(page, "light").click();
    await expect(settingsBtn(page, "light")).toHaveAttribute("aria-pressed", "true");
    const lightRgb     = await getBodyBgRgb(page);
    const [r, g, b]    = parseRgb(lightRgb);
    const lightLumPct  = (luminance(r, g, b) / 255) * 100; // ≈ 97.7

    // dark ≈ 5%,  light ≈ 97.7%  → difference must exceed 75 percentage points
    expect(lightLumPct).toBeGreaterThan(80);     // light mode IS light
    expect(darkLightness).toBeLessThan(20);       // dark mode IS dark
    expect(lightLumPct - darkLightness).toBeGreaterThan(75); // they differ significantly
  });
});
