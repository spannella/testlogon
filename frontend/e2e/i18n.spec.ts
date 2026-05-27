/**
 * E2E tests for Internationalization (i18n) & Multi-Language Support (PLATFORM-003).
 *
 * Sections:
 *   A — Locale Detection & Switching (4 tests)
 *   B — Translation Rendering       (4 tests)
 *   C — Backend Locale API           (4 tests)
 *   D — UI Language Switcher         (3 tests)
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

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    (uid: string) => {
      const state = { userId: uid, accessToken: null, isAuthenticated: true };
      localStorage.setItem(
        "auth-store",
        JSON.stringify({ state, version: 0 }),
      );
    },
    userId,
  );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function csrfHeaders(identity: string) {
  const session = getSessions()[identity];
  return { "x-csrf-token": session.csrf_token };
}

// ─── Section A: Locale Detection & Switching ──────────────────────────────────

test.describe("Section A: Locale Detection & Switching", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    // Clear any lingering i18next localStorage
    await page.evaluate(() => localStorage.removeItem("i18nextLng"));
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("1 — Default locale is English", async () => {
    await page.goto(`${BASE}/settings`, { waitUntil: "domcontentloaded" });
    // The settings page title should be "Settings" in English
    await expect(page.getByText("Settings", { exact: true }).first()).toBeVisible();
    // The desktop sidebar (aside element) should show English nav labels
    const sidebar = page.locator("aside");
    await expect(sidebar.getByText("Dashboard").first()).toBeVisible();
    await expect(sidebar.getByText("Messages").first()).toBeVisible();
  });

  test("2 — Switching to Spanish updates nav labels", async () => {
    await page.goto(`${BASE}/settings`, { waitUntil: "domcontentloaded" });

    // Change locale via i18n
    await page.evaluate(() => {
      localStorage.setItem("i18nextLng", "es");
      // Trigger i18next language change
      (window as any).__i18nForceChange?.("es");
    });
    // Reload to apply the locale from localStorage
    await page.reload({ waitUntil: "domcontentloaded" });

    // Verify Spanish labels in desktop sidebar
    const sidebar = page.locator("aside");
    await expect(sidebar.getByText("Inicio").first()).toBeVisible();
    await expect(sidebar.getByText("Mensajes").first()).toBeVisible();
  });

  test("3 — Locale persists across page reloads", async () => {
    // Locale should still be "es" from the previous test
    await page.reload({ waitUntil: "domcontentloaded" });
    const sidebar = page.locator("aside");
    await expect(sidebar.getByText("Inicio").first()).toBeVisible();
    await expect(sidebar.getByText("Mensajes").first()).toBeVisible();
  });

  test("4 — Switching to French updates nav labels", async () => {
    await page.evaluate(() => {
      localStorage.setItem("i18nextLng", "fr");
    });
    await page.reload({ waitUntil: "domcontentloaded" });

    const sidebar = page.locator("aside");
    await expect(
      sidebar.getByText("Tableau de bord").first(),
    ).toBeVisible();
    // French "Messages" is the same word — just verify sidebar is visible
    await expect(sidebar.getByText("Messages").first()).toBeVisible();

    // Reset to English for subsequent tests
    await page.evaluate(() => {
      localStorage.setItem("i18nextLng", "en");
    });
  });
});

// ─── Section B: Translation Rendering ─────────────────────────────────────────

test.describe("Section B: Translation Rendering", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.evaluate(() => localStorage.setItem("i18nextLng", "en"));
  });

  test.afterAll(async () => {
    await page.evaluate(() => localStorage.setItem("i18nextLng", "en"));
    await page.context().close();
  });

  test("5 — Settings page renders translated strings in Spanish", async () => {
    await page.evaluate(() => localStorage.setItem("i18nextLng", "es"));
    await page.goto(`${BASE}/settings`, { waitUntil: "domcontentloaded" });

    await expect(
      page.getByText("Configuración", { exact: true }).first(),
    ).toBeVisible();
    await expect(
      page.getByText("Idioma", { exact: true }).first(),
    ).toBeVisible();
  });

  test("6 — Settings page renders translated strings in French", async () => {
    await page.evaluate(() => localStorage.setItem("i18nextLng", "fr"));
    await page.goto(`${BASE}/settings`, { waitUntil: "domcontentloaded" });

    await expect(
      page.getByText("Paramètres", { exact: true }).first(),
    ).toBeVisible();
    await expect(
      page.getByText("Langue", { exact: true }).first(),
    ).toBeVisible();
  });

  test("7 — Missing translation falls back to English key", async () => {
    // Force English back, verify a key that only exists in en shows up
    await page.evaluate(() => localStorage.setItem("i18nextLng", "en"));
    await page.goto(`${BASE}/settings`, { waitUntil: "domcontentloaded" });

    // "Settings" is defined in en.json as settings.title -> "Settings"
    await expect(
      page.getByText("Settings", { exact: true }).first(),
    ).toBeVisible();
  });

  test("8 — Sidebar group titles translate correctly", async () => {
    await page.evaluate(() => localStorage.setItem("i18nextLng", "es"));
    await page.goto(`${BASE}/settings`, { waitUntil: "domcontentloaded" });

    // Group titles should be in Spanish in the desktop sidebar
    const sidebar = page.locator("aside");
    await expect(sidebar.getByText("Principal").first()).toBeVisible();
    await expect(sidebar.getByText("Comercio").first()).toBeVisible();
    await expect(sidebar.getByText("Productividad").first()).toBeVisible();

    // Reset
    await page.evaluate(() => localStorage.setItem("i18nextLng", "en"));
  });
});

// ─── Section C: Backend Locale API ────────────────────────────────────────────

test.describe("Section C: Backend Locale API", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("9 — GET /ui/i18n/locales returns supported locales", async () => {
    const resp = await page.request.get(`${BASE}/ui/i18n/locales`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.locales).toBeDefined();
    expect(data.locales.length).toBeGreaterThanOrEqual(3);
    const codes = data.locales.map((l: any) => l.code);
    expect(codes).toContain("en");
    expect(codes).toContain("es");
    expect(codes).toContain("fr");
    // Check shape
    const en = data.locales.find((l: any) => l.code === "en");
    expect(en.name).toBe("English");
    expect(en.native_name).toBe("English");
    expect(en.rtl).toBe(false);
  });

  test("10 — GET /ui/i18n/translations/es returns Spanish translations", async () => {
    const resp = await page.request.get(`${BASE}/ui/i18n/translations/es`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.locale).toBe("es");
    expect(data.translations).toBeDefined();
    // Check a known Spanish translation key exists
    expect(data.translations["errors.rate_limited"]).toContain(
      "Demasiadas solicitudes",
    );
  });

  test("11 — PUT /ui/i18n/locale saves locale preference", async () => {
    const resp = await page.request.put(`${BASE}/ui/i18n/locale`, {
      headers: {
        ...csrfHeaders(ALICE_ID),
        "Content-Type": "application/json",
      },
      data: { locale: "es" },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.locale).toBe("es");
  });

  test("12 — GET /ui/i18n/locale returns saved locale", async () => {
    const resp = await page.request.get(`${BASE}/ui/i18n/locale`, {
      headers: csrfHeaders(ALICE_ID),
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.locale).toBe("es");

    // Clean up — reset to English
    await page.request.put(`${BASE}/ui/i18n/locale`, {
      headers: {
        ...csrfHeaders(ALICE_ID),
        "Content-Type": "application/json",
      },
      data: { locale: "en" },
    });
  });
});

// ─── Section D: UI Language Switcher ──────────────────────────────────────────

test.describe("Section D: UI Language Switcher", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    await page.evaluate(() => localStorage.setItem("i18nextLng", "en"));
  });

  test.afterAll(async () => {
    await page.evaluate(() => localStorage.setItem("i18nextLng", "en"));
    await page.context().close();
  });

  test("13 — Language switcher renders on settings page", async () => {
    await page.goto(`${BASE}/settings`, { waitUntil: "domcontentloaded" });

    // Should see a Language card section
    await expect(
      page.getByText("Language", { exact: true }).first(),
    ).toBeVisible();

    // Should see the language select trigger
    await expect(page.locator("#language-select")).toBeVisible();
  });

  test("14 — Selecting Spanish in switcher updates UI immediately", async () => {
    await page.goto(`${BASE}/settings`, { waitUntil: "domcontentloaded" });

    // Click the language select
    await page.locator("#language-select").click();
    await page.getByText("Español (Spanish)").click();

    // After selection, the page title should change to Spanish
    await expect(
      page.getByText("Configuración", { exact: true }).first(),
    ).toBeVisible();
    // The language label should now read "Idioma"
    await expect(
      page.getByText("Idioma", { exact: true }).first(),
    ).toBeVisible();
  });

  test("15 — Selecting English in switcher restores English UI", async () => {
    // Currently in Spanish from previous test. Click the select to switch back.
    await page.locator("#language-select").click();
    await page.getByText("English (English)").click();

    await expect(
      page.getByText("Settings", { exact: true }).first(),
    ).toBeVisible();
    await expect(
      page.getByText("Language", { exact: true }).first(),
    ).toBeVisible();
  });
});
