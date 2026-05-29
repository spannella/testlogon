/**
 * E2E tests for PWA-001: Web App Manifest & Installable PWA.
 *
 * Sections:
 *   90 - Manifest accessibility (5 tests)
 *   91 - HTML meta tags for PWA (5 tests)
 *   92 - Install prompt component (5 tests)
 *
 * Auth: Cookie-based session for Alice (e2e_alice@test.local) with CSRF.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";

// ─── Session bootstrap ───────────────────────────────────────────────────────

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
  // Set auth store in localStorage so ProtectedRoute allows access
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

// ─── Helper: fire a mock beforeinstallprompt event ────────────────────────────

/**
 * Fires a beforeinstallprompt event on the page. Should be called after
 * the AppShell has mounted (i.e., after confirming the Dashboard is visible).
 */
async function fireBeforeInstallPrompt(page: Page) {
  await page.evaluate(() => {
    const event = new Event("beforeinstallprompt", { cancelable: true });
    (event as any).prompt = () => Promise.resolve();
    (event as any).userChoice = Promise.resolve({
      outcome: "dismissed",
      platform: "web",
    });
    (event as any).platforms = ["web"];
    window.dispatchEvent(event);
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Section 90 · Manifest accessibility
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("90 · Manifest accessibility", () => {
  test("90.1 manifest.json is served with correct content-type", async ({
    request,
  }) => {
    const resp = await request.get(`${BASE}/manifest.json`);
    expect(resp.status()).toBe(200);
    const contentType = resp.headers()["content-type"] ?? "";
    expect(contentType).toContain("application/json");
  });

  test("90.2 manifest.json contains required PWA fields", async ({
    request,
  }) => {
    const resp = await request.get(`${BASE}/manifest.json`);
    const manifest = await resp.json();
    expect(manifest.name).toBe("Control Panel");
    expect(manifest.short_name).toBe("CtrlPanel");
    expect(manifest.display).toBe("standalone");
    expect(manifest.start_url).toBe("/");
    expect(manifest.scope).toBe("/");
    expect(manifest.theme_color).toBe("#0f172a");
    expect(manifest.background_color).toBe("#ffffff");
    expect(manifest.icons.length).toBeGreaterThanOrEqual(6);
  });

  test("90.3 manifest has at least one 192px and one 512px icon", async ({
    request,
  }) => {
    const resp = await request.get(`${BASE}/manifest.json`);
    const manifest = await resp.json();
    const sizes = manifest.icons.map(
      (i: { sizes: string }) => i.sizes,
    );
    expect(sizes).toContain("192x192");
    expect(sizes).toContain("512x512");
  });

  test("90.4 manifest has at least one maskable icon", async ({
    request,
  }) => {
    const resp = await request.get(`${BASE}/manifest.json`);
    const manifest = await resp.json();
    const maskable = manifest.icons.filter(
      (i: { purpose?: string }) => i.purpose === "maskable",
    );
    expect(maskable.length).toBeGreaterThanOrEqual(1);
  });

  test("90.5 all manifest icon URLs are reachable", async ({ request }) => {
    const resp = await request.get(`${BASE}/manifest.json`);
    const manifest = await resp.json();
    for (const icon of manifest.icons) {
      const iconResp = await request.get(`${BASE}${icon.src}`);
      expect(iconResp.status()).toBe(200);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  Section 91 · HTML meta tags for PWA
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("91 · HTML meta tags for PWA", () => {
  test("91.1 index.html contains manifest link tag", async ({ page }) => {
    await page.goto(`${BASE}/login`);
    const link = page.locator('link[rel="manifest"]');
    await expect(link).toHaveAttribute("href", "/manifest.json");
  });

  test("91.2 theme-color meta tag exists with correct value", async ({
    page,
  }) => {
    await page.goto(`${BASE}/login`);
    const meta = page.locator('meta[name="theme-color"]').first();
    await expect(meta).toHaveAttribute("content", "#0f172a");
  });

  test("91.3 apple-mobile-web-app-capable meta exists", async ({ page }) => {
    await page.goto(`${BASE}/login`);
    const meta = page.locator('meta[name="apple-mobile-web-app-capable"]');
    await expect(meta).toHaveAttribute("content", "yes");
  });

  test("91.4 apple-mobile-web-app-title matches manifest name", async ({
    page,
  }) => {
    await page.goto(`${BASE}/login`);
    const meta = page.locator('meta[name="apple-mobile-web-app-title"]');
    await expect(meta).toHaveAttribute("content", "Control Panel");
  });

  test("91.5 apple-touch-icon link exists and is reachable", async ({
    page,
    request,
  }) => {
    await page.goto(`${BASE}/login`);
    const link = page.locator('link[rel="apple-touch-icon"]');
    await expect(link).toHaveCount(1);
    const href = await link.getAttribute("href");
    expect(href).toBeTruthy();
    const iconResp = await request.get(`${BASE}${href}`);
    expect(iconResp.status()).toBe(200);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  Section 92 · Install prompt component
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("92 · Install prompt component", () => {
  test("92.1 install prompt appears when beforeinstallprompt fires", async ({
    page,
  }) => {
    await injectAuth(page);
    // Clear any previous dismissal
    await page.addInitScript(() => {
      localStorage.removeItem("pwa_install_dismissed");
    });
    await page.goto(`${BASE}/`);
    // Wait for AppShell to mount (Dashboard heading confirms it)
    await page.locator("#main-content").waitFor({ timeout: 10000 });

    await fireBeforeInstallPrompt(page);

    const banner = page.getByTestId("install-prompt");
    await expect(banner).toBeVisible({ timeout: 5000 });
    await expect(
      page.getByText(/install control panel/i),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Install", exact: true }),
    ).toBeVisible();
  });

  test("92.2 dismiss button hides prompt and sets localStorage flag", async ({
    page,
  }) => {
    await injectAuth(page);
    await page.addInitScript(() => {
      localStorage.removeItem("pwa_install_dismissed");
    });
    await page.goto(`${BASE}/`);
    await page.locator("#main-content").waitFor({ timeout: 10000 });

    await fireBeforeInstallPrompt(page);

    const banner = page.getByTestId("install-prompt");
    await expect(banner).toBeVisible({ timeout: 5000 });

    await page.getByLabel(/dismiss install prompt/i).click();
    await expect(banner).not.toBeVisible();

    const flag = await page.evaluate(() =>
      localStorage.getItem("pwa_install_dismissed"),
    );
    expect(flag).toBeTruthy();
    expect(Number(flag)).toBeGreaterThan(Date.now() - 10_000);
  });

  test("92.3 prompt does not show again within 30-day cooldown", async ({
    page,
  }) => {
    await injectAuth(page);
    // Set dismissal flag to 5 minutes ago (within 30-day cooldown)
    await page.addInitScript(() => {
      localStorage.setItem(
        "pwa_install_dismissed",
        String(Date.now() - 5 * 60 * 1000),
      );
    });
    await page.goto(`${BASE}/`);
    await page.locator("#main-content").waitFor({ timeout: 10000 });

    await fireBeforeInstallPrompt(page);

    // Wait enough time for the event to be processed
    await page.waitForTimeout(1000);
    await expect(
      page.getByTestId("install-prompt"),
    ).not.toBeVisible();
  });

  test("92.4 prompt shows again after 30-day cooldown expires", async ({
    page,
  }) => {
    await injectAuth(page);
    // Set dismissal flag to 31 days ago (cooldown expired)
    await page.addInitScript(() => {
      localStorage.setItem(
        "pwa_install_dismissed",
        String(Date.now() - 31 * 86400 * 1000),
      );
    });
    await page.goto(`${BASE}/`);
    await page.locator("#main-content").waitFor({ timeout: 10000 });

    await fireBeforeInstallPrompt(page);

    await expect(page.getByTestId("install-prompt")).toBeVisible({
      timeout: 5000,
    });
  });

  test("92.5 manifest shortcuts reference valid routes", async ({
    request,
  }) => {
    const resp = await request.get(`${BASE}/manifest.json`);
    const manifest = await resp.json();
    const validRoutes = ["/messages", "/feed", "/calendar"];
    for (const shortcut of manifest.shortcuts ?? []) {
      expect(validRoutes).toContain(shortcut.url);
    }
  });
});
