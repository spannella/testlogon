/**
 * E2E tests for the SuiteCRM GEO/MAP cluster (EVT-Geo, EVT-005..007).
 *
 * Sections:
 *   80 — CRM map feature flags (EVT-007) — API
 *   81 — Geocoded addresses list + re-geocode (EVT-005) — API
 *   82 — Proximity search (EVT-006) — API
 *   83 — CRM Maps UI
 *
 * Auth: uses e2e_admin_session_setup.py (all identities).
 *
 * Backend:
 *   GET   /ui/crm/maps/feature-flags          (ungated)
 *   GET   /ui/crm/maps/contacts/proximity     (gated: crm_geocoding + proximity flags)
 *   GET   /ui/crm/geocoding/addresses         (gated: crm_geocoding flag)
 *   PATCH /ui/crm/geocoding/addresses/{id}    (gated: crm_geocoding flag)
 *
 * NOTE: gated endpoints return 404 when the flags are OFF (their default).
 * Tests tolerate both the enabled and disabled flag states.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ──────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface AdminSessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name:     string;
    value:    string;
    domain:   string;
    path:     string;
    httpOnly: boolean;
    secure:   boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires:  number;
  }>;
}

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const s = sessions[identity];
  if (!s) throw new Error(`No session for identity ${identity}`);
  const ctx = await browser.newContext({ baseURL: BASE });
  await ctx.addCookies(
    s.cookies.map((c) => ({
      name: c.name,
      value: c.value,
      domain: "localhost",
      path: c.path || "/",
      httpOnly: c.httpOnly,
      secure: false,
      sameSite: c.sameSite,
      expires: c.expires,
    })),
  );
  // Seed the auth-store so the React route guard treats the page as
  // authenticated (cookie-only contexts otherwise redirect to /login).
  await ctx.addInitScript(
    ([userId, accessToken]: [string, string]) => {
      localStorage.setItem(
        "auth-store",
        JSON.stringify({ state: { userId, accessToken, isAuthenticated: true }, version: 0 }),
      );
    },
    [s.user_sub, s.access_token] as [string, string],
  );
  return ctx.newPage();
}

function csrf(identity: string): string {
  return getAdminSessions()[identity]!.csrf_token;
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  const qs = params ? "?" + new URLSearchParams(params).toString() : "";
  return page.request.get(`${API}${path}${qs}`);
}

async function apiPatch(page: Page, identity: string, path: string) {
  return page.request.patch(`${API}${path}`, {
    headers: { "x-csrf-token": csrf(identity) },
  });
}

// ─── Section 80 — Feature flags (EVT-007, ungated) ────────────────────────────

test.describe("Section 80 — CRM map feature flags (API)", () => {
  test("80.1 feature-flags returns flag state + map defaults", async ({ browser }) => {
    const page = await newIdentityPage(browser, "alice");
    const resp = await apiGet(page, "/ui/crm/maps/feature-flags");
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body).toHaveProperty("crm_geocoding_enabled");
    expect(typeof body.crm_geocoding_enabled).toBe("boolean");
    expect(typeof body.default_lat).toBe("number");
    expect(typeof body.default_lng).toBe("number");
    expect(typeof body.default_radius_km).toBe("number");
    expect(typeof body.max_radius_km).toBe("number");
    expect(typeof body.max_pins).toBe("number");
    await page.close();
  });
});

// ─── Section 81 — Geocoded addresses (EVT-005) ────────────────────────────────

test.describe("Section 81 — Geocoded addresses (API)", () => {
  test("81.1 list addresses returns 200 envelope or 404 when flag off", async ({ browser }) => {
    const page = await newIdentityPage(browser, "alice");
    const resp = await apiGet(page, "/ui/crm/geocoding/addresses");
    if (resp.status() === 404) {
      // Flag disabled — expected default.
      expect(resp.status()).toBe(404);
    } else {
      expect(resp.ok()).toBeTruthy();
      const body = await resp.json();
      expect(Array.isArray(body.addresses)).toBeTruthy();
      expect(typeof body.count).toBe("number");
    }
    await page.close();
  });

  test("81.2 re-geocode unknown address returns 404", async ({ browser }) => {
    const page = await newIdentityPage(browser, "alice");
    const resp = await apiPatch(
      page,
      "alice",
      "/ui/crm/geocoding/addresses/addr_does_not_exist_xyz",
    );
    // 404 either from the flag gate or the unknown-address guard.
    expect([404, 422]).toContain(resp.status());
    await page.close();
  });
});

// ─── Section 82 — Proximity search (EVT-006) ──────────────────────────────────

test.describe("Section 82 — Proximity search (API)", () => {
  test("82.1 valid proximity query returns envelope or 404 when flag off", async ({ browser }) => {
    const page = await newIdentityPage(browser, "alice");
    const resp = await apiGet(page, "/ui/crm/maps/contacts/proximity", {
      lat: "40.7128",
      lng: "-74.006",
      radius_km: "50",
      limit: "25",
    });
    if (resp.status() === 404) {
      expect(resp.status()).toBe(404);
    } else {
      expect(resp.ok()).toBeTruthy();
      const body = await resp.json();
      expect(Array.isArray(body.results)).toBeTruthy();
      expect(typeof body.count).toBe("number");
      expect(body.center_lat).toBeCloseTo(40.7128, 3);
      expect(body.center_lng).toBeCloseTo(-74.006, 3);
    }
    await page.close();
  });

  test("82.2 out-of-range latitude rejected (400) when enabled", async ({ browser }) => {
    const page = await newIdentityPage(browser, "alice");
    const resp = await apiGet(page, "/ui/crm/maps/contacts/proximity", {
      lat: "999",
      lng: "0",
      radius_km: "10",
    });
    // 400 when enabled (bad lat), or 404 when flag off (gate runs first).
    expect([400, 404]).toContain(resp.status());
    await page.close();
  });
});

// ─── Section 83 — CRM Maps UI ─────────────────────────────────────────────────

test.describe("Section 83 — CRM Maps UI", () => {
  test("83.1 page renders header", async ({ browser }) => {
    const page = await newIdentityPage(browser, "alice");
    await page.goto(`${BASE}/crm/maps`);
    await expect(page.getByRole("heading", { name: "CRM Maps", exact: true })).toBeVisible({
      timeout: 15000,
    });
    await page.close();
  });

  test("83.2 page shows either the map tabs or the not-enabled state", async ({ browser }) => {
    const page = await newIdentityPage(browser, "alice");
    await page.goto(`${BASE}/crm/maps`);
    await page.waitForLoadState("domcontentloaded");
    const tab = page.getByRole("tab", { name: /Map & proximity/i });
    const notEnabled = page.getByText("CRM Maps not enabled", { exact: true });
    await expect(tab.or(notEnabled).first()).toBeVisible({ timeout: 15000 });
    await page.close();
  });
});
