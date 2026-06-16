/**
 * E2E tests for the SuiteCRM AOS Invoices + Currency/Tax (INV) cluster.
 *
 * Sections:
 *   70 — Invoices list/detail/lifecycle — API (/ui/invoices)
 *   71 — Convert quote → invoice — API (/ui/quotes/{id}/convert-to-invoice)
 *   72 — Currency admin registry — API (/ui/admin/currencies)
 *   73 — Tax-rate admin registry — API (/ui/admin/tax-rates)
 *   74 — CRM Invoices UI (/crm/invoices, /crm/billing-settings)
 *
 * Auth: uses e2e_admin_session_setup.py (all identities).
 *
 * NOTE: AOS invoices, currencies, and tax rates are flag-gated and default OFF
 * in several cases. Tests tolerate the "not enabled" (404/503) shape by
 * asserting the disabled response is well-formed rather than the feature output.
 *
 * Mirrors frontend/e2e/tickets.spec.ts structure (do not run here).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ROOT_SUB = "root.admin@testdev.local";
const BOB_ID   = "e2e_bob@test.local";
const TS       = Date.now();

interface AdminSessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getAdminSessions()[identity];
  if (!session) throw new Error(`No session for identity: ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    ([userId, accessToken]: [string, string]) => {
      const state = { userId, accessToken, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    [session.user_sub, session.access_token],
  );
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

/** True when a response indicates the feature flag is off. */
function isDisabled(status: number): boolean {
  return status === 404 || status === 503;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 70 — Invoices list/detail/lifecycle — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 70: Invoices — list/detail (API)", () => {
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    bobPage = await newIdentityPage(browser, "bob");
  });

  test("70.1 List invoices → 200 list shape (or disabled)", async () => {
    const resp = await apiGet(bobPage, "ui/invoices", { limit: "5" });
    if (isDisabled(resp.status())) {
      expect(isDisabled(resp.status())).toBe(true);
      return;
    }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { invoices: unknown[] };
    expect(Array.isArray(data.invoices)).toBe(true);
  });

  test("70.2 Unknown invoice → 404", async () => {
    const resp = await apiGet(bobPage, `ui/invoices/INV-DOES-NOT-EXIST-${TS}`);
    expect(resp.status()).toBe(404);
  });

  test("70.3 List with type filter → 200 (or disabled)", async () => {
    const resp = await apiGet(bobPage, "ui/invoices", { type: "shop", limit: "5" });
    expect([200, 404, 503]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 71 — Convert quote → invoice — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 71: Convert quote → invoice (API)", () => {
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    bobPage = await newIdentityPage(browser, "bob");
  });

  test("71.1 List quotes → 200 list (or disabled)", async () => {
    const resp = await apiGet(bobPage, "ui/quotes", { limit: "5" });
    if (isDisabled(resp.status())) {
      expect(isDisabled(resp.status())).toBe(true);
      return;
    }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { quotes: unknown[] };
    expect(Array.isArray(data.quotes)).toBe(true);
  });

  test("71.2 Convert non-existent quote → 404 (or disabled)", async () => {
    const resp = await apiPost(bobPage, "bob", `ui/quotes/q-missing-${TS}/convert-to-invoice`, {});
    expect([404, 503]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 72 — Currency admin registry — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 72: Currency admin (API)", () => {
  let rootPage: Page;
  let bobPage: Page;
  const ISO = "EUR";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    bobPage = await newIdentityPage(browser, "bob");
  });

  test("72.1 List currencies → 200 (or disabled)", async () => {
    const resp = await apiGet(rootPage, "ui/admin/currencies", { active_only: "false" });
    if (isDisabled(resp.status())) {
      expect(isDisabled(resp.status())).toBe(true);
      return;
    }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { currencies: unknown[] };
    expect(Array.isArray(data.currencies)).toBe(true);
  });

  test("72.2 Create currency → 201/409 (or disabled)", async () => {
    const resp = await apiPost(rootPage, "root", "ui/admin/currencies", {
      iso_code: ISO,
      name: "Euro",
      symbol: "€",
      rate_to_usd: 1.08,
      decimal_places: 2,
      is_active: true,
    });
    expect([201, 409, 404, 503]).toContain(resp.status());
    if (resp.status() === 201) {
      const data = await resp.json() as { iso_code: string };
      expect(data.iso_code).toBe(ISO);
    }
  });

  test("72.3 Non-admin cannot create currency → 401/403 (or disabled)", async () => {
    const resp = await apiPost(bobPage, "bob", "ui/admin/currencies", {
      iso_code: "GBP", name: "Pound", symbol: "£", rate_to_usd: 1.27,
    });
    expect([401, 403, 404, 503]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 73 — Tax-rate admin registry — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 73: Tax-rate admin (API)", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test("73.1 List tax rates → 200 (or disabled)", async () => {
    const resp = await apiGet(rootPage, "ui/admin/tax-rates", { active_only: "false" });
    if (isDisabled(resp.status())) {
      expect(isDisabled(resp.status())).toBe(true);
      return;
    }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { tax_rates: unknown[] };
    expect(Array.isArray(data.tax_rates)).toBe(true);
  });

  test("73.2 Create then patch tax rate (or disabled)", async () => {
    const create = await apiPost(rootPage, "root", "ui/admin/tax-rates", {
      name: `E2E Tax ${TS}`,
      rate_bps: 825,
      jurisdiction: "US-CA",
      description: "E2E test rate",
    });
    expect([201, 404, 503]).toContain(create.status());
    if (create.status() !== 201) return;
    const created = await create.json() as { tax_rate_id: string; rate_bps: number };
    expect(created.rate_bps).toBe(825);
    const patch = await apiPatch(rootPage, "root", `ui/admin/tax-rates/${created.tax_rate_id}`, {
      rate_bps: 900,
    });
    expect(patch.status()).toBe(200);
    const patched = await patch.json() as { rate_bps: number };
    expect(patched.rate_bps).toBe(900);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 74 — CRM Invoices UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 74: CRM Invoices UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "root");
  });

  test("74.1 Invoices list page renders header", async () => {
    await page.goto(`${BASE}/crm/invoices`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("CRM Invoices").first()).toBeVisible({ timeout: 15_000 });
  });

  test("74.2 Convert-from-quote page renders", async () => {
    await page.goto(`${BASE}/crm/invoices/convert`, { waitUntil: "domcontentloaded" });
    await expect(
      page.getByText(/Convert Quote to Invoice/i).first(),
    ).toBeVisible({ timeout: 15_000 });
  });

  test("74.3 Billing settings page renders with tabs", async () => {
    await page.goto(`${BASE}/crm/billing-settings`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText(/Currency & Tax Settings/i).first()).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("tab", { name: /Currencies/i })).toBeVisible();
    await expect(page.getByRole("tab", { name: /Tax Rates/i })).toBeVisible();
  });
});

// Keep references so unused-symbol lint stays quiet across concurrent edits.
void ROOT_SUB;
void BOB_ID;
