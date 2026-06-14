/**
 * E2E tests for the CRM Audit Log Browse feature (EVT-015).
 *
 * Sections:
 *   82 — Audit Log Browse — API
 *   83 — CrmAuditLogPage UI
 *
 * Auth: uses e2e_admin_session_setup.py (root/alice).
 *
 * NOTE: CRM_AUDIT_LOG_BROWSE_ENABLED defaults OFF. When off the endpoint
 * 404s. When on, it is ROOT-only (403 for non-root). Tests are gate-aware.
 *
 * Live backend: app/routers/audit_export.py (browse_router)
 *   GET /ui/admin/audit-log?category&from_ts&to_ts[&user_sub&event_type&limit&cursor]
 *   -> { items, cursor, total_scanned, category, from_ts, to_ts }
 *   categories: auth, moderation, broadcast, admin, billing
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const API  = "http://localhost:8000";

interface AdminSessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean;
    sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _sessions: Record<string, AdminSessionData> | null = null;
function getSessions(): Record<string, AdminSessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getSessions()[identity];
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

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

const NOW = Math.floor(Date.now() / 1000);
const FROM = NOW - 7 * 86400;

// ─────────────────────────────────────────────────────────────────────────────
// Section 82 — Audit Log Browse — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 82: Audit Log Browse — API", () => {
  let rootPage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("82.1 root browse auth category — 200 (enabled) or 404 (disabled)", async () => {
    const resp = await apiGet(rootPage, "ui/admin/audit-log", {
      category: "auth", from_ts: String(FROM), to_ts: String(NOW), limit: "20",
    });
    expect([200, 404, 429]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = await resp.json() as {
        items: unknown[]; cursor: string | null; total_scanned: number; category: string;
      };
      expect(Array.isArray(data.items)).toBe(true);
      expect(data.category).toBe("auth");
      expect(typeof data.total_scanned).toBe("number");
    }
  });

  test("82.2 invalid category — 400 (enabled) or 404 (disabled)", async () => {
    const resp = await apiGet(rootPage, "ui/admin/audit-log", {
      category: "nope", from_ts: String(FROM), to_ts: String(NOW),
    });
    expect([400, 404, 429]).toContain(resp.status());
  });

  test("82.3 from_ts > to_ts — 400 (enabled) or 404 (disabled)", async () => {
    const resp = await apiGet(rootPage, "ui/admin/audit-log", {
      category: "auth", from_ts: String(NOW), to_ts: String(FROM),
    });
    expect([400, 404, 429]).toContain(resp.status());
  });

  test("82.4 non-root (alice) — 403 (enabled) or 404 (disabled)", async () => {
    const resp = await apiGet(alicePage, "ui/admin/audit-log", {
      category: "auth", from_ts: String(FROM), to_ts: String(NOW),
    });
    expect([403, 404, 429]).toContain(resp.status());
  });

  test("82.5 missing required params — 422 (enabled) or 404 (disabled)", async () => {
    const resp = await apiGet(rootPage, "ui/admin/audit-log", { category: "auth" });
    expect([422, 404, 429]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 83 — CrmAuditLogPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 83: CrmAuditLogPage UI", () => {
  test("83.1 Page renders filters or not-enabled state", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "root");
    await page.goto(`${BASE}/crm/audit-log`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Audit Log" })).toBeVisible();
    const filtersOrDisabled = page
      .getByText("Filters", { exact: true })
      .or(page.getByText("Audit log browse is not enabled"))
      .or(page.getByText("Root access required"));
    await expect(filtersOrDisabled.first()).toBeVisible();
  });

  test("83.2 Mocked enabled — search renders results table", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "root");
    await page.route(/\/ui\/admin\/audit-log/, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          items: [{
            event_id: "e1", event_type: "auth", event_action: "login_success",
            timestamp_unix: Math.floor(Date.now() / 1000),
            actor_user_id: "root.admin@testdev.local", actor_role: "root",
            outcome: "success",
          }],
          cursor: null, total_scanned: 1, category: "auth",
          from_ts: FROM, to_ts: NOW,
        }),
      });
    });
    await page.goto(`${BASE}/crm/audit-log`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Filters", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: /Search/ }).click();
    await expect(page.getByText("login_success")).toBeVisible({ timeout: 5000 });
  });
});
