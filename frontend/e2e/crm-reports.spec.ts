/**
 * E2E tests for the SuiteCRM Reports & Dashboards (RPT cluster) frontend.
 *
 * Sections:
 *   80 — Report CRUD + run (API)
 *   81 — Report schedules (API)
 *   82 — Dashboard + dashlets (API)
 *   83 — Reports UI
 *   84 — Dashboard UI
 *
 * Auth: uses e2e_admin_session_setup.py (cookie + CSRF patterns).
 *
 * NOTE: The RPT endpoints are gated by the `crm_reports_enabled` backend flag.
 * When the flag is OFF every endpoint returns 404, so the API sections assert
 * a "feature enabled OR cleanly disabled (404)" contract and the UI sections
 * assert the graceful "not enabled" state surfaces. DO NOT RUN automatically.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

interface AdminSessionData {
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

let _sessions: Record<string, AdminSessionData> | null = null;
function getSessions(): Record<string, AdminSessionData> {
  if (!_sessions) {
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
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
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

/** True when the RPT feature flag is enabled (any non-404 list response). */
async function reportsEnabled(page: Page): Promise<boolean> {
  const resp = await apiGet(page, "ui/crm/reports");
  return resp.status() !== 404;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 80 — Report CRUD + run (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 80: Report CRUD + run (API)", () => {
  let alicePage: Page;
  let enabled = false;
  let reportId = "";

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    enabled = await reportsEnabled(alicePage);
  });

  test("80.1 Create report → 201 with report_id", async () => {
    const resp = await apiPost(alicePage, "alice", "ui/crm/reports", {
      name: `E2E Report ${TS}`,
      module: "tickets",
      fields: ["ticket_id", "subject", "status"],
    });
    if (!enabled) {
      expect(resp.status()).toBe(404);
      return;
    }
    expect(resp.status()).toBe(201);
    const data = (await resp.json()) as { report_id: string; module: string };
    expect(data.report_id).toBeTruthy();
    expect(data.module).toBe("tickets");
    reportId = data.report_id;
  });

  test("80.2 List reports includes the created report", async () => {
    const resp = await apiGet(alicePage, "ui/crm/reports");
    if (!enabled) {
      expect(resp.status()).toBe(404);
      return;
    }
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { reports: Array<{ report_id: string }> };
    expect(Array.isArray(data.reports)).toBe(true);
    expect(data.reports.some((r) => r.report_id === reportId)).toBe(true);
  });

  test("80.3 Get report by id", async () => {
    if (!enabled) return;
    const resp = await apiGet(alicePage, `ui/crm/reports/${encodeURIComponent(reportId)}`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { fields: string[] };
    expect(data.fields).toContain("subject");
  });

  test("80.4 Run report returns columns + rows", async () => {
    if (!enabled) return;
    const resp = await apiPost(alicePage, "alice", `ui/crm/reports/${encodeURIComponent(reportId)}/run`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { status: string; columns: string[]; rows: unknown[][] };
    expect(data.status).toBe("ok");
    expect(Array.isArray(data.columns)).toBe(true);
    expect(Array.isArray(data.rows)).toBe(true);
  });

  test("80.5 PATCH report adds a chart config", async () => {
    if (!enabled) return;
    const resp = await apiPatch(alicePage, "alice", `ui/crm/reports/${encodeURIComponent(reportId)}`, {
      chart: { chart_type: "bar", x_field: "status", y_field: "ticket_id" },
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { chart: { chart_type: string } | null };
    expect(data.chart?.chart_type).toBe("bar");
  });

  test("80.6 Delete report → ok", async () => {
    if (!enabled || !reportId) return;
    const resp = await apiDelete(alicePage, "alice", `ui/crm/reports/${encodeURIComponent(reportId)}`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { ok: boolean };
    expect(data.ok).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 81 — Report schedules (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 81: Report schedules (API)", () => {
  let alicePage: Page;
  let enabled = false;
  let reportId = "";
  let scheduleId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    enabled = await reportsEnabled(alicePage);
    if (enabled) {
      const resp = await apiPost(alicePage, "alice", "ui/crm/reports", {
        name: `E2E Sched Report ${TS}`,
        module: "contacts",
        fields: ["contact_id", "name", "email"],
      });
      reportId = ((await resp.json()) as { report_id: string }).report_id;
    }
  });

  test("81.1 Create schedule → 201", async () => {
    if (!enabled) return;
    const resp = await apiPost(
      alicePage,
      "alice",
      `ui/crm/reports/${encodeURIComponent(reportId)}/schedules`,
      { cadence: "daily", recipients: ["ops@example.com"], format: "csv" },
    );
    expect(resp.status()).toBe(201);
    const data = (await resp.json()) as { schedule_id: string; cadence: string };
    expect(data.cadence).toBe("daily");
    scheduleId = data.schedule_id;
  });

  test("81.2 List schedules includes new schedule", async () => {
    if (!enabled) return;
    const resp = await apiGet(alicePage, `ui/crm/reports/${encodeURIComponent(reportId)}/schedules`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { schedules: Array<{ schedule_id: string }> };
    expect(data.schedules.some((s) => s.schedule_id === scheduleId)).toBe(true);
  });

  test("81.3 PATCH schedule disables it", async () => {
    if (!enabled || !scheduleId) return;
    const resp = await apiPatch(
      alicePage,
      "alice",
      `ui/crm/reports/${encodeURIComponent(reportId)}/schedules/${encodeURIComponent(scheduleId)}`,
      { enabled: false },
    );
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { enabled: boolean };
    expect(data.enabled).toBe(false);
  });

  test("81.4 Delete schedule → ok", async () => {
    if (!enabled || !scheduleId) return;
    const resp = await apiDelete(
      alicePage,
      "alice",
      `ui/crm/reports/${encodeURIComponent(reportId)}/schedules/${encodeURIComponent(scheduleId)}`,
    );
    expect(resp.status()).toBe(200);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 82 — Dashboard + dashlets (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 82: Dashboard + dashlets (API)", () => {
  let alicePage: Page;
  let enabled = false;
  let dashletId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    enabled = await reportsEnabled(alicePage);
  });

  test("82.1 GET dashboard auto-creates default", async () => {
    const resp = await apiGet(alicePage, "ui/crm/dashboard");
    if (!enabled) {
      expect(resp.status()).toBe(404);
      return;
    }
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { dashboard_id: string; dashlets: unknown[] };
    expect(data.dashboard_id).toBeTruthy();
    expect(Array.isArray(data.dashlets)).toBe(true);
  });

  test("82.2 Add a billing_summary dashlet", async () => {
    if (!enabled) return;
    const resp = await apiPost(alicePage, "alice", "ui/crm/dashboard/dashlets", {
      dashlet_type: "billing_summary",
      title: `E2E Billing ${TS}`,
      config: { period_days: 30 },
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { dashlets: Array<{ dashlet_id: string; title: string }> };
    const added = data.dashlets.find((d) => d.title === `E2E Billing ${TS}`);
    expect(added).toBeTruthy();
    dashletId = added!.dashlet_id;
  });

  test("82.3 GET dashlet data returns a payload", async () => {
    if (!enabled || !dashletId) return;
    const resp = await apiGet(alicePage, `ui/crm/dashboard/dashlets/${encodeURIComponent(dashletId)}/data`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { dashlet_type: string; data: Record<string, unknown> };
    expect(data.dashlet_type).toBe("billing_summary");
    expect(data.data).toBeTruthy();
  });

  test("82.4 Remove dashlet", async () => {
    if (!enabled || !dashletId) return;
    const resp = await apiDelete(alicePage, "alice", `ui/crm/dashboard/dashlets/${encodeURIComponent(dashletId)}`);
    expect(resp.status()).toBe(200);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 83 — Reports UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 83: Reports UI", () => {
  let page: Page;
  let enabled = false;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
    const probe = await newIdentityPage(browser, "alice");
    enabled = await reportsEnabled(probe);
  });

  test("83.1 Reports page renders header", async () => {
    await page.goto(`${BASE}/crm/reports`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Reports", exact: true })).toBeVisible({ timeout: 15_000 });
  });

  test("83.2 Reports page shows either content or not-enabled state", async () => {
    await page.goto(`${BASE}/crm/reports`, { waitUntil: "domcontentloaded" });
    if (enabled) {
      await expect(page.getByRole("button", { name: /New Report/i }).first()).toBeVisible({ timeout: 15_000 });
    } else {
      await expect(page.getByText(/not enabled/i).first()).toBeVisible({ timeout: 15_000 });
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 84 — Dashboard UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 84: Dashboard UI", () => {
  let page: Page;
  let enabled = false;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
    const probe = await newIdentityPage(browser, "alice");
    enabled = await reportsEnabled(probe);
  });

  test("84.1 Dashboard page renders header", async () => {
    await page.goto(`${BASE}/crm/dashboard`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading").first()).toBeVisible({ timeout: 15_000 });
  });

  test("84.2 Dashboard shows add-dashlet action or not-enabled state", async () => {
    await page.goto(`${BASE}/crm/dashboard`, { waitUntil: "domcontentloaded" });
    if (enabled) {
      await expect(page.getByRole("button", { name: /Add dashlet/i }).first()).toBeVisible({ timeout: 15_000 });
    } else {
      await expect(page.getByText(/not enabled/i).first()).toBeVisible({ timeout: 15_000 });
    }
  });
});
