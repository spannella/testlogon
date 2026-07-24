/**
 * E2E tests for the OFBiz HR / Payroll (HRM) admin console.
 *
 * Sections:
 *   90 — Position lifecycle (create / list / status) — API
 *   91 — Employment lifecycle (create / terminate) — API
 *   92 — Payroll run lifecycle (create / approve / post / lines) — API
 *   93 — HR console UI
 *
 * Auth: uses e2e_admin_session_setup.py (all identities). HR endpoints require
 * admin/root. Root is the only DB-admin identity, so all API calls use root.
 *
 * NOTE: HR_ENABLED / HR_PAYROLL_ENABLED default OFF. When disabled the backend
 * returns 404 {code: hr_disabled | hr_payroll_disabled}; these tests tolerate
 * that by asserting either the success shape OR the documented disabled state.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";

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

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    _adminSessions = loadSessions();
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

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

/** True when the response is the documented "feature disabled" 404. */
function isDisabled(status: number, body: any): boolean {
  return (
    status === 404 &&
    (body?.detail?.code === "hr_disabled" || body?.detail?.code === "hr_payroll_disabled")
  );
}

const TS = Date.now();

// ─────────────────────────────────────────────────────────────────────────────
// Section 90 — Position lifecycle — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 90: Position lifecycle (API)", () => {
  let rootPage: Page;
  let positionId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test("90.1 create a position", async () => {
    const res = await apiPost(rootPage, "root", "ui/hr/positions", {
      title: `E2E Position ${TS}`,
      department: "Engineering",
    });
    const body = await res.json();
    if (isDisabled(res.status(), body)) {
      test.skip(true, "HR module disabled");
      return;
    }
    expect(res.status()).toBe(201);
    expect(body.status).toBe("OPEN");
    expect(body.position_id).toBeTruthy();
    positionId = body.position_id;
  });

  test("90.2 list positions includes the new one", async () => {
    test.skip(!positionId, "create skipped");
    const res = await apiGet(rootPage, "ui/hr/positions", { limit: "100" });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body.items)).toBe(true);
    expect(body.items.some((p: any) => p.position_id === positionId)).toBe(true);
  });

  test("90.3 transition OPEN -> FILLED", async () => {
    test.skip(!positionId, "create skipped");
    const res = await apiPatch(rootPage, "root", `ui/hr/positions/${positionId}/status`, {
      status: "FILLED",
    });
    expect(res.status()).toBe(200);
    expect((await res.json()).status).toBe("FILLED");
  });

  test("90.4 invalid transition FILLED -> OPEN returns 409", async () => {
    test.skip(!positionId, "create skipped");
    const res = await apiPatch(rootPage, "root", `ui/hr/positions/${positionId}/status`, {
      status: "OPEN",
    });
    expect(res.status()).toBe(409);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 91 — Employment lifecycle — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 91: Employment lifecycle (API)", () => {
  let rootPage: Page;
  let positionId = "";
  let employmentId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    const res = await apiPost(rootPage, "root", "ui/hr/positions", {
      title: `E2E Emp Position ${TS}`,
    });
    const body = await res.json().catch(() => null);
    if (res.status() === 201) positionId = body.position_id;
  });

  test("91.1 create an employment", async () => {
    test.skip(!positionId, "HR module disabled");
    const now = Math.floor(Date.now() / 1000);
    const res = await apiPost(rootPage, "root", "ui/hr/employments", {
      party_id: `PERSON-${TS}`,
      position_id: positionId,
      org_party_id: `ORG-${TS}`,
      start_date: now,
      pay_rate_cents: 500000,
      pay_period: "MONTHLY",
      currency: "USD",
    });
    expect(res.status()).toBe(201);
    const body = await res.json();
    expect(body.status).toBe("ACTIVE");
    expect(body.pay_rate_cents).toBe(500000);
    employmentId = body.employment_id;
  });

  test("91.2 list employments filtered by status", async () => {
    test.skip(!employmentId, "create skipped");
    const res = await apiGet(rootPage, "ui/hr/employments", { status: "ACTIVE", limit: "100" });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.items.some((e: any) => e.employment_id === employmentId)).toBe(true);
  });

  test("91.3 terminate the employment", async () => {
    test.skip(!employmentId, "create skipped");
    const now = Math.floor(Date.now() / 1000);
    const res = await apiPost(rootPage, "root", `ui/hr/employments/${employmentId}/terminate`, {
      end_date: now,
      note: "E2E termination",
    });
    expect(res.status()).toBe(200);
    expect((await res.json()).status).toBe("TERMINATED");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 92 — Payroll run lifecycle — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 92: Payroll run lifecycle (API)", () => {
  let rootPage: Page;
  let runId = "";
  let payrollEnabled = true;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test("92.1 create a payroll run", async () => {
    const now = Math.floor(Date.now() / 1000);
    const res = await apiPost(rootPage, "root", "ui/hr/payroll", {
      period_start: now - 86400 * 14,
      period_end: now,
      currency: "usd",
    });
    const body = await res.json();
    if (isDisabled(res.status(), body)) {
      payrollEnabled = false;
      test.skip(true, "Payroll module disabled");
      return;
    }
    expect(res.status()).toBe(201);
    expect(body.status).toBe("DRAFT");
    runId = body.payroll_run_id;
  });

  test("92.2 fetch payroll run lines", async () => {
    test.skip(!payrollEnabled || !runId, "payroll disabled");
    const res = await apiGet(rootPage, `ui/hr/payroll/${runId}/lines`);
    expect(res.status()).toBe(200);
    expect(Array.isArray((await res.json()).lines)).toBe(true);
  });

  test("92.3 approve the run (DRAFT -> APPROVED)", async () => {
    test.skip(!payrollEnabled || !runId, "payroll disabled");
    const res = await apiPost(rootPage, "root", `ui/hr/payroll/${runId}/approve`);
    expect(res.status()).toBe(200);
    expect((await res.json()).status).toBe("APPROVED");
  });

  test("92.4 post the run (APPROVED -> POSTED)", async () => {
    test.skip(!payrollEnabled || !runId, "payroll disabled");
    const res = await apiPost(rootPage, "root", `ui/hr/payroll/${runId}/post`);
    expect(res.status()).toBe(200);
    expect((await res.json()).status).toBe("POSTED");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 93 — HR console UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 93: HR console UI", () => {
  test("93.1 renders HR page with tabs (or disabled state)", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "root");
    await page.goto(`${BASE}/ofbiz/hr`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "HR & Payroll" })).toBeVisible();

    const tabs = page.getByRole("tab", { name: "Positions" });
    const disabled = page.getByText("HR module is not enabled");
    await expect(tabs.or(disabled).first()).toBeVisible({ timeout: 10_000 });
  });

  test("93.2 can switch to payroll tab when enabled", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "root");
    await page.goto(`${BASE}/ofbiz/hr`, { waitUntil: "domcontentloaded" });

    // The page is a lazy route chunk — wait for it to settle into either the
    // tabbed console (HR enabled) or the disabled empty-state before branching.
    const payrollTab = page.getByRole("tab", { name: "Payroll" });
    await expect(
      payrollTab.or(page.getByText("HR module is not enabled")).first(),
    ).toBeVisible({ timeout: 15_000 });

    if (await payrollTab.isVisible().catch(() => false)) {
      await payrollTab.click();
      await expect(
        page
          .getByRole("button", { name: /new payroll run/i })
          .or(page.getByText("Payroll is not enabled"))
          .first(),
      ).toBeVisible({ timeout: 10_000 });
    } else {
      await expect(page.getByText("HR module is not enabled")).toBeVisible();
    }
  });
});
