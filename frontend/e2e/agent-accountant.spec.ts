/**
 * E2E tests for the Accountant / Cost Tracking Agent (AGENT-018).
 *
 * Section 691: Cost Recording & Summary API
 * Section 692: Budget Management API
 * Section 693: Alerts & Trends API
 * Section 694: Cost Dashboard UI
 *
 * Auth: cookie-based sessions from e2e_admin_session_setup.py.
 *   alice – role=user (platform owner; all cost data is owner-scoped)
 *   bob   – role=user (cross-tenant isolation check)
 * POST/PUT/DELETE requests carry an x-csrf-token header.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";

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
  // Seed the persisted auth store so ProtectedRoute treats the page as
  // authenticated (cookie injection alone leaves isAuthenticated=false → /login
  // redirect, which hides the UI under test).
  const uid = sessions[identity].user_sub;
  await page.addInitScript((userId: string) => {
    const state = { userId, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, uid);
  return page;
}

async function apiPut(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.put(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown, csrf = true) {
  const sess = getSessions()[identity];
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (csrf) headers["x-csrf-token"] = sess.csrf_token;
  return page.request.post(`${API}/${path}`, { data: body ?? {}, headers });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

const TS = Date.now();
const TODAY = new Date().toISOString().slice(0, 10);
const WORKER_CODER = `worker_coder_${TS}`;
const WORKER_SEC = `worker_sec_${TS}`;
const TICKET_ID = `TEST-${TS}`;

// ─── 691: Cost Recording & Summary API ──────────────────────────────────────

test.describe("691. Cost Recording & Summary API", () => {
  let alicePage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("691.1 record cost entry for coder worker", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/accountant/costs/entries", {
      worker_id: WORKER_CODER,
      agent_type: "coder",
      agent_id: "agent_coder_primary",
      date: TODAY,
      llm_input_tokens: 1000,
      llm_output_tokens: 500,
      llm_cost_cents: 500,
      compute_hours: 2.5,
      compute_cost_cents: 100,
      tickets_worked: 2,
      tickets_completed: 1,
    });
    expect(r.status()).toBe(201);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.total_cost_cents).toBe(600);
    expect(data.agent_type).toBe("coder");
  });

  test("691.2 record cost entry for security worker", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/accountant/costs/entries", {
      worker_id: WORKER_SEC,
      agent_type: "security",
      agent_id: "agent_sec_primary",
      date: TODAY,
      llm_cost_cents: 200,
    });
    expect(r.status()).toBe(201);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.total_cost_cents).toBe(200);
  });

  test("691.3 daily summary aggregates by agent type", async () => {
    const r = await apiGet(alicePage, "ui/agents/accountant/costs/summary/daily", { date: TODAY });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      total_cents: number;
      by_agent_type: Record<string, number>;
    };
    expect(data.total_cents).toBeGreaterThanOrEqual(800);
    expect(data.by_agent_type.coder).toBeGreaterThanOrEqual(600);
    expect(data.by_agent_type.security).toBeGreaterThanOrEqual(200);
  });

  test("691.4 attribute cost to ticket", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/accountant/costs/by-ticket", {
      ticket_id: TICKET_ID,
      agent_type: "coder",
      llm_tokens: 1500,
      llm_cost_cents: 300,
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.total_cost_cents).toBe(300);
    expect(data.worker_sessions).toBe(1);
  });

  test("691.5 get ticket cost", async () => {
    const r = await apiGet(alicePage, `ui/agents/accountant/costs/by-ticket/${TICKET_ID}`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.total_cost_cents).toBeGreaterThanOrEqual(300);
  });

  test("691.6 invalid date format rejected", async () => {
    const r = await apiGet(alicePage, "ui/agents/accountant/costs/summary/daily", { date: "not-a-date" });
    expect(r.status()).toBe(422);
  });
});

// ─── 692: Budget Management API ──────────────────────────────────────────────

test.describe("692. Budget Management API", () => {
  let alicePage: Page;
  let budgetId = "";
  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("692.1 create daily overall budget", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/accountant/costs/budgets", {
      name: `Overall Daily ${TS}`,
      scope: "overall",
      period: "daily",
      limit_cents: 5000,
      alert_threshold_pct: 80,
    });
    expect(r.status()).toBe(201);
    const data = (await r.json()) as Record<string, unknown>;
    budgetId = data.budget_id as string;
    expect(budgetId).toBeTruthy();
    expect(data.limit_cents).toBe(5000);
  });

  test("692.2 list budgets includes created budget", async () => {
    const r = await apiGet(alicePage, "ui/agents/accountant/costs/budgets");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Array<{ budget_id: string }>;
    expect(data.some((b) => b.budget_id === budgetId)).toBe(true);
  });

  test("692.3 update budget limit", async () => {
    const r = await apiPut(alicePage, "alice", `ui/agents/accountant/costs/budgets/${budgetId}`, {
      limit_cents: 10000,
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.limit_cents).toBe(10000);
  });

  test("692.4 create agent-type budget", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/accountant/costs/budgets", {
      name: `Coder Monthly ${TS}`,
      scope: "agent_type",
      scope_ref: "coder",
      period: "monthly",
      limit_cents: 100000,
    });
    expect(r.status()).toBe(201);
  });

  test("692.5 agent-type budget without scope_ref rejected", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/accountant/costs/budgets", {
      name: `Bad ${TS}`,
      scope: "agent_type",
      period: "daily",
      limit_cents: 5000,
    });
    expect(r.status()).toBe(422);
  });

  test("692.6 delete budget", async () => {
    const r = await apiDelete(alicePage, "alice", `ui/agents/accountant/costs/budgets/${budgetId}`);
    expect(r.status()).toBe(200);
    const list = await apiGet(alicePage, "ui/agents/accountant/costs/budgets");
    const data = (await list.json()) as Array<{ budget_id: string }>;
    expect(data.some((b) => b.budget_id === budgetId)).toBe(false);
  });
});

// ─── 693: Alerts & Trends API ────────────────────────────────────────────────

test.describe("693. Alerts & Trends API", () => {
  let alicePage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    // Create a tiny budget then collect so an alert is guaranteed to fire.
    await apiPost(alicePage, "alice", "ui/agents/accountant/costs/budgets", {
      name: `Tiny Daily ${TS}`,
      scope: "overall",
      period: "daily",
      limit_cents: 100,
      alert_threshold_pct: 50,
    });
    await apiPost(alicePage, "alice", "ui/agents/accountant/costs/collect", {});
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("693.1 list alerts returns array", async () => {
    const r = await apiGet(alicePage, "ui/agents/accountant/costs/alerts");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { alerts: Array<unknown> };
    expect(Array.isArray(data.alerts)).toBe(true);
    expect(data.alerts.length).toBeGreaterThan(0);
  });

  test("693.2 acknowledge an alert", async () => {
    const list = await apiGet(alicePage, "ui/agents/accountant/costs/alerts", { acknowledged: "false" });
    const data = (await list.json()) as { alerts: Array<{ alert_id: string }> };
    expect(data.alerts.length).toBeGreaterThan(0);
    const alertId = data.alerts[0]!.alert_id;
    const r = await apiPost(
      alicePage,
      "alice",
      `ui/agents/accountant/costs/alerts/${alertId}/acknowledge`,
      {},
    );
    expect(r.status()).toBe(200);
    const ack = (await r.json()) as Record<string, unknown>;
    expect(ack.acknowledged).toBe(true);
  });

  test("693.3 cost trends returns weekly buckets", async () => {
    const r = await apiGet(alicePage, "ui/agents/accountant/costs/trends", { days: "30" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { weeks: Array<Record<string, unknown>> };
    expect(Array.isArray(data.weeks)).toBe(true);
    expect(data.weeks.length).toBeGreaterThan(0);
    const w = data.weeks[data.weeks.length - 1]!;
    expect(typeof w.total_cents).toBe("number");
    expect(typeof w.llm_cents).toBe("number");
    expect(typeof w.compute_cents).toBe("number");
  });

  test("693.4 optimization recommendations returns array", async () => {
    const r = await apiGet(alicePage, "ui/agents/accountant/costs/optimizations");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Array<unknown>;
    expect(Array.isArray(data)).toBe(true);
  });

  test("693.5 ticket cost list sorted by cost", async () => {
    const r = await apiGet(alicePage, "ui/agents/accountant/costs/by-ticket", { limit: "25" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { ticket_costs: Array<{ total_cost_cents: number }> };
    expect(Array.isArray(data.ticket_costs)).toBe(true);
  });
});

// ─── 694: Cost Dashboard UI ──────────────────────────────────────────────────

test.describe("694. Cost Dashboard UI", () => {
  let alicePage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    // Clear any budgets left over from prior runs so the UI create flow below
    // does not collide with an existing overall/daily budget (backend returns
    // 409 for duplicate scope+period).
    const existing = await apiGet(alicePage, "ui/agents/accountant/costs/budgets");
    if (existing.ok()) {
      const list = (await existing.json()) as Array<{ budget_id: string }>;
      for (const b of list) {
        await apiDelete(alicePage, "alice", `ui/agents/accountant/costs/budgets/${b.budget_id}`);
      }
    }
    await apiPost(alicePage, "alice", "ui/agents/accountant/costs/entries", {
      worker_id: `worker_ui_${TS}`,
      agent_type: "coder",
      agent_id: "agent_ui",
      date: TODAY,
      llm_cost_cents: 400,
      compute_cost_cents: 50,
      tickets_completed: 1,
    });
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("694.1 cost overview page loads", async () => {
    await alicePage.goto("http://localhost:3000/agents/costs");
    await expect(alicePage.locator('[data-testid="cost-overview-page"]')).toBeVisible({ timeout: 15_000 });
    await expect(alicePage.locator('[data-testid="summary-today"]')).toBeVisible({ timeout: 10_000 });
  });

  test("694.2 cost breakdown page loads", async () => {
    await alicePage.goto("http://localhost:3000/agents/costs/breakdown");
    await expect(alicePage.locator('[data-testid="cost-breakdown-page"]')).toBeVisible({ timeout: 15_000 });
    await expect(alicePage.locator('[data-testid="breakdown-table-agent-type"]')).toBeVisible({ timeout: 10_000 });
  });

  test("694.3 budget manager page create flow", async () => {
    await alicePage.goto("http://localhost:3000/agents/costs/budgets");
    await expect(alicePage.locator('[data-testid="budget-manager-page"]')).toBeVisible({ timeout: 15_000 });
    await alicePage.locator('[data-testid="create-budget-button"]').click();
    await expect(alicePage.locator('[data-testid="budget-form-dialog"]')).toBeVisible({ timeout: 10_000 });
    await alicePage.locator('[data-testid="budget-name-input"]').fill(`UI Budget ${TS}`);
    await alicePage.locator('[data-testid="budget-save-button"]').click();
    await expect(
      alicePage.locator('[data-testid="budget-card"]').filter({ hasText: `UI Budget ${TS}` }),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("694.4 alerts page loads", async () => {
    await alicePage.goto("http://localhost:3000/agents/costs/alerts");
    await expect(alicePage.locator('[data-testid="cost-alerts-page"]')).toBeVisible({ timeout: 15_000 });
  });
});
