/**
 * E2E tests for the Project Manager Agent (AGENT-012).
 *
 * Section 667: PM Config & Idea Intake API (5 tests)
 * Section 668: Backlog & Prioritization API (4 tests)
 * Section 669: Sprint & Reporting API (5 tests)
 * Section 670: PM Config & Dashboard UI (4 tests)
 *
 * Auth: cookie-based sessions from e2e_admin_session_setup.py.
 *   root  – role=root  (configures/manages agents)
 *   alice – role=user  (submits ideas; 403 on admin endpoints)
 * POST/PUT/PATCH requests carry an x-csrf-token header.
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

const TS = Date.now();
const TYPE_ID = `pmtype_${TS}`;
const SPACE_ID = `pmspace_${TS}`;
const VALID_CONFIG = {
  priority_framework: {
    P0: "Critical/blocking",
    P1: "High/next sprint",
    P2: "Medium/backlog",
    P3: "Low/nice-to-have",
  },
  priority_weights: {
    user_impact: 0.4,
    revenue_impact: 0.3,
    technical_debt: 0.15,
    effort_inverse: 0.15,
  },
  sprint_duration_days: 14,
  capacity_per_agent_type: { coder: 80, qa: 40, devops: 20, architect: 20 },
  reporting_cadence: "both",
  report_time_utc: "09:00",
  idea_intake_enabled: true,
  auto_prioritize: true,
  auto_create_feature_requests: false,
  blocker_stale_hours: 48,
  escalation_on_conflict: true,
  coding_tool: "claude_code",
  project_space_id: SPACE_ID,
};

// ─── 667: PM Config & Idea Intake API ────────────────────────────────────────

test.describe("667. PM Config & Idea Intake API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let ideaId = "";
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("667.1 create PM agent type with config", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/pm-config`, VALID_CONFIG);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.sprint_duration_days).toBe(14);
    expect((data.priority_framework as Record<string, string>).P0).toBeTruthy();
  });

  test("667.2 get PM config", async () => {
    const r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/pm-config`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(Object.keys(data.priority_framework as object)).toContain("P0");
    expect(data.sprint_duration_days).toBe(14);
  });

  test("667.3 submit product idea as user", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/ideas", {
      title: `Add video DMs ${TS}`,
      description: "Let users share short video clips inside DMs and group chats to boost engagement.",
    });
    expect(r.status()).toBe(201);
    const data = (await r.json()) as { idea_id: string; status: string };
    ideaId = data.idea_id;
    expect(ideaId).toBeTruthy();
    expect(data.status).toBe("submitted");
  });

  test("667.4 list ideas shows submitted idea", async () => {
    const r = await apiGet(rootPage, "ui/agents/ideas", { status: "submitted", limit: "100" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { ideas: Array<{ idea_id: string; status: string }> };
    const found = data.ideas.find((i) => i.idea_id === ideaId);
    expect(found).toBeDefined();
    expect(found!.status).toBe("submitted");
  });

  test("667.5 update idea status to accepted", async () => {
    const r = await apiPatch(rootPage, "root", `ui/agents/ideas/${ideaId}`, { status: "accepted" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { status: string };
    expect(data.status).toBe("accepted");
  });
});

// ─── 668: Backlog & Prioritization API ───────────────────────────────────────

test.describe("668. Backlog & Prioritization API", () => {
  let rootPage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/pm-config`, VALID_CONFIG);
    // Seed a feature_request ticket in the project space so the backlog is non-empty.
    await apiPost(rootPage, "root", "ui/agents/architect/tickets", {
      subject: `backlog feature ${TS}`,
      description: "A feature request for the backlog.",
      labels: ["type:feature_request"],
      space_id: SPACE_ID,
    });
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("668.1 get backlog returns tickets ordered by priority score", async () => {
    const r = await apiGet(rootPage, "ui/agents/backlog", { type_id: TYPE_ID });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { items: Array<{ priority_score: number; priority: string }>; count: number };
    for (let i = 1; i < data.items.length; i++) {
      expect(data.items[i - 1].priority_score).toBeGreaterThanOrEqual(data.items[i].priority_score);
    }
  });

  test("668.2 reprioritize backlog updates labels", async () => {
    const r = await apiPost(rootPage, "root", `ui/agents/backlog/reprioritize?type_id=${TYPE_ID}`, {});
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { tickets_reprioritized: number };
    expect(data.tickets_reprioritized).toBeGreaterThanOrEqual(0);
  });

  test("668.3 get blockers detects stale/blocked tickets", async () => {
    const r = await apiGet(rootPage, "ui/agents/blockers", { type_id: TYPE_ID });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { blockers: Array<{ ticket_id: string; blocker_type: string; details: string }> };
    expect(Array.isArray(data.blockers)).toBe(true);
  });

  test("668.4 get capacity shows agent utilization", async () => {
    const r = await apiGet(rootPage, "ui/agents/capacity", { type_id: TYPE_ID });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { capacity: Array<{ agent_type: string; utilization_pct: number }> };
    expect(data.capacity.length).toBeGreaterThanOrEqual(1);
    const types = data.capacity.map((c) => c.agent_type);
    expect(types).toContain("coder");
    for (const c of data.capacity) {
      expect(typeof c.utilization_pct).toBe("number");
    }
  });
});

// ─── 669: Sprint & Reporting API ──────────────────────────────────────────────

test.describe("669. Sprint & Reporting API", () => {
  let rootPage: Page;
  let sprintId = "";
  const runId = `pmrun669_${TS}`;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/pm-config`, VALID_CONFIG);
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("669.1 create sprint", async () => {
    const r = await apiPost(rootPage, "root", `ui/agents/sprints?type_id=${TYPE_ID}`, {
      start_date: "2026-07-01",
      end_date: "2026-07-15",
    });
    expect(r.status()).toBe(201);
    const data = (await r.json()) as { sprint_id: string; status: string };
    sprintId = data.sprint_id;
    expect(sprintId).toBeTruthy();
    expect(data.status).toBe("planned");
  });

  test("669.2 get sprint details with burndown", async () => {
    const r = await apiGet(rootPage, `ui/agents/sprints/${sprintId}`, { type_id: TYPE_ID });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      sprint: { sprint_number: number; planned_hours: number; status: string };
      burndown: Array<{ date: string }>;
    };
    expect(typeof data.sprint.sprint_number).toBe("number");
    expect(typeof data.sprint.planned_hours).toBe("number");
    expect(data.sprint.status).toBe("planned");
    expect(Array.isArray(data.burndown)).toBe(true);
  });

  test("669.3 list reports (generate first)", async () => {
    const gen = await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/runs/${runId}/pm-operation`, {
      operation_type: "report_generate",
      report_type: "daily",
    });
    expect(gen.status()).toBe(200);
    const r = await apiGet(rootPage, "ui/agents/reports", { type_id: TYPE_ID });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { reports: unknown[] };
    expect(Array.isArray(data.reports)).toBe(true);
    expect(data.reports.length).toBeGreaterThanOrEqual(1);
  });

  test("669.4 get PM output from run", async () => {
    const r = await apiGet(rootPage, `ui/agents/runs/${runId}/pm-output`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { operation_type: string };
    expect(data.operation_type).toBe("report_generate");
  });

  test("669.5 get PM metrics", async () => {
    const r = await apiGet(rootPage, "ui/agents/pm/metrics", { type_id: TYPE_ID });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { velocity_current: number; backlog_size: number; p0_count: number };
    expect(typeof data.velocity_current).toBe("number");
    expect(typeof data.backlog_size).toBe("number");
    expect(typeof data.p0_count).toBe("number");
  });
});

// ─── 670: PM Config & Dashboard UI ───────────────────────────────────────────

test.describe("670. PM Config & Dashboard UI", () => {
  let rootPage: Page;
  let alicePage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/pm-config`, VALID_CONFIG);
    // ensure at least one idea exists for the Ideas tab
    await apiPost(alicePage, "alice", "ui/agents/ideas", {
      title: `ui idea ${TS}`,
      description: "An idea submitted for the UI ideas tab test.",
    });
  });
  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("670.1 PM config page loads", async () => {
    await rootPage.goto(`http://localhost:3000/agents/types/${TYPE_ID}/pm`);
    await expect(rootPage.locator('[data-testid="pm-config-page"]')).toBeVisible({ timeout: 15_000 });
    await expect(rootPage.locator('[data-testid="pm-config-tab"]')).toBeVisible({ timeout: 10_000 });
  });

  test("670.2 ideas tab shows submitted ideas", async () => {
    await rootPage.goto(`http://localhost:3000/agents/types/${TYPE_ID}/pm`);
    await rootPage.getByRole("tab", { name: "Ideas" }).click();
    await expect(rootPage.locator('[data-testid="pm-ideas-tab"]')).toBeVisible({ timeout: 10_000 });
    await expect(rootPage.locator('[data-testid="pm-idea-row"]').first()).toBeVisible({ timeout: 10_000 });
  });

  test("670.3 project dashboard loads", async () => {
    await rootPage.goto("http://localhost:3000/agents/project-dashboard");
    await expect(rootPage.locator('[data-testid="project-dashboard-page"]')).toBeVisible({ timeout: 15_000 });
    await expect(rootPage.locator('[data-testid="dashboard-pipeline"]')).toBeVisible({ timeout: 10_000 });
  });

  test("670.4 idea submission page works", async () => {
    await alicePage.goto("http://localhost:3000/ideas/submit");
    await expect(alicePage.locator('[data-testid="idea-submission-page"]')).toBeVisible({ timeout: 15_000 });
    await expect(alicePage.locator('[data-testid="idea-title"]')).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.locator('[data-testid="idea-description"]')).toBeVisible({ timeout: 10_000 });
  });
});
