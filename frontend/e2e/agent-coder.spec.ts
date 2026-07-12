/**
 * E2E tests for the Coder Agent (AGENT-008).
 *
 * Section 651: Coder Config API
 * Section 652: Ticket filtering & claiming API
 * Section 653: Workflow & output API
 * Section 654: Coder Config UI
 * Section 655: Input validation
 * Section 656: Authorization boundary
 * Section 657: Ticket label filtering
 * Section 658: Workflow edge cases
 *
 * Auth: cookie-based sessions from e2e_admin_session_setup.py.
 *   root          – role=root  (configures agents)
 *   alice         – role=user  (403 rejection tests)
 * POST/PUT requests carry an x-csrf-token header.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

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
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_admin_session_setup.py", {
      cwd: REPO_ROOT,
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

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

const TS = Date.now();
const TYPE_ID = `ctype_${TS}`;
const TYPE_ID_JUNIOR = `ctype_jr_${TS}`;
const VALID_CONFIG = {
  repo_url: "https://github.com/acme/backend.git",
  repo_branch_base: "main",
  branch_pattern: "feat/{ticket_id}-{slug}",
  test_commands: ["just test", "just e2e"],
  test_timeout_seconds: 600,
  test_retry_limit: 3,
  pr_template: "Closes #{ticket_id}\n\n{summary}",
  pr_base_branch: "main",
  skill_level: "mid",
  max_ticket_time_seconds: 3600,
  coding_tool: "claude_code",
};

// ─── 651: Coder Config API ──────────────────────────────────────────────────

test.describe("651. Coder Config API", () => {
  let rootPage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("651.1 create coder agent type with config", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/coder-config`, VALID_CONFIG);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.repo_url).toBe(VALID_CONFIG.repo_url);
    expect(data.skill_level).toBe("mid");
  });

  test("651.2 get coder config", async () => {
    const r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/coder-config`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.repo_url).toBe(VALID_CONFIG.repo_url);
    expect((data.test_commands as string[]).length).toBe(2);
  });

  test("651.3 validate coder config with invalid repo", async () => {
    const r = await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/coder-config/validate`, {
      repo_url: "not-a-url",
      branch_pattern: "my-branch",
      test_commands: [],
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { valid: boolean; errors: string[] };
    expect(data.valid).toBe(false);
    expect(data.errors.length).toBeGreaterThan(0);
  });

  test("651.4 update skill level and time budget", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/coder-config`, {
      ...VALID_CONFIG,
      skill_level: "senior",
      max_ticket_time_seconds: 7200,
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.skill_level).toBe("senior");
    expect(data.max_ticket_time_seconds).toBe(7200);
    // reset back to mid for downstream tests
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/coder-config`, VALID_CONFIG);
  });
});

// ─── 652: Ticket filtering & claiming API ────────────────────────────────────

test.describe("652. Ticket filtering & claiming API", () => {
  let rootPage: Page;
  let ticketId = "";
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/coder-config`, VALID_CONFIG);
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("652.1 create ticket with development label", async () => {
    const r = await apiPost(rootPage, "root", "ui/agents/coder/tickets", {
      subject: `dev ticket ${TS}`,
      description: "implement feature",
      labels: ["type:development", "complexity:medium"],
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    ticketId = data.ticket_id as string;
    expect(data.labels).toContain("type:development");
    expect(data.complexity).toBe("medium");
  });

  test("652.2 eligible tickets returns matching ticket", async () => {
    const r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/eligible-tickets`, { limit: "50" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { tickets: Array<{ ticket_id: string }>; count: number };
    expect(data.tickets.some((t) => t.ticket_id === ticketId)).toBe(true);
  });

  test("652.3 claim ticket assigns to agent", async () => {
    const r = await apiPost(rootPage, "root", `ui/agents/runs/run_${TS}/claim-ticket`, {
      ticket_id: ticketId,
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.status).toBe("in_progress");
    expect(data.assigned_to_sub).toBe(`agent_run_${TS}`);
  });

  test("652.4 claimed ticket no longer eligible", async () => {
    const r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/eligible-tickets`, { limit: "50" });
    const data = (await r.json()) as { tickets: Array<{ ticket_id: string }> };
    expect(data.tickets.some((t) => t.ticket_id === ticketId)).toBe(false);
  });
});

// ─── 653: Workflow & output API ──────────────────────────────────────────────

test.describe("653. Workflow & output API", () => {
  let rootPage: Page;
  let wfTicketId = "";
  const runId = `run653_${TS}`;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/coder-config`, VALID_CONFIG);
    const r = await apiPost(rootPage, "root", "ui/agents/coder/tickets", {
      subject: `workflow ticket ${TS}`,
      description: "build it",
      labels: ["type:development", "complexity:low"],
    });
    wfTicketId = ((await r.json()) as Record<string, unknown>).ticket_id as string;
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("653.1 test workflow generates steps", async () => {
    const r = await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/test-workflow`, {
      ticket_id: wfTicketId,
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { steps: Array<{ type: string }> };
    expect(data.steps.length).toBe(11);
    expect(data.steps[0].type).toBe("clone_repo");
  });

  test("653.2 branch name follows pattern", async () => {
    const r = await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/test-workflow`, {
      ticket_id: wfTicketId,
    });
    const data = (await r.json()) as { branch_name: string };
    expect(data.branch_name.startsWith(`feat/${wfTicketId}-`)).toBe(true);
  });

  test("653.3 PR command uses correct template", async () => {
    const r = await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/test-workflow`, {
      ticket_id: wfTicketId,
    });
    const data = (await r.json()) as { steps: Array<{ type: string; command: string | null }> };
    const prStep = data.steps.find((s) => s.type === "create_pr");
    expect(prStep).toBeDefined();
    expect(prStep!.command).toContain(wfTicketId);
  });

  test("653.4 get coder output from completed run", async () => {
    const exec = await apiPost(
      rootPage,
      "root",
      `ui/agents/types/${TYPE_ID}/runs/${runId}/execute`,
      { ticket_id: wfTicketId },
    );
    expect(exec.status()).toBe(200);
    const r = await apiGet(rootPage, `ui/agents/runs/${runId}/coder-output`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(typeof data.pr_url).toBe("string");
    expect(Array.isArray(data.files_changed)).toBe(true);
    expect(Array.isArray(data.test_results)).toBe(true);
  });
});

// ─── 654: Coder Config UI ────────────────────────────────────────────────────

test.describe("654. Coder Config UI", () => {
  let rootPage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/coder-config`, VALID_CONFIG);
    // ensure at least one eligible ticket exists
    await apiPost(rootPage, "root", "ui/agents/coder/tickets", {
      subject: `ui ticket ${TS}`,
      description: "ui",
      labels: ["type:development", "complexity:low"],
    });
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("654.1 config page loads", async () => {
    await rootPage.goto(`http://localhost:3000/agents/types/${TYPE_ID}/coder`);
    await expect(rootPage.locator('[data-testid="coder-config-page"]')).toBeVisible({ timeout: 15_000 });
  });

  test("654.2 config tab shows saved values", async () => {
    await rootPage.goto(`http://localhost:3000/agents/types/${TYPE_ID}/coder`);
    await expect(rootPage.locator('[data-testid="coder-config-tab"]')).toBeVisible({ timeout: 15_000 });
    await expect(rootPage.locator('[data-testid="coder-repo-url"]')).toHaveValue(VALID_CONFIG.repo_url, {
      timeout: 10_000,
    });
  });

  test("654.3 eligible tickets tab lists tickets", async () => {
    await rootPage.goto(`http://localhost:3000/agents/types/${TYPE_ID}/coder`);
    await rootPage.getByRole("tab", { name: "Eligible Tickets" }).click();
    await expect(rootPage.locator('[data-testid="eligible-tickets-tab"]')).toBeVisible({ timeout: 10_000 });
  });

  test("654.4 metrics tab renders cards", async () => {
    await rootPage.goto(`http://localhost:3000/agents/types/${TYPE_ID}/coder`);
    await rootPage.getByRole("tab", { name: "Metrics" }).click();
    await expect(rootPage.locator('[data-testid="coder-metrics-tab"]')).toBeVisible({ timeout: 10_000 });
    await expect(rootPage.locator('[data-testid="metric-completed"]')).toBeVisible();
  });
});

// ─── 655: Input validation ───────────────────────────────────────────────────

test.describe("655. Input validation", () => {
  let rootPage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("655.1 empty repo URL rejected", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/coder-config`, {
      ...VALID_CONFIG,
      repo_url: "",
    });
    expect(r.status()).toBe(422);
  });

  test("655.2 invalid repo URL rejected", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/coder-config`, {
      ...VALID_CONFIG,
      repo_url: "ftp://bad",
    });
    expect(r.status()).toBe(422);
  });

  test("655.3 branch pattern without ticket_id rejected", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/coder-config`, {
      ...VALID_CONFIG,
      branch_pattern: "my-branch",
    });
    expect(r.status()).toBe(422);
  });

  test("655.4 empty test_commands rejected", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/coder-config`, {
      ...VALID_CONFIG,
      test_commands: [],
    });
    expect(r.status()).toBe(422);
  });

  test("655.5 test_timeout_seconds below 60 rejected", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/coder-config`, {
      ...VALID_CONFIG,
      test_timeout_seconds: 10,
    });
    expect(r.status()).toBe(422);
  });
});

// ─── 656: Authorization boundary ─────────────────────────────────────────────

test.describe("656. Authorization boundary", () => {
  let rootPage: Page;
  let alicePage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/coder-config`, VALID_CONFIG);
  });
  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("656.1 non-admin cannot read coder config", async () => {
    const r = await apiGet(alicePage, `ui/agents/types/${TYPE_ID}/coder-config`);
    expect(r.status()).toBe(403);
  });

  test("656.2 non-admin cannot update coder config", async () => {
    const r = await apiPut(alicePage, "alice", `ui/agents/types/${TYPE_ID}/coder-config`, VALID_CONFIG);
    expect(r.status()).toBe(403);
  });

  test("656.3 non-admin cannot view eligible tickets", async () => {
    const r = await apiGet(alicePage, `ui/agents/types/${TYPE_ID}/eligible-tickets`);
    expect(r.status()).toBe(403);
  });

  test("656.4 CSRF required for config update", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/coder-config`, VALID_CONFIG);
    expect(r.status()).toBe(200); // sanity: with csrf works
    const noCsrf = await rootPage.request.put(`${API}/ui/agents/types/${TYPE_ID}/coder-config`, {
      data: VALID_CONFIG,
      headers: { "Content-Type": "application/json" },
    });
    expect(noCsrf.status()).toBe(403);
  });
});

// ─── 657: Ticket label filtering ─────────────────────────────────────────────

test.describe("657. Ticket label filtering", () => {
  let rootPage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/coder-config`, VALID_CONFIG);
    // junior agent type
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID_JUNIOR}/coder-config`, {
      ...VALID_CONFIG,
      skill_level: "junior",
    });
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  async function createTicket(labels: string[]): Promise<string> {
    const r = await apiPost(rootPage, "root", "ui/agents/coder/tickets", {
      subject: `lbl ${TS}_${Math.random()}`,
      description: "x",
      labels,
    });
    return ((await r.json()) as Record<string, unknown>).ticket_id as string;
  }

  test("657.1 ticket without dev label not eligible", async () => {
    const tid = await createTicket(["area:backend"]);
    const r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/eligible-tickets`, { limit: "50" });
    const data = (await r.json()) as { tickets: Array<{ ticket_id: string }> };
    expect(data.tickets.some((t) => t.ticket_id === tid)).toBe(false);
  });

  test("657.2 complexity above skill level not eligible", async () => {
    const tid = await createTicket(["type:development", "complexity:high"]);
    const r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID_JUNIOR}/eligible-tickets`, { limit: "50" });
    const data = (await r.json()) as { tickets: Array<{ ticket_id: string }> };
    expect(data.tickets.some((t) => t.ticket_id === tid)).toBe(false);
  });

  test("657.3 claimed ticket disappears from eligible list", async () => {
    const tid = await createTicket(["type:development", "complexity:low"]);
    let r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/eligible-tickets`, { limit: "50" });
    let data = (await r.json()) as { tickets: Array<{ ticket_id: string }> };
    expect(data.tickets.some((t) => t.ticket_id === tid)).toBe(true);
    await apiPost(rootPage, "root", `ui/agents/runs/run657_${TS}/claim-ticket`, { ticket_id: tid });
    r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/eligible-tickets`, { limit: "50" });
    data = (await r.json()) as { tickets: Array<{ ticket_id: string }> };
    expect(data.tickets.some((t) => t.ticket_id === tid)).toBe(false);
  });

  test("657.4 bugfix label tickets also eligible", async () => {
    const tid = await createTicket(["type:bugfix", "complexity:low"]);
    const r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/eligible-tickets`, { limit: "50" });
    const data = (await r.json()) as { tickets: Array<{ ticket_id: string }> };
    expect(data.tickets.some((t) => t.ticket_id === tid)).toBe(true);
  });
});

// ─── 658: Workflow edge cases ────────────────────────────────────────────────

test.describe("658. Workflow edge cases", () => {
  let rootPage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/coder-config`, VALID_CONFIG);
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("658.1 test workflow for nonexistent ticket returns 404", async () => {
    const r = await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/test-workflow`, {
      ticket_id: "nonexistent_xyz",
    });
    expect(r.status()).toBe(404);
  });

  test("658.2 claim already-claimed ticket returns 409", async () => {
    const c = await apiPost(rootPage, "root", "ui/agents/coder/tickets", {
      subject: `dup ${TS}`,
      description: "x",
      labels: ["type:development", "complexity:low"],
    });
    const tid = ((await c.json()) as Record<string, unknown>).ticket_id as string;
    const first = await apiPost(rootPage, "root", `ui/agents/runs/runA_${TS}/claim-ticket`, { ticket_id: tid });
    expect(first.status()).toBe(200);
    const second = await apiPost(rootPage, "root", `ui/agents/runs/runB_${TS}/claim-ticket`, { ticket_id: tid });
    expect(second.status()).toBe(409);
  });

  test("658.3 coder output for run without output returns 404", async () => {
    const r = await apiGet(rootPage, `ui/agents/runs/run_missing_${TS}/coder-output`);
    expect(r.status()).toBe(404);
  });

  test("658.4 metrics returns zeros for new agent type", async () => {
    const r = await apiGet(rootPage, "ui/agents/coder/metrics", { type_id: `empty_${TS}`, period_days: "30" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, number>;
    expect(data.completed_count).toBe(0);
    expect(data.failure_rate).toBe(0);
  });
});
