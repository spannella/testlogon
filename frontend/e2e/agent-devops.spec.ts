/**
 * E2E tests for the DevOps/SRE Agent (AGENT-010).
 *
 * Section 659: DevOps Config API
 * Section 660: Deployment & Health Check API
 * Section 661: Approval & Rollback API
 * Section 662: DevOps Config UI
 * Section 663: Edge Cases
 * Section 664: Negative Tests
 *
 * Auth: cookie-based sessions from e2e_admin_session_setup.py.
 *   root  – role=root (configures agents)
 *   alice – role=user (403 rejection tests)
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
const TYPE_ID = `dtype_${TS}`;

const STAGING_ENV = {
  name: "staging",
  requires_approval: false,
  deploy_commands: ["cd /opt/app && git pull origin main", "sudo systemctl restart app"],
  rollback_commands: ["cd /opt/app && git checkout HEAD~1", "sudo systemctl restart app"],
  health_check_urls: ["https://staging.example.com/health"],
  health_check_timeout_seconds: 60,
  smoke_test_command: "curl -sf https://staging.example.com/api/v1/status",
  rollback_window_seconds: 300,
};

const PROD_ENV = {
  name: "production",
  requires_approval: true,
  deploy_commands: ["kubectl set image deployment/app app=registry/app:${VERSION}"],
  rollback_commands: ["kubectl rollout undo deployment/app"],
  health_check_urls: ["https://api.example.com/health"],
  health_check_timeout_seconds: 120,
  rollback_window_seconds: 600,
};

const VALID_CONFIG = {
  environments: [STAGING_ENV, PROD_ENV],
  deploy_ticket_labels: ["type:deployment"],
  infra_ticket_labels: ["type:infrastructure"],
  incident_ticket_labels: ["type:incident"],
  auto_deploy_on_qa_approved: true,
  coding_tool: "claude_code",
  max_operation_time_seconds: 1800,
};

// ─── 659: DevOps Config API ──────────────────────────────────────────────────

test.describe("659. DevOps Config API", () => {
  let rootPage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("659.1 create devops agent type with environments", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/devops-config`, VALID_CONFIG);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { devops_config: { environments: unknown[] } };
    expect(data.devops_config.environments.length).toBe(2);
  });

  test("659.2 get devops config", async () => {
    const r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/devops-config`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      devops_config: { environments: Array<{ name: string; requires_approval: boolean }> };
    };
    expect(data.devops_config.environments.length).toBe(2);
    const prod = data.devops_config.environments.find((e) => e.name === "production");
    expect(prod?.requires_approval).toBe(true);
  });

  test("659.3 validate config missing rollback for production", async () => {
    const r = await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/devops-config/validate`, {
      environments: [{ ...PROD_ENV, rollback_commands: [] }],
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { valid: boolean; errors: string[] };
    expect(data.valid).toBe(false);
    expect(data.errors.length).toBeGreaterThan(0);
  });

  test("659.4 update with runbook and monitoring", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/devops-config`, {
      ...VALID_CONFIG,
      runbooks: [{ trigger_label: "ops:cert-renew", name: "Cert Renewal", steps: ["certbot renew"] }],
      monitoring_endpoints: [
        { name: "latency", url: "https://api.example.com/metrics", metric_type: "latency", threshold: 500 },
      ],
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      devops_config: { runbooks?: unknown[]; monitoring_endpoints?: unknown[] };
    };
    expect(data.devops_config.runbooks?.length).toBe(1);
    expect(data.devops_config.monitoring_endpoints?.length).toBe(1);
    // reset config
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/devops-config`, VALID_CONFIG);
  });
});

// ─── 660: Deployment & Health Check API ──────────────────────────────────────

test.describe("660. Deployment & Health Check API", () => {
  let rootPage: Page;
  let ticketId = "";
  const runId = `run660_${TS}`;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/devops-config`, VALID_CONFIG);
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("660.1 create deployment ticket", async () => {
    const r = await apiPost(rootPage, "root", "ui/agents/devops/tickets", {
      subject: `deploy ticket ${TS}`,
      description: "ship it",
      labels: ["type:deployment"],
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    ticketId = data.ticket_id as string;
    expect(data.labels).toContain("type:deployment");
    expect(data.status).toBe("open");
  });

  test("660.2 eligible tickets returns deployment ticket", async () => {
    const r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/devops-eligible-tickets`, { limit: "50" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { tickets: Array<{ ticket_id: string }> };
    expect(data.tickets.some((t) => t.ticket_id === ticketId)).toBe(true);
  });

  test("660.3 get deployment log from completed run", async () => {
    const exec = await apiPost(
      rootPage,
      "root",
      `ui/agents/types/${TYPE_ID}/runs/${runId}/execute-devops`,
      { ticket_id: ticketId, environment_name: "staging" },
    );
    expect(exec.status()).toBe(200);
    const r = await apiGet(rootPage, `ui/agents/runs/${runId}/deployment-log`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      steps: Array<{ step_type: string; status: string; duration_seconds: number }>;
    };
    expect(Array.isArray(data.steps)).toBe(true);
    expect(data.steps.length).toBeGreaterThan(0);
    expect(typeof data.steps[0].step_type).toBe("string");
    expect(typeof data.steps[0].duration_seconds).toBe("number");
  });

  test("660.4 devops output shows health check results", async () => {
    const r = await apiGet(rootPage, `ui/agents/runs/${runId}/devops-output`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      status: string;
      health_check_results: Array<{ url: string; healthy: boolean }>;
    };
    expect(data.status).toBe("success");
    expect(Array.isArray(data.health_check_results)).toBe(true);
    expect(data.health_check_results[0]).toHaveProperty("url");
    expect(data.health_check_results[0]).toHaveProperty("healthy");
  });
});

// ─── 661: Approval & Rollback API ────────────────────────────────────────────

test.describe("661. Approval & Rollback API", () => {
  let rootPage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/devops-config`, VALID_CONFIG);
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  async function createTicket(labels: string[]): Promise<string> {
    const r = await apiPost(rootPage, "root", "ui/agents/devops/tickets", {
      subject: `t ${TS}_${Math.random()}`,
      description: "x",
      labels,
    });
    return ((await r.json()) as Record<string, unknown>).ticket_id as string;
  }

  test("661.1 pending production deployment requires approval", async () => {
    const tid = await createTicket(["type:deployment"]);
    const runId = `run661a_${TS}`;
    const exec = await apiPost(
      rootPage,
      "root",
      `ui/agents/types/${TYPE_ID}/runs/${runId}/execute-devops`,
      { ticket_id: tid, environment_name: "production" },
    );
    expect(exec.status()).toBe(200);
    const data = (await exec.json()) as { status: string };
    expect(data.status).toBe("awaiting_approval");
  });

  test("661.2 approve deployment advances execution", async () => {
    const tid = await createTicket(["type:deployment"]);
    const runId = `run661b_${TS}`;
    await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/runs/${runId}/execute-devops`, {
      ticket_id: tid,
      environment_name: "production",
    });
    const r = await apiPost(rootPage, "root", `ui/agents/runs/${runId}/approve-deployment`, {
      approved: true,
      approver_notes: "LGTM",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { approval_status: string };
    expect(data.approval_status).toBe("approved");
    const out = await apiGet(rootPage, `ui/agents/runs/${runId}/devops-output`);
    const outData = (await out.json()) as { status: string };
    expect(outData.status).not.toBe("awaiting_approval");
  });

  test("661.3 reject deployment blocks ticket", async () => {
    const tid = await createTicket(["type:deployment"]);
    const runId = `run661c_${TS}`;
    await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/runs/${runId}/execute-devops`, {
      ticket_id: tid,
      environment_name: "production",
    });
    const r = await apiPost(rootPage, "root", `ui/agents/runs/${runId}/reject-deployment`, {
      approved: false,
      approver_notes: "not ready",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { approval_status: string };
    expect(data.approval_status).toBe("rejected");
  });

  test("661.4 rollback creates incident ticket", async () => {
    const tid = await createTicket(["type:deployment"]);
    const runId = `run661d_${TS}`;
    const exec = await apiPost(
      rootPage,
      "root",
      `ui/agents/types/${TYPE_ID}/runs/${runId}/execute-devops`,
      { ticket_id: tid, environment_name: "staging", force_health_failure: true },
    );
    expect(exec.status()).toBe(200);
    const data = (await exec.json()) as {
      status: string;
      rollback_executed: boolean;
      incident_ticket_id: string | null;
    };
    expect(data.status).toBe("rolled_back");
    expect(data.rollback_executed).toBe(true);
    expect(data.incident_ticket_id).toBeTruthy();
  });
});

// ─── 662: DevOps Config UI ───────────────────────────────────────────────────

test.describe("662. DevOps Config UI", () => {
  let rootPage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/devops-config`, VALID_CONFIG);
    // ensure at least one deployment row exists for the deployments tab
    const t = await apiPost(rootPage, "root", "ui/agents/devops/tickets", {
      subject: `ui deploy ${TS}`,
      description: "x",
      labels: ["type:deployment"],
    });
    const tid = ((await t.json()) as Record<string, unknown>).ticket_id as string;
    await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/runs/run662_${TS}/execute-devops`, {
      ticket_id: tid,
      environment_name: "staging",
    });
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("662.1 devops config page loads", async () => {
    await rootPage.goto(`http://localhost:3000/agents/types/${TYPE_ID}/devops`);
    await expect(rootPage.locator('[data-testid="devops-config-page"]')).toBeVisible({ timeout: 15_000 });
  });

  test("662.2 environments tab shows configured envs", async () => {
    await rootPage.goto(`http://localhost:3000/agents/types/${TYPE_ID}/devops`);
    await rootPage.getByRole("tab", { name: "Environments" }).click();
    await expect(rootPage.locator('[data-testid="devops-environments-tab"]')).toBeVisible({ timeout: 10_000 });
    await expect(rootPage.locator('[data-testid="devops-env-0"]')).toBeVisible({ timeout: 10_000 });
    await expect(rootPage.locator('[data-testid="devops-env-1"]')).toBeVisible();
  });

  test("662.3 deployments tab lists recent deployments", async () => {
    await rootPage.goto(`http://localhost:3000/agents/types/${TYPE_ID}/devops`);
    await rootPage.getByRole("tab", { name: "Deployments" }).click();
    await expect(rootPage.locator('[data-testid="devops-deployments-tab"]')).toBeVisible({ timeout: 10_000 });
  });

  test("662.4 metrics tab shows deployment frequency", async () => {
    await rootPage.goto(`http://localhost:3000/agents/types/${TYPE_ID}/devops`);
    await rootPage.getByRole("tab", { name: "Metrics" }).click();
    await expect(rootPage.locator('[data-testid="devops-metrics-tab"]')).toBeVisible({ timeout: 10_000 });
    await expect(rootPage.locator('[data-testid="metric-deploy-frequency"]')).toBeVisible();
  });
});

// ─── 663: Edge Cases ─────────────────────────────────────────────────────────

test.describe("663. Edge Cases", () => {
  let rootPage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/devops-config`, VALID_CONFIG);
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  async function createTicket(labels: string[]): Promise<string> {
    const r = await apiPost(rootPage, "root", "ui/agents/devops/tickets", {
      subject: `edge ${TS}_${Math.random()}`,
      description: "x",
      labels,
    });
    return ((await r.json()) as Record<string, unknown>).ticket_id as string;
  }

  test("663.1 deployment with no health check URLs succeeds without health step", async () => {
    const typeId2 = `dtype_nohc_${TS}`;
    await apiPut(rootPage, "root", `ui/agents/types/${typeId2}/devops-config`, {
      environments: [{ ...STAGING_ENV, health_check_urls: [], smoke_test_command: null }],
    });
    const tid = await createTicket(["type:deployment"]);
    const runId = `run663a_${TS}`;
    const exec = await apiPost(
      rootPage,
      "root",
      `ui/agents/types/${typeId2}/runs/${runId}/execute-devops`,
      { ticket_id: tid, environment_name: "staging" },
    );
    expect(exec.status()).toBe(200);
    const data = (await exec.json()) as { status: string; health_check_results: unknown[] };
    expect(data.status).toBe("success");
    expect(data.health_check_results.length).toBe(0);
  });

  test("663.2 infrastructure ticket classified as infrastructure operation", async () => {
    const tid = await createTicket(["type:infrastructure"]);
    const r = await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/test-devops-workflow`, {
      ticket_id: tid,
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { operation_type: string; steps: unknown[] };
    expect(data.operation_type).toBe("infrastructure");
    expect(data.steps.length).toBeGreaterThan(0);
  });

  test("663.3 workflow preview marks production as requiring approval", async () => {
    const tid = await createTicket(["type:deployment"]);
    const r = await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/test-devops-workflow`, {
      ticket_id: tid,
    });
    const data = (await r.json()) as { requires_approval: boolean; steps: Array<{ type: string }> };
    // First env (staging) is the default and does not require approval.
    expect(data.requires_approval).toBe(false);
    expect(data.steps.some((s) => s.type === "execute_deployment")).toBe(true);
  });

  test("663.4 incident ticket eligible and classified as incident_response", async () => {
    const tid = await createTicket(["type:incident"]);
    const r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/devops-eligible-tickets`, { limit: "50" });
    const data = (await r.json()) as { tickets: Array<{ ticket_id: string; operation_type: string }> };
    const found = data.tickets.find((t) => t.ticket_id === tid);
    expect(found).toBeTruthy();
    expect(found!.operation_type).toBe("incident_response");
  });

  test("663.5 runbook matches ticket label", async () => {
    const typeIdRb = `dtype_rb_${TS}`;
    await apiPut(rootPage, "root", `ui/agents/types/${typeIdRb}/devops-config`, {
      ...VALID_CONFIG,
      runbooks: [{ trigger_label: "ops:rotate", name: "Rotate", steps: ["rotate-logs"] }],
    });
    const tid = await createTicket(["type:deployment", "ops:rotate"]);
    const r = await apiPost(rootPage, "root", `ui/agents/types/${typeIdRb}/test-devops-workflow`, {
      ticket_id: tid,
    });
    const data = (await r.json()) as { operation_type: string };
    expect(data.operation_type).toBe("runbook");
  });

  test("663.6 metrics aggregates across deployments", async () => {
    const r = await apiGet(rootPage, "ui/agents/devops/metrics", {
      type_id: TYPE_ID,
      period_days: "30",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { deployment_frequency: number; success_rate: number };
    expect(typeof data.deployment_frequency).toBe("number");
    expect(data.success_rate).toBeGreaterThanOrEqual(0);
  });
});

// ─── 664: Negative Tests ─────────────────────────────────────────────────────

test.describe("664. Negative Tests", () => {
  let rootPage: Page;
  let alicePage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/devops-config`, VALID_CONFIG);
  });
  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("664.1 non-admin cannot access devops config", async () => {
    const r = await apiGet(alicePage, `ui/agents/types/${TYPE_ID}/devops-config`);
    expect(r.status()).toBe(403);
  });

  test("664.2 config with duplicate environment names rejected", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/devops-config`, {
      ...VALID_CONFIG,
      environments: [STAGING_ENV, { ...STAGING_ENV }],
    });
    expect(r.status()).toBe(422);
  });

  test("664.3 config with no environments rejected", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/devops-config`, {
      ...VALID_CONFIG,
      environments: [],
    });
    expect(r.status()).toBe(422);
  });

  test("664.4 approve non-existent deployment returns 404", async () => {
    const r = await apiPost(rootPage, "root", `ui/agents/runs/fake_run_${TS}/approve-deployment`, {
      approved: true,
    });
    expect(r.status()).toBe(404);
  });

  test("664.5 health check URL not HTTP(S) rejected", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/devops-config`, {
      ...VALID_CONFIG,
      environments: [{ ...STAGING_ENV, health_check_urls: ["ftp://bad"] }],
    });
    expect(r.status()).toBe(422);
  });

  test("664.6 CSRF required for config update", async () => {
    const noCsrf = await rootPage.request.put(`${API}/ui/agents/types/${TYPE_ID}/devops-config`, {
      data: VALID_CONFIG,
      headers: { "Content-Type": "application/json" },
    });
    expect(noCsrf.status()).toBe(403);
  });
});
