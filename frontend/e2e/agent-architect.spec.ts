/**
 * E2E tests for the Solution Architect Agent (AGENT-011).
 *
 * Section 663: Architect Config API (4 tests)
 * Section 664: Feature Decomposition API (4 tests)
 * Section 665: Dependency Graph & Output API (3 tests)
 * Section 666: Architect Config UI (3 tests)
 *
 * Auth: cookie-based sessions from e2e_admin_session_setup.py.
 *   root  – role=root  (configures agents)
 *   alice – role=user  (403 rejection)
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
const TYPE_ID = `atype_${TS}`;
const VALID_CONFIG = {
  repo_url: "https://github.com/acme/backend.git",
  repo_branch: "main",
  reference_docs: ["CLAUDE.md", "docs/dynamodb.md"],
  scan_paths: ["app/services/", "app/routers/", "frontend/src/"],
  ticket_template: "# {subject}\n\n## Overview\n{overview}\n",
  architecture_guidelines: "Use single-table DynamoDB. Routers per domain.",
  max_tickets_per_feature: 8,
  max_analysis_time_seconds: 900,
  ticket_spec_style: "compact",
  coding_tool: "claude_code",
  require_design_review: false,
};

async function createFeatureTicket(page: Page, subject: string): Promise<string> {
  const r = await apiPost(page, "root", "ui/agents/architect/tickets", {
    subject,
    description: "Users want to share short video clips inside DMs and group chats.",
    labels: ["type:feature_request"],
  });
  return ((await r.json()) as Record<string, unknown>).ticket_id as string;
}

// ─── 663: Architect Config API ───────────────────────────────────────────────

test.describe("663. Architect Config API", () => {
  let rootPage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("663.1 create architect agent type with config", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/architect-config`, VALID_CONFIG);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.repo_url).toBe(VALID_CONFIG.repo_url);
    expect(data.ticket_spec_style).toBe("compact");
  });

  test("663.2 get architect config", async () => {
    const r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/architect-config`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.repo_url).toBe(VALID_CONFIG.repo_url);
    expect((data.reference_docs as string[])).toContain("CLAUDE.md");
  });

  test("663.3 update ticket template and guidelines", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/architect-config`, {
      ...VALID_CONFIG,
      ticket_template: "# {subject}\n\n## Overview\n{overview}\n\n## Data\n{data_model}\n",
      architecture_guidelines: "Updated guidelines: prefer React Query.",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.architecture_guidelines).toContain("React Query");
    // reset for downstream tests
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/architect-config`, VALID_CONFIG);
  });

  test("663.4 validate config with invalid repo", async () => {
    const r = await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/architect-config/validate`, {
      repo_url: "",
      reference_docs: [],
      scan_paths: [],
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { valid: boolean; errors: string[] };
    expect(data.valid).toBe(false);
    expect(data.errors.length).toBeGreaterThan(0);
  });
});

// ─── 664: Feature Decomposition API ──────────────────────────────────────────

test.describe("664. Feature Decomposition API", () => {
  let rootPage: Page;
  let featureTicketId = "";
  const runId = `run664_${TS}`;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/architect-config`, VALID_CONFIG);
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("664.1 create feature request ticket", async () => {
    featureTicketId = await createFeatureTicket(rootPage, `video sharing ${TS}`);
    const r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/architect-eligible-tickets`, {
      limit: "100",
    });
    const data = (await r.json()) as { tickets: Array<{ ticket_id: string; status: string }> };
    const found = data.tickets.find((t) => t.ticket_id === featureTicketId);
    expect(found).toBeDefined();
    expect(found!.status).toBe("open");
  });

  test("664.2 eligible tickets returns the feature request", async () => {
    const r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/architect-eligible-tickets`, {
      limit: "100",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { tickets: Array<{ ticket_id: string }> };
    expect(data.tickets.some((t) => t.ticket_id === featureTicketId)).toBe(true);
  });

  test("664.3 decompose and get decomposition for feature", async () => {
    const exec = await apiPost(
      rootPage,
      "root",
      `ui/agents/types/${TYPE_ID}/runs/${runId}/decompose`,
      { ticket_id: featureTicketId },
    );
    expect(exec.status()).toBe(200);
    const r = await apiGet(rootPage, `ui/agents/features/${featureTicketId}/decomposition`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { decomposition_summary: string; total_tickets_created: number };
    expect(data.decomposition_summary.length).toBeGreaterThan(0);
    expect(data.total_tickets_created).toBeGreaterThanOrEqual(1);
  });

  test("664.4 get dev tickets for feature", async () => {
    const r = await apiGet(rootPage, `ui/agents/features/${featureTicketId}/dev-tickets`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      tickets: Array<{ complexity: string; estimated_hours: number; order: number }>;
    };
    expect(data.tickets.length).toBeGreaterThanOrEqual(1);
    expect(typeof data.tickets[0].complexity).toBe("string");
    expect(typeof data.tickets[0].estimated_hours).toBe("number");
    expect(typeof data.tickets[0].order).toBe("number");
  });
});

// ─── 665: Dependency Graph & Output API ──────────────────────────────────────

test.describe("665. Dependency Graph & Output API", () => {
  let rootPage: Page;
  let featureTicketId = "";
  const runId = `run665_${TS}`;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/architect-config`, VALID_CONFIG);
    featureTicketId = await createFeatureTicket(rootPage, `graph feature ${TS}`);
    await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/runs/${runId}/decompose`, {
      ticket_id: featureTicketId,
    });
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("665.1 get dependency graph", async () => {
    const r = await apiGet(rootPage, `ui/agents/features/${featureTicketId}/dependency-graph`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      nodes: Array<{ id: string; order: number }>;
      edges: Array<{ from: string; to: string }>;
    };
    expect(data.nodes.length).toBeGreaterThanOrEqual(1);
    expect(Array.isArray(data.edges)).toBe(true);
  });

  test("665.2 graph has no circular dependencies (orders respect deps)", async () => {
    const r = await apiGet(rootPage, `ui/agents/features/${featureTicketId}/dependency-graph`);
    const data = (await r.json()) as {
      nodes: Array<{ id: string; order: number }>;
      edges: Array<{ from: string; to: string }>;
    };
    const orderById = new Map(data.nodes.map((n) => [n.id, n.order]));
    for (const e of data.edges) {
      // prerequisite (from) must build no later than dependent (to)
      expect(orderById.get(e.from)!).toBeLessThanOrEqual(orderById.get(e.to)!);
    }
  });

  test("665.3 architect output includes design decisions", async () => {
    const r = await apiGet(rootPage, `ui/agents/runs/${runId}/architect-output`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      design_decisions: Array<{ decision: string; rationale: string }>;
    };
    expect(data.design_decisions.length).toBeGreaterThan(0);
    expect(typeof data.design_decisions[0].decision).toBe("string");
    expect(typeof data.design_decisions[0].rationale).toBe("string");
  });
});

// ─── 666: Architect Config UI ────────────────────────────────────────────────

test.describe("666. Architect Config UI", () => {
  let rootPage: Page;
  let featureTicketId = "";
  const runId = `run666_${TS}`;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/architect-config`, VALID_CONFIG);
    featureTicketId = await createFeatureTicket(rootPage, `ui feature ${TS}`);
    await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/runs/${runId}/decompose`, {
      ticket_id: featureTicketId,
    });
    // ensure another open feature request exists for the Features table
    await createFeatureTicket(rootPage, `ui open feature ${TS}`);
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("666.1 architect config page loads", async () => {
    await rootPage.goto(`http://localhost:3000/agents/types/${TYPE_ID}/architect`);
    await expect(rootPage.locator('[data-testid="architect-config-page"]')).toBeVisible({
      timeout: 15_000,
    });
    await expect(rootPage.locator('[data-testid="architect-repo-url"]')).toHaveValue(
      VALID_CONFIG.repo_url,
      { timeout: 10_000 },
    );
  });

  test("666.2 features tab shows feature requests", async () => {
    await rootPage.goto(`http://localhost:3000/agents/types/${TYPE_ID}/architect`);
    await rootPage.getByRole("tab", { name: "Features" }).click();
    await expect(rootPage.locator('[data-testid="architect-features-tab"]')).toBeVisible({
      timeout: 10_000,
    });
    await expect(rootPage.locator('[data-testid="architect-feature-row"]').first()).toBeVisible({
      timeout: 10_000,
    });
  });

  test("666.3 dependency graph renders for a decomposed feature", async () => {
    await rootPage.goto(`http://localhost:3000/agents/types/${TYPE_ID}/architect`);
    await rootPage.getByRole("tab", { name: "Features" }).click();
    await rootPage.locator('[data-testid="architect-feature-lookup"]').fill(featureTicketId);
    await rootPage.getByRole("button", { name: "Open" }).click();
    await expect(rootPage.locator('[data-testid="dependency-graph-view"]')).toBeVisible({
      timeout: 10_000,
    });
    await expect(rootPage.locator('[data-testid="dep-graph-node"]').first()).toBeVisible({
      timeout: 10_000,
    });
  });
});
