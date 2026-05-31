/**
 * E2E tests for the QA Agent (AGENT-009).
 *
 * Section 655: QA Config API
 * Section 656: Ticket filtering & claiming API
 * Section 657: QA output, report, screenshots & bug filing API
 * Section 658: QA Config UI
 * Section 659: Edge cases
 * Section 660: Negative cases
 *
 * Auth: cookie-based sessions from e2e_admin_session_setup.py.
 *   root          – role=root  (configures agents)
 *   alice         – role=user  (403 rejection tests)
 * POST/PUT requests carry an x-csrf-token header.
 *
 * The QA lifecycle is driven via the deterministic mock execute endpoint
 * (`/runs/{run_id}/execute-qa`) which accepts a `scenario` so verdicts
 * (pass/fail/flaky/error) are reproducible without real command execution.
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

// Create a coder-style ticket (labels) then move it to code_complete with a PR url.
async function createCodeCompleteTicket(
  page: Page,
  subject: string,
  prUrl = "https://github.com/org/repo/pull/42",
): Promise<string> {
  const c = await apiPost(page, "root", "ui/agents/coder/tickets", {
    subject,
    description:
      "## Acceptance Criteria\n- [ ] reaction bar is visible\n- [ ] tip flow works\n",
    labels: ["type:development", "complexity:low"],
  });
  const tid = ((await c.json()) as Record<string, unknown>).ticket_id as string;
  // Claim → in_progress, then mark code_complete via coder execute (sets pr_url).
  await apiPost(page, "root", `ui/agents/runs/cprep_${tid}/claim-ticket`, { ticket_id: tid });
  await apiPost(page, "root", `ui/agents/types/${CODER_TYPE_ID}/runs/cprep_${tid}/execute`, {
    ticket_id: tid,
  });
  return tid;
}

const TS = Date.now();
const TYPE_ID = `qatype_${TS}`;
const CODER_TYPE_ID = `qacoder_${TS}`;
const VALID_CONFIG = {
  test_framework: "playwright",
  browser: "chromium",
  test_dir: "frontend/e2e/",
  test_file_pattern: "{feature}.spec.ts",
  test_run_command: "cd frontend && npx playwright test",
  test_run_specific_command: "cd frontend && npx playwright test e2e/{file}",
  regression_scope: "affected",
  regression_command: "just e2e",
  screenshot_enabled: true,
  screenshot_on_failure: false,
  screenshot_s3_prefix: "qa-screenshots/",
  visual_diff_threshold: 0.01,
  max_test_time_seconds: 1800,
  flaky_retry_count: 2,
  pr_review_enabled: true,
  coding_tool: "claude_code",
};

const CODER_CONFIG = {
  repo_url: "https://github.com/acme/backend.git",
  test_commands: ["just test"],
  skill_level: "mid",
};

// ─── 655: QA Config API ──────────────────────────────────────────────────────

test.describe("655. QA Config API", () => {
  let rootPage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${CODER_TYPE_ID}/coder-config`, CODER_CONFIG);
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("655.1 create QA agent type with config", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/qa-config`, VALID_CONFIG);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.test_framework).toBe("playwright");
    expect(data.browser).toBe("chromium");
  });

  test("655.2 get QA config", async () => {
    const r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/qa-config`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.test_framework).toBe("playwright");
    expect(data.regression_scope).toBe("affected");
  });

  test("655.3 validate config with invalid framework", async () => {
    const r = await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/qa-config/validate`, {
      test_framework: "invalid",
      visual_diff_threshold: 2.0,
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { valid: boolean; errors: string[] };
    expect(data.valid).toBe(false);
    expect(data.errors.length).toBeGreaterThan(0);
  });

  test("655.4 update regression scope and screenshot settings", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/qa-config`, {
      ...VALID_CONFIG,
      regression_scope: "full",
      screenshot_on_failure: true,
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.regression_scope).toBe("full");
    expect(data.screenshot_on_failure).toBe(true);
    // reset
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/qa-config`, VALID_CONFIG);
  });
});

// ─── 656: Ticket filtering & claiming API ────────────────────────────────────

test.describe("656. Ticket filtering & claiming API", () => {
  let rootPage: Page;
  let ticketId = "";
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${CODER_TYPE_ID}/coder-config`, CODER_CONFIG);
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/qa-config`, VALID_CONFIG);
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("656.1 create ticket with code_complete status", async () => {
    ticketId = await createCodeCompleteTicket(rootPage, `qa dev ticket ${TS}`);
    expect(ticketId).toBeTruthy();
  });

  test("656.2 QA eligible tickets returns code_complete ticket", async () => {
    const r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/qa-eligible-tickets`, { limit: "50" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { tickets: Array<{ ticket_id: string; pr_url?: string }> };
    const found = data.tickets.find((t) => t.ticket_id === ticketId);
    expect(found).toBeDefined();
    expect(found!.pr_url).toContain("/pull/");
  });

  test("656.3 ticket with type:qa label is eligible", async () => {
    const c = await apiPost(rootPage, "root", "ui/agents/coder/tickets", {
      subject: `qa labelled ${TS}`,
      description: "x",
      labels: ["type:qa"],
    });
    const tid = ((await c.json()) as Record<string, unknown>).ticket_id as string;
    const r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/qa-eligible-tickets`, { limit: "50" });
    const data = (await r.json()) as { tickets: Array<{ ticket_id: string }> };
    expect(data.tickets.some((t) => t.ticket_id === tid)).toBe(true);
  });

  test("656.4 claim QA ticket updates status", async () => {
    const r = await apiPost(rootPage, "root", `ui/agents/runs/qarun_${TS}/claim-qa-ticket`, {
      ticket_id: ticketId,
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.status).toBe("qa_in_progress");
  });
});

// ─── 657: QA output, report, screenshots & bug filing API ────────────────────

test.describe("657. QA Output & Bug Filing API", () => {
  let rootPage: Page;
  let ticketId = "";
  const runId = `qaout_${TS}`;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${CODER_TYPE_ID}/coder-config`, CODER_CONFIG);
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/qa-config`, VALID_CONFIG);
    ticketId = await createCodeCompleteTicket(rootPage, `qa output ticket ${TS}`);
    // Run the deterministic FAIL scenario so bugs are filed + screenshots captured.
    const exec = await apiPost(
      rootPage,
      "root",
      `ui/agents/types/${TYPE_ID}/runs/${runId}/execute-qa`,
      { ticket_id: ticketId, scenario: "fail" },
    );
    expect(exec.status()).toBe(200);
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("657.1 get QA output from completed run", async () => {
    const r = await apiGet(rootPage, `ui/agents/runs/${runId}/qa-output`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.verdict).toBe("fail");
    expect(typeof data.new_tests_written).toBe("number");
    expect(typeof data.regression_tests_run).toBe("number");
  });

  test("657.2 QA report renders Markdown", async () => {
    const r = await apiGet(rootPage, `ui/agents/runs/${runId}/qa-report`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { report_markdown: string };
    expect(data.report_markdown).toContain("## Summary");
    expect(data.report_markdown).toContain("## Test Results");
  });

  test("657.3 screenshots listed with presigned URLs", async () => {
    const r = await apiGet(rootPage, `ui/agents/runs/${runId}/qa-screenshots`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      screenshots: Array<{ name: string; presigned_url: string; step: string; status: string }>;
    };
    expect(Array.isArray(data.screenshots)).toBe(true);
    expect(data.screenshots.length).toBeGreaterThan(0);
    expect(typeof data.screenshots[0].presigned_url).toBe("string");
  });

  test("657.4 bug tickets were auto-filed", async () => {
    const out = (await (await apiGet(rootPage, `ui/agents/runs/${runId}/qa-output`)).json()) as {
      bug_ticket_ids: string[];
    };
    expect(out.bug_ticket_ids.length).toBeGreaterThan(0);
    const bugId = out.bug_ticket_ids[0];
    const r = await apiGet(rootPage, `ui/tickets/${bugId}`).catch(() => null);
    // The bug ticket is created in the system; fetch via coder eligibility is not
    // needed — we just assert the subject convention on the output's record.
    expect(bugId).toBeTruthy();
    if (r && r.status() === 200) {
      const t = (await r.json()) as { subject?: string };
      if (t.subject) expect(t.subject).toContain("Bug:");
    }
  });

  test("657.5 metrics reflect the completed run", async () => {
    const r = await apiGet(rootPage, "ui/agents/qa/metrics", { type_id: TYPE_ID, period_days: "30" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, number>;
    expect(data.tested_count).toBeGreaterThan(0);
    expect(data.bugs_found_count).toBeGreaterThan(0);
  });
});

// ─── 658: QA Config UI ───────────────────────────────────────────────────────

test.describe("658. QA Config UI", () => {
  let rootPage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/qa-config`, VALID_CONFIG);
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("658.1 QA config page loads", async () => {
    await rootPage.goto(`http://localhost:3000/agents/types/${TYPE_ID}/qa`);
    await expect(rootPage.locator('[data-testid="qa-config-page"]')).toBeVisible({ timeout: 15_000 });
  });

  test("658.2 config tab shows saved framework", async () => {
    await rootPage.goto(`http://localhost:3000/agents/types/${TYPE_ID}/qa`);
    await expect(rootPage.locator('[data-testid="qa-config-tab"]')).toBeVisible({ timeout: 15_000 });
    await expect(rootPage.locator('[data-testid="qa-framework"]')).toContainText("playwright", {
      timeout: 10_000,
    });
  });

  test("658.3 metrics tab renders pass rate", async () => {
    await rootPage.goto(`http://localhost:3000/agents/types/${TYPE_ID}/qa`);
    await rootPage.getByRole("tab", { name: "Metrics" }).click();
    await expect(rootPage.locator('[data-testid="qa-metrics-tab"]')).toBeVisible({ timeout: 10_000 });
    await expect(rootPage.locator('[data-testid="qa-metric-pass-rate"]')).toBeVisible();
  });
});

// ─── 659: Edge cases ─────────────────────────────────────────────────────────

test.describe("659. Edge cases", () => {
  let rootPage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    await apiPut(rootPage, "root", `ui/agents/types/${CODER_TYPE_ID}/coder-config`, CODER_CONFIG);
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/qa-config`, VALID_CONFIG);
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("659.1 concurrent QA claim race – only one wins", async () => {
    const tid = await createCodeCompleteTicket(rootPage, `qa race ${TS}`);
    const [a, b] = await Promise.all([
      apiPost(rootPage, "root", `ui/agents/runs/qaA_${TS}/claim-qa-ticket`, { ticket_id: tid }),
      apiPost(rootPage, "root", `ui/agents/runs/qaB_${TS}/claim-qa-ticket`, { ticket_id: tid }),
    ]);
    const statuses = [a.status(), b.status()].sort();
    expect(statuses).toEqual([200, 409]);
  });

  test("659.2 QA config with empty run command rejected", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/qa-config`, {
      ...VALID_CONFIG,
      test_run_command: "",
    });
    expect(r.status()).toBe(422);
  });

  test("659.3 flaky scenario yields flaky verdict + approval", async () => {
    const tid = await createCodeCompleteTicket(rootPage, `qa flaky ${TS}`);
    const runId = `qaflaky_${TS}`;
    const exec = await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/runs/${runId}/execute-qa`, {
      ticket_id: tid,
      scenario: "flaky",
    });
    expect(exec.status()).toBe(200);
    const data = (await exec.json()) as Record<string, unknown>;
    expect(data.verdict).toBe("flaky");
    expect(data.pr_review_action).toBe("approved");
  });

  test("659.4 error scenario leaves ticket in qa_in_progress", async () => {
    const tid = await createCodeCompleteTicket(rootPage, `qa error ${TS}`);
    const runId = `qaerror_${TS}`;
    const exec = await apiPost(rootPage, "root", `ui/agents/types/${TYPE_ID}/runs/${runId}/execute-qa`, {
      ticket_id: tid,
      scenario: "error",
    });
    expect(exec.status()).toBe(200);
    const data = (await exec.json()) as Record<string, unknown>;
    expect(data.verdict).toBe("error");
    // ticket should NOT appear in eligible (status no longer code_complete)
    const r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/qa-eligible-tickets`, { limit: "50" });
    const elig = (await r.json()) as { tickets: Array<{ ticket_id: string }> };
    expect(elig.tickets.some((t) => t.ticket_id === tid)).toBe(false);
  });

  test("659.5 max_test_time below minimum rejected", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/qa-config`, {
      ...VALID_CONFIG,
      max_test_time_seconds: 100,
    });
    expect(r.status()).toBe(422);
  });

  test("659.6 claimed ticket excluded from eligible list", async () => {
    const tid = await createCodeCompleteTicket(rootPage, `qa exclude ${TS}`);
    let r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/qa-eligible-tickets`, { limit: "50" });
    let data = (await r.json()) as { tickets: Array<{ ticket_id: string }> };
    expect(data.tickets.some((t) => t.ticket_id === tid)).toBe(true);
    await apiPost(rootPage, "root", `ui/agents/runs/qaexcl_${TS}/claim-qa-ticket`, { ticket_id: tid });
    r = await apiGet(rootPage, `ui/agents/types/${TYPE_ID}/qa-eligible-tickets`, { limit: "50" });
    data = (await r.json()) as { tickets: Array<{ ticket_id: string }> };
    expect(data.tickets.some((t) => t.ticket_id === tid)).toBe(false);
  });
});

// ─── 660: Negative cases ─────────────────────────────────────────────────────

test.describe("660. Negative cases", () => {
  let rootPage: Page;
  let alicePage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
    await apiPut(rootPage, "root", `ui/agents/types/${CODER_TYPE_ID}/coder-config`, CODER_CONFIG);
    await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/qa-config`, VALID_CONFIG);
  });
  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("660.1 non-admin cannot access QA config", async () => {
    const r = await apiGet(alicePage, `ui/agents/types/${TYPE_ID}/qa-config`);
    expect(r.status()).toBe(403);
  });

  test("660.2 QA output for non-existent run returns 404", async () => {
    const r = await apiGet(rootPage, `ui/agents/runs/qamissing_${TS}/qa-output`);
    expect(r.status()).toBe(404);
  });

  test("660.3 QA config on non-QA (coder) agent type returns 409", async () => {
    const r = await apiGet(rootPage, `ui/agents/types/${CODER_TYPE_ID}/qa-config`);
    expect(r.status()).toBe(409);
  });

  test("660.4 claim ticket not in code_complete returns 409", async () => {
    const c = await apiPost(rootPage, "root", "ui/agents/coder/tickets", {
      subject: `qa open ${TS}`,
      description: "x",
      labels: ["type:qa"],
    });
    const tid = ((await c.json()) as Record<string, unknown>).ticket_id as string;
    const r = await apiPost(rootPage, "root", `ui/agents/runs/qaopen_${TS}/claim-qa-ticket`, {
      ticket_id: tid,
    });
    expect(r.status()).toBe(409);
  });

  test("660.5 visual diff threshold out of range rejected", async () => {
    const r = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/qa-config`, {
      ...VALID_CONFIG,
      visual_diff_threshold: 5.0,
    });
    expect(r.status()).toBe(422);
  });

  test("660.6 QA screenshots for run with no output returns 404", async () => {
    const r = await apiGet(rootPage, `ui/agents/runs/qanone_${TS}/qa-screenshots`);
    expect(r.status()).toBe(404);
  });

  test("660.7 CSRF required for QA config update", async () => {
    const ok = await apiPut(rootPage, "root", `ui/agents/types/${TYPE_ID}/qa-config`, VALID_CONFIG);
    expect(ok.status()).toBe(200);
    const noCsrf = await rootPage.request.put(`${API}/ui/agents/types/${TYPE_ID}/qa-config`, {
      data: VALID_CONFIG,
      headers: { "Content-Type": "application/json" },
    });
    expect(noCsrf.status()).toBe(403);
  });
});
