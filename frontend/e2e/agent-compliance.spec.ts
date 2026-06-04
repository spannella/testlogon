/**
 * E2E tests for the Compliance & Security Agent (AGENT-015).
 *
 * Section 679: Security Findings CRUD API (5 tests)
 * Section 680: Finding Status Workflow API (4 tests)
 * Section 681: Audit & Compliance API (4 tests)
 * Section 682: Security Dashboard UI (3 tests)
 * Section 683: Negative & edge cases (4 tests)
 *
 * Auth: cookie-based sessions from e2e_admin_session_setup.py.
 *   root  – role=root (platform owner; can trigger audits)
 *   alice – role=user (403 rejection tests)
 * POST/PUT/PATCH requests carry an x-csrf-token header.
 *
 * Findings/audits are scoped to the authenticated user, so root owns everything
 * created here. The audit trigger is admin-gated (USER → 403).
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
const REF = `PR#${TS}`;
let findingId1 = ""; // critical
let findingId2 = ""; // high
let findingId3 = ""; // medium

// ─── 679: Security Findings CRUD API ─────────────────────────────────────────

test.describe("679. Security Findings CRUD API", () => {
  let rootPage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("679.1 create critical finding", async () => {
    const r = await apiPost(rootPage, "root", "ui/agents/compliance/findings", {
      source: "pr_review",
      source_ref: REF,
      severity: "critical",
      category: "injection",
      title: `SQL injection ${TS}`,
      description: "Unsanitized input concatenated into SQL query.",
      file_path: "app/services/legacy.py",
      line_range: "42-44",
      code_snippet: "cursor.execute('SELECT * FROM u WHERE id=' + uid)",
      remediation: "Use parameterized queries.",
    });
    expect(r.status()).toBe(201);
    const data = (await r.json()) as Record<string, unknown>;
    findingId1 = data.finding_id as string;
    expect(typeof findingId1).toBe("string");
    expect(data.status).toBe("open");
    expect(data.severity).toBe("critical");
  });

  test("679.2 create high finding with remediation", async () => {
    const r = await apiPost(rootPage, "root", "ui/agents/compliance/findings", {
      source: "pr_review",
      source_ref: REF,
      severity: "high",
      category: "xss",
      title: `Reflected XSS ${TS}`,
      description: "User input rendered without escaping.",
      remediation: "Escape output and use a templating autoescape.",
    });
    expect(r.status()).toBe(201);
    const data = (await r.json()) as Record<string, unknown>;
    findingId2 = data.finding_id as string;
    expect(data.remediation).toBe("Escape output and use a templating autoescape.");
  });

  test("679.3 create medium compliance finding", async () => {
    const r = await apiPost(rootPage, "root", "ui/agents/compliance/findings", {
      source: "periodic_audit",
      source_ref: `audit-${TS}`,
      severity: "medium",
      category: "gdpr_pii",
      title: `PII in logs ${TS}`,
      description: "Email addresses written to application logs.",
    });
    expect(r.status()).toBe(201);
    const data = (await r.json()) as Record<string, unknown>;
    findingId3 = data.finding_id as string;
    expect(data.category).toBe("gdpr_pii");
  });

  test("679.4 list findings by severity", async () => {
    const r = await apiGet(rootPage, "ui/agents/compliance/findings", { severity: "critical", limit: "100" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { findings: Array<{ severity: string; finding_id: string }> };
    expect(data.findings.every((f) => f.severity === "critical")).toBe(true);
    expect(data.findings.some((f) => f.finding_id === findingId1)).toBe(true);
  });

  test("679.5 get single finding detail", async () => {
    const r = await apiGet(rootPage, `ui/agents/compliance/findings/${findingId1}`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.description).toContain("Unsanitized");
    expect(data.code_snippet).toContain("SELECT");
    expect(data.remediation).toContain("parameterized");
  });
});

// ─── 680: Finding Status Workflow API ────────────────────────────────────────

test.describe("680. Finding Status Workflow API", () => {
  let rootPage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("680.1 acknowledge finding", async () => {
    const r = await apiPatch(rootPage, "root", `ui/agents/compliance/findings/${findingId2}/status`, {
      status: "acknowledged",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.status).toBe("acknowledged");
  });

  test("680.2 mark finding as false positive", async () => {
    const r = await apiPatch(rootPage, "root", `ui/agents/compliance/findings/${findingId3}/status`, {
      status: "false_positive",
      note: "This is test code",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.status).toBe("false_positive");
  });

  test("680.3 mark finding as remediated", async () => {
    const r = await apiPatch(rootPage, "root", `ui/agents/compliance/findings/${findingId1}/status`, {
      status: "remediated",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.status).toBe("remediated");
    expect(typeof data.resolved_at).toBe("number");
  });

  test("680.4 list open findings only", async () => {
    const r = await apiGet(rootPage, "ui/agents/compliance/findings", { status: "open", limit: "200" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { findings: Array<{ finding_id: string; status: string }> };
    expect(data.findings.every((f) => f.status === "open")).toBe(true);
    const ids = data.findings.map((f) => f.finding_id);
    expect(ids).not.toContain(findingId1);
    expect(ids).not.toContain(findingId2);
    expect(ids).not.toContain(findingId3);
  });
});

// ─── 681: Audit & Compliance API ─────────────────────────────────────────────

test.describe("681. Audit & Compliance API", () => {
  let rootPage: Page;
  let auditId = "";
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("681.1 trigger security audit", async () => {
    const r = await apiPost(rootPage, "root", "ui/agents/compliance/audits/trigger", {});
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    auditId = data.audit_id as string;
    expect(typeof auditId).toBe("string");
    // mock audit completes synchronously
    expect(["running", "completed"]).toContain(data.status);
  });

  test("681.2 list audits", async () => {
    const r = await apiGet(rootPage, "ui/agents/compliance/audits", { limit: "50" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { audits: Array<{ audit_id: string }> };
    expect(data.audits.some((a) => a.audit_id === auditId)).toBe(true);
  });

  test("681.3 get finding trends", async () => {
    const r = await apiGet(rootPage, "ui/agents/compliance/trends", { days: "30" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { weeks: Array<{ by_severity: Record<string, number> }> };
    expect(Array.isArray(data.weeks)).toBe(true);
  });

  test("681.4 get compliance status", async () => {
    const r = await apiGet(rootPage, "ui/agents/compliance/compliance");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { frameworks: Record<string, unknown> };
    expect(Object.keys(data.frameworks).length).toBeGreaterThan(0);
  });
});

// ─── 682: Security Dashboard UI ──────────────────────────────────────────────

test.describe("682. Security Dashboard UI", () => {
  let rootPage: Page;
  let uiFindingId = "";
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    // ensure at least one open finding exists for the UI
    const r = await apiPost(rootPage, "root", "ui/agents/compliance/findings", {
      source: "manual_scan",
      source_ref: `ui-${TS}`,
      severity: "high",
      category: "broken_auth",
      title: `UI finding ${TS}`,
      description: "Missing session timeout.",
    });
    uiFindingId = ((await r.json()) as Record<string, unknown>).finding_id as string;
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("682.1 security dashboard loads", async () => {
    await rootPage.goto("http://localhost:3000/agents/security");
    await expect(rootPage.locator('[data-testid="security-dashboard-page"]')).toBeVisible({
      timeout: 15_000,
    });
    await expect(rootPage.locator('[data-testid="summary-critical"]')).toBeVisible();
  });

  test("682.2 findings list with severity badges", async () => {
    await rootPage.goto("http://localhost:3000/agents/security");
    await expect(rootPage.locator('[data-testid="findings-list"]')).toBeVisible({ timeout: 15_000 });
    await expect(
      rootPage.locator('[data-testid^="severity-badge-"]').first(),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("682.3 update finding status via UI", async () => {
    await rootPage.goto("http://localhost:3000/agents/security");
    await expect(rootPage.locator('[data-testid="findings-list"]')).toBeVisible({ timeout: 15_000 });
    const ackBtn = rootPage.locator(`[data-testid="ack-${uiFindingId}"]`);
    await expect(ackBtn).toBeVisible({ timeout: 10_000 });
    await ackBtn.click();
    await expect(rootPage.locator(`[data-testid="finding-status-${uiFindingId}"]`)).toHaveText(
      "acknowledged",
      { timeout: 10_000 },
    );
  });
});

// ─── 683: Negative & edge cases ──────────────────────────────────────────────

test.describe("683. Negative & edge cases", () => {
  let rootPage: Page;
  let alicePage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("683.1 non-admin cannot trigger audit", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/compliance/audits/trigger", {});
    expect(r.status()).toBe(403);
  });

  test("683.2 invalid severity filter rejected", async () => {
    const r = await apiGet(rootPage, "ui/agents/compliance/findings", { severity: "mega" });
    expect(r.status()).toBe(422);
  });

  test("683.3 get nonexistent finding returns 404", async () => {
    const r = await apiGet(rootPage, `ui/agents/compliance/findings/nope_${TS}`);
    expect(r.status()).toBe(404);
  });

  test("683.4 invalid status transition rejected", async () => {
    // findingId1 was remediated in 680.3 (terminal); re-acknowledging is a 409.
    const r = await apiPatch(rootPage, "root", `ui/agents/compliance/findings/${findingId1}/status`, {
      status: "acknowledged",
    });
    expect(r.status()).toBe(409);
  });
});
