/**
 * E2E tests for the Documentation Agent (AGENT-014).
 *
 * Section 675: Doc Coverage Registration API
 * Section 676: Freshness & Staleness API
 * Section 677: Doc Templates API
 * Section 678: Doc Coverage UI
 * Section 679: Edge cases
 * Section 680: Negative tests
 *
 * Auth: cookie-based sessions from e2e_admin_session_setup.py.
 *   alice – role=user  (platform owner / primary actor)
 *   bob   – role=user  (secondary; cross-tenant isolation tests)
 * POST/PUT/DELETE requests carry an x-csrf-token header.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";
const APP = "http://localhost:3000";

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

async function apiPost(page: Page, identity: string, path: string, body?: unknown, csrf = true) {
  const sess = getSessions()[identity];
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (csrf) headers["x-csrf-token"] = sess.csrf_token;
  return page.request.post(`${API}/${path}`, { data: body ?? {}, headers });
}

async function apiPut(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.put(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
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
const DOC_API = `docs/api/messaging_${TS}.md`;
const DOC_ARCH = `docs/arch_${TS}.md`;
const DOC_GUIDE = `docs/guides/onboarding_${TS}.md`;
const SRC_MESSAGING = `app/routers/messaging_${TS}.py`;

// ---------------------------------------------------------------------------
// Section 675: Doc Coverage Registration API
// ---------------------------------------------------------------------------

test.describe("675. Doc Coverage Registration API", () => {
  let page: Page;
  test.beforeAll(async ({ browser }) => {
    page = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await page.close();
  });

  test("675.1 register a documentation artifact", async () => {
    const resp = await apiPost(page, "alice", "ui/agents/docs/register", {
      doc_path: DOC_API,
      doc_type: "api",
      source_refs: [SRC_MESSAGING],
      coverage_score: 0.85,
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.doc_path).toBe(DOC_API);
    expect(body.is_stale).toBe(false);
    expect(typeof body.coverage_score).toBe("number");
  });

  test("675.2 register multiple docs of different types", async () => {
    const r1 = await apiPost(page, "alice", "ui/agents/docs/register", {
      doc_path: DOC_ARCH,
      doc_type: "architecture",
      source_refs: [`app/main_${TS}.py`],
      coverage_score: 0.7,
    });
    expect(r1.status()).toBe(201);
    const r2 = await apiPost(page, "alice", "ui/agents/docs/register", {
      doc_path: DOC_GUIDE,
      doc_type: "user_guide",
      source_refs: [],
      coverage_score: 0.6,
    });
    expect(r2.status()).toBe(201);
    const details = await apiGet(page, "ui/agents/docs/coverage/details");
    const body = await details.json();
    expect(body.count).toBeGreaterThanOrEqual(3);
  });

  test("675.3 get coverage summary", async () => {
    const resp = await apiGet(page, "ui/agents/docs/coverage");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(typeof body.overall_coverage).toBe("number");
    expect(body.total_docs).toBeGreaterThanOrEqual(3);
    expect(Object.keys(body.by_type).length).toBeGreaterThan(0);
  });

  test("675.4 list coverage details with type filter", async () => {
    const resp = await apiGet(page, "ui/agents/docs/coverage/details", { doc_type: "api" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.docs.length).toBeGreaterThanOrEqual(1);
    for (const d of body.docs) expect(d.doc_type).toBe("api");
  });
});

// ---------------------------------------------------------------------------
// Section 676: Freshness & Staleness API
// ---------------------------------------------------------------------------

test.describe("676. Freshness & Staleness API", () => {
  let page: Page;
  test.beforeAll(async ({ browser }) => {
    page = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await page.close();
  });

  test("676.1 trigger freshness check", async () => {
    const resp = await apiPost(page, "alice", "ui/agents/docs/freshness-check", {});
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(typeof body.total).toBe("number");
    expect(typeof body.stale).toBe("number");
    expect(typeof body.fresh).toBe("number");
  });

  test("676.2 list stale docs", async () => {
    const resp = await apiGet(page, "ui/agents/docs/stale");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.docs)).toBe(true);
  });

  test("676.3 update doc record clears staleness", async () => {
    const resp = await apiPut(page, "alice", `ui/agents/docs/coverage/${DOC_API}`, {
      source_refs: [SRC_MESSAGING, `app/services/messaging_${TS}.py`],
      coverage_score: 0.95,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.is_stale).toBe(false);
    expect(body.coverage_score).toBeCloseTo(0.95, 2);
    expect(body.last_updated).toBeGreaterThan(0);
  });

  test("676.4 assess PR impact", async () => {
    const resp = await apiPost(page, "alice", "ui/agents/docs/assess-pr", {
      changed_files: [SRC_MESSAGING],
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const paths = body.docs_to_update.map((d: { doc_path: string }) => d.doc_path);
    expect(paths).toContain(DOC_API);
    expect(["none", "low", "medium", "high"]).toContain(body.impact_level);
  });
});

// ---------------------------------------------------------------------------
// Section 677: Doc Templates API
// ---------------------------------------------------------------------------

test.describe("677. Doc Templates API", () => {
  let page: Page;
  let templateId: string;
  test.beforeAll(async ({ browser }) => {
    page = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await page.close();
  });

  test("677.1 create doc template", async () => {
    const resp = await apiPost(page, "alice", "ui/agents/docs/templates", {
      name: `API Endpoint Template ${TS}`,
      doc_type: "api",
      template_body: "# {{endpoint}}\n\n{{description}}",
      required_sections: ["Overview", "Parameters"],
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.template_id).toBeTruthy();
    templateId = body.template_id;
  });

  test("677.2 list templates", async () => {
    const resp = await apiGet(page, "ui/agents/docs/templates");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const found = body.templates.find((t: { template_id: string }) => t.template_id === templateId);
    expect(found).toBeTruthy();
    expect(found.name).toContain("API Endpoint Template");
    expect(found.doc_type).toBe("api");
  });

  test("677.3 update template", async () => {
    const resp = await apiPut(page, "alice", `ui/agents/docs/templates/${templateId}`, {
      template_body: "# Updated {{endpoint}}",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.template_body).toBe("# Updated {{endpoint}}");
  });

  test("677.4 delete template", async () => {
    const resp = await apiDelete(page, "alice", `ui/agents/docs/templates/${templateId}`);
    expect(resp.status()).toBe(200);
    const list = await apiGet(page, "ui/agents/docs/templates");
    const body = await list.json();
    const found = body.templates.find((t: { template_id: string }) => t.template_id === templateId);
    expect(found).toBeFalsy();
  });
});

// ---------------------------------------------------------------------------
// Section 678: Doc Coverage UI
// ---------------------------------------------------------------------------

test.describe("678. Doc Coverage UI", () => {
  let page: Page;
  test.beforeAll(async ({ browser }) => {
    page = await newIdentityPage(browser, "alice");
    // Ensure at least one tracked doc exists for the UI.
    await apiPost(page, "alice", "ui/agents/docs/register", {
      doc_path: `docs/ui_${TS}.md`,
      doc_type: "readme",
      source_refs: [`README_${TS}.md`],
      coverage_score: 0.8,
    });
  });
  test.afterAll(async () => {
    await page.close();
  });

  test("678.1 coverage page loads", async () => {
    await page.goto(`${APP}/agents/docs`);
    await expect(page.locator('[data-testid="doc-coverage-page"]')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText("Overall Coverage")).toBeVisible();
  });

  test("678.2 coverage table lists tracked docs", async () => {
    await page.goto(`${APP}/agents/docs`);
    await expect(page.locator('[data-testid="doc-coverage-page"]')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText(`docs/ui_${TS}.md`)).toBeVisible({ timeout: 10_000 });
  });

  test("678.3 stale docs panel shows flagged docs", async () => {
    await page.goto(`${APP}/agents/docs`);
    await expect(page.locator('[data-testid="doc-coverage-page"]')).toBeVisible({ timeout: 15_000 });
    await page.getByRole("tab", { name: /Stale Only/i }).click();
    await expect(page.locator('[data-testid="stale-docs-panel"]')).toBeVisible({ timeout: 10_000 });
  });

  test("678.4 templates page CRUD", async () => {
    await page.goto(`${APP}/agents/docs/templates`);
    await expect(page.locator('[data-testid="doc-templates-page"]')).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "New Template" }).click();
    const uiName = `UI Template ${TS}`;
    await page.locator("#tmpl-name").fill(uiName);
    await page.locator("#tmpl-body").fill("# {{title}}");
    await page.getByRole("button", { name: "Save" }).click();
    await expect(page.getByText(uiName)).toBeVisible({ timeout: 10_000 });
  });
});

// ---------------------------------------------------------------------------
// Section 679: Edge cases
// ---------------------------------------------------------------------------

test.describe("679. Edge cases", () => {
  let page: Page;
  test.beforeAll(async ({ browser }) => {
    page = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await page.close();
  });

  test("679.1 register duplicate doc path", async () => {
    const path = `docs/dup_${TS}.md`;
    const r1 = await apiPost(page, "alice", "ui/agents/docs/register", {
      doc_path: path,
      doc_type: "readme",
      source_refs: [],
      coverage_score: 1.0,
    });
    expect(r1.status()).toBe(201);
    const r2 = await apiPost(page, "alice", "ui/agents/docs/register", {
      doc_path: path,
      doc_type: "readme",
      source_refs: [],
      coverage_score: 1.0,
    });
    expect(r2.status()).toBe(409);
  });

  test("679.2 coverage summary with no matching type", async () => {
    // adr type has no docs in this run → not present in by_type.
    const resp = await apiGet(page, "ui/agents/docs/coverage/details", { doc_type: "adr" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.docs)).toBe(true);
  });

  test("679.3 assess PR with no matching docs", async () => {
    const resp = await apiPost(page, "alice", "ui/agents/docs/assess-pr", {
      changed_files: [`totally/unrelated_${TS}/nope.py`],
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.docs_to_update.length).toBe(0);
    expect(body.impact_level).toBe("none");
  });

  test("679.4 template with empty required_sections", async () => {
    const resp = await apiPost(page, "alice", "ui/agents/docs/templates", {
      name: `Empty Sections ${TS}`,
      doc_type: "readme",
      template_body: "# Title",
      required_sections: [],
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.required_sections).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Section 680: Negative tests
// ---------------------------------------------------------------------------

test.describe("680. Negative tests", () => {
  let alicePage: Page;
  let bobPage: Page;
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
  });
  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("680.1 other user cannot see Alice's docs", async () => {
    // Bob's coverage is scoped to Bob's user_sub → does not include Alice's docs.
    const resp = await apiGet(bobPage, "ui/agents/docs/coverage/details", { doc_type: "api" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const paths = body.docs.map((d: { doc_path: string }) => d.doc_path);
    expect(paths).not.toContain(DOC_API);
  });

  test("680.2 invalid doc_type", async () => {
    const resp = await apiPost(alicePage, "alice", "ui/agents/docs/register", {
      doc_path: `docs/bad_${TS}.md`,
      doc_type: "invalid",
      source_refs: [],
      coverage_score: 1.0,
    });
    expect(resp.status()).toBe(422);
  });

  test("680.3 coverage score out of range", async () => {
    const resp = await apiPost(alicePage, "alice", "ui/agents/docs/register", {
      doc_path: `docs/oor_${TS}.md`,
      doc_type: "readme",
      source_refs: [],
      coverage_score: 1.5,
    });
    expect(resp.status()).toBe(422);
  });

  test("680.4 delete nonexistent template", async () => {
    const resp = await apiDelete(alicePage, "alice", `ui/agents/docs/templates/does_not_exist_${TS}`);
    expect(resp.status()).toBe(404);
  });
});
