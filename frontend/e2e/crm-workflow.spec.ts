/**
 * E2E tests for the SuiteCRM Workflow (WFL) cluster.
 *
 * Sections:
 *   80 — Workflow rule CRUD — API
 *   81 — Rule enable/disable + run history — API
 *   82 — Drip sequence CRUD — API
 *   83 — Auth / flag gating — API
 *   84 — WorkflowRulesPage UI
 *
 * Backend router: app/routers/workflow_rules.py (prefix /ui/admin/crm/workflow).
 * Gated by CRM_WORKFLOW_ENABLED (default OFF -> 404). All endpoints are
 * admin/root only.
 *
 * NOTE: When CRM_WORKFLOW_ENABLED is OFF the CRUD endpoints return 404; the
 * API sections below skip assertions that require the flag to be ON and instead
 * assert the not-enabled contract. The UI section asserts the "not enabled"
 * state OR the loaded list, so the suite is green in both configurations.
 *
 * Auth: uses e2e_admin_session_setup.py (all identities).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const WFL = "ui/admin/crm/workflow";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();

// ─── Session bootstrap ──────────────────────────────────────────────────────

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
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _adminSessions = JSON.parse(raw);
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

// ─── API helpers ──────────────────────────────────────────────────────────────

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

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

/** Detect whether CRM_WORKFLOW_ENABLED is ON by probing the list endpoint. */
async function flagEnabled(page: Page): Promise<boolean> {
  const resp = await apiGet(page, `${WFL}/rules`, { limit: "1" });
  return resp.status() === 200;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 80 — Workflow rule CRUD — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 80: Workflow rule CRUD (API)", () => {
  let rootPage: Page;
  let enabled = false;
  let ruleId = "";

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    enabled = await flagEnabled(rootPage);
    if (enabled) {
      const resp = await apiPost(rootPage, "root", `${WFL}/rules`, {
        name: `E2E rule ${TS}`,
        description: "created by e2e",
        target_module: "ticket",
        trigger_type: "on_save",
        conditions: [{ field: "status", operator: "eq", value: "open" }],
        actions: [{ action_type: "modify_field", config: { field: "status", value: "closed" } }],
        enabled: true,
      });
      if (resp.ok()) {
        const data = (await resp.json()) as { rule_id: string };
        ruleId = data.rule_id;
      }
    }
  });

  test("80.1 Create rule → 201 with rule_id (or flag off → 404)", async () => {
    if (!enabled) {
      const resp = await apiGet(rootPage, `${WFL}/rules`);
      expect(resp.status()).toBe(404);
      return;
    }
    expect(ruleId).toBeTruthy();
  });

  test("80.2 Get rule → returns conditions + actions", async () => {
    test.skip(!enabled, "flag off");
    const resp = await apiGet(rootPage, `${WFL}/rules/${ruleId}`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as Record<string, unknown>;
    expect(data.target_module).toBe("ticket");
    expect(Array.isArray(data.conditions)).toBe(true);
    expect((data.conditions as unknown[]).length).toBe(1);
    expect(Array.isArray(data.actions)).toBe(true);
  });

  test("80.3 List rules includes created rule", async () => {
    test.skip(!enabled, "flag off");
    const resp = await apiGet(rootPage, `${WFL}/rules`, { limit: "100" });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { rules: Array<{ rule_id: string }> };
    expect(data.rules.some((r) => r.rule_id === ruleId)).toBe(true);
  });

  test("80.4 Patch rule updates name", async () => {
    test.skip(!enabled, "flag off");
    const resp = await apiPatch(rootPage, "root", `${WFL}/rules/${ruleId}`, {
      name: `E2E rule renamed ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { name: string };
    expect(data.name).toBe(`E2E rule renamed ${TS}`);
  });

  test("80.5 Invalid target_module → 422", async () => {
    test.skip(!enabled, "flag off");
    const resp = await apiPost(rootPage, "root", `${WFL}/rules`, {
      name: "bad module",
      target_module: "not_a_module",
      trigger_type: "on_save",
    });
    expect(resp.status()).toBe(422);
  });

  test("80.6 Delete rule → ok", async () => {
    test.skip(!enabled, "flag off");
    const resp = await apiDelete(rootPage, "root", `${WFL}/rules/${ruleId}`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { ok: boolean };
    expect(data.ok).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 81 — Enable/disable + run history — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 81: Enable/disable + run history (API)", () => {
  let rootPage: Page;
  let enabled = false;
  let ruleId = "";

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    enabled = await flagEnabled(rootPage);
    if (enabled) {
      const resp = await apiPost(rootPage, "root", `${WFL}/rules`, {
        name: `E2E toggle ${TS}`,
        target_module: "lead",
        trigger_type: "on_schedule",
        enabled: true,
      });
      if (resp.ok()) ruleId = ((await resp.json()) as { rule_id: string }).rule_id;
    }
  });

  test.afterAll(async () => {
    if (enabled && ruleId) await apiDelete(rootPage, "root", `${WFL}/rules/${ruleId}`);
  });

  test("81.1 Disable rule → enabled=false", async () => {
    test.skip(!enabled, "flag off");
    const resp = await apiPost(rootPage, "root", `${WFL}/rules/${ruleId}/disable`);
    expect(resp.status()).toBe(200);
    expect(((await resp.json()) as { enabled: boolean }).enabled).toBe(false);
  });

  test("81.2 Enable rule → enabled=true", async () => {
    test.skip(!enabled, "flag off");
    const resp = await apiPost(rootPage, "root", `${WFL}/rules/${ruleId}/enable`);
    expect(resp.status()).toBe(200);
    expect(((await resp.json()) as { enabled: boolean }).enabled).toBe(true);
  });

  test("81.3 List run history → 200 with runs array", async () => {
    test.skip(!enabled, "flag off");
    const resp = await apiGet(rootPage, `${WFL}/rules/${ruleId}/runs`, { limit: "10" });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { runs: unknown[] };
    expect(Array.isArray(data.runs)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 82 — Drip sequence CRUD — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 82: Drip sequence CRUD (API)", () => {
  let rootPage: Page;
  let enabled = false;
  let seqId = "";

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    enabled = await flagEnabled(rootPage);
    if (enabled) {
      const resp = await apiPost(rootPage, "root", `${WFL}/drip-sequences`, {
        name: `E2E drip ${TS}`,
        description: "e2e",
        stages: [
          { stage_number: 1, delay_hours: 0, template_id: "welcome", to_field: "email" },
          { stage_number: 2, delay_hours: 24, template_id: "followup", to_field: "email" },
        ],
      });
      if (resp.ok()) seqId = ((await resp.json()) as { sequence_id: string }).sequence_id;
    }
  });

  test("82.1 Create drip sequence → 201 with stages", async () => {
    test.skip(!enabled, "flag off");
    expect(seqId).toBeTruthy();
    const resp = await apiGet(rootPage, `${WFL}/drip-sequences/${seqId}`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { stages: unknown[] };
    expect(data.stages.length).toBe(2);
  });

  test("82.2 List drip sequences includes created one", async () => {
    test.skip(!enabled, "flag off");
    const resp = await apiGet(rootPage, `${WFL}/drip-sequences`, { limit: "100" });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { sequences: Array<{ sequence_id: string }> };
    expect(data.sequences.some((s) => s.sequence_id === seqId)).toBe(true);
  });

  test("82.3 Patch drip sequence name", async () => {
    test.skip(!enabled, "flag off");
    const resp = await apiPatch(rootPage, "root", `${WFL}/drip-sequences/${seqId}`, {
      name: `E2E drip renamed ${TS}`,
    });
    expect(resp.status()).toBe(200);
    expect(((await resp.json()) as { name: string }).name).toBe(`E2E drip renamed ${TS}`);
  });

  test("82.4 Delete drip sequence → ok", async () => {
    test.skip(!enabled, "flag off");
    const resp = await apiDelete(rootPage, "root", `${WFL}/drip-sequences/${seqId}`);
    expect(resp.status()).toBe(200);
    expect(((await resp.json()) as { ok: boolean }).ok).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 83 — Auth / flag gating — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 83: Auth / flag gating (API)", () => {
  let bobPage: Page;
  let rootPage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    bobPage = await newIdentityPage(browser, "bob");
    rootPage = await newIdentityPage(browser, "root");
  });

  test("83.1 Non-admin (bob) is blocked (403) or flag-gated (404)", async () => {
    const resp = await apiGet(bobPage, `${WFL}/rules`);
    expect([403, 404]).toContain(resp.status());
  });

  test("83.2 Unauthenticated request → 401/403/404", async ({ request }) => {
    const resp = await request.get(`${API}/${WFL}/rules`);
    expect([401, 403, 404]).toContain(resp.status());
  });

  test("83.3 Admin list endpoint reachable (200 enabled / 404 disabled)", async () => {
    const resp = await apiGet(rootPage, `${WFL}/rules`);
    expect([200, 404]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 84 — WorkflowRulesPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 84: WorkflowRulesPage UI", () => {
  test("84.1 Page renders header (list or not-enabled state)", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "root");
    await page.goto(`${BASE}/crm/workflow`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Workflow automation" })).toBeVisible({
      timeout: 15_000,
    });
  });

  test("84.2 Either New rule button or not-enabled message is shown", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "root");
    await page.goto(`${BASE}/crm/workflow`, { waitUntil: "domcontentloaded" });
    const newBtn = page.getByRole("button", { name: "New rule" });
    const notEnabled = page.getByText(/not enabled/i);
    await expect(newBtn.or(notEnabled).first()).toBeVisible({ timeout: 15_000 });
  });

  test("84.3 Drip sequences page renders header", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "root");
    await page.goto(`${BASE}/crm/workflow/drip-sequences`, {
      waitUntil: "domcontentloaded",
    });
    await expect(page.getByRole("heading", { name: "Drip sequences" })).toBeVisible({
      timeout: 15_000,
    });
  });
});

// Keep BOB_ID referenced for lint parity with sibling specs.
void BOB_ID;
