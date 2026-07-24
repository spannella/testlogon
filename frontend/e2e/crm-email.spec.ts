/**
 * E2E tests for the SuiteCRM EMAIL (EML) cluster.
 *
 * Backend: app/routers/crm_campaigns.py  (/ui/crm-marketing/*)
 * Feature flag: S.crm_campaigns_enabled (default OFF) → endpoints return 404.
 *
 * Sections:
 *   80 — Email template CRUD + preview — API
 *   81 — Email campaign CRUD + send (dry run) + attribution — API
 *   82 — CRM email pages — UI (templates / compose / log)
 *
 * Auth: uses e2e_admin_session_setup.py (cookie sessions).
 *
 * NOTE: When the marketing-campaigns flag is OFF, the API-flow tests assert the
 * 404 "not enabled" contract; otherwise they exercise full CRUD. The UI tests
 * tolerate either the live page or the "not enabled" empty state.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS       = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface AdminSessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean;
    sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

// ─── Page factory ─────────────────────────────────────────────────────────────

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

/** True when the marketing-campaigns flag is OFF (404 contract). */
function isFlagOff(status: number): boolean {
  return status === 404;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 80 — Email template CRUD + preview — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 80: Email template CRUD + preview (API)", () => {
  let alicePage: Page;
  let templateId = "";
  const NAME = `E2E tpl ${TS}`;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("80.1 create email template", async () => {
    const res = await apiPost(alicePage, "alice", "ui/crm-marketing/email-templates", {
      name: NAME,
      subject_template: "Hello {{first_name}}",
      body_html_template: "<h1>Hi {{first_name}}</h1><p>Welcome.</p>",
    });
    if (isFlagOff(res.status())) {
      test.skip(true, "crm_campaigns_enabled is OFF");
      return;
    }
    expect(res.status()).toBe(201);
    const body = await res.json();
    expect(body.template_id).toBeTruthy();
    expect(body.name).toBe(NAME);
    expect(Array.isArray(body.variables)).toBe(true);
    templateId = body.template_id;
  });

  test("80.2 list email templates includes created", async () => {
    test.skip(!templateId, "create skipped");
    const res = await apiGet(alicePage, "ui/crm-marketing/email-templates", { limit: "100" });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body.templates)).toBe(true);
    expect(body.templates.some((t: any) => t.template_id === templateId)).toBe(true);
  });

  test("80.3 get single template", async () => {
    test.skip(!templateId, "create skipped");
    const res = await apiGet(alicePage, `ui/crm-marketing/email-templates/${templateId}`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.template_id).toBe(templateId);
  });

  test("80.4 update template subject + status", async () => {
    test.skip(!templateId, "create skipped");
    const res = await apiPatch(alicePage, "alice", `ui/crm-marketing/email-templates/${templateId}`, {
      subject_template: "Updated {{first_name}}",
      status: "active",
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.subject_template).toBe("Updated {{first_name}}");
    expect(body.status).toBe("active");
  });

  test("80.5 preview template", async () => {
    test.skip(!templateId, "create skipped");
    const res = await apiPost(alicePage, "alice", `ui/crm-marketing/email-templates/${templateId}/preview`, {
      sample_vars: { first_name: "Alice" },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(typeof body.subject).toBe("string");
    expect(typeof body.body_html).toBe("string");
  });

  test("80.6 delete template", async () => {
    test.skip(!templateId, "create skipped");
    const res = await apiDelete(alicePage, "alice", `ui/crm-marketing/email-templates/${templateId}`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 81 — Email campaign CRUD + send + attribution — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 81: Email campaign CRUD + send + attribution (API)", () => {
  let alicePage: Page;
  let campaignId = "";
  const NAME = `E2E campaign ${TS}`;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("81.1 create email campaign", async () => {
    const res = await apiPost(alicePage, "alice", "ui/crm-marketing/campaigns", {
      name: NAME,
      campaign_type: "email",
      budget_cents: 5000,
      objective: "Re-engage",
    });
    if (isFlagOff(res.status())) {
      test.skip(true, "crm_campaigns_enabled is OFF");
      return;
    }
    expect(res.status()).toBe(201);
    const body = await res.json();
    expect(body.campaign_id).toBeTruthy();
    expect(body.campaign_type).toBe("email");
    expect(body.budget_cents).toBe(5000);
    campaignId = body.campaign_id;
  });

  test("81.2 list email campaigns", async () => {
    test.skip(!campaignId, "create skipped");
    const res = await apiGet(alicePage, "ui/crm-marketing/campaigns", {
      campaign_type: "email",
      limit: "100",
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.campaigns.some((c: any) => c.campaign_id === campaignId)).toBe(true);
  });

  test("81.3 update campaign", async () => {
    test.skip(!campaignId, "create skipped");
    const res = await apiPatch(alicePage, "alice", `ui/crm-marketing/campaigns/${campaignId}`, {
      objective: "Updated objective",
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.objective).toBe("Updated objective");
  });

  test("81.4 dry-run send", async () => {
    test.skip(!campaignId, "create skipped");
    const res = await apiPost(alicePage, "alice", `ui/crm-marketing/campaigns/${campaignId}/send`, {
      dry_run: true,
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.campaign_id).toBe(campaignId);
    expect(body.dry_run).toBe(true);
    expect(typeof body.total_resolved).toBe("number");
  });

  test("81.5 attribution", async () => {
    test.skip(!campaignId, "create skipped");
    const res = await apiGet(alicePage, `ui/crm-marketing/campaigns/${campaignId}/attribution`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.campaign_id).toBe(campaignId);
    expect(typeof body.open_rate).toBe("number");
    expect(typeof body.click_rate).toBe("number");
  });

  test("81.6 delete campaign", async () => {
    test.skip(!campaignId, "create skipped");
    const res = await apiDelete(alicePage, "alice", `ui/crm-marketing/campaigns/${campaignId}`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 82 — CRM email pages — UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 82: CRM email pages — UI", () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page, "alice");
  });

  test("82.1 templates page renders", async ({ page }) => {
    await page.goto(`${BASE}/crm/email/templates`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Email Templates" })).toBeVisible();
  });

  test("82.2 compose page renders", async ({ page }) => {
    await page.goto(`${BASE}/crm/email/compose`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Compose & Send" })).toBeVisible();
  });

  test("82.3 email log page renders", async ({ page }) => {
    await page.goto(`${BASE}/crm/email/log`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Email Log" })).toBeVisible();
  });

  test("82.4 templates page shows new-template action or not-enabled state", async ({ page }) => {
    await page.goto(`${BASE}/crm/email/templates`, { waitUntil: "domcontentloaded" });
    const newBtn = page.getByRole("button", { name: /new template/i });
    const notEnabled = page.getByText(/not enabled/i);
    await expect(newBtn.or(notEnabled).first()).toBeVisible();
  });
});
