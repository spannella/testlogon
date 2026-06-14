/**
 * E2E tests for SuiteCRM CAMPAIGNS-EXTRA (CMP-001..008) frontend.
 *
 * Sections:
 *   90 — Campaign CRUD — API (/ui/crm-marketing/campaigns)
 *   91 — Campaign send (dry run) + attribution — API
 *   92 — Web-to-lead capture + admin lead list — API
 *   93 — CampaignsPage UI
 *   94 — WebLeadsPage + LeadCaptureFormPage UI
 *
 * Auth: uses e2e_admin_session_setup.py (all identities)
 *
 * NOTE: the CRM campaigns features are flag-gated (CRM_CAMPAIGNS_ENABLED /
 * WEB_TO_LEAD_ENABLED), default OFF. When disabled the API returns 404 and the
 * UI renders a "not enabled" state. Tests therefore tolerate both enabled and
 * disabled environments.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ROOT_SUB = "root.admin@testdev.local";
const ALICE_ID = "e2e_alice@test.local";
const TS       = Date.now();

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

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
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

/** True if the marketing campaigns feature is enabled (probe returns non-404). */
async function campaignsEnabled(page: Page): Promise<boolean> {
  const r = await apiGet(page, "ui/crm-marketing/campaigns");
  return r.status() !== 404;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 90 — Campaign CRUD — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 90: Campaign CRUD — API", () => {
  let rootPage: Page;
  let enabled = false;
  let campaignId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    enabled = await campaignsEnabled(rootPage);
  });

  test.afterAll(async () => {
    if (enabled && campaignId) {
      await apiDelete(rootPage, "root", `ui/crm-marketing/campaigns/${campaignId}`);
    }
    await rootPage.close();
  });

  test("create campaign", async () => {
    const r = await apiPost(rootPage, "root", "ui/crm-marketing/campaigns", {
      name: `E2E campaign ${TS}`,
      campaign_type: "email",
      budget_cents: 5000,
      objective: "test objective",
    });
    if (!enabled) {
      expect(r.status()).toBe(404);
      return;
    }
    expect(r.status()).toBe(201);
    const body = await r.json();
    expect(body.name).toBe(`E2E campaign ${TS}`);
    expect(body.campaign_type).toBe("email");
    expect(body.budget_cents).toBe(5000);
    campaignId = body.campaign_id;
  });

  test("list campaigns includes created", async () => {
    const r = await apiGet(rootPage, "ui/crm-marketing/campaigns", { limit: "100" });
    if (!enabled) {
      expect(r.status()).toBe(404);
      return;
    }
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(Array.isArray(body.campaigns)).toBe(true);
    expect(body.campaigns.some((c: any) => c.campaign_id === campaignId)).toBe(true);
  });

  test("get + patch campaign", async () => {
    test.skip(!enabled, "campaigns disabled");
    const g = await apiGet(rootPage, `ui/crm-marketing/campaigns/${campaignId}`);
    expect(g.status()).toBe(200);

    const p = await rootPage.request.patch(
      `${API}/ui/crm-marketing/campaigns/${campaignId}`,
      {
        data: { objective: "updated objective" },
        headers: {
          "x-csrf-token": getAdminSessions().root.csrf_token,
          "Content-Type": "application/json",
        },
      },
    );
    expect(p.status()).toBe(200);
    const body = await p.json();
    expect(body.objective).toBe("updated objective");
  });

  test("invalid campaign_type filter → 422", async () => {
    test.skip(!enabled, "campaigns disabled");
    const r = await apiGet(rootPage, "ui/crm-marketing/campaigns", {
      campaign_type: "carrier-pigeon",
    });
    expect(r.status()).toBe(422);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 91 — Campaign send (dry run) + attribution — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 91: Send (dry run) + attribution — API", () => {
  let rootPage: Page;
  let enabled = false;
  let campaignId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    enabled = await campaignsEnabled(rootPage);
    if (enabled) {
      const r = await apiPost(rootPage, "root", "ui/crm-marketing/campaigns", {
        name: `E2E send ${TS}`,
        campaign_type: "email",
      });
      campaignId = (await r.json()).campaign_id;
    }
  });

  test.afterAll(async () => {
    if (enabled && campaignId) {
      await apiDelete(rootPage, "root", `ui/crm-marketing/campaigns/${campaignId}`);
    }
    await rootPage.close();
  });

  test("dry run send returns resolved counts", async () => {
    test.skip(!enabled, "campaigns disabled");
    const r = await apiPost(
      rootPage,
      "root",
      `ui/crm-marketing/campaigns/${campaignId}/send`,
      { dry_run: true },
    );
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.dry_run).toBe(true);
    expect(typeof body.total_resolved).toBe("number");
  });

  test("attribution returns stats shape", async () => {
    test.skip(!enabled, "campaigns disabled");
    const r = await apiGet(
      rootPage,
      `ui/crm-marketing/campaigns/${campaignId}/attribution`,
    );
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.campaign_id).toBe(campaignId);
    expect(typeof body.open_count).toBe("number");
    expect(typeof body.open_rate).toBe("number");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 92 — Web-to-lead capture + admin list — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 92: Web-to-lead — API", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("capture lead (public, no auth) tolerates flag-off", async ({ request }) => {
    const r = await request.post(`${API}/ui/crm-marketing/leads/capture`, {
      data: {
        first_name: "E2E",
        last_name: "Lead",
        email: `e2e_lead_${TS}@test.local`,
      },
    });
    // 200 when enabled, 404 when web-to-lead disabled.
    expect([200, 404]).toContain(r.status());
    if (r.status() === 200) {
      const body = await r.json();
      expect(body.ok).toBe(true);
      expect(typeof body.capture_id).toBe("string");
    }
  });

  test("admin lead list (root) tolerates flag-off", async () => {
    const r = await apiGet(rootPage, "ui/admin/crm-marketing/leads", { limit: "50" });
    expect([200, 404]).toContain(r.status());
    if (r.status() === 200) {
      const body = await r.json();
      expect(Array.isArray(body.leads)).toBe(true);
    }
  });

  test("admin lead list rejects non-admin", async ({ browser }) => {
    const alicePage = await newIdentityPage(browser, "alice");
    const r = await apiGet(alicePage, "ui/admin/crm-marketing/leads");
    // 403 (non-admin) when enabled, 404 when disabled.
    expect([403, 404]).toContain(r.status());
    await alicePage.close();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 93 — CampaignsPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 93: CampaignsPage UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "root");
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("renders campaigns page (list or not-enabled)", async () => {
    await page.goto(`${BASE}/crm/campaigns`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Campaigns", exact: true })).toBeVisible();
    // Either the "New campaign" action or the not-enabled state is present.
    const newBtn = page.getByRole("button", { name: /new campaign/i });
    const notEnabled = page.getByText(/is not enabled/i);
    await expect(newBtn.or(notEnabled).first()).toBeVisible();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 94 — WebLeadsPage + LeadCaptureFormPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 94: Web leads + capture form UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "root");
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("web leads page renders", async () => {
    await page.goto(`${BASE}/crm/web-leads`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Web Leads", exact: true })).toBeVisible();
  });

  test("lead capture form renders fields or not-enabled", async () => {
    await page.goto(`${BASE}/crm/lead-capture`, { waitUntil: "domcontentloaded" });
    await expect(
      page.getByRole("heading", { name: "Lead Capture Form", exact: true }),
    ).toBeVisible();
    const emailField = page.getByLabel("Email");
    const notEnabled = page.getByText(/is not enabled/i);
    await expect(emailField.or(notEnabled).first()).toBeVisible();
  });
});
