/**
 * E2E tests for the SuiteCRM Opportunities (sales pipeline) cluster.
 *
 * Backend: app/routers/opportunities.py — prefix /ui/sales (+ /ui/admin/sales).
 * Feature flag: S.sales_pipeline_enabled (default OFF → CRUD endpoints 503).
 * Frontend: /crm/opportunities, /crm/opportunities/:oppId, /crm/opportunities/pipeline
 *
 * Sections:
 *   90 — Feature status + stage config (API)
 *   91 — Opportunity CRUD + stage transitions / close-won-lost (API, flag-aware)
 *   92 — Contact roles (API, flag-aware)
 *   93 — Pipeline report (API, flag-aware)
 *   94 — Opportunities UI (pipeline list / board)
 *
 * Auth: uses e2e_admin_session_setup.py (all identities).
 *
 * NOTE: When the sales_pipeline flag is OFF the CRUD endpoints return 503.
 * Tests treat 503 as an accepted "feature disabled" outcome so the suite is
 * green in both flag states.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

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
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_admin_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _adminSessions = JSON.parse(raw);
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

/** Accepted statuses: a real success OR 503 when the feature flag is off. */
function okOrDisabled(status: number, ...okStatuses: number[]): boolean {
  return status === 503 || okStatuses.includes(status);
}

// ─── Shared state ─────────────────────────────────────────────────────────────

let featureEnabled = false;
let createdOppId = "";

// ─────────────────────────────────────────────────────────────────────────────
// Section 90 — Feature status + stage config (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 90: Opportunities feature status + stages (API)", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("90.1 feature-status returns enabled flag (never 503)", async () => {
    const resp = await apiGet(alicePage, "ui/sales/feature-status");
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { enabled: boolean };
    expect(typeof data.enabled).toBe("boolean");
    featureEnabled = data.enabled;
  });

  test("90.2 stages list returns stage config or 503 when disabled", async () => {
    const resp = await apiGet(alicePage, "ui/sales/stages");
    // /stages requires only a session; returns config in both flag states.
    expect(okOrDisabled(resp.status(), 200)).toBeTruthy();
    if (resp.status() === 200) {
      const data = (await resp.json()) as { stages: Array<{ stage_key: string }> };
      expect(Array.isArray(data.stages)).toBe(true);
      expect(data.stages.length).toBeGreaterThan(0);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 91 — Opportunity CRUD + stage transitions (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 91: Opportunity CRUD + transitions (API)", () => {
  let alicePage: Page;
  const NAME = `E2E Opp ${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("91.1 create opportunity → 201 or 503", async () => {
    const resp = await apiPost(alicePage, "alice", "ui/sales/opportunities", {
      name: NAME,
      stage: "prospecting",
      amount_cents: 1_000_00,
      close_date: Math.floor(Date.now() / 1000) + 30 * 86400,
      probability: 10,
      lead_source: "web_site",
    });
    expect(okOrDisabled(resp.status(), 201)).toBeTruthy();
    if (resp.status() === 201) {
      const data = (await resp.json()) as {
        opp_id: string;
        amount_cents: number;
        weighted_amount_cents: number;
      };
      expect(typeof data.opp_id).toBe("string");
      expect(data.amount_cents).toBe(1_000_00);
      // weighted = amount * probability/100 = 100000 * 0.10 = 10000
      expect(data.weighted_amount_cents).toBe(10_000);
      createdOppId = data.opp_id;
    }
  });

  test("91.2 list opportunities returns items array (or 503)", async () => {
    const resp = await apiGet(alicePage, "ui/sales/opportunities", { limit: "50" });
    expect(okOrDisabled(resp.status(), 200)).toBeTruthy();
    if (resp.status() === 200) {
      const data = (await resp.json()) as { items: unknown[] };
      expect(Array.isArray(data.items)).toBe(true);
    }
  });

  test("91.3 patch stage transition to close_won → probability 100", async () => {
    test.skip(!createdOppId, "no opportunity created (feature disabled)");
    const resp = await apiPatch(
      alicePage,
      "alice",
      `ui/sales/opportunities/${encodeURIComponent(createdOppId)}`,
      { stage: "closed_won", probability: 100 },
    );
    expect(okOrDisabled(resp.status(), 200)).toBeTruthy();
    if (resp.status() === 200) {
      const data = (await resp.json()) as { stage: string; probability: number };
      expect(data.stage).toBe("closed_won");
      expect(data.probability).toBe(100);
    }
  });

  test("91.4 get single opportunity (or 503)", async () => {
    test.skip(!createdOppId, "no opportunity created (feature disabled)");
    const resp = await apiGet(
      alicePage,
      `ui/sales/opportunities/${encodeURIComponent(createdOppId)}`,
    );
    expect(okOrDisabled(resp.status(), 200)).toBeTruthy();
  });

  test("91.5 delete opportunity → 204 (or 503)", async () => {
    test.skip(!createdOppId, "no opportunity created (feature disabled)");
    const resp = await apiDelete(
      alicePage,
      "alice",
      `ui/sales/opportunities/${encodeURIComponent(createdOppId)}`,
    );
    expect(okOrDisabled(resp.status(), 204)).toBeTruthy();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 92 — Contact roles (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 92: Opportunity contact roles (API)", () => {
  let alicePage: Page;
  let oppId = "";

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    const resp = await apiPost(alicePage, "alice", "ui/sales/opportunities", {
      name: `E2E Opp Contacts ${TS}`,
      stage: "qualification",
      amount_cents: 5_000_00,
      close_date: Math.floor(Date.now() / 1000) + 60 * 86400,
      probability: 25,
    });
    if (resp.status() === 201) {
      oppId = ((await resp.json()) as { opp_id: string }).opp_id;
    }
  });

  test("92.1 add contact role → 201 (or feature disabled)", async () => {
    test.skip(!oppId, "feature disabled");
    const resp = await apiPost(
      alicePage,
      "alice",
      `ui/sales/opportunities/${encodeURIComponent(oppId)}/contacts`,
      { contact_ref: `contact-${TS}`, contact_role: "decision_maker" },
    );
    expect(resp.status()).toBe(201);
    const data = (await resp.json()) as { contact_role: string };
    expect(data.contact_role).toBe("decision_maker");
  });

  test("92.2 list contact roles", async () => {
    test.skip(!oppId, "feature disabled");
    const resp = await apiGet(
      alicePage,
      `ui/sales/opportunities/${encodeURIComponent(oppId)}/contacts`,
    );
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as unknown[];
    expect(Array.isArray(data)).toBe(true);
  });

  test("92.3 remove contact role → 204", async () => {
    test.skip(!oppId, "feature disabled");
    const resp = await apiDelete(
      alicePage,
      "alice",
      `ui/sales/opportunities/${encodeURIComponent(oppId)}/contacts/${encodeURIComponent(`contact-${TS}`)}`,
    );
    expect(resp.status()).toBe(204);
  });

  test.afterAll(async () => {
    if (oppId) {
      await apiDelete(
        alicePage,
        "alice",
        `ui/sales/opportunities/${encodeURIComponent(oppId)}`,
      ).catch(() => {});
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 93 — Pipeline report (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 93: Pipeline report (API)", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("93.1 pipeline report returns funnel shape (or 503)", async () => {
    const resp = await apiGet(alicePage, "ui/sales/reports/pipeline");
    expect(okOrDisabled(resp.status(), 200)).toBeTruthy();
    if (resp.status() === 200) {
      const data = (await resp.json()) as {
        stages: unknown[];
        total_amount_cents: number;
        generated_at: number;
      };
      expect(Array.isArray(data.stages)).toBe(true);
      expect(typeof data.total_amount_cents).toBe("number");
      expect(typeof data.generated_at).toBe("number");
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 94 — Opportunities UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 94: Opportunities UI", () => {
  test("94.1 opportunities page renders header (board or disabled state)", async ({
    page,
  }) => {
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/crm/opportunities`, { waitUntil: "domcontentloaded" });
    await expect(
      page.getByRole("heading", { name: "Opportunities", exact: true }),
    ).toBeVisible({ timeout: 15_000 });
    // Either the board/empty state OR the disabled card is shown.
    const boardOrDisabled = page
      .getByTestId("opp-board")
      .or(page.getByText("Sales Pipeline not enabled"))
      .or(page.getByText("No opportunities yet."));
    await expect(boardOrDisabled.first()).toBeVisible({ timeout: 15_000 });
  });

  test("94.2 pipeline report page renders", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/crm/opportunities/pipeline`, {
      waitUntil: "domcontentloaded",
    });
    const headingOrDisabled = page
      .getByRole("heading", { name: "Pipeline report" })
      .or(page.getByText("Sales Pipeline not enabled"));
    await expect(headingOrDisabled.first()).toBeVisible({ timeout: 15_000 });
  });
});

void ALICE_ID;
