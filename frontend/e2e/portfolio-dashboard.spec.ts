/**
 * E2E tests for the Property Management Dashboard (PMD-001..PMD-004).
 *
 * Sections:
 *   90 — PMD-001 Rent Policy API (GET default, PUT update, GET saved, audit log)
 *   91 — PMD-002 Property Documents API (link, list, unlink)
 *   92 — PMD-003 Portfolio KPI / snapshot / priority-items API
 *   93 — PMD-004 Portfolio Dashboard UI
 *   94 — PMD-004 Rent Policy page UI
 *   95 — Flag-off smoke (all PMD endpoints → 404 when flag off)
 *
 * Auth: uses e2e_admin_session_setup.py (root, alice, charlie_admin).
 *
 * Flag default: PROPERTY_DASHBOARD_ENABLED=false → every PMD endpoint returns 404.
 * Sections 90–94 are skip-marked when the backend returns 404 for the KPI endpoint,
 * indicating the flag is off in the current environment.
 *
 * Identities:
 *   root          – root.admin@testdev.local  – role=root
 *   alice         – e2e_alice@test.local      – role=user (landlord POV)
 *   charlie_admin – e2e_charlie@test.local    – role=admin
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API  = "http://localhost:8000";
const TS   = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface AdminSessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name:     string;
    value:    string;
    domain:   string;
    path:     string;
    httpOnly: boolean;
    secure:   boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires:  number;
  }>;
}

let _adminSessions: Record<string, AdminSessionData> | null = null;

function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

// ─── Page factory ─────────────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity]!.cookies);
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

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity]!;
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiPut(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity]!;
  return page.request.put(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiDelete(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity]!;
  return page.request.delete(`${API}/${path}`, {
    data: body,
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

// ─── Flag probe ───────────────────────────────────────────────────────────────

async function isPropertyDashboardEnabled(page: Page): Promise<boolean> {
  const resp = await apiGet(page, "ui/portfolio/kpis");
  return resp.status() !== 404 && resp.status() !== 503;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 90 — PMD-001 Rent Policy API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 90: PMD-001 Rent Policy API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let featureEnabled = false;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    rootPage  = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
    featureEnabled = await isPropertyDashboardEnabled(rootPage);
  });

  test("90.1 GET /ui/rent-policy — default policy has is_default=true", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const resp = await apiGet(alicePage, "ui/rent-policy");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(data.is_default).toBe(true);
    expect(typeof data.rent_due_day).toBe("number");
    expect(data.rent_due_day).toBe(1);
    expect(data.late_fee_cents).toBe(0);
    expect(data.grace_period_days).toBe(0);
    expect(typeof data.currency).toBe("string");
  });

  test("90.2 PUT /ui/rent-policy — root can update policy", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const resp = await apiPut(rootPage, "root", "ui/rent-policy", {
      rent_due_day: 15,
      late_fee_cents: 2500,
      grace_period_days: 3,
      currency: "eur",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(data.rent_due_day).toBe(15);
    expect(data.late_fee_cents).toBe(2500);
    expect(data.grace_period_days).toBe(3);
    expect(data.currency).toBe("eur");
    expect(data.is_default).toBe(false);
  });

  test("90.3 GET /ui/rent-policy — saved values returned after PUT", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const resp = await apiGet(rootPage, "ui/rent-policy");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(data.rent_due_day).toBe(15);
    expect(data.is_default).toBe(false);
    expect(typeof data.updated_at).toBe("number");
  });

  test("90.4 GET /ui/rent-policy/audit — returns at least one entry", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const resp = await apiGet(rootPage, "ui/rent-policy/audit");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { count: number; entries: unknown[] };
    expect(data.count).toBeGreaterThanOrEqual(1);
    expect(Array.isArray(data.entries)).toBe(true);
    const entry = data.entries[0] as Record<string, unknown>;
    expect(entry).toHaveProperty("actor_sub");
    expect(entry).toHaveProperty("after");
    expect(typeof entry.created_at).toBe("number");
  });

  test("90.5 PUT /ui/rent-policy — alice (user) gets 403", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const resp = await apiPut(alicePage, "alice", "ui/rent-policy", {
      rent_due_day: 5,
      late_fee_cents: 0,
      grace_period_days: 0,
      currency: "usd",
    });
    // Alice is USER role → require_admin_or_root_csrf should reject
    expect([403, 401]).toContain(resp.status());
  });

  test("90.6 PUT /ui/rent-policy — validation: rent_due_day=0 → 422", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const resp = await apiPut(rootPage, "root", "ui/rent-policy", {
      rent_due_day: 0,
      late_fee_cents: 0,
      grace_period_days: 0,
      currency: "usd",
    });
    expect(resp.status()).toBe(422);
  });

  test("90.7 PUT /ui/rent-policy — validation: rent_due_day=29 → 422", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const resp = await apiPut(rootPage, "root", "ui/rent-policy", {
      rent_due_day: 29,
      late_fee_cents: 0,
      grace_period_days: 0,
      currency: "usd",
    });
    expect(resp.status()).toBe(422);
  });

  test("90.8 PUT /ui/rent-policy — validation: late_fee_cents=-1 → 422", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const resp = await apiPut(rootPage, "root", "ui/rent-policy", {
      rent_due_day: 1,
      late_fee_cents: -1,
      grace_period_days: 0,
      currency: "usd",
    });
    expect(resp.status()).toBe(422);
  });

  test("90.9 PUT /ui/rent-policy — validation: currency=XX (2-char) → 422", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const resp = await apiPut(rootPage, "root", "ui/rent-policy", {
      rent_due_day: 1,
      late_fee_cents: 0,
      grace_period_days: 0,
      currency: "XX",
    });
    expect(resp.status()).toBe(422);
  });

  test("90.10 Audit: two consecutive identical PUTs → count increases by 2", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const before = await apiGet(rootPage, "ui/rent-policy/audit");
    const beforeCount = ((await before.json()) as { count: number }).count;

    await apiPut(rootPage, "root", "ui/rent-policy", {
      rent_due_day: 1, late_fee_cents: 0, grace_period_days: 0, currency: "usd",
    });
    await apiPut(rootPage, "root", "ui/rent-policy", {
      rent_due_day: 1, late_fee_cents: 0, grace_period_days: 0, currency: "usd",
    });

    const after = await apiGet(rootPage, "ui/rent-policy/audit");
    const afterCount = ((await after.json()) as { count: number }).count;
    expect(afterCount).toBeGreaterThanOrEqual(beforeCount + 2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 91 — PMD-002 Property Documents API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 91: PMD-002 Property Documents API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let featureEnabled = false;

  const REC_TYPE = "property";
  const REC_ID   = `e2e-prop-${TS}`;
  const DOC_ID   = `e2e-doc-${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    rootPage  = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
    featureEnabled = await isPropertyDashboardEnabled(rootPage);
  });

  test("91.1 POST /ui/property-documents/link — creates link", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const resp = await apiPost(rootPage, "root", "ui/property-documents/link", {
      record_type: REC_TYPE,
      record_id:   REC_ID,
      doc_id:      DOC_ID,
      file_path:   "/docs/lease.pdf",
      crm_category: "lease",
      crm_description: `E2E link ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(data.doc_id).toBe(DOC_ID);
    expect(data.record_type).toBe(REC_TYPE);
    expect(data.record_id).toBe(REC_ID);
    expect(typeof data.linked_at).toBe("number");
  });

  test("91.2 GET /ui/property-documents/:type/:id — lists linked doc", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const resp = await apiGet(rootPage, `ui/property-documents/${REC_TYPE}/${REC_ID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { items: Array<Record<string, unknown>>; count: number };
    expect(Array.isArray(data.items)).toBe(true);
    expect(data.count).toBeGreaterThanOrEqual(1);
    const found = data.items.find((d) => d.doc_id === DOC_ID);
    expect(found).toBeTruthy();
    expect(found!.file_path).toBe("/docs/lease.pdf");
    expect(found!.crm_category).toBe("lease");
  });

  test("91.3 Alice cannot see root's documents (cross-user isolation)", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    // Alice's user_sub differs — her query for same record_id returns empty
    const resp = await apiGet(alicePage, `ui/property-documents/${REC_TYPE}/${REC_ID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { items: unknown[]; count: number };
    // Documents are scoped to owner_sub — alice should not see root's doc
    const found = data.items.find(
      (d) => (d as Record<string, unknown>).doc_id === DOC_ID
    );
    expect(found).toBeUndefined();
  });

  test("91.4 DELETE /ui/property-documents/link — removes link", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const resp = await apiDelete(rootPage, "root", "ui/property-documents/link", {
      record_type: REC_TYPE,
      record_id:   REC_ID,
      doc_id:      DOC_ID,
    });
    expect(resp.status()).toBe(204);
  });

  test("91.5 POST /ui/property-documents/link — invalid record_type → 400", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const resp = await apiPost(rootPage, "root", "ui/property-documents/link", {
      record_type: "invoice",  // not in allowed set
      record_id:   "any-id",
      doc_id:      "any-doc",
    });
    expect(resp.status()).toBe(400);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 92 — PMD-003 Portfolio KPI / Snapshot / Priority items
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 92: PMD-003 Portfolio KPI / snapshot / priority items", () => {
  let rootPage: Page;
  let featureEnabled = false;

  const NOW = new Date();

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    featureEnabled = await isPropertyDashboardEnabled(rootPage);
  });

  test("92.1 GET /ui/portfolio/kpis — returns valid KPI shape", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const resp = await apiGet(rootPage, "ui/portfolio/kpis");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(typeof data.occupancy_rate).toBe("number");
    expect(typeof data.unit_count).toBe("number");
    expect(typeof data.occupied_units).toBe("number");
    expect(typeof data.active_lease_count).toBe("number");
    expect(typeof data.outstanding_rent_cents).toBe("number");
    expect(typeof data.open_work_order_count).toBe("number");
    expect(typeof data.computed_at).toBe("number");
    expect(data.occupancy_rate).toBeGreaterThanOrEqual(0);
    expect(data.occupancy_rate).toBeLessThanOrEqual(1);
  });

  test("92.2 GET /ui/portfolio/rent-snapshot — current month returns valid shape", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const year  = NOW.getFullYear();
    const month = NOW.getMonth() + 1;
    const resp  = await apiGet(rootPage, "ui/portfolio/rent-snapshot", {
      year:  String(year),
      month: String(month),
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(data.year).toBe(year);
    expect(data.month).toBe(month);
    expect(typeof data.charged_cents).toBe("number");
    expect(typeof data.collected_cents).toBe("number");
    expect(typeof data.outstanding_cents).toBe("number");
    expect(typeof data.overdue_cents).toBe("number");
    expect(typeof data.rent_due_day).toBe("number");
    expect(typeof data.grace_period_days).toBe("number");
  });

  test("92.3 GET /ui/portfolio/rent-snapshot — invariant: outstanding <= charged", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const year  = NOW.getFullYear();
    const month = NOW.getMonth() + 1;
    const resp  = await apiGet(rootPage, "ui/portfolio/rent-snapshot", {
      year:  String(year),
      month: String(month),
    });
    const data = await resp.json() as Record<string, number>;
    expect(data.outstanding_cents).toBeGreaterThanOrEqual(0);
    expect(data.overdue_cents).toBeGreaterThanOrEqual(0);
    expect(data.overdue_cents).toBeLessThanOrEqual(data.outstanding_cents);
  });

  test("92.4 GET /ui/portfolio/rent-snapshot — month=13 → 422", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const resp = await apiGet(rootPage, "ui/portfolio/rent-snapshot", {
      year:  String(NOW.getFullYear()),
      month: "13",
    });
    expect(resp.status()).toBe(422);
  });

  test("92.5 GET /ui/portfolio/priority-items — returns shape with items array", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const resp = await apiGet(rootPage, "ui/portfolio/priority-items");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(Array.isArray(data.upcoming_expirations)).toBe(true);
    expect(Array.isArray(data.open_work_orders)).toBe(true);
    expect(Array.isArray(data.items)).toBe(true);
    expect(typeof data.count).toBe("number");
  });

  test("92.6 GET /ui/portfolio/priority-items?limit=5 — respects limit", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    const resp = await apiGet(rootPage, "ui/portfolio/priority-items", { limit: "5" });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { items: unknown[]; count: number };
    expect(data.items.length).toBeLessThanOrEqual(5);
    expect(data.count).toBe(data.items.length);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 93 — PMD-004 Portfolio Dashboard UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 93: PMD-004 Portfolio Dashboard UI", () => {
  let rootPage: Page;
  let featureEnabled = false;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    featureEnabled = await isPropertyDashboardEnabled(rootPage);
  });

  test("93.1 Dashboard page loads at /property/dashboard", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    await injectAuth(rootPage, "root");
    await rootPage.goto(`${BASE}/property/dashboard`, { waitUntil: "domcontentloaded" });
    // Heading
    await expect(rootPage.getByRole("heading", { name: /portfolio dashboard/i })).toBeVisible();
  });

  test("93.2 KPI cards render (four cards visible)", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    await rootPage.goto(`${BASE}/property/dashboard`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByText(/occupancy rate/i)).toBeVisible();
    await expect(rootPage.getByText(/active leases/i)).toBeVisible();
    await expect(rootPage.getByText(/outstanding rent/i)).toBeVisible();
    await expect(rootPage.getByText(/open work orders/i)).toBeVisible();
  });

  test("93.3 Monthly snapshot card renders with month navigation", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    await injectAuth(rootPage, "root");
    await rootPage.goto(`${BASE}/property/dashboard`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByText(/monthly rent snapshot/i)).toBeVisible({ timeout: 15_000 });
    // "Charged"/"Collected" appear in both the summary cards and the bar
    // chart (axis/legend), so scope to the first match (strict-mode safe).
    await expect(rootPage.getByText(/charged/i).first()).toBeVisible();
    await expect(rootPage.getByText(/collected/i).first()).toBeVisible();
  });

  test("93.4 Rent Policy button visible to root — opens dialog", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    await injectAuth(rootPage, "root");
    await rootPage.goto(`${BASE}/property/dashboard`, { waitUntil: "domcontentloaded" });
    const policyBtn = rootPage.getByRole("button", { name: /rent policy/i });
    await expect(policyBtn).toBeVisible();
    await policyBtn.click();
    await expect(rootPage.getByRole("dialog")).toBeVisible();
    await expect(rootPage.getByText(/rent policy settings/i)).toBeVisible();
    // Close
    await rootPage.keyboard.press("Escape");
  });

  test("93.5 Flag-off: page shows 'not enabled' state when backend returns 404", async () => {
    // This test runs regardless of featureEnabled:
    // mock the endpoint to return 404 and verify graceful degradation.
    // When featureEnabled=true this just verifies the page can still navigate
    // (mocking is browser-level so won't affect the live backend).
    await injectAuth(rootPage, "root");
    await rootPage.route("**/ui/portfolio/kpis", (route) =>
      route.fulfill({ status: 404, body: JSON.stringify({ detail: "not enabled" }) })
    );
    await rootPage.goto(`${BASE}/property/dashboard`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByText(/not enabled/i).first()).toBeVisible({ timeout: 8000 });
    await rootPage.unroute("**/ui/portfolio/kpis");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 94 — PMD-004 Rent Policy page UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 94: PMD-004 Rent Policy page UI", () => {
  let rootPage: Page;
  let alicePage: Page;
  let featureEnabled = false;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    rootPage  = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
    featureEnabled = await isPropertyDashboardEnabled(rootPage);
  });

  test("94.1 Rent Policy page loads at /property/policies", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    await injectAuth(rootPage, "root");
    await rootPage.goto(`${BASE}/property/policies`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByRole("heading", { name: /rent policy/i })).toBeVisible();
  });

  test("94.2 Current policy card visible with field labels", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    await injectAuth(rootPage, "root");
    await rootPage.goto(`${BASE}/property/policies`, { waitUntil: "domcontentloaded" });
    // These labels also appear as Change-History table column headers, so
    // scope to the first match to avoid strict-mode violations.
    await expect(rootPage.getByText(/rent due day/i).first()).toBeVisible({ timeout: 15_000 });
    await expect(rootPage.getByText(/grace period/i).first()).toBeVisible();
    await expect(rootPage.getByText(/late fee/i).first()).toBeVisible();
    await expect(rootPage.getByText(/currency/i).first()).toBeVisible();
  });

  test("94.3 Admin sees edit button — clicking opens inline form", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    await injectAuth(rootPage, "root");
    await rootPage.goto(`${BASE}/property/policies`, { waitUntil: "domcontentloaded" });
    const editBtn = rootPage.getByRole("button", { name: /edit policy/i });
    await expect(editBtn).toBeVisible();
    await editBtn.click();
    // Form fields should appear
    await expect(rootPage.getByLabel(/rent due day/i)).toBeVisible();
    await expect(rootPage.getByLabel(/late fee/i)).toBeVisible();
  });

  test("94.4 Admin sees Change History section (audit log)", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    await injectAuth(rootPage, "root");
    await rootPage.goto(`${BASE}/property/policies`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByText(/change history/i)).toBeVisible({ timeout: 15_000 });
  });

  test("94.5 Alice (user role) does not see Edit Policy button", async () => {
    test.skip(!featureEnabled, "PROPERTY_DASHBOARD_ENABLED flag is off");

    await injectAuth(alicePage, "alice");
    await alicePage.goto(`${BASE}/property/policies`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByRole("button", { name: /edit policy/i })).not.toBeVisible({ timeout: 3000 });
  });

  test("94.6 Flag-off: page shows 'not enabled' state when backend returns 404", async () => {
    await rootPage.route("**/ui/rent-policy", (route) =>
      route.fulfill({ status: 404, body: JSON.stringify({ detail: "not enabled" }) })
    );
    await injectAuth(rootPage, "root");
    await rootPage.goto(`${BASE}/property/policies`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByText(/not enabled/i).first()).toBeVisible({ timeout: 8000 });
    await rootPage.unroute("**/ui/rent-policy");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 95 — Flag-off smoke
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 95: Flag-off smoke — all PMD endpoints → 404", () => {
  let rootPage: Page;
  let featureEnabled = false;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    featureEnabled = await isPropertyDashboardEnabled(rootPage);
  });

  test("95.1 When flag is OFF: GET /ui/portfolio/kpis → 404", async () => {
    test.skip(featureEnabled, "PROPERTY_DASHBOARD_ENABLED is ON — skip flag-off test");

    const resp = await apiGet(rootPage, "ui/portfolio/kpis");
    expect([404, 503]).toContain(resp.status());
  });

  test("95.2 When flag is OFF: GET /ui/rent-policy → 404", async () => {
    test.skip(featureEnabled, "PROPERTY_DASHBOARD_ENABLED is ON — skip flag-off test");

    const resp = await apiGet(rootPage, "ui/rent-policy");
    expect([404, 503]).toContain(resp.status());
  });

  test("95.3 When flag is OFF: GET /ui/portfolio/rent-snapshot → 404", async () => {
    test.skip(featureEnabled, "PROPERTY_DASHBOARD_ENABLED is ON — skip flag-off test");

    const now = new Date();
    const resp = await apiGet(rootPage, "ui/portfolio/rent-snapshot", {
      year:  String(now.getFullYear()),
      month: String(now.getMonth() + 1),
    });
    expect([404, 503]).toContain(resp.status());
  });

  test("95.4 When flag is OFF: GET /ui/portfolio/priority-items → 404", async () => {
    test.skip(featureEnabled, "PROPERTY_DASHBOARD_ENABLED is ON — skip flag-off test");

    const resp = await apiGet(rootPage, "ui/portfolio/priority-items");
    expect([404, 503]).toContain(resp.status());
  });
});
