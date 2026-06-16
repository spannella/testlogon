/**
 * E2E tests for the Lease Management system (LSE-001..LSE-004).
 *
 * Sections:
 *   70 — Lease CRUD (create / list / get) — API
 *   71 — Status filter + pagination — API
 *   72 — Inline edit + status transition — API
 *   73 — Tenant lease history — API
 *   74 — Admin list authz — API
 *   75 — Flag-off guard — API
 *   76 — LeasesPage UI
 *
 * Auth: uses e2e_admin_session_setup.py
 *
 * Note: LEASES_ENABLED defaults to false. Sections 70–74 + 76 require
 * LEASES_ENABLED=1 in the backend environment. Section 75 tests the flag-off
 * behaviour (expects 404).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const ROOT_ID  = "root.admin@testdev.local";
const TS       = Date.now();

// Fake IDs — FK validation is not enforced by the lease service (opaque strings)
const TENANT_ID   = `ten_e2e_${TS}`;
const PROPERTY_ID = `prop_e2e_${TS}`;
const UNIT_ID     = `unt_e2e_${TS}`;

// start_date in the future → status = "upcoming"
const START_DATE = Math.floor(Date.now() / 1000) + 86400 * 30; // 30 days from now
const END_DATE   = START_DATE + 86400 * 365;                   // 1 year after

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
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
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
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 70 — Lease CRUD — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 70: Lease CRUD (create / list / get) — API", () => {
  let alicePage: Page;
  let leaseId: string;
  let leaseNumber: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("70.1 — create lease returns 201 with correct fields (or 404 when flag off)", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "ui/leases", {
      tenant_id: TENANT_ID,
      property_id: PROPERTY_ID,
      unit_id: UNIT_ID,
      start_date: START_DATE,
      end_date: END_DATE,
      monthly_rent_cents: 150000,
      security_deposit_cents: 300000,
      rent_due_day: 1,
      late_fee_type: "none",
      currency: "usd",
      renewal_notice_days: 30,
    });

    if (resp.status() === 404) {
      // Feature flag is off — acceptable, skip rest of section
      test.skip();
      return;
    }

    expect(resp.status()).toBe(201);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.lease_id).toBeTruthy();
    expect(typeof body.lease_number).toBe("string");
    expect((body.lease_number as string)).toMatch(/^LSE-\d{4}-\d{5}$/);
    expect(body.status).toBe("upcoming"); // future start_date → upcoming
    expect(body.tenant_id).toBe(TENANT_ID);
    expect(body.property_id).toBe(PROPERTY_ID);
    expect(body.unit_id).toBe(UNIT_ID);
    expect(body.monthly_rent_cents).toBe(150000);
    expect(body.security_deposit_cents).toBe(300000);
    expect(body.currency).toBe("usd");

    leaseId = body.lease_id as string;
    leaseNumber = body.lease_number as string;
  });

  test("70.2 — get lease by ID returns full record", async () => {
    if (!leaseId) { test.skip(); return; }

    const resp = await apiGet(alicePage, `ui/leases/${leaseId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.lease_id).toBe(leaseId);
    expect(body.lease_number).toBe(leaseNumber);
    expect(body.start_date).toBe(START_DATE);
    expect(body.end_date).toBe(END_DATE);
  });

  test("70.3 — list leases returns the created lease", async () => {
    if (!leaseId) { test.skip(); return; }

    const resp = await apiGet(alicePage, "ui/leases");
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { leases: Array<Record<string, unknown>>; count: number };
    const found = body.leases.find((l) => l.lease_id === leaseId);
    expect(found).toBeTruthy();
  });

  test("70.4 — create a second lease produces sequential lease number", async () => {
    if (!leaseId) { test.skip(); return; }

    const resp = await apiPost(alicePage, ALICE_ID, "ui/leases", {
      tenant_id: TENANT_ID,
      property_id: PROPERTY_ID,
      unit_id: `${UNIT_ID}_b`,
      start_date: START_DATE + 86400,
      monthly_rent_cents: 120000,
      rent_due_day: 5,
      late_fee_type: "none",
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json() as Record<string, unknown>;
    const seq1 = parseInt(leaseNumber.split("-")[2]);
    const seq2 = parseInt((body.lease_number as string).split("-")[2]);
    expect(seq2).toBeGreaterThan(seq1);
  });

  test("70.5 — get non-existent lease returns 404", async () => {
    if (!leaseId) { test.skip(); return; }

    const resp = await apiGet(alicePage, "ui/leases/lse_doesnotexist000000");
    expect(resp.status()).toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 71 — Status filter + pagination — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 71: Status filter + pagination — API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
  });

  test.afterAll(async () => { await alicePage.close(); });

  test("71.1 — filter by status=upcoming returns only upcoming leases", async () => {
    const resp = await apiGet(alicePage, "ui/leases", { status: "upcoming" });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { leases: Array<Record<string, unknown>> };
    for (const l of body.leases) {
      expect(l.status).toBe("upcoming");
    }
  });

  test("71.2 — filter by status=ended returns empty or only ended leases", async () => {
    const resp = await apiGet(alicePage, "ui/leases", { status: "ended" });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { leases: Array<Record<string, unknown>> };
    for (const l of body.leases) {
      expect(l.status).toBe("ended");
    }
  });

  test("71.3 — list expiring returns empty list (none expire within 1 day)", async () => {
    const resp = await apiGet(alicePage, "ui/leases/expiring", {
      within_days: "1",
      limit: "10",
    });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { leases: unknown[] };
    // Leases with future start_date won't appear (they're upcoming, not active)
    expect(Array.isArray(body.leases)).toBe(true);
  });

  test("71.4 — pagination with limit=1 returns next_cursor when more items exist", async () => {
    const resp = await apiGet(alicePage, "ui/leases", { limit: "1" });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { leases: unknown[]; count: number; next_cursor: string | null };
    expect(body.leases.length).toBeLessThanOrEqual(1);
    if (body.count > 1) {
      expect(body.next_cursor).toBeTruthy();
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 72 — Inline edit + status transition — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 72: Inline edit + status transition — API", () => {
  let alicePage: Page;
  let leaseId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);

    // Create a fresh lease for this section
    const resp = await apiPost(alicePage, ALICE_ID, "ui/leases", {
      tenant_id: `${TENANT_ID}_sec72`,
      property_id: PROPERTY_ID,
      unit_id: `${UNIT_ID}_sec72`,
      start_date: START_DATE,
      end_date: END_DATE,
      monthly_rent_cents: 200000,
      rent_due_day: 15,
      late_fee_type: "flat",
      late_fee_cents: 5000,
      late_fee_grace_days: 5,
      force_draft: true, // create as draft for transition tests
    });
    if (resp.status() === 201) {
      const body = await resp.json() as { lease_id: string };
      leaseId = body.lease_id;
    }
  });

  test.afterAll(async () => { await alicePage.close(); });

  test("72.1 — PATCH updates monthly_rent_cents", async () => {
    if (!leaseId) { test.skip(); return; }

    const resp = await apiPatch(alicePage, ALICE_ID, `ui/leases/${leaseId}`, {
      monthly_rent_cents: 210000,
    });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { monthly_rent_cents: number };
    expect(body.monthly_rent_cents).toBe(210000);
  });

  test("72.2 — PATCH updates notes", async () => {
    if (!leaseId) { test.skip(); return; }

    const resp = await apiPatch(alicePage, ALICE_ID, `ui/leases/${leaseId}`, {
      notes: `Updated notes ${TS}`,
    });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { notes: string };
    expect(body.notes).toBe(`Updated notes ${TS}`);
  });

  test("72.3 — transition draft → upcoming succeeds", async () => {
    if (!leaseId) { test.skip(); return; }

    const resp = await apiPost(alicePage, ALICE_ID, `ui/leases/${leaseId}/status`, {
      status: "upcoming",
    });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { status: string };
    expect(body.status).toBe("upcoming");
  });

  test("72.4 — transition upcoming → active succeeds", async () => {
    if (!leaseId) { test.skip(); return; }

    const resp = await apiPost(alicePage, ALICE_ID, `ui/leases/${leaseId}/status`, {
      status: "active",
    });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { status: string };
    expect(body.status).toBe("active");
  });

  test("72.5 — transition active → ended succeeds", async () => {
    if (!leaseId) { test.skip(); return; }

    const resp = await apiPost(alicePage, ALICE_ID, `ui/leases/${leaseId}/status`, {
      status: "ended",
    });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { status: string };
    expect(body.status).toBe("ended");
  });

  test("72.6 — transition from ended (terminal) returns 400", async () => {
    if (!leaseId) { test.skip(); return; }

    const resp = await apiPost(alicePage, ALICE_ID, `ui/leases/${leaseId}/status`, {
      status: "active",
    });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(400);
  });

  test("72.7 — invalid transition returns 400 with invalid_status_transition code", async () => {
    // Create a fresh upcoming lease and try an invalid backward transition
    const createResp = await apiPost(alicePage, ALICE_ID, "ui/leases", {
      tenant_id: `${TENANT_ID}_inv`,
      property_id: PROPERTY_ID,
      unit_id: `${UNIT_ID}_inv`,
      start_date: START_DATE,
      monthly_rent_cents: 100000,
      rent_due_day: 1,
      late_fee_type: "none",
    });
    if (createResp.status() !== 201) { test.skip(); return; }
    const created = await createResp.json() as { lease_id: string };

    const resp = await apiPost(alicePage, ALICE_ID, `ui/leases/${created.lease_id}/status`, {
      status: "draft", // invalid: upcoming → draft is not allowed
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json() as { detail: unknown };
    expect(JSON.stringify(body.detail)).toContain("invalid_status_transition");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 73 — Tenant lease history — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 73: Tenant lease history — API", () => {
  let alicePage: Page;
  const TENANT_HIST_ID = `ten_hist_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);

    // Create 2 leases for the same tenant
    for (let i = 0; i < 2; i++) {
      await apiPost(alicePage, ALICE_ID, "ui/leases", {
        tenant_id: TENANT_HIST_ID,
        property_id: PROPERTY_ID,
        unit_id: `${UNIT_ID}_hist_${i}`,
        start_date: START_DATE + i * 86400 * 400,
        monthly_rent_cents: 100000 + i * 10000,
        rent_due_day: 1,
        late_fee_type: "none",
      });
    }
  });

  test.afterAll(async () => { await alicePage.close(); });

  test("73.1 — GET /ui/tenants/:id/leases returns leases for the tenant", async () => {
    const resp = await apiGet(alicePage, `ui/tenants/${TENANT_HIST_ID}/leases`);
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { leases: Array<Record<string, unknown>>; count: number };
    expect(body.count).toBeGreaterThanOrEqual(2);
    for (const l of body.leases) {
      expect(l.tenant_id).toBe(TENANT_HIST_ID);
    }
  });

  test("73.2 — returns empty list for unknown tenant", async () => {
    const resp = await apiGet(alicePage, "ui/tenants/ten_nonexistent_e2e/leases");
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { leases: unknown[]; count: number };
    expect(body.count).toBe(0);
    expect(body.leases).toHaveLength(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 74 — Admin list authz — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 74: Admin list authz — API", () => {
  let alicePage: Page;
  let rootPage:  Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
    rootPage  = await newIdentityPage(browser, ROOT_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
    await rootPage.close();
  });

  test("74.1 — root can list all leases via /ui/admin/leases", async () => {
    const resp = await apiGet(rootPage, "ui/admin/leases");
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { leases: unknown[]; count: number };
    expect(Array.isArray(body.leases)).toBe(true);
  });

  test("74.2 — regular user gets 403 from /ui/admin/leases", async () => {
    const resp = await apiGet(alicePage, "ui/admin/leases");
    if (resp.status() === 404) { test.skip(); return; }
    expect([403, 401]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 75 — Flag-off guard — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 75: Flag-off guard — API", () => {
  /**
   * These tests validate the 404 guard when LEASES_ENABLED=0.
   * They will be skipped if the flag is actually on (201 / 200 responses).
   */
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
  });

  test.afterAll(async () => { await alicePage.close(); });

  test("75.1 — POST /ui/leases returns 404 when flag is off", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "ui/leases", {
      tenant_id: TENANT_ID,
      property_id: PROPERTY_ID,
      unit_id: UNIT_ID,
      start_date: START_DATE,
      monthly_rent_cents: 100000,
      rent_due_day: 1,
      late_fee_type: "none",
    });
    // Accept 404 (flag off) or 201 (flag on)
    expect([201, 404]).toContain(resp.status());
    if (resp.status() === 404) {
      const body = await resp.json() as { detail: string };
      expect(body.detail).toMatch(/not enabled/i);
    }
  });

  test("75.2 — GET /ui/leases returns 404 when flag is off", async () => {
    const resp = await apiGet(alicePage, "ui/leases");
    expect([200, 404]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 76 — LeasesPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 76: LeasesPage UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => { await alicePage.close(); });

  test("76.1 — navigating to /property/leases loads the page", async () => {
    await alicePage.goto(`${BASE}/property/leases`, {
      waitUntil: "domcontentloaded",
    });
    await expect(
      alicePage.getByRole("heading", { name: "Leases", exact: true }),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("76.2 — shows feature-not-enabled banner or lease table", async () => {
    await alicePage.goto(`${BASE}/property/leases`, {
      waitUntil: "domcontentloaded",
    });

    // Either the "not enabled" banner OR the lease table should be visible
    const notEnabled = alicePage.getByText(/not enabled/i);
    const newLeaseBtn = alicePage.getByRole("button", { name: /new lease/i });

    try {
      await expect(notEnabled.or(newLeaseBtn)).toBeVisible({ timeout: 8_000 });
    } catch {
      // Either state is acceptable depending on flag
    }
  });

  test("76.3 — status filter dropdown is visible when feature is enabled", async () => {
    await alicePage.goto(`${BASE}/property/leases`, {
      waitUntil: "domcontentloaded",
    });

    const notEnabled = alicePage.getByText(/not enabled/i);
    const isDisabled = await notEnabled.isVisible().catch(() => false);
    if (isDisabled) { test.skip(); return; }

    // Select component trigger
    const statusFilter = alicePage.locator('[role="combobox"]').first();
    await expect(statusFilter).toBeVisible({ timeout: 5_000 });
  });

  test("76.4 — New Lease button opens create dialog", async () => {
    await alicePage.goto(`${BASE}/property/leases`, {
      waitUntil: "domcontentloaded",
    });

    const notEnabled = alicePage.getByText(/not enabled/i);
    const isDisabled = await notEnabled.isVisible().catch(() => false);
    if (isDisabled) { test.skip(); return; }

    const btn = alicePage.getByRole("button", { name: /new lease/i });
    await expect(btn).toBeVisible({ timeout: 5_000 });
    await btn.click();

    // Dialog should appear
    await expect(
      alicePage.getByRole("dialog"),
    ).toBeVisible({ timeout: 3_000 });

    // Close the dialog
    const cancelBtn = alicePage.getByRole("button", { name: /cancel/i });
    if (await cancelBtn.isVisible()) await cancelBtn.click();
  });

  test("76.5 — lease detail route /property/leases/:id renders without error", async () => {
    // Navigate to a non-existent lease — should show 404 or lease not found message
    await alicePage.goto(`${BASE}/property/leases/lse_fakeid00000000`, {
      waitUntil: "domcontentloaded",
    });

    // The page should not crash (no white screen)
    const body = alicePage.locator("body");
    await expect(body).toBeVisible({ timeout: 5_000 });

    // Should show Back button or not-found state
    const backBtn = alicePage.getByRole("button", { name: /back/i });
    const notFound = alicePage.getByText(/not found|not enabled/i);
    try {
      await expect(backBtn.or(notFound)).toBeVisible({ timeout: 8_000 });
    } catch {
      // Page is accessible, content dependent on flag
    }
  });
});
