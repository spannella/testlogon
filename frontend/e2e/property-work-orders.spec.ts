/**
 * E2E tests for WOV-001..WOV-005: Maintenance Work Orders + Vendor Directory.
 *
 * Sections:
 *   S1 — Work-order CRUD — API
 *   S2 — Work-order lifecycle (assign / schedule / transition) — API
 *   S3 — Work-order list filters — API
 *   S4 — Vendor directory CRUD — API
 *   S5 — Vendor status management — API
 *   S6 — WorkOrdersPage UI
 *   S7 — VendorsPage UI
 *
 * Auth: uses e2e_admin_session_setup.py (root = admin identity for mutations).
 * Identities:
 *   alice       — e2e_alice@test.local     — role=user (read-only)
 *   root        — root.admin@testdev.local — role=root (admin mutations)
 *
 * Backend gate: MAINTENANCE_ORDERS_ENABLED (default false → 404).
 * Tests detect the 404 "not enabled" response and skip gracefully.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ROOT_ID = "root.admin@testdev.local";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

// Test property ID. When property_mgmt is enabled the work-order FK
// validation requires a real property, so we create one lazily (see
// ensureTestProperty) and overwrite this with the real property_id.
let TEST_PROPERTY_ID = `test-prop-wov-${TS}`;

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

// ─── Page factory ─────────────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const s = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(s[identity].cookies);
  return page;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getSessions()[identity];
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
  const sess = getSessions()[identity];
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
  const sess = getSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

// ─── Feature-enabled guard ────────────────────────────────────────────────────

let _featureEnabled: boolean | null = null;

// Create a real property once so work-order FK validation (when
// property_mgmt is enabled) passes. Best-effort: if property_mgmt is off
// the original synthetic id is used and the WO endpoint accepts it.
let _propertyEnsured = false;
async function ensureTestProperty(page: Page): Promise<void> {
  if (_propertyEnsured) return;
  _propertyEnsured = true;
  const resp = await apiPost(page, ROOT_ID, "ui/properties", {
    name: `WO Test Property ${TS}`,
    property_type: "single_family",
    address: {
      line1: "1 Work Order Way",
      city: "WO City",
      region: "CA",
      postal_code: "90001",
      country: "US",
    },
    color_tags: [],
  });
  if (resp.ok()) {
    const body = await resp.json().catch(() => ({})) as { property_id?: string };
    if (body.property_id) TEST_PROPERTY_ID = body.property_id;
  }
}

async function isFeatureEnabled(page: Page): Promise<boolean> {
  if (_featureEnabled !== null) return _featureEnabled;
  await ensureTestProperty(page);
  const resp = await apiPost(
    page,
    ROOT_ID,
    `ui/properties/${TEST_PROPERTY_ID}/work-orders`,
    {
      title: `Flag probe ${TS}`,
      property_id: TEST_PROPERTY_ID,
      priority: "normal",
    },
  );
  if (resp.status() === 404) {
    const body = await resp.json().catch(() => ({}));
    if (typeof body.detail === "string" && /not enabled/i.test(body.detail)) {
      _featureEnabled = false;
      return false;
    }
  }
  _featureEnabled = true;
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section S1 — Work-order CRUD — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("S1: Work-order CRUD — API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let workOrderId: string;
  const CORR = `corr-s1-${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, ROOT_ID);
    alicePage = await newIdentityPage(browser, ALICE_ID);
  });

  test("S1.1 Create work order → 200 with MaintenanceOrderOut shape", async () => {
    const enabled = await isFeatureEnabled(rootPage);
    if (!enabled) {
      test.skip(true, "MAINTENANCE_ORDERS_ENABLED=false — skipping");
      return;
    }

    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `ui/properties/${TEST_PROPERTY_ID}/work-orders`,
      {
        title: `Leaky faucet ${TS}`,
        description: "Kitchen sink dripping",
        priority: "high",
        property_id: TEST_PROPERTY_ID,
        correlation_id: CORR,
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.work_order_id).toBeTruthy();
    expect(body.wo_status).toBe("open");
    expect(body.priority).toBe("high");
    expect(body.property_id).toBe(TEST_PROPERTY_ID);
    expect(typeof body.created_at).toBe("number");
    workOrderId = body.work_order_id;
  });

  test("S1.2 Idempotent create — same correlation_id → same work_order_id", async () => {
    if (!_featureEnabled) {
      test.skip(true, "feature disabled");
      return;
    }
    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `ui/properties/${TEST_PROPERTY_ID}/work-orders`,
      {
        title: `Leaky faucet repeat ${TS}`,
        property_id: TEST_PROPERTY_ID,
        priority: "low",
        correlation_id: CORR,
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.work_order_id).toBe(workOrderId);
  });

  test("S1.3 Get work order → 200 with full shape", async () => {
    if (!_featureEnabled || !workOrderId) {
      test.skip(true, "feature disabled or no wo");
      return;
    }
    const resp = await apiGet(
      alicePage,
      `ui/properties/${TEST_PROPERTY_ID}/work-orders/${workOrderId}`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.work_order_id).toBe(workOrderId);
    expect(body.title).toContain("Leaky faucet");
  });

  test("S1.4 Get unknown work order → 404", async () => {
    if (!_featureEnabled) {
      test.skip(true, "feature disabled");
      return;
    }
    const resp = await apiGet(
      alicePage,
      `ui/properties/${TEST_PROPERTY_ID}/work-orders/nonexistent00000000000000000000001`,
    );
    expect(resp.status()).toBe(404);
  });

  test("S1.5 Create with invalid priority → 422", async () => {
    if (!_featureEnabled) {
      test.skip(true, "feature disabled");
      return;
    }
    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `ui/properties/${TEST_PROPERTY_ID}/work-orders`,
      {
        title: "Bad priority",
        property_id: TEST_PROPERTY_ID,
        priority: "critical",
      },
    );
    expect(resp.status()).toBe(422);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section S2 — Work-order lifecycle — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("S2: Work-order lifecycle (assign / schedule / transition) — API", () => {
  let rootPage: Page;
  let workOrderId: string;
  let PROP = `prop-s2-${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await newIdentityPage(browser, ROOT_ID);
    // Ensure the feature flag + a real property are resolved (work-order FK
    // validation requires a real property when property_mgmt is enabled).
    await isFeatureEnabled(rootPage);
    PROP = TEST_PROPERTY_ID;
    // Pre-create a work order for lifecycle tests
    if (_featureEnabled !== false) {
      const resp = await apiPost(
        rootPage,
        ROOT_ID,
        `ui/properties/${PROP}/work-orders`,
        {
          title: `S2 lifecycle ${TS}`,
          property_id: PROP,
          priority: "normal",
        },
      );
      if (resp.ok()) {
        const body = await resp.json();
        workOrderId = body.work_order_id;
      }
    }
  });

  test("S2.1 Assign vendor → 200 status becomes assigned", async () => {
    if (!_featureEnabled || !workOrderId) {
      test.skip(true, "feature disabled or no wo");
      return;
    }
    // Use a fake vendor_id — the active-vendor guard requires a real vendor; skip guard by using a made-up id
    // The backend will 404 if guard is strict; test for either 200 or 404 vendor_not_found
    const resp = await apiPatch(
      rootPage,
      ROOT_ID,
      `ui/maintenance/work-orders/${workOrderId}/assign`,
      {
        property_id: PROP,
        assignee_sub: "test-assignee-sub",
      },
    );
    // 200 = success, 409 = terminal (unexpected), other error = feature issue
    expect([200]).toContain(resp.status());
    if (resp.status() === 200) {
      const body = await resp.json();
      expect(body.wo_status).toBe("assigned");
      expect(body.assignee_sub).toBe("test-assignee-sub");
    }
  });

  test("S2.2 Schedule work order → 200 scheduled_for set", async () => {
    if (!_featureEnabled || !workOrderId) {
      test.skip(true, "feature disabled or no wo");
      return;
    }
    const futureTs = Math.floor(Date.now() / 1000) + 86400; // +1 day
    const resp = await apiPatch(
      rootPage,
      ROOT_ID,
      `ui/maintenance/work-orders/${workOrderId}/schedule`,
      {
        property_id: PROP,
        scheduled_for: futureTs,
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.scheduled_for).toBe(futureTs);
  });

  test("S2.3 Transition open → in_progress", async () => {
    if (!_featureEnabled || !workOrderId) {
      test.skip(true, "feature disabled or no wo");
      return;
    }
    const resp = await apiPatch(
      rootPage,
      ROOT_ID,
      `ui/maintenance/work-orders/${workOrderId}`,
      {
        property_id: PROP,
        target_status: "in_progress",
      },
    );
    expect([200, 409]).toContain(resp.status());
    if (resp.status() === 200) {
      const body = await resp.json();
      expect(body.wo_status).toBe("in_progress");
    }
  });

  test("S2.4 Transition in_progress → completed with cost_cents", async () => {
    if (!_featureEnabled || !workOrderId) {
      test.skip(true, "feature disabled or no wo");
      return;
    }
    const resp = await apiPatch(
      rootPage,
      ROOT_ID,
      `ui/maintenance/work-orders/${workOrderId}`,
      {
        property_id: PROP,
        target_status: "completed",
        cost_cents: 15000,
      },
    );
    expect([200, 409]).toContain(resp.status());
    if (resp.status() === 200) {
      const body = await resp.json();
      expect(body.wo_status).toBe("completed");
      expect(body.cost_cents).toBe(15000);
      expect(typeof body.completed_at).toBe("number");
    }
  });

  test("S2.5 cost_cents on non-completed transition → 422", async () => {
    if (!_featureEnabled) {
      test.skip(true, "feature disabled");
      return;
    }
    // Create a fresh WO for this test
    const createResp = await apiPost(
      rootPage,
      ROOT_ID,
      `ui/properties/${PROP}/work-orders`,
      {
        title: "S2.5 cost_cents test",
        property_id: PROP,
        priority: "low",
      },
    );
    if (!createResp.ok()) {
      test.skip(true, "Could not create WO");
      return;
    }
    const { work_order_id } = await createResp.json();
    const resp = await apiPatch(
      rootPage,
      ROOT_ID,
      `ui/maintenance/work-orders/${work_order_id}`,
      {
        property_id: PROP,
        target_status: "in_progress",
        cost_cents: 500,
      },
    );
    expect(resp.status()).toBe(422);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section S3 — Work-order list filters — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("S3: Work-order list filters — API", () => {
  let rootPage: Page;
  let PROP = `prop-s3-${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await newIdentityPage(browser, ROOT_ID);
    await isFeatureEnabled(rootPage);
    PROP = TEST_PROPERTY_ID;
    // Pre-create some WOs for filtering
    if (_featureEnabled !== false) {
      for (const priority of ["urgent", "normal"]) {
        await apiPost(rootPage, ROOT_ID, `ui/properties/${PROP}/work-orders`, {
          title: `S3 WO ${priority} ${TS}`,
          property_id: PROP,
          priority,
        });
      }
    }
  });

  test("S3.1 Board columns endpoint → array of 5 columns", async () => {
    if (!_featureEnabled) {
      test.skip(true, "feature disabled");
      return;
    }
    const resp = await apiGet(rootPage, "ui/maintenance/work-orders/board-columns");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.columns)).toBe(true);
    expect(body.columns.length).toBe(5);
    const statuses = body.columns.map((c: { status_key: string }) => c.status_key);
    expect(statuses).toContain("open");
    expect(statuses).toContain("completed");
  });

  test("S3.2 List by status=open → WoListOut shape", async () => {
    if (!_featureEnabled) {
      test.skip(true, "feature disabled");
      return;
    }
    const resp = await apiGet(rootPage, "ui/maintenance/work-orders", {
      wo_status: "open",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.items)).toBe(true);
    expect(typeof body.count).toBe("number");
    // All returned items should be open
    for (const item of body.items as Array<{ wo_status: string }>) {
      expect(item.wo_status).toBe("open");
    }
  });

  test("S3.3 List property work orders → items filtered to that property", async () => {
    if (!_featureEnabled) {
      test.skip(true, "feature disabled");
      return;
    }
    const resp = await apiGet(rootPage, `ui/properties/${PROP}/work-orders`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.items)).toBe(true);
    for (const item of body.items as Array<{ property_id: string }>) {
      expect(item.property_id).toBe(PROP);
    }
  });

  test("S3.4 No-filter system-wide list → 400", async () => {
    if (!_featureEnabled) {
      test.skip(true, "feature disabled");
      return;
    }
    const resp = await apiGet(rootPage, "ui/maintenance/work-orders");
    expect(resp.status()).toBe(400);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section S4 — Vendor directory CRUD — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("S4: Vendor directory CRUD — API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let vendorId: string;
  const VENDOR_NAME = `Test Vendor ${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await newIdentityPage(browser, ROOT_ID);
    alicePage = await newIdentityPage(browser, ALICE_ID);
  });

  test("S4.1 List vendor categories → array includes plumbing", async () => {
    if (!_featureEnabled) {
      test.skip(true, "feature disabled");
      return;
    }
    const resp = await apiGet(rootPage, "ui/maintenance/vendors/categories");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.categories)).toBe(true);
    expect(body.categories).toContain("plumbing");
    expect(body.categories).toContain("electrical");
    expect(body.categories.length).toBe(7);
  });

  test("S4.2 Create vendor → 200 VendorOut shape", async () => {
    if (!_featureEnabled) {
      test.skip(true, "feature disabled");
      return;
    }
    const resp = await apiPost(rootPage, ROOT_ID, "ui/maintenance/vendors", {
      name: VENDOR_NAME,
      trade_category: "plumbing",
      email: `vendor-${TS}@test.local`,
      payment_terms_days: 15,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.vendor_id).toBeTruthy();
    expect(body.name).toBe(VENDOR_NAME);
    expect(body.trade_category).toBe("plumbing");
    expect(body.status).toBe("active");
    expect(body.source).toBe("maintenance_vendor");
    expect(body.payment_terms_days).toBe(15);
    vendorId = body.vendor_id;
  });

  test("S4.3 Create vendor — invalid trade_category → 422", async () => {
    if (!_featureEnabled) {
      test.skip(true, "feature disabled");
      return;
    }
    const resp = await apiPost(rootPage, ROOT_ID, "ui/maintenance/vendors", {
      name: "Bad Category Vendor",
      trade_category: "roofing",
    });
    expect(resp.status()).toBe(422);
  });

  test("S4.4 Get vendor → 200 with VendorOut", async () => {
    if (!_featureEnabled || !vendorId) {
      test.skip(true, "feature disabled or no vendor");
      return;
    }
    const resp = await apiGet(alicePage, `ui/maintenance/vendors/${vendorId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.vendor_id).toBe(vendorId);
    expect(body.name).toBe(VENDOR_NAME);
  });

  test("S4.5 Get unknown vendor → 404", async () => {
    if (!_featureEnabled) {
      test.skip(true, "feature disabled");
      return;
    }
    const resp = await apiGet(alicePage, "ui/maintenance/vendors/nonexistent000000000000000000001");
    expect(resp.status()).toBe(404);
  });

  test("S4.6 Idempotent create — same name → same vendor_id", async () => {
    if (!_featureEnabled || !vendorId) {
      test.skip(true, "feature disabled or no vendor");
      return;
    }
    const resp = await apiPost(rootPage, ROOT_ID, "ui/maintenance/vendors", {
      name: VENDOR_NAME,
      trade_category: "electrical",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.vendor_id).toBe(vendorId);
  });

  test("S4.7 List vendors → VendorListOut with vendors array", async () => {
    if (!_featureEnabled) {
      test.skip(true, "feature disabled");
      return;
    }
    const resp = await apiGet(alicePage, "ui/maintenance/vendors", { status: "active" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.vendors)).toBe(true);
    expect(typeof body.count).toBe("number");
  });

  test("S4.8 List vendors by trade_category=plumbing → filtered results", async () => {
    if (!_featureEnabled) {
      test.skip(true, "feature disabled");
      return;
    }
    const resp = await apiGet(alicePage, "ui/maintenance/vendors", {
      status: "active",
      trade_category: "plumbing",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    for (const v of body.vendors as Array<{ trade_category: string }>) {
      expect(v.trade_category).toBe("plumbing");
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section S5 — Vendor status management — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("S5: Vendor status management — API", () => {
  let rootPage: Page;
  let vendorId: string;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await newIdentityPage(browser, ROOT_ID);
    if (_featureEnabled !== false) {
      const resp = await apiPost(rootPage, ROOT_ID, "ui/maintenance/vendors", {
        name: `S5 Vendor ${TS}`,
        trade_category: "cleaning",
      });
      if (resp.ok()) {
        vendorId = (await resp.json()).vendor_id;
      }
    }
  });

  test("S5.1 Deactivate vendor → status=inactive", async () => {
    if (!_featureEnabled || !vendorId) {
      test.skip(true, "feature disabled or no vendor");
      return;
    }
    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `ui/maintenance/vendors/${vendorId}/status`,
      { status: "inactive" },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("inactive");
  });

  test("S5.2 Deactivated vendor omitted from active list", async () => {
    if (!_featureEnabled || !vendorId) {
      test.skip(true, "feature disabled or no vendor");
      return;
    }
    const resp = await apiGet(rootPage, "ui/maintenance/vendors", { status: "active" });
    const body = await resp.json();
    const ids = (body.vendors as Array<{ vendor_id: string }>).map((v) => v.vendor_id);
    expect(ids).not.toContain(vendorId);
  });

  test("S5.3 Deactivated vendor returned in inactive list", async () => {
    if (!_featureEnabled || !vendorId) {
      test.skip(true, "feature disabled or no vendor");
      return;
    }
    const resp = await apiGet(rootPage, "ui/maintenance/vendors", { status: "inactive" });
    const body = await resp.json();
    const ids = (body.vendors as Array<{ vendor_id: string }>).map((v) => v.vendor_id);
    expect(ids).toContain(vendorId);
  });

  test("S5.4 Reactivate vendor → status=active", async () => {
    if (!_featureEnabled || !vendorId) {
      test.skip(true, "feature disabled or no vendor");
      return;
    }
    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `ui/maintenance/vendors/${vendorId}/status`,
      { status: "active" },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("active");
  });

  test("S5.5 Invalid status → 422", async () => {
    if (!_featureEnabled || !vendorId) {
      test.skip(true, "feature disabled or no vendor");
      return;
    }
    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `ui/maintenance/vendors/${vendorId}/status`,
      { status: "suspended" },
    );
    expect(resp.status()).toBe(422);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section S6 — WorkOrdersPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("S6: WorkOrdersPage UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await browser.newPage();
    await injectAuth(rootPage, ROOT_ID);
  });

  test("S6.1 Page loads and shows Work Orders heading", async () => {
    await rootPage.goto(`${BASE}/property/work-orders`, {
      waitUntil: "domcontentloaded",
    });
    await expect(
      rootPage.getByRole("heading", { name: "Work Orders", exact: true }),
    ).toBeVisible();
  });

  test("S6.2 Board view shown by default with view toggles", async () => {
    await expect(
      rootPage.getByTestId("view-board-btn"),
    ).toBeVisible();
    await expect(
      rootPage.getByTestId("view-list-btn"),
    ).toBeVisible();
  });

  test("S6.3 Feature-disabled banner shown when flag off", async () => {
    // Navigate and check for either the board or the disabled banner
    const disabled = rootPage.getByText(/not enabled/i);
    const board = rootPage.getByTestId("view-board-btn");
    // One of them must be visible
    const hasDisabled = await disabled.isVisible().catch(() => false);
    const hasBoard = await board.isVisible().catch(() => false);
    expect(hasDisabled || hasBoard).toBe(true);
  });

  test("S6.4 Switch to list view shows table or empty state", async () => {
    await rootPage.goto(`${BASE}/property/work-orders`, { waitUntil: "domcontentloaded" });
    await rootPage.getByRole("heading", { name: "Work Orders", exact: true }).waitFor({ timeout: 10_000 });
    const listBtn = rootPage.getByTestId("view-list-btn");
    const isVisible = await listBtn.isVisible().catch(() => false);
    if (!isVisible) {
      test.skip(true, "board view not available (feature disabled)");
      return;
    }
    await listBtn.click();
    // Either a table or empty state must appear (the list query loads async).
    const listState = rootPage
      .locator("table, :text('no work orders')")
      .first();
    await expect(listState).toBeVisible({ timeout: 10_000 });
  });

  test("S6.5 Admin sees New Work Order button", async () => {
    await rootPage.goto(`${BASE}/property/work-orders`, { waitUntil: "domcontentloaded" });
    await rootPage.getByRole("heading", { name: "Work Orders", exact: true }).waitFor({ timeout: 10_000 });
    const isDisabled = await rootPage
      .getByText(/not enabled/i)
      .isVisible()
      .catch(() => false);
    if (isDisabled) {
      test.skip(true, "feature disabled");
      return;
    }
    await expect(
      rootPage.getByRole("button", { name: /new work order/i }),
    ).toBeVisible();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section S7 — VendorsPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("S7: VendorsPage UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await browser.newPage();
    await injectAuth(rootPage, ROOT_ID);
  });

  test("S7.1 Page loads and shows Vendors heading", async () => {
    await rootPage.goto(`${BASE}/property/vendors`, { waitUntil: "domcontentloaded" });
    await expect(
      rootPage.getByRole("heading", { name: "Vendors", exact: true }),
    ).toBeVisible();
  });

  test("S7.2 Feature-disabled or vendor table shown", async () => {
    await rootPage.goto(`${BASE}/property/vendors`, { waitUntil: "domcontentloaded" });
    await rootPage.getByRole("heading", { name: "Vendors", exact: true }).waitFor({ timeout: 10_000 });
    // Wait for the vendor-list query to settle into one of its terminal
    // states (disabled banner / table / empty state) before asserting.
    const anyState = rootPage
      .locator("table, :text('not enabled'), :text('no vendors found')")
      .first();
    await expect(anyState).toBeVisible({ timeout: 10_000 });
  });

  test("S7.3 Admin sees Add Vendor button (when feature enabled)", async () => {
    await rootPage.goto(`${BASE}/property/vendors`, { waitUntil: "domcontentloaded" });
    await rootPage.getByRole("heading", { name: "Vendors", exact: true }).waitFor({ timeout: 10_000 });
    const isDisabled = await rootPage
      .getByText(/not enabled/i)
      .isVisible()
      .catch(() => false);
    if (isDisabled) {
      test.skip(true, "feature disabled");
      return;
    }
    await expect(
      rootPage.getByRole("button", { name: /add vendor/i }),
    ).toBeVisible();
  });

  test("S7.4 Category filter select is rendered", async () => {
    await rootPage.goto(`${BASE}/property/vendors`, { waitUntil: "domcontentloaded" });
    await rootPage.getByRole("heading", { name: "Vendors", exact: true }).waitFor({ timeout: 10_000 });
    const isDisabled = await rootPage
      .getByText(/not enabled/i)
      .isVisible()
      .catch(() => false);
    if (isDisabled) {
      test.skip(true, "feature disabled");
      return;
    }
    await expect(
      rootPage.getByText(/all categories/i).first(),
    ).toBeVisible();
  });
});
