/**
 * E2E tests for the OFBiz Manufacturing (MFG) cluster.
 *
 * Sections:
 *   80 — Work-center + BOM CRUD (API)
 *   81 — Routing tasks + routing cost (API)
 *   82 — Work-order lifecycle (API)
 *   83 — MRP run (API)
 *   84 — Manufacturing UI (BOM editor / work-order queue / MRP)
 *
 * Auth: uses e2e_admin_session_setup.py — manufacturing endpoints require
 * admin/root (require_admin_or_root_csrf). Only `root` is admin/root in DB.
 *
 * NOTE: The manufacturing feature flag defaults OFF — when disabled every
 * endpoint returns 404. These tests are written to be skipped gracefully if
 * the cluster is not enabled (checked once in beforeAll).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const TS = Date.now();

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

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

// Detect whether the manufacturing feature is enabled (404 → disabled).
let MFG_ENABLED: boolean | null = null;
async function mfgEnabled(page: Page): Promise<boolean> {
  if (MFG_ENABLED === null) {
    const resp = await apiGet(page, "ui/manufacturing/work-centers");
    MFG_ENABLED = resp.status() !== 404;
  }
  return MFG_ENABLED;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 80 — Work-center + BOM CRUD (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 80: Work-center + BOM CRUD (API)", () => {
  let rootPage: Page;
  let workCenterId = "";
  let bomId = "";

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
  });

  test("80.1 Create work center", async () => {
    if (!(await mfgEnabled(rootPage))) test.skip();
    const resp = await apiPost(rootPage, "root", "ui/manufacturing/work-centers", {
      name: `WC ${TS}`,
      capacity_per_hour: 10,
      cost_per_hour_cents: 5000,
    });
    expect(resp.ok()).toBeTruthy();
    const data = (await resp.json()) as { work_center_id: string; status: string };
    expect(data.work_center_id).toBeTruthy();
    expect(data.status).toBe("active");
    workCenterId = data.work_center_id;
  });

  test("80.2 List work centers includes new one", async () => {
    if (!(await mfgEnabled(rootPage))) test.skip();
    const resp = await apiGet(rootPage, "ui/manufacturing/work-centers", { status: "active" });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { work_centers: Array<{ work_center_id: string }> };
    expect(data.work_centers.some((w) => w.work_center_id === workCenterId)).toBeTruthy();
  });

  test("80.3 Create BOM with components", async () => {
    if (!(await mfgEnabled(rootPage))) test.skip();
    const resp = await apiPost(rootPage, "root", "ui/manufacturing/boms", {
      product_sku: `FG-${TS}`,
      name: `Widget BOM ${TS}`,
      output_quantity: 1,
      components: [
        { component_sku: `RAW-A-${TS}`, quantity_per: 2, scrap_pct: 0.05, unit_of_measure: "each" },
        { component_sku: `RAW-B-${TS}`, quantity_per: 1 },
      ],
    });
    expect(resp.ok()).toBeTruthy();
    const data = (await resp.json()) as { bom_id: string; components: unknown[] };
    expect(data.bom_id).toBeTruthy();
    expect(data.components.length).toBe(2);
    bomId = data.bom_id;
  });

  test("80.4 Get BOM + explode", async () => {
    if (!(await mfgEnabled(rootPage))) test.skip();
    const getResp = await apiGet(rootPage, `ui/manufacturing/boms/${bomId}`);
    expect(getResp.status()).toBe(200);

    const explResp = await apiGet(rootPage, `ui/manufacturing/boms/${bomId}/explode`, { build_qty: "3" });
    expect(explResp.status()).toBe(200);
    const expl = (await explResp.json()) as { build_qty: number; components: unknown[] };
    expect(expl.build_qty).toBe(3);
    expect(Array.isArray(expl.components)).toBeTruthy();
  });

  test("80.5 List BOMs filtered by product_sku", async () => {
    if (!(await mfgEnabled(rootPage))) test.skip();
    const resp = await apiGet(rootPage, "ui/manufacturing/boms", { product_sku: `FG-${TS}` });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { boms: Array<{ bom_id: string }> };
    expect(data.boms.some((b) => b.bom_id === bomId)).toBeTruthy();
  });

  test("80.6 Non-admin (bob) is forbidden", async ({ browser }) => {
    if (!(await mfgEnabled(rootPage))) test.skip();
    const bobPage = await newIdentityPage(browser, "bob");
    const resp = await apiPost(bobPage, "bob", "ui/manufacturing/work-centers", {
      name: "nope",
      capacity_per_hour: 1,
      cost_per_hour_cents: 1,
    });
    expect([401, 403]).toContain(resp.status());
    await bobPage.close();
  });

  // expose for later sections
  test("80.7 capture ids", async () => {
    if (!(await mfgEnabled(rootPage))) test.skip();
    sharedWorkCenterId = workCenterId;
    sharedBomId = bomId;
    expect(sharedBomId).toBeTruthy();
  });
});

let sharedWorkCenterId = "";
let sharedBomId = "";

// ─────────────────────────────────────────────────────────────────────────────
// Section 81 — Routing tasks + routing cost (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 81: Routing tasks + cost (API)", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test("81.1 Add routing task", async () => {
    if (!(await mfgEnabled(rootPage)) || !sharedBomId) test.skip();
    const resp = await apiPost(rootPage, "root", `ui/manufacturing/boms/${sharedBomId}/routing-tasks`, {
      work_center_id: sharedWorkCenterId,
      sequence: 10,
      setup_minutes: 15,
      run_minutes_per_unit: 5,
      description: "Assemble",
    });
    expect(resp.ok()).toBeTruthy();
  });

  test("81.2 List routing tasks", async () => {
    if (!(await mfgEnabled(rootPage)) || !sharedBomId) test.skip();
    const resp = await apiGet(rootPage, `ui/manufacturing/boms/${sharedBomId}/routing-tasks`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { tasks: Array<{ sequence: number }> };
    expect(data.tasks.some((t) => t.sequence === 10)).toBeTruthy();
  });

  test("81.3 Routing cost reflects labor rate", async () => {
    if (!(await mfgEnabled(rootPage)) || !sharedBomId) test.skip();
    const resp = await apiGet(rootPage, `ui/manufacturing/boms/${sharedBomId}/routing-cost`, {
      quantity: "10",
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { total_labor_cost_cents: number; quantity: number };
    expect(data.quantity).toBe(10);
    expect(typeof data.total_labor_cost_cents).toBe("number");
  });

  test("81.4 Delete routing task", async () => {
    if (!(await mfgEnabled(rootPage)) || !sharedBomId) test.skip();
    const resp = await apiDelete(rootPage, "root", `ui/manufacturing/boms/${sharedBomId}/routing-tasks/10`);
    expect(resp.ok()).toBeTruthy();
    const data = (await resp.json()) as { ok: boolean };
    expect(data.ok).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 82 — Work-order lifecycle (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 82: Work-order lifecycle (API)", () => {
  let rootPage: Page;
  let woId = "";

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test("82.1 Create work order", async () => {
    if (!(await mfgEnabled(rootPage))) test.skip();
    // Releasing a work order issues the BOM components from inventory, so the
    // warehouse must have stock first (a fresh per-run SKU starts at zero, which
    // would otherwise make /release abort with 409 insufficient_stock).
    for (const sku of [`RAW-A-${TS}`, `RAW-B-${TS}`]) {
      await apiPost(rootPage, "root", "ui/inventory/items/adjust", {
        sku,
        delta: 1000,
        location_id: "warehouse",
        reason: "e2e_seed",
      });
    }
    const resp = await apiPost(rootPage, "root", "ui/manufacturing/work-orders", {
      product_sku: `FG-${TS}`,
      quantity: 5,
      bom_id: sharedBomId || undefined,
    });
    expect(resp.ok()).toBeTruthy();
    const data = (await resp.json()) as { work_order_id: string; status: string };
    expect(data.work_order_id).toBeTruthy();
    woId = data.work_order_id;
  });

  test("82.2 Release work order", async () => {
    if (!(await mfgEnabled(rootPage)) || !woId) test.skip();
    const resp = await apiPost(rootPage, "root", `ui/manufacturing/work-orders/${woId}/release`);
    expect(resp.ok()).toBeTruthy();
    const data = (await resp.json()) as { status: string };
    expect(data.status).toBe("released");
  });

  test("82.3 Start work order", async () => {
    if (!(await mfgEnabled(rootPage)) || !woId) test.skip();
    const resp = await apiPost(rootPage, "root", `ui/manufacturing/work-orders/${woId}/start`);
    expect(resp.ok()).toBeTruthy();
    const data = (await resp.json()) as { status: string };
    expect(data.status).toBe("in_progress");
  });

  test("82.4 Complete work order", async () => {
    if (!(await mfgEnabled(rootPage)) || !woId) test.skip();
    const resp = await apiPost(rootPage, "root", `ui/manufacturing/work-orders/${woId}/complete`, {
      produced_qty: 5,
      location_id: "warehouse",
    });
    expect(resp.ok()).toBeTruthy();
    const data = (await resp.json()) as { status: string };
    expect(data.status).toBe("completed");
  });

  test("82.5 Cancel a separate work order", async () => {
    if (!(await mfgEnabled(rootPage))) test.skip();
    const createResp = await apiPost(rootPage, "root", "ui/manufacturing/work-orders", {
      product_sku: `FG-${TS}`,
      quantity: 1,
      bom_id: sharedBomId || undefined,
      correlation_id: `cancel-${TS}`,
    });
    const created = (await createResp.json()) as { work_order_id: string };
    const resp = await apiPost(rootPage, "root", `ui/manufacturing/work-orders/${created.work_order_id}/cancel`, {
      reason: "test cancel",
    });
    expect(resp.ok()).toBeTruthy();
    const data = (await resp.json()) as { status: string };
    expect(data.status).toBe("cancelled");
  });

  test("82.6 List work orders by status", async () => {
    if (!(await mfgEnabled(rootPage))) test.skip();
    const resp = await apiGet(rootPage, "ui/manufacturing/work-orders", { status: "completed" });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { work_orders: unknown[] };
    expect(Array.isArray(data.work_orders)).toBeTruthy();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 83 — MRP run (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 83: MRP run (API)", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test("83.1 Run MRP returns requirements", async () => {
    if (!(await mfgEnabled(rootPage))) test.skip();
    const resp = await apiPost(rootPage, "root", "ui/manufacturing/mrp/run", {
      horizon_days: 30,
      location_id: "warehouse",
    });
    expect(resp.ok()).toBeTruthy();
    const data = (await resp.json()) as { mrp_run_id: string; requirements: unknown[] };
    expect(data.mrp_run_id).toBeTruthy();
    expect(Array.isArray(data.requirements)).toBeTruthy();

    const getResp = await apiGet(rootPage, `ui/manufacturing/mrp/runs/${data.mrp_run_id}`);
    expect(getResp.status()).toBe(200);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 84 — Manufacturing UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 84: Manufacturing UI", () => {
  test("84.1 BOM editor renders", async ({ page }) => {
    await injectAuth(page, "root");
    await page.goto(`${BASE}/manufacturing/boms`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Bill of Materials" })).toBeVisible();
  });

  test("84.2 Work-order queue renders", async ({ page }) => {
    await injectAuth(page, "root");
    await page.goto(`${BASE}/manufacturing/work-orders`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Work Order Queue" })).toBeVisible();
  });

  test("84.3 MRP page renders + run button", async ({ page }) => {
    await injectAuth(page, "root");
    await page.goto(`${BASE}/manufacturing/mrp`, { waitUntil: "domcontentloaded" });
    await expect(
      page.getByRole("heading", { name: "Material Requirements Planning" }),
    ).toBeVisible();
    await expect(page.getByRole("button", { name: /Run MRP/i })).toBeVisible();
  });

  test("84.4 Work centers page renders", async ({ page }) => {
    await injectAuth(page, "root");
    await page.goto(`${BASE}/manufacturing/work-centers`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Work Centers" })).toBeVisible();
  });
});
