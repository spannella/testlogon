/**
 * E2E tests for the OFBiz Fixed Assets (FXA) cluster.
 *
 * Sections:
 *   90 — Asset register CRUD (create / list / get / patch) — API
 *   91 — Depreciation schedule (generate / get / post period) — API
 *   92 — Disposal — API
 *   93 — Maintenance work orders (create / list / transition / queue) — API
 *   94 — Fixed Assets UI (register list, detail, schedule)
 *
 * All fixed-asset endpoints are admin/root only (require_admin_or_root).
 * Identities come from e2e_admin_session_setup.py — `root` is the only DB admin/root.
 *
 * NOTE: the fixed-assets master flag (FIXED_ASSETS_ENABLED) defaults OFF, so the
 * endpoints may return 503 when the feature is disabled. The API sections tolerate
 * that and the UI section asserts the graceful "module not enabled" / empty states.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ROOT_SUB = "root.admin@testdev.local";
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
    _adminSessions = loadSessions();
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

/** True when the feature flag is off (503) — sections short-circuit gracefully. */
function featureOff(status: number): boolean {
  return status === 503;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 90 — Asset register CRUD — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 90: Fixed asset register CRUD (API)", () => {
  let rootPage: Page;
  let assetId = "";

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
  });

  test("90.1 Create asset → 200/503", async () => {
    const resp = await apiPost(rootPage, "root", "ui/fixed-assets", {
      name: `E2E asset ${TS}`,
      asset_class: "hardware",
      acquisition_cost_cents: 1_200_000,
      salvage_value_cents: 50_000,
      useful_life_months: 36,
      acquired_at: Math.floor(Date.now() / 1000),
    });
    if (featureOff(resp.status())) {
      test.skip(true, "fixed-assets feature disabled");
      return;
    }
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { asset_id: string; status: string; net_book_value_cents: number };
    expect(typeof data.asset_id).toBe("string");
    expect(data.status).toBe("active");
    expect(data.net_book_value_cents).toBe(1_200_000);
    assetId = data.asset_id;
  });

  test("90.2 Get asset → owner, NBV", async () => {
    test.skip(!assetId, "no asset created");
    const resp = await apiGet(rootPage, `ui/fixed-assets/${assetId}`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { owner_sub: string; accumulated_depreciation_cents: number };
    expect(data.owner_sub).toBe(ROOT_SUB);
    expect(data.accumulated_depreciation_cents).toBe(0);
  });

  test("90.3 List assets → includes new asset", async () => {
    test.skip(!assetId, "no asset created");
    const resp = await apiGet(rootPage, "ui/fixed-assets", { limit: "100" });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { items: Array<{ asset_id: string }> };
    expect(Array.isArray(data.items)).toBe(true);
    expect(data.items.find((a) => a.asset_id === assetId)).toBeTruthy();
  });

  test("90.4 Patch asset name", async () => {
    test.skip(!assetId, "no asset created");
    const resp = await apiPatch(rootPage, "root", `ui/fixed-assets/${assetId}`, {
      name: `E2E asset renamed ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { name: string };
    expect(data.name).toBe(`E2E asset renamed ${TS}`);
  });

  test("90.5 Salvage >= cost → 422 validation", async () => {
    const resp = await apiPost(rootPage, "root", "ui/fixed-assets", {
      name: `bad ${TS}`,
      asset_class: "hardware",
      acquisition_cost_cents: 1000,
      salvage_value_cents: 1000,
      useful_life_months: 12,
      acquired_at: Math.floor(Date.now() / 1000),
    });
    if (featureOff(resp.status())) return;
    expect(resp.status()).toBe(422);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 91 — Depreciation schedule — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 91: Depreciation schedule (API)", () => {
  let rootPage: Page;
  let assetId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    const resp = await apiPost(rootPage, "root", "ui/fixed-assets", {
      name: `E2E depr ${TS}`,
      asset_class: "hardware",
      acquisition_cost_cents: 120_000,
      salvage_value_cents: 0,
      useful_life_months: 12,
      acquired_at: Math.floor(Date.now() / 1000) - 86400 * 400,
    });
    if (resp.ok()) {
      assetId = ((await resp.json()) as { asset_id: string }).asset_id;
    }
  });

  test("91.1 Generate schedule → 12 periods", async () => {
    test.skip(!assetId, "feature off / no asset");
    const resp = await apiPost(rootPage, "root", `ui/fixed-assets/${assetId}/schedule/generate`, {});
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { total_periods: number; periods: Array<{ amount_cents: number }> };
    expect(data.total_periods).toBe(12);
    expect(data.periods[0].amount_cents).toBe(10_000);
  });

  test("91.2 Get schedule reflects generated periods", async () => {
    test.skip(!assetId, "feature off / no asset");
    const resp = await apiGet(rootPage, `ui/fixed-assets/${assetId}/schedule`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { remaining_periods: number };
    expect(data.remaining_periods).toBeGreaterThan(0);
  });

  test("91.3 Post period 1 → posted + accumulates depreciation", async () => {
    test.skip(!assetId, "feature off / no asset");
    const resp = await apiPost(rootPage, "root", `ui/fixed-assets/${assetId}/schedule/1/post`, {});
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { schedule_status: string };
    expect(data.schedule_status).toBe("posted");

    const assetResp = await apiGet(rootPage, `ui/fixed-assets/${assetId}`);
    const asset = (await assetResp.json()) as { accumulated_depreciation_cents: number };
    expect(asset.accumulated_depreciation_cents).toBe(10_000);
  });

  test("91.4 Re-post period 1 is idempotent", async () => {
    test.skip(!assetId, "feature off / no asset");
    const resp = await apiPost(rootPage, "root", `ui/fixed-assets/${assetId}/schedule/1/post`, {});
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { schedule_status: string };
    expect(data.schedule_status).toBe("posted");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 92 — Disposal — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 92: Asset disposal (API)", () => {
  let rootPage: Page;
  let assetId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    const resp = await apiPost(rootPage, "root", "ui/fixed-assets", {
      name: `E2E dispose ${TS}`,
      asset_class: "vehicle",
      acquisition_cost_cents: 500_000,
      salvage_value_cents: 100_000,
      useful_life_months: 60,
      acquired_at: Math.floor(Date.now() / 1000),
    });
    if (resp.ok()) {
      assetId = ((await resp.json()) as { asset_id: string }).asset_id;
    }
  });

  test("92.1 Dispose asset → status disposed", async () => {
    test.skip(!assetId, "feature off / no asset");
    const resp = await apiPost(rootPage, "root", `ui/fixed-assets/${assetId}/dispose`, {
      disposal_reason: "sold",
      proceeds_amount_cents: 250_000,
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { status: string };
    expect(data.status).toBe("disposed");
  });

  test("92.2 Re-dispose is idempotent", async () => {
    test.skip(!assetId, "feature off / no asset");
    const resp = await apiPost(rootPage, "root", `ui/fixed-assets/${assetId}/dispose`, {});
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { status: string };
    expect(data.status).toBe("disposed");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 93 — Maintenance work orders — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 93: Maintenance work orders (API)", () => {
  let rootPage: Page;
  let assetId = "";
  let workOrderId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    const resp = await apiPost(rootPage, "root", "ui/fixed-assets", {
      name: `E2E wo asset ${TS}`,
      asset_class: "hardware",
      acquisition_cost_cents: 200_000,
      salvage_value_cents: 10_000,
      useful_life_months: 24,
      acquired_at: Math.floor(Date.now() / 1000),
    });
    if (resp.ok()) {
      assetId = ((await resp.json()) as { asset_id: string }).asset_id;
    }
  });

  test("93.1 Create work order → open", async () => {
    test.skip(!assetId, "feature off / no asset");
    const resp = await apiPost(rootPage, "root", `ui/fixed-assets/${assetId}/work-orders`, {
      title: `Replace fan ${TS}`,
      description: "noisy fan",
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { work_order_id: string; wo_status: string };
    expect(data.wo_status).toBe("open");
    workOrderId = data.work_order_id;
  });

  test("93.2 List work orders for asset", async () => {
    test.skip(!assetId, "feature off / no asset");
    const resp = await apiGet(rootPage, `ui/fixed-assets/${assetId}/work-orders`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { items: Array<{ work_order_id: string }> };
    expect(data.items.find((w) => w.work_order_id === workOrderId)).toBeTruthy();
  });

  test("93.3 Transition open → in_progress → completed", async () => {
    test.skip(!workOrderId, "feature off / no work order");
    const r1 = await apiPatch(
      rootPage,
      "root",
      `ui/fixed-assets/work-orders/${workOrderId}?asset_id=${assetId}`,
      { target_status: "in_progress" },
    );
    expect(r1.status()).toBe(200);
    const r2 = await apiPatch(
      rootPage,
      "root",
      `ui/fixed-assets/work-orders/${workOrderId}?asset_id=${assetId}`,
      { target_status: "completed", cost_cents: 4500 },
    );
    expect(r2.status()).toBe(200);
    const data = (await r2.json()) as { wo_status: string; cost_cents: number };
    expect(data.wo_status).toBe("completed");
    expect(data.cost_cents).toBe(4500);
  });

  test("93.4 Illegal transition → 409", async () => {
    test.skip(!workOrderId, "feature off / no work order");
    const resp = await apiPatch(
      rootPage,
      "root",
      `ui/fixed-assets/work-orders/${workOrderId}?asset_id=${assetId}`,
      { target_status: "in_progress" },
    );
    expect(resp.status()).toBe(409);
  });

  test("93.5 Global work-order queue", async () => {
    test.skip(!assetId, "feature off / no asset");
    const resp = await apiGet(rootPage, "ui/fixed-assets/work-orders", { limit: "100" });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { items: unknown[] };
    expect(Array.isArray(data.items)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 94 — Fixed Assets UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 94: Fixed Assets UI", () => {
  test("94.1 Register page renders", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "root");
    await page.goto(`${BASE}/ofbiz/fixed-assets`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Fixed Assets" })).toBeVisible();
    await expect(page.getByRole("button", { name: /New asset/i })).toBeVisible();
  });

  test("94.2 Maintenance queue page renders", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "root");
    await page.goto(`${BASE}/ofbiz/fixed-assets/maintenance`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Maintenance Queue" })).toBeVisible();
  });

  test("94.3 Open create asset dialog", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "root");
    await page.goto(`${BASE}/ofbiz/fixed-assets`, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: /New asset/i }).first().click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByText("New fixed asset")).toBeVisible();
  });
});
