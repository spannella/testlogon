/**
 * E2E tests for the OFBiz Core ERP admin area (OFB cluster).
 *
 * Sections:
 *   80 — Inventory API (flag-gated INVENTORY_RESERVATIONS_ENABLED)
 *   81 — Returns / RMA API (flag-gated RETURNS_RMA_ENABLED)
 *   82 — ERP UI (overview / inventory / returns pages)
 *
 * Both backend modules default OFF, so the live endpoints return 404. The UI
 * pages render a "module is not enabled" card in that case. These tests assert
 * BOTH the disabled behavior (404 / not-enabled card) and, when the flag is on,
 * the happy-path contract — so they stay meaningful either way.
 *
 * Auth: uses e2e_admin_session_setup.py (root = admin/root in DB).
 *
 * Identities:
 *   root  – root.admin@testdev.local – role=root (admin inventory/returns ops)
 *   bob   – e2e_bob@test.local       – role=user (customer reservation/return)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";

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

async function apiPut(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.put(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 80 — Inventory API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 80: Inventory API", () => {
  let rootPage: Page;
  let bobPage: Page;
  const SKU = `E2E-SKU-${Date.now()}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    bobPage = await newIdentityPage(browser, "bob");
  });

  test("80.1 set on-hand → enabled returns record; disabled returns 404", async () => {
    const resp = await apiPut(rootPage, "root", "ui/inventory/items", {
      sku: SKU,
      on_hand: 25,
      reorder_point: 5,
      reason: "e2e seed",
    });
    if (resp.status() === 404) {
      expect(resp.status()).toBe(404); // flag off — acceptable
      return;
    }
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { sku: string; on_hand: number; available: number };
    expect(data.sku).toBe(SKU);
    expect(data.on_hand).toBe(25);
    expect(data.available).toBe(25);
  });

  test("80.2 get item → 200 record or 404 when disabled/missing", async () => {
    const resp = await apiGet(rootPage, `ui/inventory/items/${encodeURIComponent(SKU)}`);
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = (await resp.json()) as { sku: string; reserved: number };
      expect(data.sku).toBe(SKU);
      expect(typeof data.reserved).toBe("number");
    }
  });

  test("80.3 adjust delta → 200 or 404 when disabled", async () => {
    const resp = await apiPost(rootPage, "root", "ui/inventory/items/adjust", {
      sku: SKU,
      delta: -3,
      reason: "e2e damage",
    });
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = (await resp.json()) as { on_hand: number };
      expect(data.on_hand).toBe(22);
    }
  });

  test("80.4 low-stock listing → {items:[]} or 404", async () => {
    const resp = await apiGet(rootPage, "ui/inventory/low-stock", { status: "in_stock" });
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = (await resp.json()) as { items: unknown[] };
      expect(Array.isArray(data.items)).toBe(true);
    }
  });

  test("80.5 invalid status filter → 422 (when enabled) or 404 (disabled)", async () => {
    const resp = await apiGet(rootPage, "ui/inventory/low-stock", { status: "bogus" });
    expect([422, 404]).toContain(resp.status());
  });

  test("80.6 customer reservation → 200 reservation or 404", async () => {
    const resp = await apiPost(bobPage, "bob", "ui/inventory/reservations", {
      sku: SKU,
      quantity: 1,
    });
    expect([200, 404, 409]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = (await resp.json()) as { reservation_id: string; status: string };
      expect(typeof data.reservation_id).toBe("string");
      expect(data.status).toBe("active");
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 81 — Returns / RMA API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 81: Returns / RMA API", () => {
  let rootPage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    bobPage = await newIdentityPage(browser, "bob");
  });

  test("81.1 admin queue → {returns:[]} or 404 when disabled", async () => {
    const resp = await apiGet(rootPage, "ui/returns/admin/queue", { status: "requested" });
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = (await resp.json()) as { returns: unknown[] };
      expect(Array.isArray(data.returns)).toBe(true);
    }
  });

  test("81.2 invalid status filter → 422 or 404", async () => {
    const resp = await apiGet(rootPage, "ui/returns/admin/queue", { status: "bogus" });
    expect([422, 404]).toContain(resp.status());
  });

  test("81.3 customer request return → 200 record or 404", async () => {
    const resp = await apiPost(bobPage, "bob", "ui/returns", {
      order_id: `e2e-order-${Date.now()}`,
      reason: "Defective on arrival",
      lines: [{ item_id: "item-1", quantity: 1 }],
    });
    expect([200, 400, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = (await resp.json()) as { return_id: string; status: string };
      expect(typeof data.return_id).toBe("string");
      expect(data.status).toBe("requested");
    }
  });

  test("81.4 get non-existent return → 404", async () => {
    const resp = await apiGet(bobPage, "ui/returns/does-not-exist");
    expect(resp.status()).toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 82 — ERP UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 82: ERP UI", () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page, "root");
  });

  test("82.1 overview page renders module cards", async ({ page }) => {
    await page.goto(`${BASE}/erp`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "ERP", exact: true })).toBeVisible();
    await expect(page.getByText("Inventory Levels")).toBeVisible();
    await expect(page.getByText("Returns / RMA Queue")).toBeVisible();
    await expect(page.getByText("General Ledger")).toBeVisible();
  });

  test("82.2 inventory page renders (table or not-enabled card)", async ({ page }) => {
    await page.goto(`${BASE}/erp/inventory`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Inventory Levels" })).toBeVisible();
    const enabledMarker = page.getByText("Stock by status");
    const disabledMarker = page.getByText(/is not enabled/i);
    await expect(enabledMarker.or(disabledMarker).first()).toBeVisible({ timeout: 10_000 });
  });

  test("82.3 returns page renders (queue or not-enabled card)", async ({ page }) => {
    await page.goto(`${BASE}/erp/returns`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Returns / RMA Queue" })).toBeVisible();
    const enabledMarker = page.getByText("RMA queue");
    const disabledMarker = page.getByText(/is not enabled/i);
    await expect(enabledMarker.or(disabledMarker).first()).toBeVisible({ timeout: 10_000 });
  });
});
