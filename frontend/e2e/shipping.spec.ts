/**
 * E2E tests for the OFBiz SHIPPING (SHP) admin frontend.
 *
 * Sections:
 *   80 — Shipping carriers + methods (API)
 *   81 — Rate estimation (API)
 *   82 — Shipment lifecycle: create / tracking / advance / cancel (API)
 *   83 — ShippingPage UI (tabs + not-enabled handling)
 *
 * Backend: /ui/shop/shipping/* — admin mutations require require_admin_or_root_csrf,
 * reads use require_ui_session. ALL endpoints 503 when SHIPPING_ENABLED is off
 * (flag defaults OFF) — every test tolerates the disabled state.
 *
 * Auth: uses e2e_admin_session_setup.py (root is the only DB admin/root).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ROOT_SUB = "root.admin@testdev.local";
const TS       = Date.now();

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

/** True when the shipping module is disabled (503). */
function disabled(status: number): boolean {
  return status === 503;
}

const PFX = "ui/shop/shipping";

// ─────────────────────────────────────────────────────────────────────────────
// Section 80 — Carriers + methods (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 80: Shipping carriers + methods (API)", () => {
  let rootPage: Page;
  let carrierId = "";
  let shippingEnabled = true;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    const probe = await apiGet(rootPage, `${PFX}/carriers`);
    shippingEnabled = !disabled(probe.status());
  });

  test("80.1 List carriers → 200 array (or 503 disabled)", async () => {
    const resp = await apiGet(rootPage, `${PFX}/carriers`);
    if (disabled(resp.status())) {
      expect(resp.status()).toBe(503);
      return;
    }
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data)).toBe(true);
  });

  test("80.2 Create carrier → 200 with carrier_id", async () => {
    const resp = await apiPost(rootPage, "root", `${PFX}/carriers`, {
      carrier_code: "ups",
      display_name: `E2E UPS ${TS}`,
    });
    if (disabled(resp.status())) {
      expect(resp.status()).toBe(503);
      return;
    }
    // carrier_id is derived deterministically from carrier_code, so against the
    // persistent dev DynamoDB a prior run may have already created "ups" → 409.
    // Either path is valid; resolve the canonical carrier_id from the list.
    expect([200, 409]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = (await resp.json()) as { carrier_id: string; enabled: boolean };
      expect(typeof data.carrier_id).toBe("string");
      expect(data.enabled).toBe(true);
      carrierId = data.carrier_id;
    } else {
      const list = await apiGet(rootPage, `${PFX}/carriers`, { enabled_only: "false" });
      expect(list.status()).toBe(200);
      const carriers = (await list.json()) as Array<{ carrier_id: string; carrier_code: string }>;
      const ups = carriers.find((c) => c.carrier_code === "ups");
      expect(ups).toBeTruthy();
      carrierId = ups!.carrier_id;
    }
  });

  test("80.3 Add method to carrier", async () => {
    if (!shippingEnabled || !carrierId) {
      test.skip(true, "shipping disabled or carrier not created");
      return;
    }
    const resp = await apiPost(rootPage, "root", `${PFX}/carriers/${carrierId}/methods`, {
      method_code: "ground",
      method_label: "Ground",
      base_rate_cents: 599,
      transit_days_min: 2,
      transit_days_max: 5,
    });
    // A method is keyed by (carrier_id, method_code); against the persistent dev
    // DynamoDB a prior run may already hold "ground" → 409. On conflict, update
    // the existing method instead so the assertion still verifies the rate.
    expect([200, 409]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = (await resp.json()) as { method_code: string; base_rate_cents: number };
      expect(data.method_code).toBe("ground");
      expect(data.base_rate_cents).toBe(599);
    } else {
      const patch = await apiPatch(
        rootPage,
        "root",
        `${PFX}/carriers/${carrierId}/methods/ground`,
        { base_rate_cents: 599 },
      );
      expect(patch.status()).toBe(200);
      const data = (await patch.json()) as { method_code: string; base_rate_cents: number };
      expect(data.method_code).toBe("ground");
      expect(data.base_rate_cents).toBe(599);
    }
  });

  test("80.4 List methods for carrier", async () => {
    if (!shippingEnabled || !carrierId) {
      test.skip(true, "shipping disabled or carrier not created");
      return;
    }
    const resp = await apiGet(rootPage, `${PFX}/carriers/${carrierId}/methods`, {
      enabled_only: "false",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data)).toBe(true);
  });

  test("80.5 Patch carrier display_name", async () => {
    if (!shippingEnabled || !carrierId) {
      test.skip(true, "shipping disabled or carrier not created");
      return;
    }
    const resp = await apiPatch(rootPage, "root", `${PFX}/carriers/${carrierId}`, {
      display_name: `E2E UPS Renamed ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { display_name: string };
    expect(data.display_name).toContain("Renamed");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 81 — Rate estimation (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 81: Rate estimation (API)", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test("81.1 POST /estimate → quote shape (or 503)", async () => {
    const resp = await apiPost(rootPage, "root", `${PFX}/estimate`, {
      carrier_code: "ups",
      method_code: "ground",
      weight_oz: 32,
      destination_zip: "94105",
    });
    if (disabled(resp.status())) {
      expect(resp.status()).toBe(503);
      return;
    }
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as {
      request_id: string;
      options: unknown[];
      currency: string;
      generated_at: number;
    };
    expect(typeof data.request_id).toBe("string");
    expect(Array.isArray(data.options)).toBe(true);
    expect(typeof data.generated_at).toBe("number");
  });

  test("81.2 GET /estimate → quote shape (or 503)", async () => {
    const resp = await apiGet(rootPage, `${PFX}/estimate`, {
      carrier_code: "ups",
      method_code: "ground",
      weight_oz: "16",
      destination_zip: "10001",
    });
    if (disabled(resp.status())) {
      expect(resp.status()).toBe(503);
      return;
    }
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { options: unknown[] };
    expect(Array.isArray(data.options)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 82 — Shipment lifecycle (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 82: Shipment lifecycle (API)", () => {
  let rootPage: Page;
  let shipmentId = "";
  const orderId = `e2e_order_${TS}`;
  let shippingEnabled = true;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    const probe = await apiGet(rootPage, `${PFX}/carriers`);
    shippingEnabled = !disabled(probe.status());
    // Ensure a carrier+method exist so shipment creation can succeed.
    if (shippingEnabled) {
      const c = await apiPost(rootPage, "root", `${PFX}/carriers`, {
        carrier_code: "fedex",
        display_name: `E2E FedEx ${TS}`,
      });
      if (c.ok()) {
        const cid = ((await c.json()) as { carrier_id: string }).carrier_id;
        await apiPost(rootPage, "root", `${PFX}/carriers/${cid}/methods`, {
          method_code: "ground",
          method_label: "Ground",
          base_rate_cents: 700,
        });
      }
    }
  });

  test("82.1 Create shipment → pending_fulfillment (or 503)", async () => {
    const resp = await apiPost(rootPage, "root", `${PFX}/shipments`, {
      order_id: orderId,
      carrier_code: "fedex",
      method_code: "ground",
      ship_to_address: {
        name: "Jane Doe",
        line1: "1 Market St",
        city: "San Francisco",
        state: "CA",
        zip: "94105",
        country: "US",
      },
      line_items: [{ item_id: "sku_1", quantity: 1 }],
    });
    if (disabled(resp.status())) {
      expect(resp.status()).toBe(503);
      return;
    }
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { shipment_id: string; status: string };
    expect(typeof data.shipment_id).toBe("string");
    expect(data.status).toBe("pending_fulfillment");
    shipmentId = data.shipment_id;
  });

  test("82.2 List shipments for order", async () => {
    if (!shippingEnabled || !shipmentId) {
      test.skip(true, "shipping disabled or shipment not created");
      return;
    }
    const resp = await apiGet(rootPage, `${PFX}/orders/${orderId}/shipments`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { shipments: unknown[]; count: number };
    expect(Array.isArray(data.shipments)).toBe(true);
    expect(data.count).toBeGreaterThanOrEqual(1);
  });

  test("82.3 Update tracking number", async () => {
    if (!shippingEnabled || !shipmentId) {
      test.skip(true, "shipping disabled or shipment not created");
      return;
    }
    const resp = await apiPatch(rootPage, "root", `${PFX}/shipments/${shipmentId}/tracking`, {
      tracking_number: `1Z${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { tracking_number: string };
    expect(data.tracking_number).toContain("1Z");
  });

  test("82.4 Shipment reaches label_created", async () => {
    if (!shippingEnabled || !shipmentId) {
      test.skip(true, "shipping disabled or shipment not created");
      return;
    }
    // Setting a tracking number (82.3) auto-advances the shipment from
    // pending_fulfillment → label_created, so by now it is already there.
    // Verify the current status and that the transition guard rejects a
    // redundant re-advance to the same status with a 409 (no silent regress).
    const cur = await apiGet(rootPage, `${PFX}/shipments/${shipmentId}`);
    expect(cur.status()).toBe(200);
    const before = (await cur.json()) as { status: string };

    if (before.status === "pending_fulfillment") {
      const resp = await apiPost(rootPage, "root", `${PFX}/shipments/${shipmentId}/advance`, {
        target_status: "label_created",
      });
      expect(resp.status()).toBe(200);
      expect(((await resp.json()) as { status: string }).status).toBe("label_created");
    } else {
      expect(before.status).toBe("label_created");
      const resp = await apiPost(rootPage, "root", `${PFX}/shipments/${shipmentId}/advance`, {
        target_status: "label_created",
      });
      expect(resp.status()).toBe(409);
    }
  });

  test("82.5 Get shipment by id", async () => {
    if (!shippingEnabled || !shipmentId) {
      test.skip(true, "shipping disabled or shipment not created");
      return;
    }
    const resp = await apiGet(rootPage, `${PFX}/shipments/${shipmentId}`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { shipment_id: string; order_id: string };
    expect(data.shipment_id).toBe(shipmentId);
    expect(data.order_id).toBe(orderId);
  });

  test("82.6 Cancel shipment", async () => {
    if (!shippingEnabled || !shipmentId) {
      test.skip(true, "shipping disabled or shipment not created");
      return;
    }
    const resp = await apiPost(rootPage, "root", `${PFX}/shipments/${shipmentId}/cancel`, {
      reason: "e2e cleanup",
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { status: string };
    expect(data.status).toBe("cancelled");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 83 — ShippingPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 83: ShippingPage UI", () => {
  test("83.1 Page renders header and tabs", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "root");
    await page.goto(`${BASE}/ofbiz/shipping`, { waitUntil: "domcontentloaded" });
    await expect(
      page.getByRole("heading", { name: "Shipping & Logistics" }),
    ).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("tab", { name: "Shipments" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Carriers" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Rate quote" })).toBeVisible();
    await page.close();
  });

  test("83.2 Carriers tab shows panel or not-enabled state", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "root");
    await page.goto(`${BASE}/ofbiz/shipping`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "Carriers" }).click();
    // Either the Carriers card title OR the not-enabled message is shown.
    const enabled = page.getByText("Manage shipping carriers", { exact: false });
    const notEnabled = page.getByText("Shipping is not enabled", { exact: false });
    await expect(enabled.or(notEnabled).first()).toBeVisible({ timeout: 15_000 });
    await page.close();
  });

  test("83.3 Rate quote tab renders form", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "root");
    await page.goto(`${BASE}/ofbiz/shipping`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "Rate quote" }).click();
    await expect(
      page.getByRole("button", { name: /get quote/i }),
    ).toBeVisible({ timeout: 15_000 });
    await page.close();
  });
});

// keep ROOT_SUB referenced
test("shipping spec sanity", async () => {
  expect(ROOT_SUB).toContain("root");
});
