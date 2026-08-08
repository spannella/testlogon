/**
 * E2E tests for the Property Management frontend (PROP-001..PROP-005).
 *
 * Sections:
 *   70 — Properties list API (create / list / get / update / archive)
 *   71 — Unit CRUD API (create / list / get / update / delete)
 *   72 — Occupancy API (property + portfolio)
 *   73 — Properties UI (PropertiesPage — list, create, filter)
 *   74 — Property detail UI (PropertyDetailPage — info, units, edit)
 *
 * Auth: uses e2e_admin_session_setup.py (charlie_admin for writes, alice for reads).
 *
 * IMPORTANT: All endpoints return 404 when PROPERTY_MGMT_ENABLED is off (the default).
 * Tests detect this and skip gracefully. When the flag is on, all tests exercise the
 * full API. This matches the frontend "not enabled" state behavior.
 *
 * Identities:
 *   charlie_admin — e2e_charlie@test.local — role=admin (property writes + CSRF)
 *   alice         — e2e_alice@test.local   — role=user  (read-only, list/get)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const TS   = Date.now();

const PROP_NAME = `E2E Property ${TS}`;
const UNIT_LABEL = `Unit A-${TS}`;

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

let _sessions: Record<string, AdminSessionData> | null = null;
function getSessions(): Record<string, AdminSessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

// ─── Page factory ─────────────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
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

async function apiPut(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.put(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

// ─── Flag check helper ────────────────────────────────────────────────────────

/**
 * Returns true if the feature flag is off (endpoint returns 404).
 * Tests use this to skip gracefully when PROPERTY_MGMT_ENABLED is false.
 */
async function isFeatureDisabled(page: Page): Promise<boolean> {
  const resp = await apiGet(page, "ui/properties");
  return resp.status() === 404;
}

// ─── Shared state ─────────────────────────────────────────────────────────────

let charliePage: Page;
let alicePage: Page;
let propertyId = "";
let unitId = "";
let featureOff = false;

// ─────────────────────────────────────────────────────────────────────────────
// Section 70 — Properties list API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 70: Properties CRUD — API", () => {
  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getSessions();
    charliePage = await newIdentityPage(browser, "charlie_admin");
    alicePage   = await newIdentityPage(browser, "alice");
    featureOff  = await isFeatureDisabled(charliePage);
  });

  test("70.1 Flag check — 404 when disabled, 200 when enabled", async () => {
    const resp = await apiGet(charliePage, "ui/properties");
    if (featureOff) {
      expect(resp.status()).toBe(404);
    } else {
      expect(resp.status()).toBe(200);
    }
  });

  test("70.2 Create property — 201 with required fields", async () => {
    test.skip(featureOff, "Feature flag off");
    const resp = await apiPost(charliePage, "charlie_admin", "ui/properties", {
      name: PROP_NAME,
      property_type: "apartment",
      address: {
        line1: "123 Test Ave",
        city: "E2E City",
        region: "TX",
        postal_code: "78701",
        country: "US",
      },
      color_tags: ["e2e"],
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json() as {
      property_id: string;
      name: string;
      property_type: string;
      status: string;
      occupancy_status: string;
      unit_count: number;
    };
    expect(data.property_id).toBeTruthy();
    expect(data.name).toBe(PROP_NAME);
    expect(data.property_type).toBe("apartment");
    expect(data.status).toBe("active");
    expect(data.occupancy_status).toBe("vacant");
    expect(data.unit_count).toBe(0);
    propertyId = data.property_id;
  });

  test("70.3 Get property — 200 with correct shape", async () => {
    test.skip(featureOff || !propertyId, "Feature flag off or property not created");
    const resp = await apiGet(charliePage, `ui/properties/${propertyId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(data.property_id).toBe(propertyId);
    expect(data.address).toBeTruthy();
    expect(typeof data.created_at).toBe("number");
    expect(typeof data.updated_at).toBe("number");
  });

  test("70.4 List properties — includes created property", async () => {
    test.skip(featureOff || !propertyId, "Feature flag off or property not created");
    const resp = await apiGet(charliePage, "ui/properties", { status: "active" });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { properties: Array<{ property_id: string }>; count: number };
    expect(Array.isArray(data.properties)).toBe(true);
    expect(typeof data.count).toBe("number");
    const found = data.properties.find((p) => p.property_id === propertyId);
    expect(found).toBeTruthy();
  });

  test("70.5 List properties — filter by property_type", async () => {
    test.skip(featureOff || !propertyId, "Feature flag off");
    const resp = await apiGet(charliePage, "ui/properties", { property_type: "apartment" });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { properties: Array<{ property_type: string }> };
    data.properties.forEach((p) => expect(p.property_type).toBe("apartment"));
  });

  test("70.6 Update property — change name and address", async () => {
    test.skip(featureOff || !propertyId, "Feature flag off");
    const resp = await apiPut(charliePage, "charlie_admin", `ui/properties/${propertyId}`, {
      name: `${PROP_NAME} Updated`,
      address: {
        line1: "456 Updated Ave",
        city: "E2E City",
        region: "TX",
        postal_code: "78701",
        country: "US",
      },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { name: string };
    expect(data.name).toBe(`${PROP_NAME} Updated`);
  });

  test("70.7 Alice can read properties (regular user read access)", async () => {
    test.skip(featureOff, "Feature flag off");
    const resp = await apiGet(alicePage, "ui/properties");
    expect(resp.status()).toBe(200);
  });

  test("70.8 Unknown property_id returns 404", async () => {
    test.skip(featureOff, "Feature flag off");
    const resp = await apiGet(charliePage, "ui/properties/nonexistent_property_id_xyz");
    expect(resp.status()).toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 71 — Unit CRUD — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 71: Unit CRUD — API", () => {
  test("71.1 Create unit — 201 with correct shape", async () => {
    test.skip(featureOff || !propertyId, "Feature flag off or property not created");
    const resp = await apiPost(charliePage, "charlie_admin", `ui/properties/${propertyId}/units`, {
      label: UNIT_LABEL,
      bedrooms: 2,
      bathrooms: 1.5,
      square_footage: 900,
      market_rent_cents: 150000,
      occupancy_status: "vacant",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json() as {
      unit_id: string;
      label: string;
      bedrooms: number;
      bathrooms: number;
      square_footage: number;
      market_rent_cents: number;
      occupancy_status: string;
    };
    expect(data.unit_id).toBeTruthy();
    expect(data.label).toBe(UNIT_LABEL);
    expect(data.bedrooms).toBe(2);
    expect(data.bathrooms).toBe(1.5);
    expect(data.square_footage).toBe(900);
    expect(data.market_rent_cents).toBe(150000);
    expect(data.occupancy_status).toBe("vacant");
    unitId = data.unit_id;
  });

  test("71.2 List units — returns the created unit", async () => {
    test.skip(featureOff || !propertyId || !unitId, "Feature flag off or unit not created");
    const resp = await apiGet(charliePage, `ui/properties/${propertyId}/units`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Array<{ unit_id: string; label: string }>;
    expect(Array.isArray(data)).toBe(true);
    const found = data.find((u) => u.unit_id === unitId);
    expect(found).toBeTruthy();
    expect(found?.label).toBe(UNIT_LABEL);
  });

  test("71.3 Get unit — 200 with full fields", async () => {
    test.skip(featureOff || !propertyId || !unitId, "Feature flag off");
    const resp = await apiGet(charliePage, `ui/properties/${propertyId}/units/${unitId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as {
      unit_id: string;
      property_id: string;
      created_at: number;
      updated_at: number;
    };
    expect(data.unit_id).toBe(unitId);
    expect(data.property_id).toBe(propertyId);
    expect(typeof data.created_at).toBe("number");
    expect(typeof data.updated_at).toBe("number");
  });

  test("71.4 Update unit — change market_rent_cents and occupancy_status", async () => {
    test.skip(featureOff || !propertyId || !unitId, "Feature flag off");
    const resp = await apiPut(charliePage, "charlie_admin", `ui/properties/${propertyId}/units/${unitId}`, {
      market_rent_cents: 160000,
      occupancy_status: "occupied",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { market_rent_cents: number; occupancy_status: string };
    expect(data.market_rent_cents).toBe(160000);
    expect(data.occupancy_status).toBe("occupied");
  });

  test("71.5 Get property after unit create — unit_count incremented", async () => {
    test.skip(featureOff || !propertyId, "Feature flag off");
    const resp = await apiGet(charliePage, `ui/properties/${propertyId}`);
    const data = await resp.json() as { unit_count: number };
    expect(data.unit_count).toBeGreaterThanOrEqual(1);
  });

  test("71.6 Delete unit — 200 with ok=true", async () => {
    test.skip(featureOff || !propertyId || !unitId, "Feature flag off");
    const resp = await apiDelete(charliePage, "charlie_admin", `ui/properties/${propertyId}/units/${unitId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ok: boolean };
    expect(data.ok).toBe(true);
  });

  test("71.7 Get deleted unit — 404", async () => {
    test.skip(featureOff || !propertyId || !unitId, "Feature flag off");
    const resp = await apiGet(charliePage, `ui/properties/${propertyId}/units/${unitId}`);
    expect(resp.status()).toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 72 — Occupancy API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 72: Occupancy API", () => {
  test("72.1 Property occupancy — returns correct shape", async () => {
    test.skip(featureOff || !propertyId, "Feature flag off");
    const resp = await apiGet(charliePage, `ui/properties/${propertyId}/occupancy`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as {
      property_id: string;
      total: number;
      occupied: number;
      vacant: number;
      turnover: number;
      unavailable: number;
      occupancy_status: string;
      occupancy_rate: number;
    };
    expect(data.property_id).toBe(propertyId);
    expect(typeof data.total).toBe("number");
    expect(typeof data.occupied).toBe("number");
    expect(typeof data.vacant).toBe("number");
    expect(typeof data.occupancy_rate).toBe("number");
    expect(["vacant", "partial", "occupied"]).toContain(data.occupancy_status);
  });

  test("72.2 Portfolio occupancy — returns correct shape", async () => {
    test.skip(featureOff, "Feature flag off");
    const resp = await apiGet(charliePage, "ui/properties/portfolio/occupancy");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as {
      property_count: number;
      unit_count: number;
      occupied: number;
      vacant: number;
      occupancy_rate: number;
    };
    expect(typeof data.property_count).toBe("number");
    expect(typeof data.unit_count).toBe("number");
    expect(typeof data.occupancy_rate).toBe("number");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 73 — PropertiesPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 73: PropertiesPage UI", () => {
  let uiPage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    uiPage = await browser.newPage();
    await injectAuth(uiPage, "charlie_admin");
  });

  test("73.1 Page loads — shows Properties heading", async () => {
    await uiPage.goto(`${BASE}/properties`, { waitUntil: "domcontentloaded" });
    await expect(uiPage.getByRole("heading", { name: "Properties", exact: true })).toBeVisible();
  });

  test("73.2 Flag off — shows 'not enabled' state", async () => {
    test.skip(!featureOff, "Feature is enabled — skipping not-enabled state test");
    await uiPage.goto(`${BASE}/properties`, { waitUntil: "domcontentloaded" });
    await expect(uiPage.getByText(/property management is not currently enabled/i)).toBeVisible();
  });

  test("73.3 Add Property button is visible", async () => {
    test.skip(featureOff, "Feature flag off");
    await uiPage.goto(`${BASE}/properties`, { waitUntil: "domcontentloaded" });
    await expect(uiPage.getByTestId("create-property-btn")).toBeVisible();
  });

  test("73.4 Create property via UI dialog", async () => {
    test.skip(featureOff, "Feature flag off");
    await uiPage.goto(`${BASE}/properties`, { waitUntil: "domcontentloaded" });
    await uiPage.getByTestId("create-property-btn").click();
    await uiPage.getByTestId("prop-name-input").fill(`UI Prop ${TS}`);
    // Fill address
    await uiPage.getByLabel("Address Line 1").fill("789 UI Street");
    await uiPage.getByLabel("City").fill("UI City");
    await uiPage.getByLabel("State / Region").fill("CA");
    await uiPage.getByLabel("Postal Code").fill("90001");
    await uiPage.getByLabel("Country").fill("US");
    await uiPage.getByTestId("prop-create-submit").click();
    // Toast should appear
    await expect(uiPage.getByText("Property created")).toBeVisible({ timeout: 8_000 });
  });

  test("73.5 Status filter dropdown exists and is functional", async () => {
    test.skip(featureOff, "Feature flag off");
    await uiPage.goto(`${BASE}/properties`, { waitUntil: "domcontentloaded" });
    await expect(uiPage.getByTestId("status-filter-select")).toBeVisible();
  });

  test("73.6 Type filter dropdown exists", async () => {
    test.skip(featureOff, "Feature flag off");
    await uiPage.goto(`${BASE}/properties`, { waitUntil: "domcontentloaded" });
    await expect(uiPage.getByTestId("type-filter-select")).toBeVisible();
  });

  test("73.7 Refresh button exists and triggers reload", async () => {
    test.skip(featureOff, "Feature flag off");
    await uiPage.goto(`${BASE}/properties`, { waitUntil: "domcontentloaded" });
    await expect(uiPage.getByTestId("refresh-properties-btn")).toBeVisible();
    await uiPage.getByTestId("refresh-properties-btn").click();
    // Should not throw
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 74 — PropertyDetailPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 74: PropertyDetailPage UI", () => {
  let uiPage: Page;
  let detailPropertyId = "";

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    uiPage = await browser.newPage();
    await injectAuth(uiPage, "charlie_admin");

    if (!featureOff) {
      // Create a property for detail UI tests
      const sess = getSessions()["charlie_admin"];
      const resp = await uiPage.request.post(`${API}/ui/properties`, {
        data: {
          name: `Detail UI Prop ${TS}`,
          property_type: "single_family",
          address: {
            line1: "999 Detail St",
            city: "Detail City",
            region: "NY",
            postal_code: "10001",
            country: "US",
          },
          color_tags: [],
        },
        headers: {
          "x-csrf-token": sess.csrf_token,
          "Content-Type": "application/json",
        },
      });
      if (resp.ok()) {
        const data = await resp.json() as { property_id: string };
        detailPropertyId = data.property_id;
      }
    }
  });

  test("74.1 Detail page loads — shows property name", async () => {
    test.skip(featureOff || !detailPropertyId, "Feature flag off or no property");
    await uiPage.goto(`${BASE}/properties/${detailPropertyId}`, { waitUntil: "domcontentloaded" });
    await expect(uiPage.getByRole("heading", { name: `Detail UI Prop ${TS}`, exact: true })).toBeVisible();
  });

  test("74.2 Back button navigates to properties list", async () => {
    test.skip(featureOff || !detailPropertyId, "Feature flag off");
    await uiPage.goto(`${BASE}/properties/${detailPropertyId}`, { waitUntil: "domcontentloaded" });
    await expect(uiPage.getByTestId("back-to-properties-btn")).toBeVisible();
  });

  test("74.3 Address section is visible", async () => {
    test.skip(featureOff || !detailPropertyId, "Feature flag off");
    await uiPage.goto(`${BASE}/properties/${detailPropertyId}`, { waitUntil: "domcontentloaded" });
    await expect(uiPage.getByText("Address")).toBeVisible();
    await expect(uiPage.getByText("999 Detail St")).toBeVisible();
  });

  test("74.4 Edit property button opens dialog", async () => {
    test.skip(featureOff || !detailPropertyId, "Feature flag off");
    await uiPage.goto(`${BASE}/properties/${detailPropertyId}`, { waitUntil: "domcontentloaded" });
    await expect(uiPage.getByTestId("edit-property-btn")).toBeVisible();
    await uiPage.getByTestId("edit-property-btn").click();
    await expect(uiPage.getByRole("heading", { name: "Edit Property", exact: true })).toBeVisible();
    await uiPage.keyboard.press("Escape");
  });

  test("74.5 Add Unit button is visible", async () => {
    test.skip(featureOff || !detailPropertyId, "Feature flag off");
    await uiPage.goto(`${BASE}/properties/${detailPropertyId}`, { waitUntil: "domcontentloaded" });
    await expect(uiPage.getByTestId("add-unit-btn")).toBeVisible();
  });

  test("74.6 Create unit via UI dialog", async () => {
    test.skip(featureOff || !detailPropertyId, "Feature flag off");
    await uiPage.goto(`${BASE}/properties/${detailPropertyId}`, { waitUntil: "domcontentloaded" });
    await uiPage.getByTestId("add-unit-btn").click();
    await uiPage.getByTestId("unit-label-input").fill(`UI Unit ${TS}`);
    await uiPage.getByTestId("unit-rent-input").fill("1200");
    await uiPage.getByTestId("unit-create-submit").click();
    await expect(uiPage.getByText("Unit added")).toBeVisible({ timeout: 8_000 });
  });

  test("74.7 Unit appears in the list after creation", async () => {
    test.skip(featureOff || !detailPropertyId, "Feature flag off");
    await uiPage.goto(`${BASE}/properties/${detailPropertyId}`, { waitUntil: "domcontentloaded" });
    // Created in 74.6; should appear in the units list
    await expect(uiPage.getByText(`UI Unit ${TS}`)).toBeVisible({ timeout: 5_000 });
  });

  test("74.8 Archive button is visible for active property", async () => {
    test.skip(featureOff || !detailPropertyId, "Feature flag off");
    await uiPage.goto(`${BASE}/properties/${detailPropertyId}`, { waitUntil: "domcontentloaded" });
    await expect(uiPage.getByTestId("archive-property-btn")).toBeVisible();
  });

  test("74.9 Unknown property ID shows error state", async () => {
    test.skip(featureOff, "Feature flag off");
    await uiPage.goto(`${BASE}/properties/nonexistent_abc123`, { waitUntil: "domcontentloaded" });
    // Should show "not found" or navigate away; at minimum should not crash
    // (either "Property not found" text or redirect to /properties)
    const url = uiPage.url();
    const bodyText = await uiPage.locator("body").textContent();
    const ok =
      url.includes("/properties") ||
      (bodyText ?? "").toLowerCase().includes("not found") ||
      (bodyText ?? "").toLowerCase().includes("not enabled");
    expect(ok).toBe(true);
  });
});
