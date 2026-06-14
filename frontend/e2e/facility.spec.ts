/**
 * E2E tests for the OFBiz FACILITY / FULFILLMENT (FAC) cluster.
 *
 * Sections:
 *   80 — Facility CRUD + locations — API
 *   81 — Fulfillment: transfers lifecycle — API
 *   82 — FacilitiesPage UI
 *   83 — FulfillmentPage UI (tabs + lookups)
 *
 * Auth: uses e2e_admin_session_setup.py (all identities).
 *
 * NOTE: The FAC cluster is gated behind the backend flag
 * `facility_fulfillment_enabled`. When OFF every /ui/facilities + /ui/fulfillment
 * endpoint returns 404 and the pages render a "not enabled" card. These tests
 * tolerate both states (enabled → exercise flows; disabled → assert graceful
 * fallback) so they pass regardless of the flag.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ROOT = "root.admin@testdev.local";
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

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getSessions()[identity];
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
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

/** True when the FAC flag is off (endpoints 404). */
function disabled(status: number): boolean {
  return status === 404 || status === 503;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 80 — Facility CRUD + locations — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 80: Facility CRUD + locations (API)", () => {
  let rootPage: Page;
  let facilityId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test("80.1 list facilities (active)", async () => {
    const res = await apiGet(rootPage, "ui/facilities", { status: "active" });
    expect([200, 404]).toContain(res.status());
    if (res.status() === 200) {
      const body = await res.json();
      expect(Array.isArray(body.facilities)).toBe(true);
    }
  });

  test("80.2 create facility", async () => {
    const res = await apiPost(rootPage, "root", "ui/facilities", {
      name: `E2E Facility ${TS}`,
      facility_type: "warehouse",
      description: "created by e2e",
    });
    if (disabled(res.status())) {
      test.skip(true, "FAC flag disabled");
      return;
    }
    expect(res.status()).toBe(201);
    const body = await res.json();
    expect(body.facility_id).toBeTruthy();
    expect(body.name).toBe(`E2E Facility ${TS}`);
    expect(body.status).toBe("active");
    facilityId = body.facility_id;
  });

  test("80.3 get facility", async () => {
    test.skip(!facilityId, "no facility created");
    const res = await apiGet(rootPage, `ui/facilities/${encodeURIComponent(facilityId)}`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.facility_id).toBe(facilityId);
  });

  test("80.4 add a location", async () => {
    test.skip(!facilityId, "no facility created");
    const res = await apiPost(
      rootPage,
      "root",
      `ui/facilities/${encodeURIComponent(facilityId)}/locations`,
      { name: `Aisle ${TS}`, location_type: "aisle" },
    );
    expect(res.status()).toBe(201);
    const body = await res.json();
    expect(body.location_id).toBeTruthy();
    expect(body.name).toBe(`Aisle ${TS}`);
  });

  test("80.5 list locations", async () => {
    test.skip(!facilityId, "no facility created");
    const res = await apiGet(
      rootPage,
      `ui/facilities/${encodeURIComponent(facilityId)}/locations`,
    );
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body.locations)).toBe(true);
    expect(body.locations.length).toBeGreaterThanOrEqual(1);
  });

  test("80.6 archive facility", async () => {
    test.skip(!facilityId, "no facility created");
    const res = await apiDelete(rootPage, "root", `ui/facilities/${encodeURIComponent(facilityId)}`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.status).toBe("archived");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 81 — Fulfillment: transfers lifecycle — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 81: Transfers lifecycle (API)", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test("81.1 list transfers (requested)", async () => {
    const res = await apiGet(rootPage, "ui/fulfillment/transfers", { status: "requested" });
    expect([200, 404]).toContain(res.status());
    if (res.status() === 200) {
      const body = await res.json();
      expect(Array.isArray(body.transfers)).toBe(true);
    }
  });

  test("81.2 get non-existent transfer returns 404/422", async () => {
    const res = await apiGet(rootPage, "ui/fulfillment/transfers/does-not-exist");
    expect([400, 404, 422]).toContain(res.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 82 — FacilitiesPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 82: FacilitiesPage UI", () => {
  test("82.1 page renders heading", async ({ page }) => {
    await injectAuth(page, "root");
    await page.goto(`${BASE}/ofbiz/facilities`, { waitUntil: "domcontentloaded" });
    await expect(
      page.getByRole("heading", { name: "Facilities", exact: true }),
    ).toBeVisible({ timeout: 15_000 });
  });

  test("82.2 shows facilities table or not-enabled card", async ({ page }) => {
    await injectAuth(page, "root");
    await page.goto(`${BASE}/ofbiz/facilities`, { waitUntil: "domcontentloaded" });
    const enabled = page.getByText("All facilities");
    const off = page.getByText("is not enabled");
    await expect(enabled.or(off).first()).toBeVisible({ timeout: 15_000 });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 83 — FulfillmentPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 83: FulfillmentPage UI", () => {
  test("83.1 page renders heading + tabs", async ({ page }) => {
    await injectAuth(page, "root");
    await page.goto(`${BASE}/ofbiz/fulfillment`, { waitUntil: "domcontentloaded" });
    await expect(
      page.getByRole("heading", { name: "Fulfillment", exact: true }),
    ).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("tab", { name: /Transfers/ })).toBeVisible();
    await expect(page.getByRole("tab", { name: /Pick/ })).toBeVisible();
    await expect(page.getByRole("tab", { name: /Shipments/ })).toBeVisible();
  });

  test("83.2 pick & pack tab shows lookup form", async ({ page }) => {
    await injectAuth(page, "root");
    await page.goto(`${BASE}/ofbiz/fulfillment`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: /Pick/ }).click();
    const lookup = page.getByText("Look up picklist");
    const off = page.getByText("is not enabled");
    await expect(lookup.or(off).first()).toBeVisible({ timeout: 15_000 });
  });

  test("83.3 shipments tab shows lookup form", async ({ page }) => {
    await injectAuth(page, "root");
    await page.goto(`${BASE}/ofbiz/fulfillment`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: /Shipments/ }).click();
    const lookup = page.getByText("Look up shipment");
    const off = page.getByText("is not enabled");
    await expect(lookup.or(off).first()).toBeVisible({ timeout: 15_000 });
  });
});
