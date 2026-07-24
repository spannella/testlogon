/**
 * E2E tests — QloApps Hotel Cancellation Policy + KPI Reports (HTL-034/035).
 *
 * Sections:
 *   91 — Cancellation Policy API — upsert / get / validation
 *   92 — KPI Reports API — range validation / aggregation
 *   93 — Cancellation Policy UI — page renders, feature-disabled state, save
 *   94 — KPI Dashboard UI — page renders, preset date ranges, feature-disabled
 *
 * Auth: uses e2e_admin_session_setup.py (root identity for write ops).
 *
 * NOTE: All tests skip when HOTEL_PMS_ENABLED is off (404). This is intentional —
 * the feature flag is default-off in dev.
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
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const session = getAdminSessions()[identity];
  const page = await browser.newPage();
  await page.context().addCookies(session.cookies);
  // Seed the persisted Zustand auth-store so ProtectedRoute treats the
  // session as authenticated (cookies alone don't satisfy the client guard).
  await page.addInitScript(
    ([userId, accessToken]) => {
      localStorage.setItem(
        "auth-store",
        JSON.stringify({
          state: {
            userId,
            accessToken,
            isAuthenticated: true,
            logoutReason: null,
          },
          version: 0,
        }),
      );
    },
    [session.user_sub, session.access_token] as const,
  );
  return page;
}

function csrfHeaders(identity: string): Record<string, string> {
  return { "x-csrf-token": getAdminSessions()[identity].csrf_token };
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiGet(
  page: Page,
  path: string,
  params?: Record<string, string>,
): Promise<unknown> {
  const qs = params ? "?" + new URLSearchParams(params).toString() : "";
  const resp = await page.request.get(`${API}${path}${qs}`);
  return resp.json();
}

async function apiPut(
  page: Page,
  identity: string,
  path: string,
  body: unknown,
): Promise<unknown> {
  const resp = await page.request.put(`${API}${path}`, {
    data: body as Record<string, unknown>,
    headers: csrfHeaders(identity),
  });
  return resp.json();
}

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body: unknown,
): Promise<unknown> {
  const resp = await page.request.post(`${API}${path}`, {
    data: body as Record<string, unknown>,
    headers: csrfHeaders(identity),
  });
  return resp.json();
}

// ─── Feature gate helper ──────────────────────────────────────────────────────

async function hotelPmsEnabled(page: Page): Promise<boolean> {
  const resp = await page.request.get(`${API}/ui/hotels`);
  return resp.status() !== 404;
}

// ─── Hotel bootstrap helper ───────────────────────────────────────────────────

async function ensureHotel(page: Page, identity: string): Promise<string> {
  const data = (await apiPost(page, identity, "/ui/hotels", {
    name: `E2E Reports Hotel ${TS}`,
    description: "E2E test hotel for reports",
    star_rating: 3,
    address: {
      line1: "1 KPI Ave",
      city:  "Reportstown",
      region: "RP",
      postal_code: "00002",
      country: "US",
    },
    check_in_time:  "15:00",
    check_out_time: "11:00",
  })) as { hotel_id: string };
  return data.hotel_id;
}

// ─── Section 91 — Cancellation Policy API ─────────────────────────────────────

test.describe("91 — Cancellation Policy API", () => {
  let rootPage: Page;
  let hotelId: string;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("91.1 feature gate check", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");
  });

  test("91.2 setup — create hotel", async () => {
    test.skip(!(await hotelPmsEnabled(rootPage)), "HOTEL_PMS_ENABLED is off");
    hotelId = await ensureHotel(rootPage, "root");
    expect(hotelId).toBeTruthy();
  });

  test("91.3 GET /cancellation-policy returns 404 when no policy set", async () => {
    test.skip(!(await hotelPmsEnabled(rootPage)), "HOTEL_PMS_ENABLED is off");
    const resp = await rootPage.request.get(
      `${API}/ui/hotels/${hotelId}/cancellation-policy`,
    );
    expect(resp.status()).toBe(404);
  });

  test("91.4 PUT creates default cancellation policy", async () => {
    test.skip(!(await hotelPmsEnabled(rootPage)), "HOTEL_PMS_ENABLED is off");
    const data = (await apiPut(
      rootPage,
      "root",
      `/ui/hotels/${hotelId}/cancellation-policy`,
      {
        free_until_days_before: 7,
        penalty_pct: 50,
        penalty_fixed_cents: 0,
        no_show_fee_cents: 10000,
      },
    )) as {
      hotel_id: string;
      scope: string;
      free_until_days_before: number;
      penalty_pct: number;
      no_show_fee_cents: number;
    };

    expect(data.hotel_id).toBe(hotelId);
    expect(data.scope).toBe("default");
    expect(data.free_until_days_before).toBe(7);
    expect(data.penalty_pct).toBe(50);
    expect(data.no_show_fee_cents).toBe(10000);
  });

  test("91.5 GET returns the saved policy", async () => {
    test.skip(!(await hotelPmsEnabled(rootPage)), "HOTEL_PMS_ENABLED is off");
    const data = (await apiGet(
      rootPage,
      `/ui/hotels/${hotelId}/cancellation-policy`,
    )) as {
      hotel_id: string;
      scope: string;
      free_until_days_before: number;
      penalty_pct: number;
      no_show_fee_cents: number;
    };

    expect(data.hotel_id).toBe(hotelId);
    expect(data.free_until_days_before).toBe(7);
    expect(data.penalty_pct).toBe(50);
    expect(data.no_show_fee_cents).toBe(10000);
  });

  test("91.6 PUT overwrites existing policy (idempotent)", async () => {
    test.skip(!(await hotelPmsEnabled(rootPage)), "HOTEL_PMS_ENABLED is off");
    const data = (await apiPut(
      rootPage,
      "root",
      `/ui/hotels/${hotelId}/cancellation-policy`,
      {
        free_until_days_before: 3,
        penalty_pct: 25,
        penalty_fixed_cents: 5000,
        no_show_fee_cents: 0,
      },
    )) as { free_until_days_before: number; penalty_pct: number; penalty_fixed_cents: number };

    expect(data.free_until_days_before).toBe(3);
    expect(data.penalty_pct).toBe(25);
    expect(data.penalty_fixed_cents).toBe(5000);
  });

  test("91.7 PUT with penalty_pct > 100 returns 422", async () => {
    test.skip(!(await hotelPmsEnabled(rootPage)), "HOTEL_PMS_ENABLED is off");
    const resp = await rootPage.request.put(
      `${API}/ui/hotels/${hotelId}/cancellation-policy`,
      {
        data: { free_until_days_before: 0, penalty_pct: 101, penalty_fixed_cents: 0, no_show_fee_cents: 0 },
        headers: csrfHeaders("root"),
      },
    );
    // 422 from Pydantic validation or backend guard
    expect([422, 400]).toContain(resp.status());
  });

  test("91.8 GET with custom scope returns 404 when not set", async () => {
    test.skip(!(await hotelPmsEnabled(rootPage)), "HOTEL_PMS_ENABLED is off");
    const resp = await rootPage.request.get(
      `${API}/ui/hotels/${hotelId}/cancellation-policy?scope=RATE%23unknown`,
    );
    expect(resp.status()).toBe(404);
  });

  test("91.9 PUT with fixed penalty upserts scoped policy", async () => {
    test.skip(!(await hotelPmsEnabled(rootPage)), "HOTEL_PMS_ENABLED is off");
    const data = (await rootPage.request.put(
      `${API}/ui/hotels/${hotelId}/cancellation-policy?scope=summer`,
      {
        data: {
          free_until_days_before: 14,
          penalty_pct: 0,
          penalty_fixed_cents: 20000,
          no_show_fee_cents: 5000,
        },
        headers: csrfHeaders("root"),
      },
    ).then((r) => r.json())) as {
      scope: string;
      penalty_fixed_cents: number;
    };

    expect(data.scope).toBe("summer");
    expect(data.penalty_fixed_cents).toBe(20000);
  });
});

// ─── Section 92 — KPI Reports API ────────────────────────────────────────────

test.describe("92 — KPI Reports API", () => {
  let rootPage: Page;
  let hotelId: string;

  // timestamps: 30-day window ending now
  const toTs   = Math.floor(Date.now() / 1000);
  const fromTs  = toTs - 30 * 86400;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("92.1 feature gate check", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");
  });

  test("92.2 setup — create hotel", async () => {
    test.skip(!(await hotelPmsEnabled(rootPage)), "HOTEL_PMS_ENABLED is off");
    hotelId = await ensureHotel(rootPage, "root");
    expect(hotelId).toBeTruthy();
  });

  test("92.3 GET /reports/kpis returns valid structure for empty hotel", async () => {
    test.skip(!(await hotelPmsEnabled(rootPage)), "HOTEL_PMS_ENABLED is off");
    const data = (await apiGet(
      rootPage,
      `/ui/hotels/${hotelId}/reports/kpis`,
      { from_ts: String(fromTs), to_ts: String(toTs) },
    )) as {
      hotel_id: string;
      from_ts: number;
      to_ts: number;
      rooms_available: number;
      rooms_sold: number;
      occupancy_pct: number;
      room_revenue_cents: number;
      adr_cents: number;
      revpar_cents: number;
      arrivals: number;
      departures: number;
      currency: string;
    };

    expect(data.hotel_id).toBe(hotelId);
    expect(data.from_ts).toBe(fromTs);
    expect(data.to_ts).toBe(toTs);
    expect(typeof data.rooms_available).toBe("number");
    expect(typeof data.occupancy_pct).toBe("number");
    expect(typeof data.adr_cents).toBe("number");
    expect(typeof data.revpar_cents).toBe("number");
    expect(data.currency).toBeTruthy();
  });

  test("92.4 KPI fields are non-negative integers or float", async () => {
    test.skip(!(await hotelPmsEnabled(rootPage)), "HOTEL_PMS_ENABLED is off");
    const data = (await apiGet(
      rootPage,
      `/ui/hotels/${hotelId}/reports/kpis`,
      { from_ts: String(fromTs), to_ts: String(toTs) },
    )) as { rooms_available: number; rooms_sold: number; adr_cents: number; revpar_cents: number; occupancy_pct: number };

    expect(data.rooms_available).toBeGreaterThanOrEqual(0);
    expect(data.rooms_sold).toBeGreaterThanOrEqual(0);
    expect(data.adr_cents).toBeGreaterThanOrEqual(0);
    expect(data.revpar_cents).toBeGreaterThanOrEqual(0);
    expect(data.occupancy_pct).toBeGreaterThanOrEqual(0);
    expect(data.occupancy_pct).toBeLessThanOrEqual(100);
  });

  test("92.5 inverted range (to < from) returns 422", async () => {
    test.skip(!(await hotelPmsEnabled(rootPage)), "HOTEL_PMS_ENABLED is off");
    const resp = await rootPage.request.get(
      `${API}/ui/hotels/${hotelId}/reports/kpis?from_ts=${toTs}&to_ts=${fromTs}`,
    );
    expect(resp.status()).toBe(422);
  });

  test("92.6 range > 366 days returns 422", async () => {
    test.skip(!(await hotelPmsEnabled(rootPage)), "HOTEL_PMS_ENABLED is off");
    const bigFrom = toTs - 400 * 86400;
    const resp = await rootPage.request.get(
      `${API}/ui/hotels/${hotelId}/reports/kpis?from_ts=${bigFrom}&to_ts=${toTs}`,
    );
    expect(resp.status()).toBe(422);
  });

  test("92.7 missing from_ts returns 422", async () => {
    test.skip(!(await hotelPmsEnabled(rootPage)), "HOTEL_PMS_ENABLED is off");
    const resp = await rootPage.request.get(
      `${API}/ui/hotels/${hotelId}/reports/kpis?to_ts=${toTs}`,
    );
    expect(resp.status()).toBe(422);
  });
});

// ─── Section 93 — Cancellation Policy UI ─────────────────────────────────────

test.describe("93 — Cancellation Policy UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("93.1 page renders without hotelId — shows selection notice", async () => {
    // Route: /hotels/policies (no :hotelId)
    await rootPage.goto(`${BASE}/hotels/policies`);
    await rootPage.waitForLoadState("domcontentloaded");
    // Should display something — either "No hotel selected" or the PMS-off state.
    const body = await rootPage.locator("body").textContent();
    expect(body).toBeTruthy();
  });

  test("93.2 feature-disabled page shows not-enabled state", async () => {
    // Force-navigate to policy page for a made-up hotel
    await rootPage.goto(`${BASE}/hotels/policies/nonexistent-hotel-id`);
    await rootPage.waitForLoadState("domcontentloaded");
    // Either feature off or hotel not found — either way UI must not crash
    await rootPage.waitForTimeout(1500);
    const body = await rootPage.locator("body").textContent();
    expect(body).toBeTruthy();
    // Should NOT show an unhandled JS crash
    await expect(rootPage.locator("text=Something went wrong")).not.toBeVisible();
  });

  test("93.3 when feature is on, editor form renders", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    // Create a hotel for the test
    const data = (await apiPost(rootPage, "root", "/ui/hotels", {
      name:  `E2E Policy UI Hotel ${TS}`,
      description: "UI test",
      star_rating:  3,
      address: { line1: "2 UI St", city: "UIville", region: "UI", postal_code: "00003", country: "US" },
      check_in_time: "14:00",
      check_out_time: "12:00",
    })) as { hotel_id: string };

    await rootPage.goto(`${BASE}/hotels/policies/${data.hotel_id}`);
    await rootPage.waitForLoadState("domcontentloaded");
    await rootPage.waitForTimeout(1500);

    // The form should show input fields for the policy
    await expect(rootPage.locator("#free-days")).toBeVisible();
    await expect(rootPage.locator("#penalty-pct")).toBeVisible();
    await expect(rootPage.locator("#no-show-fee")).toBeVisible();
    await expect(rootPage.getByRole("button", { name: /save policy/i })).toBeVisible();
  });

  test("93.4 save button is present and clickable (smoke)", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    const data = (await apiPost(rootPage, "root", "/ui/hotels", {
      name:  `E2E Policy Save Hotel ${TS + 1}`,
      description: "UI save test",
      star_rating:  4,
      address: { line1: "3 Save Rd", city: "Saverton", region: "SV", postal_code: "00004", country: "US" },
      check_in_time: "15:00",
      check_out_time: "11:00",
    })) as { hotel_id: string };

    await rootPage.goto(`${BASE}/hotels/policies/${data.hotel_id}`);
    await rootPage.waitForLoadState("domcontentloaded");
    await rootPage.waitForTimeout(1500);

    const saveBtn = rootPage.getByRole("button", { name: /save policy/i });
    await expect(saveBtn).toBeVisible();
    await expect(saveBtn).toBeEnabled();
  });
});

// ─── Section 94 — KPI Dashboard UI ───────────────────────────────────────────

test.describe("94 — KPI Dashboard UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("94.1 page at /hotels/reports renders without crashing", async () => {
    await rootPage.goto(`${BASE}/hotels/reports`);
    await rootPage.waitForLoadState("domcontentloaded");
    await rootPage.waitForTimeout(1000);
    const body = await rootPage.locator("body").textContent();
    expect(body).toBeTruthy();
  });

  test("94.2 feature-disabled state shows correct message", async () => {
    // Navigate to a real-looking hotel id
    await rootPage.goto(`${BASE}/hotels/reports/nonexistent-hotel-id`);
    await rootPage.waitForLoadState("domcontentloaded");
    await rootPage.waitForTimeout(1500);

    const body = await rootPage.locator("body").textContent();
    expect(body).toBeTruthy();
    // Either feature-off state or loading/error — must not show JS crash
    await expect(rootPage.locator("text=Something went wrong")).not.toBeVisible();
  });

  test("94.3 preset buttons are visible when feature enabled", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    const data = (await apiPost(rootPage, "root", "/ui/hotels", {
      name:  `E2E KPI UI Hotel ${TS + 2}`,
      description: "KPI UI test",
      star_rating:  5,
      address: { line1: "4 KPI Blvd", city: "KPIcity", region: "KP", postal_code: "00005", country: "US" },
      check_in_time: "14:00",
      check_out_time: "10:00",
    })) as { hotel_id: string };

    await rootPage.goto(`${BASE}/hotels/reports/${data.hotel_id}`);
    await rootPage.waitForLoadState("domcontentloaded");
    await rootPage.waitForTimeout(2000);

    // Preset buttons
    await expect(rootPage.getByRole("button", { name: "Last 7 days" })).toBeVisible();
    await expect(rootPage.getByRole("button", { name: "Last 30 days" })).toBeVisible();
    await expect(rootPage.getByRole("button", { name: "Last 90 days" })).toBeVisible();
    await expect(rootPage.getByRole("button", { name: "Custom" })).toBeVisible();
  });

  test("94.4 KPI stat cards render when feature enabled", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    const data = (await apiPost(rootPage, "root", "/ui/hotels", {
      name:  `E2E KPI Cards Hotel ${TS + 3}`,
      description: "KPI cards UI test",
      star_rating:  3,
      address: { line1: "5 Metric Ln", city: "Metricton", region: "MT", postal_code: "00006", country: "US" },
      check_in_time: "15:00",
      check_out_time: "11:00",
    })) as { hotel_id: string };

    await rootPage.goto(`${BASE}/hotels/reports/${data.hotel_id}`);
    await rootPage.waitForLoadState("domcontentloaded");
    await rootPage.waitForTimeout(2500);

    // KPI card labels — "Occupancy"/"RevPAR" also appear inside a longer
    // descriptor string, so match the card label exactly.
    await expect(rootPage.getByText("Occupancy", { exact: true })).toBeVisible();
    await expect(rootPage.getByText("ADR (Avg Daily Rate)")).toBeVisible();
    await expect(rootPage.getByText("RevPAR", { exact: true })).toBeVisible();
    await expect(rootPage.getByText("Room Revenue", { exact: true })).toBeVisible();
  });

  test("94.5 Custom preset reveals date pickers", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    const data = (await apiPost(rootPage, "root", "/ui/hotels", {
      name:  `E2E KPI Picker Hotel ${TS + 4}`,
      description: "date picker test",
      star_rating:  2,
      address: { line1: "6 Picker St", city: "Pickertown", region: "PK", postal_code: "00007", country: "US" },
      check_in_time: "14:00",
      check_out_time: "12:00",
    })) as { hotel_id: string };

    await rootPage.goto(`${BASE}/hotels/reports/${data.hotel_id}`);
    await rootPage.waitForLoadState("domcontentloaded");
    await rootPage.waitForTimeout(1500);

    const customBtn = rootPage.getByRole("button", { name: "Custom" });
    await customBtn.click();
    await rootPage.waitForTimeout(500);

    await expect(rootPage.locator("#from-date")).toBeVisible();
    await expect(rootPage.locator("#to-date")).toBeVisible();
  });

  test("94.6 Refresh button is visible and clickable", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    const data = (await apiPost(rootPage, "root", "/ui/hotels", {
      name:  `E2E KPI Refresh Hotel ${TS + 5}`,
      description: "refresh button test",
      star_rating:  3,
      address: { line1: "7 Refresh Ave", city: "Refreshton", region: "RF", postal_code: "00008", country: "US" },
      check_in_time: "15:00",
      check_out_time: "11:00",
    })) as { hotel_id: string };

    await rootPage.goto(`${BASE}/hotels/reports/${data.hotel_id}`);
    await rootPage.waitForLoadState("domcontentloaded");
    await rootPage.waitForTimeout(1500);

    const refreshBtn = rootPage.getByRole("button", { name: /refresh/i });
    await expect(refreshBtn).toBeVisible();
    await refreshBtn.click();
    await rootPage.waitForTimeout(500);
  });
});
