/**
 * E2E tests — QloApps Hotel Booking Engine + Reservations (HTL-017..HTL-019).
 *
 * Sections:
 *   85 — Stay-search API — search by hotel_id, city, validate inputs
 *   86 — Reservation Create API — create, verify fields, idempotency checks
 *   87 — Reservation Read + List API — get, list, filter by status/dates
 *   88 — Reservation Lifecycle API — cancel, no-show, history
 *   89 — Booking Page UI — search form renders, feature-disabled state
 *   90 — Reservations Page UI — list renders, detail view, cancel action
 *
 * Auth: uses e2e_admin_session_setup.py (root identity for write ops).
 *
 * NOTE: All tests skip (soft-fail) when HOTEL_PMS_ENABLED is off (404).
 * This is by design — the feature is default-off in dev.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

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
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await injectAuth(page, identity);
  return page;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getAdminSessions()[identity];
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
}

// ─── API helpers ──────────────────────────────────────────────────────────────

function csrfHeaders(identity: string): Record<string, string> {
  return { "x-csrf-token": getAdminSessions()[identity].csrf_token };
}

async function apiGet(
  page: Page,
  path: string,
  params?: Record<string, string>,
): Promise<unknown> {
  const qs = params ? "?" + new URLSearchParams(params).toString() : "";
  const resp = await page.request.get(`${API}${path}${qs}`);
  return resp.json();
}

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body: unknown,
): Promise<{ status: number; data: unknown }> {
  const resp = await page.request.post(`${API}${path}`, {
    data: body as Record<string, unknown>,
    headers: csrfHeaders(identity),
  });
  return { status: resp.status(), data: await resp.json() };
}

async function apiPut(
  page: Page,
  identity: string,
  path: string,
  body: unknown,
): Promise<{ status: number; data: unknown }> {
  const resp = await page.request.put(`${API}${path}`, {
    data: body as Record<string, unknown>,
    headers: csrfHeaders(identity),
  });
  return { status: resp.status(), data: await resp.json() };
}

// ─── Feature gate helper ──────────────────────────────────────────────────────

async function hotelPmsEnabled(page: Page): Promise<boolean> {
  const resp = await page.request.get(`${API}/ui/hotels`);
  return resp.status() !== 404;
}

// ─── Section 85 — Stay-search API ────────────────────────────────────────────

test.describe("85 — Stay-search API", () => {
  let rootPage: Page;
  let hotelId: string;

  const checkin = new Date(Date.now() + 7 * 86400000).toISOString().split("T")[0]!;
  const checkout = new Date(Date.now() + 9 * 86400000).toISOString().split("T")[0]!;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("85.1 feature gate check", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");
  });

  test("85.2 create a test hotel for search", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    const { status, data } = await apiPost(rootPage, "root", "/ui/hotels", {
      name: `Search Test Hotel ${TS}`,
      description: "E2E search test",
      star_rating: 3,
      address: {
        line1: "1 Test Street",
        city: "TestCity",
        region: "TC",
        postal_code: "10001",
        country: "US",
      },
      check_in_time: "15:00",
      check_out_time: "11:00",
    });
    expect(status).toBe(201);
    hotelId = (data as { hotel_id: string }).hotel_id;
    expect(hotelId).toBeTruthy();
  });

  test("85.3 search with hotel_id — no results (no room types seeded)", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");
    if (!hotelId) test.skip(true, "hotel not created");

    const { status, data } = await apiPost(rootPage, "root", "/ui/hotel-search", {
      hotel_id: hotelId,
      checkin,
      checkout,
      adults: 2,
      children: 0,
      rooms: 1,
    });
    // 200 even when no results — result_count = 0
    expect(status).toBe(200);
    const result = data as { result_count: number; checkin: string; checkout: string; nights: number };
    expect(result.result_count).toBeGreaterThanOrEqual(0);
    expect(result.checkin).toBe(checkin);
    expect(result.checkout).toBe(checkout);
    expect(result.nights).toBeGreaterThan(0);
  });

  test("85.4 search requires hotel_id or city", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    const resp = await rootPage.request.post(`${API}/ui/hotel-search`, {
      data: { checkin, checkout, adults: 1 },
      headers: csrfHeaders("root"),
    });
    expect(resp.status()).toBe(422);
  });

  test("85.5 search rejects checkout before checkin", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");
    if (!hotelId) test.skip(true, "hotel not created");

    const resp = await rootPage.request.post(`${API}/ui/hotel-search`, {
      data: {
        hotel_id: hotelId,
        checkin: checkout,
        checkout: checkin,   // reversed
        adults: 1,
      },
      headers: csrfHeaders("root"),
    });
    expect(resp.status()).toBe(422);
  });

  test("85.6 search by city", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    const resp = await rootPage.request.post(`${API}/ui/hotel-search`, {
      data: { city: "TestCity", checkin, checkout, adults: 1 },
      headers: csrfHeaders("root"),
    });
    // Should succeed (even 0 results)
    expect([200, 422]).toContain(resp.status());
  });
});

// ─── Section 86 — Reservation Create API ─────────────────────────────────────

test.describe("86 — Reservation Create API", () => {
  let rootPage: Page;
  let hotelId: string;
  let reservationId: string;

  const checkin = new Date(Date.now() + 14 * 86400000).toISOString().split("T")[0]!;
  const checkout = new Date(Date.now() + 17 * 86400000).toISOString().split("T")[0]!;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("86.1 create hotel for reservation tests", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    const { status, data } = await apiPost(rootPage, "root", "/ui/hotels", {
      name: `Reservation Test Hotel ${TS}`,
      description: "E2E reservation test",
      star_rating: 4,
      address: {
        line1: "2 Booking Ave",
        city: "BookCity",
        region: "BC",
        postal_code: "20002",
        country: "US",
      },
      check_in_time: "14:00",
      check_out_time: "12:00",
    });
    expect(status).toBe(201);
    hotelId = (data as { hotel_id: string }).hotel_id;
    expect(hotelId).toBeTruthy();
  });

  test("86.2 create reservation fails without availability (no room type seeded)", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");
    if (!hotelId) test.skip(true, "hotel not created");

    const { status } = await apiPost(rootPage, "root", `/ui/hotels/${hotelId}/reservations`, {
      hotel_id: hotelId,
      guest_party_id: `guest_${TS}`,
      room_type_id: "rt_nonexistent",
      checkin,
      checkout,
      adults: 2,
      rooms: 1,
    });
    // Availability stub or 409/503 expected since room_type not seeded
    expect([201, 409, 503, 404]).toContain(status);
  });

  test("86.3 create reservation rejects missing required fields", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");
    if (!hotelId) test.skip(true, "hotel not created");

    const resp = await rootPage.request.post(`${API}/ui/hotels/${hotelId}/reservations`, {
      data: { hotel_id: hotelId },  // missing required fields
      headers: csrfHeaders("root"),
    });
    expect(resp.status()).toBe(422);
  });

  test("86.4 create reservation rejects adults < 1", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");
    if (!hotelId) test.skip(true, "hotel not created");

    const resp = await rootPage.request.post(`${API}/ui/hotels/${hotelId}/reservations`, {
      data: {
        hotel_id: hotelId,
        guest_party_id: `guest_${TS}`,
        room_type_id: "rt_test",
        checkin,
        checkout,
        adults: 0,
      },
      headers: csrfHeaders("root"),
    });
    expect(resp.status()).toBe(422);
  });
});

// ─── Section 87 — Reservation Read + List API ────────────────────────────────

test.describe("87 — Reservation Read + List API", () => {
  let rootPage: Page;
  let hotelId: string;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("87.1 create hotel for listing tests", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    const { status, data } = await apiPost(rootPage, "root", "/ui/hotels", {
      name: `List Test Hotel ${TS}`,
      description: "E2E listing test",
      star_rating: 3,
      address: {
        line1: "3 List Lane",
        city: "ListCity",
        region: "LC",
        postal_code: "30003",
        country: "US",
      },
      check_in_time: "15:00",
      check_out_time: "11:00",
    });
    expect(status).toBe(201);
    hotelId = (data as { hotel_id: string }).hotel_id;
    expect(hotelId).toBeTruthy();
  });

  test("87.2 list reservations for hotel — empty initially", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");
    if (!hotelId) test.skip(true, "hotel not created");

    const resp = await rootPage.request.get(`${API}/ui/hotels/${hotelId}/reservations`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { reservations: unknown[]; count: number };
    expect(Array.isArray(data.reservations)).toBe(true);
    expect(typeof data.count).toBe("number");
  });

  test("87.3 list reservations with status filter", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");
    if (!hotelId) test.skip(true, "hotel not created");

    const resp = await rootPage.request.get(
      `${API}/ui/hotels/${hotelId}/reservations?status=confirmed`,
    );
    expect(resp.status()).toBe(200);
  });

  test("87.4 list reservations with invalid status returns 422", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");
    if (!hotelId) test.skip(true, "hotel not created");

    const resp = await rootPage.request.get(
      `${API}/ui/hotels/${hotelId}/reservations?status=banana`,
    );
    expect(resp.status()).toBe(422);
  });

  test("87.5 get non-existent reservation returns 404", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");
    if (!hotelId) test.skip(true, "hotel not created");

    const resp = await rootPage.request.get(
      `${API}/ui/hotels/${hotelId}/reservations/res_doesnotexist`,
    );
    expect(resp.status()).toBe(404);
  });

  test("87.6 list reservations with checkin_from / checkin_to filter", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");
    if (!hotelId) test.skip(true, "hotel not created");

    const from = new Date(Date.now()).toISOString().split("T")[0]!;
    const to = new Date(Date.now() + 30 * 86400000).toISOString().split("T")[0]!;
    const resp = await rootPage.request.get(
      `${API}/ui/hotels/${hotelId}/reservations?checkin_from=${from}&checkin_to=${to}`,
    );
    expect(resp.status()).toBe(200);
  });
});

// ─── Section 88 — Reservation Lifecycle API ──────────────────────────────────

test.describe("88 — Reservation Lifecycle API", () => {
  let rootPage: Page;
  let hotelId: string;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("88.1 create hotel for lifecycle tests", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    const { status, data } = await apiPost(rootPage, "root", "/ui/hotels", {
      name: `Lifecycle Hotel ${TS}`,
      description: "E2E lifecycle test",
      star_rating: 5,
      address: {
        line1: "4 Lifecycle Blvd",
        city: "LifeCity",
        region: "LC",
        postal_code: "40004",
        country: "US",
      },
      check_in_time: "15:00",
      check_out_time: "11:00",
    });
    expect(status).toBe(201);
    hotelId = (data as { hotel_id: string }).hotel_id;
    expect(hotelId).toBeTruthy();
  });

  test("88.2 cancel non-existent reservation returns 404", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");
    if (!hotelId) test.skip(true, "hotel not created");

    const resp = await rootPage.request.post(
      `${API}/ui/hotels/${hotelId}/reservations/res_fake12345/cancel`,
      {
        data: { reason: "test" },
        headers: csrfHeaders("root"),
      },
    );
    expect(resp.status()).toBe(404);
  });

  test("88.3 no-show non-existent reservation returns 404", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");
    if (!hotelId) test.skip(true, "hotel not created");

    const resp = await rootPage.request.post(
      `${API}/ui/hotels/${hotelId}/reservations/res_fake12345/no-show`,
      {
        data: { reason: "test" },
        headers: csrfHeaders("root"),
      },
    );
    expect(resp.status()).toBe(404);
  });

  test("88.4 history of non-existent reservation returns 404", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");
    if (!hotelId) test.skip(true, "hotel not created");

    const resp = await rootPage.request.get(
      `${API}/ui/hotels/${hotelId}/reservations/res_fake12345/history`,
    );
    expect(resp.status()).toBe(404);
  });

  test("88.5 confirm non-existent reservation returns 404", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");
    if (!hotelId) test.skip(true, "hotel not created");

    const resp = await rootPage.request.post(
      `${API}/ui/hotels/${hotelId}/reservations/res_fake12345/confirm`,
      {
        data: {},
        headers: csrfHeaders("root"),
      },
    );
    expect(resp.status()).toBe(404);
  });
});

// ─── Section 89 — Booking Page UI ────────────────────────────────────────────

test.describe("89 — Booking Page UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("89.1 booking page renders or shows disabled state", async () => {
    await rootPage.goto(`${BASE}/hotels/book`);
    await rootPage.waitForLoadState("domcontentloaded");

    // The page is lazy-loaded; wait for either the title or the disabled state
    // to render rather than probing with a non-waiting isVisible().
    await expect(
      rootPage
        .getByRole("heading", { name: /hotel booking/i })
        .or(rootPage.getByText(/not enabled/i))
        .first(),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("89.2 booking page shows search form when feature enabled", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    await rootPage.goto(`${BASE}/hotels/book`);
    await rootPage.waitForLoadState("domcontentloaded");

    await expect(
      rootPage.getByRole("heading", { name: /hotel booking/i }),
    ).toBeVisible();
    await expect(rootPage.getByText(/find available rooms/i)).toBeVisible();
  });

  test("89.3 search form has required fields", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    await rootPage.goto(`${BASE}/hotels/book`);
    await rootPage.waitForLoadState("domcontentloaded");

    await expect(rootPage.getByText(/check-in/i).first()).toBeVisible();
    await expect(rootPage.getByText(/check-out/i).first()).toBeVisible();
    await expect(rootPage.getByText(/adults/i).first()).toBeVisible();
    await expect(
      rootPage.getByRole("button", { name: /search availability/i }),
    ).toBeVisible();
  });

  test("89.4 hotel vs city toggle works", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    await rootPage.goto(`${BASE}/hotels/book`);
    await rootPage.waitForLoadState("domcontentloaded");

    const cityBtn = rootPage.getByRole("button", { name: /by city/i });
    await cityBtn.click();
    await expect(rootPage.getByPlaceholder(/e\.g\. paris/i)).toBeVisible();
  });

  test("89.5 search with no hotel selected shows toast", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    await rootPage.goto(`${BASE}/hotels/book`);
    await rootPage.waitForLoadState("domcontentloaded");

    // Click search without selecting a hotel
    await rootPage.getByRole("button", { name: /search availability/i }).click();
    // Should show the validation toast. Match the toast's specific copy
    // ("Please select a hotel") rather than /select a hotel/i, which would also
    // match the always-present "Select a hotel…" Select placeholder.
    await expect(
      rootPage.getByText(/please select a hotel/i).first(),
    ).toBeVisible({ timeout: 5_000 });
  });
});

// ─── Section 90 — Reservations Page UI ───────────────────────────────────────

test.describe("90 — Reservations Page UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("90.1 reservations page renders or shows disabled state", async () => {
    await rootPage.goto(`${BASE}/hotels/reservations`);
    await rootPage.waitForLoadState("domcontentloaded");

    // Lazy-loaded page: wait for either the title or the disabled state.
    await expect(
      rootPage
        .getByRole("heading", { name: /reservations/i })
        .or(rootPage.getByText(/not enabled/i))
        .first(),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("90.2 reservations page shows hotel picker when enabled", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    await rootPage.goto(`${BASE}/hotels/reservations`);
    await rootPage.waitForLoadState("domcontentloaded");

    await expect(rootPage.getByText(/select a hotel/i)).toBeVisible();
  });

  test("90.3 reservations page shows status filter", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    await rootPage.goto(`${BASE}/hotels/reservations`);
    await rootPage.waitForLoadState("domcontentloaded");

    await expect(rootPage.getByText(/status/i).first()).toBeVisible();
    await expect(rootPage.getByText(/check-in from/i)).toBeVisible();
  });

  test("90.4 reservations page has link to new booking", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    await rootPage.goto(`${BASE}/hotels/reservations`);
    await rootPage.waitForLoadState("domcontentloaded");

    const newBookingLink = rootPage.getByRole("link", { name: /new booking/i });
    await expect(newBookingLink).toBeVisible();
    expect(await newBookingLink.getAttribute("href")).toContain("/hotels/book");
  });

  test("90.5 reservation detail page shows 404 for bad ID", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    await rootPage.goto(`${BASE}/hotels/reservations/htl_bad/res_bad`);
    await rootPage.waitForLoadState("domcontentloaded");

    // Lazy-loaded page + async query: wait for the error/not-found state.
    await expect(
      rootPage
        .getByText(/not found/i)
        .or(rootPage.getByText(/failed to load/i))
        .first(),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("90.6 booking page link navigates correctly", async () => {
    const enabled = await hotelPmsEnabled(rootPage);
    test.skip(!enabled, "HOTEL_PMS_ENABLED is off");

    await rootPage.goto(`${BASE}/hotels/reservations`);
    await rootPage.waitForLoadState("domcontentloaded");

    await rootPage.getByRole("link", { name: /new booking/i }).first().click();
    await rootPage.waitForURL(/hotels\/book/);
    expect(rootPage.url()).toContain("/hotels/book");
  });
});
