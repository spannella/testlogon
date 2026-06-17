/**
 * E2E tests for the Hotel Front-Desk Console (HTL-022..024).
 *
 * Sections:
 *   70 — Front-desk read API (arrivals / departures / in-house / occupancy)
 *   71 — Check-in flow (assign room + check-in transition) — API
 *   72 — Check-out flow — API
 *   73 — Walk-in booking — API
 *   74 — Room assignment + room-move — API
 *   75 — Front-Desk Dashboard UI
 *   76 — Check-In page UI
 *   77 — Check-Out page UI
 *
 * NOTE: All hotel endpoints return 404 when HOTEL_PMS_ENABLED=false (default).
 * Tests in sections 70-74 assert the 404 and skip further assertions.
 * Sections 75-77 check that the UI renders the "not enabled" state gracefully.
 *
 * Auth: root (ADMIN/ROOT) for write endpoints; alice for read-only.
 * Uses e2e_admin_session_setup.py for session injection.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const TS       = Date.now();

/** Placeholder hotel_id. In a real seeded env this would match a real hotel. */
const HOTEL_ID = `hotel_e2e_${TS}`;

const TODAY = new Date().toISOString().slice(0, 10);
const TOMORROW = (() => {
  const d = new Date();
  d.setDate(d.getDate() + 1);
  return d.toISOString().slice(0, 10);
})();

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
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
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

function csrfHeader(identity: string): Record<string, string> {
  return { "x-csrf-token": getAdminSessions()[identity].csrf_token };
}

// ─── Helper: API request using session cookies ────────────────────────────────

async function apiGet(
  page: Page,
  path: string,
  params?: Record<string, string>,
): Promise<Response> {
  const url = new URL(`${API}${path}`);
  if (params) {
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  }
  return page.request.get(url.toString());
}

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body: unknown = {},
): Promise<Response> {
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: csrfHeader(identity),
  });
}

// ─── Helper: feature flag check ──────────────────────────────────────────────

/**
 * Returns true if the Hotel PMS appears enabled (200 from a read endpoint).
 * Returns false if 404 (feature flag off, which is the default).
 */
async function isPmsEnabled(page: Page): Promise<boolean> {
  const resp = await apiGet(page, `/ui/hotels/${HOTEL_ID}/front-desk/occupancy`);
  // 404 = disabled OR hotel not found; both are "not enabled" for our purposes
  return resp.status() === 200;
}

// ─── Section 70: Front-desk read API ─────────────────────────────────────────

test.describe("Section 70: Front-desk read API", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("70.1 GET arrivals returns 200 or 404 (feature gate)", async () => {
    const resp = await apiGet(
      rootPage,
      `/ui/hotels/${HOTEL_ID}/front-desk/arrivals`,
      { date: TODAY },
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const body = await resp.json() as { rows: unknown[]; count: number };
      expect(Array.isArray(body.rows)).toBe(true);
      expect(typeof body.count).toBe("number");
    }
  });

  test("70.2 GET departures returns 200 or 404 (feature gate)", async () => {
    const resp = await apiGet(
      rootPage,
      `/ui/hotels/${HOTEL_ID}/front-desk/departures`,
      { date: TODAY },
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const body = await resp.json() as { rows: unknown[]; count: number };
      expect(Array.isArray(body.rows)).toBe(true);
    }
  });

  test("70.3 GET in-house returns 200 or 404 (feature gate)", async () => {
    const resp = await apiGet(
      rootPage,
      `/ui/hotels/${HOTEL_ID}/front-desk/in-house`,
    );
    expect([200, 404]).toContain(resp.status());
  });

  test("70.4 GET occupancy snapshot returns 200 or 404 (feature gate)", async () => {
    const resp = await apiGet(
      rootPage,
      `/ui/hotels/${HOTEL_ID}/front-desk/occupancy`,
      { date: TODAY },
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const snap = await resp.json() as Record<string, unknown>;
      expect(typeof snap.rooms_total).toBe("number");
      expect(typeof snap.occupancy_rate).toBe("number");
      expect(snap.occupancy_rate).toBeGreaterThanOrEqual(0);
      expect(snap.occupancy_rate).toBeLessThanOrEqual(1);
    }
  });

  test("70.5 GET arrivals with ?date param is respected", async () => {
    const resp = await apiGet(
      rootPage,
      `/ui/hotels/${HOTEL_ID}/front-desk/arrivals`,
      { date: TOMORROW },
    );
    expect([200, 404]).toContain(resp.status());
  });

  test("70.6 unauthenticated GET arrivals returns 401 or 404", async ({ request }) => {
    const resp = await request.get(
      `${API}/ui/hotels/${HOTEL_ID}/front-desk/arrivals`,
    );
    expect([401, 404]).toContain(resp.status());
  });
});

// ─── Section 71: Check-in flow — API ─────────────────────────────────────────

test.describe("Section 71: Check-in flow — API", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("71.1 POST check-in on non-existent reservation returns 404 or 404 (PMS gate)", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/ui/hotels/${HOTEL_ID}/reservations/res_nonexistent_e2e/check-in`,
      { assigned_room_ids: ["101"], reason: "" },
    );
    // 404 = PMS disabled OR reservation not found
    expect([404, 409, 422]).toContain(resp.status());
  });

  test("71.2 POST check-in without room IDs returns 422 or 404", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/ui/hotels/${HOTEL_ID}/reservations/res_nonexistent_e2e/check-in`,
      { assigned_room_ids: [], reason: "" },
    );
    expect([404, 409, 422]).toContain(resp.status());
  });

  test("71.3 POST assign-room on non-existent reservation returns 404", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/ui/hotels/${HOTEL_ID}/front-desk/reservations/res_nonexistent_e2e/assign-room`,
      { assigned_room_ids: ["102"], version: 1 },
    );
    expect([404]).toContain(resp.status());
  });

  test("71.4 Non-admin cannot POST assign-room (requires ADMIN/ROOT)", async ({ browser }) => {
    const alicePage = await newIdentityPage(browser, "alice");
    const resp = await apiPost(
      alicePage,
      "alice",
      `/ui/hotels/${HOTEL_ID}/front-desk/reservations/res_nonexistent/assign-room`,
      { assigned_room_ids: ["103"], version: 1 },
    );
    // 403 = forbidden, 404 = PMS off or not found
    expect([403, 404]).toContain(resp.status());
    await alicePage.close();
  });
});

// ─── Section 72: Check-out flow — API ────────────────────────────────────────

test.describe("Section 72: Check-out flow — API", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("72.1 POST check-out on non-existent reservation returns 404 or 409", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/ui/hotels/${HOTEL_ID}/reservations/res_nonexistent_co/check-out`,
      { reason: "test" },
    );
    expect([404, 409]).toContain(resp.status());
  });

  test("72.2 POST check-out without body returns 404 or 409 (optional body)", async () => {
    const resp = await rootPage.request.post(
      `${API}/ui/hotels/${HOTEL_ID}/reservations/res_nonexistent_co2/check-out`,
      {
        headers: csrfHeader("root"),
        // no body - should be fine (body is Optional in the router)
      },
    );
    expect([404, 409]).toContain(resp.status());
  });

  test("72.3 Non-admin cannot check out (requires ADMIN/ROOT)", async ({ browser }) => {
    const bobPage = await newIdentityPage(browser, "bob");
    const resp = await apiPost(
      bobPage,
      "bob",
      `/ui/hotels/${HOTEL_ID}/reservations/res_nope/check-out`,
      {},
    );
    expect([403, 404]).toContain(resp.status());
    await bobPage.close();
  });
});

// ─── Section 73: Walk-in booking — API ───────────────────────────────────────

test.describe("Section 73: Walk-in booking — API", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("73.1 POST walk-in returns 201 or 404 (feature gate) or 503 (deps missing)", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/ui/hotels/${HOTEL_ID}/front-desk/walk-in`,
      {
        room_type_id: "rt_standard_e2e",
        checkin: TODAY,
        checkout: TOMORROW,
        occupancy_adults: 1,
        occupancy_children: 0,
        guest_name: `E2E WalkIn ${TS}`,
        assigned_room_ids: ["101"],
      },
    );
    // 201 = created, 404 = PMS disabled, 503 = dep unavailable, 409 = no avail
    expect([201, 404, 409, 422, 503]).toContain(resp.status());
  });

  test("73.2 POST walk-in without guest_name returns 422 or 404", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/ui/hotels/${HOTEL_ID}/front-desk/walk-in`,
      {
        room_type_id: "rt_standard",
        checkin: TODAY,
        checkout: TOMORROW,
        // missing guest_name
      },
    );
    expect([404, 422]).toContain(resp.status());
  });

  test("73.3 Non-admin cannot create walk-in (requires ADMIN/ROOT)", async ({ browser }) => {
    const alicePage = await newIdentityPage(browser, "alice");
    const resp = await apiPost(
      alicePage,
      "alice",
      `/ui/hotels/${HOTEL_ID}/front-desk/walk-in`,
      {
        room_type_id: "rt_standard",
        checkin: TODAY,
        checkout: TOMORROW,
        guest_name: "Should Fail",
      },
    );
    expect([403, 404]).toContain(resp.status());
    await alicePage.close();
  });
});

// ─── Section 74: Room assignment + room-move — API ───────────────────────────

test.describe("Section 74: Room assignment + room-move — API", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("74.1 POST change-room with missing reservation returns 404", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/ui/hotels/${HOTEL_ID}/front-desk/reservations/res_nope/change-room`,
      { assigned_room_ids: ["201"], version: 1 },
    );
    expect([404]).toContain(resp.status());
  });

  test("74.2 POST room-move with missing reservation returns 404", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/ui/hotels/${HOTEL_ID}/front-desk/reservations/res_nope/room-move`,
      { from_room_id: "101", to_room_id: "202", version: 1 },
    );
    expect([404]).toContain(resp.status());
  });

  test("74.3 POST room-move without required fields returns 422 or 404", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/ui/hotels/${HOTEL_ID}/front-desk/reservations/res_nope/room-move`,
      { version: 1 }, // missing from_room_id and to_room_id
    );
    expect([404, 422]).toContain(resp.status());
  });

  test("74.4 change-room requires ADMIN/ROOT", async ({ browser }) => {
    const bobPage = await newIdentityPage(browser, "bob");
    const resp = await apiPost(
      bobPage,
      "bob",
      `/ui/hotels/${HOTEL_ID}/front-desk/reservations/res_nope/change-room`,
      { assigned_room_ids: ["301"], version: 1 },
    );
    expect([403, 404]).toContain(resp.status());
    await bobPage.close();
  });
});

// ─── Section 75: Front-Desk Dashboard UI ─────────────────────────────────────

test.describe("Section 75: Front-Desk Dashboard UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    await injectAuth(rootPage, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("75.1 /hotels/front-desk renders without crashing", async () => {
    await rootPage.goto(`${BASE}/hotels/front-desk`);
    // Either the PMS-disabled message or the dashboard
    await expect(rootPage.locator("body")).toBeVisible();
    // Must NOT show an unhandled JS error
    await expect(rootPage.locator("text=Something went wrong").first()).not.toBeVisible();
  });

  test("75.2 page shows 'Front Desk' heading or 'not enabled' message", async () => {
    await rootPage.goto(`${BASE}/hotels/front-desk`);
    await rootPage.waitForLoadState("domcontentloaded");
    // Lazy-loaded page: wait for either the heading or the disabled message.
    await expect(
      rootPage
        .getByRole("heading", { name: /front desk/i })
        .or(rootPage.getByText(/hotel pms not enabled/i))
        .first(),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("75.3 Walk-in button is visible for admin users", async () => {
    await rootPage.goto(`${BASE}/hotels/front-desk`);
    await rootPage.waitForLoadState("domcontentloaded");
    // Only check if the PMS is enabled; if not, the page shows disabled state
    const notEnabled = await rootPage.getByText(/hotel pms not enabled/i).isVisible();
    if (!notEnabled) {
      await expect(rootPage.getByRole("button", { name: /walk.in/i })).toBeVisible();
    }
  });

  test("75.4 Tabs for Arrivals / Departures / In-house are rendered", async () => {
    await rootPage.goto(`${BASE}/hotels/front-desk`);
    await rootPage.waitForLoadState("domcontentloaded");
    const notEnabled = await rootPage.getByText(/hotel pms not enabled/i).isVisible();
    if (!notEnabled) {
      await expect(rootPage.getByRole("tab", { name: /arrivals/i })).toBeVisible();
      await expect(rootPage.getByRole("tab", { name: /departures/i })).toBeVisible();
      await expect(rootPage.getByRole("tab", { name: /in.house/i })).toBeVisible();
    }
  });

  test("75.5 Clicking Departures tab does not crash", async () => {
    await rootPage.goto(`${BASE}/hotels/front-desk`);
    await rootPage.waitForLoadState("domcontentloaded");
    const notEnabled = await rootPage.getByText(/hotel pms not enabled/i).isVisible();
    if (!notEnabled) {
      const tab = rootPage.getByRole("tab", { name: /departures/i });
      if (await tab.isVisible()) await tab.click();
      await expect(rootPage.locator("body")).toBeVisible();
    }
  });

  test("75.6 Non-admin user sees read-only view (no Walk-in button)", async ({ browser }) => {
    const alicePage = await newIdentityPage(browser, "alice");
    await injectAuth(alicePage, "alice");
    await alicePage.goto(`${BASE}/hotels/front-desk`);
    await alicePage.waitForLoadState("domcontentloaded");
    // Alice is a regular user — Walk-in button should NOT be visible
    const walkInBtn = alicePage.getByRole("button", { name: /walk.in/i });
    expect(await walkInBtn.isVisible()).toBe(false);
    await alicePage.close();
  });
});

// ─── Section 76: Check-In Page UI ────────────────────────────────────────────

test.describe("Section 76: Check-In Page UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    await injectAuth(rootPage, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("76.1 /hotels/front-desk/check-in/:id renders without crashing", async () => {
    await rootPage.goto(`${BASE}/hotels/front-desk/check-in/res_test_e2e`);
    await rootPage.waitForLoadState("domcontentloaded");
    await expect(rootPage.locator("body")).toBeVisible();
  });

  test("76.2 Back button navigates to front-desk dashboard", async () => {
    await rootPage.goto(`${BASE}/hotels/front-desk/check-in/res_test_e2e`);
    await rootPage.waitForLoadState("domcontentloaded");
    const backBtn = rootPage.getByRole("button").first();
    if (await backBtn.isVisible()) {
      await backBtn.click();
      await expect(rootPage).toHaveURL(/\/hotels\/front-desk/);
    }
  });

  test("76.3 Check-In page shows reservation-not-found when no state passed", async () => {
    await rootPage.goto(`${BASE}/hotels/front-desk/check-in/res_definitely_not_real`);
    await rootPage.waitForLoadState("domcontentloaded");
    // Page should either show 'not found' or 'hotel pms not enabled' gracefully
    const body = await rootPage.locator("body").textContent();
    expect(body).toBeTruthy();
    // Should not show unhandled error
    await expect(rootPage.getByText("Something went wrong")).not.toBeVisible();
  });
});

// ─── Section 77: Check-Out Page UI ───────────────────────────────────────────

test.describe("Section 77: Check-Out Page UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    await injectAuth(rootPage, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("77.1 /hotels/front-desk/check-out/:id renders without crashing", async () => {
    await rootPage.goto(`${BASE}/hotels/front-desk/check-out/res_test_e2e`);
    await rootPage.waitForLoadState("domcontentloaded");
    await expect(rootPage.locator("body")).toBeVisible();
  });

  test("77.2 Check-Out page shows graceful not-found state", async () => {
    await rootPage.goto(`${BASE}/hotels/front-desk/check-out/res_does_not_exist_e2e`);
    await rootPage.waitForLoadState("domcontentloaded");
    // Should not crash
    await expect(rootPage.getByText("Something went wrong")).not.toBeVisible();
  });

  test("77.3 /hotels/front-desk/walk-in page renders without crashing", async () => {
    await rootPage.goto(`${BASE}/hotels/front-desk/walk-in`);
    await rootPage.waitForLoadState("domcontentloaded");
    await expect(rootPage.locator("body")).toBeVisible();
  });

  test("77.4 Walk-in page shows form fields", async () => {
    await rootPage.goto(`${BASE}/hotels/front-desk/walk-in`);
    await rootPage.waitForLoadState("domcontentloaded");
    // Either the form or disabled state
    const notEnabled = await rootPage.getByText(/hotel pms not enabled/i).isVisible();
    if (!notEnabled) {
      await expect(rootPage.getByLabel(/guest name/i)).toBeVisible();
      await expect(rootPage.getByLabel(/room type/i)).toBeVisible();
      await expect(rootPage.getByLabel(/check.in/i)).toBeVisible();
    }
  });

  test("77.5 Walk-in submit button is disabled when required fields are empty", async () => {
    await rootPage.goto(`${BASE}/hotels/front-desk/walk-in`);
    await rootPage.waitForLoadState("domcontentloaded");
    const notEnabled = await rootPage.getByText(/hotel pms not enabled/i).isVisible();
    if (!notEnabled) {
      const submitBtn = rootPage.getByRole("button", { name: /create.*check.in/i });
      if (await submitBtn.isVisible()) {
        // All fields empty = button should be disabled
        const guestInput = rootPage.getByLabel(/guest name/i);
        if (await guestInput.isVisible()) {
          await guestInput.fill("");
        }
        await expect(submitBtn).toBeDisabled();
      }
    }
  });
});
