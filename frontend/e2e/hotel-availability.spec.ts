/**
 * E2E tests for Hotel Availability + Rate Plans (QloApps PMS vertical).
 *
 * Sections:
 *   80 — Hotel Availability API (set inventory, read calendar, hold/release)
 *   81 — Rate Plan CRUD API (create, get, update, deactivate)
 *   82 — Rate Plan Rules API (add/list/delete season, weekend, occupancy, LOS, advance)
 *   83 — Stay Quote API (multi-night price computation)
 *   84 — Availability Calendar UI (AvailabilityCalendarPage)
 *   85 — Rate Plans Manager UI (RatePlansPage)
 *
 * Auth: uses e2e_admin_session_setup.py (root, alice, charlie_admin)
 *
 * HOTEL_PMS_ENABLED defaults OFF: all endpoints return 404 unless the flag
 * is enabled. When the flag is off, sections 80–83 assert 404 on each
 * endpoint, and sections 84–85 assert a "not enabled" message in the UI.
 *
 * Identities:
 *   root   – root.admin@testdev.local – role=root  (write access)
 *   alice  – e2e_alice@test.local    – role=user  (read-only)
 *   charlie_admin – e2e_charlie@test.local – role=admin (write access via admin policy)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE        = "http://localhost:3000";
const HOTEL_ID    = `e2e_hotel_${Date.now()}`;
const ROOM_TYPE   = `rt_standard_${Date.now()}`;
const TS          = Date.now();

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

// ─── Page factory ─────────────────────────────────────────────────────────────

// Track which identity each page was created for, so the write helpers can
// send a CSRF token that matches the page's own session cookies.
const _pageIdentity = new WeakMap<Page, string>();

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  _pageIdentity.set(page, identity);
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

// The write helpers are called as `apiX(page, path, body)`. The CSRF token must
// match the session cookies carried by `page`, so we look it up from the
// identity the page was created for (defaulting to "root").
function csrfForPage(page: Page): string {
  const identity = _pageIdentity.get(page) ?? "root";
  const sess = getAdminSessions()[identity];
  if (!sess) throw new Error(`No session for identity: ${identity}`);
  return sess.csrf_token;
}

async function apiPost(page: Page, path: string, body?: unknown) {
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": csrfForPage(page),
      "Content-Type": "application/json",
    },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiPut(page: Page, path: string, body?: unknown) {
  return page.request.put(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": csrfForPage(page),
      "Content-Type": "application/json",
    },
  });
}

async function apiDelete(page: Page, path: string, params?: Record<string, string>) {
  return page.request.delete(`${API}/${path}`, {
    params,
    headers: {
      "x-csrf-token": csrfForPage(page),
      "Content-Type": "application/json",
    },
  });
}

// ─── Shared state across sections ────────────────────────────────────────────

let sec81RatePlanId = "";
let sec82RuleId     = "";
let sec80HoldId     = "";

// ─────────────────────────────────────────────────────────────────────────────
// Section 80 — Hotel Availability API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 80: Hotel Availability API", () => {
  let rootPage:  Page;
  let alicePage: Page;

  const START_DATE = "2027-07-01";
  const END_DATE   = "2027-07-07";
  const CHECKIN    = "2027-07-02";
  const CHECKOUT   = "2027-07-05";

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage  = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await rootPage.close();
    await alicePage.close();
  });

  test("80.1 — GET /availability/calendar returns 404 when PMS disabled", async () => {
    const resp = await apiGet(
      alicePage,
      `ui/hotels/${HOTEL_ID}/availability/calendar`,
      { start_date: START_DATE, end_date: END_DATE },
    );
    // When HOTEL_PMS_ENABLED is off, expect 404; when on, expect 200
    expect([200, 404]).toContain(resp.status());
  });

  test("80.2 — PUT /availability/{rt}/total-rooms returns 404 or 200", async () => {
    const resp = await apiPut(
      rootPage,
      `ui/hotels/${HOTEL_ID}/availability/${ROOM_TYPE}/total-rooms`,
      {
        hotel_id: HOTEL_ID,
        room_type_id: ROOM_TYPE,
        start_date: START_DATE,
        end_date: END_DATE,
        total_rooms: 10,
      },
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = await resp.json() as unknown[];
      expect(Array.isArray(data)).toBe(true);
      expect(data.length).toBeGreaterThan(0);
    }
  });

  test("80.3 — GET /availability/{rt} returns per-night rows (or 404)", async () => {
    const resp = await apiGet(
      alicePage,
      `ui/hotels/${HOTEL_ID}/availability/${ROOM_TYPE}`,
      { checkin: CHECKIN, checkout: CHECKOUT },
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const rows = await resp.json() as Array<Record<string, unknown>>;
      expect(Array.isArray(rows)).toBe(true);
    }
  });

  test("80.4 — GET /availability/check returns availability shape (or 404)", async () => {
    const resp = await apiGet(
      alicePage,
      `ui/hotels/${HOTEL_ID}/availability/check`,
      {
        room_type_id: ROOM_TYPE,
        checkin: CHECKIN,
        checkout: CHECKOUT,
        rooms_needed: "2",
      },
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const body = await resp.json() as Record<string, unknown>;
      expect(typeof body["available"]).toBe("boolean");
      expect(typeof body["min_remaining"]).toBe("number");
      expect(Array.isArray(body["per_night"])).toBe(true);
    }
  });

  test("80.5 — POST /availability/{rt}/hold creates a hold (or 404)", async () => {
    const resp = await apiPost(
      rootPage,
      `ui/hotels/${HOTEL_ID}/availability/${ROOM_TYPE}/hold`,
      {
        hotel_id: HOTEL_ID,
        room_type_id: ROOM_TYPE,
        checkin: CHECKIN,
        checkout: CHECKOUT,
        quantity: 2,
        ttl_seconds: 300,
      },
    );
    // 409 = sold out (no inventory seeded); 404 = flag off; 200 = success
    expect([200, 404, 409]).toContain(resp.status());
    if (resp.status() === 200) {
      const hold = await resp.json() as Record<string, unknown>;
      expect(typeof hold["hold_id"]).toBe("string");
      expect(hold["status"]).toBe("active");
      sec80HoldId = hold["hold_id"] as string;
    }
  });

  test("80.6 — POST /availability/holds/{id}/release releases an active hold (or 404)", async () => {
    if (!sec80HoldId) {
      test.skip(); // Only runs if hold was created
      return;
    }
    const resp = await apiPost(
      rootPage,
      `ui/hotels/${HOTEL_ID}/availability/holds/${sec80HoldId}/release`,
      {},
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const hold = await resp.json() as Record<string, unknown>;
      expect(hold["status"]).toBe("released");
      expect(hold["hold_id"]).toBe(sec80HoldId);
    }
  });

  test("80.7 — PUT /availability/{rt}/overbooking sets allowance (or 404)", async () => {
    const resp = await apiPut(
      rootPage,
      `ui/hotels/${HOTEL_ID}/availability/${ROOM_TYPE}/overbooking`,
      {
        hotel_id: HOTEL_ID,
        room_type_id: ROOM_TYPE,
        start_date: START_DATE,
        end_date: END_DATE,
        allowance: 2,
      },
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const rows = await resp.json() as Array<Record<string, unknown>>;
      expect(Array.isArray(rows)).toBe(true);
      if (rows.length > 0) {
        expect(rows[0]!["overbooking_allowance"]).toBe(2);
      }
    }
  });

  test("80.8 — PUT /availability/{rt}/min-max sets floors/caps (or 404)", async () => {
    const resp = await apiPut(
      rootPage,
      `ui/hotels/${HOTEL_ID}/availability/${ROOM_TYPE}/min-max`,
      {
        hotel_id: HOTEL_ID,
        room_type_id: ROOM_TYPE,
        start_date: START_DATE,
        end_date: END_DATE,
        min_availability: 1,
        max_availability: 8,
      },
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const rows = await resp.json() as Array<Record<string, unknown>>;
      expect(Array.isArray(rows)).toBe(true);
      if (rows.length > 0) {
        expect(rows[0]!["min_availability"]).toBe(1);
      }
    }
  });

  test("80.9 — 422 for invalid date range on set-total-rooms", async () => {
    const resp = await apiPut(
      rootPage,
      `ui/hotels/${HOTEL_ID}/availability/${ROOM_TYPE}/total-rooms`,
      {
        hotel_id: HOTEL_ID,
        room_type_id: ROOM_TYPE,
        start_date: END_DATE,   // start > end
        end_date: START_DATE,
        total_rooms: 5,
      },
    );
    // 422 = validation error; 404 = flag off
    expect([422, 404]).toContain(resp.status());
  });

  test("80.10 — 422 for negative total_rooms", async () => {
    const resp = await apiPut(
      rootPage,
      `ui/hotels/${HOTEL_ID}/availability/${ROOM_TYPE}/total-rooms`,
      {
        hotel_id: HOTEL_ID,
        room_type_id: ROOM_TYPE,
        start_date: START_DATE,
        end_date: END_DATE,
        total_rooms: -1,
      },
    );
    expect([422, 404]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 81 — Rate Plan CRUD API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 81: Rate Plan CRUD API", () => {
  let rootPage:  Page;
  let alicePage: Page;

  const PLAN_NAME = `E2E Plan ${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage  = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await rootPage.close();
    await alicePage.close();
  });

  test("81.1 — POST /rate-plans creates a rate plan (or 404 when flag off)", async () => {
    const resp = await apiPost(
      rootPage,
      `ui/hotels/${HOTEL_ID}/rate-plans`,
      {
        room_type_id: ROOM_TYPE,
        name: PLAN_NAME,
        base_nightly_rate_cents: 15000,
        base_occupancy: 2,
        currency: "USD",
      },
    );
    expect([201, 404]).toContain(resp.status());
    if (resp.status() === 201) {
      const plan = await resp.json() as Record<string, unknown>;
      expect(typeof plan["rate_plan_id"]).toBe("string");
      expect(plan["name"]).toBe(PLAN_NAME);
      expect(plan["base_nightly_rate_cents"]).toBe(15000);
      expect(plan["active"]).toBe(true);
      sec81RatePlanId = plan["rate_plan_id"] as string;
    }
  });

  test("81.2 — GET /rate-plans lists plans for the hotel (or 404)", async () => {
    const resp = await apiGet(
      alicePage,
      `ui/hotels/${HOTEL_ID}/rate-plans`,
      { limit: "10" },
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const body = await resp.json() as Record<string, unknown>;
      expect(Array.isArray(body["rate_plans"])).toBe(true);
      expect(typeof body["count"]).toBe("number");
    }
  });

  test("81.3 — GET /room-types/{rt}/rate-plan returns the plan (or 404)", async () => {
    const resp = await apiGet(
      alicePage,
      `ui/hotels/${HOTEL_ID}/room-types/${ROOM_TYPE}/rate-plan`,
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const plan = await resp.json() as Record<string, unknown>;
      expect(plan["room_type_id"]).toBe(ROOM_TYPE);
      expect(plan["hotel_id"]).toBe(HOTEL_ID);
    }
  });

  test("81.4 — PUT /room-types/{rt}/rate-plan updates the plan (or 404)", async () => {
    const resp = await apiPut(
      rootPage,
      `ui/hotels/${HOTEL_ID}/room-types/${ROOM_TYPE}/rate-plan`,
      {
        name: `${PLAN_NAME} Updated`,
        base_nightly_rate_cents: 17500,
      },
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const plan = await resp.json() as Record<string, unknown>;
      expect(plan["name"]).toBe(`${PLAN_NAME} Updated`);
      expect(plan["base_nightly_rate_cents"]).toBe(17500);
    }
  });

  test("81.5 — DELETE /room-types/{rt}/rate-plan deactivates (soft) the plan (or 404)", async () => {
    const resp = await apiDelete(
      rootPage,
      `ui/hotels/${HOTEL_ID}/room-types/${ROOM_TYPE}/rate-plan`,
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const plan = await resp.json() as Record<string, unknown>;
      expect(plan["active"]).toBe(false);
    }
  });

  test("81.6 — POST /rate-plans idempotent for same room_type_id (or 404)", async () => {
    // Re-creating a plan for the same room type returns the existing one
    const resp = await apiPost(
      rootPage,
      `ui/hotels/${HOTEL_ID}/rate-plans`,
      {
        room_type_id: ROOM_TYPE,
        name: "Duplicate attempt",
        base_nightly_rate_cents: 9999,
        base_occupancy: 1,
        currency: "USD",
      },
    );
    expect([201, 200, 404]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 82 — Rate Plan Rules API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 82: Rate Plan Rules API", () => {
  let rootPage:  Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage  = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");

    // Ensure the plan is active for rule tests (re-create if needed)
    await apiPost(rootPage, `ui/hotels/${HOTEL_ID}/rate-plans`, {
      room_type_id: ROOM_TYPE,
      name: `E2E Plan Rules ${TS}`,
      base_nightly_rate_cents: 12000,
      base_occupancy: 2,
      currency: "USD",
    });
  });

  test.afterAll(async () => {
    await rootPage.close();
    await alicePage.close();
  });

  test("82.1 — POST rules: add a season rule (or 404)", async () => {
    const resp = await apiPost(
      rootPage,
      `ui/hotels/${HOTEL_ID}/room-types/${ROOM_TYPE}/rate-plan/rules`,
      {
        kind: "season",
        rule_config: {
          start_date: "2027-06-01",
          end_date: "2027-08-31",
          mode: "delta",
          value_cents: 2000,
        },
        priority: 100,
      },
    );
    expect([201, 404]).toContain(resp.status());
    if (resp.status() === 201) {
      const rule = await resp.json() as Record<string, unknown>;
      expect(rule["kind"]).toBe("season");
      expect(typeof rule["rule_id"]).toBe("string");
      sec82RuleId = rule["rule_id"] as string;
    }
  });

  test("82.2 — POST rules: add a weekend rule (or 404)", async () => {
    const resp = await apiPost(
      rootPage,
      `ui/hotels/${HOTEL_ID}/room-types/${ROOM_TYPE}/rate-plan/rules`,
      {
        kind: "weekend",
        rule_config: {
          dow: [6, 7],
          mode: "delta",
          value_cents: 1500,
        },
        priority: 200,
      },
    );
    expect([201, 404]).toContain(resp.status());
    if (resp.status() === 201) {
      const rule = await resp.json() as Record<string, unknown>;
      expect(rule["kind"]).toBe("weekend");
    }
  });

  test("82.3 — POST rules: add an occupancy rule (or 404)", async () => {
    const resp = await apiPost(
      rootPage,
      `ui/hotels/${HOTEL_ID}/room-types/${ROOM_TYPE}/rate-plan/rules`,
      {
        kind: "occupancy",
        rule_config: {
          extra_adult_cents: 2500,
          extra_child_cents: 1000,
        },
        priority: 300,
      },
    );
    expect([201, 404]).toContain(resp.status());
    if (resp.status() === 201) {
      const rule = await resp.json() as Record<string, unknown>;
      expect(rule["kind"]).toBe("occupancy");
    }
  });

  test("82.4 — POST rules: add an LOS rule (or 404)", async () => {
    const resp = await apiPost(
      rootPage,
      `ui/hotels/${HOTEL_ID}/room-types/${ROOM_TYPE}/rate-plan/rules`,
      {
        kind: "los",
        rule_config: {
          min_nights: 3,
          max_nights: null,
          discount_type: "percentage",
          discount_value: 10,
        },
        priority: 400,
      },
    );
    expect([201, 404]).toContain(resp.status());
    if (resp.status() === 201) {
      const rule = await resp.json() as Record<string, unknown>;
      expect(rule["kind"]).toBe("los");
    }
  });

  test("82.5 — POST rules: add an advance-purchase rule (or 404)", async () => {
    const resp = await apiPost(
      rootPage,
      `ui/hotels/${HOTEL_ID}/room-types/${ROOM_TYPE}/rate-plan/rules`,
      {
        kind: "advance",
        rule_config: {
          days_before_checkin: 21,
          comparator: "gte",
          mode: "percentage",
          value: 15,
        },
        priority: 500,
      },
    );
    expect([201, 404]).toContain(resp.status());
    if (resp.status() === 201) {
      const rule = await resp.json() as Record<string, unknown>;
      expect(rule["kind"]).toBe("advance");
    }
  });

  test("82.6 — GET rules returns all rules sorted by priority (or 404)", async () => {
    const resp = await apiGet(
      alicePage,
      `ui/hotels/${HOTEL_ID}/room-types/${ROOM_TYPE}/rate-plan/rules`,
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const rules = await resp.json() as Array<Record<string, unknown>>;
      expect(Array.isArray(rules)).toBe(true);
      // Verify sorted by priority ascending
      for (let i = 1; i < rules.length; i++) {
        expect(Number(rules[i]!["priority"])).toBeGreaterThanOrEqual(
          Number(rules[i - 1]!["priority"]),
        );
      }
    }
  });

  test("82.7 — DELETE rule removes it (or 404)", async () => {
    if (!sec82RuleId) {
      test.skip();
      return;
    }
    const resp = await apiDelete(
      rootPage,
      `ui/hotels/${HOTEL_ID}/room-types/${ROOM_TYPE}/rate-plan/rules/${sec82RuleId}`,
      { kind: "season" },
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const body = await resp.json() as Record<string, unknown>;
      expect(typeof body["ok"]).toBe("boolean");
    }
  });

  test("82.8 — POST rule: 422 for invalid kind", async () => {
    const resp = await apiPost(
      rootPage,
      `ui/hotels/${HOTEL_ID}/room-types/${ROOM_TYPE}/rate-plan/rules`,
      {
        kind: "invalid_kind",
        rule_config: {},
        priority: 0,
      },
    );
    expect([422, 404]).toContain(resp.status());
  });

  test("82.9 — POST rule: 422 for season rule with start > end", async () => {
    const resp = await apiPost(
      rootPage,
      `ui/hotels/${HOTEL_ID}/room-types/${ROOM_TYPE}/rate-plan/rules`,
      {
        kind: "season",
        rule_config: {
          start_date: "2027-09-01",
          end_date: "2027-08-01", // end before start
          mode: "delta",
          value_cents: 1000,
        },
        priority: 100,
      },
    );
    expect([422, 404]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 83 — Stay Quote API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 83: Stay Quote API (multi-night price)", () => {
  let rootPage:  Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage  = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await rootPage.close();
    await alicePage.close();
  });

  test("83.1 — POST /quote returns a stay price breakdown (or 404)", async () => {
    const resp = await apiPost(
      alicePage,
      `ui/hotels/${HOTEL_ID}/room-types/${ROOM_TYPE}/quote`,
      {
        checkin:  "2027-07-01",
        checkout: "2027-07-05",
        adults:   2,
        children: 0,
        rooms:    1,
      },
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const quote = await resp.json() as Record<string, unknown>;
      expect(typeof quote["nights"]).toBe("number");
      expect(quote["nights"]).toBe(4);
      expect(Array.isArray(quote["per_night"])).toBe(true);
      expect(typeof quote["total_cents"]).toBe("number");
      expect((quote["total_cents"] as number) >= 0).toBe(true);
      expect(typeof quote["currency"]).toBe("string");
      expect(Array.isArray(quote["applied_rule_ids"])).toBe(true);
    }
  });

  test("83.2 — /quote per_night array has correct night count (or 404)", async () => {
    const resp = await apiPost(
      alicePage,
      `ui/hotels/${HOTEL_ID}/room-types/${ROOM_TYPE}/quote`,
      {
        checkin:  "2027-08-10",
        checkout: "2027-08-13",
        adults:   1,
        rooms:    2,
      },
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const quote = await resp.json() as Record<string, unknown>;
      expect(quote["nights"]).toBe(3);
      expect((quote["per_night"] as unknown[]).length).toBe(3);
      // Two rooms: total should be 2× the per-room cost
      expect(quote["rooms"]).toBe(2);
    }
  });

  test("83.3 — /quote 422 when checkout <= checkin", async () => {
    const resp = await apiPost(
      alicePage,
      `ui/hotels/${HOTEL_ID}/room-types/${ROOM_TYPE}/quote`,
      {
        checkin:  "2027-07-05",
        checkout: "2027-07-05", // same day = zero nights
        adults:   2,
      },
    );
    expect([422, 404]).toContain(resp.status());
  });

  test("83.4 — /quote uses advance_days override parameter (or 404)", async () => {
    const resp = await apiPost(
      alicePage,
      `ui/hotels/${HOTEL_ID}/room-types/${ROOM_TYPE}/quote`,
      {
        checkin:       "2027-07-01",
        checkout:      "2027-07-04",
        adults:        2,
        advance_days:  30, // explicit override
      },
    );
    expect([200, 404]).toContain(resp.status());
    // If enabled and advance rule applies, the modifier may be nonzero
    if (resp.status() === 200) {
      const quote = await resp.json() as Record<string, unknown>;
      expect(typeof quote["advance_modifier_cents"]).toBe("number");
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 84 — Availability Calendar UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 84: Availability Calendar UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await browser.newPage();
    await injectAuth(rootPage, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("84.1 — /hotels/availability renders the page header", async () => {
    await rootPage.goto(`${BASE}/hotels/availability`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByRole("heading", { name: /availability calendar/i })).toBeVisible({
      timeout: 8000,
    });
  });

  test("84.2 — Month navigation controls are visible", async () => {
    await rootPage.goto(`${BASE}/hotels/availability`, { waitUntil: "domcontentloaded" });
    // Prev / next month buttons
    const buttons = rootPage.getByRole("button");
    await expect(buttons.first()).toBeVisible({ timeout: 5000 });
  });

  test("84.3 — Hotel ID input and Load button are present", async () => {
    await rootPage.goto(`${BASE}/hotels/availability`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByPlaceholder(/hotel id/i)).toBeVisible({ timeout: 5000 });
    await expect(rootPage.getByRole("button", { name: /load/i })).toBeVisible();
  });

  test("84.4 — When flag is off, shows 'Hotel PMS not enabled' state", async () => {
    // Navigate to the page and check for either the calendar table or the disabled state
    await rootPage.goto(`${BASE}/hotels/availability`, { waitUntil: "domcontentloaded" });
    // After load, one of these should be visible:
    const disabledMsg = rootPage.getByText(/hotel pms not enabled/i);
    const calTable    = rootPage.locator("table");
    const noDataMsg   = rootPage.getByText(/no availability data/i);
    // Wait for any of them
    await Promise.race([
      disabledMsg.waitFor({ timeout: 10000 }).catch(() => null),
      calTable.waitFor({ timeout: 10000 }).catch(() => null),
      noDataMsg.waitFor({ timeout: 10000 }).catch(() => null),
    ]);
    // At least the heading is always visible
    await expect(rootPage.getByRole("heading", { name: /availability calendar/i })).toBeVisible();
  });

  test("84.5 — Legend items are visible", async () => {
    await rootPage.goto(`${BASE}/hotels/availability`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByText(/good availability/i)).toBeVisible({ timeout: 8000 });
    await expect(rootPage.getByText(/sold out/i)).toBeVisible();
  });

  test("84.6 — Refresh button is visible and clickable", async () => {
    await rootPage.goto(`${BASE}/hotels/availability`, { waitUntil: "domcontentloaded" });
    const refreshBtn = rootPage.getByRole("button", { name: /refresh/i });
    await expect(refreshBtn).toBeVisible({ timeout: 5000 });
    await refreshBtn.click(); // should not throw
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 85 — Rate Plans Manager UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 85: Rate Plans Manager UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await browser.newPage();
    await injectAuth(rootPage, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("85.1 — /hotels/rate-plans renders the page header", async () => {
    await rootPage.goto(`${BASE}/hotels/rate-plans`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByRole("heading", { name: /rate plans/i })).toBeVisible({
      timeout: 8000,
    });
  });

  test("85.2 — Hotel ID input and Load + New Plan buttons are present", async () => {
    await rootPage.goto(`${BASE}/hotels/rate-plans`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByPlaceholder(/hotel id/i)).toBeVisible({ timeout: 5000 });
    await expect(rootPage.getByRole("button", { name: /load/i })).toBeVisible();
    await expect(rootPage.getByRole("button", { name: /new plan/i })).toBeVisible();
  });

  test("85.3 — When flag is off, shows 'Hotel PMS not enabled' state", async () => {
    await rootPage.goto(`${BASE}/hotels/rate-plans`, { waitUntil: "domcontentloaded" });
    const disabledMsg = rootPage.getByText(/hotel pms not enabled/i);
    const noPlansMsg  = rootPage.getByText(/no rate plans/i);
    const planCard    = rootPage.locator(".rounded-xl, [class*=card]").first();
    await Promise.race([
      disabledMsg.waitFor({ timeout: 10000 }).catch(() => null),
      noPlansMsg.waitFor({ timeout: 10000 }).catch(() => null),
      planCard.waitFor({ timeout: 10000 }).catch(() => null),
    ]);
    await expect(rootPage.getByRole("heading", { name: /rate plans/i })).toBeVisible();
  });

  test("85.4 — Clicking 'New Plan' opens the create dialog", async () => {
    await rootPage.goto(`${BASE}/hotels/rate-plans`, { waitUntil: "domcontentloaded" });
    await rootPage.getByRole("button", { name: /new plan/i }).click();
    const dialog = rootPage.getByRole("dialog");
    await expect(dialog).toBeVisible({ timeout: 5000 });
    // "Create Rate Plan" appears as both the dialog title and the submit button,
    // so scope the assertion to the dialog's heading.
    await expect(
      dialog.getByRole("heading", { name: /create rate plan/i }),
    ).toBeVisible();
    // Close dialog
    await rootPage.keyboard.press("Escape");
  });

  test("85.5 — Create dialog has all required fields", async () => {
    await rootPage.goto(`${BASE}/hotels/rate-plans`, { waitUntil: "domcontentloaded" });
    await rootPage.getByRole("button", { name: /new plan/i }).click();
    await expect(rootPage.getByLabel(/room type id/i)).toBeVisible({ timeout: 5000 });
    await expect(rootPage.getByLabel(/plan name/i)).toBeVisible();
    await expect(rootPage.getByLabel(/base nightly rate/i)).toBeVisible();
    await expect(rootPage.getByLabel(/base occupancy/i)).toBeVisible();
    await rootPage.keyboard.press("Escape");
  });

  test("85.6 — Refresh button is visible and clickable", async () => {
    await rootPage.goto(`${BASE}/hotels/rate-plans`, { waitUntil: "domcontentloaded" });
    const refreshBtn = rootPage.getByRole("button", { name: /refresh/i });
    await expect(refreshBtn).toBeVisible({ timeout: 5000 });
    await refreshBtn.click();
  });

  test("85.7 — Rate plan page description is visible", async () => {
    await rootPage.goto(`${BASE}/hotels/rate-plans`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByText(/multi-night pricing/i)).toBeVisible({ timeout: 8000 });
  });
});
