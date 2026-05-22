/**
 * E2E tests for Apple CalDAV integration via the mock CalDAV backend.
 *
 * Sections:
 *   78 — Apple CalDAV Mock Integration (6 tests)
 *   79 — Apple CalDAV Deep Integration Flows (5 tests)
 *
 * Auth: Alice session cookies (from e2e_session_setup.py).
 *
 * Required .env.local flags:
 *   APPLE_CALDAV_MOCK_ENABLED=1
 *   APPLE_CALDAV_BASE_URL=http://localhost:8000/mock/apple-caldav
 *
 * The mock CalDAV server lives at /mock/apple-caldav/ and is seeded via
 * POST /mock/apple-caldav/seed before each test run.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const BACKEND = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const REPO_ROOT = "/home/ubuntu/testlogon";

/** The integration router prefix (no /ui — registered at app level). */
const APPLE_PREFIX = "/calendar/integrations/apple";

const MOCK_USERNAME = "e2e_apple_user";
const MOCK_PASSWORD = "e2e_apple_pass";

interface SessionData {
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

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync("python3 e2e_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

/**
 * POST to the backend directly (port 8000) for paths not proxied by Vite.
 * page.request carries the browser-context cookies (domain=localhost).
 */
async function apiPost(page: Page, path: string, body?: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${BACKEND}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": session.csrf_token },
  });
}

/** GET from the backend directly. */
async function apiGet(page: Page, path: string) {
  const session = getSessions()[ALICE_ID];
  return page.request.get(`${BACKEND}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

/** Seed the mock CalDAV server (no auth needed — it is a mock admin endpoint). */
async function seedMock(page: Page) {
  const icalData =
    "BEGIN:VCALENDAR\r\n" +
    "VERSION:2.0\r\n" +
    "PRODID:-//Mock//Mock//EN\r\n" +
    "BEGIN:VEVENT\r\n" +
    "UID:evt1\r\n" +
    "DTSTART:20260601T100000Z\r\n" +
    "DTEND:20260601T110000Z\r\n" +
    "SUMMARY:E2E Mock Event\r\n" +
    "END:VEVENT\r\n" +
    "END:VCALENDAR\r\n";

  const resp = await page.request.post(`${BASE}/mock/apple-caldav/seed`, {
    data: {
      credentials: { [MOCK_USERNAME]: MOCK_PASSWORD },
      calendars: {
        cal1: { display_name: "My Test Calendar" },
        cal2: { display_name: "Work Calendar" },
      },
      events: {
        "cal1:evt1": icalData,
      },
    },
  });
  expect(resp.status()).toBe(200);
  const body = await resp.json();
  expect(body.ok).toBe(true);
  expect(body.credentials).toBe(1);
  expect(body.calendars).toBe(2);
  expect(body.events).toBe(1);
}

/** Reset the mock CalDAV server to a clean state. */
async function resetMock(page: Page) {
  const resp = await page.request.post(`${BASE}/mock/apple-caldav/reset`);
  expect(resp.status()).toBe(200);
}

test.describe("78 — Apple CalDAV Mock Integration", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Reset mock state then seed with test data
    await resetMock(alicePage);
    await seedMock(alicePage);
  });

  test.afterAll(async () => {
    // Disconnect so we leave a clean state for other test files
    await apiPost(alicePage, `${APPLE_PREFIX}/disconnect`).catch(() => {});
    await resetMock(alicePage).catch(() => {});
    await alicePage.context().close();
  });

  test("78.1 connect with valid credentials succeeds", async () => {
    test.setTimeout(30_000);

    const resp = await apiPost(alicePage, `${APPLE_PREFIX}/connect`, {
      username: MOCK_USERNAME,
      app_specific_password: MOCK_PASSWORD,
    });
    expect(resp.status()).toBe(200);

    const body = await resp.json();
    expect(body).toHaveProperty("connection_id");
    expect(body).toHaveProperty("provider", "apple_caldav");
    expect(body).toHaveProperty("status", "connected");
    expect(body).toHaveProperty("credential_validation_status", "valid");
    expect(body).toHaveProperty("user_sub", ALICE_ID);
    expect(typeof body.connection_id).toBe("string");
    expect(body.connection_id.length).toBeGreaterThan(0);
    expect(typeof body.created_at).toBe("string");
    expect(typeof body.updated_at).toBe("string");
  });

  test("78.2 connect with invalid credentials fails", async () => {
    test.setTimeout(30_000);

    const resp = await apiPost(alicePage, `${APPLE_PREFIX}/connect`, {
      username: MOCK_USERNAME,
      app_specific_password: "wrong_password",
    });
    // The service calls validate_credentials which probes the mock; mock returns 401
    // which the service maps to CalendarIntegrationError(AUTH) -> HTTP 401
    expect(resp.status()).toBe(401);
  });

  test("78.3 status shows connected after connect", async () => {
    test.setTimeout(30_000);

    const resp = await apiGet(alicePage, `${APPLE_PREFIX}/status`);
    expect(resp.status()).toBe(200);

    const body = await resp.json();
    expect(body).toHaveProperty("provider", "apple_caldav");
    expect(body).toHaveProperty("connection_state");
    expect(body).toHaveProperty("is_connected", true);
    expect(body).toHaveProperty("connection_id");
    expect(body).toHaveProperty("credential_validation_status", "valid");
    expect(typeof body.connection_id).toBe("string");
    expect(body.connection_id!.length).toBeGreaterThan(0);

    // Structural fields should be present
    expect(body).toHaveProperty("selected_calendar_count");
    expect(body).toHaveProperty("conflict_count");
    expect(body).toHaveProperty("recent_conflicts");
    expect(typeof body.selected_calendar_count).toBe("number");
    expect(typeof body.conflict_count).toBe("number");
    expect(Array.isArray(body.recent_conflicts)).toBe(true);
  });

  test("78.4 list Apple calendars returns seeded calendars", async () => {
    test.setTimeout(30_000);

    const resp = await apiGet(alicePage, `${APPLE_PREFIX}/calendars`);
    expect(resp.status()).toBe(200);

    const body = (await resp.json()) as Array<{
      external_calendar_id: string;
      calendar_url: string;
      display_name: string;
      sync_enabled: boolean;
      sync_direction: string;
    }>;
    expect(Array.isArray(body)).toBe(true);
    expect(body.length).toBe(2);

    const names = body.map((c) => c.display_name).sort();
    expect(names).toEqual(["My Test Calendar", "Work Calendar"]);

    const ids = body.map((c) => c.external_calendar_id).sort();
    expect(ids).toEqual(["cal1", "cal2"]);

    for (const cal of body) {
      expect(typeof cal.calendar_url).toBe("string");
      expect(cal.calendar_url.length).toBeGreaterThan(0);
      expect(typeof cal.sync_enabled).toBe("boolean");
      expect(typeof cal.sync_direction).toBe("string");
    }
  });

  test("78.5 sync now returns sync results", async () => {
    test.setTimeout(60_000);

    // First, select cal1 as sync-enabled so sync/now has something to pull
    const selectResp = await apiPost(
      alicePage,
      `${APPLE_PREFIX}/calendars/select`,
      {
        calendars: [
          {
            external_calendar_id: "cal1",
            sync_enabled: true,
            sync_direction: "two_way",
          },
        ],
      },
    );
    expect(selectResp.status()).toBe(200);
    const selected = (await selectResp.json()) as Array<{
      external_calendar_id: string;
      sync_enabled: boolean;
    }>;
    const cal1Selected = selected.find(
      (c) => c.external_calendar_id === "cal1",
    );
    expect(cal1Selected).toBeDefined();
    expect(cal1Selected!.sync_enabled).toBe(true);

    // Trigger sync now
    const syncResp = await apiPost(alicePage, `${APPLE_PREFIX}/sync/now`);
    expect(syncResp.status()).toBe(200);

    const syncBody = await syncResp.json();
    expect(syncBody).toHaveProperty("triggered_calendar_count");
    expect(syncBody).toHaveProperty("success_count");
    expect(syncBody).toHaveProperty("failure_count");
    expect(syncBody).toHaveProperty("results");
    expect(typeof syncBody.triggered_calendar_count).toBe("number");
    expect(syncBody.triggered_calendar_count).toBeGreaterThanOrEqual(1);
    expect(typeof syncBody.success_count).toBe("number");
    expect(typeof syncBody.failure_count).toBe("number");
    expect(Array.isArray(syncBody.results)).toBe(true);
  });

  test("78.6 disconnect shows disconnected", async () => {
    test.setTimeout(30_000);

    const resp = await apiPost(alicePage, `${APPLE_PREFIX}/disconnect`);
    expect(resp.status()).toBe(200);

    const body = await resp.json();
    expect(body).toHaveProperty("provider", "apple_caldav");
    expect(body).toHaveProperty("status", "disconnected");
    expect(body).toHaveProperty("credential_validation_status", "disconnected");

    // Verify status also reflects disconnected
    const statusResp = await apiGet(alicePage, `${APPLE_PREFIX}/status`);
    expect(statusResp.status()).toBe(200);
    const statusBody = await statusResp.json();
    expect(statusBody.connection_state).toBe("disconnected");
    expect(statusBody.is_connected).toBe(false);
  });
});

test.describe("79 — Apple CalDAV Deep Integration Flows", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Start with a clean mock state and fresh seed data
    await resetMock(alicePage);
    await seedMock(alicePage);

    // Connect so all tests start with an active connection
    const connectResp = await apiPost(alicePage, `${APPLE_PREFIX}/connect`, {
      username: MOCK_USERNAME,
      app_specific_password: MOCK_PASSWORD,
    });
    expect(connectResp.status()).toBe(200);
    const connectBody = await connectResp.json();
    expect(connectBody.status).toBe("connected");
  });

  test.afterAll(async () => {
    await apiPost(alicePage, `${APPLE_PREFIX}/disconnect`).catch(() => {});
    await resetMock(alicePage).catch(() => {});
    await alicePage.context().close();
  });

  test("79.1 select calendars for sync persists selection", async () => {
    test.setTimeout(30_000);

    // Select cal1 with two_way sync and cal2 with read_only sync
    const selectResp = await apiPost(
      alicePage,
      `${APPLE_PREFIX}/calendars/select`,
      {
        calendars: [
          {
            external_calendar_id: "cal1",
            sync_enabled: true,
            sync_direction: "two_way",
          },
          {
            external_calendar_id: "cal2",
            sync_enabled: false,
            sync_direction: "read_only",
          },
        ],
      },
    );
    expect(selectResp.status()).toBe(200);

    const selected = (await selectResp.json()) as Array<{
      external_calendar_id: string;
      sync_enabled: boolean;
      sync_direction: string;
      display_name: string;
      calendar_url: string;
    }>;
    expect(Array.isArray(selected)).toBe(true);

    const cal1 = selected.find((c) => c.external_calendar_id === "cal1");
    const cal2 = selected.find((c) => c.external_calendar_id === "cal2");
    expect(cal1).toBeDefined();
    expect(cal1!.sync_enabled).toBe(true);
    expect(cal1!.sync_direction).toBe("two_way");
    expect(cal2).toBeDefined();
    expect(cal2!.sync_enabled).toBe(false);

    // Verify via list endpoint that selection persisted
    const listResp = await apiGet(alicePage, `${APPLE_PREFIX}/calendars`);
    expect(listResp.status()).toBe(200);
    const calendars = (await listResp.json()) as Array<{
      external_calendar_id: string;
      sync_enabled: boolean;
      sync_direction: string;
    }>;
    const cal1Listed = calendars.find(
      (c) => c.external_calendar_id === "cal1",
    );
    expect(cal1Listed).toBeDefined();
    expect(cal1Listed!.sync_enabled).toBe(true);
    expect(cal1Listed!.sync_direction).toBe("two_way");
  });

  test("79.2 initial import triggers import job", async () => {
    test.setTimeout(60_000);

    // Ensure cal1 is selected for sync before importing
    await apiPost(alicePage, `${APPLE_PREFIX}/calendars/select`, {
      calendars: [
        {
          external_calendar_id: "cal1",
          sync_enabled: true,
          sync_direction: "two_way",
        },
      ],
    });

    const importResp = await apiPost(
      alicePage,
      `${APPLE_PREFIX}/import/initial`,
      {
        external_calendar_ids: ["cal1"],
        lookback_days: 30,
        lookahead_days: 90,
      },
    );
    expect(importResp.status()).toBe(200);

    const runs = (await importResp.json()) as Array<{
      run_id: string;
      connection_id: string;
      external_calendar_id: string;
      run_type: string;
      status: string;
      started_at: string;
      historical_window_start: string;
      historical_window_end: string;
    }>;
    expect(Array.isArray(runs)).toBe(true);
    expect(runs.length).toBeGreaterThanOrEqual(1);

    const cal1Run = runs.find((r) => r.external_calendar_id === "cal1");
    expect(cal1Run).toBeDefined();
    expect(cal1Run!.run_id).toBeTruthy();
    expect(cal1Run!.connection_id).toBeTruthy();
    expect(typeof cal1Run!.run_type).toBe("string");
    expect(typeof cal1Run!.status).toBe("string");
    expect(typeof cal1Run!.started_at).toBe("string");
    expect(typeof cal1Run!.historical_window_start).toBe("string");
    expect(typeof cal1Run!.historical_window_end).toBe("string");
  });

  test("79.3 reconnect after disconnect restores connected status", async () => {
    test.setTimeout(30_000);

    // Disconnect first
    const disconnResp = await apiPost(
      alicePage,
      `${APPLE_PREFIX}/disconnect`,
    );
    expect(disconnResp.status()).toBe(200);
    const disconnBody = await disconnResp.json();
    expect(disconnBody.status).toBe("disconnected");

    // Verify status is disconnected
    const statusBefore = await apiGet(alicePage, `${APPLE_PREFIX}/status`);
    expect(statusBefore.status()).toBe(200);
    const beforeBody = await statusBefore.json();
    expect(beforeBody.is_connected).toBe(false);
    expect(beforeBody.connection_state).toBe("disconnected");

    // Reconnect with valid credentials
    const reconnResp = await apiPost(alicePage, `${APPLE_PREFIX}/connect`, {
      username: MOCK_USERNAME,
      app_specific_password: MOCK_PASSWORD,
    });
    expect(reconnResp.status()).toBe(200);
    const reconnBody = await reconnResp.json();
    expect(reconnBody.status).toBe("connected");
    expect(reconnBody.credential_validation_status).toBe("valid");
    expect(typeof reconnBody.connection_id).toBe("string");
    expect(reconnBody.connection_id.length).toBeGreaterThan(0);

    // Verify status is connected again
    const statusAfter = await apiGet(alicePage, `${APPLE_PREFIX}/status`);
    expect(statusAfter.status()).toBe(200);
    const afterBody = await statusAfter.json();
    expect(afterBody.is_connected).toBe(true);
    expect(afterBody.connection_state).not.toBe("disconnected");
    expect(afterBody.credential_validation_status).toBe("valid");
  });

  test("79.4 sync returns delta changes after seeding new events", async () => {
    test.setTimeout(60_000);

    // Ensure cal1 is selected for sync
    await apiPost(alicePage, `${APPLE_PREFIX}/calendars/select`, {
      calendars: [
        {
          external_calendar_id: "cal1",
          sync_enabled: true,
          sync_direction: "two_way",
        },
      ],
    });

    // First sync to establish a baseline (pulls the initial seeded event)
    const firstSyncResp = await apiPost(
      alicePage,
      `${APPLE_PREFIX}/sync/now`,
    );
    expect(firstSyncResp.status()).toBe(200);
    const firstSync = await firstSyncResp.json();
    expect(firstSync.triggered_calendar_count).toBeGreaterThanOrEqual(1);
    expect(typeof firstSync.success_count).toBe("number");
    expect(typeof firstSync.failure_count).toBe("number");

    // Seed a NEW event into the mock (simulates a change on the CalDAV server)
    const newIcalData =
      "BEGIN:VCALENDAR\r\n" +
      "VERSION:2.0\r\n" +
      "PRODID:-//Mock//Mock//EN\r\n" +
      "BEGIN:VEVENT\r\n" +
      "UID:evt_delta_79\r\n" +
      "DTSTART:20260715T140000Z\r\n" +
      "DTEND:20260715T150000Z\r\n" +
      "SUMMARY:Delta Sync Event 79\r\n" +
      "END:VEVENT\r\n" +
      "END:VCALENDAR\r\n";

    const seedResp = await alicePage.request.post(
      `${BASE}/mock/apple-caldav/seed`,
      {
        data: {
          events: {
            "cal1:evt_delta_79": newIcalData,
          },
        },
      },
    );
    expect(seedResp.status()).toBe(200);

    // Second sync should pick up the new event
    const secondSyncResp = await apiPost(
      alicePage,
      `${APPLE_PREFIX}/sync/now`,
    );
    expect(secondSyncResp.status()).toBe(200);
    const secondSync = await secondSyncResp.json();
    expect(secondSync.triggered_calendar_count).toBeGreaterThanOrEqual(1);
    expect(typeof secondSync.success_count).toBe("number");
    // The sync mechanism should report at least one successful calendar sync
    expect(secondSync.success_count).toBeGreaterThanOrEqual(1);
    expect(Array.isArray(secondSync.results)).toBe(true);
  });

  test("79.5 invalid credentials on reconnect shows proper error", async () => {
    test.setTimeout(30_000);

    // Disconnect the current connection
    const disconnResp = await apiPost(
      alicePage,
      `${APPLE_PREFIX}/disconnect`,
    );
    expect(disconnResp.status()).toBe(200);

    // Attempt to reconnect with wrong password — should fail with 401
    const badResp = await apiPost(alicePage, `${APPLE_PREFIX}/connect`, {
      username: MOCK_USERNAME,
      app_specific_password: "totally_wrong_password",
    });
    expect(badResp.status()).toBe(401);

    // Status should still be disconnected after failed reconnect attempt
    const statusResp = await apiGet(alicePage, `${APPLE_PREFIX}/status`);
    expect(statusResp.status()).toBe(200);
    const statusBody = await statusResp.json();
    expect(statusBody.is_connected).toBe(false);
    expect(statusBody.connection_state).toBe("disconnected");

    // Reconnect with correct credentials to leave things clean for afterAll
    const goodResp = await apiPost(alicePage, `${APPLE_PREFIX}/connect`, {
      username: MOCK_USERNAME,
      app_specific_password: MOCK_PASSWORD,
    });
    expect(goodResp.status()).toBe(200);
    expect((await goodResp.json()).status).toBe("connected");
  });
});
