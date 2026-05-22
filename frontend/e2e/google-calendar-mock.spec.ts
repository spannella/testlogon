/**
 * E2E tests for Google Calendar integration via the mock backend.
 *
 * Tests the full OAuth connect flow, status, provider calendar listing,
 * calendar mapping, sync run, and disconnect -- all driven through the
 * real integration endpoints that talk to the mock Google Calendar server.
 *
 * Auth: Cookie-based session for Alice (e2e_alice@test.local) with CSRF.
 *
 * Endpoints under test:
 *   POST /ui/calendar/integrations/google/connect/start
 *   GET  /ui/calendar/integrations/google/connect/callback?code=...&state=...
 *   GET  /ui/calendar/integrations/google/status
 *   GET  /ui/calendar/integrations/google/calendars
 *   POST /ui/calendar/integrations/google/mappings
 *   POST /ui/calendar/integrations/google/sync/run?mode=full
 *   POST /ui/calendar/integrations/google/disconnect
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";

// The mock Google user sub is "primary" so that connection_id becomes
// "google-primary" which matches GOOGLE_CALENDAR_CONNECTION_DEFAULT_ID.
const MOCK_GOOGLE_USER_SUB = "primary";
const MOCK_GOOGLE_USER_EMAIL = "e2e-gcal-user@gmail.com";
const MOCK_GOOGLE_CAL_ID = "e2e-primary@google.com";
const MOCK_GOOGLE_CAL_SUMMARY = "E2E Primary Calendar";
const MOCK_EVENT_ID = "e2e-event-001";

// ─── Session bootstrap ───────────────────────────────────────────────────────

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
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

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

// ─── API helpers ──────────────────────────────────────────────────────────────

/** POST with session cookies + CSRF header. */
async function apiPost(page: Page, path: string, body?: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": session.csrf_token },
  });
}

/** GET with session cookies. */
async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

/** POST to mock endpoint (no auth needed). */
async function mockPost(page: Page, path: string, body: object) {
  return page.request.post(`${API}${path}`, { data: body });
}

// ─── Seed helper ─────────────────────────────────────────────────────────────

/** Reset and seed the Google Calendar mock with test data. */
async function seedMock(page: Page) {
  const resetResp = await mockPost(page, "/mock/google-calendar/reset", {});
  expect(resetResp.ok()).toBe(true);

  const seedResp = await mockPost(page, "/mock/google-calendar/seed", {
    users: {
      default: {
        sub: MOCK_GOOGLE_USER_SUB,
        email: MOCK_GOOGLE_USER_EMAIL,
        email_verified: true,
        name: "E2E Google User",
        picture: "",
      },
    },
    calendars: {
      [MOCK_GOOGLE_CAL_ID]: {
        kind: "calendar#calendarListEntry",
        id: MOCK_GOOGLE_CAL_ID,
        summary: MOCK_GOOGLE_CAL_SUMMARY,
        accessRole: "owner",
        primary: true,
      },
    },
    events: {
      [MOCK_GOOGLE_CAL_ID]: {
        [MOCK_EVENT_ID]: {
          kind: "calendar#event",
          id: MOCK_EVENT_ID,
          status: "confirmed",
          summary: "E2E Test Meeting",
          start: { dateTime: "2026-06-01T10:00:00Z" },
          end: { dateTime: "2026-06-01T11:00:00Z" },
        },
      },
    },
  });
  expect(seedResp.ok()).toBe(true);
}

/** Run connect/start + callback to establish a connection. Returns callback data. */
async function connectGoogleCalendar(page: Page) {
  const startResp = await apiPost(
    page,
    "/ui/calendar/integrations/google/connect/start",
  );
  expect(startResp.ok()).toBe(true);
  const startData = await startResp.json();
  const state = startData.state as string;

  const callbackPath = `/ui/calendar/integrations/google/connect/callback?code=mock-auth-code&state=${encodeURIComponent(state)}`;
  const callbackResp = await apiGet(page, callbackPath);
  expect(callbackResp.ok()).toBe(true);
  return callbackResp.json();
}

// ─── 1. Connect flow ─────────────────────────────────────────────────────────

test.describe("1. Google Calendar connect/start", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await seedMock(page);
  });

  test.afterAll(async () => {
    await mockPost(page, "/mock/google-calendar/reset", {});
    await page?.close();
  });

  test("returns authorization URL, state, nonce, and expiry", async () => {
    const resp = await apiPost(
      page,
      "/ui/calendar/integrations/google/connect/start",
    );
    expect(resp.ok()).toBe(true);

    const data = await resp.json();
    expect(data.provider).toBe("google");
    expect(typeof data.authorization_url).toBe("string");
    expect(data.authorization_url).toContain("client_id=");
    expect(data.authorization_url).toContain("scope=");
    expect(typeof data.state).toBe("string");
    expect(data.state.length).toBeGreaterThan(10);
    expect(typeof data.nonce).toBe("string");
    expect(data.nonce.length).toBeGreaterThan(5);
    expect(typeof data.expires_at_utc).toBe("string");
    expect(data.expires_at_utc).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});

// ─── 2. Connect callback ─────────────────────────────────────────────────────

test.describe("2. Google Calendar connect/callback", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await seedMock(page);
  });

  test.afterAll(async () => {
    await mockPost(page, "/mock/google-calendar/reset", {});
    await page?.close();
  });

  test("exchanges code for connection with linked status", async () => {
    // Start the connect flow.
    const startResp = await apiPost(
      page,
      "/ui/calendar/integrations/google/connect/start",
    );
    expect(startResp.ok()).toBe(true);
    const { state } = await startResp.json();

    // Complete the callback.
    const callbackPath = `/ui/calendar/integrations/google/connect/callback?code=mock-auth-code-e2e&state=${encodeURIComponent(state)}`;
    const resp = await apiGet(page, callbackPath);
    expect(resp.ok()).toBe(true);

    const data = await resp.json();
    expect(data.provider).toBe("google");
    expect(typeof data.connection_id).toBe("string");
    expect(data.connection_id.length).toBeGreaterThan(0);
    expect(data.account_email).toBe(MOCK_GOOGLE_USER_EMAIL);
    expect(data.linked).toBe(true);
    expect(typeof data.updated_at_utc).toBe("string");
  });
});

// ─── 3. Status, calendars, mapping, sync, disconnect ─────────────────────────

test.describe("3. Google Calendar integration operations", () => {
  let page: Page;
  let internalCalendarId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await seedMock(page);

    // Establish a connection so all subsequent tests can operate on it.
    await connectGoogleCalendar(page);
  });

  test.afterAll(async () => {
    await mockPost(page, "/mock/google-calendar/reset", {});
    await page?.close();
  });

  test("status shows connection_active after connecting", async () => {
    const resp = await apiGet(
      page,
      "/ui/calendar/integrations/google/status",
    );
    expect(resp.ok()).toBe(true);

    const data = await resp.json();
    expect(data.provider).toBe("google");
    expect(data.sync_enabled).toBe(true);
    expect(data.connection_active).toBe(true);
    expect(typeof data.sync_health).toBe("string");
    expect(typeof data.last_sync_status).toBe("string");
    expect(data.in_rollout_cohort).toBe(true);
    expect(data.reauth_required).toBe(false);
    expect(typeof data.rollout_mode).toBe("string");
    expect(typeof data.rollout_percent).toBe("number");
  });

  test("list provider calendars returns seeded calendar", async () => {
    const resp = await apiGet(
      page,
      "/ui/calendar/integrations/google/calendars",
    );
    expect(resp.ok()).toBe(true);

    const data = await resp.json();
    expect(Array.isArray(data.calendars)).toBe(true);
    expect(data.calendars.length).toBeGreaterThanOrEqual(1);

    const primaryCal = data.calendars.find(
      (c: { google_calendar_id: string }) =>
        c.google_calendar_id === MOCK_GOOGLE_CAL_ID,
    );
    expect(primaryCal).toBeTruthy();
    expect(primaryCal.summary).toBe(MOCK_GOOGLE_CAL_SUMMARY);
    expect(primaryCal.primary).toBe(true);
    expect(primaryCal.access_role).toBe("owner");
  });

  test("create calendar mapping links internal to Google calendar", async () => {
    // Create an internal calendar owned by Alice.
    const calResp = await apiPost(page, "/ui/calendars", {
      name: `E2E GCal Map ${Date.now()}`,
      timezone: "UTC",
    });
    expect(calResp.ok()).toBe(true);
    const calData = await calResp.json();
    internalCalendarId = calData.calendar_id;
    expect(typeof internalCalendarId).toBe("string");

    // Map internal calendar to the seeded Google calendar.
    const mapResp = await apiPost(
      page,
      "/ui/calendar/integrations/google/mappings",
      {
        internal_calendar_id: internalCalendarId,
        google_calendar_id: MOCK_GOOGLE_CAL_ID,
      },
    );
    expect(mapResp.ok()).toBe(true);

    const mapData = await mapResp.json();
    expect(typeof mapData.mapping_id).toBe("string");
    expect(mapData.mapping_id.length).toBeGreaterThan(0);
    expect(mapData.provider).toBe("google");
    expect(mapData.user_sub).toBe(ALICE_ID);
    expect(mapData.internal_calendar_id).toBe(internalCalendarId);
    expect(mapData.google_calendar_id).toBe(MOCK_GOOGLE_CAL_ID);
    expect(mapData.active).toBe(true);
    expect(typeof mapData.created_at_utc).toBe("string");
    expect(typeof mapData.updated_at_utc).toBe("string");
  });

  test("sync/run with mode=full returns accepted with metrics", async () => {
    const resp = await apiPost(
      page,
      "/ui/calendar/integrations/google/sync/run?mode=full",
    );
    expect(resp.ok()).toBe(true);

    const data = await resp.json();
    expect(data.accepted).toBe(true);
    expect(data.mode).toBe("full");
    expect(data.rate_limited).toBe(false);
    expect(typeof data.metrics).toBe("object");
  });

  test("disconnect revokes tokens and marks connection inactive", async () => {
    const resp = await apiPost(
      page,
      "/ui/calendar/integrations/google/disconnect",
    );
    expect(resp.ok()).toBe(true);

    const data = await resp.json();
    expect(data.provider).toBe("google");
    expect(typeof data.connection_id).toBe("string");
    expect(data.active).toBe(false);
    expect(data.revoked).toBe(true);
    expect(data.revoke_status).toBe("revoked");
    expect(typeof data.disconnected_at_utc).toBe("string");

    // Confirm status endpoint now shows disconnected.
    const statusResp = await apiGet(
      page,
      "/ui/calendar/integrations/google/status",
    );
    expect(statusResp.ok()).toBe(true);
    const statusData = await statusResp.json();
    expect(statusData.connection_active).toBe(false);
  });
});
