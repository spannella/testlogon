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
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, resolveIdentityId } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = resolveIdentityId("e2e_alice@test.local");

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
    _sessions = loadSessions();
  }
  return _sessions!;
}

function refreshSessions(): Record<string, SessionData> {
  _sessions = null;
  return getSessions();
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

test.describe.serial("3. Google Calendar integration operations", () => {
  let page: Page;
  let internalCalendarId: string;

  test.beforeAll(async ({ browser }) => {
    refreshSessions();
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

// ─── 4. Deep integration flows ──────────────────────────────────────────────

test.describe("4. Google Calendar deep integration flows", () => {
  let page: Page;
  const TS = Date.now();

  // Second Google calendar for multi-mapping tests.
  const MOCK_GOOGLE_CAL_ID_2 = "e2e-secondary@google.com";
  const MOCK_GOOGLE_CAL_SUMMARY_2 = "E2E Secondary Calendar";

  // Event IDs unique to this section.
  const SYNC_EVENT_A = `e2e-sync-a-${TS}`;
  const SYNC_EVENT_B = `e2e-sync-b-${TS}`;
  const SYNC_EVENT_C = `e2e-sync-c-${TS}`;
  const INCR_EVENT = `e2e-incr-${TS}`;
  const SECONDARY_EVENT = `e2e-sec-${TS}`;
  const CONFLICT_EVENT_1 = `e2e-conflict1-${TS}`;
  const CONFLICT_EVENT_2 = `e2e-conflict2-${TS}`;

  /** Seed mock with one or two calendars and given events map. */
  async function seedWithEvents(
    events: Record<string, Record<string, object>>,
    extraCalendars?: Record<string, object>,
  ) {
    const resetResp = await mockPost(page, "/mock/google-calendar/reset", {});
    expect(resetResp.ok()).toBe(true);

    const calendars: Record<string, object> = {
      [MOCK_GOOGLE_CAL_ID]: {
        kind: "calendar#calendarListEntry",
        id: MOCK_GOOGLE_CAL_ID,
        summary: MOCK_GOOGLE_CAL_SUMMARY,
        accessRole: "owner",
        primary: true,
      },
      ...(extraCalendars ?? {}),
    };

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
      calendars,
      events,
    });
    expect(seedResp.ok()).toBe(true);
  }

  /** Create an internal calendar and return its id. */
  async function createInternalCalendar(name: string): Promise<string> {
    const resp = await apiPost(page, "/ui/calendars", {
      name,
      timezone: "UTC",
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    return data.calendar_id as string;
  }

  /** Create a mapping between internal and google calendar. */
  async function createMapping(
    internalCalId: string,
    googleCalId: string,
  ): Promise<string> {
    const resp = await apiPost(
      page,
      "/ui/calendar/integrations/google/mappings",
      {
        internal_calendar_id: internalCalId,
        google_calendar_id: googleCalId,
      },
    );
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    return data.mapping_id as string;
  }

  /** List events for an internal calendar. */
  async function listInternalEvents(
    calendarId: string,
  ): Promise<Array<{ event_id: string; name: string; start_utc: string; end_utc: string; sync_state?: string; sync_conflict_reason?: string }>> {
    const resp = await apiGet(
      page,
      `/ui/calendars/${calendarId}/events`,
    );
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    return data.events ?? [];
  }

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
  });

  test.afterAll(async () => {
    await mockPost(page, "/mock/google-calendar/reset", {});
    await page?.close();
  });

  test("4.1 full sync completes without errors and reports metrics", async () => {
    await seedWithEvents({
      [MOCK_GOOGLE_CAL_ID]: {
        [SYNC_EVENT_A]: {
          kind: "calendar#event",
          id: SYNC_EVENT_A,
          status: "confirmed",
          summary: `Sync Meeting A ${TS}`,
          start: { dateTime: "2026-07-01T09:00:00Z" },
          end: { dateTime: "2026-07-01T10:00:00Z" },
        },
        [SYNC_EVENT_B]: {
          kind: "calendar#event",
          id: SYNC_EVENT_B,
          status: "confirmed",
          summary: `Sync Meeting B ${TS}`,
          start: { dateTime: "2026-07-01T11:00:00Z" },
          end: { dateTime: "2026-07-01T12:00:00Z" },
        },
      },
    });

    await connectGoogleCalendar(page);
    const internalCalId = await createInternalCalendar(`E2E SyncCal ${TS}`);
    await createMapping(internalCalId, MOCK_GOOGLE_CAL_ID);

    const syncResp = await apiPost(
      page,
      "/ui/calendar/integrations/google/sync/run?mode=full",
    );
    expect(syncResp.ok()).toBe(true);
    const syncData = await syncResp.json();
    expect(syncData.accepted).toBe(true);
    expect(syncData.mode).toBe("full");
    expect(syncData.metrics).toBeDefined();
    expect(syncData.metrics.errors).toBe(0);

    await apiPost(page, "/ui/calendar/integrations/google/disconnect");
  });

  test("4.2 second full sync picks up newly added events", async () => {
    // Fresh seed with one event.
    await seedWithEvents({
      [MOCK_GOOGLE_CAL_ID]: {
        [SYNC_EVENT_C]: {
          kind: "calendar#event",
          id: SYNC_EVENT_C,
          status: "confirmed",
          summary: `Incr Base ${TS}`,
          start: { dateTime: "2026-08-01T09:00:00Z" },
          end: { dateTime: "2026-08-01T10:00:00Z" },
        },
      },
    });

    await connectGoogleCalendar(page);
    const internalCalId = await createInternalCalendar(`E2E IncrCal ${TS}`);
    await createMapping(internalCalId, MOCK_GOOGLE_CAL_ID);

    // First full sync imports the seeded event.
    const fullResp = await apiPost(
      page,
      "/ui/calendar/integrations/google/sync/run?mode=full",
    );
    expect(fullResp.ok()).toBe(true);
    const fullData = await fullResp.json();
    expect(fullData.accepted).toBe(true);
    expect(fullData.metrics.created).toBeGreaterThanOrEqual(1);
    expect(fullData.metrics.errors).toBe(0);

    // Add a new event to mock AFTER first sync.
    const addResp = await page.request.post(
      `${API}/mock/google-calendar/calendar/v3/calendars/${MOCK_GOOGLE_CAL_ID}/events`,
      {
        headers: { Authorization: "Bearer mock-at-placeholder" },
        data: {
          id: INCR_EVENT,
          summary: `Incr New ${TS}`,
          start: { dateTime: "2026-08-02T14:00:00Z" },
          end: { dateTime: "2026-08-02T15:00:00Z" },
        },
      },
    );
    expect(addResp.ok()).toBe(true);

    // Second full sync should pick up the new event.
    const syncResp2 = await apiPost(
      page,
      "/ui/calendar/integrations/google/sync/run?mode=full",
    );
    expect(syncResp2.ok()).toBe(true);
    const syncData2 = await syncResp2.json();
    expect(syncData2.accepted).toBe(true);
    // Either created (new) or updated (re-import) — the new event is processed.
    expect(syncData2.metrics.created + syncData2.metrics.updated).toBeGreaterThanOrEqual(1);
    expect(syncData2.metrics.errors).toBe(0);

    await apiPost(page, "/ui/calendar/integrations/google/disconnect");
  });

  test("4.3 multiple calendar mappings — sync processes both calendars", async () => {
    // Seed with two Google calendars, each with one event.
    await seedWithEvents(
      {
        [MOCK_GOOGLE_CAL_ID]: {
          [`primary-evt-${TS}`]: {
            kind: "calendar#event",
            id: `primary-evt-${TS}`,
            status: "confirmed",
            summary: `Primary Evt ${TS}`,
            start: { dateTime: "2026-09-01T10:00:00Z" },
            end: { dateTime: "2026-09-01T11:00:00Z" },
          },
        },
        [MOCK_GOOGLE_CAL_ID_2]: {
          [SECONDARY_EVENT]: {
            kind: "calendar#event",
            id: SECONDARY_EVENT,
            status: "confirmed",
            summary: `Secondary Evt ${TS}`,
            start: { dateTime: "2026-09-02T10:00:00Z" },
            end: { dateTime: "2026-09-02T11:00:00Z" },
          },
        },
      },
      {
        [MOCK_GOOGLE_CAL_ID_2]: {
          kind: "calendar#calendarListEntry",
          id: MOCK_GOOGLE_CAL_ID_2,
          summary: MOCK_GOOGLE_CAL_SUMMARY_2,
          accessRole: "writer",
          primary: false,
        },
      },
    );

    await connectGoogleCalendar(page);

    // Create two internal calendars, one per Google calendar.
    const internalCal1 = await createInternalCalendar(`E2E Multi1 ${TS}`);
    const internalCal2 = await createInternalCalendar(`E2E Multi2 ${TS}`);
    await createMapping(internalCal1, MOCK_GOOGLE_CAL_ID);
    await createMapping(internalCal2, MOCK_GOOGLE_CAL_ID_2);

    // Full sync should process both mappings.
    const syncResp = await apiPost(
      page,
      "/ui/calendar/integrations/google/sync/run?mode=full",
    );
    expect(syncResp.ok()).toBe(true);
    const syncData = await syncResp.json();
    // At least 2 events should be created (one per calendar).
    expect(syncData.metrics.created).toBeGreaterThanOrEqual(2);
    expect(syncData.metrics.errors).toBe(0);
    // Both calendars scanned.
    expect(syncData.metrics.google_events_scanned).toBeGreaterThanOrEqual(2);

    // Verify provider calendars list shows both.
    const calsResp = await apiGet(
      page,
      "/ui/calendar/integrations/google/calendars",
    );
    expect(calsResp.ok()).toBe(true);
    const calsData = await calsResp.json();
    const primary = calsData.calendars.find(
      (c: { google_calendar_id: string }) =>
        c.google_calendar_id === MOCK_GOOGLE_CAL_ID,
    );
    const secondary = calsData.calendars.find(
      (c: { google_calendar_id: string }) =>
        c.google_calendar_id === MOCK_GOOGLE_CAL_ID_2,
    );
    expect(primary).toBeTruthy();
    expect(secondary).toBeTruthy();

    await apiPost(page, "/ui/calendar/integrations/google/disconnect");
  });

  test("4.4 reconnect after disconnect restores connection", async () => {
    // Seed fresh mock.
    await seedWithEvents({
      [MOCK_GOOGLE_CAL_ID]: {
        [`recon-evt-${TS}`]: {
          kind: "calendar#event",
          id: `recon-evt-${TS}`,
          status: "confirmed",
          summary: `Recon Evt ${TS}`,
          start: { dateTime: "2026-10-01T10:00:00Z" },
          end: { dateTime: "2026-10-01T11:00:00Z" },
        },
      },
    });

    // Connect, verify active, disconnect.
    await connectGoogleCalendar(page);
    let statusResp = await apiGet(
      page,
      "/ui/calendar/integrations/google/status",
    );
    expect(statusResp.ok()).toBe(true);
    let statusData = await statusResp.json();
    expect(statusData.connection_active).toBe(true);

    const disconnResp = await apiPost(
      page,
      "/ui/calendar/integrations/google/disconnect",
    );
    expect(disconnResp.ok()).toBe(true);
    const disconnData = await disconnResp.json();
    expect(disconnData.active).toBe(false);

    // Status should show inactive.
    statusResp = await apiGet(
      page,
      "/ui/calendar/integrations/google/status",
    );
    expect(statusResp.ok()).toBe(true);
    statusData = await statusResp.json();
    expect(statusData.connection_active).toBe(false);

    // Reconnect via new OAuth flow.
    await connectGoogleCalendar(page);

    // Status should be active again.
    statusResp = await apiGet(
      page,
      "/ui/calendar/integrations/google/status",
    );
    expect(statusResp.ok()).toBe(true);
    statusData = await statusResp.json();
    expect(statusData.connection_active).toBe(true);
    expect(statusData.sync_enabled).toBe(true);

    // Can list calendars after reconnect.
    const calsResp = await apiGet(
      page,
      "/ui/calendar/integrations/google/calendars",
    );
    expect(calsResp.ok()).toBe(true);
    const calsData = await calsResp.json();
    expect(calsData.calendars.length).toBeGreaterThanOrEqual(1);

    await apiPost(page, "/ui/calendar/integrations/google/disconnect");
  });

  test("4.5 sync imports overlapping events without errors", async () => {
    // Seed with two events at the exact same time slot.
    await seedWithEvents({
      [MOCK_GOOGLE_CAL_ID]: {
        [CONFLICT_EVENT_1]: {
          kind: "calendar#event",
          id: CONFLICT_EVENT_1,
          status: "confirmed",
          summary: `Conflict A ${TS}`,
          start: { dateTime: "2026-11-01T14:00:00Z" },
          end: { dateTime: "2026-11-01T15:00:00Z" },
        },
        [CONFLICT_EVENT_2]: {
          kind: "calendar#event",
          id: CONFLICT_EVENT_2,
          status: "confirmed",
          summary: `Conflict B ${TS}`,
          start: { dateTime: "2026-11-01T14:00:00Z" },
          end: { dateTime: "2026-11-01T15:00:00Z" },
        },
      },
    });

    await connectGoogleCalendar(page);
    const internalCalId = await createInternalCalendar(`E2E Conflict ${TS}`);
    await createMapping(internalCalId, MOCK_GOOGLE_CAL_ID);

    // Full sync should import both events (sync doesn't reject conflicts,
    // it imports them — conflicts are a scheduling-layer concern, not sync).
    const syncResp = await apiPost(
      page,
      "/ui/calendar/integrations/google/sync/run?mode=full",
    );
    expect(syncResp.ok()).toBe(true);
    const syncData = await syncResp.json();
    // Both overlapping events should be imported without errors.
    expect(syncData.metrics.created).toBeGreaterThanOrEqual(2);
    expect(syncData.metrics.errors).toBe(0);
    expect(syncData.metrics.google_events_scanned).toBeGreaterThanOrEqual(2);

    await apiPost(page, "/ui/calendar/integrations/google/disconnect");
  });

  test("4.6 sync after disconnect fails gracefully", async () => {
    // Seed a minimal calendar and event.
    await seedWithEvents({
      [MOCK_GOOGLE_CAL_ID]: {
        [`token-evt-${TS}`]: {
          kind: "calendar#event",
          id: `token-evt-${TS}`,
          status: "confirmed",
          summary: `Token Evt ${TS}`,
          start: { dateTime: "2026-12-01T10:00:00Z" },
          end: { dateTime: "2026-12-01T11:00:00Z" },
        },
      },
    });

    await connectGoogleCalendar(page);

    // Verify connection is active.
    const statusResp = await apiGet(
      page,
      "/ui/calendar/integrations/google/status",
    );
    expect(statusResp.ok()).toBe(true);
    const statusData = await statusResp.json();
    expect(statusData.connection_active).toBe(true);

    // Disconnect.
    const disconnResp = await apiPost(
      page,
      "/ui/calendar/integrations/google/disconnect",
    );
    expect(disconnResp.ok()).toBe(true);

    // Attempting sync after disconnect should fail (connection inactive).
    const syncResp = await apiPost(
      page,
      "/ui/calendar/integrations/google/sync/run?mode=full",
    );
    // Should return an error (403/404/422) since connection is no longer active.
    expect(syncResp.ok()).toBe(false);
    expect(syncResp.status()).toBeGreaterThanOrEqual(400);

    // Attempting to list calendars should also fail.
    const calsResp = await apiGet(
      page,
      "/ui/calendar/integrations/google/calendars",
    );
    expect(calsResp.ok()).toBe(false);
    expect(calsResp.status()).toBeGreaterThanOrEqual(400);

    await mockPost(page, "/mock/google-calendar/reset", {});
  });
});
