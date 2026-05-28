import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

/* ------------------------------------------------------------------ */
/*  Constants & helpers                                                */
/* ------------------------------------------------------------------ */

const API = "http://localhost:8000";
const TS = Date.now();

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
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
}

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body: object,
) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiDelete(page: Page, identity: string, path: string) {
  const s = getSessions()[identity];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": s.csrf_token },
  });
}

/* ------------------------------------------------------------------ */
/*  Section 119 — Broadcast Scheduling API                             */
/* ------------------------------------------------------------------ */

test.describe("Broadcast Scheduling — API", () => {
  let rootPage: Page;
  let profileId: string;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    rootPage = await ctx.newPage();
    await injectAuth(rootPage, "root");

    // Create a broadcast profile for scheduling tests
    const profileResp = await apiPost(rootPage, "root", "/broadcast/profiles", {
      name: `sched-test-profile-${TS}`,
      region: "us-east-1",
      rendition_preset: "720p30",
    });
    expect(profileResp.status()).toBe(201);
    profileId = (await profileResp.json()).id;
  });

  test.afterAll(async () => {
    await rootPage.context().close();
  });

  test("119.1 Schedule a broadcast 30 minutes in the future", async () => {
    // Create a draft session
    const createResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(createResp.status()).toBe(201);
    sessionId = (await createResp.json()).id;

    const scheduledAt = Math.floor(Date.now() / 1000) + 1800; // 30 min from now
    const resp = await apiPost(rootPage, "root", `/broadcast/sessions/${sessionId}/schedule`, {
      scheduled_at: scheduledAt,
      name: `Scheduled Show ${TS}`,
      description: "E2E scheduling test",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("scheduled");
    expect(body.scheduled_at).toBe(scheduledAt);
    expect(body.schedule_status).toBe("scheduled");
    expect(body.name).toBe(`Scheduled Show ${TS}`);
  });

  test("119.2 Scheduling with scheduled_at in the past returns 400", async () => {
    // Create another draft session
    const createResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(createResp.status()).toBe(201);
    const newSessionId = (await createResp.json()).id;

    const pastTime = Math.floor(Date.now() / 1000) - 600;
    const resp = await apiPost(rootPage, "root", `/broadcast/sessions/${newSessionId}/schedule`, {
      scheduled_at: pastTime,
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail.code).toBe("SCHEDULE_TOO_SOON");
  });

  test("119.3 Scheduling too soon (< min lead time) returns 400", async () => {
    // Create another draft session
    const createResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(createResp.status()).toBe(201);
    const newSessionId = (await createResp.json()).id;

    const tooSoon = Math.floor(Date.now() / 1000) + 60; // 1 min — less than min_lead_time (300s)
    const resp = await apiPost(rootPage, "root", `/broadcast/sessions/${newSessionId}/schedule`, {
      scheduled_at: tooSoon,
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail.code).toBe("SCHEDULE_TOO_SOON");
  });

  test("119.4 Reschedule a broadcast updates scheduled_at", async () => {
    // sessionId from test 119.1 should be in "scheduled" state
    const newScheduledAt = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
    const resp = await apiPost(rootPage, "root", `/broadcast/sessions/${sessionId}/reschedule`, {
      scheduled_at: newScheduledAt,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.scheduled_at).toBe(newScheduledAt);
    expect(body.schedule_status).toBe("scheduled");
  });

  test("119.5 Cancel scheduled broadcast returns cancelled status", async () => {
    const resp = await apiPost(rootPage, "root", `/broadcast/sessions/${sessionId}/cancel-schedule`, {});
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("cancelled");
    expect(body.schedule_status).toBe("cancelled");
    expect(body.cancelled_at).toBeTruthy();
  });

  test("119.6 Cancel non-scheduled session returns 409", async () => {
    // sessionId is now cancelled, trying to cancel again should fail
    const resp = await apiPost(rootPage, "root", `/broadcast/sessions/${sessionId}/cancel-schedule`, {});
    expect(resp.status()).toBe(409);
  });

  test("119.7 List scheduled broadcasts", async () => {
    // Create and schedule a new session
    const createResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(createResp.status()).toBe(201);
    const newSessionId = (await createResp.json()).id;

    const scheduledAt = Math.floor(Date.now() / 1000) + 7200;
    await apiPost(rootPage, "root", `/broadcast/sessions/${newSessionId}/schedule`, {
      scheduled_at: scheduledAt,
      name: `Listed Show ${TS}`,
    });

    const listResp = await apiGet(rootPage, "/broadcast/sessions/scheduled");
    expect(listResp.status()).toBe(200);
    const listBody = await listResp.json();
    expect(listBody.items.length).toBeGreaterThanOrEqual(1);
    const found = listBody.items.find((s: { id: string }) => s.id === newSessionId);
    expect(found).toBeTruthy();
    expect(found.schedule_status).toBe("scheduled");

    // Cleanup: cancel it
    await apiPost(rootPage, "root", `/broadcast/sessions/${newSessionId}/cancel-schedule`, {});
  });

  test("119.8 Register and cancel reminder", async () => {
    // Create and schedule a session
    const createResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(createResp.status()).toBe(201);
    const remSessionId = (await createResp.json()).id;

    const scheduledAt = Math.floor(Date.now() / 1000) + 7200; // 2 hours
    await apiPost(rootPage, "root", `/broadcast/sessions/${remSessionId}/schedule`, {
      scheduled_at: scheduledAt,
      name: `Reminder Test ${TS}`,
    });

    // Register reminder
    const remResp = await apiPost(rootPage, "root", `/broadcast/sessions/${remSessionId}/remind-me`, {});
    expect(remResp.status()).toBe(200);
    const remBody = await remResp.json();
    expect(remBody.ok).toBe(true);
    expect(remBody.remind_at).toBeLessThan(scheduledAt);

    // Cancel reminder
    const cancelResp = await apiDelete(rootPage, "root", `/broadcast/sessions/${remSessionId}/remind-me`);
    expect(cancelResp.status()).toBe(200);
    const cancelBody = await cancelResp.json();
    expect(cancelBody.ok).toBe(true);

    // Cleanup
    await apiPost(rootPage, "root", `/broadcast/sessions/${remSessionId}/cancel-schedule`, {});
  });

  test("119.9 Schedule already-live session fails", async () => {
    // Create a session and start it (makes it live)
    const createResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(createResp.status()).toBe(201);
    const liveSessionId = (await createResp.json()).id;

    // Start it
    const startResp = await apiPost(rootPage, "root", `/broadcast/sessions/${liveSessionId}/start`, {
      reason: "test-start",
    });
    expect(startResp.status()).toBe(202);

    // Try to schedule it — should fail (status is not "draft")
    const scheduledAt = Math.floor(Date.now() / 1000) + 3600;
    const schedResp = await apiPost(rootPage, "root", `/broadcast/sessions/${liveSessionId}/schedule`, {
      scheduled_at: scheduledAt,
    });
    expect(schedResp.status()).toBe(409);

    // Stop it to clean up
    await apiPost(rootPage, "root", `/broadcast/sessions/${liveSessionId}/stop`, {
      reason: "test-stop",
    });
  });

  test("119.10 Calendar invite downloads as .ics file", async () => {
    // Create and schedule a session
    const createResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(createResp.status()).toBe(201);
    const icalSessionId = (await createResp.json()).id;

    const scheduledAt = Math.floor(Date.now() / 1000) + 3600;
    await apiPost(rootPage, "root", `/broadcast/sessions/${icalSessionId}/schedule`, {
      scheduled_at: scheduledAt,
      name: `ICal Test ${TS}`,
    });

    const icalResp = await apiGet(rootPage, `/broadcast/sessions/${icalSessionId}/ical`);
    expect(icalResp.status()).toBe(200);

    const contentType = icalResp.headers()["content-type"];
    expect(contentType).toContain("text/calendar");

    const body = await icalResp.text();
    expect(body).toContain("BEGIN:VCALENDAR");
    expect(body).toContain("BEGIN:VEVENT");
    expect(body).toContain(`SUMMARY:ICal Test ${TS}`);
    expect(body).toContain("DTSTART:");
    expect(body).toContain("DTEND:");
    expect(body).toContain("BEGIN:VALARM");
    expect(body).toContain("END:VCALENDAR");

    // Cleanup
    await apiPost(rootPage, "root", `/broadcast/sessions/${icalSessionId}/cancel-schedule`, {});
  });
});
