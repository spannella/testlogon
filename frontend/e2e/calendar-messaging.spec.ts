/**
 * E2E tests for Calendar Integration in Messenger.
 *
 * Tests three new message kinds:
 *   - calendar_share  — share calendar access + optional booking link
 *   - calendar_event  — share a specific event snapshot
 *   - meeting_poll    — Doodle-style scheduling poll with vote + confirm
 *
 * Also tests:
 *   - Public event page (/event/:calendarId/:eventId) — no auth required
 *   - iCal download endpoints (public + auth)
 *   - ComposeBar CalendarDays dropdown (UI)
 *   - MessageBubble card rendering (UI)
 *   - MeetingPollCard vote + confirm flow (UI)
 *
 * Design principles (resilient to retry-spawned workers):
 *   - Each describe section creates its own calendar / event / poll resources.
 *   - API sections use `request` fixture with Bearer token auth — no browser page.
 *   - UI sections use `browser.newPage()` + `injectAuth`.
 *   - Module-level state is only used for constants (slot times, etc.).
 *
 * Sections:
 *   1.  Calendar share — send via API (read permission, no booking link)
 *   2.  Calendar share — send via API (write permission + booking link)
 *   3.  Calendar share — calendar granted to recipient (DDB + API verification)
 *   4.  Calendar event share — send via API and verify snapshot fields
 *   5.  Calendar event share — public event page (no auth)
 *   6.  Calendar event share — iCal download (public endpoint)
 *   7.  Calendar event share — iCal download (authenticated endpoint)
 *   8.  Meeting poll — create via API and verify response shape
 *   9.  Meeting poll — GET poll state (slots, counts, my_vote)
 *   10. Meeting poll — vote on slots
 *   11. Meeting poll — confirm a slot (no calendar event creation)
 *   12. Meeting poll — confirm a slot + create calendar event
 *   13. Meeting poll — validation errors (too few slots, empty title)
 *   14. UI — ComposeBar CalendarDays dropdown opens dialogs
 *   15. UI — calendar_share MessageBubble card rendering
 *   16. UI — calendar_event MessageBubble card rendering
 *   17. UI — meeting_poll MessageBubble card + voting UI
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
import { usingCpp, cppBearerPost, cppBearerGet } from "./helpers/cpp-seed-messaging-calls";

// ─── Constants ────────────────────────────────────────────────────────────────

// Repo root from the Playwright run cwd (frontend/) so seeders/env resolve in CI
// (/home/runner/...) and on any host, not just the dev box.
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");
const BASE   = "http://localhost:3000";
const PYTHON = `${REPO_ROOT}/.venv/bin/python3`;

const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";

// Slot times for meeting polls (reused across sections)
const SLOT1_START = "2026-07-10T09:00:00Z";
const SLOT1_END   = "2026-07-10T09:30:00Z";
const SLOT2_START = "2026-07-10T14:00:00Z";
const SLOT2_END   = "2026-07-10T14:30:00Z";
const SLOT3_START = "2026-07-11T10:00:00Z";
const SLOT3_END   = "2026-07-11T10:30:00Z";

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
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

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
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

// ─── API request helpers ──────────────────────────────────────────────────────

type APIRequestContext = import("@playwright/test").APIRequestContext;
type Browser = import("@playwright/test").Browser;

/** POST as any user with dev-mode Bearer token (messaging endpoints only). */
async function apiPost(req: APIRequestContext, path: string, body: object, userId: string) {
  const sub = getSessions()[userId]?.user_sub ?? userId; // non-member fallback: raw id (cpp dev raw-sub) -> non-participant 403
  if (usingCpp()) return cppBearerPost(path, body, sub);
  return req.post(`${API}${path}`, {
    data: body,
    headers: { Authorization: `Bearer ${sub}` },
  });
}

/** GET as any user with dev-mode Bearer token (messaging endpoints only). */
async function apiGet(req: APIRequestContext, path: string, userId: string) {
  const sub = getSessions()[userId]?.user_sub ?? userId; // non-member fallback: raw id (cpp dev raw-sub) -> non-participant 403
  if (usingCpp()) return cppBearerGet(path, sub);
  return req.get(`${API}${path}`, {
    headers: { Authorization: `Bearer ${sub}` },
  });
}

// ─── Browser API helpers (for UI tests that need session cookies) ─────────────

async function pagePost(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function pageGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

/** A minimal response-like object with body already buffered (safe after context.close). */
interface BufferedResponse {
  ok: () => boolean;
  status: () => number;
  text: () => Promise<string>;
  json: <T = unknown>() => Promise<T>;
  headers: () => Record<string, string>;
}

/**
 * POST using session auth (calendar endpoints use require_ui_session, not Bearer).
 * Buffers the response body before closing the context so callers can read it freely.
 */
async function sessionPost(browser: Browser, userId: string, path: string, body: object): Promise<BufferedResponse> {
  const session = getSessions()[userId];
  const ctx = await browser.newContext();
  await ctx.addCookies(session.cookies);
  let status: number;
  let text: string;
  let hdrs: Record<string, string> = {};
  try {
    const resp = await ctx.request.post(`${API}${path}`, {
      data: body,
      headers: { "x-csrf-token": session.csrf_token },
    });
    status = resp.status();
    text   = await resp.text();
    hdrs   = resp.headers();
  } finally {
    await ctx.close();
  }
  return {
    ok:      () => status >= 200 && status < 300,
    status:  () => status,
    text:    async () => text,
    json:    async <T = unknown>() => JSON.parse(text) as T,
    headers: () => hdrs,
  };
}

/**
 * GET using session auth (calendar endpoints use require_ui_session, not Bearer).
 * Buffers the response body before closing the context.
 */
async function sessionGet(browser: Browser, userId: string, path: string): Promise<BufferedResponse> {
  const session = getSessions()[userId];
  const ctx = await browser.newContext();
  await ctx.addCookies(session.cookies);
  let status: number;
  let text: string;
  let hdrs: Record<string, string> = {};
  try {
    const resp = await ctx.request.get(`${API}${path}`);
    status = resp.status();
    text   = await resp.text();
    hdrs   = resp.headers();
  } finally {
    await ctx.close();
  }
  return {
    ok:      () => status >= 200 && status < 300,
    status:  () => status,
    text:    async () => text,
    json:    async <T = unknown>() => JSON.parse(text) as T,
    headers: () => hdrs,
  };
}

// ─── Refetch trigger ──────────────────────────────────────────────────────────

async function triggerRefetch(page: Page): Promise<void> {
  await page.evaluate(() => window.dispatchEvent(new Event("online")));
}

/**
 * Send a message card via API and wait for the messages list to refresh.
 * Pattern: POST → register waitForMsgs → dispatch online → await response.
 * This ensures we catch the refetch-triggered GET, not a pre-POST GET.
 */
async function sendAndWaitForCard(page: Page, convoId: string, msgPath: string, body: object) {
  const postResp = await pagePost(page, msgPath, body);
  if (!postResp.ok()) {
    throw new Error(`pagePost failed: ${postResp.status()} ${await postResp.text()}`);
  }
  const waitForMsgs = page.waitForResponse(
    r => r.url().includes(`/messaging/conversations/${convoId}/messages`) &&
         r.request().method() === "GET" &&
         !r.url().match(/\/messages\/[^/]+$/),
    { timeout: 15000 },
  );
  await page.evaluate(() => window.dispatchEvent(new Event("online")));
  await waitForMsgs;
  await page.waitForTimeout(400);
}

/**
 * Open a conversation and wait for messages to fully load.
 * Used in beforeAll to ensure the page is ready before tests run.
 */
async function waitForConversationLoad(page: Page, convoId: string, timeout = 15000) {
  const waitForMsgs = page.waitForResponse(
    r => r.url().includes(`/messaging/conversations/${convoId}/messages`) &&
         r.request().method() === "GET" &&
         !r.url().match(/\/messages\/[^/]+$/),
    { timeout },
  );
  await page.evaluate(() => window.dispatchEvent(new Event("online")));
  await waitForMsgs;
  await page.waitForTimeout(500);
}

// ─── Setup helpers ────────────────────────────────────────────────────────────

/** Create a DM between Alice and Bob, return conversation_id. */
async function createDm(req: APIRequestContext): Promise<string> {
  const bobSub = getSessions()[BOB_ID].user_sub;
  const resp = await apiPost(req, "/messaging/conversations", {
    participant_ids: [bobSub],
    type: "dm",
  }, ALICE_ID);
  if (!resp.ok()) throw new Error(`DM creation failed: ${resp.status()} ${await resp.text()}`);
  return ((await resp.json()) as { conversation_id: string }).conversation_id;
}

/** Create a calendar for Alice using session auth, return { calendar_id, name }. */
async function createCalendar(browser: Browser, name: string): Promise<{ calendar_id: string; name: string }> {
  const resp = await sessionPost(browser, ALICE_ID, "/ui/calendars", { name, timezone: "UTC" });
  if (!resp.ok()) throw new Error(`Calendar create failed: ${resp.status()} ${await resp.text()}`);
  return await resp.json() as { calendar_id: string; name: string };
}

/** Create an event in a calendar for Alice using session auth, return event info. */
async function createEvent(
  browser: Browser,
  calendarId: string,
  name: string,
): Promise<{ event_id: string; name: string; start_utc: string; end_utc: string }> {
  const startUtc = "2026-06-15T14:00:00Z";
  const endUtc   = "2026-06-15T15:00:00Z";
  const resp = await sessionPost(browser, ALICE_ID, `/ui/calendars/${calendarId}/events`, {
    name,
    start_utc: startUtc,
    end_utc: endUtc,
    timezone: "UTC",
  });
  if (!resp.ok()) throw new Error(`Event create failed: ${resp.status()} ${await resp.text()}`);
  const body = await resp.json() as { event_id: string };
  return { event_id: body.event_id, name, start_utc: startUtc, end_utc: endUtc };
}

/** DDB helper: check if a calendar share record exists for a recipient. */
function checkCalendarShareInDdb(calendarId: string, recipientSub: string): boolean {
  try {
    const out = execSync(
      `${PYTHON} -c "
import boto3, os
from pathlib import Path
env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
tbl = ddb.Table('calendar')
item = tbl.get_item(Key={'calendar_id': '${calendarId}', 'sk': 'share#${recipientSub}'}).get('Item')
print('found' if item else 'not_found')
"`,
      { timeout: 10_000 },
    ).toString().trim();
    return out === "found";
  } catch {
    return false;
  }
}

/** Navigate Alice's page to the open DM with Bob (UI tests). */
let _uiDmConvoId: string | null = null;
async function openDmWithBob(page: Page): Promise<string> {
  if (!_uiDmConvoId) {
    const session = getSessions()[ALICE_ID];
    const bobSub = getSessions()[BOB_ID].user_sub;
    const resp = await page.request.post(`${API}/messaging/conversations`, {
      data: { participant_ids: [bobSub], type: "dm" },
      headers: { "x-csrf-token": session.csrf_token },
    });
    _uiDmConvoId = ((await resp.json()) as { conversation_id: string }).conversation_id;
  }
  // Seed a touch message so the conversation has content, then deep-link
  // straight to it via /messages/:conversationId (auto-opens the thread).
  // The sidebar-row click was flaky: the row centre overlaps the avatar/name
  // profile-links (role=link + stopPropagation), so a default click navigates
  // to the recipient profile instead of opening the DM. Deep-linking is the
  // deterministic, race-free equivalent.
  const session = getSessions()[ALICE_ID];
  await page.request.post(`${API}/messaging/conversations/${_uiDmConvoId}/messages`, {
    data: { text: `touch${Date.now()}` },
    headers: { "x-csrf-token": session.csrf_token },
  }).catch(() => {});
  const waitForMsgs = page.waitForResponse(
    r => r.url().includes(`/messaging/conversations/${_uiDmConvoId}/messages`) &&
         r.request().method() === "GET" &&
         !r.url().match(/\/messages\/[^/]+$/),
    { timeout: 15000 },
  ).catch(() => undefined);
  await page.goto(`${BASE}/messages/${_uiDmConvoId}`, { waitUntil: "load" });
  await expect(
    page.getByPlaceholder("Type a message...").or(
      page.getByPlaceholder("Type an encrypted message..."),
    ),
  ).toBeVisible({ timeout: 15000 });
  await waitForMsgs;
  return _uiDmConvoId;
}

// ─── Section 1 ────────────────────────────────────────────────────────────────

test.describe("1. Calendar share — read permission, no booking link", () => {
  let convoId = "";
  let calendarId = "";
  let calendarName = "";
  let msgId = "";

  test.beforeAll(async ({ request, browser }) => {
    convoId    = await createDm(request);
    const cal  = await createCalendar(browser, `E2E Share Cal ${Date.now()}`);
    calendarId = cal.calendar_id;
    calendarName = cal.name;
  });

  test("POST calendar-share returns 200 with calendar_share attachment", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/calendar-share`, {
      calendar_id: calendarId,
      permission: "read",
      include_booking_link: false,
    }, ALICE_ID);
    expect(resp.status()).toBe(200);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.kind).toBe("calendar_share");
    const cs = body.calendar_share as Record<string, unknown>;
    expect(cs).toBeTruthy();
    expect(cs.calendar_id).toBe(calendarId);
    expect(cs.name).toBe(calendarName);
    expect(cs.permission).toBe("read");
    expect(cs.booking_link_id ?? null).toBeNull();
    expect(cs.booking_public_url ?? null).toBeNull();
    msgId = body.message_id as string;
  });

  test("calendar_share message appears in conversation message list", async ({ request }) => {
    const resp = await apiGet(request, `/messaging/conversations/${convoId}/messages`, ALICE_ID);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Array<Record<string, unknown>>;
    const msg = data.find(m => m.message_id === msgId);
    expect(msg).toBeTruthy();
    expect(msg!.kind).toBe("calendar_share");
  });

  test("calendar_share with optional text includes text field", async ({ request }) => {
    const uniqueText = `Sharing my calendar ${Date.now()}`;
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/calendar-share`, {
      calendar_id: calendarId,
      permission: "read",
      include_booking_link: false,
      text: uniqueText,
    }, ALICE_ID);
    expect(resp.status()).toBe(200);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.text).toBe(uniqueText);
    expect(body.kind).toBe("calendar_share");
  });
});

// ─── Section 2 ────────────────────────────────────────────────────────────────

test.describe("2. Calendar share — write permission + booking link", () => {
  let convoId = "";
  let calendarId = "";

  test.beforeAll(async ({ request, browser }) => {
    convoId    = await createDm(request);
    const cal  = await createCalendar(browser, `E2E Write Cal ${Date.now()}`);
    calendarId = cal.calendar_id;
  });

  test("POST calendar-share write+booking returns booking_public_url", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/calendar-share`, {
      calendar_id: calendarId,
      permission: "write",
      include_booking_link: true,
    }, ALICE_ID);
    expect(resp.status()).toBe(200);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.kind).toBe("calendar_share");
    const cs = body.calendar_share as Record<string, unknown>;
    expect(cs.permission).toBe("write");
    expect(cs.booking_link_id).toBeTruthy();
    expect(typeof cs.booking_public_url).toBe("string");
    expect((cs.booking_public_url as string).startsWith("/booking/")).toBe(true);
  });

  test("Repeated calendar-share with booking link reuses existing booking link", async ({ request }) => {
    const r1 = await apiPost(request, `/messaging/conversations/${convoId}/messages/calendar-share`, {
      calendar_id: calendarId, permission: "read", include_booking_link: true,
    }, ALICE_ID);
    const r2 = await apiPost(request, `/messaging/conversations/${convoId}/messages/calendar-share`, {
      calendar_id: calendarId, permission: "read", include_booking_link: true,
    }, ALICE_ID);
    const b1 = (await r1.json() as Record<string, unknown>).calendar_share as Record<string, unknown>;
    const b2 = (await r2.json() as Record<string, unknown>).calendar_share as Record<string, unknown>;
    // Backend reuses existing booking link for the same calendar
    expect(b1.booking_link_id).toBe(b2.booking_link_id);
  });

  test("calendar_share rejects non-owned calendar", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/calendar-share`, {
      calendar_id: "nonexistent_calendar_xyz",
      permission: "read",
      include_booking_link: false,
    }, ALICE_ID);
    expect([403, 404]).toContain(resp.status());
  });
});

// ─── Section 3 ────────────────────────────────────────────────────────────────

test.describe("3. Calendar share — calendar granted to recipient (DDB + API verification)", () => {
  let convoId = "";
  let calendarId = "";

  test.beforeAll(async ({ request, browser }) => {
    // Create a fresh calendar and share it to Bob
    convoId    = await createDm(request);
    const cal  = await createCalendar(browser, `E2E Grant Cal ${Date.now()}`);
    calendarId = cal.calendar_id;
    // Share to Bob so we can verify
    const shareResp = await apiPost(request, `/messaging/conversations/${convoId}/messages/calendar-share`, {
      calendar_id: calendarId,
      permission: "read",
      include_booking_link: false,
    }, ALICE_ID);
    if (!shareResp.ok()) throw new Error(`Share failed: ${shareResp.status()} ${await shareResp.text()}`);
  });

  test("Bob has a calendar share record in DynamoDB after Alice shares", async () => {
    const bobSub = getSessions()[BOB_ID].user_sub;
    const found = checkCalendarShareInDdb(calendarId, bobSub);
    expect(found).toBe(true);
  });

  test("Bob can see the shared calendar in his calendar list", async ({ browser }) => {
    const resp = await sessionGet(browser, BOB_ID, "/ui/calendars");
    expect(resp.status()).toBe(200);
    const body = await resp.json() as Array<Record<string, unknown>>;
    const shared = body.find(c => c.calendar_id === calendarId);
    expect(shared).toBeTruthy();
  });

  test("Calendar share message sets last_message_preview on conversation", async ({ request }) => {
    const resp = await apiGet(request, `/messaging/conversations/${convoId}`, ALICE_ID);
    expect(resp.status()).toBe(200);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.last_message_preview).toBeTruthy();
  });
});

// ─── Section 4 ────────────────────────────────────────────────────────────────

test.describe("4. Calendar event share — send via API and verify snapshot fields", () => {
  let convoId = "";
  let calendarId = "";
  let eventId = "";
  let eventName = "";
  let evtMsgId = "";

  test.beforeAll(async ({ request, browser }) => {
    convoId    = await createDm(request);
    const cal  = await createCalendar(browser, `E2E Event Cal ${Date.now()}`);
    calendarId = cal.calendar_id;
    const evt  = await createEvent(browser, calendarId, `E2E Event ${Date.now()}`);
    eventId    = evt.event_id;
    eventName  = evt.name;
  });

  test("POST calendar-event returns 200 with calendar_event attachment", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/calendar-event`, {
      calendar_id: calendarId,
      event_id: eventId,
    }, ALICE_ID);
    expect(resp.status()).toBe(200);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.kind).toBe("calendar_event");
    const ce = body.calendar_event as Record<string, unknown>;
    expect(ce).toBeTruthy();
    expect(ce.event_id).toBe(eventId);
    expect(ce.calendar_id).toBe(calendarId);
    expect(ce.name).toBe(eventName);
    expect(ce.start_utc).toBe("2026-06-15T14:00:00Z");
    expect(ce.end_utc).toBe("2026-06-15T15:00:00Z");
    expect(ce.all_day).toBe(false);
    evtMsgId = body.message_id as string;
  });

  test("calendar_event message appears in conversation list with correct fields", async ({ request }) => {
    const resp = await apiGet(request, `/messaging/conversations/${convoId}/messages`, ALICE_ID);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Array<Record<string, unknown>>;
    const msg = data.find(m => m.message_id === evtMsgId);
    expect(msg).toBeTruthy();
    const ce = msg!.calendar_event as Record<string, unknown>;
    expect(ce.event_id).toBe(eventId);
    expect(ce.name).toBe(eventName);
  });

  test("calendar_event message with optional text includes text field", async ({ request }) => {
    const uniqueText = `Check out this event ${Date.now()}`;
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/calendar-event`, {
      calendar_id: calendarId,
      event_id: eventId,
      text: uniqueText,
    }, ALICE_ID);
    expect(resp.status()).toBe(200);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.text).toBe(uniqueText);
    expect(body.kind).toBe("calendar_event");
  });

  test("calendar_event rejects invalid calendar_id with 404", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/calendar-event`, {
      calendar_id: "nonexistent_calendar_xyz",
      event_id: eventId,
    }, ALICE_ID);
    expect(resp.status()).toBe(404);
  });

  test("calendar_event rejects invalid event_id with 404", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/calendar-event`, {
      calendar_id: calendarId,
      event_id: "nonexistent_event_xyz",
    }, ALICE_ID);
    expect(resp.status()).toBe(404);
  });
});

// ─── Section 5 ────────────────────────────────────────────────────────────────

test.describe("5. Calendar event share — public event page (no auth)", () => {
  let page: Page;
  let calendarId = "";
  let eventId = "";
  let eventName = "";

  test.beforeAll(async ({ browser }) => {
    const cal  = await createCalendar(browser, `E2E Public Cal ${Date.now()}`);
    calendarId = cal.calendar_id;
    const evt  = await createEvent(browser, calendarId, `E2E Public Event ${Date.now()}`);
    eventId    = evt.event_id;
    eventName  = evt.name;
    // Truly anonymous: the chromium project injects the admin storageState by
    // default, so browser.newPage() would inherit auth. Create an explicit
    // context with no storageState so isAuthenticated is false and the public
    // event page renders the "Sign in to add to calendar" prompt.
    const anonCtx = await browser.newContext({ storageState: undefined });
    page = await anonCtx.newPage();
  });
  test.afterAll(async () => page.close());

  test("GET /event/:calId/:eventId renders event info without auth", async () => {
    await page.goto(`${BASE}/event/${calendarId}/${eventId}`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(1000);
    await expect(page.getByText(eventName, { exact: false })).toBeVisible({ timeout: 8000 });
    await expect(
      page.getByRole("link", { name: /download.*ics/i }).or(
        page.getByRole("button", { name: /download.*ics/i }),
      ),
    ).toBeVisible({ timeout: 5000 });
  });

  test("Public event page shows sign-in prompt when not authenticated", async () => {
    await page.goto(`${BASE}/event/${calendarId}/${eventId}`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(1000);
    await expect(
      page.getByRole("link", { name: /sign in to add to calendar/i }),
    ).toBeVisible({ timeout: 5000 });
  });

  test("Public event page shows 'Add to my Calendar' when authenticated", async () => {
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/event/${calendarId}/${eventId}`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(1200);
    await expect(page.getByRole("button", { name: /add to my calendar/i })).toBeVisible({ timeout: 8000 });
  });

  test("Public event page returns 404 for non-existent event", async () => {
    await page.goto(`${BASE}/event/${calendarId}/nonexistent_event_404`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(1000);
    await expect(
      page.getByText(/not found/i).or(page.getByText(/404/i)),
    ).toBeVisible({ timeout: 5000 });
  });
});

// ─── Section 6 ────────────────────────────────────────────────────────────────

test.describe("6. Calendar event share — iCal download (public endpoint)", () => {
  let calendarId = "";
  let eventId = "";
  let eventName = "";

  test.beforeAll(async ({ browser }) => {
    const cal  = await createCalendar(browser, `E2E iCal Cal ${Date.now()}`);
    calendarId = cal.calendar_id;
    const evt  = await createEvent(browser, calendarId, `E2E iCal Event ${Date.now()}`);
    eventId    = evt.event_id;
    eventName  = evt.name;
  });

  test("GET /calendar/public/event/:calId/:eventId returns event JSON", async ({ request }) => {
    const resp = await request.get(`${API}/calendar/public/event/${calendarId}/${eventId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.name).toBe(eventName);
    expect(body.start_utc).toBe("2026-06-15T14:00:00Z");
    expect(body.end_utc).toBe("2026-06-15T15:00:00Z");
  });

  test("GET /calendar/public/event/:calId/:eventId/ical returns text/calendar", async ({ request }) => {
    const resp = await request.get(`${API}/calendar/public/event/${calendarId}/${eventId}/ical`);
    expect(resp.status()).toBe(200);
    expect(resp.headers()["content-type"]).toContain("text/calendar");
    const body = await resp.text();
    expect(body).toContain("BEGIN:VCALENDAR");
    expect(body).toContain("BEGIN:VEVENT");
    expect(body).toContain(eventName);
    expect(body).toContain("END:VEVENT");
    expect(body).toContain("END:VCALENDAR");
  });

  test("iCal file contains correct DTSTART and DTEND", async ({ request }) => {
    const resp = await request.get(`${API}/calendar/public/event/${calendarId}/${eventId}/ical`);
    const body = await resp.text();
    // 2026-06-15T14:00:00Z → 20260615T140000Z
    expect(body).toContain("DTSTART:20260615T140000Z");
    expect(body).toContain("DTEND:20260615T150000Z");
  });

  test("iCal file contains RFC 5545 UID field", async ({ request }) => {
    const resp = await request.get(`${API}/calendar/public/event/${calendarId}/${eventId}/ical`);
    const body = await resp.text();
    expect(body).toContain("UID:");
    expect(body).toContain(eventId);
  });

  test("Public iCal returns 404 for non-existent event", async ({ request }) => {
    const resp = await request.get(`${API}/calendar/public/event/${calendarId}/no_such_event/ical`);
    expect(resp.status()).toBe(404);
  });
});

// ─── Section 7 ────────────────────────────────────────────────────────────────

test.describe("7. Calendar event share — iCal download (authenticated endpoint)", () => {
  let page: Page;
  let calendarId = "";
  let eventId = "";
  let eventName = "";

  test.beforeAll(async ({ browser }) => {
    const cal  = await createCalendar(browser, `E2E Auth iCal Cal ${Date.now()}`);
    calendarId = cal.calendar_id;
    const evt  = await createEvent(browser, calendarId, `E2E Auth iCal Event ${Date.now()}`);
    eventId    = evt.event_id;
    eventName  = evt.name;
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
  });
  test.afterAll(async () => page.close());

  test("GET /ui/calendars/:calId/events/:eventId/ical returns iCal for calendar owner", async () => {
    const resp = await pageGet(page, `/ui/calendars/${calendarId}/events/${eventId}/ical`);
    expect(resp.status()).toBe(200);
    expect(resp.headers()["content-type"]).toContain("text/calendar");
    const body = await resp.text();
    expect(body).toContain("BEGIN:VCALENDAR");
    expect(body).toContain(eventName);
    expect(body).toContain("DTSTART:20260615T140000Z");
  });

  test("Authenticated iCal has Content-Disposition attachment header", async () => {
    const resp = await pageGet(page, `/ui/calendars/${calendarId}/events/${eventId}/ical`);
    expect(resp.status()).toBe(200);
    const cd = resp.headers()["content-disposition"] ?? "";
    expect(cd).toContain("attachment");
    expect(cd).toContain(".ics");
  });

  test("Authenticated iCal endpoint rejects unauthenticated request", async ({ request }) => {
    // Raw request without auth header — should be rejected
    const resp = await request.get(`${API}/ui/calendars/${calendarId}/events/${eventId}/ical`);
    expect([401, 403, 302]).toContain(resp.status());
  });
});

// ─── Section 8 ────────────────────────────────────────────────────────────────

test.describe("8. Meeting poll — create via API and verify response shape", () => {
  let convoId = "";
  let pollId = "";
  let pollMsgId = "";
  const pollTitle = `E2E Poll ${Date.now()}`;

  test.beforeAll(async ({ request }) => {
    convoId = await createDm(request);
  });

  test("POST meeting-poll returns 200 with meeting_poll attachment", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/meeting-poll`, {
      title: pollTitle,
      duration_minutes: 30,
      slots: [
        { start_utc: SLOT1_START, end_utc: SLOT1_END },
        { start_utc: SLOT2_START, end_utc: SLOT2_END },
        { start_utc: SLOT3_START, end_utc: SLOT3_END },
      ],
    }, ALICE_ID);
    expect(resp.status()).toBe(200);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.kind).toBe("meeting_poll");
    const mp = body.meeting_poll as Record<string, unknown>;
    expect(mp).toBeTruthy();
    expect(mp.title).toBe(pollTitle);
    expect(mp.duration_minutes).toBe(30);
    expect(mp.status).toBe("open");
    expect(mp.confirmed_slot_id).toBeNull();
    expect(mp.poll_id).toBeTruthy();
    expect(mp.creator_id).toBeTruthy();
    pollId    = mp.poll_id as string;
    pollMsgId = body.message_id as string;
  });

  test("meeting_poll message appears in conversation list", async ({ request }) => {
    const resp = await apiGet(request, `/messaging/conversations/${convoId}/messages`, ALICE_ID);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Array<Record<string, unknown>>;
    const msg = data.find(m => m.message_id === pollMsgId);
    expect(msg).toBeTruthy();
    expect(msg!.kind).toBe("meeting_poll");
    expect((msg!.meeting_poll as Record<string, unknown>).title).toBe(pollTitle);
  });

  test("meeting_poll with optional text includes text field", async ({ request }) => {
    const customText = `Join our team sync ${Date.now()}`;
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/meeting-poll`, {
      title: `${pollTitle} with text`,
      duration_minutes: 15,
      slots: [
        { start_utc: SLOT1_START, end_utc: SLOT1_END },
        { start_utc: SLOT2_START, end_utc: SLOT2_END },
      ],
      text: customText,
    }, ALICE_ID);
    expect(resp.status()).toBe(200);
    expect(((await resp.json()) as Record<string, unknown>).text).toBe(customText);
  });

  test("POST meeting-poll with 5 slots (maximum) succeeds", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/meeting-poll`, {
      title: "Max slots poll",
      duration_minutes: 30,
      slots: [
        { start_utc: SLOT1_START, end_utc: SLOT1_END },
        { start_utc: SLOT2_START, end_utc: SLOT2_END },
        { start_utc: SLOT3_START, end_utc: SLOT3_END },
        { start_utc: "2026-07-12T10:00:00Z", end_utc: "2026-07-12T10:30:00Z" },
        { start_utc: "2026-07-13T10:00:00Z", end_utc: "2026-07-13T10:30:00Z" },
      ],
    }, ALICE_ID);
    expect(resp.status()).toBe(200);
  });

  test("GET poll returns full state with 3 slots", async ({ request }) => {
    const resp = await apiGet(request, `/messaging/conversations/${convoId}/polls/${pollId}`, ALICE_ID);
    expect(resp.status()).toBe(200);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.status).toBe("open");
    expect((body.slots as unknown[]).length).toBe(3);
  });
});

// ─── Section 9 ────────────────────────────────────────────────────────────────

test.describe("9. Meeting poll — GET poll state (slots, counts, my_vote)", () => {
  let convoId = "";
  let pollId = "";
  let slotIds: string[] = [];
  const pollTitle = `E2E GET Poll ${Date.now()}`;

  test.beforeAll(async ({ request }) => {
    convoId = await createDm(request);
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/meeting-poll`, {
      title: pollTitle,
      duration_minutes: 30,
      slots: [
        { start_utc: SLOT1_START, end_utc: SLOT1_END },
        { start_utc: SLOT2_START, end_utc: SLOT2_END },
        { start_utc: SLOT3_START, end_utc: SLOT3_END },
      ],
    }, ALICE_ID);
    const body = await resp.json() as Record<string, unknown>;
    const mp = body.meeting_poll as Record<string, unknown>;
    pollId = mp.poll_id as string;
    // Fetch slots
    const pollResp = await apiGet(request, `/messaging/conversations/${convoId}/polls/${pollId}`, ALICE_ID);
    const pollBody = await pollResp.json() as Record<string, unknown>;
    slotIds = (pollBody.slots as Array<Record<string, unknown>>).map(s => s.slot_id as string);
  });

  test("GET poll returns correct fields: poll_id, title, duration, status, slots", async ({ request }) => {
    const resp = await apiGet(request, `/messaging/conversations/${convoId}/polls/${pollId}`, ALICE_ID);
    expect(resp.status()).toBe(200);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.poll_id).toBe(pollId);
    expect(body.title).toBe(pollTitle);
    expect(body.duration_minutes).toBe(30);
    expect(body.status).toBe("open");
    expect(body.confirmed_slot_id).toBeNull();
    const slots = body.slots as Array<Record<string, unknown>>;
    expect(slots.length).toBe(3);
    const slot = slots[0];
    expect(slot.slot_id).toBeTruthy();
    expect(typeof slot.yes_count).toBe("number");
    expect(typeof slot.maybe_count).toBe("number");
    expect(typeof slot.no_count).toBe("number");
    expect(slot.my_vote).toBeNull();
  });

  test("All initial vote counts are zero", async ({ request }) => {
    const resp = await apiGet(request, `/messaging/conversations/${convoId}/polls/${pollId}`, ALICE_ID);
    const body = await resp.json() as Record<string, unknown>;
    const slots = body.slots as Array<Record<string, unknown>>;
    for (const s of slots) {
      expect(s.yes_count).toBe(0);
      expect(s.maybe_count).toBe(0);
      expect(s.no_count).toBe(0);
      expect(s.my_vote).toBeNull();
    }
  });

  test("GET poll returns 404 for non-existent poll", async ({ request }) => {
    const resp = await apiGet(request, `/messaging/conversations/${convoId}/polls/nonexistent_poll_xyz`, ALICE_ID);
    expect(resp.status()).toBe(404);
  });

  test("Non-participant cannot access poll", async ({ request }) => {
    const charlieId = "e2e_charlie@test.local";
    if (!getSessions()[charlieId]) return;
    const resp = await apiGet(request, `/messaging/conversations/${convoId}/polls/${pollId}`, charlieId);
    expect([403, 404]).toContain(resp.status());
  });
});

// ─── Section 10 ───────────────────────────────────────────────────────────────

test.describe("10. Meeting poll — vote on slots", () => {
  let convoId = "";
  let pollId = "";
  let slotIds: string[] = [];

  test.beforeAll(async ({ request }) => {
    convoId = await createDm(request);
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/meeting-poll`, {
      title: `E2E Vote Poll ${Date.now()}`,
      duration_minutes: 30,
      slots: [
        { start_utc: SLOT1_START, end_utc: SLOT1_END },
        { start_utc: SLOT2_START, end_utc: SLOT2_END },
        { start_utc: SLOT3_START, end_utc: SLOT3_END },
      ],
    }, ALICE_ID);
    const body = await resp.json() as Record<string, unknown>;
    const mp = body.meeting_poll as Record<string, unknown>;
    pollId = mp.poll_id as string;
    const pollResp = await apiGet(request, `/messaging/conversations/${convoId}/polls/${pollId}`, ALICE_ID);
    const pollBody = await pollResp.json() as Record<string, unknown>;
    slotIds = (pollBody.slots as Array<Record<string, unknown>>).map(s => s.slot_id as string);
  });

  test("Alice votes yes/maybe/no on three slots", async ({ request }) => {
    const votes: Record<string, string> = {
      [slotIds[0]]: "yes",
      [slotIds[1]]: "maybe",
      [slotIds[2]]: "no",
    };
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/polls/${pollId}/vote`, {
      votes,
    }, ALICE_ID);
    expect(resp.status()).toBe(200);
    expect(((await resp.json()) as { ok: boolean }).ok).toBe(true);
  });

  test("GET poll reflects Alice's votes in slot counts and my_vote", async ({ request }) => {
    const resp = await apiGet(request, `/messaging/conversations/${convoId}/polls/${pollId}`, ALICE_ID);
    const body = await resp.json() as Record<string, unknown>;
    const slots = body.slots as Array<Record<string, unknown>>;
    const s0 = slots.find(s => s.slot_id === slotIds[0])!;
    const s1 = slots.find(s => s.slot_id === slotIds[1])!;
    const s2 = slots.find(s => s.slot_id === slotIds[2])!;
    expect(s0.yes_count).toBe(1);
    expect(s0.my_vote).toBe("yes");
    expect(s1.maybe_count).toBe(1);
    expect(s1.my_vote).toBe("maybe");
    expect(s2.no_count).toBe(1);
    expect(s2.my_vote).toBe("no");
  });

  test("Bob votes yes on slot 1 and slot 2", async ({ request }) => {
    const votes: Record<string, string> = { [slotIds[0]]: "yes", [slotIds[1]]: "yes" };
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/polls/${pollId}/vote`, {
      votes,
    }, BOB_ID);
    expect(resp.status()).toBe(200);
    expect(((await resp.json()) as { ok: boolean }).ok).toBe(true);
  });

  test("GET poll shows cumulative votes from Alice and Bob", async ({ request }) => {
    const resp = await apiGet(request, `/messaging/conversations/${convoId}/polls/${pollId}`, ALICE_ID);
    const body = await resp.json() as Record<string, unknown>;
    const slots = body.slots as Array<Record<string, unknown>>;
    const s0 = slots.find(s => s.slot_id === slotIds[0])!;
    const s1 = slots.find(s => s.slot_id === slotIds[1])!;
    expect(s0.yes_count).toBe(2);   // Alice + Bob
    expect(s1.maybe_count).toBe(1); // Alice
    expect(s1.yes_count).toBe(1);   // Bob
  });

  test("Vote with invalid slot_id returns 400", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/polls/${pollId}/vote`, {
      votes: { "nonexistent_slot_xyz": "yes" },
    }, ALICE_ID);
    expect(resp.status()).toBe(400);
  });
});

// ─── Section 11 ───────────────────────────────────────────────────────────────

test.describe("11. Meeting poll — confirm a slot (no calendar event creation)", () => {
  let convoId = "";
  let pollId = "";
  let slotIds: string[] = [];

  test.beforeAll(async ({ request }) => {
    convoId = await createDm(request);
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/meeting-poll`, {
      title: `E2E Confirm Poll ${Date.now()}`,
      duration_minutes: 60,
      slots: [
        { start_utc: SLOT1_START, end_utc: SLOT1_END },
        { start_utc: SLOT2_START, end_utc: SLOT2_END },
      ],
    }, ALICE_ID);
    const body = await resp.json() as Record<string, unknown>;
    pollId = (body.meeting_poll as Record<string, unknown>).poll_id as string;
    const pollResp = await apiGet(request, `/messaging/conversations/${convoId}/polls/${pollId}`, ALICE_ID);
    const pollBody = await pollResp.json() as Record<string, unknown>;
    slotIds = (pollBody.slots as Array<Record<string, unknown>>).map(s => s.slot_id as string);
  });

  test("Creator can confirm a slot", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/polls/${pollId}/confirm`, {
      slot_id: slotIds[0],
    }, ALICE_ID);
    expect(resp.status()).toBe(200);
    expect(((await resp.json()) as { ok: boolean }).ok).toBe(true);
  });

  test("GET confirmed poll shows status=confirmed and confirmed_slot_id", async ({ request }) => {
    const resp = await apiGet(request, `/messaging/conversations/${convoId}/polls/${pollId}`, ALICE_ID);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.status).toBe("confirmed");
    expect(body.confirmed_slot_id).toBe(slotIds[0]);
  });

  test("Non-creator (Bob) cannot confirm a slot", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/polls/${pollId}/confirm`, {
      slot_id: slotIds[0],
    }, BOB_ID);
    expect([403, 400]).toContain(resp.status());
  });

  test("Cannot vote on a confirmed poll", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/polls/${pollId}/vote`, {
      votes: { [slotIds[0]]: "yes" },
    }, ALICE_ID);
    expect(resp.status()).toBe(400);
  });

  test("Cannot confirm an already-confirmed poll", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/polls/${pollId}/confirm`, {
      slot_id: slotIds[1],
    }, ALICE_ID);
    expect(resp.status()).toBe(400);
  });
});

// ─── Section 12 ───────────────────────────────────────────────────────────────

test.describe("12. Meeting poll — confirm a slot + create calendar event", () => {
  let convoId = "";
  let calendarId = "";
  let pollId = "";
  let slotIds: string[] = [];

  test.beforeAll(async ({ request, browser }) => {
    convoId = await createDm(request);
    const cal = await createCalendar(browser, `E2E Poll Cal ${Date.now()}`);
    calendarId = cal.calendar_id;
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/meeting-poll`, {
      title: `E2E Cal Event Poll ${Date.now()}`,
      duration_minutes: 30,
      slots: [
        { start_utc: SLOT1_START, end_utc: SLOT1_END },
        { start_utc: SLOT2_START, end_utc: SLOT2_END },
      ],
    }, ALICE_ID);
    const body = await resp.json() as Record<string, unknown>;
    pollId = (body.meeting_poll as Record<string, unknown>).poll_id as string;
    const pollResp = await apiGet(request, `/messaging/conversations/${convoId}/polls/${pollId}`, ALICE_ID);
    const pollBody = await pollResp.json() as Record<string, unknown>;
    slotIds = (pollBody.slots as Array<Record<string, unknown>>).map(s => s.slot_id as string);
  });

  test("Confirm with calendar_id returns ok=true and event_id", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/polls/${pollId}/confirm`, {
      slot_id: slotIds[0],
      calendar_id: calendarId,
    }, ALICE_ID);
    expect(resp.status()).toBe(200);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.ok).toBe(true);
    expect(body.event_id).toBeTruthy();
  });

  test("GET confirmed poll shows status=confirmed with calendar event", async ({ request }) => {
    const resp = await apiGet(request, `/messaging/conversations/${convoId}/polls/${pollId}`, ALICE_ID);
    const body = await resp.json() as Record<string, unknown>;
    expect(body.status).toBe("confirmed");
    expect(body.confirmed_slot_id).toBe(slotIds[0]);
  });
});

// ─── Section 13 ───────────────────────────────────────────────────────────────

test.describe("13. Meeting poll — validation errors", () => {
  let convoId = "";

  test.beforeAll(async ({ request }) => {
    convoId = await createDm(request);
  });

  test("Reject poll with only 1 slot (minimum is 2)", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/meeting-poll`, {
      title: "Single slot poll",
      duration_minutes: 30,
      slots: [{ start_utc: SLOT1_START, end_utc: SLOT1_END }],
    }, ALICE_ID);
    expect([400, 422]).toContain(resp.status());
  });

  test("Reject poll with 6 slots (maximum is 5)", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/meeting-poll`, {
      title: "Too many slots",
      duration_minutes: 30,
      slots: [
        { start_utc: SLOT1_START, end_utc: SLOT1_END },
        { start_utc: SLOT2_START, end_utc: SLOT2_END },
        { start_utc: SLOT3_START, end_utc: SLOT3_END },
        { start_utc: "2026-07-12T10:00:00Z", end_utc: "2026-07-12T10:30:00Z" },
        { start_utc: "2026-07-13T10:00:00Z", end_utc: "2026-07-13T10:30:00Z" },
        { start_utc: "2026-07-14T10:00:00Z", end_utc: "2026-07-14T10:30:00Z" },
      ],
    }, ALICE_ID);
    expect([400, 422]).toContain(resp.status());
  });

  test("Reject poll with empty title", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/meeting-poll`, {
      title: "",
      duration_minutes: 30,
      slots: [
        { start_utc: SLOT1_START, end_utc: SLOT1_END },
        { start_utc: SLOT2_START, end_utc: SLOT2_END },
      ],
    }, ALICE_ID);
    expect([400, 422]).toContain(resp.status());
  });

  test("Reject poll with duration below 15 minutes", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/meeting-poll`, {
      title: "Short duration poll",
      duration_minutes: 5,
      slots: [
        { start_utc: SLOT1_START, end_utc: SLOT1_END },
        { start_utc: SLOT2_START, end_utc: SLOT2_END },
      ],
    }, ALICE_ID);
    expect([400, 422]).toContain(resp.status());
  });

  test("Reject poll with duration above 1440 minutes", async ({ request }) => {
    const resp = await apiPost(request, `/messaging/conversations/${convoId}/messages/meeting-poll`, {
      title: "Very long poll",
      duration_minutes: 2000,
      slots: [
        { start_utc: SLOT1_START, end_utc: SLOT1_END },
        { start_utc: SLOT2_START, end_utc: SLOT2_END },
      ],
    }, ALICE_ID);
    expect([400, 422]).toContain(resp.status());
  });
});

// ─── Section 14 ───────────────────────────────────────────────────────────────

test.describe("14. UI — ComposeBar CalendarDays dropdown opens dialogs", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await openDmWithBob(page);
  });
  test.afterAll(async () => page.close());

  test("CalendarDays dropdown button is visible in ComposeBar", async () => {
    const calBtn = page.getByRole("button", { name: "More compose options" });
    await expect(calBtn).toBeVisible({ timeout: 5000 });
  });

  test("CalendarDays dropdown shows three calendar menu items", async () => {
    const calBtn = page.getByRole("button", { name: "More compose options" });
    await calBtn.click();
    await expect(page.getByText(/share my calendar/i)).toBeVisible({ timeout: 3000 });
    await expect(page.getByText(/share an event/i)).toBeVisible({ timeout: 3000 });
    await expect(page.getByText(/schedule a meeting/i)).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
    await page.waitForTimeout(200);
  });

  test("'Share my calendar' opens CalendarPickerDialog", async () => {
    const calBtn = page.getByRole("button", { name: "More compose options" });
    await calBtn.click();
    await page.getByText(/share my calendar/i).click();
    await expect(page.getByRole("dialog")).toBeVisible({ timeout: 5000 });
    await expect(page.getByText(/share a calendar/i)).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
    await page.waitForTimeout(300);
  });

  test("'Share an event' opens EventPickerDialog", async () => {
    const calBtn = page.getByRole("button", { name: "More compose options" });
    await calBtn.click();
    await page.getByText(/share an event/i).click();
    await expect(page.getByRole("dialog")).toBeVisible({ timeout: 5000 });
    await page.keyboard.press("Escape");
    await page.waitForTimeout(300);
  });

  test("'Schedule a meeting' opens MeetingPollComposer", async () => {
    const calBtn = page.getByRole("button", { name: "More compose options" });
    await calBtn.click();
    await page.getByText(/schedule a meeting/i).click();
    await expect(page.getByRole("dialog")).toBeVisible({ timeout: 5000 });
    await expect(page.getByText(/schedule a meeting/i)).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
    await page.waitForTimeout(300);
  });
});

// ─── Section 15 ───────────────────────────────────────────────────────────────

test.describe("15. UI — calendar_share MessageBubble card rendering", () => {
  let page: Page;
  let convoId = "";
  let calendarId = "";
  let calendarName = "";

  test.beforeAll(async ({ browser }) => {
    const cal    = await createCalendar(browser, `E2E UI Share Cal ${Date.now()}`);
    calendarId   = cal.calendar_id;
    calendarName = cal.name;
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await openDmWithBob(page);
  });
  test.afterAll(async () => page.close());

  test("calendar_share card (read) shows calendar name and View Calendar link", async () => {
    test.setTimeout(40000);
    await sendAndWaitForCard(page, convoId, `/messaging/conversations/${convoId}/messages/calendar-share`, {
      calendar_id: calendarId,
      permission: "read",
      include_booking_link: false,
    });
    await expect(page.getByRole("link", { name: "View Calendar" }).first()).toBeVisible({ timeout: 15000 });
    // calendarName appears in a message card <p> element (not just sidebar preview)
    await expect(page.locator("p").filter({ hasText: calendarName }).first()).toBeVisible({ timeout: 5000 });
  });

  test("calendar_share card shows 'View only' badge for read permission", async () => {
    test.setTimeout(40000);
    await sendAndWaitForCard(page, convoId, `/messaging/conversations/${convoId}/messages/calendar-share`, {
      calendar_id: calendarId,
      permission: "read",
      include_booking_link: false,
    });
    await expect(page.getByText(/view only/i).first()).toBeVisible({ timeout: 15000 });
  });

  test("calendar_share card shows 'View + Edit' badge for write permission", async () => {
    test.setTimeout(40000);
    await sendAndWaitForCard(page, convoId, `/messaging/conversations/${convoId}/messages/calendar-share`, {
      calendar_id: calendarId,
      permission: "write",
      include_booking_link: false,
    });
    await expect(page.getByText(/view \+ edit/i).first()).toBeVisible({ timeout: 15000 });
  });

  test("calendar_share card with booking link shows 'Book a time' link", async () => {
    test.setTimeout(40000);
    await sendAndWaitForCard(page, convoId, `/messaging/conversations/${convoId}/messages/calendar-share`, {
      calendar_id: calendarId,
      permission: "read",
      include_booking_link: true,
    });
    await expect(page.getByRole("link", { name: /book a time/i }).first()).toBeVisible({ timeout: 15000 });
  });
});

// ─── Section 16 ───────────────────────────────────────────────────────────────

test.describe("16. UI — calendar_event MessageBubble card rendering", () => {
  let page: Page;
  let convoId = "";
  let calendarId = "";
  let eventId = "";
  let eventName = "";

  test.beforeAll(async ({ browser }) => {
    const cal  = await createCalendar(browser, `E2E UI Event Cal ${Date.now()}`);
    calendarId = cal.calendar_id;
    const evt  = await createEvent(browser, calendarId, `E2E UI Event ${Date.now()}`);
    eventId    = evt.event_id;
    eventName  = evt.name;
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await openDmWithBob(page);
  });
  test.afterAll(async () => page.close());

  test("calendar_event card shows event name with View details and Download .ics links", async () => {
    test.setTimeout(40000);
    await sendAndWaitForCard(page, convoId, `/messaging/conversations/${convoId}/messages/calendar-event`, {
      calendar_id: calendarId,
      event_id: eventId,
    });
    await expect(page.getByText(eventName, { exact: false }).first()).toBeVisible({ timeout: 15000 });
    await expect(page.getByRole("link", { name: /view details/i }).first()).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("link", { name: /download.*ics/i }).first()).toBeVisible({ timeout: 5000 });
  });

  test("calendar_event 'View details' link points to /event/:calId/:eventId", async () => {
    const link = page.getByRole("link", { name: /view details/i }).last();
    const href = await link.getAttribute("href");
    expect(href).toContain(calendarId);
    expect(href).toContain(eventId);
  });

  test("calendar_event 'Download .ics' href points to iCal endpoint", async () => {
    const link = page.getByRole("link", { name: /download.*ics/i }).last();
    const href = await link.getAttribute("href");
    expect(href).toContain("/ical");
    expect(href).toContain(calendarId);
    expect(href).toContain(eventId);
  });
});

// ─── Section 17 ───────────────────────────────────────────────────────────────

test.describe("17. UI — meeting_poll MessageBubble card + voting UI", () => {
  let page: Page;
  let convoId = "";
  let pollId = "";
  let slotIds: string[] = [];
  const uiPollTitle = `E2E UI Poll ${Date.now()}`;

  test.beforeAll(async ({ browser, request }) => {
    // Create page + inject auth FIRST so page.request uses session cookies
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const session = getSessions()[ALICE_ID];
    const bobSub = getSessions()[BOB_ID].user_sub;

    // Create DM via session auth so it appears in the session-auth conversations list
    const dmResp = await page.request.post(`${API}/messaging/conversations`, {
      data: { participant_ids: [bobSub], type: "dm" },
      headers: { "x-csrf-token": session.csrf_token },
    });
    if (!dmResp.ok()) throw new Error(`DM create failed: ${dmResp.status()} ${await dmResp.text()}`);
    convoId = ((await dmResp.json()) as { conversation_id: string }).conversation_id;

    // Create poll via session auth (consistent with DM creation)
    const pollResp = await pagePost(page, `/messaging/conversations/${convoId}/messages/meeting-poll`, {
      title: uiPollTitle,
      duration_minutes: 30,
      slots: [
        { start_utc: SLOT1_START, end_utc: SLOT1_END },
        { start_utc: SLOT2_START, end_utc: SLOT2_END },
      ],
    });
    if (!pollResp.ok()) throw new Error(`Poll create failed: ${pollResp.status()} ${await pollResp.text()}`);
    const body = await pollResp.json() as Record<string, unknown>;
    pollId = (body.meeting_poll as Record<string, unknown>).poll_id as string;

    // Get poll slots (needed for the Confirm test fallback)
    const pollStateResp = await pageGet(page, `/messaging/conversations/${convoId}/polls/${pollId}`);
    if (!pollStateResp.ok()) throw new Error(`Poll GET failed: ${pollStateResp.status()} ${await pollStateResp.text()}`);
    const pollBody = await pollStateResp.json() as Record<string, unknown>;
    slotIds = (pollBody.slots as Array<Record<string, unknown>>).map(s => s.slot_id as string);

    // Seed a touch message, then deep-link straight to the conversation via
    // /messages/:conversationId (auto-opens the thread). The sidebar-row click
    // was flaky because the row centre overlaps the avatar/name profile-links,
    // navigating to the recipient profile instead of opening the DM.
    await page.request.post(`${API}/messaging/conversations/${convoId}/messages`, {
      data: { text: `touch17${Date.now()}` },
      headers: { "x-csrf-token": session.csrf_token },
    }).catch(() => {});
    const waitForMsgs17 = page.waitForResponse(
      r => r.url().includes(`/messaging/conversations/${convoId}/messages`) &&
           r.request().method() === "GET" &&
           !r.url().match(/\/messages\/[^/]+$/),
      { timeout: 15000 },
    ).catch(() => undefined);
    await page.goto(`${BASE}/messages/${convoId}`, { waitUntil: "load" });
    await expect(page.getByPlaceholder("Type a message...")).toBeVisible({ timeout: 15000 });
    await waitForMsgs17;
    await page.waitForTimeout(500);
  });
  test.afterAll(async () => page.close());

  test("meeting_poll card is visible with poll title and 'Voting open' badge", async () => {
    test.setTimeout(30000);
    await expect(page.getByText(uiPollTitle, { exact: false })).toBeVisible({ timeout: 15000 });
    await expect(page.getByText(/voting open/i)).toBeVisible({ timeout: 10000 });
  });

  test("meeting_poll card shows duration badge (30 min)", async () => {
    await expect(page.getByText(/30 min/i)).toBeVisible({ timeout: 8000 });
  });

  test("Confirm button is visible for poll creator (Alice)", async () => {
    const confirmBtns = page.getByRole("button", { name: /confirm →/i });
    await expect(confirmBtns.first()).toBeVisible({ timeout: 8000 });
  });

  test("Clicking 'Confirm' updates card to show 'Confirmed' status", async ({ request }) => {
    test.setTimeout(35000);
    const confirmBtn = page.getByRole("button", { name: /confirm →/i }).first();
    const isVisible = await confirmBtn.isVisible().catch(() => false);
    if (isVisible) {
      // Wait for the poll mutation + refetch to complete
      const waitForPoll = page.waitForResponse(
        r => r.url().includes(`/polls/${pollId}`) && r.request().method() === "GET",
        { timeout: 10000 },
      );
      await confirmBtn.click();
      await waitForPoll;
      await page.waitForTimeout(300);
    } else {
      // Confirm via session auth then trigger a refetch
      await pagePost(page, `/messaging/conversations/${convoId}/polls/${pollId}/confirm`, {
        slot_id: slotIds[0],
      });
      await waitForConversationLoad(page, convoId);
    }
    await expect(page.getByText(/✅ Confirmed/i)).toBeVisible({ timeout: 8000 });
  });
});
