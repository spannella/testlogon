/**
 * VIDEO SEGMENT 10 — Calendar & Booking  (~60-90s)
 *
 * A guided tour of the platform's scheduling tooling:
 *   - The Calendar (/calendar): a real month grid with event blocks
 *   - Event details: clicking an event chip opens the event editor dialog
 *   - Booking Links (/calendar → Booking Links tab): shareable scheduling links
 *     with auto-computed openings
 *   - Public event page (/event/:calendarId/:eventId): the no-auth, shareable
 *     public face of an event — with an "Add to my Calendar" affordance and a
 *     Download .ics (iCal export) button
 *
 * Pattern mirrors seg09-files.demo.ts: ONE long test, paced with beat() and
 * narrated with caption()/titleCard(). Everything shown is brought on-screen and
 * PROVEN visible via reveal()'s toBeInViewport assertion.
 *
 * Cast (sessions seeded by e2e_admin_session_setup.py, loaded via loadSessions):
 *   - Alice — on camera. She owns the calendar, its events, and a booking link.
 *
 * Seeding (all off-camera, before any UI is shown):
 *   - One calendar ("Alice's Schedule") via POST /ui/calendars.
 *   - A handful of events in the CURRENT month (so they land on the default month
 *     grid, which opens on `new Date()`) via POST /ui/calendars/{id}/events.
 *   - One booking link ("30 min meeting") via POST /ui/calendars/{id}/booking_links.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg10-calendar.demo.ts
 */
import { test, expect, type APIResponse } from "@playwright/test";
import {
  BASE,
  API,
  injectAuth,
  caption,
  clearCaption,
  titleCard,
  beat,
  reveal,
  loadSessions,
  type SessionData,
} from "./_demo";

const ALICE = "alice";

async function jsonOk(resp: APIResponse, what: string): Promise<any> {
  if (!resp.ok()) throw new Error(`${what} failed: ${resp.status()} ${await resp.text()}`);
  return resp.json();
}

/** Pad to 2 digits. */
const p2 = (n: number) => String(n).padStart(2, "0");

/**
 * Build an ISO-UTC datetime string for a day in the CURRENT month so the seeded
 * events land on the calendar's default month grid (it opens on `new Date()`).
 * Falls back to clamping the day to the month length.
 */
function inThisMonth(day: number, hour: number): string {
  const now = new Date();
  const y = now.getUTCFullYear();
  const m = now.getUTCMonth(); // 0-based
  const lastDay = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
  const d = Math.min(day, lastDay);
  return `${y}-${p2(m + 1)}-${p2(d)}T${p2(hour)}:00:00Z`;
}

test("Segment 10 — Calendar & Booking", async ({ page }) => {
  test.setTimeout(600_000);
  const sessions = loadSessions();
  const alice: SessionData = sessions[ALICE];

  // ── Off-camera seeding ──────────────────────────────────────────────────────
  await injectAuth(page, ALICE);
  const post = (path: string, body: unknown) =>
    page.request.post(`${API}${path}`, {
      headers: { "x-csrf-token": alice.csrf_token, "content-type": "application/json" },
      data: body,
    });

  // 1. A calendar. Reuse the FIRST existing calendar if Alice already has one, so
  //    re-runs don't pile up duplicate "Alice's Schedule" calendars (the Booking
  //    Links tab defaults to the first calendar, which must be the seeded one).
  const existingCals = (await jsonOk(
    (await page.request.get(`${API}/ui/calendars`)) as APIResponse,
    "list calendars",
  )) as Array<{ calendar_id: string }>;
  let calendarId: string;
  if (Array.isArray(existingCals) && existingCals.length > 0) {
    calendarId = existingCals[0]!.calendar_id;
  } else {
    const cal = await jsonOk(
      (await post("/ui/calendars", { name: "Alice's Schedule", timezone: "UTC" })) as APIResponse,
      "create calendar",
    );
    calendarId = cal.calendar_id as string;
  }

  // 2. A handful of events in the current month (so they paint on the month grid).
  //    Pick a single anchor day for two events so the "+more"/stacking reads well,
  //    plus a couple spread across the month.
  const now = new Date();
  const anchorDay = Math.min(15, new Date(now.getUTCFullYear(), now.getUTCMonth() + 1, 0).getUTCDate());
  const eventSpecs: Array<{ name: string; start: string; end: string; description?: string }> = [
    {
      name: "Product Demo",
      start: inThisMonth(anchorDay, 14),
      end: inThisMonth(anchorDay, 15),
      description: "Walkthrough of the new release with the design team.",
    },
    {
      name: "1:1 with Bob",
      start: inThisMonth(anchorDay, 16),
      end: inThisMonth(anchorDay, 17),
      description: "Weekly sync.",
    },
    { name: "Team Standup", start: inThisMonth(Math.max(anchorDay - 5, 2), 9), end: inThisMonth(Math.max(anchorDay - 5, 2), 10) },
    { name: "Design Review", start: inThisMonth(Math.min(anchorDay + 6, 27), 11), end: inThisMonth(Math.min(anchorDay + 6, 27), 12) },
    { name: "Client Call", start: inThisMonth(Math.min(anchorDay + 9, 28), 13), end: inThisMonth(Math.min(anchorDay + 9, 28), 14) },
  ];
  const existingEvents = (await jsonOk(
    (await page.request.get(`${API}/ui/calendars/${calendarId}/events`)) as APIResponse,
    "list events",
  )) as { events?: Array<{ event_id: string; name: string }> };
  const haveEvents = existingEvents.events ?? [];
  let demoEventId = haveEvents.find((e) => e.name === "Product Demo")?.event_id ?? "";
  if (!demoEventId) {
    for (const e of eventSpecs) {
      const created = await jsonOk(
        (await post(`/ui/calendars/${calendarId}/events`, {
          name: e.name,
          start_utc: e.start,
          end_utc: e.end,
          timezone: "UTC",
          description: e.description,
        })) as APIResponse,
        `create event ${e.name}`,
      );
      if (e.name === "Product Demo") demoEventId = created.event_id as string;
    }
  }

  // 3. A booking link (only if not already present, so re-runs don't duplicate).
  const existingLinks = (await jsonOk(
    (await page.request.get(`${API}/ui/calendars/${calendarId}/booking_links`)) as APIResponse,
    "list booking links",
  )) as Array<{ name: string }>;
  if (!existingLinks.some((l) => l.name === "30 min meeting")) {
    await jsonOk(
      (await post(`/ui/calendars/${calendarId}/booking_links`, {
        name: "30 min meeting",
        duration_minutes: 30,
      })) as APIResponse,
      "create booking link",
    );
  }

  // ── Load the shell ──────────────────────────────────────────────────────────
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1000);

  // ── 1. Intro ────────────────────────────────────────────────────────────────
  await titleCard(
    page,
    10,
    "Calendar & Booking",
    "Events · scheduling · public booking · iCal export",
  );

  // ── 2. The Calendar view (month grid with events) ───────────────────────────
  await page.goto(`${BASE}/calendar`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: /^Calendar$/ }).first()).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(900);

  // Switch to the "View" tab (the page opens on the Calendars manager tab).
  await page.getByRole("tab", { name: /^View$/ }).click().catch(() => {});
  await page.waitForTimeout(600);
  // Ensure the month grid + at least one event chip is rendered before filming.
  await expect(page.getByText("Product Demo").first()).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(900);

  await reveal(
    page,
    page.getByText("Product Demo").first(),
    "A full calendar, built in",
    "Month, week, and day views with your events laid out on a grid",
    { ms: 4200 },
  );
  await reveal(
    page,
    page.getByRole("tab", { name: /^Month$/ }),
    "Switch your view",
    "Flip between Month, Week, and Day at a glance",
    { ms: 3600 },
  );

  // Switch to the Week view to show the hourly grid, then back to Month.
  await page.getByRole("tab", { name: /^Week$/ }).click().catch(() => {});
  await page.waitForTimeout(900);
  await reveal(
    page,
    page.getByRole("tab", { name: /^Week$/ }),
    "Week at a glance",
    "An hour-by-hour grid lays out exactly when your time is booked",
    { ms: 4000 },
  );
  await page.getByRole("tab", { name: /^Month$/ }).click().catch(() => {});
  await page.waitForTimeout(800);
  await expect(page.getByText("Product Demo").first()).toBeVisible({ timeout: 8000 });

  // ── 3. Event details (click an event chip → editor dialog) ──────────────────
  await page.getByText("Product Demo").first().click().catch(() => {});
  await expect(page.getByRole("dialog")).toBeVisible({ timeout: 8000 });
  await page.waitForTimeout(800);
  await reveal(
    page,
    page.getByRole("dialog"),
    "Event details",
    "Click any event to edit its time, description, and recurrence",
    { ms: 4400 },
  );
  // Close the dialog.
  await page.keyboard.press("Escape").catch(() => {});
  await page.waitForTimeout(700);

  // ── 4. Booking Links tab ────────────────────────────────────────────────────
  await page.getByRole("tab", { name: /^Booking Links$/ }).click().catch(() => {});
  await expect(page.getByText("30 min meeting").first()).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(900);
  await reveal(
    page,
    page.getByText("30 min meeting").first(),
    "Shareable booking links",
    "Publish a link and let others pick an open slot on your calendar",
    { ms: 4400 },
  );
  // Expand the openings panel to show computed availability.
  await page.getByRole("button", { name: "View openings" }).first().click().catch(() => {});
  await page.waitForTimeout(1000);
  await caption(page, "Auto-computed availability", "Open slots are calculated from your calendar and working hours");
  await beat(page, 3600);

  // ── 5. Public event page (no-auth shareable view + iCal export) ─────────────
  await caption(page, "The public booking page", "Loading the shareable, no-login event page…");
  await page.goto(`${BASE}/event/${calendarId}/${demoEventId}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Product Demo" })).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1000);

  await reveal(
    page,
    page.getByRole("heading", { name: "Product Demo" }),
    "A public page for every event",
    "Share a link — anyone can view the details without signing in",
    { ms: 4400 },
  );
  await reveal(
    page,
    page.getByRole("button", { name: /Add to my Calendar/i }),
    "One-tap booking",
    "Visitors add the event straight to their own calendar",
    { ms: 4000 },
  );
  await reveal(
    page,
    page.getByRole("button", { name: /Download \.ics/i }),
    "iCal export",
    "Or download a standard .ics file for Apple, Google, or Outlook",
    { ms: 4400 },
  );

  // ── 6. Outro ────────────────────────────────────────────────────────────────
  await caption(page, "Calendar & Booking ✓", "Next: Tickets & Helpdesk");
  await beat(page, 3200);
  await clearCaption(page);
  await beat(page, 900);
});
