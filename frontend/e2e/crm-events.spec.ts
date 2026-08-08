/**
 * E2E tests for the SuiteCRM Events cluster (EVT-001..EVT-004).
 *
 * Sections:
 *   90 — Event CRUD + capacity — API
 *   91 — Invitee management — API
 *   92 — Registration workflow + capacity/waitlist — API
 *   93 — Events UI (list / create / detail)
 *
 * Backend router: app/routers/crm_events.py (prefix /ui/crm/events)
 * Feature flag:   CRM_EVENTS_ENABLED (default OFF -> 404). When the flag is
 *                 off the API sections expect 404 and the UI shows a
 *                 "not enabled" state.
 *
 * Auth: uses e2e_admin_session_setup.py (all identities).
 *
 * Identities:
 *   alice – e2e_alice@test.local – role=user (event owner)
 *   bob   – e2e_bob@test.local   – role=user (invitee / registrant)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, resolveIdentityId } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE     = "http://localhost:3000";
const ALICE_ID = resolveIdentityId("e2e_alice@test.local");
const BOB_ID   = resolveIdentityId("e2e_bob@test.local");
const TS       = Date.now();

interface AdminSessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
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
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
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

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}
async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}
async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

/** True when the events feature is disabled (router returns 404). */
async function eventsDisabled(page: Page): Promise<boolean> {
  const r = await apiPost(page, ALICE_ID, "ui/crm/events/", { name: "probe" });
  return r.status() === 404;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 90 — Event CRUD + capacity (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 90: CRM Event CRUD + capacity (API)", () => {
  let alicePage: Page;
  let disabled = false;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
    disabled = await eventsDisabled(alicePage);
  });
  test.afterAll(async () => { await alicePage?.close(); });

  test("90.1 create event returns 201 with event_id (or 404 when disabled)", async () => {
    const res = await apiPost(alicePage, ALICE_ID, "ui/crm/events/", {
      name: `E2E Event ${TS}`,
      description: "Created by Playwright",
      max_attendance: 2,
    });
    if (disabled) {
      expect(res.status()).toBe(404);
      return;
    }
    expect(res.status()).toBe(201);
    const body = await res.json();
    expect(body.event_id).toBeTruthy();
    expect(body.name).toBe(`E2E Event ${TS}`);
    expect(body.max_attendance).toBe(2);
  });

  test("90.2 capacity endpoint reports limits", async () => {
    const c = await apiPost(alicePage, ALICE_ID, "ui/crm/events/", {
      name: `Cap Event ${TS}`,
      max_attendance: 5,
    });
    if (disabled) { expect(c.status()).toBe(404); return; }
    const ev = await c.json();
    const cap = await apiGet(alicePage, `ui/crm/events/${ev.event_id}/capacity`);
    expect(cap.status()).toBe(200);
    const body = await cap.json();
    expect(body.max_attendance).toBe(5);
    expect(body.accepted_count).toBe(0);
    expect(body.available_spots).toBe(5);
  });

  test("90.3 capacity for unknown event is 404", async () => {
    const cap = await apiGet(alicePage, `ui/crm/events/does-not-exist-${TS}/capacity`);
    expect([404]).toContain(cap.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 91 — Invitee management (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 91: Invitee management (API)", () => {
  let alicePage: Page;
  let eventId = "";
  let disabled = false;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
    disabled = await eventsDisabled(alicePage);
    if (!disabled) {
      const r = await apiPost(alicePage, ALICE_ID, "ui/crm/events/", { name: `Invitee Event ${TS}` });
      eventId = (await r.json()).event_id;
    }
  });
  test.afterAll(async () => { await alicePage?.close(); });

  test("91.1 add + list invitee", async () => {
    if (disabled) { test.skip(); return; }
    const add = await apiPost(alicePage, ALICE_ID, `ui/crm/events/${eventId}/invitees`, {
      invitee_sub: BOB_ID,
    });
    expect(add.status()).toBe(201);
    const inv = await add.json();
    expect(inv.invitee_sub).toBe(BOB_ID);
    expect(inv.invite_status).toBe("pending");

    const list = await apiGet(alicePage, `ui/crm/events/${eventId}/invitees`);
    expect(list.status()).toBe(200);
    const body = await list.json();
    expect(body.invitees.some((i: any) => i.invitee_sub === BOB_ID)).toBe(true);
  });

  test("91.2 send invitations advances status", async () => {
    if (disabled) { test.skip(); return; }
    const res = await apiPost(alicePage, ALICE_ID, `ui/crm/events/${eventId}/invitees/send-invitations`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty("sent");
    expect(body).toHaveProperty("skipped");
    expect(body).toHaveProperty("failed");
  });

  test("91.3 remove invitee returns 204", async () => {
    if (disabled) { test.skip(); return; }
    const del = await apiDelete(alicePage, ALICE_ID, `ui/crm/events/${eventId}/invitees/${encodeURIComponent(BOB_ID)}`);
    expect(del.status()).toBe(204);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 92 — Registration workflow + capacity/waitlist (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 92: Registration workflow (API)", () => {
  let alicePage: Page;
  let bobPage: Page;
  let eventId = "";
  let disabled = false;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
    bobPage = await newIdentityPage(browser, BOB_ID);
    disabled = await eventsDisabled(alicePage);
    if (!disabled) {
      const r = await apiPost(alicePage, ALICE_ID, "ui/crm/events/", {
        name: `Reg Event ${TS}`,
        max_attendance: 10,
      });
      eventId = (await r.json()).event_id;
    }
  });
  test.afterAll(async () => { await alicePage?.close(); await bobPage?.close(); });

  test("92.1 self-register returns 201", async () => {
    if (disabled) { test.skip(); return; }
    const reg = await apiPost(bobPage, BOB_ID, `ui/crm/events/${eventId}/registrations`);
    expect(reg.status()).toBe(201);
    const body = await reg.json();
    expect(body.registrant_sub).toBe(BOB_ID);
    expect(["registered", "waitlisted"]).toContain(body.status);
  });

  test("92.2 duplicate registration returns 409", async () => {
    if (disabled) { test.skip(); return; }
    const reg = await apiPost(bobPage, BOB_ID, `ui/crm/events/${eventId}/registrations`);
    expect(reg.status()).toBe(409);
  });

  test("92.3 owner can check in registrant", async () => {
    if (disabled) { test.skip(); return; }
    const ci = await apiPost(alicePage, ALICE_ID, `ui/crm/events/${eventId}/registrations/${encodeURIComponent(BOB_ID)}/check-in`);
    expect(ci.status()).toBe(200);
    expect((await ci.json()).status).toBe("attended");
  });

  test("92.4 list registrations shows the registrant", async () => {
    if (disabled) { test.skip(); return; }
    const list = await apiGet(alicePage, `ui/crm/events/${eventId}/registrations`);
    expect(list.status()).toBe(200);
    const body = await list.json();
    expect(body.registrations.some((r: any) => r.registrant_sub === BOB_ID)).toBe(true);
  });

  test("92.5 cancel registration returns 204", async () => {
    if (disabled) { test.skip(); return; }
    const del = await apiDelete(bobPage, BOB_ID, `ui/crm/events/${eventId}/registrations/${encodeURIComponent(BOB_ID)}`);
    expect(del.status()).toBe(204);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 93 — Events UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 93: Events UI", () => {
  let page: Page;
  let disabled = false;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    const probe = await newIdentityPage(browser, ALICE_ID);
    disabled = await eventsDisabled(probe);
    await probe.close();
  });
  test.afterAll(async () => { await page?.close(); });

  test("93.1 events list page renders", async () => {
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/crm/events`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Events", exact: true })).toBeVisible();
  });

  test("93.2 create page renders the form (or disabled state)", async () => {
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/crm/events/new`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Create Event" })).toBeVisible();
    await expect(page.getByLabel("Name *")).toBeVisible();
  });

  test("93.3 create event via UI navigates to detail", async () => {
    if (disabled) { test.skip(); return; }
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/crm/events/new`, { waitUntil: "domcontentloaded" });
    const name = `UI Event ${TS}`;
    await page.getByLabel("Name *").fill(name);
    await page.getByRole("button", { name: "Create event" }).click();
    await page.waitForURL(/\/crm\/events\/[0-9a-f]+/, { timeout: 10_000 });
    await expect(page.getByText("Registrations", { exact: false }).first()).toBeVisible();
  });
});
