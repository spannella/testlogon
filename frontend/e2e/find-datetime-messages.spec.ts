/**
 * E2E tests for Find-a-DateTime Messages (MSG-009).
 *
 * A group availability finder embedded as a new message kind (`find_datetime`).
 * Participants mark available time ranges on a continuous grid; the backend
 * computes the best overlapping windows on close.
 *
 * Actors:
 *   Alice   (e2e_alice@test.local)   — creator / primary actor
 *   Bob     (e2e_bob@test.local)     — participant
 *   Charlie (e2e_charlie@test.local) — group participant
 *
 * Auth patterns:
 *   - Alice: browser-context cookies + CSRF (page.request + x-csrf-token)
 *   - Bob/Charlie: dev-mode Bearer token auth (request fixture, bypasses CSRF)
 *
 * Sections:
 *   712. Find-a-DateTime Creation API
 *   713. Availability Submission API
 *   714. Close & Compute API
 *   715. Find-a-DateTime Message Rendering (UI)
 *   716. Group parity & edge cases
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";

const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";

const TS = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None";
    expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
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

type APIRequestContext = import("@playwright/test").APIRequestContext;

/** POST authenticated as Alice (browser context cookies + Alice CSRF). */
async function apiPost(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

/** GET authenticated as Alice. */
async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

/** POST as an arbitrary user using the dev-mode Bearer token. */
async function apiPostBearer(req: APIRequestContext, path: string, body: object, userId: string) {
  return req.post(`${API}${path}`, {
    data: body,
    headers: { Authorization: `Bearer ${userId}` },
  });
}

/** GET as an arbitrary user using the dev-mode Bearer token. */
async function apiGetBearer(req: APIRequestContext, path: string, userId: string) {
  return req.get(`${API}${path}`, {
    headers: { Authorization: `Bearer ${userId}` },
  });
}

// ─── Date helpers (grid range = tomorrow .. +3 days) ──────────────────────────

function isoDate(offsetDays: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + offsetDays);
  return d.toISOString().slice(0, 10);
}

const FROM_DATE = isoDate(1);
const TO_DATE = isoDate(3);

interface CreateFadtReq {
  title: string;
  from_date?: string;
  to_date?: string;
  start_hour?: number;
  end_hour?: number;
  slot_duration_minutes?: number;
  deadline_hours?: number;
  text?: string;
}

function fadtBody(req: CreateFadtReq): object {
  return {
    title: req.title,
    from_date: req.from_date ?? FROM_DATE,
    to_date: req.to_date ?? TO_DATE,
    start_hour: req.start_hour ?? 9,
    end_hour: req.end_hour ?? 17,
    slot_duration_minutes: req.slot_duration_minutes ?? 30,
    deadline_hours: req.deadline_hours ?? 48,
    text: req.text,
  };
}

// ─── Conversation bootstrap ───────────────────────────────────────────────────

async function createDm(page: Page): Promise<string> {
  const bobSub = getSessions()[BOB_ID].user_sub;
  const resp = await apiPost(page, "/messaging/conversations", {
    participant_ids: [bobSub],
    type: "dm",
  });
  if (!resp.ok()) {
    const body = await resp.text().catch(() => "(unreadable)");
    throw new Error(`DM creation failed: HTTP ${resp.status()} — ${body}`);
  }
  return (await resp.json()).conversation_id as string;
}

async function createGroup(page: Page, request: APIRequestContext): Promise<string> {
  const bobSub = getSessions()[BOB_ID].user_sub;
  const charlieSub = getSessions()[CHARLIE_ID].user_sub;
  const resp = await apiPost(page, "/messaging/conversations/group", {
    participant_ids: [bobSub, charlieSub],
    title: `FADT Group ${TS}`,
  });
  if (!resp.ok()) {
    const body = await resp.text().catch(() => "(unreadable)");
    throw new Error(`Group creation failed: HTTP ${resp.status()} — ${body}`);
  }
  const convoId = (await resp.json()).conversation_id as string;
  // Group members are invited as "pending" and must accept before they count as
  // active participants (require_participant_active) — otherwise availability
  // submission returns 403 and participant_count stays at 1.
  for (const userId of [BOB_ID, CHARLIE_ID]) {
    await apiPostBearer(request, `/messaging/conversations/${convoId}/accept`, {}, userId);
  }
  return convoId;
}

async function createFadt(page: Page, convoId: string, req: CreateFadtReq) {
  return apiPost(page, `/messaging/conversations/${convoId}/messages/find-datetime`, fadtBody(req));
}

interface RawMsg {
  message_id: string;
  kind: string;
  find_datetime?: {
    poll_id: string;
    title: string;
    status: string;
    from_date: string;
    to_date: string;
    start_hour: number;
    end_hour: number;
    slot_duration_minutes: number;
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 712: Find-a-DateTime Creation API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 712: Find-a-DateTime Creation API", () => {
  let convoId: string;

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await createDm(page);
    await page.close();
  });

  test("712.1 create FADT with valid parameters", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await createFadt(page, convoId, { title: `Standup ${TS}-712-1` });
    expect(resp.status()).toBe(201);
    const msg = (await resp.json()) as RawMsg;
    expect(msg.kind).toBe("find_datetime");
    expect(msg.find_datetime?.poll_id).toMatch(/^fadt_/);
    expect(msg.find_datetime?.status).toBe("open");
    await page.close();
  });

  test("712.2 FADT metadata stored correctly", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await createFadt(page, convoId, {
      title: `Meta ${TS}-712-2`,
      start_hour: 8,
      end_hour: 12,
      slot_duration_minutes: 60,
    });
    expect(resp.status()).toBe(201);
    const pollId = (await resp.json()).find_datetime.poll_id as string;
    const getResp = await apiGet(page, `/messaging/messages/find-datetime/${pollId}`);
    expect(getResp.status()).toBe(200);
    const full = await getResp.json();
    expect(full.meta.title).toBe(`Meta ${TS}-712-2`);
    expect(full.meta.from_date).toBe(FROM_DATE);
    expect(full.meta.to_date).toBe(TO_DATE);
    expect(full.meta.start_hour).toBe(8);
    expect(full.meta.end_hour).toBe(12);
    expect(full.meta.slot_duration_minutes).toBe(60);
    expect(full.meta.status).toBe("open");
    expect(full.result).toBeNull();
    await page.close();
  });

  test("712.3 reject from_date >= to_date", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await createFadt(page, convoId, {
      title: `Bad ${TS}-712-3`,
      from_date: TO_DATE,
      to_date: FROM_DATE,
    });
    expect(resp.status()).toBe(400);
    await page.close();
  });

  test("712.4 reject start_hour >= end_hour", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await createFadt(page, convoId, {
      title: `Bad ${TS}-712-4`,
      start_hour: 17,
      end_hour: 9,
    });
    expect(resp.status()).toBe(422);
    await page.close();
  });

  test("712.5 reject invalid slot_duration", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await createFadt(page, convoId, {
      title: `Bad ${TS}-712-5`,
      slot_duration_minutes: 45,
    });
    expect(resp.status()).toBe(422);
    await page.close();
  });

  test("712.6 reject date range > 14 days", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await createFadt(page, convoId, {
      title: `Long ${TS}-712-6`,
      from_date: isoDate(1),
      to_date: isoDate(20),
    });
    expect(resp.status()).toBe(400);
    const body = await resp.text();
    expect(body).toContain("Date range cannot exceed");
    await page.close();
  });

  test("712.7 auth required (no cookie/bearer → 401)", async ({ request }) => {
    const resp = await request.post(
      `${API}/messaging/conversations/${convoId}/messages/find-datetime`,
      { data: fadtBody({ title: "x" }) },
    );
    expect(resp.status()).toBe(401);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 713: Availability Submission API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 713: Availability Submission API", () => {
  let convoId: string;
  let pollId: string;

  test.beforeAll(async ({ browser, request }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await createGroup(page, request);
    const resp = await createFadt(page, convoId, { title: `AvailPoll ${TS}-713` });
    pollId = (await resp.json()).find_datetime.poll_id;
    await page.close();
  });

  test("713.1 Alice submits availability", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const slots = [`${FROM_DATE}T09:00`, `${FROM_DATE}T09:30`, `${FROM_DATE}T10:00`];
    const resp = await apiPost(page, `/messaging/messages/find-datetime/${pollId}/availability`, { slots });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.slots_count).toBe(3);
    await page.close();
  });

  test("713.2 Bob submits availability → participant_count = 2", async ({ request }) => {
    const slots = [`${FROM_DATE}T09:00`, `${FROM_DATE}T09:30`];
    const resp = await apiPostBearer(
      request,
      `/messaging/messages/find-datetime/${pollId}/availability`,
      { slots },
      BOB_ID,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.participant_count).toBe(2);
  });

  test("713.3 Alice updates availability (replaces old)", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const slots = [`${FROM_DATE}T14:00`, `${FROM_DATE}T14:30`];
    const resp = await apiPost(page, `/messaging/messages/find-datetime/${pollId}/availability`, { slots });
    expect(resp.status()).toBe(200);
    // Re-fetch and confirm slots were replaced, participant count unchanged.
    const getResp = await apiGet(page, `/messaging/messages/find-datetime/${pollId}`);
    const full = await getResp.json();
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    const mine = full.availabilities.find((a: { user_sub: string }) => a.user_sub === aliceSub);
    expect(mine.slots).toEqual([`${FROM_DATE}T14:00`, `${FROM_DATE}T14:30`]);
    expect(full.meta.participant_count).toBe(2);
    await page.close();
  });

  test("713.4 reject availability for non-existent poll (404)", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiPost(
      page,
      `/messaging/messages/find-datetime/fadt_doesnotexist${TS}/availability`,
      { slots: [`${FROM_DATE}T09:00`] },
    );
    expect(resp.status()).toBe(404);
    await page.close();
  });

  test("713.5 reject slot outside date range (400)", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiPost(page, `/messaging/messages/find-datetime/${pollId}/availability`, {
      slots: [`${isoDate(90)}T09:00`],
    });
    expect(resp.status()).toBe(400);
    await page.close();
  });

  test("713.6 reject empty slots list (422)", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiPost(page, `/messaging/messages/find-datetime/${pollId}/availability`, {
      slots: [],
    });
    expect(resp.status()).toBe(422);
    await page.close();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 714: Close & Compute API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 714: Close & Compute API", () => {
  let convoId: string;
  let pollId: string;

  test.beforeAll(async ({ browser, request }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await createGroup(page, request);
    const resp = await createFadt(page, convoId, { title: `ClosePoll ${TS}-714` });
    pollId = (await resp.json()).find_datetime.poll_id;
    // Alice + Bob both available 09:00-10:00 (overlap), Alice also 14:00.
    await apiPost(page, `/messaging/messages/find-datetime/${pollId}/availability`, {
      slots: [`${FROM_DATE}T09:00`, `${FROM_DATE}T09:30`, `${FROM_DATE}T14:00`],
    });
    await apiPostBearer(
      request,
      `/messaging/messages/find-datetime/${pollId}/availability`,
      { slots: [`${FROM_DATE}T09:00`, `${FROM_DATE}T09:30`] },
      BOB_ID,
    );
    await page.close();
  });

  test("714.1 non-creator cannot close (403)", async ({ request }) => {
    const resp = await apiPostBearer(
      request,
      `/messaging/messages/find-datetime/${pollId}/close`,
      {},
      BOB_ID,
    );
    expect(resp.status()).toBe(403);
  });

  test("714.2 creator closes poll & best windows computed", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiPost(page, `/messaging/messages/find-datetime/${pollId}/close`, {});
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("closed");
    expect(Array.isArray(body.result.best_windows)).toBe(true);
    expect(body.result.best_windows.length).toBeGreaterThan(0);
    // Top window is the 09:00-10:00 overlap shared by both participants.
    const top = body.result.best_windows[0];
    expect(top.start).toBe(`${FROM_DATE}T09:00`);
    expect(top.end).toBe(`${FROM_DATE}T10:00`);
    expect(top.count).toBe(2);
    expect(top.participants.length).toBe(2);
    await page.close();
  });

  test("714.3 best windows ranked by count descending", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const getResp = await apiGet(page, `/messaging/messages/find-datetime/${pollId}`);
    const full = await getResp.json();
    const windows = full.result.best_windows as Array<{ count: number }>;
    for (let i = 1; i < windows.length; i++) {
      expect(windows[i - 1].count).toBeGreaterThanOrEqual(windows[i].count);
    }
    await page.close();
  });

  test("714.4 closed poll rejects new availability (400)", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiPost(page, `/messaging/messages/find-datetime/${pollId}/availability`, {
      slots: [`${FROM_DATE}T11:00`],
    });
    expect(resp.status()).toBe(400);
    const body = await resp.text();
    expect(body.toLowerCase()).toContain("closed");
    await page.close();
  });

  test("714.5 closing already-closed poll returns error (400)", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiPost(page, `/messaging/messages/find-datetime/${pollId}/close`, {});
    expect(resp.status()).toBe(400);
    const body = await resp.text();
    expect(body.toLowerCase()).toContain("already closed");
    await page.close();
  });

  test("714.6 poll data retrievable by any participant (Bob)", async ({ request }) => {
    const resp = await apiGetBearer(request, `/messaging/messages/find-datetime/${pollId}`, BOB_ID);
    expect(resp.status()).toBe(200);
    const full = await resp.json();
    expect(full.availabilities.length).toBe(2);
    expect(full.result).not.toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 715: Find-a-DateTime Message Rendering (UI)
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 715: Find-a-DateTime Rendering", () => {
  let convoId: string;
  const title = `RenderFADT ${TS}-715`;

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await createDm(page);
    await createFadt(page, convoId, { title });
    await page.close();
  });

  test("715.1 FADT card renders with title", async ({ page }) => {
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages/${convoId}`, { waitUntil: "domcontentloaded" });
    await page.evaluate(() => window.dispatchEvent(new Event("online")));
    const card = page.locator('[data-testid="fadt-card"]').filter({ hasText: title });
    await expect(card).toBeVisible({ timeout: 15_000 });
    await expect(card.locator('[data-testid="fadt-title"]')).toContainText(title);
  });

  test("715.2 open FADT shows Submit Availability affordance", async ({ page }) => {
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages/${convoId}`, { waitUntil: "domcontentloaded" });
    await page.evaluate(() => window.dispatchEvent(new Event("online")));
    const card = page.locator('[data-testid="fadt-card"]').filter({ hasText: title });
    await expect(card).toBeVisible({ timeout: 15_000 });
    await expect(card.getByRole("button", { name: /submit availability/i })).toBeVisible();
  });

  test("715.3 opening grid shows the availability grid", async ({ page }) => {
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages/${convoId}`, { waitUntil: "domcontentloaded" });
    await page.evaluate(() => window.dispatchEvent(new Event("online")));
    const card = page.locator('[data-testid="fadt-card"]').filter({ hasText: title });
    await expect(card).toBeVisible({ timeout: 15_000 });
    await card.getByRole("button", { name: /submit availability/i }).click();
    await expect(page.locator('[data-testid="availability-grid"]')).toBeVisible({ timeout: 10_000 });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 716: Group parity & edge cases
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 716: Group parity & edge cases", () => {
  test("716.1 FADT works in group chats with 3 participants", async ({ browser, request }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const convoId = await createGroup(page, request);
    const resp = await createFadt(page, convoId, { title: `GroupFADT ${TS}-716-1` });
    expect(resp.status()).toBe(201);
    const pollId = (await resp.json()).find_datetime.poll_id;

    await apiPost(page, `/messaging/messages/find-datetime/${pollId}/availability`, {
      slots: [`${FROM_DATE}T09:00`, `${FROM_DATE}T09:30`],
    });
    await apiPostBearer(
      request,
      `/messaging/messages/find-datetime/${pollId}/availability`,
      { slots: [`${FROM_DATE}T09:00`, `${FROM_DATE}T09:30`] },
      BOB_ID,
    );
    const charlieResp = await apiPostBearer(
      request,
      `/messaging/messages/find-datetime/${pollId}/availability`,
      { slots: [`${FROM_DATE}T09:00`] },
      CHARLIE_ID,
    );
    expect(charlieResp.status()).toBe(200);
    expect((await charlieResp.json()).participant_count).toBe(3);

    const closeResp = await apiPost(page, `/messaging/messages/find-datetime/${pollId}/close`, {});
    expect(closeResp.status()).toBe(200);
    const top = (await closeResp.json()).result.best_windows[0];
    expect(top.start).toBe(`${FROM_DATE}T09:00`);
    expect(top.count).toBe(3);
    await page.close();
  });

  test("716.2 15-minute slot granularity accepted", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const convoId = await createDm(page);
    const resp = await createFadt(page, convoId, {
      title: `Fifteen ${TS}-716-2`,
      slot_duration_minutes: 15,
    });
    expect(resp.status()).toBe(201);
    const pollId = (await resp.json()).find_datetime.poll_id;
    const submit = await apiPost(page, `/messaging/messages/find-datetime/${pollId}/availability`, {
      slots: [`${FROM_DATE}T09:00`, `${FROM_DATE}T09:15`, `${FROM_DATE}T09:30`],
    });
    expect(submit.status()).toBe(200);
    expect((await submit.json()).slots_count).toBe(3);
    await page.close();
  });

  test("716.3 duplicate slots are deduplicated server-side", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const convoId = await createDm(page);
    const resp = await createFadt(page, convoId, { title: `Dedup ${TS}-716-3` });
    const pollId = (await resp.json()).find_datetime.poll_id;
    const submit = await apiPost(page, `/messaging/messages/find-datetime/${pollId}/availability`, {
      slots: [`${FROM_DATE}T09:00`, `${FROM_DATE}T09:00`, `${FROM_DATE}T09:30`],
    });
    expect(submit.status()).toBe(200);
    expect((await submit.json()).slots_count).toBe(2);
    await page.close();
  });
});
