/**
 * E2E tests for Countdown Messages (MSG-010).
 *
 * A countdown message displays a live ticking countdown to a target datetime.
 * When the countdown reaches zero it switches to an "expired"/"live now" state,
 * optionally showing a CTA button (Watch Live / Join Call / View Event).
 *
 * Actors:
 *   Alice  (e2e_alice@test.local)   — sender / primary actor
 *   Bob    (e2e_bob@test.local)     — recipient
 *   Charlie (e2e_charlie@test.local) — group participant
 *
 * Auth patterns:
 *   - Alice: browser-context cookies + CSRF (page.request + x-csrf-token)
 *   - Bob/Charlie: dev-mode Bearer token auth (request fixture, bypasses CSRF)
 *
 * Sections:
 *   696. Countdown Message API
 *   697. Countdown Message in Conversation
 *   698. Countdown Rendering (UI)
 *   699. Countdown Validation Edge Cases
 *   700. Countdown in Group Chats
 *   701. Countdown CTA Buttons (UI)
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, cppRegisterThrowaway } from "./helpers/session";
import { usingCpp, cppBearerPost, cppBearerGet } from "./helpers/cpp-seed-messaging-calls";
import { asArray } from "./helpers/shape";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ───────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";

const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";

const TS = Date.now();
const nowSec = () => Math.floor(Date.now() / 1000);

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
  const sub = getSessions()[userId]?.user_sub ?? userId; // non-member fallback: raw id (cpp dev raw-sub) -> non-participant 403
  if (usingCpp()) return cppBearerPost(path, body, sub);
  return req.post(`${API}${path}`, {
    data: body,
    headers: { Authorization: `Bearer ${sub}` },
  });
}

/** GET as an arbitrary user using the dev-mode Bearer token. */
async function apiGetBearer(req: APIRequestContext, path: string, userId: string) {
  const sub = getSessions()[userId]?.user_sub ?? userId; // non-member fallback: raw id (cpp dev raw-sub) -> non-participant 403
  if (usingCpp()) return cppBearerGet(path, sub);
  return req.get(`${API}${path}`, {
    headers: { Authorization: `Bearer ${sub}` },
  });
}

// ─── DM conversation bootstrap ────────────────────────────────────────────────

let _dmConvoId: string | null = null;

async function getOrCreateDm(page: Page): Promise<string> {
  if (_dmConvoId) return _dmConvoId;
  const bobSub = getSessions()[BOB_ID].user_sub;
  const resp = await apiPost(page, "/messaging/conversations", {
    participant_ids: [bobSub],
    type: "dm",
  });
  if (!resp.ok()) {
    const body = await resp.text().catch(() => "(unreadable)");
    throw new Error(`DM creation failed: HTTP ${resp.status()} — ${body}`);
  }
  const body = await resp.json();
  _dmConvoId = body.conversation_id as string;
  return _dmConvoId;
}

interface CountdownReq {
  title: string;
  target_datetime: number;
  associated_event_type?: string;
  associated_event_id?: string;
  reply_to_message_id?: string;
}

async function sendCountdown(page: Page, convoId: string, body: CountdownReq) {
  return apiPost(page, `/messaging/conversations/${convoId}/messages/countdown`, body);
}

interface RawMsg {
  message_id: string;
  kind: string;
  countdown_title?: string;
  target_datetime?: number;
  associated_event_type?: string;
  associated_event_id?: string;
  text?: string;
  reply_to_message_id?: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 696: Countdown Message API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 696: Countdown Message API", () => {
  let convoId: string;

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await getOrCreateDm(page);
    await page.close();
  });

  test("696.1 create countdown with valid future target", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const title = `Standup ${TS}-696-1`;
    const target = nowSec() + 3600;
    const resp = await sendCountdown(page, convoId, { title, target_datetime: target });
    expect(resp.status()).toBe(201);
    const msg = (await resp.json()) as RawMsg;
    expect(msg.kind).toBe("countdown");
    expect(msg.countdown_title).toBe(title);
    expect(msg.target_datetime).toBe(target);
    await page.close();
  });

  test("696.2 custom event type needs no event id", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await sendCountdown(page, convoId, {
      title: `Birthday ${TS}-696-2`,
      target_datetime: nowSec() + 7200,
      associated_event_type: "custom",
    });
    expect(resp.status()).toBe(201);
    const msg = (await resp.json()) as RawMsg;
    expect(msg.associated_event_type).toBe("custom");
    expect(msg.associated_event_id ?? null).toBeNull();
    await page.close();
  });

  test("696.3 broadcast link is accepted", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await sendCountdown(page, convoId, {
      title: `Live ${TS}-696-3`,
      target_datetime: nowSec() + 1800,
      associated_event_type: "broadcast",
      associated_event_id: `bcast_${TS}`,
    });
    expect(resp.status()).toBe(201);
    const msg = (await resp.json()) as RawMsg;
    expect(msg.associated_event_type).toBe("broadcast");
    expect(msg.associated_event_id).toBe(`bcast_${TS}`);
    await page.close();
  });

  test("696.4 reject past target_datetime", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await sendCountdown(page, convoId, {
      title: `Past ${TS}-696-4`,
      target_datetime: nowSec() - 60,
    });
    expect(resp.status()).toBe(422);
    const body = await resp.text();
    expect(body).toContain("target_datetime must be in the future");
    await page.close();
  });

  test("696.5 reject broadcast without event id", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await sendCountdown(page, convoId, {
      title: `NoId ${TS}-696-5`,
      target_datetime: nowSec() + 600,
      associated_event_type: "broadcast",
    });
    expect(resp.status()).toBe(422);
    await page.close();
  });

  test("696.6 auth required (no cookie/bearer → 401)", async ({ browser }) => {
    const anonCtx = await browser.newContext({ storageState: undefined });
    const resp = await anonCtx.request.post(
      `${API}/messaging/conversations/${convoId}/messages/countdown`,
      { data: { title: "x", target_datetime: nowSec() + 600 } },
    );
    await anonCtx.close();
    expect(resp.status()).toBe(401);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 697: Countdown Message in Conversation
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 697: Countdown Message in Conversation", () => {
  let convoId: string;
  let countdownId: string;
  const title = `ConvCountdown ${TS}-697`;
  const target = nowSec() + 5400;

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await getOrCreateDm(page);
    const resp = await sendCountdown(page, convoId, { title, target_datetime: target });
    const msg = (await resp.json()) as RawMsg;
    countdownId = msg.message_id;
    await page.close();
  });

  test("697.1 countdown appears in message list", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiGet(page, `/messaging/conversations/${convoId}/messages`);
    expect(resp.ok()).toBeTruthy();
    const data = asArray<RawMsg>(await resp.json());
    const found = data.find((m) => m.message_id === countdownId);
    expect(found).toBeDefined();
    expect(found!.kind).toBe("countdown");
    expect(found!.countdown_title).toBe(title);
    await page.close();
  });

  test("697.2 Bob receives the countdown", async ({ request }) => {
    const resp = await apiGetBearer(request, `/messaging/conversations/${convoId}/messages`, BOB_ID);
    expect(resp.ok()).toBeTruthy();
    const data = asArray<RawMsg>(await resp.json());
    const found = data.find((m) => m.message_id === countdownId);
    expect(found).toBeDefined();
    expect(found!.target_datetime).toBe(target);
    await request.dispose();
  });

  test("697.3 countdown supports replies", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiPost(page, `/messaging/conversations/${convoId}/messages`, {
      text: `reply-to-countdown ${TS}-697-3`,
      reply_to_message_id: countdownId,
    });
    expect([200, 201]).toContain(resp.status());
    const msg = (await resp.json()) as RawMsg;
    expect(msg.reply_to_message_id).toBe(countdownId);
    await page.close();
  });

  test("697.4 countdown appears in conversation last_message preview", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    // Fresh countdown so it's the most recent message in this DM.
    const freshTitle = `LastMsg ${TS}-697-4`;
    await sendCountdown(page, convoId, { title: freshTitle, target_datetime: nowSec() + 999 });
    const resp = await apiGet(page, `/messaging/conversations/${convoId}`);
    expect(resp.ok()).toBeTruthy();
    const convo = (await resp.json()) as {
      last_message?: { kind?: string; countdown_title?: string };
      last_message_preview?: string;
    };
    const kind = convo.last_message?.kind;
    const preview = convo.last_message_preview ?? "";
    expect(kind === "countdown" || preview.includes("Countdown")).toBeTruthy();
    await page.close();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 698: Countdown Rendering (UI)
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 698: Countdown Rendering", () => {
  let convoId: string;

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await getOrCreateDm(page);
    await page.close();
  });

  test("698.1 active countdown shows ticking timer", async ({ page }) => {
    await injectAuth(page, ALICE_ID);
    const title = `RenderActive ${TS}-698-1`;
    await sendCountdown(page, convoId, { title, target_datetime: nowSec() + 3600 });
    await page.goto(`${BASE}/messages/${convoId}`, { waitUntil: "domcontentloaded" });
    await page.evaluate(() => window.dispatchEvent(new Event("online")));
    const card = page.locator('[data-testid="countdown-card"]').filter({ hasText: title });
    await expect(card).toBeVisible({ timeout: 15_000 });
    const timer = card.locator('[data-testid="countdown-timer"]');
    await expect(timer).toBeVisible();
    await expect(timer).toContainText(":");
  });

  test("698.2 countdown card shows its title", async ({ page }) => {
    await injectAuth(page, ALICE_ID);
    const title = `RenderTitle ${TS}-698-2`;
    await sendCountdown(page, convoId, { title, target_datetime: nowSec() + 3600 });
    await page.goto(`${BASE}/messages/${convoId}`, { waitUntil: "domcontentloaded" });
    await page.evaluate(() => window.dispatchEvent(new Event("online")));
    const card = page.locator('[data-testid="countdown-card"]').filter({ hasText: title });
    await expect(card).toBeVisible({ timeout: 15_000 });
    await expect(card.locator('[data-testid="countdown-title"]')).toContainText(title);
  });

  test("698.3 expired custom countdown shows completion state", async ({ page }) => {
    await injectAuth(page, ALICE_ID);
    const title = `RenderExpired ${TS}-698-3`;
    // Target a few seconds in the future so the live timer flips while we watch.
    await sendCountdown(page, convoId, {
      title,
      target_datetime: nowSec() + 4,
      associated_event_type: "custom",
    });
    await page.goto(`${BASE}/messages/${convoId}`, { waitUntil: "domcontentloaded" });
    await page.evaluate(() => window.dispatchEvent(new Event("online")));
    const card = page.locator('[data-testid="countdown-card"]').filter({ hasText: title });
    await expect(card).toBeVisible({ timeout: 15_000 });
    await expect(card.locator('[data-testid="countdown-expired"]')).toBeVisible({ timeout: 15_000 });
    await expect(card).toContainText("Time's up!");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 699: Countdown Validation Edge Cases
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 699: Countdown Validation Edge Cases", () => {
  let convoId: string;

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await getOrCreateDm(page);
    await page.close();
  });

  test("699.1 reject title > 200 chars", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await sendCountdown(page, convoId, {
      title: "x".repeat(201),
      target_datetime: nowSec() + 600,
    });
    expect(resp.status()).toBe(422);
    await page.close();
  });

  test("699.2 reject invalid event type", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await sendCountdown(page, convoId, {
      title: `Invalid ${TS}-699-2`,
      target_datetime: nowSec() + 600,
      associated_event_type: "invalid",
    });
    expect(resp.status()).toBe(422);
    await page.close();
  });

  test("699.3 calendar event type with id is accepted", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await sendCountdown(page, convoId, {
      title: `Cal ${TS}-699-3`,
      target_datetime: nowSec() + 600,
      associated_event_type: "calendar",
      associated_event_id: `evt_${TS}`,
    });
    expect(resp.status()).toBe(201);
    const msg = (await resp.json()) as RawMsg;
    expect(msg.associated_event_type).toBe("calendar");
    await page.close();
  });

  test("699.4 call event type with id is accepted", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await sendCountdown(page, convoId, {
      title: `Call ${TS}-699-4`,
      target_datetime: nowSec() + 600,
      associated_event_type: "call",
      associated_event_id: `call_${TS}`,
    });
    expect(resp.status()).toBe(201);
    const msg = (await resp.json()) as RawMsg;
    expect(msg.associated_event_type).toBe("call");
    expect(msg.associated_event_id).toBe(`call_${TS}`);
    await page.close();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 700: Countdown in Group Chats
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 700: Countdown in Group Chats", () => {
  let groupId: string;

  test.beforeAll(async ({ browser, request }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const bobSub = getSessions()[BOB_ID].user_sub;
    const charlieSub = getSessions()[CHARLIE_ID].user_sub;
    const resp = await apiPost(page, "/messaging/conversations/group", {
      participant_ids: [bobSub, charlieSub],
      title: `Countdown Group ${TS}`,
    });
    const body = (await resp.json()) as { conversation_id: string };
    groupId = body.conversation_id;
    for (const userId of [BOB_ID, CHARLIE_ID]) {
      await apiPostBearer(request, `/messaging/conversations/${groupId}/accept`, {}, userId);
    }
    await page.close();
  });

  test("700.1 create countdown in group; participants receive it", async ({ browser, request }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const title = `GroupCD ${TS}-700-1`;
    const resp = await sendCountdown(page, groupId, { title, target_datetime: nowSec() + 3600 });
    expect(resp.status()).toBe(201);
    const created = (await resp.json()) as RawMsg;
    const bobResp = await apiGetBearer(request, `/messaging/conversations/${groupId}/messages`, BOB_ID);
    const bobData = asArray<RawMsg>(await bobResp.json());
    expect(bobData.find((m) => m.message_id === created.message_id)).toBeDefined();
    await page.close();
  });

  test("700.2 multiple countdowns coexist with distinct ids", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) {
      const resp = await sendCountdown(page, groupId, {
        title: `Multi ${TS}-700-2-${i}`,
        target_datetime: nowSec() + 1000 + i,
      });
      ids.push(((await resp.json()) as RawMsg).message_id);
    }
    expect(new Set(ids).size).toBe(3);
    const listResp = await apiGet(page, `/messaging/conversations/${groupId}/messages`);
    const data = asArray<RawMsg>(await listResp.json());
    for (const id of ids) {
      expect(data.find((m) => m.message_id === id)).toBeDefined();
    }
    await page.close();
  });

  test("700.3 countdown reply in group keeps reply_to", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const textResp = await apiPost(page, `/messaging/conversations/${groupId}/messages`, {
      text: `anchor ${TS}-700-3`,
    });
    const anchor = (await textResp.json()) as RawMsg;
    const resp = await sendCountdown(page, groupId, {
      title: `ReplyCD ${TS}-700-3`,
      target_datetime: nowSec() + 600,
      reply_to_message_id: anchor.message_id,
    });
    expect(resp.status()).toBe(201);
    const msg = (await resp.json()) as RawMsg;
    expect(msg.reply_to_message_id).toBe(anchor.message_id);
    await page.close();
  });

  test("700.4 non-participant cannot send countdown (403)", async ({ request }) => {
    // Use a REAL authenticated user who is not a member of the group. A bogus
    // e2e_nonmember@ raw sub 401s (unknown token); an authenticated non-member
    // triggers the 403/404 membership gate.
    const outsider = cppRegisterThrowaway("cd_700_4");
    const resp = await apiPostBearer(
      request,
      `/messaging/conversations/${groupId}/messages/countdown`,
      { title: `Intruder ${TS}-700-4`, target_datetime: nowSec() + 600 },
      outsider!.session.user_sub,
    );
    expect([403, 404]).toContain(resp.status());
    await request.dispose();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 701: Countdown CTA Buttons (UI)
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 701: Countdown CTA Buttons", () => {
  let convoId: string;

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await getOrCreateDm(page);
    await page.close();
  });

  async function renderExpired(page: Page, body: CountdownReq, title: string) {
    await injectAuth(page, ALICE_ID);
    await sendCountdown(page, convoId, body);
    await page.goto(`${BASE}/messages/${convoId}`, { waitUntil: "domcontentloaded" });
    await page.evaluate(() => window.dispatchEvent(new Event("online")));
    const card = page.locator('[data-testid="countdown-card"]').filter({ hasText: title });
    await expect(card).toBeVisible({ timeout: 15_000 });
    await expect(card.locator('[data-testid="countdown-expired"]')).toBeVisible({ timeout: 15_000 });
    return card;
  }

  test("701.1 broadcast countdown shows Watch Live when expired", async ({ page }) => {
    const title = `CTABroadcast ${TS}-701-1`;
    const card = await renderExpired(page, {
      title,
      target_datetime: nowSec() + 4,
      associated_event_type: "broadcast",
      associated_event_id: `bcast_${TS}_1`,
    }, title);
    await expect(card.getByText("Watch Live")).toBeVisible();
  });

  test("701.2 call countdown shows Join Call when expired", async ({ page }) => {
    const title = `CTACall ${TS}-701-2`;
    const card = await renderExpired(page, {
      title,
      target_datetime: nowSec() + 4,
      associated_event_type: "call",
      associated_event_id: `call_${TS}_2`,
    }, title);
    await expect(card.getByText("Join Call")).toBeVisible();
  });

  test("701.3 custom countdown shows Time's up! with no CTA", async ({ page }) => {
    const title = `CTACustom ${TS}-701-3`;
    const card = await renderExpired(page, {
      title,
      target_datetime: nowSec() + 4,
      associated_event_type: "custom",
    }, title);
    await expect(card).toContainText("Time's up!");
    await expect(card.locator('[data-testid="countdown-cta"]')).toHaveCount(0);
  });

  test("701.4 Watch Live links to /broadcasts/{id}", async ({ page }) => {
    const title = `CTAHref ${TS}-701-4`;
    const eventId = `bcast_${TS}_4`;
    const card = await renderExpired(page, {
      title,
      target_datetime: nowSec() + 4,
      associated_event_type: "broadcast",
      associated_event_id: eventId,
    }, title);
    const cta = card.locator('[data-testid="countdown-cta"]');
    await expect(cta).toHaveAttribute("href", `/broadcasts/${eventId}`);
  });
});
