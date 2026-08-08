/**
 * E2E tests for MSG-011: Emoji Reactions Enhancement.
 *
 * Builds on the existing reaction backend (reactions stored as a DDB String Set
 * per emoji key; POST /reactions add/remove). MSG-011 adds:
 *   - per-message 20-unique-emoji reaction limit (server-enforced 400)
 *   - GET /reactions/details (who reacted with what: display_name + avatar)
 *   - custom-emoji reactions via the "custom:shortcode" key (MSG-007)
 *   - double-tap quick-react (❤️) with pop animation
 *   - reaction-detail popover UI
 *
 * Sections:
 *   733 — Reaction limit & details API
 *   734 — Quick-react (double-tap) + animation UI
 *   735 — Reaction-detail popover UI
 *   736 — Custom-emoji reactions
 *
 * Auth: cookie-based session injection (injectAuth). Test users Alice + Bob.
 * Reactions by a second user go through that user's own session (CSRF header).
 */

import { test, expect, type Page, type APIRequestContext } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

const TS = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

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

// Retry on 429: under a shared-backend shard run the accumulated request volume
// from other specs can trip the global IP rate-limit window. Honor Retry-After
// (capped) so a transient 429 doesn't silently drop a reaction/message POST
// (which would leave the UI never rendering the expected badge).
async function retry429(fn: () => Promise<any>) {
  let resp = await fn();
  for (let attempt = 0; attempt < 4 && resp.status() === 429; attempt++) {
    const ra = Number(resp.headers()["retry-after"] || "1");
    await new Promise((r) => setTimeout(r, Math.min(Math.max(ra, 1), 3) * 1000));
    resp = await fn();
  }
  return resp;
}

// API helpers bound to a specific identity (carries that user's cookies + CSRF).
async function reactAs(
  rc: APIRequestContext,
  identity: string,
  convoId: string,
  msgId: string,
  emoji: string,
  action: "add" | "remove" = "add",
) {
  const s = getSessions()[identity];
  return retry429(() =>
    rc.post(
      `${API}/messaging/conversations/${convoId}/messages/${msgId}/reactions`,
      {
        data: { emoji, action },
        headers: {
          "x-csrf-token": s.csrf_token,
          Cookie: s.cookies.map((c) => `${c.name}=${c.value}`).join("; "),
        },
      },
    ),
  );
}

async function detailsAs(
  rc: APIRequestContext,
  identity: string,
  convoId: string,
  msgId: string,
) {
  const s = getSessions()[identity];
  return rc.get(
    `${API}/messaging/conversations/${convoId}/messages/${msgId}/reactions/details`,
    {
      headers: { Cookie: s.cookies.map((c) => `${c.name}=${c.value}`).join("; ") },
    },
  );
}

async function apiPostAlice(page: Page, path: string, body: object) {
  const s = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

// ─── DM helpers ───────────────────────────────────────────────────────────────

let _dmConvoId: string | null = null;
async function getOrCreateDm(page: Page): Promise<string> {
  if (_dmConvoId) return _dmConvoId;
  const bobSub = getSessions()[BOB_ID].user_sub;
  const resp = await apiPostAlice(page, "/messaging/conversations", {
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

// Send a message as Alice; return its message_id.
async function sendMessage(page: Page, convoId: string, text: string): Promise<string> {
  const s = getSessions()[ALICE_ID];
  const resp = await retry429(() =>
    page.request.post(`${API}/messaging/conversations/${convoId}/messages`, {
      data: { text },
      headers: { "x-csrf-token": s.csrf_token },
    }),
  );
  if (!resp.ok()) throw new Error(`send failed: ${resp.status()}`);
  const body = await resp.json();
  return body.message_id as string;
}

async function openDmWithBob(page: Page) {
  await injectAuth(page, ALICE_ID);
  const convoId = await getOrCreateDm(page);
  const session = getSessions()[ALICE_ID];
  await page.request
    .post(`${API}/messaging/conversations/${convoId}/messages`, {
      data: { text: `__touch__${Date.now()}` },
      headers: { "x-csrf-token": session.csrf_token },
    })
    .catch(() => {});
  // Deep-link straight to the conversation by id instead of hunting the sidebar.
  // Under a shard run the conversations list accumulates thousands of DMs and is
  // paginated, so the "E2E Bob" sidebar row is frequently NOT rendered/visible —
  // making the row-click flow flake (the beforeAll then throws and every test in
  // the describe reports 0ms). The `/messages/:conversationId` route mounts the
  // ConversationView directly via the URL param, with no sidebar dependency.
  await page.goto(`${BASE}/messages/${convoId}`, { waitUntil: "load" });
  await expect(
    page.getByPlaceholder("Type a message...").or(page.getByPlaceholder("Type an encrypted message...")),
  ).toBeVisible({ timeout: 12000 });
}

// ─── 733. Reaction limit & details API ────────────────────────────────────────

test.describe("733. Reaction limit & details API", () => {
  let page: Page;
  let convoId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await getOrCreateDm(page);
  });

  test.afterAll(async () => page?.close());

  test("733.1 Alice adds a standard reaction", async ({ request }) => {
    const msgId = await sendMessage(page, convoId, `react-std-${TS}`);
    const resp = await reactAs(request, ALICE_ID, convoId, msgId, "🎉");
    expect(resp.status()).toBe(200);
    expect((await resp.json()).ok).toBe(true);
  });

  test("733.2 Reaction details returns user info", async ({ request }) => {
    const msgId = await sendMessage(page, convoId, `react-det-${TS}`);
    await reactAs(request, ALICE_ID, convoId, msgId, "🔥");
    const resp = await detailsAs(request, ALICE_ID, convoId, msgId);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.reactions["🔥"]).toBeTruthy();
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    const entry = body.reactions["🔥"].find((u: { user_sub: string }) => u.user_sub === aliceSub);
    expect(entry).toBeTruthy();
    expect(typeof entry.display_name).toBe("string");
    expect(entry.display_name.length).toBeGreaterThan(0);
  });

  test("733.3 Twenty unique reactions are allowed", async ({ request }) => {
    const msgId = await sendMessage(page, convoId, `react-20-${TS}`);
    for (let i = 0; i < 20; i++) {
      const resp = await reactAs(request, ALICE_ID, convoId, msgId, `r20_${i}_${TS}`);
      expect(resp.status(), `emoji #${i + 1}`).toBe(200);
    }
  });

  test("733.4 Twenty-first unique reaction is rejected (400)", async ({ request }) => {
    const msgId = await sendMessage(page, convoId, `react-21-${TS}`);
    for (let i = 0; i < 20; i++) {
      const ok = await reactAs(request, ALICE_ID, convoId, msgId, `r21_${i}_${TS}`);
      expect(ok.status()).toBe(200);
    }
    const over = await reactAs(request, ALICE_ID, convoId, msgId, `r21_over_${TS}`);
    expect(over.status()).toBe(400);
    const body = await over.json();
    expect(body.detail).toContain("Maximum 20 unique reactions");
  });

  test("733.5 Second user reacting with an existing emoji is not a new unique (count=2)", async ({ request }) => {
    const msgId = await sendMessage(page, convoId, `react-2u-${TS}`);
    const r1 = await reactAs(request, ALICE_ID, convoId, msgId, "👍");
    expect(r1.status()).toBe(200);
    const r2 = await reactAs(request, BOB_ID, convoId, msgId, "👍");
    expect(r2.status()).toBe(200);

    const resp = await detailsAs(request, ALICE_ID, convoId, msgId);
    const body = await resp.json();
    expect(body.reactions["👍"]).toHaveLength(2);
    const subs = body.reactions["👍"].map((u: { user_sub: string }) => u.user_sub);
    expect(subs).toContain(getSessions()[ALICE_ID].user_sub);
    expect(subs).toContain(getSessions()[BOB_ID].user_sub);
  });

  test("733.6 Reaction details requires auth (401 without session)", async ({ request }) => {
    const msgId = await sendMessage(page, convoId, `react-401-${TS}`);
    const resp = await request.get(
      `${API}/messaging/conversations/${convoId}/messages/${msgId}/reactions/details`,
    );
    // cpp's CurrentUser dependency returns 403 for a missing session where the
    // Python backend returns 401; accept either for the unauth case.
    expect([401, 403]).toContain(resp.status());
  });
});

// ─── 734. Quick-react (double-tap) + animation UI ─────────────────────────────

test.describe("734. Quick-react double-tap & animation", () => {
  let page: Page;
  let convoId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await openDmWithBob(page);
    convoId = _dmConvoId!;
  });

  test.afterAll(async () => page?.close());

  test("734.1 Double-click adds a heart reaction with the pop animation class", async () => {
    const text = `dbltap-${TS}`;
    await sendMessage(page, convoId, text);
    await page.evaluate(() => window.dispatchEvent(new Event("online")));
    const bubble = page.getByTestId("message-bubble").filter({ hasText: text }).last();
    await expect(bubble).toBeVisible({ timeout: 8000 });

    const badge = bubble.getByTestId("reaction-badge-❤️");
    // The `reaction-badge-enter` pop class is applied for only ~320ms AFTER the
    // reaction's network refetch lands. Under a shared-backend shard run that
    // round-trip is slow, so the original one-shot dblclick + fixed-timeout
    // `toHaveClass` assertion raced the 320ms window — by the time Playwright
    // sampled the class it had already been removed. Instead, install a
    // browser-side MutationObserver on the bubble BEFORE the dblclick that
    // latches whether the class ever appeared, then trigger the dblclick.
    // This deterministically catches the transient regardless of refetch
    // latency (no polling-cadence race).
    await bubble.evaluate((el: Element) => {
      const w = window as unknown as { __popSeen?: boolean; __popObs?: MutationObserver };
      w.__popSeen = false;
      const check = () => {
        if (el.querySelector(".reaction-badge-enter")) w.__popSeen = true;
      };
      const obs = new MutationObserver(check);
      // childList+subtree: the badge node is *inserted* with the
      // `reaction-badge-enter` class already on it (then the class is removed
      // ~320ms later), so we must observe node insertion, not just attr changes.
      obs.observe(el, { attributes: true, childList: true, subtree: true, attributeFilter: ["class"] });
      w.__popObs = obs;
      check();
    });

    await bubble.dblclick();
    // Heart badge appears (durable outcome of the add).
    await expect(badge).toBeVisible({ timeout: 8000 });
    // The pop animation class fired at some point during/after the add.
    await expect
      .poll(
        () =>
          page.evaluate(
            () => (window as unknown as { __popSeen?: boolean }).__popSeen === true,
          ),
        { timeout: 6000, intervals: [50, 100, 150, 200] },
      )
      .toBe(true);
    await page.evaluate(() => {
      const w = window as unknown as { __popObs?: MutationObserver };
      w.__popObs?.disconnect();
    });
  });

  test("734.2 Double-click again removes the heart reaction", async () => {
    const text = `dbltap-rm-${TS}`;
    await sendMessage(page, convoId, text);
    await page.evaluate(() => window.dispatchEvent(new Event("online")));
    const bubble = page.getByTestId("message-bubble").filter({ hasText: text }).last();
    await expect(bubble).toBeVisible({ timeout: 8000 });

    await bubble.dblclick();
    await expect(bubble.getByTestId("reaction-badge-❤️")).toBeVisible({ timeout: 6000 });
    // Second double-tap toggles it off.
    await bubble.dblclick();
    await page.evaluate(() => window.dispatchEvent(new Event("online")));
    await expect(bubble.getByTestId("reaction-badge-❤️")).toHaveCount(0, { timeout: 6000 });
  });
});

// ─── 735. Reaction-detail popover UI ──────────────────────────────────────────

test.describe("735. Reaction-detail popover UI", () => {
  let page: Page;
  let convoId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await openDmWithBob(page);
    convoId = _dmConvoId!;
  });

  test.afterAll(async () => page?.close());

  test("735.1 Clicking the details trigger opens the popover listing reactors", async ({ request }) => {
    const text = `popover-${TS}`;
    const msgId = await sendMessage(page, convoId, text);
    // Confirm the reaction landed (not dropped by a shard-load 429) — otherwise
    // the badge would never render and the trigger below would never appear.
    const reactResp = await reactAs(request, ALICE_ID, convoId, msgId, "🚀");
    expect(reactResp.status()).toBe(200);
    await page.evaluate(() => window.dispatchEvent(new Event("online")));

    const bubble = page.getByTestId("message-bubble").filter({ hasText: text }).last();
    await expect(bubble).toBeVisible({ timeout: 8000 });
    // The 🚀 reaction was added via API; under shard load the first `online`
    // refetch may land before the reaction is committed/visible. Re-dispatch
    // `online` until the badge appears (the refetch is idempotent).
    const badge = bubble.getByTestId("reaction-badge-🚀");
    await expect
      .poll(
        async () => {
          await page.evaluate(() => window.dispatchEvent(new Event("online")));
          return badge.count();
        },
        { timeout: 12_000, intervals: [400, 600, 800, 1000] },
      )
      .toBeGreaterThan(0);
    await expect(badge).toBeVisible({ timeout: 6000 });

    await bubble.getByTestId("reaction-details-trigger").click();
    const popover = page.getByTestId("reaction-detail-popover");
    await expect(popover).toBeVisible({ timeout: 5000 });
    // Emoji tab present.
    await expect(popover.getByTestId("reaction-tab-🚀")).toBeVisible();
    // At least one reactor row rendered.
    await expect(popover.getByTestId("reaction-user-row").first()).toBeVisible({ timeout: 5000 });
  });

  test("735.2 Closing the popover hides it", async ({ request }) => {
    const text = `popover-close-${TS}`;
    const msgId = await sendMessage(page, convoId, text);
    await reactAs(request, ALICE_ID, convoId, msgId, "😎");
    await page.evaluate(() => window.dispatchEvent(new Event("online")));

    const bubble = page.getByTestId("message-bubble").filter({ hasText: text }).last();
    await expect(bubble).toBeVisible({ timeout: 8000 });
    await expect(bubble.getByTestId("reaction-badge-😎")).toBeVisible({ timeout: 6000 });

    const trigger = bubble.getByTestId("reaction-details-trigger");
    await trigger.scrollIntoViewIfNeeded();
    await trigger.click();
    await expect(page.getByTestId("reaction-detail-popover")).toBeVisible({ timeout: 5000 });
    // Press Escape to dismiss the popover.
    await page.keyboard.press("Escape");
    await expect(page.getByTestId("reaction-detail-popover")).toBeHidden({ timeout: 5000 });
  });
});

// ─── 736. Custom-emoji reactions ──────────────────────────────────────────────

test.describe("736. Custom-emoji reactions", () => {
  let page: Page;
  let convoId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await getOrCreateDm(page);
  });

  test.afterAll(async () => page?.close());

  test("736.1 React with a custom emoji key (custom:shortcode); 200", async ({ request }) => {
    const msgId = await sendMessage(page, convoId, `custom-react-${TS}`);
    const key = `custom:e2e_party_${TS}`;
    const resp = await reactAs(request, ALICE_ID, convoId, msgId, key);
    expect(resp.status()).toBe(200);
  });

  test("736.2 Custom-emoji reaction appears in the message reactions_counts", async ({ request }) => {
    const msgId = await sendMessage(page, convoId, `custom-count-${TS}`);
    const key = `custom:e2e_cat_${TS}`;
    await reactAs(request, ALICE_ID, convoId, msgId, key);

    const s = getSessions()[ALICE_ID];
    const resp = await request.get(
      `${API}/messaging/conversations/${convoId}/messages`,
      { headers: { Cookie: s.cookies.map((c) => `${c.name}=${c.value}`).join("; ") } },
    );
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as Array<{ message_id: string; reactions_counts?: Record<string, number> }>;
    const msg = data.find((m) => m.message_id === msgId);
    expect(msg).toBeTruthy();
    expect(msg!.reactions_counts?.[key]).toBe(1);
  });

  test("736.3 Reaction details includes the custom emoji key", async ({ request }) => {
    const msgId = await sendMessage(page, convoId, `custom-det-${TS}`);
    const key = `custom:e2e_fox_${TS}`;
    await reactAs(request, ALICE_ID, convoId, msgId, key);

    const resp = await detailsAs(request, ALICE_ID, convoId, msgId);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.reactions[key]).toBeTruthy();
    expect(body.reactions[key]).toHaveLength(1);
    expect(body.reactions[key][0].user_sub).toBe(getSessions()[ALICE_ID].user_sub);
  });
});
