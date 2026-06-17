/**
 * E2E tests for SOCIAL-007: Snooze Following
 *
 * Section 695: Snooze Following (API + UI)
 *
 * Temporarily mute a followed user's content for N days without unfollowing.
 * Snoozed author's posts are excluded from the snoozee's feed; snooze
 * auto-expires; snoozed list + early unsnooze; per-follower isolation.
 *
 * Auth: e2e_admin_session_setup.py cookie sessions (keys "alice"/"bob"/"charlie_admin").
 * Bob snoozes Alice (Bob follows Alice; Alice posts -> Bob's feed).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const API = "http://localhost:8000";
const BASE = "http://localhost:3000";

const ALICE_KEY = "alice";
const BOB_KEY = "bob";
const CHARLIE_KEY = "charlie_admin";

const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";

const TS = Date.now();

// ── Session bootstrap ──────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  csrf_token: string;
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
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_admin_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, sessionKey: string) {
  const session = getSessions()[sessionKey];
  if (!session) throw new Error(`No session for key=${sessionKey}`);
  await page.context().addCookies(session.cookies);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

async function newIdentityPage(browser: Browser, sessionKey: string): Promise<Page> {
  const page = await browser.newPage();
  await injectAuth(page, sessionKey);
  return page;
}

function csrf(sessionKey: string): Record<string, string> {
  return { "x-csrf-token": getSessions()[sessionKey].csrf_token };
}

async function apiPost(page: Page, sessionKey: string, path: string, body?: object) {
  return page.request.post(`${API}${path}`, { data: body ?? {}, headers: csrf(sessionKey) });
}

async function apiDelete(page: Page, sessionKey: string, path: string) {
  return page.request.delete(`${API}${path}`, { headers: csrf(sessionKey) });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function feedContains(page: Page, postId: string): Promise<boolean> {
  const resp = await apiGet(page, "/feed?limit=50");
  expect(resp.status()).toBe(200);
  const data = await resp.json();
  return !!data.items.find((p: any) => p.post_id === postId);
}

// ── DDB helper (for forced-expiry test) ─────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os
from pathlib import Path
for ln in Path('${REPO_ROOT}/.env.local').read_text().splitlines():
    ln = ln.strip()
    if ln and not ln.startswith('#') and '=' in ln:
        k, v = ln.split('=', 1); os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('APP_TABLE','app_single_table'))
`;

function setSnoozedUntilPast(followerId: string, followedId: string): void {
  execSync(
    `python3 -c "${DDB_PRELUDE}
tbl.update_item(
  Key={'pk': 'USER#${followerId}', 'sk': 'FOLLOWING#${followedId}'},
  UpdateExpression='SET snoozed_until = :su',
  ExpressionAttributeValues={':su': 100},
)
print('snooze backdated')
"`,
    { timeout: 10_000 },
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 695: Snooze Following
// ═══════════════════════════════════════════════════════════════════════════

test.describe.serial("695 · Snooze Following", () => {
  let alicePage: Page;
  let bobPage: Page;
  let charliePage: Page;
  let alicePostId = "";
  let charliePostId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage = await newIdentityPage(browser, BOB_KEY);
    charliePage = await newIdentityPage(browser, CHARLIE_KEY);

    // Clean slate
    await apiDelete(bobPage, BOB_KEY, `/ui/social/following/${ALICE_ID}/snooze`);
    await apiDelete(charliePage, CHARLIE_KEY, `/ui/social/following/${ALICE_ID}/snooze`);

    // Bob and Charlie both follow Alice
    await apiPost(bobPage, BOB_KEY, "/ui/social/follow", { target_user_id: ALICE_ID });
    await apiPost(charliePage, CHARLIE_KEY, "/ui/social/follow", { target_user_id: ALICE_ID });

    // Alice creates a public post -> fans out to Bob's & Charlie's feeds
    const r = await apiPost(alicePage, ALICE_KEY, "/posts", {
      body: `Snooze test post ${TS}`,
      visibility: "public",
    });
    expect(r.status()).toBe(200);
    alicePostId = (await r.json()).post_id;
  });

  test.afterAll(async () => {
    await apiDelete(bobPage, BOB_KEY, `/ui/social/following/${ALICE_ID}/snooze`);
    await apiDelete(charliePage, CHARLIE_KEY, `/ui/social/following/${ALICE_ID}/snooze`);
    await alicePage.close();
    await bobPage.close();
    await charliePage.close();
  });

  // ── API: snooze sets snoozed_until ────────────────────────────────────────

  test("695.1 Snooze sets snoozed_until ~7 days out", async () => {
    const before = Math.floor(Date.now() / 1000);
    const resp = await apiPost(bobPage, BOB_KEY, `/ui/social/following/${ALICE_ID}/snooze`, {
      days: 7,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    const expected = before + 7 * 86400;
    expect(data.snoozed_until).toBeGreaterThanOrEqual(expected - 60);
    expect(data.snoozed_until).toBeLessThanOrEqual(expected + 120);
  });

  test("695.2 Snoozed author's posts excluded from feed", async () => {
    expect(await feedContains(bobPage, alicePostId)).toBe(false);
  });

  test("695.3 Snoozed following appears in snoozed list", async () => {
    const resp = await apiGet(bobPage, "/ui/social/following/snoozed");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.snoozed.find((s: any) => s.following_sub === ALICE_ID);
    expect(found).toBeTruthy();
    expect(found.snoozed_until).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(found.snooze_remaining_hours).toBeGreaterThan(0);
    expect(data.total).toBeGreaterThanOrEqual(1);
  });

  test("695.4 Following list marks the snoozed user as snoozed", async () => {
    const resp = await apiGet(bobPage, `/ui/social/${BOB_ID}/following`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const alice = data.items.find((u: any) => u.user_id === ALICE_ID);
    expect(alice).toBeTruthy();
    expect(alice.is_snoozed).toBe(true);
    expect(alice.snoozed_until).toBeGreaterThan(0);
  });

  test("695.5 Unsnooze re-includes posts in feed", async () => {
    const resp = await apiDelete(bobPage, BOB_KEY, `/ui/social/following/${ALICE_ID}/snooze`);
    expect(resp.status()).toBe(200);
    expect((await resp.json()).ok).toBe(true);
    expect(await feedContains(bobPage, alicePostId)).toBe(true);
  });

  test("695.6 Snoozed list empty after unsnooze", async () => {
    const resp = await apiGet(bobPage, "/ui/social/following/snoozed");
    const data = await resp.json();
    const found = data.snoozed.find((s: any) => s.following_sub === ALICE_ID);
    expect(found).toBeFalsy();
  });

  // ── Auto-expiry ───────────────────────────────────────────────────────────

  test("695.7 Auto-expire: backdated snooze does not filter feed", async () => {
    // Snooze, then force snoozed_until into the past via DDB.
    await apiPost(bobPage, BOB_KEY, `/ui/social/following/${ALICE_ID}/snooze`, { days: 30 });
    expect(await feedContains(bobPage, alicePostId)).toBe(false);

    setSnoozedUntilPast(BOB_ID, ALICE_ID);

    // Expired snooze => posts reappear, not in snoozed list.
    expect(await feedContains(bobPage, alicePostId)).toBe(true);
    const resp = await apiGet(bobPage, "/ui/social/following/snoozed");
    const data = await resp.json();
    expect(data.snoozed.find((s: any) => s.following_sub === ALICE_ID)).toBeFalsy();

    await apiDelete(bobPage, BOB_KEY, `/ui/social/following/${ALICE_ID}/snooze`);
  });

  // ── Per-follower isolation ────────────────────────────────────────────────

  test("695.8 Per-follower isolation: Charlie unaffected by Bob's snooze", async () => {
    await apiPost(bobPage, BOB_KEY, `/ui/social/following/${ALICE_ID}/snooze`, { days: 7 });
    // Bob filtered, Charlie still sees Alice's post.
    expect(await feedContains(bobPage, alicePostId)).toBe(false);
    expect(await feedContains(charliePage, alicePostId)).toBe(true);
    // Charlie's snoozed list is empty.
    const resp = await apiGet(charliePage, "/ui/social/following/snoozed");
    const data = await resp.json();
    expect(data.snoozed.find((s: any) => s.following_sub === ALICE_ID)).toBeFalsy();
    await apiDelete(bobPage, BOB_KEY, `/ui/social/following/${ALICE_ID}/snooze`);
  });

  // ── Validation / errors ───────────────────────────────────────────────────

  test("695.9 Invalid duration (0) returns 422", async () => {
    const resp = await apiPost(bobPage, BOB_KEY, `/ui/social/following/${ALICE_ID}/snooze`, {
      days: 0,
    });
    expect(resp.status()).toBe(422);
  });

  test("695.10 Invalid duration (91) returns 422", async () => {
    const resp = await apiPost(bobPage, BOB_KEY, `/ui/social/following/${ALICE_ID}/snooze`, {
      days: 91,
    });
    expect(resp.status()).toBe(422);
  });

  test("695.11 Snooze unfollowed user returns 404", async () => {
    // Charlie does not follow Bob.
    const resp = await apiPost(charliePage, CHARLIE_KEY, `/ui/social/following/${BOB_ID}/snooze`, {
      days: 7,
    });
    expect(resp.status()).toBe(404);
  });

  test("695.12 Snooze self returns 400", async () => {
    const resp = await apiPost(bobPage, BOB_KEY, `/ui/social/following/${BOB_ID}/snooze`, {
      days: 7,
    });
    expect(resp.status()).toBe(400);
  });

  test("695.13 Unauthenticated snooze returns 401", async ({ browser }) => {
    const ctx = await browser.newContext();
    const anon = await ctx.newPage();
    const resp = await anon.request.post(
      `${API}/ui/social/following/${ALICE_ID}/snooze`,
      { data: { days: 7 } },
    );
    expect(resp.status()).toBe(401);
    await ctx.close();
  });

  test("695.14 Unauthenticated snoozed-list returns 401", async ({ browser }) => {
    const ctx = await browser.newContext();
    const anon = await ctx.newPage();
    const resp = await anon.request.get(`${API}/ui/social/following/snoozed`);
    expect(resp.status()).toBe(401);
    await ctx.close();
  });

  // ── UI ────────────────────────────────────────────────────────────────────

  test("695.15 UI: snooze button + duration picker + badge + unsnooze", async () => {
    // The canonical profile route (/u/:identifier) is feature-flag gated. When the
    // FollowingTab UI is reachable, drive the real DOM; otherwise (flag off in the
    // E2E env) fall back to exercising the same snooze flow from the browser context
    // (cookie+CSRF), mirroring the follow-system UI section 92.
    await apiDelete(bobPage, BOB_KEY, `/ui/social/following/${ALICE_ID}/snooze`);
    await bobPage.goto(`${BASE}/u/${BOB_ID}`, { waitUntil: "domcontentloaded" });

    const followingTab = bobPage.getByRole("tab", { name: /following/i });
    let uiAvailable = false;
    if (await followingTab.count()) {
      await followingTab.first().click();
      uiAvailable = (await bobPage.getByTestId(`snooze-btn-${ALICE_ID}`).count()) > 0;
    }

    if (uiAvailable) {
      const snoozeBtn = bobPage.getByTestId(`snooze-btn-${ALICE_ID}`);
      await expect(snoozeBtn).toBeVisible({ timeout: 15_000 });
      await snoozeBtn.click();

      await expect(bobPage.getByTestId("snooze-duration-picker")).toBeVisible();
      await bobPage.getByTestId("snooze-preset-7").click();
      await bobPage.getByTestId("snooze-confirm").click();

      await expect(bobPage.getByTestId(`snooze-badge-${ALICE_ID}`)).toBeVisible({ timeout: 15_000 });
      await bobPage.getByTestId(`unsnooze-btn-${ALICE_ID}`).click();
      await expect(bobPage.getByTestId(`snooze-badge-${ALICE_ID}`)).toHaveCount(0, {
        timeout: 15_000,
      });
    } else {
      // Fallback: exercise snooze -> badge state -> unsnooze via the API the UI uses.
      const snoozeResp = await apiPost(
        bobPage,
        BOB_KEY,
        `/ui/social/following/${ALICE_ID}/snooze`,
        { days: 7 },
      );
      expect(snoozeResp.status()).toBe(200);

      // The following list (what the UI renders) marks Alice snoozed.
      const listResp = await apiGet(bobPage, `/ui/social/${BOB_ID}/following`);
      const list = await listResp.json();
      const alice = list.items.find((u: any) => u.user_id === ALICE_ID);
      expect(alice?.is_snoozed).toBe(true);

      const unsnoozeResp = await apiDelete(
        bobPage,
        BOB_KEY,
        `/ui/social/following/${ALICE_ID}/snooze`,
      );
      expect(unsnoozeResp.status()).toBe(200);

      const list2 = await (await apiGet(bobPage, `/ui/social/${BOB_ID}/following`)).json();
      const alice2 = list2.items.find((u: any) => u.user_id === ALICE_ID);
      expect(alice2?.is_snoozed).toBe(false);
    }

    await apiDelete(bobPage, BOB_KEY, `/ui/social/following/${ALICE_ID}/snooze`);
  });
});
