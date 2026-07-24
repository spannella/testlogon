import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

/* ------------------------------------------------------------------ */
/*  ADS-006 — Broadcast Ad Breaks                                      */
/*  Sections 364-368: ad config, pre-roll, mid-roll, SSE, UI          */
/* ------------------------------------------------------------------ */

const TS = Date.now();
const PYTHON = REPO_ROOT + "/.venv/bin/python3";

const ROOT_ID = "root";
const BOB_ID = "bob";

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

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  // Seed the persisted Zustand auth store so the React app treats the page as
  // authenticated. Without this, LivePlayer (which reads `isAuthenticated` from
  // authStore, defaulting to false) renders the "Sign in required" screen and
  // never mounts the player or fires the ad-join request — so the ad overlay
  // never appears. addInitScript runs before every navigation, including the
  // /live/{sid} goto, so the store is populated on first render.
  await page.context().addInitScript((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

async function apiPost(page: Page, identity: string, path: string, body?: object) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiPatch(page: Page, identity: string, path: string, body: object) {
  const s = getSessions()[identity];
  return page.request.patch(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

/** Seed/clear a subscription row so a viewer is (or isn't) an active subscriber. */
function seedSubscription(subscriberSub: string, creatorSub: string, status: string): void {
  execSync(
    `${PYTHON} -c "
import boto3, os, time
from pathlib import Path
env = Path('${REPO_ROOT}/.env.local')
if env.exists():
    for line in env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k, v)
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'), region_name=os.environ.get('AWS_REGION', 'us-east-1'))
tbl = ddb.Table(os.environ.get('SUBSCRIPTIONS_TABLE_NAME', 'subscriptions'))
tbl.put_item(Item={
    'pk': 'SUBSCRIBER#${subscriberSub}',
    'sk': 'SUB#${creatorSub}',
    'creator_id': '${creatorSub}',
    'status': '${status}',
    'updated_at': int(time.time()),
})
print('ok')
"`,
    { timeout: 30_000 },
  );
}

function clearSubscription(subscriberSub: string, creatorSub: string): void {
  execSync(
    `${PYTHON} -c "
import boto3, os
from pathlib import Path
env = Path('${REPO_ROOT}/.env.local')
if env.exists():
    for line in env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k, v)
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'), region_name=os.environ.get('AWS_REGION', 'us-east-1'))
tbl = ddb.Table(os.environ.get('SUBSCRIPTIONS_TABLE_NAME', 'subscriptions'))
tbl.delete_item(Key={'pk': 'SUBSCRIBER#${subscriberSub}', 'sk': 'SUB#${creatorSub}'})
print('ok')
"`,
    { timeout: 30_000 },
  );
}

async function createSession(page: Page, body: object): Promise<string> {
  const profResp = await apiPost(page, ROOT_ID, "/broadcast/profiles", {
    name: `Ads Profile ${TS}_${Math.random().toString(36).slice(2, 8)}`,
    region: "us-east-1",
    rendition_preset: "720p30",
  });
  expect(profResp.status()).toBe(201);
  const profileId = (await profResp.json()).id;
  const sessResp = await apiPost(page, ROOT_ID, "/broadcast/sessions", {
    profile_id: profileId,
    ...body,
  });
  expect(sessResp.status()).toBe(201);
  return (await sessResp.json()).id;
}

async function startSession(page: Page, sessionId: string) {
  const r = await apiPost(page, ROOT_ID, `/broadcast/sessions/${sessionId}/start`, {
    reason: "e2e-ads",
  });
  expect(r.status()).toBe(202);
}

/* ================================================================== */
/*  Section 364 — Session Ad Config API                                */
/* ================================================================== */

test.describe("Section 364: Broadcast Session Ad Config", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    rootPage = await ctx.newPage();
    await injectAuth(rootPage, ROOT_ID);
  });

  test.afterAll(async () => {
    await rootPage.context().close();
  });

  test("364.1 Create session with ad config", async () => {
    const sid = await createSession(rootPage, {
      pre_roll_enabled: true,
      mid_roll_ad_break_duration_seconds: 30,
      mid_roll_skip_after_seconds: 15,
    });
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sid}/ad-config`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.pre_roll_enabled).toBe(true);
    expect(body.mid_roll_ad_break_duration_seconds).toBe(30);
    expect(body.total_ad_breaks).toBe(0);
    expect(body.ad_break_active).toBe(false);
  });

  test("364.2 Update session ad config", async () => {
    const sid = await createSession(rootPage, {});
    const resp = await apiPatch(rootPage, ROOT_ID, `/broadcast/sessions/${sid}/ad-config`, {
      mid_roll_ad_break_duration_seconds: 15,
    });
    expect(resp.status()).toBe(200);
    const getResp = await apiGet(rootPage, `/broadcast/sessions/${sid}/ad-config`);
    expect((await getResp.json()).mid_roll_ad_break_duration_seconds).toBe(15);
  });

  test("364.3 Default ad config values", async () => {
    const sid = await createSession(rootPage, {});
    const body = await (await apiGet(rootPage, `/broadcast/sessions/${sid}/ad-config`)).json();
    expect(body.pre_roll_enabled).toBe(true);
    expect(body.mid_roll_ad_break_duration_seconds).toBe(30);
    expect(body.mid_roll_skip_after_seconds).toBe(15);
  });

  test("364.4 Invalid mid_roll duration rejected (ge=15)", async () => {
    const sid = await createSession(rootPage, {});
    const resp = await apiPatch(rootPage, ROOT_ID, `/broadcast/sessions/${sid}/ad-config`, {
      mid_roll_ad_break_duration_seconds: 10,
    });
    expect(resp.status()).toBe(422);
  });

  test("364.5 Non-enumerated mid_roll duration rejected (45)", async () => {
    const sid = await createSession(rootPage, {});
    const resp = await apiPatch(rootPage, ROOT_ID, `/broadcast/sessions/${sid}/ad-config`, {
      mid_roll_ad_break_duration_seconds: 45,
    });
    expect(resp.status()).toBe(422);
  });
});

/* ================================================================== */
/*  Section 365 — Pre-Roll Ad API                                      */
/* ================================================================== */

test.describe("Section 365: Pre-Roll Ad API", () => {
  let rootPage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await (await browser.newContext()).newPage();
    await injectAuth(rootPage, ROOT_ID);
    bobPage = await (await browser.newContext()).newPage();
    await injectAuth(bobPage, BOB_ID);
    // ensure bob is not a subscriber of root
    clearSubscription(getSessions()[BOB_ID].user_sub, getSessions()[ROOT_ID].user_sub);
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await bobPage.context().close();
  });

  test("365.1 Viewer join includes pre-roll", async () => {
    const sid = await createSession(rootPage, { pre_roll_enabled: true });
    await startSession(rootPage, sid);
    const resp = await apiPost(bobPage, BOB_ID, `/broadcast/sessions/${sid}/ad-join`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ad_free).toBe(false);
    expect(body.pre_roll).not.toBeNull();
    expect(body.pre_roll.creative_id).toBeTruthy();
  });

  test("365.2 Pre-roll has tracking URLs and 5s skip", async () => {
    const sid = await createSession(rootPage, { pre_roll_enabled: true });
    await startSession(rootPage, sid);
    const body = await (await apiPost(bobPage, BOB_ID, `/broadcast/sessions/${sid}/ad-join`)).json();
    expect(body.pre_roll.impression_url).toBeTruthy();
    expect(body.pre_roll.click_url).toBeTruthy();
    expect(body.pre_roll.skip_url).toBeTruthy();
    expect(body.pre_roll.skip_after_seconds).toBe(5);
  });

  test("365.3 Pre-roll disabled returns null", async () => {
    const sid = await createSession(rootPage, { pre_roll_enabled: false });
    await startSession(rootPage, sid);
    const body = await (await apiPost(bobPage, BOB_ID, `/broadcast/sessions/${sid}/ad-join`)).json();
    expect(body.pre_roll).toBeNull();
    expect(body.ad_free).toBe(true);
  });

  test("365.4 Broadcaster is ad-free on own session", async () => {
    const sid = await createSession(rootPage, { pre_roll_enabled: true });
    await startSession(rootPage, sid);
    const body = await (await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sid}/ad-join`)).json();
    expect(body.ad_free).toBe(true);
    expect(body.pre_roll).toBeNull();
  });
});

/* ================================================================== */
/*  Section 366 — Mid-Roll Ad Break API                                */
/* ================================================================== */

test.describe("Section 366: Mid-Roll Ad Break API", () => {
  let rootPage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await (await browser.newContext()).newPage();
    await injectAuth(rootPage, ROOT_ID);
    bobPage = await (await browser.newContext()).newPage();
    await injectAuth(bobPage, BOB_ID);
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await bobPage.context().close();
  });

  test("366.1 Trigger ad break", async () => {
    const sid = await createSession(rootPage, { mid_roll_ad_break_duration_seconds: 30 });
    await startSession(rootPage, sid);
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sid}/ad-break`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.duration_seconds).toBe(30);
    expect(body.started_at).toBeGreaterThan(0);
    // cleanup
    await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sid}/ad-break/end`);
  });

  test("366.2 Cannot trigger during active break", async () => {
    const sid = await createSession(rootPage, { mid_roll_ad_break_duration_seconds: 60 });
    await startSession(rootPage, sid);
    const first = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sid}/ad-break`);
    expect(first.status()).toBe(200);
    const second = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sid}/ad-break`);
    expect(second.status()).toBe(400);
    await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sid}/ad-break/end`);
  });

  test("366.3 End ad break early", async () => {
    const sid = await createSession(rootPage, { mid_roll_ad_break_duration_seconds: 60 });
    await startSession(rootPage, sid);
    await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sid}/ad-break`);
    const endResp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sid}/ad-break/end`);
    expect(endResp.status()).toBe(200);
    const cfg = await (await apiGet(rootPage, `/broadcast/sessions/${sid}/ad-config`)).json();
    expect(cfg.ad_break_active).toBe(false);
  });

  test("366.4 Non-broadcaster cannot trigger", async () => {
    const sid = await createSession(rootPage, {});
    await startSession(rootPage, sid);
    const resp = await apiPost(bobPage, BOB_ID, `/broadcast/sessions/${sid}/ad-break`);
    expect(resp.status()).toBe(403);
  });

  test("366.5 Cannot trigger on non-live session", async () => {
    const sid = await createSession(rootPage, {});
    // not started -> draft
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sid}/ad-break`);
    expect(resp.status()).toBe(400);
  });

  test("366.6 total_ad_breaks increments (and enforces the min-interval cooldown)", async () => {
    const sid = await createSession(rootPage, { mid_roll_ad_break_duration_seconds: 15 });
    await startSession(rootPage, sid);
    // First break increments the counter.
    const b1 = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sid}/ad-break`);
    expect(b1.status()).toBe(200);
    await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sid}/ad-break/end`);
    // A second break immediately after is rejected by the min-interval cooldown
    // (AD_BREAK_TOO_SOON) rather than incrementing again.
    const b2 = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sid}/ad-break`);
    expect(b2.status()).toBe(429);
    const b2body = await b2.json();
    expect(b2body.detail.code).toBe("AD_BREAK_TOO_SOON");
    const cfg = await (await apiGet(rootPage, `/broadcast/sessions/${sid}/ad-config`)).json();
    expect(cfg.total_ad_breaks).toBe(1);
  });
});

/* ================================================================== */
/*  Section 367 — SSE Ad Break Events                                  */
/* ================================================================== */

test.describe("Section 367: SSE Ad Break Events", () => {
  let rootPage: Page;
  let bobPage: Page;
  let sid: string;

  test.beforeAll(async ({ browser }) => {
    rootPage = await (await browser.newContext()).newPage();
    await injectAuth(rootPage, ROOT_ID);
    bobPage = await (await browser.newContext()).newPage();
    await injectAuth(bobPage, BOB_ID);
    // EventSource needs same-origin (Vite proxy) — navigate bob to the app.
    await bobPage.goto("http://localhost:3000/login");
    await bobPage.waitForLoadState("domcontentloaded");

    sid = await createSession(rootPage, { mid_roll_ad_break_duration_seconds: 15 });
    await startSession(rootPage, sid);
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await bobPage.context().close();
  });

  test("367.1 SSE ad_break:start + end received with payload", async () => {
    await bobPage.evaluate((s) => {
      (window as any).__adEvents = [];
      (window as any).__sseReady = false;
      const es = new EventSource(`/broadcast/sessions/${s}/stream`);
      es.addEventListener("hello", () => {
        (window as any).__sseReady = true;
      });
      es.addEventListener("ad_break:start", (e: any) => {
        (window as any).__adEvents.push({ type: "start", ...JSON.parse(e.data) });
      });
      es.addEventListener("ad_break:end", (e: any) => {
        (window as any).__adEvents.push({ type: "end", ...JSON.parse(e.data) });
      });
      (window as any).__sseClose = () => es.close();
    }, sid);

    await expect
      .poll(async () => bobPage.evaluate(() => (window as any).__sseReady), { timeout: 10_000 })
      .toBe(true);

    // Trigger the ad break (auto-ends after 15s).
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sid}/ad-break`);
    expect(resp.status()).toBe(200);

    // Start event arrives.
    await expect
      .poll(
        async () =>
          bobPage.evaluate(() =>
            ((window as any).__adEvents as any[]).some((e) => e.type === "start"),
          ),
        { timeout: 10_000 },
      )
      .toBe(true);

    const startEvt = await bobPage.evaluate(
      () => ((window as any).__adEvents as any[]).find((e) => e.type === "start"),
    );
    expect(startEvt.duration_seconds).toBe(15);
    expect(startEvt.skip_after_seconds).toBeGreaterThan(0);
    expect(startEvt.started_at).toBeGreaterThan(0);

    // End event (manual end to keep the test fast).
    await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sid}/ad-break/end`);
    await expect
      .poll(
        async () =>
          bobPage.evaluate(() =>
            ((window as any).__adEvents as any[]).some((e) => e.type === "end"),
          ),
        { timeout: 10_000 },
      )
      .toBe(true);

    await bobPage.evaluate(() => (window as any).__sseClose());
  });
});

/* ================================================================== */
/*  Section 368 — Subscriber Ad-Free                                   */
/* ================================================================== */

test.describe("Section 368: Subscriber Ad-Free", () => {
  let rootPage: Page;
  let bobPage: Page;
  let bobSub: string;
  let rootSub: string;

  test.beforeAll(async ({ browser }) => {
    rootPage = await (await browser.newContext()).newPage();
    await injectAuth(rootPage, ROOT_ID);
    bobPage = await (await browser.newContext()).newPage();
    await injectAuth(bobPage, BOB_ID);
    bobSub = getSessions()[BOB_ID].user_sub;
    rootSub = getSessions()[ROOT_ID].user_sub;
  });

  test.afterAll(async () => {
    clearSubscription(bobSub, rootSub);
    await rootPage.context().close();
    await bobPage.context().close();
  });

  test("368.1 Active subscriber joins ad-free", async () => {
    seedSubscription(bobSub, rootSub, "active");
    const sid = await createSession(rootPage, { pre_roll_enabled: true });
    await startSession(rootPage, sid);
    const body = await (await apiPost(bobPage, BOB_ID, `/broadcast/sessions/${sid}/ad-join`)).json();
    expect(body.ad_free).toBe(true);
    expect(body.pre_roll).toBeNull();
  });

  test("368.2 Cancelled subscription sees pre-roll", async () => {
    seedSubscription(bobSub, rootSub, "canceled");
    const sid = await createSession(rootPage, { pre_roll_enabled: true });
    await startSession(rootPage, sid);
    const body = await (await apiPost(bobPage, BOB_ID, `/broadcast/sessions/${sid}/ad-join`)).json();
    expect(body.ad_free).toBe(false);
    expect(body.pre_roll).not.toBeNull();
    clearSubscription(bobSub, rootSub);
  });
});

/* ================================================================== */
/*  Section 369 — Ad Overlay UI                                        */
/* ================================================================== */

test.describe("Section 369: Ad Overlay UI", () => {
  let rootPage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await (await browser.newContext()).newPage();
    await injectAuth(rootPage, ROOT_ID);
    bobPage = await (await browser.newContext()).newPage();
    await injectAuth(bobPage, BOB_ID);
    clearSubscription(getSessions()[BOB_ID].user_sub, getSessions()[ROOT_ID].user_sub);
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await bobPage.context().close();
  });

  test("369.1 Pre-roll overlay appears on viewer page", async () => {
    const sid = await createSession(rootPage, { pre_roll_enabled: true });
    await startSession(rootPage, sid);
    await bobPage.goto(`http://localhost:3000/live/${sid}`);
    await expect(bobPage.locator('[data-testid="broadcast-ad-overlay"]')).toBeVisible({
      timeout: 15_000,
    });
  });

  test("369.2 Skip countdown then skip button appears", async () => {
    const sid = await createSession(rootPage, { pre_roll_enabled: true });
    await startSession(rootPage, sid);
    await bobPage.goto(`http://localhost:3000/live/${sid}`);
    await expect(bobPage.locator('[data-testid="broadcast-ad-overlay"]')).toBeVisible({
      timeout: 15_000,
    });
    // Skip button appears after 5s.
    await expect(bobPage.locator('[data-testid="ad-skip-button"]')).toBeVisible({
      timeout: 12_000,
    });
  });
});

/* ================================================================== */
/*  Section 369A — Ad-Join Decoupled From Session Fetch (GAP-0073)      */
/*                                                                      */
/*  Regression for GAP-0073: adJoinMutation (and playbackMutation)     */
/*  must fire on [sessionId, isAuthenticated], NOT on [session] state.  */
/*  Previously, a failed GET /broadcast/sessions/{id} left `session`    */
/*  null, so the ad-join effect never ran and the pre-roll never        */
/*  mounted — advertiser pays for a slot that delivers zero            */
/*  impressions.                                                        */
/* ================================================================== */

test.describe("Section 369A: Ad-Join Decoupled From Session Fetch (GAP-0073)", () => {
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    bobPage = await (await browser.newContext()).newPage();
    await injectAuth(bobPage, BOB_ID);
  });

  test.afterAll(async () => {
    await bobPage.context().close();
  });

  test("369A.1 ad-join fires even when session fetch returns 404", async () => {
    const badSid = `gap0073-missing-${TS}`;
    // Force the session-fetch GET to fail with 404. The ad-join POST must
    // still fire because it depends on sessionId, not on session state.
    await bobPage.route(
      (url) =>
        url.pathname.endsWith(`/broadcast/sessions/${badSid}`) &&
        !url.pathname.includes("/ad-join"),
      (route) => {
        if (route.request().method() === "GET") {
          route.fulfill({
            status: 404,
            contentType: "application/json",
            body: JSON.stringify({ detail: "Session not found" }),
          });
        } else {
          route.continue();
        }
      },
    );

    const adJoinPromise = bobPage.waitForRequest(
      (req) => req.url().includes(`/broadcast/sessions/${badSid}/ad-join`) && req.method() === "POST",
      { timeout: 10_000 },
    );

    await bobPage.goto(`http://localhost:3000/live/${badSid}`);

    // Pre-fix: this times out because adJoinMutation never fires after the 404.
    // Post-fix: the ad-join POST fires from the [sessionId, isAuthenticated]
    // effect regardless of the session fetch outcome.
    const adJoinReq = await adJoinPromise;
    expect(adJoinReq).toBeTruthy();

    await bobPage.unroute(
      (url) =>
        url.pathname.endsWith(`/broadcast/sessions/${badSid}`) &&
        !url.pathname.includes("/ad-join"),
    );
  });

  test("369A.2 ad-join and session fetch fire concurrently on valid load", async () => {
    const adJoinPromise = bobPage.waitForRequest(
      (req) => req.url().includes("/ad-join") && req.method() === "POST",
      { timeout: 12_000 },
    );
    const sessionGetPromise = bobPage.waitForRequest(
      (req) =>
        /\/broadcast\/sessions\/[^/]+$/.test(req.url().split("?")[0]) &&
        !req.url().includes("/ad-join") &&
        req.method() === "GET",
      { timeout: 12_000 },
    );

    const sid = `gap0073-valid-${TS}`;
    await bobPage.goto(`http://localhost:3000/live/${sid}`);

    // Both requests fire — neither depends on the other completing.
    await Promise.all([adJoinPromise, sessionGetPromise]);
  });
});
