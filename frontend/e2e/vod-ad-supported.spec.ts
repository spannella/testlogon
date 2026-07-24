/**
 * E2E tests for VOD-018: Ad-Supported Viewing Tier (vod_ad_supported).
 *
 * Exercises the DEDICATED ad-supported viewing layer (separate
 * `vod_ad_sessions` table, /ui/vod/ad-supported router) — distinct from the
 * VOD purchase/rental systems. A viewer watches an `ad_supported` video for
 * FREE in exchange for watching ad breaks.
 *
 * Section 1: start session (free playback grant + ad schedule) + gating
 * Section 2: report ad-break complete/skip + completion + status
 * Section 3: viewer UI affordance
 *
 * Deterministic: ad selection uses static placeholder creatives
 * (VOD_AD_SUPPORTED_DETERMINISTIC), so the schedule is reproducible. Videos
 * are seeded directly into DynamoDB (no upload pipeline needed).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";

const ALICE_KEY = "alice"; // creator / owner
const BOB_KEY = "bob"; // viewer

const ALICE_SUB = "e2e_alice@test.local";
const BOB_SUB = "e2e_bob@test.local";

// ── Session bootstrap ─────────────────────────────────────────────────────

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

async function injectAuth(page: Page, sessionKey: string) {
  const sessions = getSessions();
  const session = sessions[sessionKey];
  if (!session) throw new Error(`No session for key=${sessionKey}`);
  await page.context().addCookies(session.cookies);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

function csrf(sessionKey: string): Record<string, string> {
  const sessions = getSessions();
  return { "x-csrf-token": sessions[sessionKey].csrf_token };
}

async function apiGet(page: Page, sessionKey: string, path: string) {
  return page.request.get(BASE + path, { headers: csrf(sessionKey) });
}

async function apiPost(page: Page, sessionKey: string, path: string, body?: object) {
  return page.request.post(BASE + path, {
    headers: { ...csrf(sessionKey), "Content-Type": "application/json" },
    data: body ?? {},
  });
}

// ── DDB helpers ───────────────────────────────────────────────────────────

const DDB_URL = "http://localhost:8001";
const DDB_HEADERS = {
  "Content-Type": "application/x-amz-json-1.0",
  Authorization:
    "AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1/dynamodb/aws4_request",
};

async function ddbRequest(page: Page, target: string, data: object) {
  return page.request.post(DDB_URL, {
    headers: { ...DDB_HEADERS, "X-Amz-Target": `DynamoDB_20120810.${target}` },
    data,
  });
}

async function seedVideo(
  page: Page,
  opts: {
    videoId: string;
    ownerId: string;
    title: string;
    accessMode: string;
    durationSeconds?: number;
    priceCents?: number;
  },
) {
  const ts = Math.floor(Date.now() / 1000);
  const item: Record<string, any> = {
    video_id: { S: opts.videoId },
    owner_user_id: { S: opts.ownerId },
    title: { S: opts.title },
    status: { S: "published" },
    visibility: { S: "public" },
    created_at: { N: String(ts) },
    updated_at: { N: String(ts) },
    source_type: { S: "upload" },
    drm_enabled: { BOOL: false },
    access_mode: { S: opts.accessMode },
    price_cents: { N: String(opts.priceCents ?? 0) },
    // Long duration so the default ad config yields pre-roll + mid-roll(s).
    duration_seconds: { N: String(opts.durationSeconds ?? 900) },
  };
  await ddbRequest(page, "PutItem", { TableName: "VideoMetadata", Item: item });
}

async function deleteSession(page: Page, userId: string, videoId: string) {
  await ddbRequest(page, "DeleteItem", {
    TableName: "VodAdSessions",
    Key: { pk: { S: `USER#${userId}` }, sk: { S: `VIDEO#${videoId}` } },
  });
}

const TS = Date.now();
function vid(suffix: string): string {
  return `vad_${TS.toString(16).slice(0, 8)}_${suffix}`;
}

// ── Section 1: start session + gating ─────────────────────────────────────

test.describe("vod-ad-supported 1 - start + gating", () => {
  const AD_VID = vid("ad1");
  const PPV_VID = vid("ppv");

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);
    await seedVideo(page, {
      videoId: AD_VID,
      ownerId: ALICE_SUB,
      title: "Ad-Supported Test Video",
      accessMode: "ad_supported",
    });
    await seedVideo(page, {
      videoId: PPV_VID,
      ownerId: ALICE_SUB,
      title: "PPV Video",
      accessMode: "ppv",
      priceCents: 500,
    });
    await deleteSession(page, BOB_SUB, AD_VID);
    await ctx.close();
  });

  test("no session initially -> abandoned stub", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    await deleteSession(page, BOB_SUB, AD_VID);

    const resp = await apiGet(page, BOB_KEY, `/ui/vod/ad-supported/${AD_VID}/session`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("abandoned");
    expect(data.breaks_total).toBe(0);
    await ctx.close();
  });

  test("start returns free playback grant + ad schedule (pre-roll gates start)", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    await deleteSession(page, BOB_SUB, AD_VID);

    const resp = await apiPost(page, BOB_KEY, `/ui/vod/ad-supported/${AD_VID}/start`, {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.session_id).toMatch(/^vadsess_/);
    // Free playback grant present (no charge).
    expect(data.playback_url).toBeTruthy();
    // Ad schedule has at least a pre-roll break.
    expect(data.breaks_total).toBeGreaterThanOrEqual(1);
    expect(data.ad_schedule[0].slot_type).toBe("pre_roll");
    // Pre-roll not yet watched -> playback locked at start.
    expect(data.playback_unlocked).toBe(false);
    expect(data.next_required_break_id).toBe(data.ad_schedule[0].break_id);
    expect(data.status).toBe("active");
    await ctx.close();
  });

  test("start is idempotent for an active session (schedule preserved)", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    await deleteSession(page, BOB_SUB, AD_VID);

    const first = await (await apiPost(page, BOB_KEY, `/ui/vod/ad-supported/${AD_VID}/start`, {})).json();
    const second = await (await apiPost(page, BOB_KEY, `/ui/vod/ad-supported/${AD_VID}/start`, {})).json();
    expect(second.session_id).toBe(first.session_id);
    expect(second.ad_schedule[0].break_id).toBe(first.ad_schedule[0].break_id);
    await ctx.close();
  });

  test("non ad-supported video cannot start an ad-supported session (400)", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    const resp = await apiPost(page, BOB_KEY, `/ui/vod/ad-supported/${PPV_VID}/start`, {});
    expect(resp.status()).toBe(400);
    await ctx.close();
  });

  test("start requires auth (401 without session)", async ({ request }) => {
    const resp = await request.post(BASE + `/ui/vod/ad-supported/${AD_VID}/start`, {
      headers: { "Content-Type": "application/json" },
      data: {},
    });
    expect(resp.status()).toBe(401);
  });
});

// ── Section 2: report breaks + completion + status ────────────────────────

test.describe("vod-ad-supported 2 - report breaks + completion", () => {
  const AD_VID = vid("ad2");

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);
    await seedVideo(page, {
      videoId: AD_VID,
      ownerId: ALICE_SUB,
      title: "Ad-Supported Report Video",
      accessMode: "ad_supported",
    });
    await ctx.close();
  });

  test("completing the pre-roll unlocks playback start", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    await deleteSession(page, BOB_SUB, AD_VID);

    const started = await (await apiPost(page, BOB_KEY, `/ui/vod/ad-supported/${AD_VID}/start`, {})).json();
    const preRoll = started.ad_schedule.find((b: any) => b.slot_type === "pre_roll");
    expect(preRoll).toBeTruthy();

    const resp = await apiPost(page, BOB_KEY, `/ui/vod/ad-supported/${AD_VID}/break`, {
      break_id: preRoll.break_id,
      event_type: "complete",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.completed).toBe(true);
    expect(data.playback_unlocked).toBe(true);
    expect(data.breaks_completed).toBeGreaterThanOrEqual(1);
    await ctx.close();
  });

  test("completing all required breaks marks the session completed", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    await deleteSession(page, BOB_SUB, AD_VID);

    const started = await (await apiPost(page, BOB_KEY, `/ui/vod/ad-supported/${AD_VID}/start`, {})).json();
    for (const b of started.ad_schedule) {
      if (b.slot_type === "pre_roll" || b.slot_type === "mid_roll") {
        await apiPost(page, BOB_KEY, `/ui/vod/ad-supported/${AD_VID}/break`, {
          break_id: b.break_id,
          event_type: "complete",
        });
      }
    }

    const final = await (await apiGet(page, BOB_KEY, `/ui/vod/ad-supported/${AD_VID}/session`)).json();
    expect(final.status).toBe("completed");
    expect(final.playback_unlocked).toBe(true);
    expect(final.next_required_break_id).toBeNull();
    await ctx.close();
  });

  test("skip does not mark the break complete (still gates)", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    await deleteSession(page, BOB_SUB, AD_VID);

    const started = await (await apiPost(page, BOB_KEY, `/ui/vod/ad-supported/${AD_VID}/start`, {})).json();
    const preRoll = started.ad_schedule.find((b: any) => b.slot_type === "pre_roll");

    const resp = await apiPost(page, BOB_KEY, `/ui/vod/ad-supported/${AD_VID}/break`, {
      break_id: preRoll.break_id,
      event_type: "skip",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.completed).toBe(false);
    expect(data.playback_unlocked).toBe(false);
    expect(data.status).toBe("active");
    await ctx.close();
  });

  test("reporting an unknown break id returns 404", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    await deleteSession(page, BOB_SUB, AD_VID);
    await apiPost(page, BOB_KEY, `/ui/vod/ad-supported/${AD_VID}/start`, {});

    const resp = await apiPost(page, BOB_KEY, `/ui/vod/ad-supported/${AD_VID}/break`, {
      break_id: "adbrk_does_not_exist",
      event_type: "complete",
    });
    expect(resp.status()).toBe(404);
    await ctx.close();
  });
});

// ── Section 3: viewer UI affordance ───────────────────────────────────────

test.describe("vod-ad-supported 3 - UI", () => {
  const AD_VID = vid("ad3");

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);
    await seedVideo(page, {
      videoId: AD_VID,
      ownerId: ALICE_SUB,
      title: "Ad-Supported UI Video",
      accessMode: "ad_supported",
    });
    await ctx.close();
  });

  test("ad-supported page renders and starts a session", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    await deleteSession(page, BOB_SUB, AD_VID);

    await page.goto(BASE + `/vod/${AD_VID}/free-with-ads`, {
      waitUntil: "domcontentloaded",
    });
    await expect(page.getByTestId("vod-ad-supported-page")).toBeVisible({
      timeout: 15_000,
    });
    await expect(
      page.getByRole("heading", { name: "Watch Free with Ads" }),
    ).toBeVisible();

    await page.getByTestId("start-ad-session").click();
    await expect(page.getByTestId("playback-unlocked")).toBeVisible({
      timeout: 15_000,
    });
    await ctx.close();
  });
});
