/**
 * E2E tests for VOD-018: Ad-Supported Video Tier
 *
 * Sections:
 *   134 — Ad Configuration API (4 tests)
 *   135 — Ad Impression Tracking + Revenue (6 tests)
 *
 * Auth: Alice (creator) + Bob (viewer) session cookies.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ──────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_KEY = "alice";
const BOB_KEY = "bob";
const ALICE_SUB = "e2e_alice@test.local";
const BOB_SUB = "e2e_bob@test.local";
const TS = Date.now();

// ─── Session bootstrap ──────────────────────────────────────────────────────

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

// ─── Auth helpers ───────────────────────────────────────────────────────────

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

async function apiPost(page: Page, sessionKey: string, path: string, body: object) {
  return page.request.post(BASE + path, {
    headers: { ...csrf(sessionKey), "Content-Type": "application/json" },
    data: body,
  });
}

async function apiPatch(page: Page, sessionKey: string, path: string, body: object) {
  return page.request.patch(BASE + path, {
    headers: { ...csrf(sessionKey), "Content-Type": "application/json" },
    data: body,
  });
}

// ─── DDB helpers ────────────────────────────────────────────────────────────

const DDB_URL = "http://localhost:8001";
const DDB_HEADERS = {
  "Content-Type": "application/x-amz-json-1.0",
  Authorization:
    "AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1/dynamodb/aws4_request",
};

async function ddbRequest(page: Page, target: string, data: object) {
  return page.request.post(DDB_URL, {
    headers: {
      ...DDB_HEADERS,
      "X-Amz-Target": `DynamoDB_20120810.${target}`,
    },
    data,
  });
}

async function seedVideo(
  page: Page,
  opts: {
    videoId: string;
    ownerId: string;
    title: string;
    status?: string;
    priceCents?: number;
    accessMode?: string;
    durationSeconds?: number;
    adsFreeForSubscribers?: boolean;
  },
) {
  await ddbRequest(page, "PutItem", {
    TableName: "VideoMetadata",
    Item: {
      video_id: { S: opts.videoId },
      owner_user_id: { S: opts.ownerId },
      title: { S: opts.title },
      status: { S: opts.status || "published" },
      visibility: { S: "public" },
      created_at: { N: String(Math.floor(Date.now() / 1000)) },
      updated_at: { N: String(Math.floor(Date.now() / 1000)) },
      source_type: { S: "upload" },
      drm_enabled: { BOOL: false },
      ad_impression_count: { N: "0" },
      ad_revenue_cents: { N: "0" },
      ads_free_for_subscribers: { BOOL: opts.adsFreeForSubscribers ?? false },
      ...(opts.priceCents != null
        ? { price_cents: { N: String(opts.priceCents) } }
        : {}),
      ...(opts.accessMode
        ? { access_mode: { S: opts.accessMode } }
        : {}),
      ...(opts.durationSeconds != null
        ? { duration_seconds: { N: String(opts.durationSeconds) } }
        : {}),
    },
  });
}

async function deleteVideo(page: Page, videoId: string) {
  await ddbRequest(page, "DeleteItem", {
    TableName: "VideoMetadata",
    Key: { video_id: { S: videoId } },
  });
}

async function seedSubscription(page: Page, subscriberId: string, creatorId: string) {
  await ddbRequest(page, "PutItem", {
    TableName: "subscriptions",
    Item: {
      pk: { S: `SUBSCRIBER#${subscriberId}` },
      sk: { S: `SUB#e2e_ad_sub_${TS}` },
      creator_id: { S: creatorId },
      status: { S: "active" },
    },
  });
}

async function deleteSubscription(page: Page, subscriberId: string) {
  await ddbRequest(page, "DeleteItem", {
    TableName: "subscriptions",
    Key: {
      pk: { S: `SUBSCRIBER#${subscriberId}` },
      sk: { S: `SUB#e2e_ad_sub_${TS}` },
    },
  });
}

// ─── Video IDs ──────────────────────────────────────────────────────────────

const AD_VID = `v_ad_${TS.toString(16).slice(0, 10)}`.padEnd(20, "0");
const AD_VID_SUB = `v_adsub_${TS.toString(16).slice(0, 8)}`.padEnd(20, "0");
const PPV_VID = `v_adppv_${TS.toString(16).slice(0, 8)}`.padEnd(20, "0");

// ═══════════════════════════════════════════════════════════════════════════
// Section 134: Ad Configuration API
// ═══════════════════════════════════════════════════════════════════════════

test.describe("134 · Ad Configuration API", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);

    // Seed ad-supported video owned by Alice
    await seedVideo(page, {
      videoId: AD_VID,
      ownerId: ALICE_SUB,
      title: `Ad Video ${TS}`,
      accessMode: "ad_supported",
      priceCents: 0,
      durationSeconds: 900,  // 15 min
    });

    await ctx.close();
  });

  test.afterAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);
    await deleteVideo(page, AD_VID);
    await ctx.close();
  });

  test("134.1 Set access_mode to ad_supported", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_KEY);

    const resp = await apiPatch(page, ALICE_KEY, `/ui/videos/${AD_VID}/pricing`, {
      access_mode: "ad_supported",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.access_mode).toBe("ad_supported");

    await page.context().close();
  });

  test("134.2 Creator sets ad config", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_KEY);

    const resp = await apiPatch(page, ALICE_KEY, `/ui/videos/${AD_VID}/ad-config`, {
      pre_roll: true,
      mid_roll_intervals_seconds: [300, 600],
      overlay_enabled: false,
      skip_after_seconds: 5,
      ads_free_for_subscribers: true,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.ad_config.pre_roll).toBe(true);
    expect(data.ad_config.mid_roll_intervals_seconds).toContain(300);
    expect(data.ads_free_for_subscribers).toBe(true);

    await page.context().close();
  });

  test("134.3 Non-owner cannot set ad config", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);

    const resp = await apiPatch(page, BOB_KEY, `/ui/videos/${AD_VID}/ad-config`, {
      pre_roll: false,
    });
    expect(resp.status()).toBe(403);

    await page.context().close();
  });

  test("134.4 Invalid mid_roll timestamps are sanitized", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_KEY);

    // Duration is 900s; timestamps >= 870 should be dropped
    const resp = await apiPatch(page, ALICE_KEY, `/ui/videos/${AD_VID}/ad-config`, {
      pre_roll: true,
      mid_roll_intervals_seconds: [10, 300, 875, 950],
      overlay_enabled: false,
      skip_after_seconds: 5,
      ads_free_for_subscribers: false,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // 10 < 30 should be dropped; 875 >= 870 should be dropped; 950 > 870 dropped
    const midRolls = data.ad_config.mid_roll_intervals_seconds;
    for (const ts of midRolls) {
      expect(ts).toBeGreaterThanOrEqual(30);
      expect(ts).toBeLessThan(870);
    }

    await page.context().close();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 135: Ad Impression Tracking + Revenue
// ═══════════════════════════════════════════════════════════════════════════

test.describe("135 · Ad Impression Tracking + Revenue", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);

    // Clean up any leftover subscription from previous runs
    await deleteSubscription(page, BOB_SUB);

    // Seed fresh ad-supported video — ads_free_for_subscribers OFF by default
    // (test 135.2 will temporarily enable it)
    await seedVideo(page, {
      videoId: AD_VID_SUB,
      ownerId: ALICE_SUB,
      title: `Ad Sub Video ${TS}`,
      accessMode: "ad_supported",
      priceCents: 0,
      durationSeconds: 600,
      adsFreeForSubscribers: false,
    });

    // Seed ppv video for comparison
    await seedVideo(page, {
      videoId: PPV_VID,
      ownerId: ALICE_SUB,
      title: `PPV Video ${TS}`,
      accessMode: "ppv",
      priceCents: 500,
      durationSeconds: 300,
    });

    // Configure ad on the ad-supported video (ads_free OFF)
    await apiPatch(page, ALICE_KEY, `/ui/videos/${AD_VID_SUB}/ad-config`, {
      pre_roll: true,
      mid_roll_intervals_seconds: [300],
      overlay_enabled: false,
      skip_after_seconds: 5,
      ads_free_for_subscribers: false,
    });

    await ctx.close();
  });

  test.afterAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);
    await deleteVideo(page, AD_VID_SUB);
    await deleteVideo(page, PPV_VID);
    await deleteSubscription(page, BOB_SUB);
    await ctx.close();
  });

  test("135.1 Ad config returns slots for ad_supported video", async ({
    browser,
  }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);

    const resp = await apiGet(
      page,
      BOB_KEY,
      `/ui/videos/${AD_VID_SUB}/ad-config`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ads_enabled).toBe(true);
    expect(data.ad_free).toBe(false);
    expect(data.slots.length).toBeGreaterThanOrEqual(1);
    expect(data.slots[0].type).toBe("pre_roll");

    await page.context().close();
  });

  test("135.2 Subscriber gets ad-free response", async ({ browser }) => {
    // Temporarily enable ads_free_for_subscribers on the video
    const aliceCtx = await browser.newContext();
    const alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_KEY);
    await apiPatch(alicePage, ALICE_KEY, `/ui/videos/${AD_VID_SUB}/ad-config`, {
      pre_roll: true,
      mid_roll_intervals_seconds: [300],
      overlay_enabled: false,
      skip_after_seconds: 5,
      ads_free_for_subscribers: true,
    });
    await aliceCtx.close();

    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);

    // Seed subscription for Bob -> Alice
    await seedSubscription(page, BOB_SUB, ALICE_SUB);

    const resp = await apiGet(
      page,
      BOB_KEY,
      `/ui/videos/${AD_VID_SUB}/ad-config`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ads_enabled).toBe(false);
    expect(data.ad_free).toBe(true);
    expect(data.slots).toHaveLength(0);

    // Clean up: remove subscription and disable ads_free_for_subscribers
    await deleteSubscription(page, BOB_SUB);
    await ctx.close();

    const cleanupCtx = await browser.newContext();
    const cleanupPage = await cleanupCtx.newPage();
    await injectAuth(cleanupPage, ALICE_KEY);
    await apiPatch(cleanupPage, ALICE_KEY, `/ui/videos/${AD_VID_SUB}/ad-config`, {
      pre_roll: true,
      mid_roll_intervals_seconds: [300],
      overlay_enabled: false,
      skip_after_seconds: 5,
      ads_free_for_subscribers: false,
    });
    await cleanupCtx.close();
  });

  test("135.3 PPV video returns empty ad config", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);

    const resp = await apiGet(
      page,
      BOB_KEY,
      `/ui/videos/${PPV_VID}/ad-config`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ads_enabled).toBe(false);
    expect(data.ad_free).toBe(true);
    expect(data.slots).toHaveLength(0);

    await page.context().close();
  });

  test("135.4 Record ad impression", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);

    const resp = await apiPost(
      page,
      BOB_KEY,
      `/ui/videos/${AD_VID_SUB}/ad-impression`,
      {
        slot_type: "pre_roll",
        slot_index: 0,
        creative_id: "dev_ad_preroll_15s",
        event_type: "impression",
      },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.event_id).toMatch(/^adimp_/);

    await page.context().close();
  });

  test("135.5 Complete event credits creator revenue", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);

    // Record a complete event
    const resp = await apiPost(
      page,
      BOB_KEY,
      `/ui/videos/${AD_VID_SUB}/ad-impression`,
      {
        slot_type: "pre_roll",
        slot_index: 0,
        creative_id: "dev_ad_preroll_15s",
        event_type: "complete",
      },
    );
    expect(resp.status()).toBe(200);

    // Now check ad stats as Alice (owner)
    const alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_KEY);
    const statsResp = await apiGet(
      alicePage,
      ALICE_KEY,
      `/ui/videos/${AD_VID_SUB}/ad-stats`,
    );
    expect(statsResp.status()).toBe(200);
    const stats = await statsResp.json();
    expect(stats.ad_impression_count).toBeGreaterThanOrEqual(1);
    expect(stats.ad_revenue_cents).toBeGreaterThan(0);
    expect(stats.estimated_cpm_cents).toBe(500);

    await page.context().close();
    await alicePage.context().close();
  });

  test("135.6 Non-owner cannot view ad stats", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);

    const resp = await apiGet(
      page,
      BOB_KEY,
      `/ui/videos/${AD_VID_SUB}/ad-stats`,
    );
    expect(resp.status()).toBe(403);

    await page.context().close();
  });

  test("135.7 Access check for ad_supported returns entitled + ads_enabled", async ({
    browser,
  }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);

    const resp = await apiGet(
      page,
      BOB_KEY,
      `/ui/videos/${AD_VID_SUB}/access`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.entitled).toBe(true);
    expect(data.reason).toBe("ad");
    expect(data.ads_enabled).toBe(true);

    await page.context().close();
  });

  test("135.8 Skip event does not credit revenue", async ({ browser }) => {
    // Get current stats
    const alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_KEY);
    const beforeResp = await apiGet(
      alicePage,
      ALICE_KEY,
      `/ui/videos/${AD_VID_SUB}/ad-stats`,
    );
    const beforeStats = await beforeResp.json();
    const revenueBefore = beforeStats.ad_revenue_cents;

    // Record a skip event as Bob
    const bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_KEY);
    const skipResp = await apiPost(
      bobPage,
      BOB_KEY,
      `/ui/videos/${AD_VID_SUB}/ad-impression`,
      {
        slot_type: "pre_roll",
        slot_index: 0,
        creative_id: "dev_ad_preroll_15s",
        event_type: "skip",
      },
    );
    expect(skipResp.status()).toBe(200);

    // Check stats after - revenue should be unchanged
    const afterResp = await apiGet(
      alicePage,
      ALICE_KEY,
      `/ui/videos/${AD_VID_SUB}/ad-stats`,
    );
    const afterStats = await afterResp.json();
    expect(afterStats.ad_revenue_cents).toBe(revenueBefore);

    await alicePage.context().close();
    await bobPage.context().close();
  });
});
