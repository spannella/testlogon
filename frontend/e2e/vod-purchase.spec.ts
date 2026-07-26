/**
 * E2E tests for MON-001: VOD Pay-Per-View
 *
 * Section 105: VOD Purchase API (9 tests)
 * Section 106: VOD Pricing API (5 tests)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions, resolveIdentityId } from "./helpers/session";
import {
  usingCpp,
  cppSeedVodVideo,
  cppDeleteVodVideo,
  cppDeleteVodEntitlement,
} from "./helpers/cpp-seed-video-vod";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ── Constants ─────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";

const ALICE_KEY = "alice";
const BOB_KEY = "bob";

const ALICE_SUB = resolveIdentityId("e2e_alice@test.local");
const BOB_SUB = resolveIdentityId("e2e_bob@test.local");

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

// ── Auth helpers ──────────────────────────────────────────────────────────

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

// ── DDB helpers ───────────────────────────────────────────────────────────

const DDB_URL = "http://localhost:8001";
const DDB_HEADERS = {
  "Content-Type": "application/x-amz-json-1.0",
  "Authorization": "AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1/dynamodb/aws4_request",
};

async function ddbRequest(page: Page, target: string, data: object) {
  return page.request.post(DDB_URL, {
    headers: { ...DDB_HEADERS, "X-Amz-Target": `DynamoDB_20120810.${target}` },
    data,
  });
}

async function seedVideo(page: Page, opts: {
  videoId: string;
  ownerId: string;
  title: string;
  status?: string;
  priceCents?: number;
  accessMode?: string;
}) {
  if (usingCpp()) {
    cppSeedVodVideo({
      videoId: opts.videoId,
      ownerSub: opts.ownerId,
      title: opts.title,
      status: opts.status,
      priceCents: opts.priceCents,
      accessMode: opts.accessMode,
    });
    return;
  }
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
      ...(opts.priceCents != null ? { price_cents: { N: String(opts.priceCents) } } : {}),
      ...(opts.accessMode ? { access_mode: { S: opts.accessMode } } : {}),
    },
  });
}

async function deleteVideo(page: Page, videoId: string) {
  if (usingCpp()) {
    cppDeleteVodVideo(videoId);
    return;
  }
  await ddbRequest(page, "DeleteItem", {
    TableName: "VideoMetadata",
    Key: { video_id: { S: videoId } },
  });
}

async function deleteEntitlement(page: Page, userId: string, videoId: string) {
  if (usingCpp()) {
    cppDeleteVodEntitlement(userId, videoId);
    return;
  }
  await ddbRequest(page, "DeleteItem", {
    TableName: "VodEntitlements",
    Key: { pk: { S: `USER#${userId}` }, sk: { S: `VIDEO#${videoId}` } },
  });
}

// ── Section 105: VOD Purchase API ─────────────────────────────────────────

test.describe("105 · VOD Purchase API", () => {
  const TS = Date.now();
  const FREE_VID = `v_free_${TS.toString(16).slice(0, 12)}`.padEnd(20, "0");
  const PPV_VID = `v_ppv0_${TS.toString(16).slice(0, 12)}`.padEnd(20, "0");

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);

    await seedVideo(page, {
      videoId: FREE_VID,
      ownerId: ALICE_SUB,
      title: `Free Video ${TS}`,
      priceCents: 0,
      accessMode: "free",
    });

    await seedVideo(page, {
      videoId: PPV_VID,
      ownerId: ALICE_SUB,
      title: `PPV Video ${TS}`,
      priceCents: 999,
      accessMode: "ppv",
    });

    await deleteEntitlement(page, BOB_SUB, PPV_VID);
    await ctx.close();
  });

  test.afterAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);
    await deleteVideo(page, FREE_VID);
    await deleteVideo(page, PPV_VID);
    await deleteEntitlement(page, BOB_SUB, PPV_VID);
    await ctx.close();
  });

  test("105.1 Owner is always entitled", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_KEY);
    const resp = await apiGet(page, ALICE_KEY, `/ui/videos/${PPV_VID}/access`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.entitled).toBe(true);
    expect(data.reason).toBe("owner");
    await page.context().close();
  });

  test("105.2 Free video returns entitled", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);
    const resp = await apiGet(page, BOB_KEY, `/ui/videos/${FREE_VID}/access`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.entitled).toBe(true);
    expect(data.reason).toBe("free");
    await page.context().close();
  });

  test("105.3 PPV video returns not entitled for non-owner", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);
    const resp = await apiGet(page, BOB_KEY, `/ui/videos/${PPV_VID}/access`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.entitled).toBe(false);
    expect(data.reason).toBe("none");
    expect(data.price_cents).toBe(999);
    await page.context().close();
  });

  test("105.4 Purchase PPV video succeeds", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);
    const resp = await apiPost(page, BOB_KEY, `/ui/videos/${PPV_VID}/purchase`, {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_id).toBe(PPV_VID);
    expect(data.already_owned).toBe(false);
    expect(data.amount_cents).toBe(999);
    expect(data.grant_type).toBe("purchase");
    expect(data.purchase_id).toMatch(/^vpurch_/);
    await page.context().close();
  });

  test("105.5 Repeat purchase returns already_owned", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);
    const resp = await apiPost(page, BOB_KEY, `/ui/videos/${PPV_VID}/purchase`, {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.already_owned).toBe(true);
    await page.context().close();
  });

  test("105.6 After purchase, access check returns entitled", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);
    const resp = await apiGet(page, BOB_KEY, `/ui/videos/${PPV_VID}/access`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.entitled).toBe(true);
    expect(data.reason).toBe("purchased");
    await page.context().close();
  });

  test("105.7 Cannot purchase own video", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_KEY);
    const resp = await apiPost(page, ALICE_KEY, `/ui/videos/${PPV_VID}/purchase`, {});
    expect(resp.status()).toBe(400);
    await page.context().close();
  });

  test("105.8 Cannot purchase free video", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);
    const resp = await apiPost(page, BOB_KEY, `/ui/videos/${FREE_VID}/purchase`, {});
    expect(resp.status()).toBe(400);
    await page.context().close();
  });

  test("105.9 List purchases shows purchased video", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);
    const resp = await apiGet(page, BOB_KEY, "/ui/videos/purchases/list");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find((i: any) => i.video_id === PPV_VID);
    expect(found).toBeTruthy();
    expect(found.amount_cents).toBe(999);
    await page.context().close();
  });
});

// ── Section 106: VOD Pricing API ──────────────────────────────────────────

test.describe("106 · VOD Pricing API", () => {
  const TS = Date.now();
  const PRICE_VID = `v_prce_${TS.toString(16).slice(0, 12)}`.padEnd(20, "0");

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);
    await seedVideo(page, {
      videoId: PRICE_VID,
      ownerId: ALICE_SUB,
      title: `Pricing Test ${TS}`,
    });
    await ctx.close();
  });

  test.afterAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);
    await deleteVideo(page, PRICE_VID);
    await ctx.close();
  });

  test("106.1 Owner can set price", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_KEY);
    const resp = await apiPatch(page, ALICE_KEY, `/ui/videos/${PRICE_VID}/pricing`, {
      price_cents: 499,
      access_mode: "ppv",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.price_cents).toBe(499);
    expect(data.access_mode).toBe("ppv");
    await page.context().close();
  });

  test("106.2 Non-owner cannot set price", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);
    const resp = await apiPatch(page, BOB_KEY, `/ui/videos/${PRICE_VID}/pricing`, {
      price_cents: 100,
    });
    expect(resp.status()).toBe(403);
    await page.context().close();
  });

  test("106.3 Price persists on detail endpoint", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_KEY);
    const resp = await apiGet(page, ALICE_KEY, `/ui/videos/${PRICE_VID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.price_cents).toBe(499);
    expect(data.access_mode).toBe("ppv");
    await page.context().close();
  });

  test("106.4 Can set price to zero (make free)", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_KEY);
    const resp = await apiPatch(page, ALICE_KEY, `/ui/videos/${PRICE_VID}/pricing`, {
      price_cents: 0,
      access_mode: "free",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.price_cents).toBe(0);
    expect(data.access_mode).toBe("free");
    await page.context().close();
  });

  test("106.5 Detail shows PPV video without playback for non-owner", async ({ browser }) => {
    // Set price back to PPV first
    const alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_KEY);
    await apiPatch(alicePage, ALICE_KEY, `/ui/videos/${PRICE_VID}/pricing`, {
      price_cents: 799,
      access_mode: "ppv",
    });
    await alicePage.context().close();

    // Bob checks detail — should see price but not entitled
    const bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_KEY);
    const resp = await apiGet(bobPage, BOB_KEY, `/ui/videos/${PRICE_VID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.price_cents).toBe(799);
    expect(data.is_entitled).toBe(false);
    await bobPage.context().close();
  });
});
