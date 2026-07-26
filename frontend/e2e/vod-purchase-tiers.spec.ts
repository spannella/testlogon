/**
 * E2E tests for VOD-019: View-Once / Rental / Download Purchase Tiers
 *
 * Section 136: Purchase Type Configuration (4 tests)
 * Section 137: View-Once + Rental Entitlement Lifecycle (5 tests)
 * Section 138: Download Purchase + Access (3 tests)
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions, resolveIdentityId } from "./helpers/session";
import {
  usingCpp,
  cppSeedVodVideo,
  cppDeleteVodVideo,
  cppSeedVodEntitlement,
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
    status?: string;
    priceCents?: number;
    accessMode?: string;
    availablePurchaseTypes?: string[];
    viewOncePriceCents?: number;
    rentalPriceCents?: number;
    rentalDurationHours?: number;
    downloadPriceCents?: number;
    allowDownload?: boolean;
    downloadMp4Status?: string;
    downloadMp4Key?: string;
  },
) {
  if (usingCpp()) {
    cppSeedVodVideo({
      videoId: opts.videoId,
      ownerSub: opts.ownerId,
      title: opts.title,
      status: opts.status,
      priceCents: opts.priceCents,
      accessMode: opts.accessMode,
      availablePurchaseTypes: opts.availablePurchaseTypes,
      viewOncePriceCents: opts.viewOncePriceCents,
      rentalPriceCents: opts.rentalPriceCents,
      rentalDurationHours: opts.rentalDurationHours,
      downloadPriceCents: opts.downloadPriceCents,
      extra: {
        ...(opts.allowDownload != null ? { allow_download: opts.allowDownload } : {}),
        ...(opts.downloadMp4Status ? { download_mp4_status: opts.downloadMp4Status } : {}),
        ...(opts.downloadMp4Key ? { download_mp4_key: opts.downloadMp4Key } : {}),
      },
    });
    return;
  }
  const item: Record<string, any> = {
    video_id: { S: opts.videoId },
    owner_user_id: { S: opts.ownerId },
    title: { S: opts.title },
    status: { S: opts.status || "published" },
    visibility: { S: "public" },
    created_at: { N: String(Math.floor(Date.now() / 1000)) },
    updated_at: { N: String(Math.floor(Date.now() / 1000)) },
    source_type: { S: "upload" },
    drm_enabled: { BOOL: false },
  };

  if (opts.priceCents != null) item.price_cents = { N: String(opts.priceCents) };
  if (opts.accessMode) item.access_mode = { S: opts.accessMode };
  if (opts.availablePurchaseTypes) {
    item.available_purchase_types = { L: opts.availablePurchaseTypes.map((t) => ({ S: t })) };
  }
  if (opts.viewOncePriceCents != null)
    item.view_once_price_cents = { N: String(opts.viewOncePriceCents) };
  if (opts.rentalPriceCents != null)
    item.rental_price_cents = { N: String(opts.rentalPriceCents) };
  if (opts.rentalDurationHours != null)
    item.rental_duration_hours = { N: String(opts.rentalDurationHours) };
  if (opts.downloadPriceCents != null)
    item.download_price_cents = { N: String(opts.downloadPriceCents) };
  if (opts.allowDownload != null) item.allow_download = { BOOL: opts.allowDownload };
  if (opts.downloadMp4Status) item.download_mp4_status = { S: opts.downloadMp4Status };
  if (opts.downloadMp4Key) item.download_mp4_key = { S: opts.downloadMp4Key };

  await ddbRequest(page, "PutItem", { TableName: "VideoMetadata", Item: item });
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

async function seedExpiredRental(
  page: Page,
  userId: string,
  videoId: string,
) {
  const expiredAt = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
  const createdAt = expiredAt - 172800; // 48 hours before that
  if (usingCpp()) {
    cppSeedVodEntitlement({
      buyerSub: userId,
      videoId,
      sellerSub: ALICE_SUB,
      purchaseType: "rental",
      grantType: "purchase",
      amountCents: 299,
      viewsRemaining: -1,
      expiresAt: expiredAt,
      createdAt,
      purchaseId: "vpurch_expired_test",
      downloadAllowed: false,
    });
    return;
  }
  await ddbRequest(page, "PutItem", {
    TableName: "VodEntitlements",
    Item: {
      pk: { S: `USER#${userId}` },
      sk: { S: `VIDEO#${videoId}` },
      video_id: { S: videoId },
      buyer_id: { S: userId },
      seller_id: { S: ALICE_SUB },
      grant_type: { S: "purchase" },
      purchase_type: { S: "rental" },
      views_remaining: { N: "-1" },
      expires_at: { N: String(expiredAt) },
      created_at: { N: String(createdAt) },
      amount_cents: { N: "299" },
      purchase_id: { S: "vpurch_expired_test" },
      download_allowed: { BOOL: false },
    },
  });
}

// ── Section 136: Purchase Type Configuration ─────────────────────────────

test.describe("136 - Purchase Type Configuration", () => {
  const TS = Date.now();
  const CFG_VID = `v_cfg_${TS.toString(16).slice(0, 12)}`.padEnd(20, "0");

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);
    await seedVideo(page, {
      videoId: CFG_VID,
      ownerId: ALICE_SUB,
      title: `Tier Config ${TS}`,
      priceCents: 999,
      accessMode: "ppv",
    });
    await ctx.close();
  });

  test.afterAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);
    await deleteVideo(page, CFG_VID);
    await ctx.close();
  });

  test("136.1 Creator configures multiple purchase types", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_KEY);
    const resp = await apiPatch(page, ALICE_KEY, `/ui/videos/${CFG_VID}/pricing`, {
      available_purchase_types: ["view_once", "rental", "permanent", "download"],
      view_once_price_cents: 199,
      rental_price_cents: 299,
      rental_duration_hours: 48,
      download_price_cents: 1299,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.available_purchase_types).toEqual(["view_once", "rental", "permanent", "download"]);
    expect(data.view_once_price_cents).toBe(199);
    expect(data.rental_price_cents).toBe(299);
    expect(data.rental_duration_hours).toBe(48);
    expect(data.download_price_cents).toBe(1299);
    await page.context().close();
  });

  test("136.2 Creator sets rental duration to 72 hours", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_KEY);
    const resp = await apiPatch(page, ALICE_KEY, `/ui/videos/${CFG_VID}/pricing`, {
      rental_duration_hours: 72,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.rental_duration_hours).toBe(72);
    await page.context().close();
  });

  test("136.3 Download price must be >= permanent price", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_KEY);
    const resp = await apiPatch(page, ALICE_KEY, `/ui/videos/${CFG_VID}/pricing`, {
      price_cents: 999,
      download_price_cents: 500,
    });
    expect(resp.status()).toBe(422);
    await page.context().close();
  });

  test("136.4 Invalid purchase type rejected", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_KEY);
    const resp = await apiPatch(page, ALICE_KEY, `/ui/videos/${CFG_VID}/pricing`, {
      available_purchase_types: ["invalid_type"],
    });
    expect(resp.status()).toBe(422);
    await page.context().close();
  });
});

// ── Section 137: View-Once + Rental Entitlement Lifecycle ────────────────

test.describe("137 - View-Once + Rental Lifecycle", () => {
  const TS = Date.now();
  const VO_VID = `v_vo_${TS.toString(16).slice(0, 12)}`.padEnd(20, "0");
  const RENT_VID = `v_rnt_${TS.toString(16).slice(0, 12)}`.padEnd(20, "0");
  const RENT_EXP_VID = `v_rne_${TS.toString(16).slice(0, 12)}`.padEnd(20, "0");

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);

    // Seed view-once video
    await seedVideo(page, {
      videoId: VO_VID,
      ownerId: ALICE_SUB,
      title: `View Once ${TS}`,
      priceCents: 999,
      accessMode: "ppv",
      availablePurchaseTypes: ["view_once", "rental", "permanent"],
      viewOncePriceCents: 199,
      rentalPriceCents: 299,
      rentalDurationHours: 48,
    });

    // Seed rental video
    await seedVideo(page, {
      videoId: RENT_VID,
      ownerId: ALICE_SUB,
      title: `Rental ${TS}`,
      priceCents: 999,
      accessMode: "ppv",
      availablePurchaseTypes: ["view_once", "rental", "permanent"],
      viewOncePriceCents: 199,
      rentalPriceCents: 299,
      rentalDurationHours: 48,
    });

    // Seed rental-expiry test video
    await seedVideo(page, {
      videoId: RENT_EXP_VID,
      ownerId: ALICE_SUB,
      title: `Rental Expiry ${TS}`,
      priceCents: 999,
      accessMode: "ppv",
      availablePurchaseTypes: ["view_once", "rental", "permanent"],
      viewOncePriceCents: 199,
      rentalPriceCents: 299,
      rentalDurationHours: 48,
    });

    // Clean up any stale entitlements
    await deleteEntitlement(page, BOB_SUB, VO_VID);
    await deleteEntitlement(page, BOB_SUB, RENT_VID);
    await deleteEntitlement(page, BOB_SUB, RENT_EXP_VID);

    await ctx.close();
  });

  test.afterAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);
    await deleteVideo(page, VO_VID);
    await deleteVideo(page, RENT_VID);
    await deleteVideo(page, RENT_EXP_VID);
    await deleteEntitlement(page, BOB_SUB, VO_VID);
    await deleteEntitlement(page, BOB_SUB, RENT_VID);
    await deleteEntitlement(page, BOB_SUB, RENT_EXP_VID);
    await ctx.close();
  });

  test("137.1 View-once purchase: entitled with views_remaining=1", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);

    // Purchase
    const purchResp = await apiPost(page, BOB_KEY, `/ui/videos/${VO_VID}/purchase`, {
      purchase_type: "view_once",
    });
    expect(purchResp.status()).toBe(200);
    const purchData = await purchResp.json();
    expect(purchData.purchase_type).toBe("view_once");
    expect(purchData.views_remaining).toBe(1);
    expect(purchData.already_owned).toBe(false);

    // Verify entitled
    const detailResp = await apiGet(page, BOB_KEY, `/ui/videos/${VO_VID}`);
    expect(detailResp.status()).toBe(200);
    const detail = await detailResp.json();
    expect(detail.is_entitled).toBe(true);
    expect(detail.views_remaining).toBe(1);
    expect(detail.purchase_type).toBe("view_once");

    await page.context().close();
  });

  test("137.2 View-once: playback-complete consumes view", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);

    // Trigger playback complete
    const pbResp = await apiPost(page, BOB_KEY, `/ui/videos/${VO_VID}/playback-complete`, {});
    expect(pbResp.status()).toBe(200);
    const pbData = await pbResp.json();
    expect(pbData.ok).toBe(true);
    expect(pbData.views_remaining).toBe(0);

    // Verify not entitled
    const detailResp = await apiGet(page, BOB_KEY, `/ui/videos/${VO_VID}`);
    const detail = await detailResp.json();
    expect(detail.is_entitled).toBe(false);
    expect(detail.views_remaining).toBe(-1); // not entitled = default values
    expect(detail.access_reason).toBe("consumed");

    await page.context().close();
  });

  test("137.3 View-once: consumed viewer can re-purchase", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);

    // Re-purchase after consumption (view-once consumed allows re-purchase)
    const resp = await apiPost(page, BOB_KEY, `/ui/videos/${VO_VID}/purchase`, {
      purchase_type: "view_once",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.already_owned).toBe(false);
    expect(data.views_remaining).toBe(1);
    expect(data.purchase_type).toBe("view_once");

    await page.context().close();
  });

  test("137.4 Rental purchase: entitled with expires_at set", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);

    const resp = await apiPost(page, BOB_KEY, `/ui/videos/${RENT_VID}/purchase`, {
      purchase_type: "rental",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.purchase_type).toBe("rental");
    expect(data.expires_at).toBeTruthy();
    expect(data.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));

    // Verify entitled via detail
    const detailResp = await apiGet(page, BOB_KEY, `/ui/videos/${RENT_VID}`);
    const detail = await detailResp.json();
    expect(detail.is_entitled).toBe(true);
    expect(detail.purchase_type).toBe("rental");
    expect(detail.rental_expires_at).toBeTruthy();
    expect(detail.rental_remaining_seconds).toBeGreaterThan(0);

    await page.context().close();
  });

  test("137.5 Rental after expiry: not entitled", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);

    // Seed expired rental directly in DDB
    await seedExpiredRental(page, BOB_SUB, RENT_EXP_VID);

    // Verify not entitled
    const detailResp = await apiGet(page, BOB_KEY, `/ui/videos/${RENT_EXP_VID}`);
    const detail = await detailResp.json();
    expect(detail.is_entitled).toBe(false);
    expect(detail.access_reason).toBe("expired");

    await page.context().close();
  });
});

// ── Section 138: Download Purchase + Access ──────────────────────────────

test.describe("138 - Download Purchase + Access", () => {
  const TS = Date.now();
  const DL_VID = `v_dl_${TS.toString(16).slice(0, 12)}`.padEnd(20, "0");

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);
    await seedVideo(page, {
      videoId: DL_VID,
      ownerId: ALICE_SUB,
      title: `Download ${TS}`,
      priceCents: 999,
      accessMode: "ppv",
      availablePurchaseTypes: ["permanent", "download"],
      downloadPriceCents: 1299,
      allowDownload: true,
      downloadMp4Status: "ready",
      downloadMp4Key: "s3://test-bucket/test.mp4",
    });
    await deleteEntitlement(page, BOB_SUB, DL_VID);
    await ctx.close();
  });

  test.afterAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);
    await deleteVideo(page, DL_VID);
    await deleteEntitlement(page, BOB_SUB, DL_VID);
    await ctx.close();
  });

  test("138.1 Download purchase: entitled with download_allowed=true", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);

    const resp = await apiPost(page, BOB_KEY, `/ui/videos/${DL_VID}/purchase`, {
      purchase_type: "download",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.purchase_type).toBe("download");
    expect(data.download_allowed).toBe(true);
    expect(data.already_owned).toBe(false);

    // Verify via detail
    const detailResp = await apiGet(page, BOB_KEY, `/ui/videos/${DL_VID}`);
    const detail = await detailResp.json();
    expect(detail.is_entitled).toBe(true);
    expect(detail.download_allowed).toBe(true);
    expect(detail.purchase_type).toBe("download");

    await page.context().close();
  });

  test("138.2 List purchases shows purchase_type and download_allowed", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);

    const resp = await apiGet(page, BOB_KEY, `/ui/videos/purchases/list`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find((i: any) => i.video_id === DL_VID);
    expect(found).toBeTruthy();
    expect(found.purchase_type).toBe("download");
    expect(found.download_allowed).toBe(true);

    await page.context().close();
  });

  test("138.3 Purchase type not in available_purchase_types returns 400", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_KEY);

    // DL_VID only has ["permanent", "download"] as available types
    // Delete entitlement first so it's not "already_owned"
    await deleteEntitlement(page, BOB_SUB, DL_VID);

    const resp = await apiPost(page, BOB_KEY, `/ui/videos/${DL_VID}/purchase`, {
      purchase_type: "view_once",
    });
    expect(resp.status()).toBe(400);

    await page.context().close();
  });
});
