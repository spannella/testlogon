/**
 * E2E tests for VOD-019: View-Once / Rental Access layer (vod_rental).
 *
 * This exercises the DEDICATED rental-access layer (separate `vod_rentals`
 * table, /ui/vod/rental router) — distinct from the permanent-purchase
 * entitlement system. Coverage:
 *
 * Section 1: Start rental / view-once + validation/auth
 * Section 2: Time-window + view-once consumption (deterministic via `now`)
 * Section 3: Gated playback URL issuance + status/history + UI
 *
 * Time is injected deterministically via the dev-only `?now=` query param so
 * rental expiry and view-once consumption can be tested without sleeping.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions, resolveIdentityId } from "./helpers/session";
import {
  usingCpp,
  cppSeedVodVideo,
  cppDeleteVodRental,
} from "./helpers/cpp-seed-video-vod";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";

const ALICE_KEY = "alice"; // creator / owner
const BOB_KEY = "bob"; // renter

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
    status?: string;
    availablePurchaseTypes?: string[];
    viewOncePriceCents?: number;
    rentalPriceCents?: number;
    rentalDurationHours?: number;
  },
) {
  if (usingCpp()) {
    cppSeedVodVideo({
      videoId: opts.videoId,
      ownerSub: opts.ownerId,
      title: opts.title,
      status: opts.status,
      availablePurchaseTypes: opts.availablePurchaseTypes,
      viewOncePriceCents: opts.viewOncePriceCents,
      rentalPriceCents: opts.rentalPriceCents,
      rentalDurationHours: opts.rentalDurationHours,
    });
    return;
  }
  const ts = Math.floor(Date.now() / 1000);
  const item: Record<string, any> = {
    video_id: { S: opts.videoId },
    owner_user_id: { S: opts.ownerId },
    title: { S: opts.title },
    status: { S: opts.status || "published" },
    visibility: { S: "public" },
    created_at: { N: String(ts) },
    updated_at: { N: String(ts) },
    source_type: { S: "upload" },
    drm_enabled: { BOOL: false },
  };
  if (opts.availablePurchaseTypes) {
    item.available_purchase_types = {
      L: opts.availablePurchaseTypes.map((t) => ({ S: t })),
    };
  }
  if (opts.viewOncePriceCents != null)
    item.view_once_price_cents = { N: String(opts.viewOncePriceCents) };
  if (opts.rentalPriceCents != null)
    item.rental_price_cents = { N: String(opts.rentalPriceCents) };
  if (opts.rentalDurationHours != null)
    item.rental_duration_hours = { N: String(opts.rentalDurationHours) };

  await ddbRequest(page, "PutItem", { TableName: "VideoMetadata", Item: item });
}

async function deleteRental(page: Page, userId: string, videoId: string) {
  if (usingCpp()) {
    cppDeleteVodRental(userId, videoId);
    return;
  }
  await ddbRequest(page, "DeleteItem", {
    TableName: "VodRentals",
    Key: { pk: { S: `USER#${userId}` }, sk: { S: `VIDEO#${videoId}` } },
  });
}

const TS = Date.now();
const NOW = Math.floor(TS / 1000);
function vid(suffix: string): string {
  return `vr_${TS.toString(16).slice(0, 8)}_${suffix}`;
}

// ── Section 1: Start rental / view-once + validation/auth ────────────────

test.describe("vod-rental 1 - start + validation", () => {
  const RENTAL_VID = vid("rent1");
  const NOPRICE_VID = vid("noprice");

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);
    await seedVideo(page, {
      videoId: RENTAL_VID,
      ownerId: ALICE_SUB,
      title: "Rental Test Video",
      availablePurchaseTypes: ["view_once", "rental", "permanent"],
      viewOncePriceCents: 199,
      rentalPriceCents: 299,
      rentalDurationHours: 48,
    });
    await seedVideo(page, {
      videoId: NOPRICE_VID,
      ownerId: ALICE_SUB,
      title: "No Rental Price Video",
      availablePurchaseTypes: ["rental"],
    });
    await deleteRental(page, BOB_SUB, RENTAL_VID);
    await ctx.close();
  });

  test("start rental returns 200 with expected fields", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    await deleteRental(page, BOB_SUB, RENTAL_VID);

    const resp = await apiPost(page, BOB_KEY, `/ui/vod/rental/${RENTAL_VID}/start`, {
      tier: "rental",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.tier).toBe("rental");
    expect(data.rental_id).toMatch(/^vrent_/);
    expect(data.video_id).toBe(RENTAL_VID);
    expect(data.amount_cents).toBe(299);
    await ctx.close();
  });

  test("invalid tier returns 422", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    const resp = await apiPost(page, BOB_KEY, `/ui/vod/rental/${RENTAL_VID}/start`, {
      tier: "forever",
    });
    expect(resp.status()).toBe(422);
    await ctx.close();
  });

  test("tier without configured price returns 400", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    await deleteRental(page, BOB_SUB, NOPRICE_VID);
    const resp = await apiPost(page, BOB_KEY, `/ui/vod/rental/${NOPRICE_VID}/start`, {
      tier: "rental",
    });
    expect(resp.status()).toBe(400);
    await ctx.close();
  });

  test("start rental requires auth (401 without session)", async ({ request }) => {
    const resp = await request.post(BASE + `/ui/vod/rental/${RENTAL_VID}/start`, {
      headers: { "Content-Type": "application/json" },
      data: { tier: "rental" },
    });
    expect(resp.status()).toBe(401);
  });
});

// ── Section 2: time-window + view-once consumption ───────────────────────

test.describe("vod-rental 2 - window + consumption", () => {
  const WINDOW_VID = vid("window");
  const VO_VID = vid("viewonce");

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);
    await seedVideo(page, {
      videoId: WINDOW_VID,
      ownerId: ALICE_SUB,
      title: "Window Video",
      availablePurchaseTypes: ["rental"],
      rentalPriceCents: 299,
      rentalDurationHours: 48,
    });
    await seedVideo(page, {
      videoId: VO_VID,
      ownerId: ALICE_SUB,
      title: "View Once Video",
      availablePurchaseTypes: ["view_once"],
      viewOncePriceCents: 199,
    });
    await ctx.close();
  });

  test("rental: active within window, expired after window", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    await deleteRental(page, BOB_SUB, WINDOW_VID);

    // Start the rental (window not yet started).
    const start = await apiPost(page, BOB_KEY, `/ui/vod/rental/${WINDOW_VID}/start`, {
      tier: "rental",
    });
    expect(start.status()).toBe(200);

    // First playback starts the 48h clock at NOW.
    const play = await apiPost(
      page,
      BOB_KEY,
      `/ui/vod/rental/${WINDOW_VID}/playback?now=${NOW}`,
    );
    expect(play.status()).toBe(200);
    const playData = await play.json();
    expect(playData.playback_url).toBeTruthy();
    expect(playData.access.active).toBe(true);
    expect(playData.access.expires_at).toBe(NOW + 48 * 3600);

    // Within window (1h later): still active.
    const within = await apiGet(
      page,
      BOB_KEY,
      `/ui/vod/rental/${WINDOW_VID}/access?now=${NOW + 3600}`,
    );
    const withinData = await within.json();
    expect(withinData.active).toBe(true);
    expect(withinData.remaining_seconds).toBeGreaterThan(0);

    // After window (49h later): expired.
    const after = await apiGet(
      page,
      BOB_KEY,
      `/ui/vod/rental/${WINDOW_VID}/access?now=${NOW + 49 * 3600}`,
    );
    const afterData = await after.json();
    expect(afterData.active).toBe(false);
    expect(afterData.reason).toBe("expired");
    await ctx.close();
  });

  test("rental: playback blocked (403) after expiry", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    // Reuses the started rental from prior test; play far in the future.
    const resp = await apiPost(
      page,
      BOB_KEY,
      `/ui/vod/rental/${WINDOW_VID}/playback?now=${NOW + 100 * 3600}`,
    );
    expect(resp.status()).toBe(403);
    await ctx.close();
  });

  test("view-once: consumed after playback-complete, then blocked", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    await deleteRental(page, BOB_SUB, VO_VID);

    await apiPost(page, BOB_KEY, `/ui/vod/rental/${VO_VID}/start`, {
      tier: "view_once",
    });

    // Before watching: 1 view remaining + entitled.
    const before = await apiGet(page, BOB_KEY, `/ui/vod/rental/${VO_VID}/access`);
    const beforeData = await before.json();
    expect(beforeData.active).toBe(true);
    expect(beforeData.views_remaining).toBe(1);

    // Playback URL issued.
    const play = await apiPost(page, BOB_KEY, `/ui/vod/rental/${VO_VID}/playback`);
    expect(play.status()).toBe(200);

    // Consume the view.
    const complete = await apiPost(
      page,
      BOB_KEY,
      `/ui/vod/rental/${VO_VID}/playback-complete`,
    );
    expect(complete.status()).toBe(200);
    expect((await complete.json()).consumed).toBe(true);

    // After consumption: not entitled.
    const after = await apiGet(page, BOB_KEY, `/ui/vod/rental/${VO_VID}/access`);
    const afterData = await after.json();
    expect(afterData.active).toBe(false);
    expect(afterData.reason).toBe("consumed");

    // Playback now blocked.
    const blocked = await apiPost(page, BOB_KEY, `/ui/vod/rental/${VO_VID}/playback`);
    expect(blocked.status()).toBe(403);
    await ctx.close();
  });

  test("view-once: playback-complete is idempotent", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    // VO_VID already consumed in prior test — second complete is a no-op.
    const resp = await apiPost(
      page,
      BOB_KEY,
      `/ui/vod/rental/${VO_VID}/playback-complete`,
    );
    expect(resp.status()).toBe(200);
    expect((await resp.json()).views_remaining).toBe(0);
    await ctx.close();
  });

  test("view-once: consumed viewer can re-rent", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    // VO_VID consumed; starting again overwrites with a fresh view.
    const resp = await apiPost(page, BOB_KEY, `/ui/vod/rental/${VO_VID}/start`, {
      tier: "view_once",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.already_active).toBe(false);
    expect(data.views_remaining).toBe(1);
    await ctx.close();
  });
});

// ── Section 3: status / history + UI ─────────────────────────────────────

test.describe("vod-rental 3 - status, history, UI", () => {
  const STATUS_VID = vid("status");

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, ALICE_KEY);
    await seedVideo(page, {
      videoId: STATUS_VID,
      ownerId: ALICE_SUB,
      title: "Status Video",
      availablePurchaseTypes: ["rental"],
      rentalPriceCents: 299,
      rentalDurationHours: 24,
    });
    await ctx.close();
  });

  test("status endpoint reflects active rental", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    await deleteRental(page, BOB_SUB, STATUS_VID);
    await apiPost(page, BOB_KEY, `/ui/vod/rental/${STATUS_VID}/start`, {
      tier: "rental",
    });
    const resp = await apiGet(page, BOB_KEY, `/ui/vod/rental/${STATUS_VID}/status`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_id).toBe(STATUS_VID);
    expect(data.tier).toBe("rental");
    expect(data.active).toBe(true);
    await ctx.close();
  });

  test("list endpoint includes the rental", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    const resp = await apiGet(page, BOB_KEY, `/ui/vod/rental/list`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.items)).toBe(true);
    const found = data.items.find((i: any) => i.video_id === STATUS_VID);
    expect(found).toBeTruthy();
    await ctx.close();
  });

  test("My Rentals page renders", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await injectAuth(page, BOB_KEY);
    await page.goto(BASE + "/vod/rentals", { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("vod-rentals-page")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("heading", { name: "My Rentals" })).toBeVisible();
    await ctx.close();
  });
});
