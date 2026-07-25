/**
 * E2E tests for Content-Provider Ad Controls (ADS-010).
 *
 * Extends the ADS-003 creator ad preferences with:
 *   - per-content ad-control overrides (precedence over global/video settings)
 *   - revenue-share management (basis points)
 *   - ad-revenue transparency / breakdown layer
 *
 * Sections:
 *   600 — Per-content override CRUD API
 *   601 — Override reflected in /ui/videos/{id}/ad-config
 *   602 — Revenue share API
 *   603 — Ad-revenue breakdown + transparency API
 *   604 — Ownership / authorization boundary
 *   605 — Content Ad Controls UI
 *
 * Auth: cookie-based sessions from e2e_admin_session_setup.py.
 * Test users: Alice (creator/content owner), Bob (other creator).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, resolveIdentityId } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const DDB_URL = "http://localhost:8001/";
const DDB_HEADERS = {
  "Content-Type": "application/x-amz-json-1.0",
  Authorization:
    "AWS4-HMAC-SHA256 Credential=test/20200101/us-east-1/dynamodb/aws4_request",
};

const ALICE_KEY = "alice";
const BOB_KEY = "bob";
const ALICE_ID = resolveIdentityId("e2e_alice@test.local");
const BOB_ID = resolveIdentityId("e2e_bob@test.local");
const TS = Date.now();

function vid(suffix: string): string {
  return `cadc_${TS.toString(16).slice(0, 8)}_${suffix}`;
}

const ALICE_VID = vid("a1");
const ALICE_VID2 = vid("a2");
const BOB_VID = vid("b1");

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

async function injectAuth(page: Page, sessionKey: string) {
  const session = getSessions()[sessionKey];
  if (!session) throw new Error(`No session for ${sessionKey}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
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

// ─── API helpers (cookie session + CSRF) ──────────────────────────────────────

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiPut(page: Page, sessionKey: string, path: string, body: object) {
  const session = getSessions()[sessionKey];
  return page.request.put(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiDelete(page: Page, sessionKey: string, path: string) {
  const session = getSessions()[sessionKey];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── DDB helpers (seed videos directly) ────────────────────────────────────────

async function ddbRequest(page: Page, target: string, data: object) {
  return page.request.post(DDB_URL, {
    headers: { ...DDB_HEADERS, "X-Amz-Target": `DynamoDB_20120810.${target}` },
    data,
  });
}

async function seedVideo(
  page: Page,
  opts: { videoId: string; ownerId: string; title: string },
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
    access_mode: { S: "ad_supported" },
    price_cents: { N: "0" },
    duration_seconds: { N: "900" },
  };
  await ddbRequest(page, "PutItem", { TableName: "VideoMetadata", Item: item });
}

async function seedTransparency(
  page: Page,
  creatorSub: string,
  accountId: string,
  month: string,
  company: string,
  impressions: number,
  clicks: number,
  revenueCents: number,
) {
  await ddbRequest(page, "PutItem", {
    TableName: "billing",
    Item: {
      pk: { S: `USER#${creatorSub}` },
      sk: { S: `AD_TRANSPARENCY#${accountId}#${month}` },
      account_id: { S: accountId },
      company_name: { S: company },
      month: { S: month },
      impression_count: { N: String(impressions) },
      click_count: { N: String(clicks) },
      revenue_cents: { N: String(revenueCents) },
      updated_at: { N: String(Math.floor(Date.now() / 1000)) },
    },
  });
}

async function seedAdRevenueLedger(
  page: Page,
  creatorSub: string,
  videoId: string,
  amountCents: number,
  ts: number,
) {
  await ddbRequest(page, "PutItem", {
    TableName: "billing",
    Item: {
      pk: { S: `USER#${creatorSub}` },
      sk: { S: `LEDGER#${ts}#${videoId}_${Math.random().toString(36).slice(2, 8)}` },
      ts: { N: String(ts) },
      type: { S: "ad_revenue_credit" },
      amount_cents: { N: String(amountCents) },
      state: { S: "settled" },
      reason: { S: "Ad revenue" },
      meta: { M: { video_id: { S: videoId } } },
    },
  });
}

// ─── Shared state ─────────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;

test.beforeAll(async ({ browser }) => {
  alicePage = await newIdentityPage(browser, ALICE_KEY);
  bobPage = await newIdentityPage(browser, BOB_KEY);

  await seedVideo(alicePage, { videoId: ALICE_VID, ownerId: ALICE_ID, title: "Alice Vid 1" });
  await seedVideo(alicePage, { videoId: ALICE_VID2, ownerId: ALICE_ID, title: "Alice Vid 2" });
  await seedVideo(bobPage, { videoId: BOB_VID, ownerId: BOB_ID, title: "Bob Vid" });

  const now = Math.floor(Date.now() / 1000);
  // Ad-revenue ledger for Alice's content (recent).
  await seedAdRevenueLedger(alicePage, ALICE_ID, ALICE_VID, 8500, now - 3600);
  await seedAdRevenueLedger(alicePage, ALICE_ID, ALICE_VID2, 4200, now - 7200);

  // Transparency across two months.
  await seedTransparency(alicePage, ALICE_ID, "adv_acme", "2026-05", "Acme Corp", 5200, 120, 8500);
  await seedTransparency(alicePage, ALICE_ID, "adv_widget", "2026-04", "Widget Inc", 3100, 75, 4200);
});

test.afterAll(async () => {
  await alicePage?.close();
  await bobPage?.close();
});

const PREFIX = "/ui/ads/content-controls";

// ─── Section 600: Per-content override CRUD API ─────────────────────────────────

test.describe("600 — Per-content override CRUD API", () => {
  test("600.1 Upsert override for owned content", async () => {
    const resp = await apiPut(alicePage, ALICE_KEY, `${PREFIX}/overrides/${ALICE_VID}`, {
      content_type: "video",
      ad_enabled: true,
      ad_density: "low",
      pre_roll_enabled: false,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.content_id).toBe(ALICE_VID);
    expect(body.ad_density).toBe("low");
    expect(body.pre_roll_enabled).toBe(false);
  });

  test("600.2 Get override", async () => {
    const resp = await apiGet(alicePage, `${PREFIX}/overrides/${ALICE_VID}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.content_id).toBe(ALICE_VID);
    expect(body.owner_sub).toBe(ALICE_ID);
  });

  test("600.3 List overrides (owner-scoped)", async () => {
    const resp = await apiGet(alicePage, `${PREFIX}/overrides`);
    expect(resp.status()).toBe(200);
    const arr = await resp.json();
    expect(Array.isArray(arr)).toBe(true);
    expect(arr.some((o: any) => o.content_id === ALICE_VID)).toBe(true);
  });

  test("600.4 Partial update preserves other fields", async () => {
    const resp = await apiPut(alicePage, ALICE_KEY, `${PREFIX}/overrides/${ALICE_VID}`, {
      mid_roll_enabled: false,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.mid_roll_enabled).toBe(false);
    // density from 600.1 preserved
    expect(body.ad_density).toBe("low");
  });

  test("600.5 Invalid density rejected", async () => {
    const resp = await apiPut(alicePage, ALICE_KEY, `${PREFIX}/overrides/${ALICE_VID}`, {
      ad_density: "insane",
    });
    expect(resp.status()).toBe(422);
  });

  test("600.6 Delete override", async () => {
    const resp = await apiDelete(alicePage, ALICE_KEY, `${PREFIX}/overrides/${ALICE_VID2}`);
    expect(resp.status()).toBe(200);
  });

  test("600.7 Get missing override → 404", async () => {
    const resp = await apiGet(alicePage, `${PREFIX}/overrides/cadc_does_not_exist`);
    expect(resp.status()).toBe(404);
  });
});

// ─── Section 601: Override reflected in ad-config ──────────────────────────────

test.describe("601 — Override reflected in ad-config", () => {
  test("601.1 Disabling ads via override → ad-config has no slots", async () => {
    const up = await apiPut(alicePage, ALICE_KEY, `${PREFIX}/overrides/${ALICE_VID}`, {
      ad_enabled: false,
    });
    expect(up.status()).toBe(200);

    const cfg = await apiGet(alicePage, `/ui/videos/${ALICE_VID}/ad-config`);
    expect(cfg.status()).toBe(200);
    const body = await cfg.json();
    expect(body.ads_enabled).toBe(false);
    expect(body.slots.length).toBe(0);
  });

  test("601.2 Re-enabling ads restores slots", async () => {
    const up = await apiPut(alicePage, ALICE_KEY, `${PREFIX}/overrides/${ALICE_VID}`, {
      ad_enabled: true,
      pre_roll_enabled: true,
      mid_roll_enabled: true,
      ad_density: "standard",
    });
    expect(up.status()).toBe(200);

    const cfg = await apiGet(alicePage, `/ui/videos/${ALICE_VID}/ad-config`);
    expect(cfg.status()).toBe(200);
    const body = await cfg.json();
    expect(body.ads_enabled).toBe(true);
    expect(body.slots.length).toBeGreaterThan(0);
  });

  test("601.3 Disabling pre-roll drops pre_roll slots", async () => {
    const up = await apiPut(alicePage, ALICE_KEY, `${PREFIX}/overrides/${ALICE_VID}`, {
      ad_enabled: true,
      pre_roll_enabled: false,
      mid_roll_enabled: true,
    });
    expect(up.status()).toBe(200);

    const cfg = await apiGet(alicePage, `/ui/videos/${ALICE_VID}/ad-config`);
    const body = await cfg.json();
    expect(body.slots.some((s: any) => s.type === "pre_roll")).toBe(false);
  });
});

// ─── Section 602: Revenue share API ────────────────────────────────────────────

test.describe("602 — Revenue share API", () => {
  test("602.1 Default revenue share is 7000 bps", async () => {
    const resp = await apiGet(bobPage, `${PREFIX}/revenue-share`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.revenue_share_bps).toBe(7000);
  });

  test("602.2 Set revenue share to 6500 bps", async () => {
    // GAP-0054: a creator may take at most 7000 bps (70%) via self-service;
    // RevenueShareIn validates revenue_share_bps with Field(ge=0, le=7000), so
    // 6500 is a valid below-cap value that proves the set + persistence works.
    const resp = await apiPut(alicePage, ALICE_KEY, `${PREFIX}/revenue-share`, {
      revenue_share_bps: 6500,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.revenue_share_bps).toBe(6500);

    const get = await apiGet(alicePage, `${PREFIX}/revenue-share`);
    expect((await get.json()).revenue_share_bps).toBe(6500);
  });

  test("602.3 Out-of-range bps rejected", async () => {
    // 8000 (> 7000 cap) and 20000 are both rejected by the Field(le=7000)
    // validator (GAP-0054).
    const over = await apiPut(alicePage, ALICE_KEY, `${PREFIX}/revenue-share`, {
      revenue_share_bps: 8000,
    });
    expect(over.status()).toBe(422);

    const resp = await apiPut(alicePage, ALICE_KEY, `${PREFIX}/revenue-share`, {
      revenue_share_bps: 20000,
    });
    expect(resp.status()).toBe(422);
  });
});

// ─── Section 603: Ad-revenue breakdown + transparency API ───────────────────────

test.describe("603 — Ad-revenue breakdown + transparency API", () => {
  test("603.1 Revenue breakdown returns total + per-content", async () => {
    const resp = await apiGet(alicePage, `${PREFIX}/revenue-breakdown?days=30`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.total_ad_revenue_cents).toBeGreaterThanOrEqual(12700);
    expect(Array.isArray(body.top_content)).toBe(true);
    const ids = body.top_content.map((c: any) => c.content_id);
    expect(ids).toContain(ALICE_VID);
    expect(ids).toContain(ALICE_VID2);
  });

  test("603.2 Breakdown includes revenue_share_bps", async () => {
    const resp = await apiGet(alicePage, `${PREFIX}/revenue-breakdown?days=30`);
    const body = await resp.json();
    // Reflects the value set in 602.2 (capped at 7000 bps per GAP-0054).
    expect(body.revenue_share_bps).toBe(6500);
  });

  test("603.3 Invalid days rejected", async () => {
    const resp = await apiGet(alicePage, `${PREFIX}/revenue-breakdown?days=0`);
    expect(resp.status()).toBe(422);
  });

  test("603.4 Transparency lists advertisers", async () => {
    const resp = await apiGet(alicePage, `${PREFIX}/transparency`);
    expect(resp.status()).toBe(200);
    const arr = await resp.json();
    expect(Array.isArray(arr)).toBe(true);
    expect(arr.some((a: any) => a.account_id === "adv_acme")).toBe(true);
  });

  test("603.5 Transparency filters by month", async () => {
    const resp = await apiGet(alicePage, `${PREFIX}/transparency?month=2026-05`);
    expect(resp.status()).toBe(200);
    const arr = await resp.json();
    expect(arr.some((a: any) => a.account_id === "adv_acme")).toBe(true);
    expect(arr.some((a: any) => a.account_id === "adv_widget")).toBe(false);
  });

  test("603.6 Invalid month format rejected", async () => {
    const resp = await apiGet(alicePage, `${PREFIX}/transparency?month=2026`);
    expect(resp.status()).toBe(400);
  });
});

// ─── Section 604: Ownership / authorization boundary ────────────────────────────

test.describe("604 — Ownership boundary", () => {
  test("604.1 Cannot set override on another creator's video", async () => {
    const resp = await apiPut(alicePage, ALICE_KEY, `${PREFIX}/overrides/${BOB_VID}`, {
      ad_enabled: false,
    });
    expect(resp.status()).toBe(403);
  });

  test("604.2 Override on missing video → 404", async () => {
    const resp = await apiPut(alicePage, ALICE_KEY, `${PREFIX}/overrides/cadc_missing_vid`, {
      ad_enabled: false,
    });
    expect(resp.status()).toBe(404);
  });

  test("604.3 Transparency is creator-scoped", async () => {
    // Bob has no seeded transparency → empty array.
    const resp = await apiGet(bobPage, `${PREFIX}/transparency`);
    expect(resp.status()).toBe(200);
    const arr = await resp.json();
    expect(arr.some((a: any) => a.account_id === "adv_acme")).toBe(false);
  });

  test("604.4 Breakdown with no data returns zeros", async () => {
    const resp = await apiGet(bobPage, `${PREFIX}/revenue-breakdown?days=30`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.total_ad_revenue_cents).toBe(0);
    expect(body.top_content).toEqual([]);
  });
});

// ─── Section 605: Content Ad Controls UI ────────────────────────────────────────

test.describe("605 — Content Ad Controls UI", () => {
  test("605.1 Page loads", async () => {
    await alicePage.goto(`${BASE}/ads/content-controls`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByTestId("content-ad-controls")).toBeVisible({ timeout: 15_000 });
    await expect(
      alicePage.getByRole("heading", { name: "Content Ad Controls" }),
    ).toBeVisible();
  });

  test("605.2 Revenue breakdown card renders", async () => {
    await alicePage.goto(`${BASE}/ads/content-controls`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByTestId("ad-revenue-breakdown")).toBeVisible({ timeout: 15_000 });
  });

  test("605.3 Revenue share input present", async () => {
    await alicePage.goto(`${BASE}/ads/content-controls`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByTestId("revenue-share-input")).toBeVisible({ timeout: 15_000 });
  });
});
