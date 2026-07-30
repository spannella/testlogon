/**
 * E2E tests for GEO-001: Geo-Blocking & Content Restrictions.
 *
 * Sections:
 *   201 — Geo-Restriction CRUD API    (5 tests)
 *   202 — Geo-Access Enforcement API  (5 tests)
 *   203 — My Country & Utilities API  (2 tests)
 *   204 — Geo Rules Settings UI       (3 tests)
 *
 * Auth: Alice + Bob session cookies (from e2e_session_setup.py).
 *
 * These tests create a video record directly in DynamoDB, then exercise
 * the geo-restriction CRUD and enforcement endpoints. The X-Geo-Country
 * header override is used in dev mode to simulate different geolocations.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions, resolveIdentityId } from "./helpers/session";
import { usingCpp, cppSeedVideo } from "./helpers/cpp-seed";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();
const PYTHON = REPO_ROOT + "/.venv/bin/python3";

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

async function injectAuth(page: Page, identity: string) {
  const sessions = getSessions();
  const s = sessions[identity];
  if (!s) throw new Error(`No session for identity: ${identity}`);
  await page.context().addCookies(s.cookies);
}

function csrfHeader(identity: string): Record<string, string> {
  const sessions = getSessions();
  return { "x-csrf-token": sessions[identity].csrf_token };
}

// ─── DDB Helpers (via Python boto3) ───────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os
ddb = boto3.resource(
    'dynamodb',
    endpoint_url='http://localhost:8001',
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
`;

function ddbPutVideo(videoId: string, ownerId: string, title: string): void {
  if (usingCpp()) {
    // cpp reads tlc_video_metadata keyed by owner SUB, not the Python
    // VideoMetadata table keyed by email. Seed the sub-shaped row so the
    // owner-gate (201.5) and enforcement (202.x) see Alice/Bob as owner.
    cppSeedVideo({
      videoId,
      ownerSub: resolveIdentityId(ownerId),
      title,
      status: "published",
      visibility: "public",
      durationSeconds: 120,
    });
    return;
  }
  const script = `${DDB_PRELUDE}
import time
tbl = ddb.Table('VideoMetadata')
tbl.put_item(Item={
    'video_id': '${videoId}',
    'owner_user_id': '${ownerId}',
    'title': '${title}',
    'description': 'Geo test video',
    'status': 'published',
    'visibility': 'public',
    'duration_seconds': 120,
    'created_at': int(time.time()),
    'updated_at': int(time.time()),
})
print('OK')
`;
  execSync(`${PYTHON} -c "${script}"`, { timeout: 10_000 });
}

function ddbDeleteVideo(videoId: string): void {
  if (usingCpp()) return; // unique per-run TS ids; no cpp delete shim needed
  const script = `${DDB_PRELUDE}
tbl = ddb.Table('VideoMetadata')
tbl.delete_item(Key={'video_id': '${videoId}'})
print('OK')
`;
  try {
    execSync(`${PYTHON} -c "${script}"`, { timeout: 10_000 });
  } catch {
    /* best-effort */
  }
}

// ─── API Helpers ──────────────────────────────────────────────────────────────

async function apiGet(
  page: Page,
  identity: string,
  path: string,
  extraHeaders?: Record<string, string>,
) {
  return page.request.get(`${BASE}${path}`, {
    headers: { ...csrfHeader(identity), ...(extraHeaders ?? {}) },
  });
}

async function apiPatch(
  page: Page,
  identity: string,
  path: string,
  body: any,
  extraHeaders?: Record<string, string>,
) {
  return page.request.patch(`${BASE}${path}`, {
    headers: { ...csrfHeader(identity), ...(extraHeaders ?? {}) },
    data: body,
  });
}

// ─── Test State ──────────────────────────────────────────────────────────────

const VIDEO_ID = `v_e2e_geo_${TS}`;
const VIDEO_ID_BOB = `v_e2e_geo_bob_${TS}`;

let alicePage: Page;
let bobPage: Page;

// ─── Setup ───────────────────────────────────────────────────────────────────

test.beforeAll(async ({ browser }) => {
  getSessions();

  // Seed published videos
  ddbPutVideo(VIDEO_ID, ALICE_ID, `Geo Test Video ${TS}`);
  ddbPutVideo(VIDEO_ID_BOB, BOB_ID, `Bob Geo Test Video ${TS}`);

  // Create pages with auth
  const aliceCtx = await browser.newContext();
  alicePage = await aliceCtx.newPage();
  await injectAuth(alicePage, ALICE_ID);

  const bobCtx = await browser.newContext();
  bobPage = await bobCtx.newPage();
  await injectAuth(bobPage, BOB_ID);
});

test.afterAll(async () => {
  ddbDeleteVideo(VIDEO_ID);
  ddbDeleteVideo(VIDEO_ID_BOB);
  await alicePage?.context().close();
  await bobPage?.context().close();
});

// ─── Section 201: Geo-Restriction CRUD API ───────────────────────────────────

test.describe("201 — Geo-Restriction CRUD API", () => {
  test("201.1 Set allow-mode geo-restriction on video", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/geo/videos/${VIDEO_ID}`,
      { geo_mode: "allow", geo_countries: ["US", "CA"] },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.geo_mode).toBe("allow");
    expect(data.geo_countries).toEqual(["US", "CA"]);

    // Verify via GET
    const getResp = await apiGet(alicePage, ALICE_ID, `/ui/geo/videos/${VIDEO_ID}`);
    expect(getResp.status()).toBe(200);
    const getData = await getResp.json();
    expect(getData.geo_mode).toBe("allow");
    expect(getData.geo_countries).toEqual(["US", "CA"]);
  });

  test("201.2 Set block-mode geo-restriction", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/geo/videos/${VIDEO_ID}`,
      { geo_mode: "block", geo_countries: ["DE", "FR"] },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.geo_mode).toBe("block");
    expect(data.geo_countries).toEqual(["DE", "FR"]);
  });

  test("201.3 Clear geo-restriction", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/geo/videos/${VIDEO_ID}`,
      { geo_mode: null, geo_countries: null },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.geo_mode).toBeNull();
    expect(data.geo_countries).toBeNull();

    // Verify via GET
    const getResp = await apiGet(alicePage, ALICE_ID, `/ui/geo/videos/${VIDEO_ID}`);
    expect(getResp.status()).toBe(200);
    const getData = await getResp.json();
    expect(getData.geo_mode).toBeNull();
  });

  test("201.4 Reject invalid country code", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/geo/videos/${VIDEO_ID}`,
      { geo_mode: "allow", geo_countries: ["XX"] },
    );
    expect(resp.status()).toBe(422);
  });

  test("201.5 Non-owner cannot set geo-restriction", async () => {
    const resp = await apiPatch(
      bobPage,
      BOB_ID,
      `/ui/geo/videos/${VIDEO_ID}`,
      { geo_mode: "allow", geo_countries: ["US"] },
    );
    expect(resp.status()).toBe(403);
  });
});

// ─── Section 202: Geo-Access Enforcement API ─────────────────────────────────

test.describe("202 — Geo-Access Enforcement API", () => {
  test.beforeAll(async () => {
    // Set allow-mode on Alice's video: US only
    await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/geo/videos/${VIDEO_ID}`,
      { geo_mode: "allow", geo_countries: ["US"] },
    );
  });

  test("202.1 Allowed country can access video", async () => {
    // Bob requests with X-Geo-Country: US (dev mode header override)
    const resp = await apiGet(
      bobPage,
      BOB_ID,
      `/ui/videos/${VIDEO_ID}`,
      { "x-geo-country": "US" },
    );
    expect(resp.status()).toBe(200);
  });

  test("202.2 Blocked country gets 403 with geo_blocked code", async () => {
    const resp = await apiGet(
      bobPage,
      BOB_ID,
      `/ui/videos/${VIDEO_ID}`,
      { "x-geo-country": "DE" },
    );
    expect(resp.status()).toBe(403);
    const data = await resp.json();
    expect(data.detail.code).toBe("geo_blocked");
    expect(data.detail.country).toBe("DE");
  });

  test("202.3 Block-mode denies listed country", async () => {
    // Switch to block mode on Bob's video: block DE
    await apiPatch(
      bobPage,
      BOB_ID,
      `/ui/geo/videos/${VIDEO_ID_BOB}`,
      { geo_mode: "block", geo_countries: ["DE"] },
    );

    // Alice requests from DE -> blocked
    const resp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/videos/${VIDEO_ID_BOB}`,
      { "x-geo-country": "DE" },
    );
    expect(resp.status()).toBe(403);
    const data = await resp.json();
    expect(data.detail.code).toBe("geo_blocked");
  });

  test("202.4 Block-mode allows unlisted country", async () => {
    // Alice requests from US (not in block list) -> allowed
    const resp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/videos/${VIDEO_ID_BOB}`,
      { "x-geo-country": "US" },
    );
    expect(resp.status()).toBe(200);
  });

  test("202.5 No geo restriction allows all countries", async () => {
    // Clear restriction on Alice's video
    await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/geo/videos/${VIDEO_ID}`,
      { geo_mode: null, geo_countries: null },
    );

    // Bob requests from DE -> now allowed
    const resp = await apiGet(
      bobPage,
      BOB_ID,
      `/ui/videos/${VIDEO_ID}`,
      { "x-geo-country": "DE" },
    );
    expect(resp.status()).toBe(200);
  });
});

// ─── Section 203: My Country & Utilities API ─────────────────────────────────

test.describe("203 — My Country & Utilities API", () => {
  test("203.1 My country endpoint returns data", async () => {
    const resp = await apiGet(
      alicePage,
      ALICE_ID,
      "/ui/geo/my-country",
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data).toHaveProperty("ip");
    expect(data).toHaveProperty("source");
  });

  test("203.2 Countries list returns 200+ countries", async () => {
    const resp = await apiGet(
      alicePage,
      ALICE_ID,
      "/ui/geo/countries",
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.countries.length).toBeGreaterThan(200);
    // Verify US is in the list
    const us = data.countries.find(
      (c: { code: string }) => c.code === "US",
    );
    expect(us).toBeTruthy();
    expect(us.name).toBe("United States");
  });
});

// ─── Section 204: Geo Rules Settings UI ──────────────────────────────────────

test.describe("204 — Geo Rules Settings UI", () => {
  let uiPage: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    uiPage = await ctx.newPage();
    const session = getSessions()[ALICE_ID];
    await uiPage.context().addCookies(session.cookies);
    // Navigate to login first to set up localStorage auth store
    await uiPage.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await uiPage.evaluate((uid: string) => {
      const state = { userId: uid, accessToken: null, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    }, ALICE_ID);
    // Now navigate to geo rules page
    await uiPage.goto(`${BASE}/settings/geo`, {
      waitUntil: "domcontentloaded",
    });
  });

  test.afterAll(async () => {
    await uiPage?.context().close();
  });

  test("204.1 Geo settings page loads with title", async () => {
    await expect(
      uiPage.getByText("Geo-Blocking Settings"),
    ).toBeVisible({ timeout: 15_000 });
  });

  test("204.2 My country section is visible", async () => {
    await expect(
      uiPage.getByText("Your Detected Location"),
    ).toBeVisible();
  });

  test("204.3 Test Geo Rules section is visible", async () => {
    await expect(
      uiPage.getByText("Test Geo Rules"),
    ).toBeVisible();
  });
});
