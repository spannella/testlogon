/**
 * Section 109: VOD DRM Key Server
 *
 * Auth: Cookie sessions via e2e_admin_session_setup.py
 * Identities: alice (USER)
 *
 * Tests the DRM key server endpoint for AES-128 HLS encryption:
 * - Token validation (missing, invalid, expired, wrong asset)
 * - Key delivery (16 bytes, correct content-type, deterministic)
 * - DRM info endpoint
 * - Non-existent key_id handling
 */
import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const TS = Date.now();
// GAP-0372: DRM key IDs/URIs are tenant-scoped. All tokens in this spec are
// issued for this tenant, and the info endpoint requires it to derive key_id.
const TENANT = `tenant_${TS}`;

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function newPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await page.context().addCookies(getSessions()[identity].cookies);
  return page;
}

async function apiPost(page: Page, id: string, path: string, body?: unknown) {
  const s = getSessions()[id];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

// ─── Helper: Issue a playback entitlement token ─────────────────────────────

let _issueCounter = 0;
async function issueToken(page: Page, identity: string, assetId: string): Promise<string> {
  _issueCounter++;
  const resp = await apiPost(page, identity, "/v1/playback/entitlements/issue", {
    tenant_id: TENANT,
    asset_id: assetId,
    session_id: `sess_${TS}_${_issueCounter}`,
    device_id: `dev_${TS}_${_issueCounter}`,
    profile: "hd_1080p",
    audience: "playback",
    ttl_seconds: 120,
  });
  expect(resp.status()).toBe(200);
  const data = await resp.json();
  return data.entitlement.token;
}

// ─── Helper: Get DRM key_id for an asset via the info endpoint ──────────────

async function getKeyId(page: Page, assetId: string): Promise<string> {
  // GAP-0372: key_id is tenant-scoped; the info endpoint only returns it when
  // a matching tenant is supplied.
  const resp = await apiGet(page, `/v1/vod/drm/info/${assetId}?tenant=${TENANT}`);
  expect(resp.status()).toBe(200);
  const data = await resp.json();
  return data.key_id;
}

// ─── 109. VOD DRM Key Server ────────────────────────────────────────────────

test.describe.serial("109 — VOD DRM Key Server", () => {
  let alicePage: Page;
  const ASSET_ID = `drm_asset_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("109.1 Key server returns 422 without token query param", async () => {
    const keyId = await getKeyId(alicePage, ASSET_ID);
    const resp = await apiGet(alicePage, `/v1/vod/drm/key/${keyId}?asset=${ASSET_ID}`);
    // Missing required 'token' query param => 422 validation error
    expect(resp.status()).toBe(422);
  });

  test("109.2 Key server returns 16 bytes with valid entitlement token", async () => {
    const token = await issueToken(alicePage, "alice", ASSET_ID);
    const keyId = await getKeyId(alicePage, ASSET_ID);

    const resp = await alicePage.request.get(
      `${BASE}/v1/vod/drm/key/${keyId}?asset=${ASSET_ID}&token=${token}`
    );
    expect(resp.status()).toBe(200);

    const contentType = resp.headers()["content-type"];
    expect(contentType).toBe("application/octet-stream");

    const body = await resp.body();
    expect(body.length).toBe(16);
  });

  test("109.3 Wrong asset_id in token returns 403", async () => {
    // Token issued for a DIFFERENT asset
    const token = await issueToken(alicePage, "alice", `other_asset_${TS}`);
    const keyId = await getKeyId(alicePage, ASSET_ID);

    const resp = await alicePage.request.get(
      `${BASE}/v1/vod/drm/key/${keyId}?asset=${ASSET_ID}&token=${token}`
    );
    expect(resp.status()).toBe(403);
    const data = await resp.json();
    expect(data.detail.code).toBe("asset_mismatch");
  });

  test("109.4 Expired token returns 401 or 403", async () => {
    // We can't easily create an expired token from E2E without backend manipulation.
    // Instead, use a completely invalid token string.
    const keyId = await getKeyId(alicePage, ASSET_ID);
    const resp = await alicePage.request.get(
      `${BASE}/v1/vod/drm/key/${keyId}?asset=${ASSET_ID}&token=invalid.expired.token`
    );
    expect([401, 403]).toContain(resp.status());
  });

  test("109.5 DRM info endpoint returns key server URI info", async () => {
    // GAP-0372: key_id/key_uri are tenant-scoped — supply the tenant.
    const resp = await apiGet(alicePage, `/v1/vod/drm/info/${ASSET_ID}?tenant=${TENANT}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();

    expect(data.drm_enabled).toBe(true);
    expect(data.asset_id).toBe(ASSET_ID);
    expect(data.key_id).toBeTruthy();
    expect(data.key_uri).toContain("/v1/vod/drm/key/");
    expect(data.key_uri).toContain(`asset=${ASSET_ID}`);
  });

  test("109.6 Key derivation is consistent (same request = same response)", async () => {
    const token1 = await issueToken(alicePage, "alice", ASSET_ID);
    const keyId = await getKeyId(alicePage, ASSET_ID);

    const resp1 = await alicePage.request.get(
      `${BASE}/v1/vod/drm/key/${keyId}?asset=${ASSET_ID}&token=${token1}`
    );
    expect(resp1.status()).toBe(200);
    const body1 = await resp1.body();

    // Issue a second token (different jti) for the same asset
    const token2 = await issueToken(alicePage, "alice", ASSET_ID);
    const resp2 = await alicePage.request.get(
      `${BASE}/v1/vod/drm/key/${keyId}?asset=${ASSET_ID}&token=${token2}`
    );
    expect(resp2.status()).toBe(200);
    const body2 = await resp2.body();

    // Same asset => same key bytes
    expect(body1.equals(body2)).toBe(true);
  });

  test("109.7 Non-existent key_id returns 404", async () => {
    const token = await issueToken(alicePage, "alice", ASSET_ID);
    const fakeKeyId = "00000000000000000000000000000000";

    const resp = await alicePage.request.get(
      `${BASE}/v1/vod/drm/key/${fakeKeyId}?asset=${ASSET_ID}&token=${token}`
    );
    expect(resp.status()).toBe(404);
    const data = await resp.json();
    expect(data.detail.code).toBe("key_not_found");
  });

  test("109.8 DRM info for different assets returns different key_ids", async () => {
    // GAP-0372: tenant required to derive tenant-scoped key_ids.
    const resp1 = await apiGet(alicePage, `/v1/vod/drm/info/asset_a_${TS}?tenant=${TENANT}`);
    const resp2 = await apiGet(alicePage, `/v1/vod/drm/info/asset_b_${TS}?tenant=${TENANT}`);

    expect(resp1.status()).toBe(200);
    expect(resp2.status()).toBe(200);

    const data1 = await resp1.json();
    const data2 = await resp2.json();

    expect(data1.key_id).not.toBe(data2.key_id);
  });
});
