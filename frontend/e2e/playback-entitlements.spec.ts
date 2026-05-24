/**
 * Section 104: Playback Entitlements — issue, revoke, validate (protected ping)
 *
 * Auth: Cookie sessions via e2e_admin_session_setup.py
 * Identities: alice (USER)
 *
 * Requires PLAYBACK_ENTITLEMENT_SECRET to be set in .env.local
 */
import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const TS = Date.now();

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
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
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

async function apiGetBearer(page: Page, path: string, token: string) {
  return page.request.get(`${BASE}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

// ─── 104. Playback Entitlements ──────────────────────────────────────────

test.describe.serial("104 — Playback Entitlements: issue, revoke, validate", () => {
  let alicePage: Page;
  let issuedToken: string;
  let issuedJti: string;
  let issuedExpiry: number;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("104.1 Issue playback entitlement token", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/playback/entitlements/issue", {
      tenant_id: `tenant_${TS}`,
      asset_id: `asset_${TS}`,
      session_id: `sess_${TS}`,
      device_id: `dev_${TS}`,
      profile: "hd_1080p",
      audience: "playback",
      ttl_seconds: 120,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.entitlement).toBeTruthy();
    expect(data.entitlement.token).toBeTruthy();
    expect(data.entitlement.expires_at_epoch).toBeGreaterThan(0);
    expect(data.entitlement.audience).toBe("playback");
    expect(data.entitlement.ttl_seconds).toBe(120);
    expect(data.entitlement.jti).toBeTruthy();
    expect(data.issued_for).toBeTruthy();
    issuedToken = data.entitlement.token;
    issuedJti = data.entitlement.jti;
    issuedExpiry = data.entitlement.expires_at_epoch;
  });

  test("104.2 Validate issued token via protected ping", async () => {
    const resp = await apiGetBearer(alicePage, "/v1/playback/protected/ping", issuedToken);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.claims).toBeTruthy();
    expect(data.claims.tenant_id).toBe(`tenant_${TS}`);
    expect(data.claims.asset_id).toBe(`asset_${TS}`);
    expect(data.claims.profile).toBe("hd_1080p");
    expect(data.claims.aud).toBe("playback");
  });

  test("104.3 Invalid bearer token returns 401", async () => {
    const resp = await apiGetBearer(alicePage, "/v1/playback/protected/ping", "invalid.token.here");
    expect(resp.status()).toBe(401);
  });

  test("104.4 Missing bearer token returns 401", async () => {
    const resp = await alicePage.request.get(`${BASE}/v1/playback/protected/ping`);
    expect(resp.status()).toBe(401);
  });

  test("104.5 Revoke entitlement by JTI", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/playback/entitlements/revoke", {
      jti: issuedJti,
      expires_at_epoch: issuedExpiry,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.revoked.jti).toBe(issuedJti);
    expect(data.revoked_by).toBeTruthy();
  });

  test("104.6 Revoked token fails validation", async () => {
    const resp = await apiGetBearer(alicePage, "/v1/playback/protected/ping", issuedToken);
    expect(resp.status()).toBe(401);
    const data = await resp.json();
    expect(data.detail.code).toBe("token_revoked");
  });

  test("104.7 Revoke by session_id requires tenant_id", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/playback/entitlements/revoke", {
      session_id: `sess_${TS}`,
      expires_at_epoch: Math.floor(Date.now() / 1000) + 300,
    });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail.code).toBe("invalid_revocation_request");
  });

  test("104.8 Revoke without jti or session_id returns 400", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/playback/entitlements/revoke", {
      expires_at_epoch: Math.floor(Date.now() / 1000) + 300,
    });
    expect(resp.status()).toBe(400);
  });

  test("104.9 Revoke by session_id + tenant_id succeeds", async () => {
    // Issue a new token first
    const issueResp = await apiPost(alicePage, "alice", "/v1/playback/entitlements/issue", {
      tenant_id: `tenant_rev_${TS}`,
      asset_id: `asset_rev_${TS}`,
      session_id: `sess_rev_${TS}`,
      device_id: `dev_rev_${TS}`,
      profile: "sd_480p",
      audience: "playback",
      ttl_seconds: 60,
    });
    const issueData = await issueResp.json();
    const newToken = issueData.entitlement.token;
    const newExpiry = issueData.entitlement.expires_at_epoch;

    // Revoke by session
    const revokeResp = await apiPost(alicePage, "alice", "/v1/playback/entitlements/revoke", {
      session_id: `sess_rev_${TS}`,
      tenant_id: `tenant_rev_${TS}`,
      expires_at_epoch: newExpiry,
    });
    expect(revokeResp.status()).toBe(200);
    const revokeData = await revokeResp.json();
    expect(revokeData.ok).toBe(true);
    expect(revokeData.revoked.session_id).toBe(`sess_rev_${TS}`);

    // Validate fails
    const pingResp = await apiGetBearer(alicePage, "/v1/playback/protected/ping", newToken);
    expect(pingResp.status()).toBe(401);
    const pingData = await pingResp.json();
    expect(pingData.detail.code).toBe("session_revoked");
  });

  test("104.10 Issue with empty tenant_id returns 422", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/playback/entitlements/issue", {
      tenant_id: "",
      asset_id: "a",
      session_id: "s",
      device_id: "d",
      profile: "p",
      ttl_seconds: 60,
    });
    expect(resp.status()).toBe(422);
  });
});
