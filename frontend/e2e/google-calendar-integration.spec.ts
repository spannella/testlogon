/**
 * E2E tests for Google Calendar integration API endpoints.
 *
 * Sections:
 *   77 — Google Calendar integration API (7 tests)
 *
 * Auth: Alice session cookies (from e2e_session_setup.py).
 *
 * Required .env.local flags:
 *   GOOGLE_CALENDAR_SYNC_ENABLED=true
 *   GOOGLE_CALENDAR_OAUTH_CLIENT_ID=e2e-test-client-id.apps.googleusercontent.com
 *   GOOGLE_CALENDAR_OAUTH_CLIENT_SECRET=e2e-test-secret
 *   GOOGLE_CALENDAR_OAUTH_REDIRECT_URI=http://localhost:3000/calendar/integrations/google/callback
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const GOOGLE_PREFIX = "/ui/calendar/integrations/google";

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
    const raw = execSync("python3 e2e_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function apiGet(page: Page, path: string) {
  const session = getSessions()[ALICE_ID];
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiPost(page: Page, path: string, body?: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": session.csrf_token },
  });
}

test.describe("77 — Google Calendar integration API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("77.1 status endpoint returns integration state", async () => {
    test.setTimeout(60_000);

    const resp = await apiGet(alicePage, `${GOOGLE_PREFIX}/status`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();

    expect(body).toHaveProperty("provider", "google");
    expect(body).toHaveProperty("sync_enabled");
    expect(body).toHaveProperty("writeback_enabled");
    expect(body).toHaveProperty("rollout_mode");
    expect(body).toHaveProperty("rollout_percent");
    expect(body).toHaveProperty("in_rollout_cohort");
    expect(body).toHaveProperty("connection_active");
    expect(body).toHaveProperty("sync_health");
    expect(body).toHaveProperty("last_sync_status");
    expect(body).toHaveProperty("last_sync_at_utc");
    expect(body).toHaveProperty("reauth_required");

    expect(body.connection_active).toBe(false);

    expect(typeof body.sync_enabled).toBe("boolean");
    expect(typeof body.writeback_enabled).toBe("boolean");
    expect(typeof body.rollout_mode).toBe("string");
    expect(typeof body.rollout_percent).toBe("number");
    expect(typeof body.in_rollout_cohort).toBe("boolean");
    expect(typeof body.connection_active).toBe("boolean");
    expect(typeof body.sync_health).toBe("string");
    expect(typeof body.last_sync_status).toBe("string");
    expect(typeof body.reauth_required).toBe("boolean");
  });

  test("77.2 status shows sync_enabled=true with feature flag on", async () => {
    test.setTimeout(60_000);

    const resp = await apiGet(alicePage, `${GOOGLE_PREFIX}/status`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();

    expect(body.sync_enabled).toBe(true);
    expect(body.in_rollout_cohort).toBe(true);
  });

  test("77.3 connect/start returns authorization URL structure", async () => {
    test.setTimeout(60_000);

    const resp = await apiPost(alicePage, `${GOOGLE_PREFIX}/connect/start`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();

    expect(body).toHaveProperty("provider", "google");
    expect(body).toHaveProperty("state");
    expect(body).toHaveProperty("nonce");
    expect(body).toHaveProperty("expires_at_utc");
    expect(body).toHaveProperty("authorization_url");

    expect(typeof body.state).toBe("string");
    expect(body.state.length).toBeGreaterThan(0);
    expect(typeof body.nonce).toBe("string");
    expect(body.nonce.length).toBeGreaterThan(0);
    expect(typeof body.authorization_url).toBe("string");
    expect(body.authorization_url).toContain("accounts.google.com");
  });

  test("77.4 disconnect without active connection returns 404", async () => {
    test.setTimeout(60_000);

    const resp = await apiPost(alicePage, `${GOOGLE_PREFIX}/disconnect`);
    expect(resp.status()).toBe(404);
    const body = await resp.json();
    expect(body).toHaveProperty("detail");
  });

  test("77.5 calendars endpoint without connection returns 404", async () => {
    test.setTimeout(60_000);

    const resp = await apiGet(alicePage, `${GOOGLE_PREFIX}/calendars`);
    expect(resp.status()).toBe(404);
    const body = await resp.json();
    expect(body).toHaveProperty("detail");
  });

  test("77.6 sync run without active connection returns 404", async () => {
    test.setTimeout(60_000);

    const resp = await apiPost(
      alicePage,
      `${GOOGLE_PREFIX}/sync/run?mode=incremental`,
    );
    expect(resp.status()).toBe(404);
    const body = await resp.json();
    expect(body).toHaveProperty("detail");
  });

  test("77.7 status endpoint is idempotent", async () => {
    test.setTimeout(60_000);

    const resp1 = await apiGet(alicePage, `${GOOGLE_PREFIX}/status`);
    expect(resp1.status()).toBe(200);
    const body1 = await resp1.json();

    const resp2 = await apiGet(alicePage, `${GOOGLE_PREFIX}/status`);
    expect(resp2.status()).toBe(200);
    const body2 = await resp2.json();

    expect(body2.provider).toBe(body1.provider);
    expect(body2.sync_enabled).toBe(body1.sync_enabled);
    expect(body2.writeback_enabled).toBe(body1.writeback_enabled);
    expect(body2.rollout_mode).toBe(body1.rollout_mode);
    expect(body2.rollout_percent).toBe(body1.rollout_percent);
    expect(body2.in_rollout_cohort).toBe(body1.in_rollout_cohort);
    expect(body2.connection_active).toBe(body1.connection_active);
    expect(body2.sync_health).toBe(body1.sync_health);
    expect(body2.last_sync_status).toBe(body1.last_sync_status);
    expect(body2.reauth_required).toBe(body1.reauth_required);
  });
});
