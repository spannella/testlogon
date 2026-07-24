/**
 * E2E tests for the Push Notification Device endpoints.
 *
 * Sections:
 *   97 — Push Device API (6 tests)
 *
 * Auth: Cookie-based session for Alice (e2e_alice@test.local) with CSRF.
 *
 * Endpoints under test:
 *   GET  /ui/push/devices   — list registered push devices
 *   POST /ui/push/register  — register a push device (FCM token + platform)
 *   POST /ui/push/revoke    — revoke/unregister a push device
 *   POST /ui/push/test      — send test push notification
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();
const FCM_TOKEN = `e2e_fcm_token_${TS}_aaaaaaaaaaaaaaaaaaa`; // min 20 chars
const PLATFORM = "android";

// ─── Session bootstrap ───────────────────────────────────────────────────────

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

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, path: string, body?: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

// ─── Section 97: Push Device API ─────────────────────────────────────────────

test.describe.serial("97 — Push Device API", () => {
  let page: Page;
  let deviceId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("97.1 — List devices initially returns empty array", async () => {
    const resp = await apiGet(page, "/ui/push/devices");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.devices).toBeDefined();
    expect(Array.isArray(data.devices)).toBe(true);
  });

  test("97.2 — Register a push device", async () => {
    const resp = await apiPost(page, "/ui/push/register", {
      token: FCM_TOKEN,
      platform: PLATFORM,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.device_id).toBeTruthy();
    expect(data.platform).toBe(PLATFORM);
    expect(data.created_at).toBeGreaterThan(0);
    expect(data.last_seen_at).toBeGreaterThan(0);
    deviceId = data.device_id;
  });

  test("97.3 — List devices includes newly registered device", async () => {
    const resp = await apiGet(page, "/ui/push/devices");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.devices)).toBe(true);
    const found = data.devices.find((d: any) => d.device_id === deviceId);
    expect(found).toBeTruthy();
    expect(found.platform).toBe(PLATFORM);
  });

  test("97.4 — Send test notification", async () => {
    const resp = await apiPost(page, "/ui/push/test");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
  });

  test("97.5 — Revoke/unregister the device", async () => {
    const resp = await apiPost(page, "/ui/push/revoke", {
      device_id: deviceId,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
  });

  test("97.6 — List devices no longer includes revoked device", async () => {
    const resp = await apiGet(page, "/ui/push/devices");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.devices)).toBe(true);
    const found = data.devices.find((d: any) => d.device_id === deviceId);
    expect(found).toBeFalsy();
  });
});
