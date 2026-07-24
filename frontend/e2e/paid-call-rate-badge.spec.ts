/**
 * E2E tests for GAP-0148: caller rate display before initiating a call.
 *
 * Verifies the PaidCallRateBadge component:
 *  - shows the callee's per-minute rate next to the call buttons when the
 *    callee has configured an enabled paid-call rate
 *  - renders nothing when the callee has no rate / paid calls are disabled
 *
 * Auth pattern: e2e_session_setup.py sessions with injectAuth + CSRF cookies.
 * The conversation is opened via the deep-link route /messages/{conversationId}.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const PYTHON = REPO_ROOT + "/.venv/bin/python3";

const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

const RATE_BADGE = "[data-testid='paid-call-rate-badge']";

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

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  // ProtectedRoute gates the SPA on the persisted auth-store; cookies alone
  // authenticate API calls but the router would redirect to /login. Seed the
  // auth-store before every navigation so protected pages actually render.
  await page.addInitScript((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

function csrfHeader(userId: string): Record<string, string> {
  return { "x-csrf-token": getSessions()[userId]!.csrf_token };
}

async function setBobRate(page: Page, enabled: boolean) {
  if (enabled) {
    await page.request.post(`${BASE}/ui/calls/rates`, {
      headers: csrfHeader(BOB_ID),
      data: {
        rate_cents_per_minute: 150,
        enabled: true,
        min_balance_minutes: 5,
        max_duration_minutes: 120,
      },
    });
  } else {
    await page.request.delete(`${BASE}/ui/calls/rates`, {
      headers: csrfHeader(BOB_ID),
    });
  }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

test.describe("GAP-0148 — Paid call rate badge", () => {
  let alicePage: Page;
  let bobPage: Page;
  let dmConvoId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);

    const resp = await alicePage.request.post(
      `${BASE}/messaging/conversations/dm/find-or-create`,
      { headers: csrfHeader(ALICE_ID), data: { user_id: BOB_ID } },
    );
    expect(resp.status()).toBe(200);
    dmConvoId = (await resp.json()).conversation_id;
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("shows rate badge when callee has an enabled paid call rate", async () => {
    await setBobRate(bobPage, true);

    await alicePage.goto(`${BASE}/messages/${dmConvoId}`, { waitUntil: "domcontentloaded" });

    // FAILS BEFORE FIX: PaidCallRateBadge does not exist → no badge rendered.
    const badge = alicePage.locator(RATE_BADGE);
    await expect(badge).toBeVisible();
    await expect(badge).toContainText("1.50/min");
  });

  test("no rate badge when callee has paid calls disabled", async () => {
    await setBobRate(bobPage, false);

    await alicePage.goto(`${BASE}/messages/${dmConvoId}`, { waitUntil: "domcontentloaded" });

    // Ensure the conversation actually rendered before asserting absence.
    await expect(
      alicePage.locator("[data-testid='conversation-drop-zone']"),
    ).toBeVisible();
    await expect(alicePage.locator(RATE_BADGE)).not.toBeAttached();
  });
});
