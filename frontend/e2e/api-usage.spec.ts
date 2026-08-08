/**
 * E2E tests for the API Usage endpoints.
 *
 * Sections:
 *   99 — API Usage (4 tests)
 *
 * Auth: Cookie-based session for Alice (e2e_alice@test.local) with CSRF.
 *
 * Endpoints under test:
 *   GET /ui/api-usage/summary?period=YYYY-MM
 *   GET /ui/api-usage/routes?period=YYYY-MM
 *   GET /ui/api-usage/keys?period=YYYY-MM
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";

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

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

// ─── Section 99: API Usage ──────────────────────────────────────────────────

test.describe.serial("99 — API Usage", () => {
  let page: Page;
  const period = new Date().toISOString().slice(0, 7); // e.g. "2026-05"

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("99.1 — Get usage summary returns valid response", async () => {
    const resp = await apiGet(page, `/ui/api-usage/summary?period=${period}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.period).toBe(period);
    expect(data.totals).toBeTruthy();
    expect(typeof data.totals.calls_total).toBe("number");
    expect(typeof data.totals.billable_calls_total).toBe("number");
    expect(typeof data.totals.request_units_total).toBe("number");
    expect(typeof data.totals.cost_subtotal_micros).toBe("number");
    expect(typeof data.totals.estimated_cost_micros).toBe("number");
    expect(data.limits).toBeTruthy();
    expect(typeof data.limits.monthly_calls_limit).toBe("number");
    expect(typeof data.limits.monthly_spend_micros_limit).toBe("number");
    expect(data.remaining).toBeTruthy();
  });

  test("99.2 — Get route-level usage breakdown", async () => {
    const resp = await apiGet(page, `/ui/api-usage/routes?period=${period}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.period).toBe(period);
    expect(Array.isArray(data.items)).toBe(true);
    expect(typeof data.count).toBe("number");
    expect(typeof data.total).toBe("number");
    // next_cursor may be null or a string
    expect(data.next_cursor === null || typeof data.next_cursor === "string").toBe(true);
  });

  test("99.3 — Get per-key usage breakdown", async () => {
    const resp = await apiGet(page, `/ui/api-usage/keys?period=${period}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.period).toBe(period);
    expect(Array.isArray(data.items)).toBe(true);
    expect(typeof data.count).toBe("number");
    expect(typeof data.total).toBe("number");
    expect(data.next_cursor === null || typeof data.next_cursor === "string").toBe(true);
  });

  test("99.4 — Invalid period format returns 400", async () => {
    const resp = await apiGet(page, `/ui/api-usage/summary?period=invalid`);
    expect(resp.status()).toBe(400);

    const resp2 = await apiGet(page, `/ui/api-usage/routes?period=2026-13`);
    expect(resp2.status()).toBe(400);

    const resp3 = await apiGet(page, `/ui/api-usage/keys?period=2026-00`);
    expect(resp3.status()).toBe(400);
  });
});
