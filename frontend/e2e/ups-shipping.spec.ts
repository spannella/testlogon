/**
 * E2E tests for the UPS mock shipping endpoints.
 *
 * Sections:
 *   100 — UPS Shipping Mock (5 tests)
 *
 * Auth: Cookie-based session for Alice (e2e_alice@test.local) with CSRF.
 *
 * Endpoints under test:
 *   POST /api/ups/quote           — get shipping quote
 *   POST /api/ups/label           — create shipping label
 *   POST /api/ups/address-validate — validate address
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

async function apiPost(page: Page, path: string, body?: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── Section 100: UPS Shipping Mock ─────────────────────────────────────────

test.describe.serial("100 — UPS Shipping Mock", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("100.1 — Get shipping quote with valid addresses", async () => {
    const resp = await apiPost(page, "/api/ups/quote", {
      service: "ground",
      from: {
        line1: "123 Main St",
        city: "Springfield",
        state: "IL",
        postal_code: "62704",
        country: "US",
      },
      to: {
        line1: "456 Oak Ave",
        city: "Chicago",
        state: "IL",
        postal_code: "60601",
        country: "US",
      },
      package: {
        weight: 5.0,
        length: 12,
        width: 8,
        height: 6,
      },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.service).toBe("ground");
    expect(data.currency).toBe("USD");
    expect(typeof data.amount).toBe("number");
    expect(data.amount).toBeGreaterThan(0);
    expect(typeof data.eta_days).toBe("number");
  });

  test("100.2 — Create shipping label", async () => {
    const resp = await apiPost(page, "/api/ups/label", {
      service: "ground",
      from: {
        line1: "123 Main St",
        city: "Springfield",
        state: "IL",
        postal_code: "62704",
        country: "US",
      },
      to: {
        line1: "456 Oak Ave",
        city: "Chicago",
        state: "IL",
        postal_code: "60601",
        country: "US",
      },
      package: {
        weight: 5.0,
      },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.tracking_number).toBeTruthy();
    expect(data.tracking_number).toMatch(/^1ZMOCK/);
    expect(data.label_url).toContain(data.tracking_number);
    expect(data.service).toBe("ground");
    expect(data.status).toBe("created");
  });

  test("100.3 — Address validation for valid address", async () => {
    const resp = await apiPost(page, "/api/ups/address-validate", {
      line1: "123 Main St",
      city: "Springfield",
      state: "IL",
      postal_code: "62704",
      country: "US",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.valid).toBe(true);
    expect(data.dpv_match_code).toBe("Y");
    expect(Array.isArray(data.candidates)).toBe(true);
    expect(data.candidates.length).toBeGreaterThanOrEqual(1);
    const candidate = data.candidates[0];
    expect(candidate.line1).toBe("123 MAIN ST");
    expect(candidate.city).toBe("SPRINGFIELD");
    expect(candidate.state).toBe("IL");
    expect(candidate.country).toBe("US");
  });

  test("100.4 — Address validation for invalid address", async () => {
    const resp = await apiPost(page, "/api/ups/address-validate", {
      line1: "INVALID ADDRESS LINE",
      city: "Nowhere",
      state: "XX",
      postal_code: "00000",
      country: "US",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.valid).toBe(false);
    expect(data.dpv_match_code).toBe("");
    expect(data.candidates).toEqual([]);
  });

  test("100.5 — Address validation with empty line1 returns invalid", async () => {
    const resp = await apiPost(page, "/api/ups/address-validate", {
      line1: "",
      city: "Springfield",
      state: "IL",
      postal_code: "62704",
      country: "US",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.valid).toBe(false);
    expect(data.candidates).toEqual([]);
  });
});
