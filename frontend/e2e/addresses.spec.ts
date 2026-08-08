/**
 * E2E tests for the Addresses feature.
 *
 * Sections:
 *   91 — Address CRUD API (8 tests)
 *
 * Auth: Cookie-based session for Alice (e2e_alice@test.local) with CSRF.
 *
 * Endpoints under test:
 *   GET    /ui/addresses
 *   POST   /ui/addresses
 *   PATCH  /ui/addresses/{address_id}
 *   DELETE /ui/addresses/{address_id}
 *   PUT    /ui/addresses/primary
 *   POST   /ui/addresses/search
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

async function apiPatch(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.patch(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiPut(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.put(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiDelete(page: Page, path: string) {
  const session = getSessions()[ALICE_ID];
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── Section 91: Address CRUD ────────────────────────────────────────────────

test.describe.serial("91 — Address CRUD API", () => {
  let page: Page;
  let addressId: string;
  let secondAddressId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("91.1 — Create address", async () => {
    const resp = await apiPost(page, "/ui/addresses", {
      name: `Home ${TS}`,
      line1: "123 Main St",
      line2: "Apt 4",
      city: "Springfield",
      state: "IL",
      postal_code: "62704",
      country: "US",
      label: "home",
      notes: "Front door",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.address_id).toBeTruthy();
    expect(data.name).toBe(`Home ${TS}`);
    expect(data.line1).toBe("123 Main St");
    expect(data.city).toBe("Springfield");
    expect(data.is_primary_mailing).toBe(false);
    expect(data.created_at).toBeGreaterThan(0);
    addressId = data.address_id;
  });

  test("91.2 — List addresses includes the created address", async () => {
    const resp = await apiGet(page, "/ui/addresses");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data)).toBe(true);
    const found = data.find((a: any) => a.address_id === addressId);
    expect(found).toBeTruthy();
    expect(found.name).toBe(`Home ${TS}`);
  });

  test("91.3 — Update address", async () => {
    const resp = await apiPatch(page, `/ui/addresses/${addressId}`, {
      city: "Chicago",
      state: "IL",
      postal_code: "60601",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.address_id).toBe(addressId);
    expect(data.city).toBe("Chicago");
    expect(data.postal_code).toBe("60601");
    expect(data.line1).toBe("123 Main St");
  });

  test("91.4 — Set primary address", async () => {
    const resp = await apiPut(page, "/ui/addresses/primary", {
      address_id: addressId,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.address_id).toBe(addressId);
    expect(data.is_primary_mailing).toBe(true);
  });

  test("91.5 — Create second address and verify primary stays", async () => {
    const resp = await apiPost(page, "/ui/addresses", {
      name: `Work ${TS}`,
      line1: "456 Office Blvd",
      city: "Austin",
      state: "TX",
      postal_code: "73301",
      country: "US",
      label: "work",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    secondAddressId = data.address_id;
    expect(data.is_primary_mailing).toBe(false);

    // Verify first address is still primary
    const listResp = await apiGet(page, "/ui/addresses");
    const list = await listResp.json();
    const primary = list.find((a: any) => a.address_id === addressId);
    expect(primary.is_primary_mailing).toBe(true);
  });

  test("91.6 — Search addresses", async () => {
    const resp = await apiPost(page, "/ui/addresses/search", {
      query: `Home ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.query).toBe(`Home ${TS}`);
    expect(Array.isArray(data.matches)).toBe(true);
    expect(data.matches.length).toBeGreaterThanOrEqual(1);
    const found = data.matches.find((a: any) => a.address_id === addressId);
    expect(found).toBeTruthy();
  });

  test("91.7 — Delete second address", async () => {
    const resp = await apiDelete(page, `/ui/addresses/${secondAddressId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.deleted).toBe(true);

    // Verify it no longer appears in list
    const listResp = await apiGet(page, "/ui/addresses");
    const list = await listResp.json();
    const gone = list.find((a: any) => a.address_id === secondAddressId);
    expect(gone).toBeFalsy();
  });

  test("91.8 — Delete primary address", async () => {
    const resp = await apiDelete(page, `/ui/addresses/${addressId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.deleted).toBe(true);
  });
});
