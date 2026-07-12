/**
 * E2E tests for CALL-004: Call History
 *
 * Section 200: Record Call API (3 tests)
 * Section 201: List History API (3 tests)
 * Section 202: Get Call Detail API (2 tests)
 * Section 203: Delete Call Record API (2 tests)
 * Section 204: Call Stats API (2 tests)
 * Section 205: Pagination (2 tests)
 * Section 206: Call History UI (2 tests)
 *
 * Auth: uses e2e_admin_session_setup.py to get cookie-based sessions.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ───────────────────────────────────────────────────────────────

const API = "http://localhost:8000";
const BASE = "http://localhost:3000";
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
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ────────────────────────────────────────────────────────────

async function injectAuth(page: Page, sessionKey: string) {
  const sessions = getSessions();
  const session = sessions[sessionKey];
  if (!session) throw new Error(`No session for key=${sessionKey}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

// ─── Request helpers ─────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body: unknown) {
  const sessions = getSessions();
  return page.request.post(`${API}${path}`, {
    headers: { "x-csrf-token": sessions[identity].csrf_token },
    data: body,
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  let url = `${API}${path}`;
  if (params) {
    const qs = new URLSearchParams(params).toString();
    url += `?${qs}`;
  }
  return page.request.get(url);
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sessions = getSessions();
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": sessions[identity].csrf_token },
  });
}

// ─── Test state ──────────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;
const ALICE_KEY = "alice";
const BOB_KEY = "bob";
let aliceSub: string;
let bobSub: string;

test.describe("call-history — CALL-004", () => {
  test.beforeAll(async ({ browser }) => {
    const sessions = getSessions();
    aliceSub = sessions[ALICE_KEY].user_sub;
    bobSub = sessions[BOB_KEY].user_sub;

    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_KEY);

    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_KEY);
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  // ─── Section 200: Record Call API ─────────────────────────────────────

  let recordedCallId: string;

  test("200.1 — POST /ui/calls/record creates a call record", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/calls/record", {
      caller_id: aliceSub,
      callee_id: bobSub,
      call_type: "audio",
      duration_seconds: 120,
      status: "completed",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.call_id).toBeTruthy();
    expect(body.caller_id).toBe(aliceSub);
    expect(body.callee_id).toBe(bobSub);
    expect(body.call_type).toBe("audio");
    expect(body.duration_seconds).toBe(120);
    expect(body.status).toBe("completed");
    expect(body.direction).toBe("outgoing");
    recordedCallId = body.call_id;
  });

  test("200.2 — POST /ui/calls/record creates video call record", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/calls/record", {
      caller_id: aliceSub,
      callee_id: bobSub,
      call_type: "video",
      duration_seconds: 300,
      status: "completed",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.call_type).toBe("video");
    expect(body.duration_seconds).toBe(300);
  });

  test("200.3 — POST /ui/calls/record rejects invalid call_type", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/calls/record", {
      caller_id: aliceSub,
      callee_id: bobSub,
      call_type: "invalid_type",
      duration_seconds: 60,
      status: "completed",
    });
    expect(resp.status()).toBe(422);
  });

  // ─── Section 201: List History API ────────────────────────────────────

  test("201.1 — GET /ui/calls/history returns caller's records", async () => {
    const resp = await apiGet(alicePage, "/ui/calls/history");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.items).toBeInstanceOf(Array);
    expect(body.items.length).toBeGreaterThanOrEqual(2);
    // All records should belong to Alice (either as caller or callee)
    for (const item of body.items) {
      expect(
        item.caller_id === aliceSub || item.callee_id === aliceSub
      ).toBe(true);
    }
  });

  test("201.2 — GET /ui/calls/history returns callee's records too", async () => {
    // Bob was the callee — should also see the calls
    const resp = await apiGet(bobPage, "/ui/calls/history");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.items).toBeInstanceOf(Array);
    expect(body.items.length).toBeGreaterThanOrEqual(2);
    // Bob's records should show direction=incoming
    const incoming = body.items.filter((i: any) => i.direction === "incoming");
    expect(incoming.length).toBeGreaterThanOrEqual(2);
  });

  test("201.3 — GET /ui/calls/history supports limit param", async () => {
    const resp = await apiGet(alicePage, "/ui/calls/history", { limit: "1" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.items.length).toBe(1);
  });

  // ─── Section 202: Get Call Detail API ─────────────────────────────────

  test("202.1 — GET /ui/calls/history/:call_id returns detail", async () => {
    const resp = await apiGet(alicePage, `/ui/calls/history/${recordedCallId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.call_id).toBe(recordedCallId);
    expect(body.caller_id).toBe(aliceSub);
    expect(body.callee_id).toBe(bobSub);
    expect(body.call_type).toBe("audio");
    expect(body.duration_seconds).toBe(120);
  });

  test("202.2 — GET /ui/calls/history/:call_id returns 404 for unknown", async () => {
    const resp = await apiGet(alicePage, "/ui/calls/history/nonexistent_id");
    expect(resp.status()).toBe(404);
  });

  // ─── Section 203: Delete Call Record API ──────────────────────────────

  let deleteCallId: string;

  test("203.1 — DELETE /ui/calls/history/:call_id deletes record", async () => {
    // Create a call to delete
    const createResp = await apiPost(alicePage, ALICE_KEY, "/ui/calls/record", {
      caller_id: aliceSub,
      callee_id: bobSub,
      call_type: "audio",
      duration_seconds: 10,
      status: "missed",
    });
    const created = await createResp.json();
    deleteCallId = created.call_id;

    const resp = await apiDelete(alicePage, ALICE_KEY, `/ui/calls/history/${deleteCallId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);

    // Verify it's gone for Alice
    const getResp = await apiGet(alicePage, `/ui/calls/history/${deleteCallId}`);
    expect(getResp.status()).toBe(404);
  });

  test("203.2 — DELETE /ui/calls/history/:call_id returns 404 for unknown", async () => {
    const resp = await apiDelete(alicePage, ALICE_KEY, "/ui/calls/history/nonexistent_id");
    expect(resp.status()).toBe(404);
  });

  // ─── Section 204: Call Stats API ──────────────────────────────────────

  test("204.1 — GET /ui/calls/stats returns aggregated stats", async () => {
    const resp = await apiGet(alicePage, "/ui/calls/stats");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.total_calls).toBeGreaterThanOrEqual(2);
    expect(body.total_duration_seconds).toBeGreaterThan(0);
    expect(body.calls_by_type).toBeDefined();
    expect(body.calls_by_type.audio).toBeGreaterThanOrEqual(1);
    expect(body.calls_by_type.video).toBeGreaterThanOrEqual(1);
    expect(body.calls_by_status).toBeDefined();
    expect(body.calls_by_status.completed).toBeGreaterThanOrEqual(2);
  });

  test("204.2 — GET /ui/calls/stats for Bob shows incoming calls", async () => {
    const resp = await apiGet(bobPage, "/ui/calls/stats");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.total_calls).toBeGreaterThanOrEqual(2);
  });

  // ─── Section 205: Pagination ──────────────────────────────────────────

  test("205.1 — Pagination returns next_cursor when more items exist", async () => {
    // Seed enough calls
    for (let i = 0; i < 3; i++) {
      await apiPost(alicePage, ALICE_KEY, "/ui/calls/record", {
        caller_id: aliceSub,
        callee_id: bobSub,
        call_type: i % 2 === 0 ? "audio" : "video",
        duration_seconds: 60 + i * 10,
        status: "completed",
      });
    }

    const resp = await apiGet(alicePage, "/ui/calls/history", { limit: "2" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.items.length).toBe(2);
    expect(body.next_cursor).toBeTruthy();
  });

  test("205.2 — Using cursor returns next page", async () => {
    const firstResp = await apiGet(alicePage, "/ui/calls/history", { limit: "2" });
    const firstBody = await firstResp.json();
    expect(firstBody.next_cursor).toBeTruthy();

    const secondResp = await apiGet(alicePage, "/ui/calls/history", {
      limit: "2",
      cursor: firstBody.next_cursor,
    });
    expect(secondResp.status()).toBe(200);
    const secondBody = await secondResp.json();
    expect(secondBody.items.length).toBeGreaterThanOrEqual(1);

    // Ensure no overlap between pages
    const firstIds = new Set(firstBody.items.map((i: any) => i.call_id));
    for (const item of secondBody.items) {
      expect(firstIds.has(item.call_id)).toBe(false);
    }
  });

  // ─── Section 206: Call History UI ─────────────────────────────────────

  test("206.1 — Call History page loads and shows records", async () => {
    await alicePage.goto(`${BASE}/calls/history`, { waitUntil: "domcontentloaded" });
    // Wait for the page heading
    await expect(alicePage.getByRole("heading", { name: "Call History" })).toBeVisible({ timeout: 10_000 });
    // Wait for data to load
    await expect(alicePage.getByText("Recent Calls")).toBeVisible({ timeout: 10_000 });
    // Should show at least one call row
    const rows = alicePage.locator("tr[data-testid^='call-row-']");
    await expect(rows.first()).toBeVisible({ timeout: 10_000 });
  });

  test("206.2 — Call History page shows stats cards", async () => {
    await alicePage.goto(`${BASE}/calls/history`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText("Total Calls")).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.getByText("Total Duration")).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.getByText("Audio Calls")).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.getByText("Video Calls")).toBeVisible({ timeout: 10_000 });
  });
});
