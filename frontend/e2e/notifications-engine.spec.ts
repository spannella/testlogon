/**
 * E2E tests for Notification Engine (SOC-004).
 *
 * Sections:
 *   200 — Notification send + list API (5 tests)
 *   201 — Notification mark-read + unread-count API (5 tests)
 *   202 — Notification batching API (3 tests)
 *   203 — Notifications UI (3 tests)
 *
 * Auth: Alice and Bob session cookies (from e2e_session_setup.py).
 * Notifications are created via the POST /ui/notifications/send test endpoint.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const TS       = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name:     string;
    value:    string;
    domain:   string;
    path:     string;
    httpOnly: boolean;
    secure:   boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires:  number;
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
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function apiPost(page: Page, identity: string, path: string, body: unknown) {
  const session = getSessions()[identity];
  return page.request.post(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body,
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  let url = `${BASE}${path}`;
  if (params) {
    const qs = new URLSearchParams(params).toString();
    url += `?${qs}`;
  }
  return page.request.get(url);
}

// ─── Section 200: Notification send + list API ────────────────────────────────

test.describe("200 — Notification send + list API", () => {
  let alicePage: Page;
  const createdIds: string[] = [];

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("200.1 send a follow notification", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/notifications/send", {
      user_id: ALICE_ID,
      notification_type: "follow",
      title: `Bob started following you ${TS}`,
      body: "You have a new follower!",
      data: { actor_id: BOB_ID },
    });
    expect(resp.status()).toBe(200);
    const json = await resp.json();
    expect(json.ok).toBe(true);
    expect(json.notification_id).toBeTruthy();
    createdIds.push(json.notification_id);
  });

  test("200.2 send a like notification", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/notifications/send", {
      user_id: ALICE_ID,
      notification_type: "like",
      title: `Someone liked your post ${TS}`,
      data: { actor_id: BOB_ID, post_id: "post_123" },
    });
    expect(resp.status()).toBe(200);
    const json = await resp.json();
    expect(json.ok).toBe(true);
    createdIds.push(json.notification_id);
  });

  test("200.3 send a comment notification", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/notifications/send", {
      user_id: ALICE_ID,
      notification_type: "comment",
      title: `Bob commented on your post ${TS}`,
      body: "Great post!",
      data: { actor_id: BOB_ID, post_id: "post_456" },
    });
    expect(resp.status()).toBe(200);
    const json = await resp.json();
    expect(json.ok).toBe(true);
    createdIds.push(json.notification_id);
  });

  test("200.4 list notifications returns created items", async () => {
    const resp = await apiGet(alicePage, "/ui/notifications", { limit: "50" });
    expect(resp.status()).toBe(200);
    const json = await resp.json();
    expect(json.items).toBeDefined();
    expect(Array.isArray(json.items)).toBe(true);
    // Should have at least the 3 we created
    const ids = json.items.map((n: { notification_id: string }) => n.notification_id);
    for (const id of createdIds) {
      expect(ids).toContain(id);
    }
  });

  test("200.5 reject invalid notification type", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/notifications/send", {
      user_id: ALICE_ID,
      notification_type: "invalid_type",
      title: "Should fail",
    });
    expect(resp.status()).toBe(400);
  });
});

// ─── Section 201: Mark-read + unread-count API ────────────────────────────────

test.describe("201 — Mark-read + unread-count API", () => {
  let alicePage: Page;
  let notificationId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Create a notification to mark read
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/notifications/send", {
      user_id: ALICE_ID,
      notification_type: "mention",
      title: `You were mentioned ${TS}_201`,
      data: { actor_id: BOB_ID },
    });
    const json = await resp.json();
    notificationId = json.notification_id;
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("201.1 unread count is positive", async () => {
    const resp = await apiGet(alicePage, "/ui/notifications/unread-count");
    expect(resp.status()).toBe(200);
    const json = await resp.json();
    expect(json.count).toBeGreaterThan(0);
  });

  test("201.2 mark specific notification as read", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/notifications/mark-read", {
      notification_ids: [notificationId],
    });
    expect(resp.status()).toBe(200);
    const json = await resp.json();
    expect(json.ok).toBe(true);
    expect(json.marked_count).toBe(1);
  });

  test("201.3 marked notification appears as read in list", async () => {
    const resp = await apiGet(alicePage, "/ui/notifications", { limit: "50" });
    expect(resp.status()).toBe(200);
    const json = await resp.json();
    const found = json.items.find(
      (n: { notification_id: string }) => n.notification_id === notificationId,
    );
    expect(found).toBeDefined();
    expect(found.read).toBe(true);
  });

  test("201.4 mark-read with empty list returns 400", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/notifications/mark-read", {
      notification_ids: [],
    });
    expect(resp.status()).toBe(400);
  });

  test("201.5 mark all read clears unread count", async () => {
    // Send one more unread notification first
    await apiPost(alicePage, ALICE_ID, "/ui/notifications/send", {
      user_id: ALICE_ID,
      notification_type: "tip",
      title: `You received a tip ${TS}_201_5`,
      data: { actor_id: BOB_ID, amount_cents: 500 },
    });

    const resp = await apiPost(alicePage, ALICE_ID, "/ui/notifications/mark-all-read", {});
    expect(resp.status()).toBe(200);
    const json = await resp.json();
    expect(json.ok).toBe(true);
    expect(json.marked_count).toBeGreaterThanOrEqual(1);

    // Verify unread count is 0
    const countResp = await apiGet(alicePage, "/ui/notifications/unread-count");
    const countJson = await countResp.json();
    expect(countJson.count).toBe(0);
  });
});

// ─── Section 202: Notification batching API ───────────────────────────────────

test.describe("202 — Notification batching API", () => {
  let alicePage: Page;
  const BATCH_KEY = `like:post_batch_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("202.1 first notification with batch_key creates new entry", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/notifications/send", {
      user_id: ALICE_ID,
      notification_type: "like",
      title: `Bob liked your post ${TS}`,
      data: { actor_id: BOB_ID, post_id: `batch_post_${TS}` },
      batch_key: BATCH_KEY,
    });
    expect(resp.status()).toBe(200);
    const json = await resp.json();
    expect(json.ok).toBe(true);
    expect(json.batch_count).toBe(1);
  });

  test("202.2 second notification with same batch_key increments count", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/notifications/send", {
      user_id: ALICE_ID,
      notification_type: "like",
      title: `Charlie liked your post ${TS}`,
      data: { actor_id: "charlie@test.local", post_id: `batch_post_${TS}` },
      batch_key: BATCH_KEY,
    });
    expect(resp.status()).toBe(200);
    const json = await resp.json();
    expect(json.ok).toBe(true);
    // batch_count should be 2 now (batched into existing)
    expect(json.batch_count).toBe(2);
  });

  test("202.3 batched notification shows correct count in list", async () => {
    const resp = await apiGet(alicePage, "/ui/notifications", { limit: "50" });
    expect(resp.status()).toBe(200);
    const json = await resp.json();
    // Find a notification with our batch_key
    const batched = json.items.find(
      (n: { batch_key: string }) => n.batch_key === BATCH_KEY,
    );
    expect(batched).toBeDefined();
    expect(batched.batch_count).toBe(2);
    expect(batched.batch_actors.length).toBe(2);
    expect(batched.batch_actors).toContain(BOB_ID);
    expect(batched.batch_actors).toContain("charlie@test.local");
  });
});

// ─── Section 203: Notifications UI ────────────────────────────────────────────

test.describe("203 — Notifications UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Create a fresh notification for UI testing
    await apiPost(alicePage, ALICE_ID, "/ui/notifications/send", {
      user_id: ALICE_ID,
      notification_type: "system",
      title: `System notification ${TS}_ui`,
      body: `Test body for UI ${TS}_ui`,
      data: {},
    });
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("203.1 notifications page loads and shows header", async () => {
    await alicePage.goto(`${BASE}/notifications`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText("Notifications", { exact: true }).first()).toBeVisible();
  });

  test("203.2 notifications list shows at least one item", async () => {
    await alicePage.goto(`${BASE}/notifications`, { waitUntil: "domcontentloaded" });
    // Wait for the notification items to load
    await expect(alicePage.locator("[class*='rounded-lg border']").first()).toBeVisible({
      timeout: 10_000,
    });
  });

  test("203.3 notifications page shows type badges", async () => {
    await alicePage.goto(`${BASE}/notifications`, { waitUntil: "domcontentloaded" });
    // There should be at least one type badge
    await expect(
      alicePage.locator("text=system").first()
    ).toBeVisible({ timeout: 10_000 });
  });
});
