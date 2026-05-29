/**
 * E2E tests for Bot Framework (BOT-001).
 *
 * Sections:
 *   507 — Bot CRUD API       (5 tests)
 *   508 — Bot Status Lifecycle (3 tests)
 *   509 — Bot Assignment API  (4 tests)
 *   510 — Bot Manager UI      (4 tests)
 *
 * Auth: Alice (creator), Bob (user).
 * Sessions seeded by e2e_session_setup.py.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ───────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
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
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ────────────────────────────────────────────────────────────

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

// ─── API helpers ─────────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body: Record<string, unknown>) {
  const session = getSessions()[identity];
  return page.request.post(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body,
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

async function apiPut(page: Page, identity: string, path: string, body: Record<string, unknown>) {
  const session = getSessions()[identity];
  return page.request.put(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body,
  });
}

async function apiPatch(page: Page, identity: string, path: string, body: Record<string, unknown>) {
  const session = getSessions()[identity];
  return page.request.patch(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body,
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const session = getSessions()[identity];
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── Shared state ────────────────────────────────────────────────────────────

let botId: string;
let secondBotId: string;
let alicePage: Page;

// =============================================================================
// Section 507: Bot CRUD API
// =============================================================================

test.describe("507 — Bot CRUD API", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("507.1 Creator creates a bot", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/bots", {
      name: `TestBot_${TS}`,
      description: "E2E test bot",
      personality: "friendly",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.bot_id).toBeTruthy();
    expect(data.status).toBe("active");
    expect(data.name).toBe(`TestBot_${TS}`);
    expect(data.personality).toBe("friendly");
    botId = data.bot_id;
  });

  test("507.2 Creator lists bots", async () => {
    const resp = await apiGet(alicePage, "/ui/bots");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.bots).toBeInstanceOf(Array);
    const found = data.bots.find((b: any) => b.bot_id === botId);
    expect(found).toBeTruthy();
  });

  test("507.3 Creator updates bot name and personality", async () => {
    const resp = await apiPut(alicePage, ALICE_ID, `/ui/bots/${botId}`, {
      name: `UpdatedBot_${TS}`,
      personality: "professional",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.name).toBe(`UpdatedBot_${TS}`);
    expect(data.personality).toBe("professional");
  });

  test("507.4 Creator creates a second bot", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/bots", {
      name: `SecondBot_${TS}`,
      description: "Second test bot",
      personality: "casual",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.bot_id).toBeTruthy();
    expect(data.bot_id).not.toBe(botId);
    secondBotId = data.bot_id;
  });

  test("507.5 Creator deletes second bot", async () => {
    const delResp = await apiDelete(alicePage, ALICE_ID, `/ui/bots/${secondBotId}`);
    expect(delResp.status()).toBe(200);

    // Verify deleted — GET returns 404
    const getResp = await apiGet(alicePage, `/ui/bots/${secondBotId}`);
    expect(getResp.status()).toBe(404);
  });
});

// =============================================================================
// Section 508: Bot Status Lifecycle
// =============================================================================

test.describe("508 — Bot Status Lifecycle", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Ensure we have a bot to work with
    if (!botId) {
      const resp = await apiPost(alicePage, ALICE_ID, "/ui/bots", {
        name: `LifecycleBot_${TS}`,
        description: "Status test bot",
        personality: "friendly",
      });
      const data = await resp.json();
      botId = data.bot_id;
    }
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("508.1 Pause a bot", async () => {
    const resp = await apiPatch(alicePage, ALICE_ID, `/ui/bots/${botId}/status`, {
      status: "paused",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("paused");
  });

  test("508.2 Resume a paused bot", async () => {
    const resp = await apiPatch(alicePage, ALICE_ID, `/ui/bots/${botId}/status`, {
      status: "active",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("active");
  });

  test("508.3 Disable a bot", async () => {
    const resp = await apiPatch(alicePage, ALICE_ID, `/ui/bots/${botId}/status`, {
      status: "disabled",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("disabled");
  });
});

// =============================================================================
// Section 509: Bot Assignment API
// =============================================================================

test.describe("509 — Bot Assignment API", () => {
  let assignmentBotId: string;
  const fakeConvoId = `convo_e2e_${TS}`;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Create a fresh active bot for assignment tests
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/bots", {
      name: `AssignBot_${TS}`,
      description: "Assignment test bot",
      personality: "friendly",
    });
    const data = await resp.json();
    assignmentBotId = data.bot_id;
  });

  test.afterAll(async () => {
    // Clean up: delete the assignment bot
    await apiDelete(alicePage, ALICE_ID, `/ui/bots/${assignmentBotId}`);
    await alicePage.context().close();
  });

  test("509.1 Assign bot to a conversation", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${assignmentBotId}/assignments`, {
      target_type: "conversation",
      target_id: fakeConvoId,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.bot_id).toBe(assignmentBotId);
    expect(data.target_type).toBe("conversation");
  });

  test("509.2 Assign bot to all DMs", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${assignmentBotId}/assignments`, {
      target_type: "all_dms",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.target_type).toBe("all_dms");
  });

  test("509.3 List bot assignments", async () => {
    const resp = await apiGet(alicePage, `/ui/bots/${assignmentBotId}/assignments`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.assignments.length).toBeGreaterThanOrEqual(2);
  });

  test("509.4 Remove conversation assignment", async () => {
    // First list to find the conversation assignment sk
    const listResp = await apiGet(alicePage, `/ui/bots/${assignmentBotId}/assignments`);
    const listData = await listResp.json();
    const convAssignment = listData.assignments.find(
      (a: any) => a.target_type === "conversation",
    );
    expect(convAssignment).toBeTruthy();

    const delResp = await apiDelete(
      alicePage,
      ALICE_ID,
      `/ui/bots/${assignmentBotId}/assignments/${encodeURIComponent(convAssignment.sk)}`,
    );
    expect(delResp.status()).toBe(200);

    // Verify list length decremented
    const listResp2 = await apiGet(alicePage, `/ui/bots/${assignmentBotId}/assignments`);
    const listData2 = await listResp2.json();
    expect(listData2.assignments.length).toBe(listData.assignments.length - 1);
  });
});

// =============================================================================
// Section 510: Bot Manager UI
// =============================================================================

test.describe("510 — Bot Manager UI", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("510.1 Bot Manager page loads", async () => {
    await alicePage.goto(`${BASE}/bots`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.locator('[data-testid="bot-manager-page"]')).toBeVisible();
    await expect(alicePage.getByText("Chat Bots")).toBeVisible();
  });

  test("510.2 Create bot via dialog", async () => {
    await alicePage.goto(`${BASE}/bots`, { waitUntil: "domcontentloaded" });
    // Wait for the page to be ready
    await expect(alicePage.locator('[data-testid="bot-manager-page"]')).toBeVisible();

    await alicePage.locator('[data-testid="create-bot-btn"]').click();
    await expect(alicePage.locator('[data-testid="bot-editor-dialog"]')).toBeVisible();

    const botName = `UIBot_${TS}`;
    await alicePage.locator('[data-testid="bot-name-input"]').fill(botName);
    await alicePage.locator('[data-testid="bot-description-input"]').fill("Created via UI test");
    await alicePage.locator('[data-testid="bot-save-btn"]').click();

    // Wait for the dialog to close and the bot card to appear
    await expect(alicePage.locator('[data-testid="bot-editor-dialog"]')).not.toBeVisible({ timeout: 5000 });
    // Reload to see fresh list
    await alicePage.goto(`${BASE}/bots`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText(botName)).toBeVisible({ timeout: 5000 });
  });

  test("510.3 Pause bot via UI", async () => {
    await alicePage.goto(`${BASE}/bots`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.locator('[data-testid="bot-manager-page"]')).toBeVisible();

    // Find a Pause button and click it
    const pauseBtn = alicePage.getByRole("button", { name: /Pause/i }).first();
    if (await pauseBtn.isVisible()) {
      await pauseBtn.click();
      // After pause, should see "Paused" badge somewhere
      await expect(alicePage.getByText("Paused")).toBeVisible({ timeout: 5000 });
    } else {
      // No active bots to pause, create one and then pause
      const resp = await apiPost(alicePage, ALICE_ID, "/ui/bots", {
        name: `PauseTestBot_${TS}`,
        personality: "friendly",
      });
      const data = await resp.json();
      await alicePage.reload();
      await expect(alicePage.locator('[data-testid="bot-manager-page"]')).toBeVisible();
      const newPauseBtn = alicePage.locator(`[data-testid="pause-bot-${data.bot_id}"]`);
      await newPauseBtn.click();
      await expect(alicePage.getByText("Paused")).toBeVisible({ timeout: 5000 });
    }
  });

  test("510.4 Bot stats endpoint returns data", async () => {
    // Get a bot ID from the list
    const listResp = await apiGet(alicePage, "/ui/bots");
    const listData = await listResp.json();
    expect(listData.bots.length).toBeGreaterThan(0);
    const aBotId = listData.bots[0].bot_id;

    const resp = await apiGet(alicePage, `/ui/bots/${aBotId}/stats`);
    expect(resp.status()).toBe(200);
    const stats = await resp.json();
    expect(typeof stats.message_count).toBe("number");
    expect(typeof stats.assignment_count).toBe("number");
  });
});
