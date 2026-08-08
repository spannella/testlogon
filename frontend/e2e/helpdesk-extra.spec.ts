/**
 * E2E tests for additional helpdesk scenarios not covered in helpdesk.spec.ts.
 *
 * Sections:
 *   58 — Helpdesk idempotent claim + error cases + "Your Support Chats" UI
 *
 * Auth: uses e2e_session_setup.py (same as helpdesk.spec.ts)
 *
 * Test users:
 *   Alice (e2e_alice@test.local) — helpdesk agent (HELPDESK_GROUP_MEMBERS_JSON)
 *   Bob   (e2e_bob@test.local)   — customer
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const GROUP_ID = "e2e-helpdesk";
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

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

// ─── API helpers (session-auth via page.request) ──────────────────────────────

async function apiPost(page: Page, userId: string, path: string, body: object) {
  const session = getSessions()[userId];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGet(
  page: Page,
  userId: string,
  path: string,
  params?: Record<string, string>,
) {
  const session = getSessions()[userId];
  const url = params
    ? `${API}${path}?${new URLSearchParams(params).toString()}`
    : `${API}${path}`;
  return page.request.get(url, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── Page factory ─────────────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, userId: string): Promise<Page> {
  const page = await browser.newPage();
  await injectAuth(page, userId);
  return page;
}

// ─── Helpdesk helpers ─────────────────────────────────────────────────────────

async function createHelpdeskConvo(bobPage: Page): Promise<string> {
  const resp = await apiPost(bobPage, BOB_ID, "/messaging/conversations", {
    routing_mode:      "helpdesk_bridge",
    helpdesk_group_id: GROUP_ID,
    type:              "dm",
  });
  if (!resp.ok()) throw new Error(`Failed to create helpdesk convo: ${await resp.text()}`);
  const data = await resp.json() as { conversation_id: string };
  return data.conversation_id;
}

async function refreshAliceHeartbeat(alicePage: Page) {
  return apiPost(alicePage, ALICE_ID, "/messaging/presence/heartbeat", { status: "online" });
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 58 — Helpdesk idempotent claim + error cases + "Your Support Chats" UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 58: Helpdesk idempotent claim + error cases", () => {
  let alicePage: Page;
  let bobPage:   Page;
  let convoId:   string;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
    bobPage   = await newIdentityPage(browser, BOB_ID);

    // Alice sends heartbeat BEFORE Bob creates the conversation
    await refreshAliceHeartbeat(alicePage);

    // Bob creates a fresh helpdesk conversation
    convoId = await createHelpdeskConvo(bobPage);

    // Bob sends a message so the convo is identifiable
    await apiPost(bobPage, BOB_ID, `/messaging/conversations/${convoId}/messages`, {
      text: `Idempotent claim test ${TS}`,
    });

    // Alice claims the conversation
    await refreshAliceHeartbeat(alicePage);
    const claimResp = await apiPost(
      alicePage, ALICE_ID,
      `/messaging/helpdesk/conversations/${convoId}/claim`,
      {},
    );
    if (!claimResp.ok()) throw new Error(`Initial claim failed: ${await claimResp.text()}`);
  });

  test("58.1 Claiming already-assigned convo by same agent → idempotent=true", async () => {
    // Alice already claimed in beforeAll; claiming again should be idempotent
    const resp = await apiPost(
      alicePage, ALICE_ID,
      `/messaging/helpdesk/conversations/${convoId}/claim`,
      {},
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ok: boolean; state: string; idempotent: boolean };
    expect(data.ok).toBe(true);
    expect(data.state).toBe("assigned");
    expect(data.idempotent).toBe(true);
  });

  test("58.2 Claiming a non-existent conversation → 404", async () => {
    const fakeId = "conv_does_not_exist_12345";
    const resp = await apiPost(
      alicePage, ALICE_ID,
      `/messaging/helpdesk/conversations/${fakeId}/claim`,
      {},
    );
    expect(resp.status()).toBe(404);
  });

  test("58.3 Bob's helpdesk chat visible in 'Your Support Chats' UI section", async () => {
    test.setTimeout(20_000);
    // Navigate Bob to /helpdesk — his own convo should appear under "Your Support Chats"
    await bobPage.goto(`${BASE}/helpdesk`, { waitUntil: "load" });
    // The heading is always visible regardless of conversation count
    await expect(
      bobPage.getByText("Your Support Chats"),
    ).toBeVisible({ timeout: 8000 });
    // Bob's own convo should appear (routing_mode=helpdesk_bridge → myHelpdeskConvos)
    // We verify the section has at least one conversation row (not the empty-state message)
    const emptyMsg = bobPage.getByText(/no support chats yet/i);
    await expect(emptyMsg).not.toBeVisible({ timeout: 5000 });
  });

  test("58.4 Messages in claimed convo readable by Alice (agent)", async () => {
    const resp = await apiGet(
      alicePage, ALICE_ID,
      `/messaging/conversations/${convoId}/messages`,
    );
    expect(resp.status()).toBe(200);
    const messages = await resp.json() as Array<{ text: string }>;
    expect(Array.isArray(messages)).toBe(true);
    const found = messages.find((m) => m.text === `Idempotent claim test ${TS}`);
    expect(found).toBeTruthy();
  });

  test("58.5 Creating helpdesk convo returns valid routing state", async () => {
    // Create a fresh convo — state is awaiting_agent (Alice online) or paused_no_agents_online
    const freshConvoId = await createHelpdeskConvo(bobPage);
    expect(typeof freshConvoId).toBe("string");
    expect(freshConvoId.length).toBeGreaterThan(0);

    // Verify the convo exists and has a recognized helpdesk routing state
    const resp = await apiGet(
      alicePage, ALICE_ID,
      "/messaging/helpdesk/queue",
      { group_id: GROUP_ID },
    );
    expect(resp.status()).toBe(200);
    const queue = await resp.json() as Array<{ conversation_id: string; routing_state: string }>;
    const entry = queue.find((c) => c.conversation_id === freshConvoId);
    // Entry may be in awaiting_agent or assigned states in the queue
    if (entry) {
      const validStates = ["awaiting_agent", "assigned", "paused_no_agents_online"];
      expect(validStates).toContain(entry.routing_state);
    }
    // If not in the queue, it may be paused — verify it was created via Bob's convo list
    else {
      const convosResp = await apiGet(bobPage, BOB_ID, "/messaging/conversations");
      expect(convosResp.status()).toBe(200);
      const convosData = await convosResp.json() as { conversations: Array<{ conversation_id: string }> };
      const found = convosData.conversations.find((c) => c.conversation_id === freshConvoId);
      expect(found).toBeTruthy();
    }
  });
});
