/**
 * E2E tests for Mass Messaging (campaign-based bulk send).
 *
 * Routes tested:
 *   POST   /messaging/mass-messages                    — create campaign
 *   GET    /messaging/mass-messages                    — list campaigns
 *   GET    /messaging/mass-messages/{campaign_id}      — campaign detail
 *   POST   /messaging/mass-messages/{campaign_id}/cancel — cancel campaign
 *
 * Auth pattern:
 *   All mass-messaging endpoints use `get_authenticated_user_sub` which
 *   resolves via `require_ui_session` (cookie auth + CSRF for POST).
 *
 * Test users:
 *   Alice (e2e_alice@test.local) — primary actor, creates campaigns
 *   Bob   (e2e_bob@test.local)  — secondary user for cross-user isolation
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

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
    _sessions = loadSessions();
  }
  return _sessions!;
}

// ─── Auth helpers ────────────────────────────────────────────────────────────

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

// ─── Shared state (populated in beforeAll) ───────────────────────────────────

let alicePage: Page;
let bobPage: Page;
let dmConvoId: string;
let immediateCampaignId: string;
let scheduledCampaignId: string;

test.describe("Mass Messaging", () => {
  test.beforeAll(async ({ browser }) => {
    // Create Alice's browser context + page
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    // Create Bob's browser context + page
    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, "bob");

    // Create a DM conversation between Alice and Bob
    const dmResp = await apiPost(alicePage, "alice", "/messaging/conversations/dm/find-or-create", {
      user_id: BOB_ID,
    });
    expect(dmResp.ok()).toBeTruthy();
    const dmData = await dmResp.json();
    dmConvoId = dmData.conversation_id;
    expect(dmConvoId).toBeTruthy();

    // Pre-create the immediate campaign so tests 2/3/10 don't depend on test 1
    const immResp = await apiPost(alicePage, "alice", "/messaging/mass-messages", {
      conversation_ids: [dmConvoId],
      content: { kind: "text", text: `beforeAll immediate ${TS}` },
      mode: "immediate",
    });
    expect(immResp.status()).toBe(201);
    const immBody = await immResp.json();
    immediateCampaignId = immBody.campaign_id;

    // Pre-create the scheduled campaign so tests 5/6/9 don't depend on test 4
    const futureTs = Math.floor(Date.now() / 1000) + 7200;
    const schResp = await apiPost(alicePage, "alice", "/messaging/mass-messages", {
      conversation_ids: [dmConvoId],
      content: { kind: "text", text: `beforeAll scheduled ${TS}` },
      mode: "scheduled",
      send_at: futureTs,
    });
    expect(schResp.status()).toBe(201);
    const schBody = await schResp.json();
    scheduledCampaignId = schBody.campaign_id;
  });

  test.afterAll(async () => {
    await alicePage?.context().close();
    await bobPage?.context().close();
  });

  // ── 1. Create immediate campaign ────────────────────────────────────────

  test("1 — Alice creates an immediate mass-message campaign", async () => {
    const messageText = `Mass hello ${TS}_t1`;
    const resp = await apiPost(alicePage, "alice", "/messaging/mass-messages", {
      conversation_ids: [dmConvoId],
      content: { kind: "text", text: messageText },
      mode: "immediate",
    });
    expect(resp.status()).toBe(201);

    const body = await resp.json();
    expect(body.campaign_id).toBeTruthy();
    expect(body.mode).toBe("immediate");
    expect(body.status).toBeTruthy(); // pending or processing
    expect(body.accepted_count).toBe(1);
    expect(body.accepted_conversation_ids).toContain(dmConvoId);
    expect(body.rejected).toHaveLength(0);
    expect(body.counters).toBeDefined();
    expect(body.counters.total).toBeGreaterThanOrEqual(0);
    expect(body.created_at).toBeGreaterThan(0);
    expect(body.updated_at).toBeGreaterThan(0);
  });

  // ── 2. List campaigns ──────────────────────────────────────────────────

  test("2 — Alice lists her campaigns and the immediate campaign appears", async () => {
    const resp = await apiGet(alicePage, "/messaging/mass-messages");
    expect(resp.ok()).toBeTruthy();

    const body = await resp.json();
    expect(body.items).toBeDefined();
    expect(Array.isArray(body.items)).toBeTruthy();

    const found = body.items.find(
      (c: { campaign_id: string }) => c.campaign_id === immediateCampaignId,
    );
    expect(found).toBeDefined();
    expect(found.mode).toBe("immediate");
  });

  // ── 3. Get campaign detail ─────────────────────────────────────────────

  test("3 — Alice gets campaign detail with destinations", async () => {
    const resp = await apiGet(
      alicePage,
      `/messaging/mass-messages/${immediateCampaignId}`,
    );
    expect(resp.ok()).toBeTruthy();

    const body = await resp.json();
    expect(body.campaign_id).toBe(immediateCampaignId);
    expect(body.sender_id).toBe(ALICE_ID);
    expect(body.mode).toBe("immediate");
    expect(body.counters).toBeDefined();
    expect(body.destinations).toBeDefined();
    expect(Array.isArray(body.destinations)).toBeTruthy();

    // At least one destination should exist (the DM conversation)
    const dest = body.destinations.find(
      (d: { conversation_id: string }) => d.conversation_id === dmConvoId,
    );
    expect(dest).toBeDefined();
  });

  // ── 4. Create scheduled campaign ───────────────────────────────────────

  test("4 — Alice creates a scheduled mass-message campaign", async () => {
    const futureTs = Math.floor(Date.now() / 1000) + 3600;
    const messageText = `Scheduled mass ${TS}_t4`;

    const resp = await apiPost(alicePage, "alice", "/messaging/mass-messages", {
      conversation_ids: [dmConvoId],
      content: { kind: "text", text: messageText },
      mode: "scheduled",
      send_at: futureTs,
    });
    expect(resp.status()).toBe(201);

    const body = await resp.json();
    expect(body.campaign_id).toBeTruthy();
    expect(body.mode).toBe("scheduled");
    expect(body.send_at).toBe(futureTs);
    expect(body.accepted_count).toBe(1);
    expect(body.accepted_conversation_ids).toContain(dmConvoId);
  });

  // ── 5. Cancel scheduled campaign ──────────────────────────────────────

  test("5 — Alice cancels the scheduled campaign", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      `/messaging/mass-messages/${scheduledCampaignId}/cancel`,
      {},
    );
    expect(resp.ok()).toBeTruthy();

    const body = await resp.json();
    expect(body.campaign_id).toBe(scheduledCampaignId);
    expect(body.status).toBe("cancelled");
    expect(body.counters).toBeDefined();
    expect(body.updated_at).toBeGreaterThan(0);
  });

  // ── 6. List campaigns filtered by status ───────────────────────────────

  test("6 — Alice lists campaigns filtered by status=cancelled", async () => {
    // Ensure the scheduled campaign is cancelled first (idempotent)
    await apiPost(
      alicePage,
      "alice",
      `/messaging/mass-messages/${scheduledCampaignId}/cancel`,
      {},
    );

    const resp = await apiGet(
      alicePage,
      "/messaging/mass-messages?status=cancelled",
    );
    expect(resp.ok()).toBeTruthy();

    const body = await resp.json();
    expect(body.items).toBeDefined();

    // The cancelled scheduled campaign should appear in the filtered list
    const found = body.items.find(
      (c: { campaign_id: string }) => c.campaign_id === scheduledCampaignId,
    );
    expect(found).toBeDefined();
    expect(found.status).toBe("cancelled");

    // All items returned should have status=cancelled
    for (const item of body.items) {
      expect(item.status).toBe("cancelled");
    }
  });

  // ── 7. Empty conversation_ids returns 422 ──────────────────────────────

  test("7 — Creating a campaign with empty conversation_ids returns 422", async () => {
    const resp = await apiPost(alicePage, "alice", "/messaging/mass-messages", {
      conversation_ids: [],
      content: { kind: "text", text: "Should fail" },
      mode: "immediate",
    });
    expect(resp.status()).toBe(422);
  });

  // ── 8. Non-existent campaign returns 404 ───────────────────────────────

  test("8 — Getting a non-existent campaign returns 404", async () => {
    const resp = await apiGet(
      alicePage,
      "/messaging/mass-messages/mmc_nonexistent_000",
    );
    expect(resp.status()).toBe(404);
  });

  // ── 9. Cancel an already-cancelled campaign ────────────────────────────

  test("9 — Cancelling an already-cancelled campaign returns current state", async () => {
    // Ensure the scheduled campaign is cancelled first (idempotent)
    await apiPost(
      alicePage,
      "alice",
      `/messaging/mass-messages/${scheduledCampaignId}/cancel`,
      {},
    );

    // Cancel again — should be a noop returning the current state
    const resp = await apiPost(
      alicePage,
      "alice",
      `/messaging/mass-messages/${scheduledCampaignId}/cancel`,
      {},
    );
    expect(resp.ok()).toBeTruthy();

    const body = await resp.json();
    expect(body.campaign_id).toBe(scheduledCampaignId);
    expect(body.status).toBe("cancelled");
    // No additional destinations should have been cancelled on the second call
    expect(body.cancelled_destinations).toBe(0);
  });

  // ── 10. Cross-user isolation ───────────────────────────────────────────

  test("10 — Bob cannot see Alice's campaigns", async () => {
    // Bob lists his own campaigns — Alice's should not appear
    const listResp = await apiGet(bobPage, "/messaging/mass-messages");
    expect(listResp.ok()).toBeTruthy();

    const listBody = await listResp.json();
    const aliceCampaign = listBody.items.find(
      (c: { campaign_id: string }) => c.campaign_id === immediateCampaignId,
    );
    expect(aliceCampaign).toBeUndefined();

    // Bob tries to get Alice's campaign detail — should get 404
    const detailResp = await apiGet(
      bobPage,
      `/messaging/mass-messages/${immediateCampaignId}`,
    );
    expect(detailResp.status()).toBe(404);

    // Bob tries to cancel Alice's campaign — should get 404
    const cancelResp = await apiPost(
      bobPage,
      "bob",
      `/messaging/mass-messages/${immediateCampaignId}/cancel`,
      {},
    );
    expect(cancelResp.status()).toBe(404);
  });
});
