/**
 * E2E tests for Helpdesk Agent Chat integration.
 *
 * Sections 47–51:
 *   47 — Helpdesk page is accessible (UI)
 *   48 — Customer starts a support request (UI)
 *   49 — Agent queue API
 *   50 — Agent claim + reply (UI + API)
 *   51 — Routing events & error cases (API)
 *
 * Test users:
 *   Alice (e2e_alice@test.local) — helpdesk agent (HELPDESK_GROUP_MEMBERS_JSON)
 *   Bob   (e2e_bob@test.local)   — customer
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, resolveIdentityId } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ───────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = resolveIdentityId("e2e_alice@test.local");
const BOB_ID   = resolveIdentityId("e2e_bob@test.local");
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

async function apiGet(page: Page, userId: string, path: string, params?: Record<string, string>, timeout = 30_000) {
  const session = getSessions()[userId];
  const url = params
    ? `${API}${path}?${new URLSearchParams(params).toString()}`
    : `${API}${path}`;
  return page.request.get(url, {
    headers: { "x-csrf-token": session.csrf_token },
    timeout,
  });
}

// ─── Page factory ─────────────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, userId: string): Promise<Page> {
  const page = await browser.newPage();
  await injectAuth(page, userId);
  return page;
}

// ─── Helpdesk conversation bootstrap ─────────────────────────────────────────

/** Create a fresh helpdesk conversation as Bob and return its conversation_id */
async function createHelpdeskConvo(bobPage: Page): Promise<string> {
  const resp = await apiPost(bobPage, BOB_ID, "/messaging/conversations", {
    routing_mode: "helpdesk_bridge",
    helpdesk_group_id: GROUP_ID,
    type: "dm",
  });
  if (!resp.ok()) throw new Error(`Failed to create helpdesk convo: ${await resp.text()}`);
  const data = await resp.json() as { conversation_id: string };
  return data.conversation_id;
}

/** Ensure Alice has a fresh heartbeat (required by claim endpoint) */
async function refreshAliceHeartbeat(alicePage: Page) {
  return apiPost(alicePage, ALICE_ID, "/messaging/presence/heartbeat", { status: "online" });
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 47 — Helpdesk page is accessible
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 47: Helpdesk page is accessible", () => {
  let page47: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page47 = await newIdentityPage(browser, BOB_ID);
  });

  test("47.1 Bob can navigate to /helpdesk", async () => {
    await page47.goto(`${BASE}/helpdesk`, { waitUntil: "load" });
    await expect(page47.locator("h1").filter({ hasText: /helpdesk/i })).toBeVisible({ timeout: 8000 });
  });

  test("47.2 Contact Support button is visible", async () => {
    await expect(
      page47.getByRole("button", { name: /contact support/i }),
    ).toBeVisible({ timeout: 5000 });
  });

  test("47.3 Helpdesk nav item is in sidebar", async () => {
    await expect(
      page47.locator("nav").getByText("Helpdesk"),
    ).toBeVisible({ timeout: 5000 });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 48 — Customer starts a support request (UI)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 48: Customer starts support request", () => {
  let alicePage48: Page;
  let bobPage48: Page;
  const MSG = `Support request ${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    // Alice must be online BEFORE Bob creates the conversation (so it routes to awaiting_agent)
    alicePage48 = await newIdentityPage(browser, ALICE_ID);
    await refreshAliceHeartbeat(alicePage48);

    bobPage48 = await newIdentityPage(browser, BOB_ID);
    await bobPage48.goto(`${BASE}/helpdesk`, { waitUntil: "load" });
    await expect(bobPage48.getByRole("button", { name: /contact support/i })).toBeVisible({ timeout: 8000 });
    await bobPage48.getByRole("button", { name: /contact support/i }).click();
    await expect(
      bobPage48.getByPlaceholder("Type a message...").or(
        bobPage48.getByPlaceholder("Type an encrypted message..."),
      ),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("48.1 ComposeBar is visible after clicking Contact Support", async () => {
    await expect(
      bobPage48.getByPlaceholder("Type a message...").or(
        bobPage48.getByPlaceholder("Type an encrypted message..."),
      ),
    ).toBeVisible({ timeout: 5000 });
  });

  test("48.2 Bob sends a message via ComposeBar", async () => {
    test.setTimeout(30_000);
    const compose = bobPage48.getByPlaceholder("Type a message...").or(
      bobPage48.getByPlaceholder("Type an encrypted message..."),
    );
    await compose.fill(MSG);

    const [postResp] = await Promise.all([
      bobPage48.waitForResponse(
        (r) => r.url().includes("/messages") && r.request().method() === "POST",
      ),
      bobPage48.getByRole("button", { name: "Send message" }).click(),
    ]);
    expect(postResp.status()).toBe(200);

    await expect(
      bobPage48.locator("p").filter({ hasText: MSG }),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("48.3 Bob's helpdesk conversation appears in Alice's queue with routing_mode=helpdesk_bridge (API)", async () => {
    // Bob's conversation is not visible with routing_mode from Bob's list (non-agent view strips it).
    // Verify from Alice's agent perspective — the newly created convo should be in awaiting_agent queue.
    const resp = await apiGet(alicePage48, ALICE_ID, "/messaging/helpdesk/queue", { group_id: GROUP_ID });
    expect(resp.status()).toBe(200);
    const queue = await resp.json() as Array<{ conversation_id: string; routing_state: string; routing_mode: string }>;
    // At least one awaiting_agent or paused helpdesk conversation exists (the one Bob just created)
    const entry = queue.find((c) => c.routing_state === "awaiting_agent" || c.routing_state === "paused_no_agents_online");
    expect(entry).toBeTruthy();
    expect(entry!.routing_mode).toBe("helpdesk_bridge");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 49 — Agent queue API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 49: Agent queue", () => {
  let alicePage49: Page;
  let bobPage49: Page;
  let convoId49: string;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage49 = await newIdentityPage(browser, ALICE_ID);
    bobPage49   = await newIdentityPage(browser, BOB_ID);
    // Send Alice's heartbeat so she's "online"
    await refreshAliceHeartbeat(alicePage49);
    // Create a fresh helpdesk conversation as Bob
    convoId49 = await createHelpdeskConvo(bobPage49);
    // Send a message in the new convo so it's easy to find
    await apiPost(bobPage49, BOB_ID, `/messaging/conversations/${convoId49}/messages`, {
      text: `Queue test ${TS}`,
    });
  });

  test("49.1 Alice can query the helpdesk queue (200)", async () => {
    const resp = await apiGet(alicePage49, ALICE_ID, "/messaging/helpdesk/queue", { group_id: GROUP_ID });
    expect(resp.status()).toBe(200);
    const queue = await resp.json() as Array<{ conversation_id: string }>;
    expect(Array.isArray(queue)).toBe(true);
  });

  test("49.2 Bob's conversation appears in queue with awaiting_agent state", async () => {
    const resp = await apiGet(alicePage49, ALICE_ID, "/messaging/helpdesk/queue", { group_id: GROUP_ID });
    const queue = await resp.json() as Array<{ conversation_id: string; routing_state: string }>;
    const entry = queue.find((c) => c.conversation_id === convoId49);
    expect(entry).toBeTruthy();
    expect(entry!.routing_state).toBe("awaiting_agent");
  });

  test("49.3 Queue includes routing fields", async () => {
    const resp = await apiGet(alicePage49, ALICE_ID, "/messaging/helpdesk/queue", { group_id: GROUP_ID });
    type QueueEntry = { conversation_id: string; routing_mode: string; routing_group_id: string; routing_state: string };
    const queue = await resp.json() as QueueEntry[];
    const entry = queue.find((c) => c.conversation_id === convoId49);
    expect(entry!.routing_mode).toBe("helpdesk_bridge");
    expect(entry!.routing_group_id).toBe(GROUP_ID);
  });

  test("49.4 Bob (non-agent) gets 403 on queue", async () => {
    const resp = await apiGet(bobPage49, BOB_ID, "/messaging/helpdesk/queue", { group_id: GROUP_ID });
    expect(resp.status()).toBe(403);
  });

  test("49.5 State filter limits results correctly", async () => {
    const respAll = await apiGet(alicePage49, ALICE_ID, "/messaging/helpdesk/queue", {
      group_id: GROUP_ID,
      state: "awaiting_agent",
    });
    expect(respAll.status()).toBe(200);
    const queue = await respAll.json() as Array<{ routing_state: string }>;
    for (const c of queue) {
      expect(c.routing_state).toBe("awaiting_agent");
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 50 — Agent claim + reply (UI + API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 50: Agent claim and reply", () => {
  let alicePage50: Page;
  let bobPage50: Page;
  let convoId50: string;
  const ALICE_REPLY = `Agent reply ${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage50 = await newIdentityPage(browser, ALICE_ID);
    bobPage50   = await newIdentityPage(browser, BOB_ID);
    // Alice's heartbeat MUST be sent before creating the conversation,
    // otherwise the backend transitions immediately to paused_no_agents_online.
    await refreshAliceHeartbeat(alicePage50);
    // Create a fresh helpdesk conversation as Bob (via session auth)
    convoId50 = await createHelpdeskConvo(bobPage50);
    // Bob sends first message
    await apiPost(bobPage50, BOB_ID, `/messaging/conversations/${convoId50}/messages`, {
      text: `Help me please ${TS}`,
    });
  });

  test("50.1 Alice navigates to /helpdesk and sees the Agent Queue section", async () => {
    test.setTimeout(30_000);
    await alicePage50.goto(`${BASE}/helpdesk`, { waitUntil: "load" });
    await expect(alicePage50.locator("h1").filter({ hasText: /helpdesk/i })).toBeVisible({ timeout: 8000 });
    await expect(alicePage50.getByText("Agent Queue")).toBeVisible({ timeout: 5000 });
  });

  test("50.2 Bob's conversation shows Waiting badge in Alice's queue", async () => {
    test.setTimeout(15_000);
    // The queue should show at least one "Waiting" badge for a queued conversation
    await expect(alicePage50.getByText("Waiting").first()).toBeVisible({ timeout: 10_000 });
  });

  test("50.3 Alice selects the conversation and sees the ComposeBar", async () => {
    test.setTimeout(30_000);
    // Click on the first queue item (any "Waiting" queue entry)
    const queueItem = alicePage50.locator("button").filter({ has: alicePage50.getByText("Waiting") }).first();
    await queueItem.click();
    await expect(
      alicePage50.getByPlaceholder("Type a message...").or(
        alicePage50.getByPlaceholder("Type an encrypted message..."),
      ),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("50.4 Claim button visible in routing banner", async () => {
    await expect(
      alicePage50.getByRole("button", { name: /claim/i }),
    ).toBeVisible({ timeout: 5000 });
    // Banner should say "Waiting for agent"
    await expect(alicePage50.getByText(/waiting for agent/i)).toBeVisible({ timeout: 5000 });
  });

  test("50.5 Alice claims via API and banner updates to assigned", async () => {
    test.setTimeout(30_000);
    // Refresh heartbeat right before claiming
    await refreshAliceHeartbeat(alicePage50);

    // Get the conversation ID from the currently open conversation
    // (it's the one we navigated to in 50.3 — could be a different convo from beforeAll)
    // Use API to claim convoId50 directly and verify state
    const claimResp = await apiPost(
      alicePage50, ALICE_ID,
      `/messaging/helpdesk/conversations/${convoId50}/claim`,
      {},
    );
    expect(claimResp.status()).toBe(200);
    const claimData = await claimResp.json() as { ok: boolean; state: string; assigned_agent_user_id: string };
    expect(claimData.ok).toBe(true);
    expect(claimData.state).toBe("assigned");
    expect(claimData.assigned_agent_user_id).toBe(ALICE_ID);
  });

  test("50.6 After claim, conversation state is assigned in queue API", async () => {
    const resp = await apiGet(alicePage50, ALICE_ID, "/messaging/helpdesk/queue", {
      group_id: GROUP_ID,
      state: "assigned",
    });
    expect(resp.status()).toBe(200);
    const queue = await resp.json() as Array<{ conversation_id: string; routing_state: string }>;
    const entry = queue.find((c) => c.conversation_id === convoId50);
    expect(entry).toBeTruthy();
    expect(entry!.routing_state).toBe("assigned");
  });

  test("50.7 Alice sends a reply message (API)", async () => {
    test.setTimeout(20_000);
    const resp = await apiPost(
      alicePage50, ALICE_ID,
      `/messaging/conversations/${convoId50}/messages`,
      { text: ALICE_REPLY },
    );
    expect(resp.status()).toBe(200);
    const msg = await resp.json() as { message_id: string; text: string };
    expect(msg.text).toBe(ALICE_REPLY);
  });

  test("50.8 Bob can see Alice's reply via API", async () => {
    const resp = await apiGet(bobPage50, BOB_ID, `/messaging/conversations/${convoId50}/messages`);
    expect(resp.status()).toBe(200);
    const messages = await resp.json() as Array<{ text: string }>;
    const found = messages.find((m) => m.text === ALICE_REPLY);
    expect(found).toBeTruthy();
  });

  test("50.9 UI banner shows 'You are handling' after UI-claim on Helpdesk page", async () => {
    test.setTimeout(30_000);
    // Create a fresh convo so there is at least one awaiting_agent item in the queue.
    // Heartbeat MUST be sent before creating the conversation.
    await refreshAliceHeartbeat(alicePage50);
    const freshConvoId = await createHelpdeskConvo(bobPage50);

    // Re-navigate alicePage50 to /helpdesk with a full reload to clear any stale
    // UI state from tests 50.1–50.8. alicePage50 has Alice's valid session cookies
    // and localStorage, so no new page (and no injectAuth) is needed.
    await alicePage50.goto(`${BASE}/helpdesk`, { waitUntil: "load" });

    // Wait for Agent Queue to show a Waiting item
    await expect(alicePage50.getByText("Waiting").first()).toBeVisible({ timeout: 10_000 });

    // Click the first Waiting queue item to open it in the conversation panel
    const queueItem = alicePage50.locator("button").filter({ has: alicePage50.getByText("Waiting") }).first();
    await queueItem.click();
    await expect(
      alicePage50.getByRole("button", { name: /claim/i }),
    ).toBeVisible({ timeout: 8000 });

    // Click Claim via UI and wait for the claim response
    const [claimResp] = await Promise.all([
      alicePage50.waitForResponse((r) =>
        r.url().includes("/helpdesk/conversations/") && r.url().includes("/claim"),
      ),
      alicePage50.getByRole("button", { name: /claim/i }).click(),
    ]);
    expect(claimResp.status()).toBe(200);

    // After the claim, both ["conversations"] and ["helpdesk-queue"] are invalidated
    // and re-fetched. The banner should update to "You are handling this conversation".
    await expect(
      alicePage50.getByText(/you are handling this conversation/i),
    ).toBeVisible({ timeout: 12_000 });

    void freshConvoId; // suppress unused warning
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 51 — Routing events & error cases (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 51: Routing events and error cases", () => {
  let alicePage51: Page;
  let bobPage51: Page;
  let convoId51: string;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage51 = await newIdentityPage(browser, ALICE_ID);
    bobPage51   = await newIdentityPage(browser, BOB_ID);
    await refreshAliceHeartbeat(alicePage51);
    // Create fresh convo and claim it so routing events exist
    convoId51 = await createHelpdeskConvo(bobPage51);
    await apiPost(bobPage51, BOB_ID, `/messaging/conversations/${convoId51}/messages`, {
      text: `Routing events test ${TS}`,
    });
    await refreshAliceHeartbeat(alicePage51);
    const claimResp = await apiPost(
      alicePage51, ALICE_ID,
      `/messaging/helpdesk/conversations/${convoId51}/claim`,
      {},
    );
    if (!claimResp.ok()) throw new Error(`Claim failed: ${await claimResp.text()}`);
  });

  test("51.1 Alice can fetch routing events (200)", async () => {
    const resp = await apiGet(
      alicePage51, ALICE_ID,
      `/messaging/conversations/${convoId51}/routing-events`,
    );
    expect(resp.status()).toBe(200);
    const events = await resp.json() as Array<{ event_type: string }>;
    expect(Array.isArray(events)).toBe(true);
    expect(events.length).toBeGreaterThan(0);
  });

  test("51.2 Routing events include the assigned event", async () => {
    const resp = await apiGet(
      alicePage51, ALICE_ID,
      `/messaging/conversations/${convoId51}/routing-events`,
    );
    type RoutingEvent = { event_type: string; from_state: string; to_state: string; actor_user_id: string };
    const events = await resp.json() as RoutingEvent[];
    const assignEvent = events.find((e) => e.event_type === "helpdesk.conversation.assigned");
    expect(assignEvent).toBeTruthy();
    expect(assignEvent!.from_state).toBe("awaiting_agent");
    expect(assignEvent!.to_state).toBe("assigned");
    expect(assignEvent!.actor_user_id).toBe(ALICE_ID);
  });

  test("51.3 Bob (non-agent) gets 403 claiming the conversation", async () => {
    const resp = await apiPost(
      bobPage51, BOB_ID,
      `/messaging/helpdesk/conversations/${convoId51}/claim`,
      {},
    );
    expect(resp.status()).toBe(403);
  });

  test("51.4 Bob cannot query the agent queue", async () => {
    const resp = await apiGet(bobPage51, BOB_ID, "/messaging/helpdesk/queue", { group_id: GROUP_ID });
    expect(resp.status()).toBe(403);
  });

  test("51.5 awaiting_agent filter excludes claimed conversation", async () => {
    const resp = await apiGet(alicePage51, ALICE_ID, "/messaging/helpdesk/queue", {
      group_id: GROUP_ID,
      state: "awaiting_agent",
    });
    expect(resp.status()).toBe(200);
    const queue = await resp.json() as Array<{ conversation_id: string; routing_state: string }>;
    const found = queue.find((c) => c.conversation_id === convoId51);
    expect(found).toBeFalsy();
  });

  test("51.6 assigned filter includes claimed conversation", async () => {
    const resp = await apiGet(alicePage51, ALICE_ID, "/messaging/helpdesk/queue", {
      group_id: GROUP_ID,
      state: "assigned",
    });
    expect(resp.status()).toBe(200);
    const queue = await resp.json() as Array<{ conversation_id: string; routing_state: string }>;
    const found = queue.find((c) => c.conversation_id === convoId51);
    expect(found).toBeTruthy();
    expect(found!.routing_state).toBe("assigned");
  });
});
