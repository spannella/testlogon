/**
 * E2E tests for the Agent Orchestrator (AGENT-003).
 *
 * Sections:
 *   631 — Agent State Machine API (5 tests)
 *   632 — Ticket Claiming API (5 tests)
 *   633 — Ticket Lifecycle API (5 tests)
 *   634 — Agent Error Recovery API (3 tests)
 *
 * Auth: uses e2e_admin_session_setup.py (root identity)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ROOT_SUB = "root.admin@testdev.local";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface AdminSessionData {
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

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

// ─── Page factory ─────────────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  // Seed the persisted auth store so ProtectedRoute treats the page as
  // authenticated (cookie injection alone leaves isAuthenticated=false → /login
  // redirect, which hides the UI under test).
  const uid = sessions[identity].user_sub;
  await page.addInitScript((userId: string) => {
    const state = { userId, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, uid);
  return page;
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiPut(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.put(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

// ─── Shared state ─────────────────────────────────────────────────────────────

let rootPage: Page;
let alicePage: Page;
const WORKER_ID = `w_orch_${TS}`;
const WORKER_ID_2 = `w_orch2_${TS}`;
let testTicketId = "";
let testTicketId2 = "";
let testTicketIdBug = "";
let testSpaceId = "";

// ─── Setup ────────────────────────────────────────────────────────────────────

test.beforeAll(async ({ browser }) => {
  rootPage = await newIdentityPage(browser, "root");
  alicePage = await newIdentityPage(browser, "alice");

  // 1. Create worker via orchestrator stub endpoint
  const createResp = await apiPost(rootPage, "root", "ui/agent/orchestrator/create-worker", {
    worker_id: WORKER_ID,
    label: `E2E Orch Worker ${TS}`,
    agent_type: "coder",
  });
  expect(createResp.status()).toBe(200);

  // Create a ticket space for our tests
  const spaceResp = await apiPost(rootPage, "root", "ticket-spaces", {
    name: `e2e_orch_space_${TS}`,
  });
  expect(spaceResp.status()).toBe(200);
  const spaceData = await spaceResp.json();
  testSpaceId = spaceData.space.space_id;

  // 2. Create a test ticket with agent_eligible = "yes"
  const ticketResp = await apiPost(rootPage, "root", "tickets", {
    subject: `E2E Agent Test Ticket ${TS}`,
    description: "Test ticket for agent orchestrator E2E tests",
    space_id: testSpaceId,
    category: "feature",
  });
  expect(ticketResp.status()).toBe(200);
  const ticketData = await ticketResp.json();
  testTicketId = ticketData.ticket.ticket_id;

  // Mark ticket as agent-eligible by writing directly via the API
  // We use the tickets table directly -- set agent_eligible = "yes"
  await setTicketAgentEligible(rootPage, testTicketId);
});

async function setTicketAgentEligible(page: Page, ticketId: string) {
  // Since there's no dedicated endpoint for setting agent_eligible,
  // we'll write directly via a DDB helper endpoint or rely on
  // the ticket metadata field. For E2E, we use the claim-ticket approach:
  // first, ensure the ticket has agent_eligible = "yes" via the
  // orchestrator's eligible tickets endpoint by injecting it directly.
  //
  // For this test, we'll use a Python script to set the field.
  try {
    execSync(
      `python3 -c "
import boto3, os
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1',
    aws_access_key_id='test', aws_secret_access_key='test')
table = ddb.Table('tickets')
table.update_item(
    Key={'pk': 'TICKET#${ticketId}', 'sk': 'META'},
    UpdateExpression='SET agent_eligible = :ae, agent_worker_id = :empty, priority = :p, #t = :tt',
    ExpressionAttributeNames={'#t': 'type'},
    ExpressionAttributeValues={':ae': 'yes', ':empty': '', ':p': 'high', ':tt': 'feature'}
)
print('OK')
"`,
      { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
    );
  } catch {
    // If boto3 is not available, skip the DDB write
  }
}

test.afterAll(async () => {
  await rootPage?.close();
  await alicePage?.close();
});

// =============================================================================
// Section 631: Agent State Machine API
// =============================================================================

test.describe("631 — Agent State Machine API", () => {
  test("Agent starts in idle state", async () => {
    const resp = await apiGet(rootPage, `ui/agent/orchestrator/${WORKER_ID}/status`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.worker_id).toBe(WORKER_ID);
    expect(data.agent_state).toBe("idle");
    expect(data.current_ticket_id).toBe("");
    expect(data.tickets_completed).toBe(0);
  });

  test("Start agent loop transitions to idle", async () => {
    const resp = await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/start`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);

    const statusResp = await apiGet(rootPage, `ui/agent/orchestrator/${WORKER_ID}/status`);
    const status = await statusResp.json();
    // The autonomous loop (AGENT-003) may already have advanced past idle by
    // the time we poll: it discovers + claims an eligible ticket, moving through
    // claiming -> working (and on to completing). Any of these are valid once
    // the loop is running.
    expect(["idle", "claiming", "working", "completing"]).toContain(status.agent_state);
    expect(status.loop_running).toBe(true);
  });

  test("Pause agent sets state to paused", async () => {
    const resp = await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/pause`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.agent_state).toBe("paused");

    const statusResp = await apiGet(rootPage, `ui/agent/orchestrator/${WORKER_ID}/status`);
    const status = await statusResp.json();
    expect(status.agent_state).toBe("paused");
  });

  test("Resume agent returns to idle", async () => {
    const resp = await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/resume`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.agent_state).toBe("idle");

    const statusResp = await apiGet(rootPage, `ui/agent/orchestrator/${WORKER_ID}/status`);
    const status = await statusResp.json();
    expect(status.agent_state).toBe("idle");
  });

  test("Invalid state transition returns 400", async () => {
    // Agent is in idle; try to go directly to "completing" which is not allowed
    // We need to attempt this via the pause endpoint when already in idle
    // (idle -> idle is not a valid transition)
    // Let's try pause -> resume -> then try an invalid transition
    // Actually, we use the direct claim-ticket + then try pause when in working
    // Simpler: just verify that going from idle to completing fails
    // We need a way to trigger an arbitrary transition. Use the internal service.
    // For E2E, let's try to transition from idle to "completing" by calling
    // a combination of endpoints in wrong order.

    // Stop the agent loop first
    await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/stop`);

    // Agent is idle. Try to resume (which requires paused state)
    const resp = await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/resume`);
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail.code).toBe("invalid_state_transition");
  });
});

// =============================================================================
// Section 632: Ticket Claiming API
// =============================================================================

test.describe("632 — Ticket Claiming API", () => {
  test("Eligible tickets endpoint returns results", async () => {
    const resp = await apiGet(rootPage, `ui/agent/orchestrator/${WORKER_ID}/eligible-tickets`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data).toHaveProperty("tickets");
    expect(data).toHaveProperty("count");
    // If the ticket was marked agent_eligible, it should appear
    if (data.count > 0) {
      expect(data.tickets[0]).toHaveProperty("ticket_id");
    }
  });

  test("Agent claims a ticket via claim-ticket endpoint", async () => {
    // The AGENT-003 autonomous loop (started/stopped in section 631) may have
    // auto-claimed an eligible ticket and `stop_agent_loop` retains an
    // in-progress ticket — so WORKER_ID can still be holding a ticket here,
    // which would make a manual claim 409 with `worker_busy`. Ensure the worker
    // is idle (release any retained ticket) before the manual claim. Also make
    // sure its loop is stopped so it can't race-claim the fresh ticket below.
    await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/stop`);
    const preStatus = await (
      await apiGet(rootPage, `ui/agent/orchestrator/${WORKER_ID}/status`)
    ).json();
    if (preStatus.current_ticket_id) {
      await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/release-ticket`);
    }

    // First, create a fresh ticket and mark it eligible
    const ticketResp = await apiPost(rootPage, "root", "tickets", {
      subject: `E2E Claim Test ${TS}`,
      description: "Claim test ticket",
      space_id: testSpaceId,
    });
    expect(ticketResp.status()).toBe(200);
    const tData = await ticketResp.json();
    testTicketId2 = tData.ticket.ticket_id;
    await setTicketAgentEligible(rootPage, testTicketId2);

    // Claim the ticket
    const claimResp = await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/claim-ticket`, {
      ticket_id: testTicketId2,
    });
    expect(claimResp.status()).toBe(200);
    const claim = await claimResp.json();
    expect(claim.worker_id).toBe(WORKER_ID);
    expect(claim.status).toBe("active");

    // Verify worker status
    const statusResp = await apiGet(rootPage, `ui/agent/orchestrator/${WORKER_ID}/status`);
    const status = await statusResp.json();
    expect(status.agent_state).toBe("working");
    expect(status.current_ticket_id).toBe(testTicketId2);
  });

  test("Claimed ticket shows agent_worker_id", async () => {
    // The ticket's agent_* fields are stored on the raw DDB META item
    // (they are not surfaced through the public TicketOut model), so read
    // them directly from DynamoDB.
    const raw = execSync(
      `python3 -c "
import boto3, json
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1',
    aws_access_key_id='test', aws_secret_access_key='test')
table = ddb.Table('tickets')
item = table.get_item(Key={'pk': 'TICKET#${testTicketId2}', 'sk': 'META'}).get('Item', {})
print(json.dumps({
    'agent_worker_id': item.get('agent_worker_id', ''),
    'agent_claimed_at': int(item.get('agent_claimed_at', 0)),
}))
"`,
      { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
    ).toString();
    const ticket = JSON.parse(raw);
    expect(ticket.agent_worker_id).toBe(WORKER_ID);
    expect(ticket.agent_claimed_at).toBeGreaterThan(0);
  });

  test("Double-claim is prevented", async () => {
    // Create a second worker
    await apiPost(rootPage, "root", "ui/agent/orchestrator/create-worker", {
      worker_id: WORKER_ID_2,
      label: `E2E Orch Worker 2 ${TS}`,
      agent_type: "coder",
    });

    // Attempt to claim the same ticket with the second worker
    const claimResp = await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID_2}/claim-ticket`, {
      ticket_id: testTicketId2,
    });
    expect(claimResp.status()).toBe(409);
    const data = await claimResp.json();
    expect(data.detail.code).toBe("ticket_already_claimed");
  });

  test("Non-eligible ticket does not appear in eligible-tickets", async () => {
    // Create a ticket WITHOUT agent_eligible
    const ticketResp = await apiPost(rootPage, "root", "tickets", {
      subject: `E2E Non-Eligible ${TS}`,
      description: "Should not be eligible",
      space_id: testSpaceId,
    });
    expect(ticketResp.status()).toBe(200);
    const tData = await ticketResp.json();

    // Check eligible-tickets for WORKER_ID_2 (which has no ticket claimed)
    const resp = await apiGet(rootPage, `ui/agent/orchestrator/${WORKER_ID_2}/eligible-tickets`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // The non-eligible ticket should not appear
    const found = data.tickets.find((t: any) => t.ticket_id === tData.ticket.ticket_id);
    expect(found).toBeUndefined();
  });
});

// =============================================================================
// Section 633: Ticket Lifecycle API
// =============================================================================

test.describe("633 — Ticket Lifecycle API", () => {
  test("Release ticket returns it to queue", async () => {
    // WORKER_ID should have testTicketId2 claimed from section 632
    const releaseResp = await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/release-ticket`);
    expect(releaseResp.status()).toBe(200);
    const releaseData = await releaseResp.json();
    expect(releaseData.ok).toBe(true);
    expect(releaseData.released_ticket_id).toBe(testTicketId2);
    expect(releaseData.agent_state).toBe("idle");

    // Verify status
    const statusResp = await apiGet(rootPage, `ui/agent/orchestrator/${WORKER_ID}/status`);
    const status = await statusResp.json();
    expect(status.agent_state).toBe("idle");
    expect(status.current_ticket_id).toBe("");
  });

  test("Eligible tickets preview respects filter", async () => {
    // Set filter to only "bug" type tickets
    const filterResp = await apiPut(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/ticket-filter`, {
      types: ["bug"],
      tags: [],
      space_ids: [],
      priorities: [],
    });
    expect(filterResp.status()).toBe(200);

    // Create a "bug" ticket
    const bugResp = await apiPost(rootPage, "root", "tickets", {
      subject: `E2E Bug Ticket ${TS}`,
      description: "Bug ticket for filter test",
      space_id: testSpaceId,
    });
    expect(bugResp.status()).toBe(200);
    testTicketIdBug = (await bugResp.json()).ticket.ticket_id;

    // Mark as eligible and set type to "bug"
    try {
      execSync(
        `python3 -c "
import boto3
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1',
    aws_access_key_id='test', aws_secret_access_key='test')
table = ddb.Table('tickets')
table.update_item(
    Key={'pk': 'TICKET#${testTicketIdBug}', 'sk': 'META'},
    UpdateExpression='SET agent_eligible = :ae, agent_worker_id = :empty, #t = :tt, priority = :p',
    ExpressionAttributeNames={'#t': 'type'},
    ExpressionAttributeValues={':ae': 'yes', ':empty': '', ':tt': 'bug', ':p': 'high'}
)
print('OK')
"`,
        { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
      );
    } catch {
      // If boto3 is not available, skip
    }

    // Get eligible tickets - should only show bug tickets
    const eligResp = await apiGet(rootPage, `ui/agent/orchestrator/${WORKER_ID}/eligible-tickets`);
    expect(eligResp.status()).toBe(200);
    const eligData = await eligResp.json();
    // All returned tickets should be of type "bug"
    for (const t of eligData.tickets) {
      expect(t.type).toBe("bug");
    }

    // Reset filter to empty (match all)
    await apiPut(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/ticket-filter`, {
      types: [],
      tags: [],
      space_ids: [],
      priorities: [],
    });
  });

  test("Heartbeat updates timestamp", async () => {
    const before = Math.floor(Date.now() / 1000);
    const resp = await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/heartbeat`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.heartbeat_at).toBeGreaterThanOrEqual(before);

    // Verify via status
    const statusResp = await apiGet(rootPage, `ui/agent/orchestrator/${WORKER_ID}/status`);
    const status = await statusResp.json();
    expect(status.heartbeat_at).toBeGreaterThanOrEqual(before);
  });

  test("Save and retrieve checkpoint", async () => {
    // Claim a ticket first
    // Ensure the released ticket is re-claimable
    await setTicketAgentEligible(rootPage, testTicketId2);
    const claimResp = await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/claim-ticket`, {
      ticket_id: testTicketId2,
    });
    // Could be 200 or might fail if already claimed; handle gracefully
    if (claimResp.status() !== 200) {
      // Create a new ticket for this test
      const newTicket = await apiPost(rootPage, "root", "tickets", {
        subject: `E2E Checkpoint Ticket ${TS}`,
        description: "Checkpoint test ticket",
        space_id: testSpaceId,
      });
      const newData = await newTicket.json();
      await setTicketAgentEligible(rootPage, newData.ticket.ticket_id);
      const claim2 = await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/claim-ticket`, {
        ticket_id: newData.ticket.ticket_id,
      });
      expect(claim2.status()).toBe(200);
    }

    // Save checkpoint
    const checkpointData = { step: "coding", files_changed: 3 };
    const saveResp = await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/checkpoint`, {
      checkpoint: checkpointData,
    });
    expect(saveResp.status()).toBe(200);

    // Retrieve checkpoint
    const getResp = await apiGet(rootPage, `ui/agent/orchestrator/${WORKER_ID}/checkpoint`);
    expect(getResp.status()).toBe(200);
    const cpData = await getResp.json();
    expect(cpData.checkpoint.step).toBe("coding");
    expect(cpData.checkpoint.files_changed).toBe(3);
  });

  test("Complete ticket increments counter", async () => {
    // Get current completed count
    const beforeResp = await apiGet(rootPage, `ui/agent/orchestrator/${WORKER_ID}/status`);
    const beforeStatus = await beforeResp.json();
    const completedBefore = beforeStatus.tickets_completed;

    // Complete the currently claimed ticket
    const completeResp = await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/complete-ticket`, {
      summary: "Completed via E2E test",
    });
    expect(completeResp.status()).toBe(200);
    const completeData = await completeResp.json();
    expect(completeData.ok).toBe(true);
    expect(completeData.agent_state).toBe("idle");

    // Verify counter incremented
    const afterResp = await apiGet(rootPage, `ui/agent/orchestrator/${WORKER_ID}/status`);
    const afterStatus = await afterResp.json();
    expect(afterStatus.tickets_completed).toBe(completedBefore + 1);
    expect(afterStatus.agent_state).toBe("idle");
    expect(afterStatus.current_ticket_id).toBe("");
  });
});

// =============================================================================
// Section 634: Agent Error Recovery API
// =============================================================================

test.describe("634 — Agent Error Recovery API", () => {
  test("Stop agent loop gracefully", async () => {
    // Start the loop first
    await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/start`);

    // Stop the loop
    const resp = await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/stop`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);

    // Verify loop is stopped
    const statusResp = await apiGet(rootPage, `ui/agent/orchestrator/${WORKER_ID}/status`);
    const status = await statusResp.json();
    expect(status.loop_running).toBe(false);
  });

  test("Release ticket with no active ticket returns 400", async () => {
    // The autonomous loop (AGENT-003) may have auto-claimed an eligible ticket
    // for this worker during earlier tests. Drain any active ticket first so we
    // can deterministically exercise the no-active-ticket path. Releasing twice
    // is harmless — the second call is the 400 we're asserting.
    const statusResp = await apiGet(rootPage, `ui/agent/orchestrator/${WORKER_ID}/status`);
    const status = await statusResp.json();
    if (status.current_ticket_id) {
      await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/release-ticket`);
    }

    const cleared = await apiGet(rootPage, `ui/agent/orchestrator/${WORKER_ID}/status`);
    expect((await cleared.json()).current_ticket_id).toBe("");

    const resp = await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/release-ticket`);
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail.code).toBe("no_active_ticket");
  });

  test("Starting already-running loop returns 409", async () => {
    // Start the loop
    const start1 = await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/start`);
    expect(start1.status()).toBe(200);

    // Try starting again
    const start2 = await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/start`);
    expect(start2.status()).toBe(409);
    const data = await start2.json();
    expect(data.detail.code).toBe("loop_already_running");

    // Clean up
    await apiPost(rootPage, "root", `ui/agent/orchestrator/${WORKER_ID}/stop`);
  });
});
