/**
 * E2E tests for Agent Feedback & Terminal Monitoring (AGENT-006):
 *
 * Section 645: Feedback request API — create, list, get, filter by status
 * Section 646: Response & skip API — respond, skip, already-responded rejection
 * Section 647: Pattern config API — get defaults, update, validate, test patterns
 * Section 648: Feedback page UI — page loads, request list, response form, skip
 *
 * ── Authentication strategy ────────────────────────────────────────────────
 *
 * Uses `e2e_admin_session_setup.py` sessions (cookie auth + CSRF).
 * Alice (role=user) is the primary actor who owns agent workers.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ──────────────────────────────────────────────────────────────

const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

// ─── Session bootstrap ──────────────────────────────────────────────────────

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
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
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
  const sess = getSessions()[identity];
  return page.request.put(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

// ─── Shared state ───────────────────────────────────────────────────────────

const WORKER_ID = `e2e-feedback-worker-${TS}`;
let alicePage: Page;
let feedbackRequestId1 = "";
let feedbackRequestId2 = "";

// ─── Section 645: Feedback Request API ──────────────────────────────────────

test.describe("645 — Feedback request API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("645.1 Create a feedback request", async () => {
    const resp = await apiPost(alicePage, "alice", `ui/agent/feedback/${WORKER_ID}`, {
      ticket_id: `TICKET-${TS}`,
      question: `Should I use async or sync for ${TS}?`,
      terminal_context: `...multiple approaches available for ${TS}...`,
      detected_pattern: "[AGENT_FEEDBACK_NEEDED]",
      timeout_seconds: 3600,
      timeout_action: "skip",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.request_id).toBeTruthy();
    expect(data.feedback_status).toBe("pending");
    expect(data.question).toContain(String(TS));
    expect(data.timeout_at).toBeGreaterThan(0);
    expect(data.worker_id).toBe(WORKER_ID);
    feedbackRequestId1 = data.request_id;
  });

  test("645.2 List pending feedback for worker", async () => {
    const resp = await apiGet(alicePage, `ui/agent/feedback/${WORKER_ID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.count).toBeGreaterThanOrEqual(1);
    expect(data.pending_count).toBeGreaterThanOrEqual(1);
    const match = data.requests.find((r: any) => r.request_id === feedbackRequestId1);
    expect(match).toBeTruthy();
    expect(match.feedback_status).toBe("pending");
  });

  test("645.3 List pending feedback across all workers", async () => {
    const resp = await apiGet(alicePage, "ui/agent/feedback");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.count).toBeGreaterThanOrEqual(1);
    const match = data.requests.find((r: any) => r.request_id === feedbackRequestId1);
    expect(match).toBeTruthy();
    expect(match.worker_id).toBe(WORKER_ID);
    expect(match.question).toBeTruthy();
  });

  test("645.4 Get single feedback request", async () => {
    const resp = await apiGet(
      alicePage,
      `ui/agent/feedback/${WORKER_ID}/${feedbackRequestId1}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.request_id).toBe(feedbackRequestId1);
    expect(data.question).toContain(String(TS));
    expect(data.terminal_context).toContain(String(TS));
    expect(data.detected_pattern).toBe("[AGENT_FEEDBACK_NEEDED]");
    expect(data.feedback_status).toBe("pending");
  });
});

// ─── Section 646: Response & Skip API ───────────────────────────────────────

test.describe("646 — Response & skip API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");

    // Create a second feedback request for skip test
    const resp = await apiPost(alicePage, "alice", `ui/agent/feedback/${WORKER_ID}`, {
      ticket_id: `TICKET-SKIP-${TS}`,
      question: `Which database should I use for ${TS}?`,
      terminal_context: "Evaluating options...",
      detected_pattern: "[NEEDS_INPUT]",
    });
    const data = await resp.json();
    feedbackRequestId2 = data.request_id;
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("646.1 Respond to feedback request", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      `ui/agent/feedback/${WORKER_ID}/${feedbackRequestId1}/respond`,
      { response_text: `Use async for all I/O operations (${TS})` },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.feedback_status).toBe("responded");
    expect(data.response_text).toContain("Use async");
    expect(data.responded_at).toBeGreaterThan(0);
  });

  test("646.2 Cannot respond to already-responded request", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      `ui/agent/feedback/${WORKER_ID}/${feedbackRequestId1}/respond`,
      { response_text: "Try again" },
    );
    expect(resp.status()).toBe(409);
  });

  test("646.3 Skip feedback request", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      `ui/agent/feedback/${WORKER_ID}/${feedbackRequestId2}/skip`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.feedback_status).toBe("skipped");
  });

  test("646.4 Cannot skip already-skipped request", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      `ui/agent/feedback/${WORKER_ID}/${feedbackRequestId2}/skip`,
    );
    expect(resp.status()).toBe(409);
  });
});

// ─── Section 647: Pattern Config API ────────────────────────────────────────

test.describe("647 — Pattern config API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("647.1 Get default pattern config", async () => {
    const resp = await apiGet(
      alicePage,
      `ui/agent/feedback/${WORKER_ID}/patterns`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.completion).toBeInstanceOf(Array);
    expect(data.feedback_needed).toBeInstanceOf(Array);
    expect(data.error).toBeInstanceOf(Array);
    // Default patterns should contain AGENT_COMPLETE
    const hasComplete = data.completion.some((p: string) => p.includes("AGENT_COMPLETE"));
    expect(hasComplete).toBe(true);
  });

  test("647.2 Update pattern config", async () => {
    const resp = await apiPut(
      alicePage,
      "alice",
      `ui/agent/feedback/${WORKER_ID}/patterns`,
      {
        feedback_needed: [
          "\\[AGENT_FEEDBACK_NEEDED\\]",
          "(?i)custom pattern for testing",
        ],
      },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.agent_type).toBe("custom");
    expect(data.feedback_needed).toContain("(?i)custom pattern for testing");
  });

  test("647.3 Get updated pattern config", async () => {
    const resp = await apiGet(
      alicePage,
      `ui/agent/feedback/${WORKER_ID}/patterns`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.agent_type).toBe("custom");
    expect(data.feedback_needed).toContain("(?i)custom pattern for testing");
  });

  test("647.4 Test patterns against sample text", async () => {
    const resp = await apiPost(alicePage, "alice", "ui/agent/feedback/test-patterns", {
      patterns: {
        feedback_needed: ["(?i)waiting for user input", "\\[AGENT_FEEDBACK_NEEDED\\]"],
        completion: ["\\[AGENT_COMPLETE\\]"],
        error: ["\\[AGENT_ERROR\\]"],
      },
      sample_text: "Processing... waiting for user input on the schema design",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.match_count).toBeGreaterThanOrEqual(1);
    expect(data.matches.length).toBeGreaterThanOrEqual(1);
    const feedbackMatch = data.matches.find((m: any) => m.signal === "feedback_needed");
    expect(feedbackMatch).toBeTruthy();
    expect(feedbackMatch.match).toContain("waiting for user input");
  });
});

// ─── Section 648: Feedback Page UI ──────────────────────────────────────────

test.describe("648 — Feedback page UI", () => {
  let uiPage: Page;
  const UI_WORKER = `e2e-ui-worker-${TS}`;
  let uiRequestId = "";

  test.beforeAll(async ({ browser }) => {
    uiPage = await newIdentityPage(browser, "alice");
    // Create a pending feedback request for UI display
    const resp = await apiPost(uiPage, "alice", `ui/agent/feedback/${UI_WORKER}`, {
      ticket_id: `UI-TICKET-${TS}`,
      question: `Should I deploy to production for ${TS}?`,
      terminal_context: `Build passed. Ready to deploy. ${TS}`,
      detected_pattern: "[AGENT_FEEDBACK_NEEDED]",
    });
    const data = await resp.json();
    uiRequestId = data.request_id;
  });

  test.afterAll(async () => {
    await uiPage?.close();
  });

  test("648.1 Feedback page loads", async () => {
    await uiPage.goto("http://localhost:3000/agents/feedback");
    await expect(
      uiPage.getByRole("heading", { name: "Agent Feedback", exact: true }),
    ).toBeVisible();
  });

  test("648.2 Pending request is visible", async () => {
    await uiPage.goto("http://localhost:3000/agents/feedback");
    // Wait for query to load
    await uiPage.waitForTimeout(1500);
    await expect(
      uiPage.getByText(`Should I deploy to production for ${TS}?`),
    ).toBeVisible();
    await expect(uiPage.getByText("Pending")).toBeVisible();
  });

  test("648.3 Response form submits", async () => {
    await uiPage.goto("http://localhost:3000/agents/feedback");
    await uiPage.waitForTimeout(1500);

    // Find the response textarea and type a response
    const textarea = uiPage.getByTestId("response-textarea").first();
    await textarea.fill(`Yes, deploy to production (${TS})`);
    await uiPage.getByRole("button", { name: "Send Response" }).first().click();

    // Verify the request moves to responded status
    await uiPage.waitForTimeout(1500);
    // After responding, the pending badge count should decrease
    // and the card should either disappear or show responded status
    const resp = await apiGet(
      uiPage,
      `ui/agent/feedback/${UI_WORKER}/${uiRequestId}`,
    );
    const data = await resp.json();
    expect(data.feedback_status).toBe("responded");
    expect(data.response_text).toContain("deploy to production");
  });

  test("648.4 No-requests empty state", async () => {
    // Navigate to feedback for a non-existent worker
    const emptyWorker = `empty-worker-${TS}`;
    // Create a fresh page to avoid any cached state
    const emptyPage = await newIdentityPage(
      uiPage.context().browser()!,
      "alice",
    );
    // Use the API to verify empty list
    const resp = await apiGet(emptyPage, `ui/agent/feedback/${emptyWorker}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.count).toBe(0);
    expect(data.requests).toEqual([]);
    await emptyPage.close();
  });
});
