/**
 * E2E tests for CREATOR-001: Collaboration Requests.
 *
 * Sections:
 *   1 — Create collaboration request API (5 tests)
 *   2 — Accept/reject/cancel API (5 tests)
 *   3 — Counter-propose + revision history API (5 tests)
 *   4 — Terminate collaboration API (3 tests)
 *   5 — List + filter collaborations API (4 tests)
 *   6 — Per-creator settings API (4 tests)
 *   7 — Revenue split ledger API (4 tests)
 *   8 — CollaborationsPage UI (5 tests)
 *
 * Auth: Alice + Bob sessions (from e2e_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE      = "http://localhost:3000";
const ALICE_ID  = "e2e_alice@test.local";
const BOB_ID    = "e2e_bob@test.local";
const TS        = Date.now();

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

const sessions = getSessions();
const aliceSub = sessions[ALICE_ID].user_sub;
const bobSub   = sessions[BOB_ID].user_sub;

async function injectAuth(page: Page, identity: string) {
  const s = sessions[identity];
  await page.context().addCookies(s.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, s.user_sub);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body: unknown) {
  return page.request.post(`${BASE}${path}`, {
    headers: { "x-csrf-token": sessions[identity].csrf_token },
    data: body,
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

async function apiPut(page: Page, identity: string, path: string, body: unknown) {
  return page.request.put(`${BASE}${path}`, {
    headers: { "x-csrf-token": sessions[identity].csrf_token },
    data: body,
  });
}

/**
 * Cancel all pending/counter collaborations between Alice and Bob
 * to clean up state from previous test runs.
 */
async function cleanupPendingCollabs(page: Page) {
  const resp = await apiGet(page, "/ui/collaborations?status=pending,counter");
  if (resp.status() !== 200) return;
  const body = await resp.json();
  for (const item of body.items || []) {
    // Cancel if Alice is initiator, otherwise skip
    if (item.initiator_id === aliceSub) {
      await apiPost(page, ALICE_ID, `/ui/collaborations/${item.collaboration_id}/cancel`, {});
    }
  }
}

// ─── Shared state ─────────────────────────────────────────────────────────────

let collabId_s1: string;

// ==========================================================================
// Section 1: Create collaboration request API
// ==========================================================================
test.describe("1 — Create collaboration request API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    // Clean up any pending collabs from previous runs
    await cleanupPendingCollabs(alicePage);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("1.1 — Alice creates a collaboration proposal to Bob", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/collaborations", {
      recipient_id: bobSub,
      content_types: ["broadcast", "post"],
      split_pct: 60,
      title: `E2E Collab ${TS}`,
      description: "Test collaboration",
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.status).toBe("pending");
    expect(body.initiator_id).toBe(aliceSub);
    expect(body.recipient_id).toBe(bobSub);
    expect(body.split[aliceSub]).toBe(60);
    expect(body.split[bobSub]).toBe(40);
    expect(body.title).toBe(`E2E Collab ${TS}`);
    expect(body.revision).toBe(1);
    collabId_s1 = body.collaboration_id;
  });

  test("1.2 — Self-collaboration returns 400", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/collaborations", {
      recipient_id: aliceSub,
      content_types: ["post"],
      split_pct: 50,
      title: "Self collab",
    });
    expect(resp.status()).toBe(400);
  });

  test("1.3 — Alice can GET her collaboration by ID", async () => {
    const resp = await apiGet(alicePage, `/ui/collaborations/${collabId_s1}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.collaboration_id).toBe(collabId_s1);
    expect(body.status).toBe("pending");
  });

  test("1.4 — Alice lists collaborations (role=any)", async () => {
    const resp = await apiGet(alicePage, "/ui/collaborations?role=any");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.items.length).toBeGreaterThanOrEqual(1);
    const found = body.items.find((i: any) => i.collaboration_id === collabId_s1);
    expect(found).toBeTruthy();
  });

  test("1.5 — Duplicate pending request returns 409", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/collaborations", {
      recipient_id: bobSub,
      content_types: ["post"],
      split_pct: 50,
      title: "Dup collab",
    });
    expect(resp.status()).toBe(409);
  });
});

// ==========================================================================
// Section 2: Accept/reject/cancel API
// ==========================================================================
test.describe("2 — Accept/reject/cancel API", () => {
  let alicePage: Page;
  let bobPage: Page;
  // Only ONE pending collab can exist between Alice & Bob at a time.
  // Each test creates its own collab inline.
  let acceptCollabId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);

    // Clean up any pending collabs from previous runs
    await cleanupPendingCollabs(alicePage);

    // Create ONE collab for the accept tests (2.1 + 2.2)
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/collaborations", {
      recipient_id: bobSub,
      content_types: ["post"],
      split_pct: 55,
      title: `S2-accept-${TS}`,
    });
    expect(resp.status()).toBe(201);
    acceptCollabId = (await resp.json()).collaboration_id;
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("2.1 — Initiator cannot accept own proposal", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${acceptCollabId}/accept`, {});
    expect(resp.status()).toBe(403);
  });

  test("2.2 — Bob accepts the collaboration", async () => {
    const resp = await apiPost(bobPage, BOB_ID, `/ui/collaborations/${acceptCollabId}/accept`, {});
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("accepted");
    expect(body.accepted_at).toBeTruthy();
  });

  test("2.3 — Bob rejects the collaboration", async () => {
    // Create a fresh collab for reject (slot freed after 2.2 accepted)
    const createResp = await apiPost(alicePage, ALICE_ID, "/ui/collaborations", {
      recipient_id: bobSub,
      content_types: ["post"],
      split_pct: 55,
      title: `S2-reject-${TS}`,
    });
    expect(createResp.status()).toBe(201);
    const rejectId = (await createResp.json()).collaboration_id;
    const resp = await apiPost(bobPage, BOB_ID, `/ui/collaborations/${rejectId}/reject`, {});
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("rejected");
  });

  test("2.4 — Alice cancels the collaboration", async () => {
    // Create a fresh collab for cancel (slot freed after 2.3 rejected)
    const createResp = await apiPost(alicePage, ALICE_ID, "/ui/collaborations", {
      recipient_id: bobSub,
      content_types: ["post"],
      split_pct: 55,
      title: `S2-cancel-${TS}`,
    });
    expect(createResp.status()).toBe(201);
    const cancelId = (await createResp.json()).collaboration_id;
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${cancelId}/cancel`, {});
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("cancelled");
  });

  test("2.5 — Bob cannot cancel (not initiator)", async () => {
    // Create a new one to test (slot freed after 2.4 cancelled)
    const createResp = await apiPost(alicePage, ALICE_ID, "/ui/collaborations", {
      recipient_id: bobSub,
      content_types: ["post"],
      split_pct: 50,
      title: `S2-bob-cancel-${TS}`,
    });
    expect(createResp.status()).toBe(201);
    const cid = (await createResp.json()).collaboration_id;
    const resp = await apiPost(bobPage, BOB_ID, `/ui/collaborations/${cid}/cancel`, {});
    expect(resp.status()).toBe(403);
    // Clean up
    await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${cid}/cancel`, {});
  });
});

// ==========================================================================
// Section 3: Counter-propose + revision history API
// ==========================================================================
test.describe("3 — Counter-propose + revision history API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let collabId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);

    // Clean up pending collabs
    await cleanupPendingCollabs(alicePage);

    // Create a collab for counter-propose tests
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/collaborations", {
      recipient_id: bobSub,
      content_types: ["broadcast", "post"],
      split_pct: 70,
      title: `S3-counter-${TS}`,
      terms_text: "Original terms",
    });
    expect(resp.status()).toBe(201);
    collabId = (await resp.json()).collaboration_id;
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("3.1 — Bob counter-proposes with 50/50 split", async () => {
    const resp = await apiPost(bobPage, BOB_ID, `/ui/collaborations/${collabId}/counter`, {
      counter_split_pct: 50,
      counter_terms_text: "Counter terms",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("counter");
    expect(body.split[aliceSub]).toBe(50);
    expect(body.split[bobSub]).toBe(50);
    expect(body.revision).toBe(2);
    expect(body.last_proposed_by).toBe(bobSub);
  });

  test("3.2 — Bob cannot counter own counter (must wait for Alice)", async () => {
    const resp = await apiPost(bobPage, BOB_ID, `/ui/collaborations/${collabId}/counter`, {
      counter_split_pct: 45,
    });
    expect(resp.status()).toBe(403);
  });

  test("3.3 — Alice counter-proposes back with 55/45", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${collabId}/counter`, {
      counter_split_pct: 55,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.revision).toBe(3);
    expect(body.split[aliceSub]).toBe(55);
    expect(body.last_proposed_by).toBe(aliceSub);
  });

  test("3.4 — Revision history shows 2 revisions", async () => {
    const resp = await apiGet(alicePage, `/ui/collaborations/${collabId}/revisions`);
    expect(resp.status()).toBe(200);
    const revisions = await resp.json();
    expect(revisions.length).toBe(2);
    expect(revisions[0].revision).toBe(1);
    expect(revisions[0].split[aliceSub]).toBe(70);
    expect(revisions[0].status).toBe("superseded");
    expect(revisions[1].revision).toBe(2);
    expect(revisions[1].split[aliceSub]).toBe(50);
  });

  test("3.5 — Bob accepts the final counter-proposal", async () => {
    const resp = await apiPost(bobPage, BOB_ID, `/ui/collaborations/${collabId}/accept`, {});
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("accepted");
    expect(body.split[aliceSub]).toBe(55);
  });
});

// ==========================================================================
// Section 4: Terminate collaboration API
// ==========================================================================
test.describe("4 — Terminate collaboration API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let collabId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);

    // Clean up pending collabs
    await cleanupPendingCollabs(alicePage);

    // Create and accept a collab for termination
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/collaborations", {
      recipient_id: bobSub,
      content_types: ["post"],
      split_pct: 50,
      title: `S4-terminate-${TS}`,
    });
    expect(resp.status()).toBe(201);
    collabId = (await resp.json()).collaboration_id;

    const acceptResp = await apiPost(bobPage, BOB_ID, `/ui/collaborations/${collabId}/accept`, {});
    expect(acceptResp.status()).toBe(200);
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("4.1 — Cannot terminate a non-accepted collaboration", async () => {
    // Create a pending collab
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/collaborations", {
      recipient_id: bobSub,
      content_types: ["post"],
      split_pct: 50,
      title: `S4-pending-${TS}`,
    });
    expect(resp.status()).toBe(201);
    const pid = (await resp.json()).collaboration_id;
    const termResp = await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${pid}/terminate`, {});
    expect(termResp.status()).toBe(409);
    // Clean up
    await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${pid}/cancel`, {});
  });

  test("4.2 — Either party can terminate (Bob terminates)", async () => {
    const resp = await apiPost(bobPage, BOB_ID, `/ui/collaborations/${collabId}/terminate`, {
      reason: "No longer interested",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("terminated");
    expect(body.terminated_by).toBe(bobSub);
    expect(body.termination_reason).toBe("No longer interested");
  });

  test("4.3 — Cannot terminate already terminated collaboration", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${collabId}/terminate`, {});
    expect(resp.status()).toBe(409);
  });
});

// ==========================================================================
// Section 5: List + filter collaborations API
// ==========================================================================
test.describe("5 — List + filter collaborations API", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("5.1 — Alice lists all collaborations (role=any)", async () => {
    const resp = await apiGet(alicePage, "/ui/collaborations?role=any");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.items.length).toBeGreaterThanOrEqual(1);
  });

  test("5.2 — Filter by status=accepted returns only accepted", async () => {
    const resp = await apiGet(alicePage, "/ui/collaborations?status=accepted");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    for (const item of body.items) {
      expect(item.status).toBe("accepted");
    }
  });

  test("5.3 — Filter by status=terminated returns only terminated", async () => {
    const resp = await apiGet(alicePage, "/ui/collaborations?status=terminated");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    for (const item of body.items) {
      expect(item.status).toBe("terminated");
    }
  });

  test("5.4 — Bob can also list his collaborations", async () => {
    const resp = await apiGet(bobPage, "/ui/collaborations?role=any");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.items.length).toBeGreaterThanOrEqual(1);
  });
});

// ==========================================================================
// Section 6: Per-creator settings API
// ==========================================================================
test.describe("6 — Per-creator settings API", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);

    // Clean up pending collabs and reset settings
    await cleanupPendingCollabs(alicePage);
    await apiPut(bobPage, BOB_ID, "/ui/collaborations/settings", {
      accepting_requests: true,
      min_split_pct: 1,
    });
  });

  test.afterAll(async () => {
    // Restore Bob's settings
    await apiPut(bobPage, BOB_ID, "/ui/collaborations/settings", {
      accepting_requests: true,
      min_split_pct: 1,
    });
    await alicePage.close();
    await bobPage.close();
  });

  test("6.1 — GET default settings returns accepting_requests=true", async () => {
    const resp = await apiGet(alicePage, "/ui/collaborations/settings");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.accepting_requests).toBe(true);
    expect(body.min_split_pct).toBeGreaterThanOrEqual(1);
  });

  test("6.2 — PUT updates settings", async () => {
    const resp = await apiPut(bobPage, BOB_ID, "/ui/collaborations/settings", {
      accepting_requests: false,
      min_split_pct: 30,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.accepting_requests).toBe(false);
    expect(body.min_split_pct).toBe(30);
  });

  test("6.3 — Creating collab to non-accepting creator returns 403", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/collaborations", {
      recipient_id: bobSub,
      content_types: ["post"],
      split_pct: 50,
      title: `S6-blocked-${TS}`,
    });
    expect(resp.status()).toBe(403);
  });

  test("6.4 — Re-enable accepting and verify min_split_pct enforcement", async () => {
    // Re-enable accepting but with min_split_pct=30
    await apiPut(bobPage, BOB_ID, "/ui/collaborations/settings", {
      accepting_requests: true,
      min_split_pct: 30,
    });
    // Try to create with only 10% for Bob (i.e. 90% for Alice) - should fail
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/collaborations", {
      recipient_id: bobSub,
      content_types: ["post"],
      split_pct: 90,
      title: `S6-lowsplit-${TS}`,
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail).toContain("30%");
  });
});

// ==========================================================================
// Section 7: Revenue split ledger API
// ==========================================================================
test.describe("7 — Revenue split ledger API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let collabId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);

    // Reset Bob settings and clean up
    await apiPut(bobPage, BOB_ID, "/ui/collaborations/settings", {
      accepting_requests: true,
      min_split_pct: 1,
    });
    await cleanupPendingCollabs(alicePage);

    // Create and accept a collab for split testing
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/collaborations", {
      recipient_id: bobSub,
      content_types: ["broadcast", "post"],
      split_pct: 60,
      title: `S7-split-${TS}`,
    });
    expect(resp.status()).toBe(201);
    collabId = (await resp.json()).collaboration_id;

    const acceptResp = await apiPost(bobPage, BOB_ID, `/ui/collaborations/${collabId}/accept`, {});
    expect(acceptResp.status()).toBe(200);
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("7.1 — Split $10.00 (1000 cents) at 60/40", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${collabId}/split`, {
      collaboration_id: collabId,
      amount_cents: 1000,
      currency: "USD",
      content_type: "broadcast",
      content_id: "test_content_1",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.splits[aliceSub]).toBe(600);
    expect(body.splits[bobSub]).toBe(400);
  });

  test("7.2 — Split $10.33 (1033 cents) - verify rounding", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${collabId}/split`, {
      collaboration_id: collabId,
      amount_cents: 1033,
      currency: "USD",
      content_type: "post",
      content_id: "test_content_2",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    // floor(1033*40/100) = 413 for Bob
    // floor(1033*60/100) = 619 for Alice + remainder(1) = 620
    expect(body.splits[bobSub]).toBe(413);
    expect(body.splits[aliceSub]).toBe(620);
    expect(body.splits[aliceSub] + body.splits[bobSub]).toBe(1033);
  });

  test("7.3 — Split 1 cent - all goes to initiator", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${collabId}/split`, {
      collaboration_id: collabId,
      amount_cents: 1,
      currency: "USD",
      content_type: "broadcast",
      content_id: "test_content_3",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    // floor(1*60/100) = 0 for Alice initially, floor(1*40/100) = 0 for Bob
    // Remainder = 1 goes to initiator (Alice)
    expect(body.splits[aliceSub]).toBe(1);
  });

  test("7.4 — Revenue total is updated on the collaboration", async () => {
    const resp = await apiGet(alicePage, `/ui/collaborations/${collabId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    // 1000 + 1033 + 1 = 2034
    expect(body.total_revenue_cents).toBe(2034);
  });
});

// ==========================================================================
// Section 8: CollaborationsPage UI
// ==========================================================================
test.describe("8 — CollaborationsPage UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("8.1 — CollaborationsPage loads with tabs", async () => {
    await alicePage.goto(`${BASE}/collaborations`);
    await expect(alicePage.getByRole("heading", { name: "Collaborations", exact: true })).toBeVisible();
    await expect(alicePage.getByRole("tab", { name: /Active/i })).toBeVisible();
    await expect(alicePage.getByRole("tab", { name: /Pending/i })).toBeVisible();
    await expect(alicePage.getByRole("tab", { name: /History/i })).toBeVisible();
  });

  test("8.2 — New Collaboration button opens create dialog", async () => {
    await alicePage.goto(`${BASE}/collaborations`);
    await alicePage.getByRole("button", { name: /New Collaboration/i }).click();
    await expect(alicePage.getByRole("dialog")).toBeVisible();
    await expect(alicePage.getByText("Propose a collaboration")).toBeVisible();
    // Close dialog
    await alicePage.keyboard.press("Escape");
  });

  test("8.3 — History tab can be selected", async () => {
    await alicePage.goto(`${BASE}/collaborations`);
    const historyTab = alicePage.getByRole("tab", { name: /History/i });
    await historyTab.click();
    // Verify the tab is now selected (aria-selected="true")
    await expect(historyTab).toHaveAttribute("data-state", "active");
  });

  test("8.4 — Settings button opens settings dialog", async () => {
    await alicePage.goto(`${BASE}/collaborations`);
    await alicePage.getByRole("button", { name: /Settings/i }).first().click();
    await expect(alicePage.getByText("Collaboration Settings")).toBeVisible();
    await alicePage.keyboard.press("Escape");
  });

  test("8.5 — Page shows description text", async () => {
    await alicePage.goto(`${BASE}/collaborations`);
    await expect(alicePage.getByText("Manage creator partnerships and revenue splits")).toBeVisible();
  });
});
