/**
 * E2E tests for the Product Manager Agent (AGENT-013).
 *
 * Section 671: Feature Idea CRUD API
 * Section 672: Approval & Rejection Workflow API
 * Section 673: Preference Learning & Config API
 * Section 674: Feature Ideas UI
 * Section 675: Edge Cases
 * Section 676: Negative Tests
 *
 * Auth: cookie-based sessions from e2e_admin_session_setup.py.
 *   alice  – role=user (platform owner / primary actor)
 *   bob    – role=user (cross-user negative tests)
 * POST/PUT requests carry an x-csrf-token header.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";

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
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
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

// On a busy shard the shared backend can return 429 (rate limit). Retry a few
// times so idea-creation calls in beforeAll (whose ids dependent tests use) and
// the assertions themselves don't fail spuriously.
async function withRetry429(fn: () => Promise<any>) {
  let resp = await fn();
  for (let i = 0; i < 4 && resp.status() === 429; i++) {
    await new Promise((r) => setTimeout(r, 400 * (i + 1)));
    resp = await fn();
  }
  return resp;
}

async function apiPut(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return withRetry429(() =>
    page.request.put(`${API}/${path}`, {
      data: body ?? {},
      headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
    }),
  );
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown, csrf = true) {
  const sess = getSessions()[identity];
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (csrf) headers["x-csrf-token"] = sess.csrf_token;
  return withRetry429(() => page.request.post(`${API}/${path}`, { data: body ?? {}, headers }));
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return withRetry429(() => page.request.get(`${API}/${path}`, { params }));
}

const TS = Date.now();
const AGENT_ID = `pm_${TS}`;

// The PM-config `max_ideas_per_review` cap (default 5) is enforced PER agent_id
// across ALL of a user's *pending* ideas — and that pending set accumulates
// across every prior test run (GSI1PK is `USER#alice#STATUS#pending`, never
// wiped between runs). When many describe-blocks share a single agent_id, the
// 5th+ create in a shard run trips the cap and returns 400, leaving the
// dependent idea_id undefined → downstream lookups 404. Give each describe
// block its own agent_id so its create-count starts fresh and never collides
// with sibling blocks' (or prior runs') pending ideas.
let _agentSeq = 0;
function freshAgentId(label: string): string {
  _agentSeq += 1;
  return `pm_${TS}_${label}_${_agentSeq}`;
}

function ideaBody(overrides: Record<string, unknown> = {}) {
  return {
    agent_id: AGENT_ID,
    title: `Idea ${TS}_${Math.random().toString(36).slice(2, 7)}`,
    description: "Detailed rationale for this feature idea.",
    category: "feature",
    priority_suggestion: "high",
    user_impact: "Increases engagement by 20-30%.",
    evidence: [{ type: "screenshot", description: "feed flow" }],
    ...overrides,
  };
}

// ─── 671: Feature Idea CRUD API ──────────────────────────────────────────────

test.describe("671. Feature Idea CRUD API", () => {
  let alicePage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("671.1 create feature idea", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody());
    expect(r.status()).toBe(201);
    const data = (await r.json()) as Record<string, unknown>;
    expect(typeof data.idea_id).toBe("string");
    expect(data.status).toBe("pending");
    expect(data.category).toBe("feature");
    expect(data.priority_suggestion).toBe("high");
  });

  test("671.2 list pending ideas", async () => {
    const r = await apiGet(alicePage, "ui/agents/pm/ideas", { status: "pending" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { ideas: Array<Record<string, unknown>> };
    expect(Array.isArray(data.ideas)).toBe(true);
    expect(data.ideas.length).toBeGreaterThan(0);
    expect(data.ideas[0]).toHaveProperty("title");
    expect(data.ideas[0]).toHaveProperty("description");
    expect(data.ideas[0]).toHaveProperty("category");
  });

  test("671.3 get single idea detail", async () => {
    const c = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody());
    const ideaId = ((await c.json()) as Record<string, unknown>).idea_id as string;
    const r = await apiGet(alicePage, `ui/agents/pm/ideas/${ideaId}`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.idea_id).toBe(ideaId);
    expect(data.user_impact).toBe("Increases engagement by 20-30%.");
    expect(Array.isArray(data.evidence)).toBe(true);
  });

  test("671.4 create ideas with different categories", async () => {
    const r1 = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody({ category: "ux", priority_suggestion: "medium" }));
    const r2 = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody({ category: "monetization", priority_suggestion: "low" }));
    expect(r1.status()).toBe(201);
    expect(r2.status()).toBe(201);
    const list = await apiGet(alicePage, "ui/agents/pm/ideas", { status: "pending", limit: "100" });
    const data = (await list.json()) as { ideas: unknown[] };
    expect(data.ideas.length).toBeGreaterThanOrEqual(3);
  });
});

// ─── 672: Approval & Rejection Workflow API ──────────────────────────────────

test.describe("672. Approval & Rejection Workflow API", () => {
  let alicePage: Page;
  let approveId = "";
  let rejectId = "";
  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    // Give EACH create its own unique agent_id so the per-agent
    // `max_ideas_per_review` cap counts 0 pending at every insert. The cap is
    // enforced per agent_id across ALL of alice's accumulated pending ideas
    // (the `USER#alice#STATUS#pending` GSI partition is never wiped between
    // runs), and a prior interrupted run can leave the cap lowered (676.3 sets
    // it to 2 before resetting). A single shared agent_id here therefore trips
    // the cap on a busy shard, leaving the dependent idea_id undefined → the
    // reject lookup 404s. Unique agent_ids make each create independent of
    // both accumulation and any leaked low cap value.
    const a = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody({ agent_id: freshAgentId("approve") }));
    approveId = ((await a.json()) as Record<string, unknown>).idea_id as string;
    const r = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody({ agent_id: freshAgentId("reject"), category: "ux" }));
    rejectId = ((await r.json()) as Record<string, unknown>).idea_id as string;
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("672.1 approve idea creates ticket", async () => {
    const r = await apiPost(alicePage, "alice", `ui/agents/pm/ideas/${approveId}/approve`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.status).toBe("approved");
    expect(typeof data.created_ticket_id).toBe("string");
    expect((data.created_ticket_id as string).length).toBeGreaterThan(0);
  });

  test("672.2 reject idea with reason", async () => {
    // A Playwright retry can spawn a fresh worker that re-imports the module
    // with `rejectId` undefined (only the failing test re-runs, not beforeAll) →
    // reject of `/ideas/undefined` → 404. Re-create the idea in that case so the
    // test is self-healing while still rejecting the same idea 672.3/672.4 act on.
    if (!rejectId) {
      const c = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody({ agent_id: freshAgentId("reject"), category: "ux" }));
      expect(c.status()).toBe(201);
      rejectId = ((await c.json()) as Record<string, unknown>).idea_id as string;
    }
    const r = await apiPost(alicePage, "alice", `ui/agents/pm/ideas/${rejectId}/reject`, {
      reason: "Not aligned with roadmap",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.status).toBe("rejected");
    expect(data.rejection_reason).toBe("Not aligned with roadmap");
  });

  test("672.3 archive rejected idea", async () => {
    const r = await apiPost(alicePage, "alice", `ui/agents/pm/ideas/${rejectId}/archive`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.status).toBe("archived");
  });

  test("672.4 cannot approve already-archived idea", async () => {
    const r = await apiPost(alicePage, "alice", `ui/agents/pm/ideas/${rejectId}/approve`);
    expect(r.status()).toBe(409);
  });
});

// ─── 673: Preference Learning & Config API ───────────────────────────────────

test.describe("673. Preference Learning & Config API", () => {
  let alicePage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    // approve a monetization idea so its approval rate is 1.0
    const m = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody({ category: "monetization" }));
    const mid = ((await m.json()) as Record<string, unknown>).idea_id as string;
    await apiPost(alicePage, "alice", `ui/agents/pm/ideas/${mid}/approve`);
    // reject a performance idea
    const p = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody({ category: "performance" }));
    const pid = ((await p.json()) as Record<string, unknown>).idea_id as string;
    await apiPost(alicePage, "alice", `ui/agents/pm/ideas/${pid}/reject`, { reason: "later" });
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("673.1 preference summary reflects approvals", async () => {
    const r = await apiGet(alicePage, "ui/agents/pm/preferences");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { preferences: Array<Record<string, number | string>> };
    const mon = data.preferences.find((p) => p.category === "monetization");
    expect(mon).toBeDefined();
    expect(Number(mon!.total_approved)).toBeGreaterThanOrEqual(1);
  });

  test("673.2 preference summary reflects rejections", async () => {
    const r = await apiGet(alicePage, "ui/agents/pm/preferences");
    const data = (await r.json()) as { preferences: Array<Record<string, number | string>> };
    const perf = data.preferences.find((p) => p.category === "performance");
    expect(perf).toBeDefined();
    expect(Number(perf!.total_rejected)).toBeGreaterThanOrEqual(1);
  });

  test("673.3 approval rate computed correctly", async () => {
    const r = await apiGet(alicePage, "ui/agents/pm/preferences");
    const data = (await r.json()) as { preferences: Array<Record<string, number | string>> };
    const mon = data.preferences.find((p) => p.category === "monetization");
    expect(Number(mon!.approval_rate)).toBe(1.0);
  });

  test("673.4 update PM config", async () => {
    const r = await apiPut(alicePage, "alice", "ui/agents/pm/config", {
      review_frequency: "daily",
      max_ideas_per_review: 10,
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.review_frequency).toBe("daily");
    expect(data.max_ideas_per_review).toBe(10);
    // reset for downstream tests
    await apiPut(alicePage, "alice", "ui/agents/pm/config", {
      review_frequency: "weekly",
      max_ideas_per_review: 5,
    });
  });
});

// ─── 674: Feature Ideas UI ───────────────────────────────────────────────────

test.describe("674. Feature Ideas UI", () => {
  let alicePage: Page;
  let cardId = "";
  // Use a fresh, block-local agent_id so the per-agent pending-ideas cap
  // (max_ideas_per_review, default 5) starts from zero here. The shared
  // module-level AGENT_ID accumulates pending ideas across earlier describe
  // blocks AND prior runs, which trips the cap → create returns 400 →
  // idea_id is undefined → the card lookup times out.
  const UI_AGENT_ID = freshAgentId("ideas_ui");
  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    const r = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody({ agent_id: UI_AGENT_ID, category: "integration" }));
    cardId = ((await r.json()) as Record<string, unknown>).idea_id as string;
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("674.1 feature ideas page loads", async () => {
    await alicePage.goto("http://localhost:3000/agents/pm/ideas");
    await expect(alicePage.locator('[data-testid="feature-ideas-page"]')).toBeVisible({ timeout: 15_000 });
    await expect(alicePage.locator(`[data-testid="idea-card-${cardId}"]`)).toBeVisible({ timeout: 10_000 });
  });

  test("674.2 idea card shows category and priority badges", async () => {
    await alicePage.goto("http://localhost:3000/agents/pm/ideas");
    await expect(alicePage.locator(`[data-testid="idea-category-${cardId}"]`)).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.locator(`[data-testid="idea-priority-${cardId}"]`)).toBeVisible();
  });

  test("674.3 approve idea via UI", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody({ agent_id: UI_AGENT_ID, category: "ux" }));
    expect(r.status()).toBe(201);
    const id = ((await r.json()) as Record<string, unknown>).idea_id as string;
    expect(id, "create idea returned an idea_id").toBeTruthy();
    await alicePage.goto("http://localhost:3000/agents/pm/ideas");
    await alicePage.locator(`[data-testid="idea-card-${id}"]`).click();
    await expect(alicePage.locator('[data-testid="idea-detail-dialog"]')).toBeVisible({ timeout: 10_000 });
    await alicePage.locator('[data-testid="idea-approve-btn"]').click();
    await alicePage.getByRole("tab", { name: "Approved" }).click();
    await expect(alicePage.locator(`[data-testid="idea-card-${id}"]`)).toBeVisible({ timeout: 10_000 });
  });

  test("674.4 reject idea via UI", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody({ agent_id: UI_AGENT_ID, category: "feature" }));
    expect(r.status()).toBe(201);
    const id = ((await r.json()) as Record<string, unknown>).idea_id as string;
    expect(id, "create idea returned an idea_id").toBeTruthy();
    await alicePage.goto("http://localhost:3000/agents/pm/ideas");
    await alicePage.locator(`[data-testid="idea-card-${id}"]`).click();
    await expect(alicePage.locator('[data-testid="idea-detail-dialog"]')).toBeVisible({ timeout: 10_000 });
    await alicePage.locator('[data-testid="idea-reject-btn"]').click();
    await alicePage.locator('[data-testid="idea-reject-reason"]').fill("Not now");
    await alicePage.locator('[data-testid="idea-reject-confirm"]').click();
    await alicePage.getByRole("tab", { name: "Rejected" }).click();
    await expect(alicePage.locator(`[data-testid="idea-card-${id}"]`)).toBeVisible({ timeout: 10_000 });
  });
});

// ─── 675: Edge Cases ─────────────────────────────────────────────────────────

test.describe("675. Edge Cases", () => {
  let alicePage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("675.1 approve already-approved idea returns 409", async () => {
    const c = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody());
    const id = ((await c.json()) as Record<string, unknown>).idea_id as string;
    const first = await apiPost(alicePage, "alice", `ui/agents/pm/ideas/${id}/approve`);
    expect(first.status()).toBe(200);
    const second = await apiPost(alicePage, "alice", `ui/agents/pm/ideas/${id}/approve`);
    expect(second.status()).toBe(409);
  });

  test("675.2 reject without reason returns 422", async () => {
    const c = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody());
    const id = ((await c.json()) as Record<string, unknown>).idea_id as string;
    const r = await apiPost(alicePage, "alice", `ui/agents/pm/ideas/${id}/reject`, {});
    expect(r.status()).toBe(422);
  });

  test("675.3 list ideas with pagination", async () => {
    const r = await apiGet(alicePage, "ui/agents/pm/ideas", { status: "pending", limit: "2" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { ideas: unknown[]; next_cursor: string | null };
    expect(data.ideas.length).toBeLessThanOrEqual(2);
    if (data.next_cursor) {
      const r2 = await apiGet(alicePage, "ui/agents/pm/ideas", {
        status: "pending",
        limit: "2",
        cursor: data.next_cursor,
      });
      expect(r2.status()).toBe(200);
    }
  });

  test("675.4 trigger review then config max enforced", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/pm/trigger-review", {
      agent_id: `trig_${TS}`,
      count: 2,
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.ideas_created).toBe(2);
  });
});

// ─── 676: Negative Tests ─────────────────────────────────────────────────────

test.describe("676. Negative Tests", () => {
  let alicePage: Page;
  let bobPage: Page;
  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
  });
  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("676.1 other user cannot view alice's idea", async () => {
    const c = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody());
    const id = ((await c.json()) as Record<string, unknown>).idea_id as string;
    const r = await apiGet(bobPage, `ui/agents/pm/ideas/${id}`);
    expect([403, 404]).toContain(r.status());
  });

  test("676.2 invalid category rejected", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody({ category: "invalid" }));
    expect(r.status()).toBe(422);
  });

  test("676.3 exceed max_ideas_per_review", async () => {
    const agentId = `cap_${TS}`;
    await apiPut(alicePage, "alice", "ui/agents/pm/config", { max_ideas_per_review: 2 });
    const r1 = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody({ agent_id: agentId }));
    const r2 = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody({ agent_id: agentId }));
    const r3 = await apiPost(alicePage, "alice", "ui/agents/pm/ideas", ideaBody({ agent_id: agentId }));
    expect(r1.status()).toBe(201);
    expect(r2.status()).toBe(201);
    expect(r3.status()).toBe(400);
    await apiPut(alicePage, "alice", "ui/agents/pm/config", { max_ideas_per_review: 5 });
  });

  test("676.4 invalid review frequency rejected", async () => {
    const r = await apiPut(alicePage, "alice", "ui/agents/pm/config", { review_frequency: "hourly" });
    expect(r.status()).toBe(422);
  });

  test("676.5 unauthenticated request rejected", async ({ request }) => {
    const r = await request.get(`${API}/ui/agents/pm/ideas`);
    expect([401, 403]).toContain(r.status());
  });
});
