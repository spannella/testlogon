import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

/* ------------------------------------------------------------------ */
/*  Live Q&A Mode (ENGAGE-003) — distinct /ui/live-qa implementation   */
/* ------------------------------------------------------------------ */

const API = "http://localhost:8000";
const BASE = "http://localhost:3000";
const TS = Date.now();

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

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  // ProtectedRoute gates UI routes on the persisted auth-store; cookies alone
  // are not enough for browser navigation. Seed it so /broadcast/* renders.
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

async function apiPost(page: Page, identity: string, path: string, body: object = {}) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiDelete(page: Page, identity: string, path: string) {
  const s = getSessions()[identity];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": s.csrf_token },
  });
}

const ALICE_ID = "alice"; // host
const BOB_ID = "bob"; // audience
const ROOT_ID = "root"; // second audience member

/** Create a live broadcast session owned by `host`, enable Live Q&A, return ids. */
async function createSession(page: Page, host: string): Promise<string> {
  const profResp = await apiPost(page, host, "/broadcast/profiles", {
    name: `LiveQA ${TS}-${Math.random().toString(36).slice(2, 6)}`,
    region: "us-east-1",
    rendition_preset: "720p30",
  });
  expect(profResp.status()).toBe(201);
  const profileId = (await profResp.json()).id;

  const sessResp = await apiPost(page, host, "/broadcast/sessions", { profile_id: profileId });
  expect(sessResp.status()).toBe(201);
  const sessionId = (await sessResp.json()).id;

  await apiPost(page, host, `/broadcast/sessions/${sessionId}/start`, { reason: "e2e-live-qa" });
  const modeResp = await apiPost(page, host, `/ui/live-qa/sessions/${sessionId}/mode`, {
    enabled: true,
  });
  expect(modeResp.status()).toBe(200);
  return sessionId;
}

async function submitQuestion(page: Page, identity: string, sessionId: string, text: string) {
  return apiPost(page, identity, `/ui/live-qa/sessions/${sessionId}/questions`, { text });
}

/* ------------------------------------------------------------------ */
/*  Section 89 — Q&A Mode Toggle API                                   */
/* ------------------------------------------------------------------ */

test.describe("Section 89 — Live Q&A Mode Toggle API", () => {
  let page: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    sessionId = await createSession(page, ALICE_ID);
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("89.1 Enable Q&A mode on active session", async () => {
    const resp = await apiPost(page, ALICE_ID, `/ui/live-qa/sessions/${sessionId}/mode`, {
      enabled: true,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.qa_mode_enabled).toBe(true);
  });

  test("89.2 Disable Q&A mode", async () => {
    const resp = await apiPost(page, ALICE_ID, `/ui/live-qa/sessions/${sessionId}/mode`, {
      enabled: false,
    });
    expect(resp.status()).toBe(200);
    expect((await resp.json()).qa_mode_enabled).toBe(false);
    // re-enable for later sections
    await apiPost(page, ALICE_ID, `/ui/live-qa/sessions/${sessionId}/mode`, { enabled: true });
  });

  test("89.3 Non-owner cannot toggle Q&A mode", async () => {
    const ctx = await page.context().browser()!.newContext();
    const bobPage = await ctx.newPage();
    await injectAuth(bobPage, BOB_ID);
    const resp = await apiPost(bobPage, BOB_ID, `/ui/live-qa/sessions/${sessionId}/mode`, {
      enabled: true,
    });
    expect(resp.status()).toBe(403);
    await ctx.close();
  });

  test("89.4 Toggle on non-existent session returns 404", async () => {
    const resp = await apiPost(page, ALICE_ID, `/ui/live-qa/sessions/nope-${TS}/mode`, {
      enabled: true,
    });
    expect(resp.status()).toBe(404);
  });

  test("89.5 Q&A mode state readable via GET", async () => {
    const resp = await apiGet(page, `/ui/live-qa/sessions/${sessionId}/mode`);
    expect(resp.status()).toBe(200);
    expect((await resp.json()).qa_mode_enabled).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 90 — Question Submission API                               */
/* ------------------------------------------------------------------ */

test.describe("Section 90 — Question Submission API", () => {
  let page: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    sessionId = await createSession(page, ALICE_ID);
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("90.1 Viewer submits a question", async () => {
    const ctx = await page.context().browser()!.newContext();
    const bobPage = await ctx.newPage();
    await injectAuth(bobPage, BOB_ID);
    const resp = await submitQuestion(bobPage, BOB_ID, sessionId, `Q-90-1-${TS}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.question_id).toBeTruthy();
    expect(body.status).toBe("pending");
    expect(body.vote_count).toBe(0);
    await ctx.close();
  });

  test("90.3 Rate-limited viewer gets 429 on rapid second submit", async () => {
    const ctx = await page.context().browser()!.newContext();
    const bobPage = await ctx.newPage();
    await injectAuth(bobPage, BOB_ID);
    const first = await submitQuestion(bobPage, BOB_ID, sessionId, `Q-90-3a-${TS}`);
    expect([200, 429]).toContain(first.status());
    const second = await submitQuestion(bobPage, BOB_ID, sessionId, `Q-90-3b-${TS}`);
    expect(second.status()).toBe(429);
    expect((await second.json()).detail.code).toBe("LIVE_QA_RATE_LIMITED");
    await ctx.close();
  });

  test("90.5 Submission rejected when Q&A disabled", async () => {
    await apiPost(page, ALICE_ID, `/ui/live-qa/sessions/${sessionId}/mode`, { enabled: false });
    const ctx = await page.context().browser()!.newContext();
    const rootPage = await ctx.newPage();
    await injectAuth(rootPage, ROOT_ID);
    const resp = await submitQuestion(rootPage, ROOT_ID, sessionId, `Q-90-5-${TS}`);
    expect(resp.status()).toBe(400);
    expect((await resp.json()).detail.code).toBe("LIVE_QA_DISABLED");
    await apiPost(page, ALICE_ID, `/ui/live-qa/sessions/${sessionId}/mode`, { enabled: true });
    await ctx.close();
  });

  test("90.6 Empty question text rejected (validation)", async () => {
    const ctx = await page.context().browser()!.newContext();
    const rootPage = await ctx.newPage();
    await injectAuth(rootPage, ROOT_ID);
    const resp = await submitQuestion(rootPage, ROOT_ID, sessionId, "");
    expect(resp.status()).toBe(422);
    await ctx.close();
  });

  test("90.8 Submitted question appears in pending queue", async () => {
    const ctx = await page.context().browser()!.newContext();
    const rootPage = await ctx.newPage();
    await injectAuth(rootPage, ROOT_ID);
    const text = `Q-90-8-${TS}`;
    const sub = await submitQuestion(rootPage, ROOT_ID, sessionId, text);
    expect(sub.status()).toBe(200);
    await ctx.close();

    const listResp = await apiGet(page, `/ui/live-qa/sessions/${sessionId}/questions?status=pending`);
    expect(listResp.status()).toBe(200);
    const body = await listResp.json();
    expect(body.questions.some((q: { text: string }) => q.text === text)).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 91 — Queue & Host Actions API                              */
/* ------------------------------------------------------------------ */

test.describe("Section 91 — Queue & Host Actions API", () => {
  let page: Page;
  let sessionId: string;
  let qid1: string;
  let qid2: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    sessionId = await createSession(page, ALICE_ID);

    // submit two questions from distinct users (avoid rate limit)
    const bobCtx = await browser.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);
    qid1 = (await (await submitQuestion(bobPage, BOB_ID, sessionId, `Q-91-1-${TS}`)).json()).question_id;
    await bobCtx.close();

    const rootCtx = await browser.newContext();
    const rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);
    qid2 = (await (await submitQuestion(rootPage, ROOT_ID, sessionId, `Q-91-2-${TS}`)).json()).question_id;
    await rootCtx.close();
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("91.1 List pending questions sorted by votes descending", async () => {
    // give qid2 a vote so it should sort first
    await apiPost(page, ALICE_ID, `/ui/live-qa/sessions/${sessionId}/questions/${qid2}/vote`);
    const resp = await apiGet(page, `/ui/live-qa/sessions/${sessionId}/questions?status=pending`);
    const body = await resp.json();
    const counts = body.questions.map((q: { vote_count: number }) => q.vote_count);
    const sorted = [...counts].sort((a, b) => b - a);
    expect(counts).toEqual(sorted);
  });

  test("91.2 Feature a question", async () => {
    const resp = await apiPost(page, ALICE_ID, `/ui/live-qa/sessions/${sessionId}/questions/${qid1}/feature`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("featured");
    expect(body.featured_at).toBeGreaterThan(0);
  });

  test("91.3 Featuring a new question unfeatures the previous", async () => {
    await apiPost(page, ALICE_ID, `/ui/live-qa/sessions/${sessionId}/questions/${qid2}/feature`);
    const q1 = await (await apiGet(page, `/ui/live-qa/sessions/${sessionId}/questions?status=answered`)).json();
    expect(q1.questions.some((q: { question_id: string }) => q.question_id === qid1)).toBe(true);
    const featured = await apiGet(page, `/ui/live-qa/sessions/${sessionId}/featured`);
    expect(featured.status()).toBe(200);
    expect((await featured.json()).question_id).toBe(qid2);
  });

  test("91.4 Answer a featured question", async () => {
    const resp = await apiPost(page, ALICE_ID, `/ui/live-qa/sessions/${sessionId}/questions/${qid2}/answer`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("answered");
    expect(body.answered_at).toBeGreaterThan(0);
  });

  test("91.5 Dismiss a pending question", async () => {
    // Use a fresh session so Bob's per-(session,user) submit rate-limit bucket
    // (one question / 30s) is empty — he already submitted to `sessionId` above.
    const fresh = await createSession(page, ALICE_ID);
    const bobCtx = await page.context().browser()!.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);
    const subResp = await submitQuestion(bobPage, BOB_ID, fresh, `Q-91-5-${TS}`);
    expect(subResp.status()).toBe(200);
    const qid = (await subResp.json()).question_id;
    await bobCtx.close();

    const resp = await apiPost(page, ALICE_ID, `/ui/live-qa/sessions/${fresh}/questions/${qid}/dismiss`);
    expect(resp.status()).toBe(200);
    expect((await resp.json()).status).toBe("dismissed");
  });

  test("91.6 Host removes a question (soft delete, hidden)", async () => {
    const fresh = await createSession(page, ALICE_ID);
    const rootCtx = await page.context().browser()!.newContext();
    const rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);
    const subResp = await submitQuestion(rootPage, ROOT_ID, fresh, `Q-91-6-${TS}`);
    expect(subResp.status()).toBe(200);
    const qid = (await subResp.json()).question_id;
    await rootCtx.close();

    const resp = await apiPost(page, ALICE_ID, `/ui/live-qa/sessions/${fresh}/questions/${qid}/remove`);
    expect(resp.status()).toBe(200);
    expect((await resp.json()).ok).toBe(true);

    const list = await (await apiGet(page, `/ui/live-qa/sessions/${fresh}/questions?status=pending`)).json();
    expect(list.questions.some((q: { question_id: string }) => q.question_id === qid)).toBe(false);
  });

  test("91.7 Non-host/non-moderator cannot feature", async () => {
    const bobCtx = await page.context().browser()!.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);
    const resp = await apiPost(bobPage, BOB_ID, `/ui/live-qa/sessions/${sessionId}/questions/${qid1}/feature`);
    expect(resp.status()).toBe(403);
    await bobCtx.close();
  });

  test("91.9 Get featured question when none returns 204", async () => {
    const fresh = await createSession(page, ALICE_ID);
    const resp = await apiGet(page, `/ui/live-qa/sessions/${fresh}/featured`);
    expect(resp.status()).toBe(204);
  });

  test("91.10 Regular viewer cannot view pending queue", async () => {
    const bobCtx = await page.context().browser()!.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);
    const resp = await bobPage.request.get(
      `${API}/ui/live-qa/sessions/${sessionId}/questions?status=pending`,
    );
    expect(resp.status()).toBe(403);
    await bobCtx.close();
  });

  test("91.11 Regular viewer can view answered queue", async () => {
    const bobCtx = await page.context().browser()!.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);
    const resp = await bobPage.request.get(
      `${API}/ui/live-qa/sessions/${sessionId}/questions?status=answered`,
    );
    expect(resp.status()).toBe(200);
    await bobCtx.close();
  });

  test("91.12 Pin a question floats it to the top", async () => {
    const fresh = await createSession(page, ALICE_ID);
    const bobCtx = await page.context().browser()!.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);
    const subResp = await submitQuestion(bobPage, BOB_ID, fresh, `Q-91-12-${TS}`);
    expect(subResp.status()).toBe(200);
    const qid = (await subResp.json()).question_id;
    await bobCtx.close();

    const resp = await apiPost(page, ALICE_ID, `/ui/live-qa/sessions/${fresh}/questions/${qid}/pin`, {
      pinned: true,
    });
    expect(resp.status()).toBe(200);
    expect((await resp.json()).pinned).toBe(true);

    const list = await (await apiGet(page, `/ui/live-qa/sessions/${fresh}/questions?status=pending`)).json();
    expect(list.questions[0].question_id).toBe(qid);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 92 — Upvote API                                            */
/* ------------------------------------------------------------------ */

test.describe("Section 92 — Upvote API", () => {
  let page: Page;
  let sessionId: string;
  let qid: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    sessionId = await createSession(page, ALICE_ID);

    const bobCtx = await browser.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);
    qid = (await (await submitQuestion(bobPage, BOB_ID, sessionId, `Q-92-${TS}`)).json()).question_id;
    await bobCtx.close();
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("92.1 Upvote a question increments count", async () => {
    const resp = await apiPost(page, ALICE_ID, `/ui/live-qa/sessions/${sessionId}/questions/${qid}/vote`);
    expect(resp.status()).toBe(200);
    expect((await resp.json()).vote_count).toBe(1);
  });

  test("92.3 Cannot upvote same question twice (idempotent)", async () => {
    const resp = await apiPost(page, ALICE_ID, `/ui/live-qa/sessions/${sessionId}/questions/${qid}/vote`);
    expect(resp.status()).toBe(200);
    expect((await resp.json()).vote_count).toBe(1);
  });

  test("92.4 Multiple users upvote increments to unique total", async () => {
    const bobCtx = await page.context().browser()!.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);
    const resp = await apiPost(bobPage, BOB_ID, `/ui/live-qa/sessions/${sessionId}/questions/${qid}/vote`);
    expect(resp.status()).toBe(200);
    expect((await resp.json()).vote_count).toBe(2);
    await bobCtx.close();
  });

  test("92.2 Remove upvote decrements count", async () => {
    const resp = await apiDelete(page, ALICE_ID, `/ui/live-qa/sessions/${sessionId}/questions/${qid}/vote`);
    expect(resp.status()).toBe(200);
    expect((await resp.json()).vote_count).toBe(1);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 93 — Q&A UI                                                 */
/* ------------------------------------------------------------------ */

test.describe("Section 93 — Live Q&A UI", () => {
  let page: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    sessionId = await createSession(page, ALICE_ID);
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("93.1 Live Q&A page renders the mode toggle", async () => {
    await page.goto(`/broadcast/${sessionId}/live-qa`);
    await expect(page.getByText("Live Q&A", { exact: true }).first()).toBeVisible({ timeout: 15_000 });
  });

  test("93.3 Host queue panel renders when Q&A enabled", async () => {
    await page.goto(`/broadcast/${sessionId}/live-qa`);
    await expect(page.getByTestId("live-qa-queue-panel")).toBeVisible({ timeout: 15_000 });
  });
});

/* ------------------------------------------------------------------ */
/*  Section 93b — Q&A Statistics API                                   */
/* ------------------------------------------------------------------ */

test.describe("Section 93b — Live Q&A Statistics API", () => {
  let page: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
    sessionId = await createSession(page, ALICE_ID);

    const bobCtx = await browser.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);
    const qid = (await (await submitQuestion(bobPage, BOB_ID, sessionId, `Q-93b-${TS}`)).json()).question_id;
    await bobCtx.close();

    await apiPost(page, ALICE_ID, `/ui/live-qa/sessions/${sessionId}/questions/${qid}/feature`);
    await apiPost(page, ALICE_ID, `/ui/live-qa/sessions/${sessionId}/questions/${qid}/answer`);
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("93b.1 Stats endpoint returns counts", async () => {
    const resp = await apiGet(page, `/ui/live-qa/sessions/${sessionId}/stats`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.total_questions).toBeGreaterThanOrEqual(1);
    expect(body.answered).toBeGreaterThanOrEqual(1);
  });

  test("93b.3 Non-host cannot access stats", async () => {
    const bobCtx = await page.context().browser()!.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);
    const resp = await bobPage.request.get(`${API}/ui/live-qa/sessions/${sessionId}/stats`);
    expect(resp.status()).toBe(403);
    await bobCtx.close();
  });
});
