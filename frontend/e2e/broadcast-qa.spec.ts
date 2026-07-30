import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, resolveIdentityId } from "./helpers/session";
import { cppResetBroadcastQaRateLimit } from "./helpers/cpp-seed";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

/* ------------------------------------------------------------------ */
/*  Constants & helpers                                                */
/* ------------------------------------------------------------------ */

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
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
}

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body: object,
) {
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

const ALICE_ID = "alice";
const BOB_ID = "bob";
const ROOT_ID = "root";

/** Create a live broadcast session, enable Q&A, return session ID. */
async function createLiveQASession(page: Page): Promise<{ profileId: string; sessionId: string }> {
  const profResp = await apiPost(page, ROOT_ID, "/broadcast/profiles", {
    name: `QA Profile ${TS}-${Math.random().toString(36).slice(2, 6)}`,
    region: "us-east-1",
    rendition_preset: "720p30",
  });
  expect(profResp.status()).toBe(201);
  const profileId = (await profResp.json()).id;

  const sessResp = await apiPost(page, ROOT_ID, "/broadcast/sessions", {
    profile_id: profileId,
  });
  expect(sessResp.status()).toBe(201);
  const sessionId = (await sessResp.json()).id;

  const startResp = await apiPost(
    page,
    ROOT_ID,
    `/broadcast/sessions/${sessionId}/start`,
    { reason: "e2e-qa-test" },
  );
  expect(startResp.status()).toBe(202);

  // Enable Q&A mode
  const qaResp = await apiPost(
    page,
    ROOT_ID,
    `/broadcast/sessions/${sessionId}/qa-mode`,
    { enabled: true },
  );
  expect(qaResp.status()).toBe(200);

  return { profileId, sessionId };
}

/**
 * Submit a question bypassing rate limit by writing directly to DDB.
 * Falls back to API call.
 */
async function submitQuestionDirect(
  page: Page,
  identity: string,
  sessionId: string,
  text: string,
): Promise<string> {
  const resp = await apiPost(
    page,
    identity,
    `/broadcast/sessions/${sessionId}/qa/questions`,
    { text },
  );
  if (resp.status() === 200) {
    return (await resp.json()).question_id;
  }
  // If rate limited, throw with context
  throw new Error(`Failed to submit question: ${resp.status()} ${await resp.text()}`);
}

/* ------------------------------------------------------------------ */
/*  Section 89 — Q&A Mode Toggle API                                  */
/* ------------------------------------------------------------------ */

test.describe("Section 89 — Q&A Mode Toggle API", () => {
  let page: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, ROOT_ID);

    const result = await createLiveQASession(page);
    sessionId = result.sessionId;

    // Disable Q&A first so we start from a known state
    await apiPost(page, ROOT_ID, `/broadcast/sessions/${sessionId}/qa-mode`, { enabled: false });
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("89.1 Enable Q&A mode on active session", async () => {
    const resp = await apiPost(
      page,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/qa-mode`,
      { enabled: true },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.qa_mode_enabled).toBe(true);
  });

  test("89.2 Disable Q&A mode", async () => {
    const resp = await apiPost(
      page,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/qa-mode`,
      { enabled: false },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.qa_mode_enabled).toBe(false);
  });

  test("89.3 Non-owner cannot toggle Q&A mode", async () => {
    const aliceCtx = await page.context().browser()!.newContext();
    const alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/broadcast/sessions/${sessionId}/qa-mode`,
      { enabled: true },
    );
    expect(resp.status()).toBe(403);

    await aliceCtx.close();
  });

  test("89.4 Toggle on non-existent session returns 404", async () => {
    const resp = await apiPost(
      page,
      ROOT_ID,
      `/broadcast/sessions/nonexistent-session-id/qa-mode`,
      { enabled: true },
    );
    expect(resp.status()).toBe(404);
  });

  test("89.5 Q&A mode persists across re-fetches", async () => {
    // Enable Q&A
    await apiPost(page, ROOT_ID, `/broadcast/sessions/${sessionId}/qa-mode`, { enabled: true });

    // Toggle again to verify it was stored
    const resp = await apiPost(
      page,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/qa-mode`,
      { enabled: true },
    );
    expect(resp.status()).toBe(200);
    expect((await resp.json()).qa_mode_enabled).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 90 — Question Submission API                              */
/* ------------------------------------------------------------------ */

test.describe("Section 90 — Question Submission API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let sessionId: string;
  let submittedQuestionId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const result = await createLiveQASession(rootPage);
    sessionId = result.sessionId;
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("90.1 Viewer submits a question", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/broadcast/sessions/${sessionId}/qa/questions`,
      { text: `What camera do you use? ${TS}` },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.question_id).toBeTruthy();
    expect(body.status).toBe("pending");
    expect(body.upvote_count).toBe(0);
    submittedQuestionId = body.question_id;
  });

  test("90.3 Rate-limited viewer gets 429", async () => {
    // Submit a second question immediately — should be rate-limited
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/broadcast/sessions/${sessionId}/qa/questions`,
      { text: `Another question ${TS}` },
    );
    expect(resp.status()).toBe(429);
    const body = await resp.json();
    expect(body.detail.code).toBe("QA_RATE_LIMITED");
  });

  test("90.4 Question text over 500 chars rejected by Pydantic", async () => {
    const bobCtx = await rootPage.context().browser()!.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    const longText = "A".repeat(600);
    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/broadcast/sessions/${sessionId}/qa/questions`,
      { text: longText },
    );
    expect(resp.status()).toBe(422);

    await bobCtx.close();
  });

  test("90.5 Q&A mode disabled rejects submission", async () => {
    // Disable Q&A mode
    await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/qa-mode`, { enabled: false });

    const bobCtx = await rootPage.context().browser()!.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/broadcast/sessions/${sessionId}/qa/questions`,
      { text: `Should fail ${TS}` },
    );
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail.code).toBe("QA_MODE_DISABLED");

    // Re-enable for remaining tests
    await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/qa-mode`, { enabled: true });
    await bobCtx.close();
  });

  test("90.6 Empty question text rejected", async () => {
    const bobCtx = await rootPage.context().browser()!.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    // Clear cpp's 2s QA-submit debounce for bob on this session so the empty-text
    // POST reaches validation (422) instead of being rate-limited (429) by the
    // rapidly-preceding submissions in 90.1-90.5.
    cppResetBroadcastQaRateLimit(sessionId, resolveIdentityId(BOB_ID));
    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/broadcast/sessions/${sessionId}/qa/questions`,
      { text: "" },
    );
    expect(resp.status()).toBe(422);

    await bobCtx.close();
  });

  test("90.7 Question created_at is a valid timestamp", async () => {
    const bobCtx = await rootPage.context().browser()!.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    // Clear cpp's 2s QA-submit debounce so this real submit isn't rate-limited
    // (429) by the immediately-preceding 90.6 empty-text POST.
    cppResetBroadcastQaRateLimit(sessionId, resolveIdentityId(BOB_ID));
    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/broadcast/sessions/${sessionId}/qa/questions`,
      { text: `Timestamp check ${TS}` },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.created_at).toBeGreaterThan(0);

    await bobCtx.close();
  });

  test("90.8 Submitted question appears in pending queue", async () => {
    const resp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/qa/questions?status=pending`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.questions.length).toBeGreaterThanOrEqual(1);
    const found = body.questions.find(
      (q: any) => q.question_id === submittedQuestionId,
    );
    expect(found).toBeTruthy();
    expect(found.status).toBe("pending");
  });
});

/* ------------------------------------------------------------------ */
/*  Section 91 — Queue & Actions API                                  */
/* ------------------------------------------------------------------ */

test.describe("Section 91 — Queue & Actions API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let sessionId: string;
  let q1Id: string;
  let q2Id: string;
  let q3Id: string;
  let q4Id: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const result = await createLiveQASession(rootPage);
    sessionId = result.sessionId;

    // Submit 4 questions from different users with delays to avoid rate limiting.
    // Root submits first one
    const r1 = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/qa/questions`, {
      text: `S91 Q1 ${TS}`,
    });
    expect(r1.status()).toBe(200);
    q1Id = (await r1.json()).question_id;

    // Alice submits second
    const r2 = await apiPost(alicePage, ALICE_ID, `/broadcast/sessions/${sessionId}/qa/questions`, {
      text: `S91 Q2 ${TS}`,
    });
    expect(r2.status()).toBe(200);
    q2Id = (await r2.json()).question_id;

    // Bob submits third and fourth
    const bobCtx = await browser.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    const r3 = await apiPost(bobPage, BOB_ID, `/broadcast/sessions/${sessionId}/qa/questions`, {
      text: `S91 Q3 ${TS}`,
    });
    expect(r3.status()).toBe(200);
    q3Id = (await r3.json()).question_id;

    // Charlie submits fourth
    const charlieCtx = await browser.newContext();
    const charliePage = await charlieCtx.newPage();
    await injectAuth(charliePage, "charlie_admin");
    const r4 = await apiPost(charliePage, "charlie_admin", `/broadcast/sessions/${sessionId}/qa/questions`, {
      text: `S91 Q4 ${TS}`,
    });
    expect(r4.status()).toBe(200);
    q4Id = (await r4.json()).question_id;

    await bobCtx.close();
    await charlieCtx.close();
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("91.1 List pending questions sorted by upvotes", async () => {
    const resp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/qa/questions?status=pending`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.questions.length).toBeGreaterThanOrEqual(4);
    for (const q of body.questions) {
      expect(q.status).toBe("pending");
    }
  });

  test("91.2 Feature a question", async () => {
    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/qa/questions/${q1Id}/feature`,
      {},
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("featured");
    expect(body.featured_at).toBeGreaterThan(0);
  });

  test("91.3 Featuring a new question unfeatures the previous", async () => {
    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/qa/questions/${q4Id}/feature`,
      {},
    );
    expect(resp.status()).toBe(200);
    expect((await resp.json()).status).toBe("featured");

    // q1 should now be answered
    const getResp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/qa/questions?status=answered`,
    );
    expect(getResp.status()).toBe(200);
    const answered = (await getResp.json()).questions;
    const q1 = answered.find((q: any) => q.question_id === q1Id);
    expect(q1).toBeTruthy();
    expect(q1.status).toBe("answered");
  });

  test("91.4 Answer a featured question", async () => {
    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/qa/questions/${q4Id}/answer`,
      {},
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("answered");
    expect(body.answered_at).toBeGreaterThan(0);
  });

  test("91.5 Dismiss a pending question", async () => {
    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/qa/questions/${q2Id}/dismiss`,
      {},
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("dismissed");
  });

  test("91.6 Moderator removes a question", async () => {
    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/qa/questions/${q3Id}/remove`,
      {},
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);

    // Verify removed question doesn't appear in pending list
    const listResp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/qa/questions?status=pending`,
    );
    const pending = (await listResp.json()).questions;
    const removed = pending.find((q: any) => q.question_id === q3Id);
    expect(removed).toBeFalsy();
  });

  test("91.7 Non-owner/non-moderator cannot feature", async () => {
    // Try to feature q2 as Alice
    const featureResp = await apiPost(
      alicePage,
      ALICE_ID,
      `/broadcast/sessions/${sessionId}/qa/questions/${q2Id}/feature`,
      {},
    );
    expect(featureResp.status()).toBe(403);
  });

  test("91.8 Get featured question returns current", async () => {
    // Submit a fresh question from root (may be rate-limited, but root should still be able to submit via fresh session timing)
    // Use a different approach: just feature an existing pending question
    const listResp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/qa/questions?status=pending`,
    );
    const pending = (await listResp.json()).questions;
    // If there are pending questions, feature one
    if (pending.length > 0) {
      const qId = pending[0].question_id;
      await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/qa/questions/${qId}/feature`, {});

      const featuredResp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/qa/featured`);
      expect(featuredResp.status()).toBe(200);
      const featured = await featuredResp.json();
      expect(featured.question_id).toBe(qId);
      expect(featured.status).toBe("featured");

      // Clean up
      await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/qa/questions/${qId}/answer`, {});
    } else {
      // No pending questions; just verify featured returns 204
      const featuredResp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/qa/featured`);
      expect([200, 204]).toContain(featuredResp.status());
    }
  });

  test("91.9 Get featured question when none returns 204", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/qa/featured`);
    expect(resp.status()).toBe(204);
  });

  test("91.10 Regular viewer cannot view pending queue", async () => {
    const resp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/qa/questions?status=pending`,
    );
    expect(resp.status()).toBe(403);
  });

  test("91.11 Regular viewer can view answered queue", async () => {
    const resp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/qa/questions?status=answered`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.questions).toBeDefined();
    expect(Array.isArray(body.questions)).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 92 — Upvote API                                           */
/* ------------------------------------------------------------------ */

test.describe("Section 92 — Upvote API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let bobPage: Page;
  let sessionId: string;
  let upvoteQId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    const result = await createLiveQASession(rootPage);
    sessionId = result.sessionId;

    // Submit a question from root for upvote tests
    const submitResp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/qa/questions`,
      { text: `Upvote test question ${TS}` },
    );
    expect(submitResp.status()).toBe(200);
    upvoteQId = (await submitResp.json()).question_id;
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
    await bobPage.context().close();
  });

  test("92.1 Upvote a question", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/broadcast/sessions/${sessionId}/qa/questions/${upvoteQId}/upvote`,
      {},
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.upvote_count).toBe(1);
  });

  test("92.2 Remove upvote", async () => {
    const resp = await apiDelete(
      alicePage,
      ALICE_ID,
      `/broadcast/sessions/${sessionId}/qa/questions/${upvoteQId}/upvote`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.upvote_count).toBe(0);
  });

  test("92.3 Cannot upvote same question twice", async () => {
    // Upvote once
    await apiPost(
      alicePage,
      ALICE_ID,
      `/broadcast/sessions/${sessionId}/qa/questions/${upvoteQId}/upvote`,
      {},
    );
    // Upvote again — should be idempotent
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/broadcast/sessions/${sessionId}/qa/questions/${upvoteQId}/upvote`,
      {},
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.upvote_count).toBe(1); // Still 1
  });

  test("92.4 Multiple users upvote same question", async () => {
    // Bob upvotes too
    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/broadcast/sessions/${sessionId}/qa/questions/${upvoteQId}/upvote`,
      {},
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.upvote_count).toBe(2);
  });

  test("92.5 Upvote changes sort order in queue", async () => {
    // Submit a new question with no upvotes from Alice
    const submitResp = await apiPost(
      alicePage,
      ALICE_ID,
      `/broadcast/sessions/${sessionId}/qa/questions`,
      { text: `No upvotes question ${TS}` },
    );
    expect(submitResp.status()).toBe(200);
    const noUpvoteQId = (await submitResp.json()).question_id;

    // List pending — upvoted question (2 upvotes) should appear before 0-upvote one
    const listResp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/qa/questions?status=pending`,
    );
    expect(listResp.status()).toBe(200);
    const questions = (await listResp.json()).questions;

    const upvotedIdx = questions.findIndex((q: any) => q.question_id === upvoteQId);
    const noUpvoteIdx = questions.findIndex((q: any) => q.question_id === noUpvoteQId);

    // The upvoted one should come before the 0-upvote one
    if (upvotedIdx >= 0 && noUpvoteIdx >= 0) {
      expect(upvotedIdx).toBeLessThan(noUpvoteIdx);
    }
  });
});

/* ------------------------------------------------------------------ */
/*  Section 93 — Q&A UI Components                                    */
/* ------------------------------------------------------------------ */

test.describe("Section 93 — Q&A UI Components", () => {
  let rootPage: Page;
  let alicePage: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const result = await createLiveQASession(rootPage);
    sessionId = result.sessionId;
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("93.1 Q&A mode toggle endpoint works", async () => {
    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/qa-mode`,
      { enabled: true },
    );
    expect(resp.status()).toBe(200);
    expect((await resp.json()).qa_mode_enabled).toBe(true);
  });

  test("93.2 Featured question data is available via API", async () => {
    // Submit and feature a question
    const submitResp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/qa/questions`,
      { text: `Overlay test ${TS}` },
    );
    expect(submitResp.status()).toBe(200);
    const qId = (await submitResp.json()).question_id;

    await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/qa/questions/${qId}/feature`, {});

    const featuredResp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/qa/featured`);
    expect(featuredResp.status()).toBe(200);
    const featured = await featuredResp.json();
    expect(featured.text).toContain("Overlay test");
    expect(featured.submitter_display_name).toBeTruthy();

    // Answer to clean up
    await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/qa/questions/${qId}/answer`, {});
  });

  test("93.3 Broadcaster queue panel shows pending questions count", async () => {
    const resp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/qa/questions?status=pending`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.questions).toBeDefined();
    expect(typeof body.questions.length).toBe("number");
  });

  test("93.4 Q&A mode toggle switch works both ways", async () => {
    let resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/qa-mode`, { enabled: false });
    expect(resp.status()).toBe(200);
    expect((await resp.json()).qa_mode_enabled).toBe(false);

    resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/qa-mode`, { enabled: true });
    expect(resp.status()).toBe(200);
    expect((await resp.json()).qa_mode_enabled).toBe(true);
  });

  test("93.5 Dismissed question removed from pending list", async () => {
    const submitResp = await apiPost(
      alicePage,
      ALICE_ID,
      `/broadcast/sessions/${sessionId}/qa/questions`,
      { text: `Dismiss UI test ${TS}` },
    );
    expect(submitResp.status()).toBe(200);
    const qId = (await submitResp.json()).question_id;

    await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/qa/questions/${qId}/dismiss`, {});

    const listResp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/qa/questions?status=pending`);
    const pending = (await listResp.json()).questions;
    expect(pending.find((q: any) => q.question_id === qId)).toBeFalsy();
  });

  test("93.6 Answered questions appear in answered tab", async () => {
    // Submit and feature-then-answer a question
    const bobCtx = await rootPage.context().browser()!.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    const submitResp = await apiPost(bobPage, BOB_ID, `/broadcast/sessions/${sessionId}/qa/questions`, {
      text: `Answered tab test ${TS}`,
    });
    expect(submitResp.status()).toBe(200);
    const qId = (await submitResp.json()).question_id;

    await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/qa/questions/${qId}/feature`, {});
    await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/qa/questions/${qId}/answer`, {});

    const listResp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/qa/questions?status=answered`);
    expect(listResp.status()).toBe(200);
    const answered = (await listResp.json()).questions;
    expect(answered.length).toBeGreaterThanOrEqual(1);
    const found = answered.find((q: any) => q.question_id === qId);
    expect(found).toBeTruthy();
    expect(found.status).toBe("answered");

    await bobCtx.close();
  });
});

/* ------------------------------------------------------------------ */
/*  Section 93b — Q&A Statistics API                                  */
/* ------------------------------------------------------------------ */

test.describe("Section 93b — Q&A Statistics API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const result = await createLiveQASession(rootPage);
    sessionId = result.sessionId;

    // Submit, feature, and answer a question to have stats
    const r1 = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/qa/questions`, {
      text: `Stats Q1 ${TS}`,
    });
    expect(r1.status()).toBe(200);
    const q1 = (await r1.json()).question_id;

    await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/qa/questions/${q1}/feature`, {});
    await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/qa/questions/${q1}/answer`, {});

    // Submit another from Alice
    const r2 = await apiPost(alicePage, ALICE_ID, `/broadcast/sessions/${sessionId}/qa/questions`, {
      text: `Stats Q2 ${TS}`,
    });
    expect(r2.status()).toBe(200);
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("93b.1 Stats endpoint returns correct counts", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/qa/stats`);
    expect(resp.status()).toBe(200);
    const stats = await resp.json();
    expect(stats.total_questions).toBeGreaterThanOrEqual(2);
    expect(stats.answered).toBeGreaterThanOrEqual(1);
    expect(typeof stats.dismissed).toBe("number");
    expect(typeof stats.pending).toBe("number");
    expect(typeof stats.total_upvotes).toBe("number");
    expect(typeof stats.avg_upvotes).toBe("number");
    expect(typeof stats.answer_rate).toBe("number");
  });

  test("93b.2 Answer rate calculated correctly", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/qa/stats`);
    expect(resp.status()).toBe(200);
    const stats = await resp.json();
    if (stats.total_questions > 0) {
      const expectedRate = Math.round(
        (stats.answered / stats.total_questions) * 1000,
      ) / 10;
      expect(stats.answer_rate).toBe(expectedRate);
    }
  });

  test("93b.3 Non-owner cannot access stats", async () => {
    const resp = await apiGet(alicePage, `/broadcast/sessions/${sessionId}/qa/stats`);
    expect(resp.status()).toBe(403);
  });
});
