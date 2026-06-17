/**
 * ENGAGE-002: Newsfeed Polls & Surveys E2E tests.
 *
 * Section 85: Poll API
 * Section 86: Poll Feed Rendering (UI)
 */
import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None";
    expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

/** POST helper that includes session cookies and CSRF header. */
async function feedPost(page: Page, path: string, body: object, userId = ALICE_ID) {
  const session = getSessions()[userId];
  return page.request.post(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body,
  });
}

async function feedGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function feedDelete(page: Page, path: string, userId = ALICE_ID) {
  const session = getSessions()[userId];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── Section 85: Poll API ─────────────────────────────────────────────────────

test.describe("85 — Poll API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let pollPostId: string;
  let questionId: string;
  let optionIds: string[];

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("85.1 Create a single-choice poll with 3 options", async () => {
    const resp = await feedPost(alicePage, "/posts", {
      body_plain: "What should I stream next?",
      post_type: "poll",
      // Public visibility so Bob (a non-follower) can cast votes — voting now
      // enforces the post visibility gate (GAP-0164: can_view_post on /vote).
      visibility: "public",
      poll_data: {
        questions: [
          {
            text: "What should I stream next?",
            choice_mode: "single",
            options: [
              { text: "Horror game" },
              { text: "Cooking stream" },
              { text: "Music session" },
            ],
          },
        ],
        anonymous: true,
        allow_vote_change: true,
      },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.post_type).toBe("poll");
    expect(data.poll_data).toBeTruthy();
    expect(data.poll_data.questions).toHaveLength(1);
    expect(data.poll_data.questions[0].options).toHaveLength(3);
    expect(data.poll_data.questions[0].question_id).toBeTruthy();
    expect(data.poll_data.questions[0].options[0].option_id).toBeTruthy();
    expect(data.poll_data.closed).toBe(false);
    pollPostId = data.post_id;
    questionId = data.poll_data.questions[0].question_id;
    optionIds = data.poll_data.questions[0].options.map(
      (o: { option_id: string }) => o.option_id,
    );
  });

  test("85.2 Vote for an option", async () => {
    const resp = await feedPost(bobPage, `/posts/${pollPostId}/vote`, {
      question_id: questionId,
      option_id: optionIds[0],
    }, BOB_ID);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.vote_counts[optionIds[0]]).toBe(1);
    expect(data.my_vote).toBe(optionIds[0]);
  });

  test("85.3 Vote for a different option (change vote)", async () => {
    const resp = await feedPost(bobPage, `/posts/${pollPostId}/vote`, {
      question_id: questionId,
      option_id: optionIds[1],
    }, BOB_ID);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.vote_counts[optionIds[0]]).toBe(0);
    expect(data.vote_counts[optionIds[1]]).toBe(1);
    expect(data.my_vote).toBe(optionIds[1]);
  });

  test("85.4 Duplicate vote is idempotent (same option)", async () => {
    const resp = await feedPost(bobPage, `/posts/${pollPostId}/vote`, {
      question_id: questionId,
      option_id: optionIds[1],
    }, BOB_ID);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.vote_counts[optionIds[1]]).toBe(1);
  });

  test("85.5 Delete vote", async () => {
    const resp = await feedDelete(
      bobPage,
      `/posts/${pollPostId}/vote?question_id=${questionId}`,
      BOB_ID,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.my_vote).toBeNull();
    expect(data.vote_counts[optionIds[1]]).toBe(0);
  });

  test("85.6 Poll results show correct percentages", async () => {
    // Alice votes for opt 0, Bob votes for opt 1
    await feedPost(alicePage, `/posts/${pollPostId}/vote`, {
      question_id: questionId,
      option_id: optionIds[0],
    });
    await feedPost(bobPage, `/posts/${pollPostId}/vote`, {
      question_id: questionId,
      option_id: optionIds[1],
    }, BOB_ID);

    const resp = await feedGet(
      alicePage,
      `/posts/${pollPostId}/poll-results?question_id=${questionId}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.total_votes).toBe(2);
    const opt0 = data.options.find(
      (o: { option_id: string }) => o.option_id === optionIds[0],
    );
    const opt1 = data.options.find(
      (o: { option_id: string }) => o.option_id === optionIds[1],
    );
    expect(opt0.count).toBe(1);
    expect(opt0.percentage).toBeCloseTo(50, 0);
    expect(opt1.count).toBe(1);
    expect(opt1.percentage).toBeCloseTo(50, 0);
  });

  test("85.7 Anonymous poll results omit voter list", async () => {
    const resp = await feedGet(
      alicePage,
      `/posts/${pollPostId}/poll-results?question_id=${questionId}`,
    );
    const data = await resp.json();
    for (const opt of data.options) {
      expect(opt.voters).toEqual([]);
    }
  });

  test("85.8 Creator manually closes poll", async () => {
    const resp = await feedPost(alicePage, `/posts/${pollPostId}/close-poll`, {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.closed).toBe(true);
  });

  test("85.9 Vote after poll closed returns 409", async () => {
    const resp = await feedPost(bobPage, `/posts/${pollPostId}/vote`, {
      question_id: questionId,
      option_id: optionIds[2],
    }, BOB_ID);
    expect(resp.status()).toBe(409);
  });

  test("85.10 Non-creator cannot close poll", async () => {
    // Create a new poll first
    const createResp = await feedPost(alicePage, "/posts", {
      body_plain: "Non-creator close test",
      post_type: "poll",
      poll_data: {
        questions: [
          {
            text: "Test?",
            choice_mode: "single",
            options: [{ text: "A" }, { text: "B" }],
          },
        ],
        anonymous: true,
        allow_vote_change: true,
      },
    });
    const newPoll = await createResp.json();
    const resp = await feedPost(
      bobPage,
      `/posts/${newPoll.post_id}/close-poll`,
      {},
      BOB_ID,
    );
    expect(resp.status()).toBe(403);
  });

  test("85.11 Poll with fewer than 2 options rejected", async () => {
    const resp = await feedPost(alicePage, "/posts", {
      body_plain: "Bad poll",
      post_type: "poll",
      poll_data: {
        questions: [
          {
            text: "Test?",
            choice_mode: "single",
            options: [{ text: "Only one" }],
          },
        ],
        anonymous: true,
        allow_vote_change: true,
      },
    });
    expect(resp.status()).toBe(422);
  });

  test("85.12 Create multi-choice poll and vote for 2 options", async () => {
    const createResp = await feedPost(alicePage, "/posts", {
      body_plain: "Multi-choice poll",
      post_type: "poll",
      poll_data: {
        questions: [
          {
            text: "Pick your favorites",
            choice_mode: "multi",
            options: [
              { text: "Pizza" },
              { text: "Sushi" },
              { text: "Tacos" },
            ],
          },
        ],
        anonymous: true,
        allow_vote_change: true,
      },
    });
    expect(createResp.status()).toBe(200);
    const poll = await createResp.json();
    const mQid = poll.poll_data.questions[0].question_id;
    const mOpts = poll.poll_data.questions[0].options;

    // Vote for first option
    const v1 = await feedPost(alicePage, `/posts/${poll.post_id}/vote`, {
      question_id: mQid,
      option_id: mOpts[0].option_id,
    });
    expect(v1.status()).toBe(200);

    // Vote for second option (multi-select)
    const v2 = await feedPost(alicePage, `/posts/${poll.post_id}/vote`, {
      question_id: mQid,
      option_id: mOpts[1].option_id,
    });
    expect(v2.status()).toBe(200);
    const v2Data = await v2.json();
    expect(v2Data.vote_counts[mOpts[0].option_id]).toBe(1);
    expect(v2Data.vote_counts[mOpts[1].option_id]).toBe(1);
    expect(v2Data.my_votes).toContain(mOpts[0].option_id);
    expect(v2Data.my_votes).toContain(mOpts[1].option_id);
  });

  test("85.13 Poll with allow_vote_change=false rejects vote change", async () => {
    const createResp = await feedPost(alicePage, "/posts", {
      body_plain: "No change poll",
      post_type: "poll",
      // Public so Bob can vote (voting enforces visibility gate, GAP-0164).
      visibility: "public",
      poll_data: {
        questions: [
          {
            text: "Pick one",
            choice_mode: "single",
            options: [{ text: "X" }, { text: "Y" }],
          },
        ],
        anonymous: true,
        allow_vote_change: false,
      },
    });
    const poll = await createResp.json();
    const qid = poll.poll_data.questions[0].question_id;
    const opts = poll.poll_data.questions[0].options;

    // First vote succeeds
    const v1 = await feedPost(bobPage, `/posts/${poll.post_id}/vote`, {
      question_id: qid,
      option_id: opts[0].option_id,
    }, BOB_ID);
    expect(v1.status()).toBe(200);

    // Attempt to change vote
    const v2 = await feedPost(bobPage, `/posts/${poll.post_id}/vote`, {
      question_id: qid,
      option_id: opts[1].option_id,
    }, BOB_ID);
    expect(v2.status()).toBe(409);
    const err = await v2.json();
    expect(err.detail.code).toBe("VOTE_CHANGE_DISABLED");
  });

  test("85.14 Poll appears in feed with poll_data", async () => {
    const createResp = await feedPost(alicePage, "/posts", {
      body_plain: "Feed poll test",
      post_type: "poll",
      poll_data: {
        questions: [
          {
            text: "In-feed poll?",
            choice_mode: "single",
            options: [{ text: "Yes" }, { text: "No" }],
          },
        ],
        anonymous: true,
        allow_vote_change: true,
      },
    });
    const poll = await createResp.json();

    const feedResp = await feedGet(alicePage, `/posts/${poll.post_id}`);
    expect(feedResp.status()).toBe(200);
    const feedData = await feedResp.json();
    expect(feedData.post_type).toBe("poll");
    expect(feedData.poll_data).toBeTruthy();
    expect(feedData.poll_data.questions).toHaveLength(1);
    expect(feedData.poll_vote_counts).toBeTruthy();
  });

  test("85.15 Non-anonymous poll results include voter IDs", async () => {
    const createResp = await feedPost(alicePage, "/posts", {
      body_plain: "Public vote poll",
      post_type: "poll",
      poll_data: {
        questions: [
          {
            text: "Public votes?",
            choice_mode: "single",
            options: [{ text: "Opt A" }, { text: "Opt B" }],
          },
        ],
        anonymous: false,
        allow_vote_change: true,
      },
    });
    const poll = await createResp.json();
    const qid = poll.poll_data.questions[0].question_id;
    const opts = poll.poll_data.questions[0].options;

    // Alice votes
    await feedPost(alicePage, `/posts/${poll.post_id}/vote`, {
      question_id: qid,
      option_id: opts[0].option_id,
    });

    const resultsResp = await feedGet(
      alicePage,
      `/posts/${poll.post_id}/poll-results?question_id=${qid}`,
    );
    const results = await resultsResp.json();
    const optA = results.options.find(
      (o: { option_id: string }) => o.option_id === opts[0].option_id,
    );
    expect(optA.voters).toContain(ALICE_ID);
  });
});
