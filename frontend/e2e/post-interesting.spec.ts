/**
 * E2E tests for FEED-007 — Mark Post Interesting.
 *
 * A per-viewer "interesting" signal (distinct from like/react) stored on the
 * billing table (PK=USER#{sub}, SK=POST_SIGNAL#{post_id}). Exercises the new
 * endpoints: POST /feed/interesting (toggle ON), POST /feed/uninteresting
 * (toggle OFF), GET /feed/interesting (list-my-interesting) plus the
 * is_interesting / interesting_count fields surfaced on the post response.
 *
 * Auth: cookie sessions seeded by e2e_session_setup.py; page.request carries the
 * browser-context cookies, so the backend uses session auth and enforces CSRF —
 * the session's csrf_token is sent as the x-csrf-token header on non-GET calls.
 */
import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

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
    _sessions = loadSessions();
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

function csrf(userId: string): string {
  return getSessions()[userId].csrf_token;
}

async function createPost(page: Page, userId: string, body: string): Promise<string> {
  const res = await page.request.post(`${BASE}/posts`, {
    headers: { "x-csrf-token": csrf(userId) },
    data: { body, visibility: "public" },
  });
  expect(res.ok(), `createPost failed: ${res.status()}`).toBeTruthy();
  const json = await res.json();
  return (json.post_id ?? json.id) as string;
}

async function getPost(page: Page, postId: string) {
  const res = await page.request.get(`${BASE}/posts/${postId}`);
  expect(res.ok(), `getPost failed: ${res.status()}`).toBeTruthy();
  return res.json();
}

async function mark(page: Page, userId: string, postId: string) {
  return page.request.post(`${BASE}/feed/interesting`, {
    headers: { "x-csrf-token": csrf(userId) },
    data: { post_id: postId },
  });
}

async function unmark(page: Page, userId: string, postId: string) {
  return page.request.post(`${BASE}/feed/uninteresting`, {
    headers: { "x-csrf-token": csrf(userId) },
    data: { post_id: postId },
  });
}

async function interestingIds(page: Page): Promise<string[]> {
  const res = await page.request.get(`${BASE}/feed/interesting?limit=200`);
  expect(res.ok()).toBeTruthy();
  return ((await res.json()).post_ids ?? []) as string[];
}

test.describe("Section: Mark Post Interesting (FEED-007)", () => {
  const TS = Date.now();
  let alicePage: Page;
  let bobPage: Page;
  let alicePost = "";
  let bobPost = "";

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    alicePost = await createPost(alicePage, ALICE_ID, `alice-interesting-${TS}`);
    bobPost = await createPost(bobPage, BOB_ID, `bob-interesting-${TS}`);
  });

  test("mark interesting sets is_interesting and increments the count", async () => {
    const before = await getPost(bobPage, alicePost);
    const baseCount = before.interesting_count ?? 0;

    const res = await mark(bobPage, BOB_ID, alicePost);
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.post_id).toBe(alicePost);
    expect(body.is_interesting).toBe(true);

    const after = await getPost(bobPage, alicePost);
    expect(after.is_interesting).toBe(true);
    expect(after.interesting_count).toBe(baseCount + 1);
  });

  test("list-my-interesting includes the marked post", async () => {
    expect(await interestingIds(bobPage)).toContain(alicePost);
  });

  test("mark is idempotent — count does not double on repeat", async () => {
    const before = await getPost(bobPage, alicePost);
    const res = await mark(bobPage, BOB_ID, alicePost);
    expect(res.ok()).toBeTruthy();
    expect((await res.json()).is_interesting).toBe(true);

    const after = await getPost(bobPage, alicePost);
    expect(after.interesting_count).toBe(before.interesting_count);
  });

  test("per-viewer isolation — bob's mark does not flip alice's view", async () => {
    const fromAlice = await getPost(alicePage, alicePost);
    expect(fromAlice.is_interesting).toBe(false);
    expect(await interestingIds(alicePage)).not.toContain(alicePost);
  });

  test("unmark clears is_interesting and decrements the count", async () => {
    const before = await getPost(bobPage, alicePost);
    const res = await unmark(bobPage, BOB_ID, alicePost);
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.is_interesting).toBe(false);

    const after = await getPost(bobPage, alicePost);
    expect(after.is_interesting).toBe(false);
    expect(after.interesting_count).toBe((before.interesting_count ?? 1) - 1);
    expect(await interestingIds(bobPage)).not.toContain(alicePost);
  });

  test("unmark is idempotent (no-op success on a non-marked post)", async () => {
    const res = await unmark(bobPage, BOB_ID, alicePost);
    expect(res.ok()).toBeTruthy();
    expect((await res.json()).is_interesting).toBe(false);

    const neverMarked = `p_never_${TS}`;
    const res2 = await unmark(bobPage, BOB_ID, neverMarked);
    expect(res2.ok()).toBeTruthy();
    expect((await res2.json()).is_interesting).toBe(false);
  });

  test("cannot mark your own post (400)", async () => {
    const res = await mark(bobPage, BOB_ID, bobPost);
    expect(res.status()).toBe(400);
    expect((await res.json()).detail).toContain("Cannot signal your own post");
  });

  test("marking a non-existent post returns 404", async () => {
    const res = await mark(bobPage, BOB_ID, `p_missing_${TS}`);
    expect(res.status()).toBe(404);
  });
});
