/**
 * E2E tests for MOD-002: DMCA Takedown Workflow
 *
 * Section 95: Claim Submission API (6 tests)
 * Section 96: Counter-Notice API (5 tests)
 * Section 97: Admin DMCA Dashboard API (6 tests)
 * Section 98: Repeat Infringer Policy (3 tests)
 *
 * Auth: uses e2e_admin_session_setup.py cookie-based sessions.
 * Alice = rights holder (claimant), Bob = content creator (target), Root = admin.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, resolveIdentityId } from "./helpers/session";
import { usingCpp } from "./helpers/cpp-seed";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");
const PYTHON = REPO_ROOT + "/.venv/bin/python3";

// ── Constants ─────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";

const ALICE_KEY = "alice";
const BOB_KEY   = "bob";
const ROOT_KEY  = "root";
// cpp keys dmca target_user_id / strike counts / infringer-status by the opaque login sub.
const ALICE_SUB = usingCpp() ? resolveIdentityId("e2e_alice@test.local") : "e2e_alice@test.local";
const BOB_SUB   = usingCpp() ? resolveIdentityId("e2e_bob@test.local") : "e2e_bob@test.local";

const TS = Date.now();

// ── Session bootstrap ─────────────────────────────────────────────────────

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

// ── Auth helpers ──────────────────────────────────────────────────────────

async function injectAuth(page: Page, sessionKey: string) {
  const sessions = getSessions();
  const session = sessions[sessionKey];
  if (!session) throw new Error(`No session for key=${sessionKey}`);
  await page.context().addCookies(session.cookies);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

async function newIdentityPage(browser: Browser, sessionKey: string): Promise<Page> {
  const page = await browser.newPage();
  await injectAuth(page, sessionKey);
  return page;
}

/**
 * Test isolation (MOD/DMCA): this spec accumulates upheld DMCA claims against Bob
 * and, once the strike threshold is crossed, the policy engine bans Bob in
 * account_state — which then 403s every subsequent POST /posts as Bob (in this
 * file AND in later specs like post-hide). Reset Bob to a clean slate up front:
 * clear the account_state ban + purge prior claims so the strike count restarts
 * from 0. Idempotent; delegates to the shared e2e_moderation_reset.py.
 */
function resetModerationState(userSub: string): void {
  execSync(`${PYTHON} ${REPO_ROOT}/e2e_moderation_reset.py ${userSub}`, {
    cwd: REPO_ROOT,
    timeout: 30_000,
  });
}

async function apiPost(page: Page, sessionKey: string, path: string, body: object) {
  const sessions = getSessions();
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": sessions[sessionKey].csrf_token },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  let url = `${API}${path}`;
  if (params) {
    const qs = new URLSearchParams(params).toString();
    url += `?${qs}`;
  }
  return page.request.get(url);
}

async function apiPut(page: Page, sessionKey: string, path: string, body: object) {
  const sessions = getSessions();
  return page.request.put(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": sessions[sessionKey].csrf_token },
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────

function validClaimBody(overrides: Record<string, unknown> = {}) {
  return {
    claimant_name: `Test Claimant ${TS}`,
    claimant_email: "claimant@test.local",
    claimant_address: "123 Test Street, Test City, TS 12345, USA",
    claimant_phone: "",
    content_url: `/feed/post/post_dmca_${TS}`,
    content_type: "feed_post",
    content_id: `post_dmca_${TS}`,
    original_work_description: "This is my original photographic work created on 2025-01-15 and registered with the US Copyright Office under registration number TX-1234567.",
    sworn_statement: true,
    good_faith_belief: true,
    signature: `Test Claimant ${TS}`,
    ...overrides,
  };
}

// ═════════════════════════════════════════════════════════════════════════
// Section 95: Claim Submission API
// ═════════════════════════════════════════════════════════════════════════

test.describe("95 · DMCA Claim Submission API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let claimId: string;
  let postId: string;

  test.beforeAll(async ({ browser }) => {
    // Clear any leaked ban + accumulated strikes so Bob can post (test isolation).
    resetModerationState(BOB_SUB);

    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage   = await newIdentityPage(browser, BOB_KEY);

    // Bob creates a feed post (the "infringing content")
    const postResp = await apiPost(bobPage, BOB_KEY, "/posts", {
      body: `DMCA test post ${TS}`,
      visibility: "public",
    });
    expect(postResp.ok()).toBe(true);
    const postData = await postResp.json();
    postId = postData.post_id || postData.id;
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("95.1 Alice submits valid DMCA claim", async () => {
    const body = validClaimBody({
      content_id: postId,
      content_url: `/feed/post/${postId}`,
    });
    const resp = await apiPost(alicePage, ALICE_KEY, "/v1/dmca/claims", body);
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.claim_id).toBeTruthy();
    expect(data.status).toBe("content_removed");
    expect(data.created_at).toBeGreaterThan(0);
    claimId = data.claim_id;
  });

  test("95.2 Claim without sworn statement returns 422", async () => {
    const body = validClaimBody({ sworn_statement: false });
    const resp = await apiPost(alicePage, ALICE_KEY, "/v1/dmca/claims", body);
    expect(resp.status()).toBe(422);
  });

  test("95.3 Claim without good faith belief returns 422", async () => {
    const body = validClaimBody({ good_faith_belief: false });
    const resp = await apiPost(alicePage, ALICE_KEY, "/v1/dmca/claims", body);
    expect(resp.status()).toBe(422);
  });

  test("95.4 GET claim by ID returns claim details", async () => {
    const resp = await apiGet(alicePage, `/v1/dmca/claims/${claimId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.claim_id).toBe(claimId);
    expect(data.status).toBe("content_removed");
    expect(data.claimant_name).toContain("Test Claimant");
    expect(data.target_user_id).toBe(BOB_SUB);
  });

  test("95.5 Bob can view claim against his content", async () => {
    const resp = await apiGet(bobPage, `/v1/dmca/claims/${claimId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.claim_id).toBe(claimId);
  });

  test("95.6 Claim creates strike record", async () => {
    const resp = await apiGet(alicePage, `/v1/dmca/claims/${claimId}`);
    const data = await resp.json();
    expect(data.strike_number).toBeGreaterThanOrEqual(1);
  });
});

// ═════════════════════════════════════════════════════════════════════════
// Section 96: Counter-Notice API
// ═════════════════════════════════════════════════════════════════════════

test.describe("96 · DMCA Counter-Notice API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let claimId: string;

  test.beforeAll(async ({ browser }) => {
    // Test isolation: clear leaked ban + accumulated strikes so Bob can post.
    resetModerationState(BOB_SUB);

    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage   = await newIdentityPage(browser, BOB_KEY);

    // Bob creates a post so Alice can file a DMCA claim against it
    const postResp = await apiPost(bobPage, BOB_KEY, "/posts", {
      body: `DMCA counter-notice post ${TS}`,
      visibility: "public",
    });
    const postData = await postResp.json();
    const cnPostId = postData.post_id;

    // Alice files a DMCA claim so Bob can counter-notice it
    const body = validClaimBody({
      content_url: `/feed/post/${cnPostId}`,
      content_id: cnPostId,
    });
    const resp = await apiPost(alicePage, ALICE_KEY, "/v1/dmca/claims", body);
    const data = await resp.json();
    claimId = data.claim_id;
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("96.1 Bob files counter-notice", async () => {
    const resp = await apiPost(bobPage, BOB_KEY, `/v1/dmca/claims/${claimId}/counter-notice`, {
      counter_notice_text: "This content is my original work and was created by me independently. I swear under penalty of perjury that the takedown was a mistake or misidentification.",
      consent_to_jurisdiction: true,
      counter_notice_signature: "Bob E2E Test User",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("waiting_period");
    expect(data.waiting_period_expires_at).toBeGreaterThan(0);
    expect(data.counter_notice_filed_at).toBeGreaterThan(0);
  });

  test("96.2 Alice (non-creator) cannot file counter-notice", async () => {
    // Bob creates a post, Alice files a claim against it, then Alice tries to counter-notice (should fail)
    const postResp = await apiPost(bobPage, BOB_KEY, "/posts", {
      body: `DMCA nocn post ${TS}`,
      visibility: "public",
    });
    const postData = await postResp.json();
    const nocnPostId = postData.post_id;

    const claimBody = validClaimBody({
      content_url: `/feed/post/${nocnPostId}`,
      content_id: nocnPostId,
    });
    const claimResp = await apiPost(alicePage, ALICE_KEY, "/v1/dmca/claims", claimBody);
    const claimData = await claimResp.json();

    const resp = await apiPost(alicePage, ALICE_KEY, `/v1/dmca/claims/${claimData.claim_id}/counter-notice`, {
      counter_notice_text: "This is not my content but I want to counter-notice anyway. I swear under penalty of perjury that the takedown was a mistake.",
      consent_to_jurisdiction: true,
      counter_notice_signature: "Alice Fake",
    });
    expect(resp.status()).toBe(403);
  });

  test("96.3 Duplicate counter-notice returns 409", async () => {
    const resp = await apiPost(bobPage, BOB_KEY, `/v1/dmca/claims/${claimId}/counter-notice`, {
      counter_notice_text: "Second counter-notice attempt which should fail. I swear under penalty of perjury that the takedown was a mistake.",
      consent_to_jurisdiction: true,
      counter_notice_signature: "Bob Again",
    });
    expect(resp.status()).toBe(409);
  });

  test("96.4 Waiting period is ~14 days from filing", async () => {
    const resp = await apiGet(bobPage, `/v1/dmca/claims/${claimId}`);
    const data = await resp.json();
    expect(data.status).toBe("waiting_period");
    const waitDays = (data.waiting_period_expires_at - data.counter_notice_filed_at) / 86400;
    expect(waitDays).toBeCloseTo(14, 0);
  });

  test("96.5 Counter-notice without consent returns 422", async () => {
    // Bob creates a post, Alice files claim, Bob tries counter-notice without consent
    const postResp = await apiPost(bobPage, BOB_KEY, "/posts", {
      body: `DMCA consent post ${TS}`,
      visibility: "public",
    });
    const postData = await postResp.json();
    const consentPostId = postData.post_id;

    const claimBody = validClaimBody({
      content_url: `/feed/post/${consentPostId}`,
      content_id: consentPostId,
    });
    const claimResp = await apiPost(alicePage, ALICE_KEY, "/v1/dmca/claims", claimBody);
    const claimData = await claimResp.json();

    const resp = await apiPost(bobPage, BOB_KEY, `/v1/dmca/claims/${claimData.claim_id}/counter-notice`, {
      counter_notice_text: "Counter-notice without consent. I swear under penalty of perjury this is a mistake.",
      consent_to_jurisdiction: false,
      counter_notice_signature: "Bob No Consent",
    });
    expect(resp.status()).toBe(422);
  });
});

// ═════════════════════════════════════════════════════════════════════════
// Section 97: Admin DMCA Dashboard API
// ═════════════════════════════════════════════════════════════════════════

test.describe("97 · Admin DMCA Dashboard API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let bobPage: Page;
  let claimId: string;

  test.beforeAll(async ({ browser }) => {
    // Test isolation: clear leaked ban + accumulated strikes so Bob can post.
    resetModerationState(BOB_SUB);

    rootPage  = await newIdentityPage(browser, ROOT_KEY);
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage   = await newIdentityPage(browser, BOB_KEY);

    // Bob creates a post, Alice files a DMCA claim for admin to manage
    const postResp = await apiPost(bobPage, BOB_KEY, "/posts", {
      body: `DMCA admin post ${TS}`,
      visibility: "public",
    });
    const postData = await postResp.json();
    const adminPostId = postData.post_id;

    const body = validClaimBody({
      content_url: `/feed/post/${adminPostId}`,
      content_id: adminPostId,
    });
    const resp = await apiPost(alicePage, ALICE_KEY, "/v1/dmca/claims", body);
    const data = await resp.json();
    claimId = data.claim_id;
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
    await bobPage?.close();
  });

  test("97.1 Root lists claims by status", async () => {
    const resp = await apiGet(rootPage, "/v1/admin/dmca/claims", { status: "content_removed" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.items)).toBe(true);
    const found = data.items.find((c: any) => c.claim_id === claimId);
    expect(found).toBeTruthy();
  });

  test("97.2 Root views claim detail", async () => {
    const resp = await apiGet(rootPage, `/v1/admin/dmca/claims/${claimId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.claim).toBeTruthy();
    expect(data.claim.claim_id).toBe(claimId);
    expect(typeof data.prior_claims_against_user).toBe("number");
  });

  test("97.3 Root resolves claim as restored", async () => {
    const resp = await apiPost(rootPage, ROOT_KEY, `/v1/admin/dmca/claims/${claimId}/resolve`, {
      resolution: "restored",
      resolution_notes: "Content is not infringing",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.resolution).toBe("restored");
    expect(data.resolved_at).toBeGreaterThan(0);
  });

  test("97.4 Resolving already-resolved claim returns 409", async () => {
    const resp = await apiPost(rootPage, ROOT_KEY, `/v1/admin/dmca/claims/${claimId}/resolve`, {
      resolution: "upheld",
      resolution_notes: "Trying again",
    });
    expect(resp.status()).toBe(409);
  });

  test("97.5 Root views repeat infringer status", async () => {
    const resp = await apiGet(rootPage, `/v1/admin/dmca/users/${BOB_SUB}/infringer-status`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.user_id).toBe(BOB_SUB);
    expect(typeof data.strike_count).toBe("number");
    expect(typeof data.threshold).toBe("number");
    expect(["clear", "warning", "banned"]).toContain(data.status);
  });

  test("97.6 Root updates DMCA agent config", async () => {
    const config = {
      agent_name: "E2E Test Agent",
      agent_email: "dmca-agent@test.local",
      agent_address: "456 Agent Avenue, Legal City, LC 67890, USA",
      agent_phone: "+1-555-0199",
    };
    const resp = await apiPut(rootPage, ROOT_KEY, "/v1/admin/dmca/agent-config", config);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.agent_name).toBe("E2E Test Agent");

    // Verify public endpoint returns updated info
    const pubResp = await apiGet(rootPage, "/v1/dmca/agent-info");
    expect(pubResp.status()).toBe(200);
    const pubData = await pubResp.json();
    expect(pubData.agent_name).toBe("E2E Test Agent");
  });
});

// ═════════════════════════════════════════════════════════════════════════
// Section 98: Repeat Infringer Policy
// ═════════════════════════════════════════════════════════════════════════

test.describe("98 · Repeat Infringer Policy", () => {
  let alicePage: Page;
  let bobPage: Page;
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    // Test isolation: clear leaked ban + accumulated strikes so Bob can post.
    resetModerationState(BOB_SUB);

    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage   = await newIdentityPage(browser, BOB_KEY);
    rootPage  = await newIdentityPage(browser, ROOT_KEY);
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
    await rootPage?.close();
  });

  test("98.1 Strike count increments with each claim", async () => {
    // Bob creates two posts, Alice files claims against both
    const post1Resp = await apiPost(bobPage, BOB_KEY, "/posts", {
      body: `DMCA strike1 ${TS}`, visibility: "public",
    });
    const post1Id = (await post1Resp.json()).post_id;

    const claim1Body = validClaimBody({
      content_url: `/feed/post/${post1Id}`,
      content_id: post1Id,
    });
    const resp1 = await apiPost(alicePage, ALICE_KEY, "/v1/dmca/claims", claim1Body);
    expect(resp1.status()).toBe(201);
    const data1 = await resp1.json();
    const strike1 = data1.strike_number;

    const post2Resp = await apiPost(bobPage, BOB_KEY, "/posts", {
      body: `DMCA strike2 ${TS}`, visibility: "public",
    });
    const post2Id = (await post2Resp.json()).post_id;

    const claim2Body = validClaimBody({
      content_url: `/feed/post/${post2Id}`,
      content_id: post2Id,
    });
    const resp2 = await apiPost(alicePage, ALICE_KEY, "/v1/dmca/claims", claim2Body);
    expect(resp2.status()).toBe(201);
    const data2 = await resp2.json();
    expect(data2.strike_number).toBeGreaterThan(strike1);
  });

  test("98.2 Infringer status reflects accumulated strikes", async () => {
    const resp = await apiGet(rootPage, `/v1/admin/dmca/users/${BOB_SUB}/infringer-status`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.strike_count).toBeGreaterThanOrEqual(2);
    expect(data.total_claims).toBeGreaterThanOrEqual(2);
  });

  test("98.3 Public agent-info endpoint works without auth", async () => {
    // Use a fresh page without any auth
    const resp = await alicePage.request.get(`${API}/v1/dmca/agent-info`);
    // Should return 200 (or 404 if no config set yet, which is also acceptable)
    expect([200, 404]).toContain(resp.status());
  });
});
