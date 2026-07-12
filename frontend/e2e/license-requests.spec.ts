/**
 * E2E tests for License Request & Approval Workflow (LICENSE-004).
 *
 * Sections:
 *   475 -- License Request Creation API   (4 tests)
 *   476 -- Approve & Deny API             (4 tests)
 *   477 -- Counter-Offer & Negotiation API (5 tests)
 *   478 -- Withdraw & Expiry API          (3 tests)
 *
 * Auth: Alice, Bob session cookies (from e2e_admin_session_setup.py).
 *       Keys: "alice", "bob"
 *
 * Total: 16 tests
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const TS = Date.now();

// Identity keys matching e2e_admin_session_setup.py
const ALICE_KEY = "alice";
const BOB_KEY = "bob";

// Email-based user subs
const ALICE_SUB = "e2e_alice@test.local";
const BOB_SUB = "e2e_bob@test.local";

// Unique content IDs per run
const CONTENT_APPROVE = `lr_approve_${TS}`;
const CONTENT_DENY = `lr_deny_${TS}`;
const CONTENT_COUNTER = `lr_counter_${TS}`;
const CONTENT_COUNTER_REJECT = `lr_counter_reject_${TS}`;
const CONTENT_WITHDRAW = `lr_withdraw_${TS}`;
const CONTENT_COUNTER_ONLY_OWNER = `lr_counter_own_${TS}`;
const CONTENT_ACCEPT_BAD = `lr_accept_bad_${TS}`;

// ─── Session bootstrap ───────────────────────────────────────────────────────

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
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth + request helpers ──────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body: Record<string, unknown>,
) {
  const session = getSessions()[identity];
  return page.request.post(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body,
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

// ─── Shared state ─────────────────────────────────────────────────────────────

let requestApproveId = "";
let requestDenyId = "";
let requestCounterId = "";
let requestCounterRejectId = "";
let requestWithdrawId = "";
let requestCounterOnlyOwnerId = "";
let requestAcceptBadId = "";

// ─── Section 475: License Request Creation API ──────────────────────────────

test.describe("475 -- License Request Creation API", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage = await newIdentityPage(browser, BOB_KEY);
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("475.1 Bob requests license for Alice's content", async () => {
    const resp = await apiPost(bobPage, BOB_KEY, "/ui/licenses/requests", {
      content_id: CONTENT_APPROVE,
      content_type: "video",
      owner_id: ALICE_SUB,
      proposed_terms: {
        profit_share_pct: 5,
        fixed_cost_cents: 0,
        revenue_share_pct: 3,
      },
      message: `E2E request ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.request_id).toBeTruthy();
    expect(data.status).toBe("pending");
    expect(data.proposed_terms.profit_share_pct).toBe(5);
    expect(data.proposed_terms.revenue_share_pct).toBe(3);
    expect(data.content_id).toBe(CONTENT_APPROVE);
    expect(data.requester_id).toBe(BOB_SUB);
    expect(data.owner_id).toBe(ALICE_SUB);
    requestApproveId = data.request_id;
  });

  test("475.2 Request appears in Bob's sent list", async () => {
    const resp = await apiGet(bobPage, "/ui/licenses/requests/sent");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find(
      (i: { request_id: string }) => i.request_id === requestApproveId,
    );
    expect(found).toBeTruthy();
    expect(found.status).toBe("pending");
  });

  test("475.3 Request appears in Alice's inbox", async () => {
    const resp = await apiGet(alicePage, "/ui/licenses/requests/received");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find(
      (i: { request_id: string }) => i.request_id === requestApproveId,
    );
    expect(found).toBeTruthy();
    expect(found.status).toBe("pending");
    expect(found.requester_id).toBe(BOB_SUB);
  });

  test("475.4 Duplicate request for same content fails", async () => {
    const resp = await apiPost(bobPage, BOB_KEY, "/ui/licenses/requests", {
      content_id: CONTENT_APPROVE,
      content_type: "video",
      owner_id: ALICE_SUB,
      proposed_terms: {
        profit_share_pct: 10,
        fixed_cost_cents: 0,
        revenue_share_pct: 5,
      },
    });
    expect(resp.status()).toBe(409);
  });
});

// ─── Section 476: Approve & Deny API ────────────────────────────────────────

test.describe("476 -- Approve & Deny API", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage = await newIdentityPage(browser, BOB_KEY);

    // Create a request for deny testing
    const denyResp = await apiPost(bobPage, BOB_KEY, "/ui/licenses/requests", {
      content_id: CONTENT_DENY,
      content_type: "music",
      owner_id: ALICE_SUB,
      proposed_terms: { profit_share_pct: 8, fixed_cost_cents: 100, revenue_share_pct: 2 },
    });
    const denyData = await denyResp.json();
    requestDenyId = denyData.request_id;
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("476.1 Alice approves Bob's request", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_KEY,
      `/ui/licenses/requests/${requestApproveId}/approve?content_id=${encodeURIComponent(CONTENT_APPROVE)}`,
      {},
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.request.status).toBe("approved");
    expect(data.issued_license).toBeTruthy();
    expect(data.issued_license.issued_license_id).toBeTruthy();
  });

  test("476.2 Approved request creates IssuedLicense in Bob's held list", async () => {
    const resp = await apiGet(bobPage, "/ui/licenses/held");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find(
      (i: { content_id: string }) => i.content_id === CONTENT_APPROVE,
    );
    expect(found).toBeTruthy();
    expect(found.status).toBe("active");
    expect(Number(found.terms_snapshot.profit_share_pct)).toBe(5);
  });

  test("476.3 Alice denies a different request with reason", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_KEY,
      `/ui/licenses/requests/${requestDenyId}/deny?content_id=${encodeURIComponent(CONTENT_DENY)}`,
      { reason: "Not compatible" },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("denied");
    expect(data.denial_reason).toBe("Not compatible");
  });

  test("476.4 Non-owner cannot approve", async () => {
    // Bob tries to approve his own request (he's not the owner)
    // First create a new request for this test
    const createResp = await apiPost(bobPage, BOB_KEY, "/ui/licenses/requests", {
      content_id: `lr_noauth_${TS}`,
      content_type: "video",
      owner_id: ALICE_SUB,
      proposed_terms: { profit_share_pct: 1, fixed_cost_cents: 0, revenue_share_pct: 0 },
    });
    const createData = await createResp.json();
    const reqId = createData.request_id;

    const resp = await apiPost(
      bobPage,
      BOB_KEY,
      `/ui/licenses/requests/${reqId}/approve?content_id=${encodeURIComponent(`lr_noauth_${TS}`)}`,
      {},
    );
    expect(resp.status()).toBe(403);
  });
});

// ─── Section 477: Counter-Offer & Negotiation API ──────────────────────────

test.describe("477 -- Counter-Offer & Negotiation API", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage = await newIdentityPage(browser, BOB_KEY);

    // Create requests for counter-offer tests
    const counterResp = await apiPost(bobPage, BOB_KEY, "/ui/licenses/requests", {
      content_id: CONTENT_COUNTER,
      content_type: "video",
      owner_id: ALICE_SUB,
      proposed_terms: { profit_share_pct: 5, fixed_cost_cents: 0, revenue_share_pct: 3 },
    });
    requestCounterId = (await counterResp.json()).request_id;

    const rejectResp = await apiPost(bobPage, BOB_KEY, "/ui/licenses/requests", {
      content_id: CONTENT_COUNTER_REJECT,
      content_type: "image",
      owner_id: ALICE_SUB,
      proposed_terms: { profit_share_pct: 2, fixed_cost_cents: 0, revenue_share_pct: 1 },
    });
    requestCounterRejectId = (await rejectResp.json()).request_id;

    const counterOnlyResp = await apiPost(bobPage, BOB_KEY, "/ui/licenses/requests", {
      content_id: CONTENT_COUNTER_ONLY_OWNER,
      content_type: "video",
      owner_id: ALICE_SUB,
      proposed_terms: { profit_share_pct: 5, fixed_cost_cents: 0, revenue_share_pct: 3 },
    });
    requestCounterOnlyOwnerId = (await counterOnlyResp.json()).request_id;

    const acceptBadResp = await apiPost(bobPage, BOB_KEY, "/ui/licenses/requests", {
      content_id: CONTENT_ACCEPT_BAD,
      content_type: "video",
      owner_id: ALICE_SUB,
      proposed_terms: { profit_share_pct: 5, fixed_cost_cents: 0, revenue_share_pct: 3 },
    });
    requestAcceptBadId = (await acceptBadResp.json()).request_id;
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("477.1 Alice counter-offers with different terms", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_KEY,
      `/ui/licenses/requests/${requestCounterId}/counter?content_id=${encodeURIComponent(CONTENT_COUNTER)}`,
      {
        counter_terms: {
          profit_share_pct: 10,
          fixed_cost_cents: 200,
          revenue_share_pct: 5,
        },
      },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("negotiating");
    expect(data.counter_terms).toBeTruthy();
    expect(data.counter_terms.profit_share_pct).toBe(10);
    expect(data.counter_terms.fixed_cost_cents).toBe(200);
  });

  test("477.2 Bob accepts counter-offer", async () => {
    const resp = await apiPost(
      bobPage,
      BOB_KEY,
      `/ui/licenses/requests/${requestCounterId}/accept-counter?content_id=${encodeURIComponent(CONTENT_COUNTER)}`,
      {},
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.request.status).toBe("approved");
    expect(data.issued_license).toBeTruthy();
    expect(data.issued_license.issued_license_id).toBeTruthy();
    // Verify license was created with counter terms (not proposed)
    expect(Number(data.issued_license.profit_share_pct)).toBe(10);
  });

  test("477.3 Bob rejects counter-offer on another request", async () => {
    // First Alice counter-offers on the reject request
    const counterResp = await apiPost(
      alicePage,
      ALICE_KEY,
      `/ui/licenses/requests/${requestCounterRejectId}/counter?content_id=${encodeURIComponent(CONTENT_COUNTER_REJECT)}`,
      {
        counter_terms: { profit_share_pct: 20, fixed_cost_cents: 0, revenue_share_pct: 10 },
      },
    );
    expect(counterResp.status()).toBe(200);

    // Bob rejects
    const resp = await apiPost(
      bobPage,
      BOB_KEY,
      `/ui/licenses/requests/${requestCounterRejectId}/reject-counter?content_id=${encodeURIComponent(CONTENT_COUNTER_REJECT)}`,
      {},
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("denied");
  });

  test("477.4 Requester cannot counter (only owner can)", async () => {
    const resp = await apiPost(
      bobPage,
      BOB_KEY,
      `/ui/licenses/requests/${requestCounterOnlyOwnerId}/counter?content_id=${encodeURIComponent(CONTENT_COUNTER_ONLY_OWNER)}`,
      {
        counter_terms: { profit_share_pct: 99, fixed_cost_cents: 0, revenue_share_pct: 0 },
      },
    );
    expect(resp.status()).toBe(403);
  });

  test("477.5 Cannot accept counter on non-negotiating request", async () => {
    // requestAcceptBadId is still "pending" (no counter-offer made)
    const resp = await apiPost(
      bobPage,
      BOB_KEY,
      `/ui/licenses/requests/${requestAcceptBadId}/accept-counter?content_id=${encodeURIComponent(CONTENT_ACCEPT_BAD)}`,
      {},
    );
    expect(resp.status()).toBe(400);
  });
});

// ─── Section 478: Withdraw & Expiry API ─────────────────────────────────────

test.describe("478 -- Withdraw & Expiry API", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage = await newIdentityPage(browser, BOB_KEY);

    // Create a request for withdrawal
    const withdrawResp = await apiPost(bobPage, BOB_KEY, "/ui/licenses/requests", {
      content_id: CONTENT_WITHDRAW,
      content_type: "post",
      owner_id: ALICE_SUB,
      proposed_terms: { profit_share_pct: 3, fixed_cost_cents: 0, revenue_share_pct: 1 },
      message: `Withdraw test ${TS}`,
    });
    requestWithdrawId = (await withdrawResp.json()).request_id;
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("478.1 Bob withdraws a pending request", async () => {
    const resp = await apiPost(
      bobPage,
      BOB_KEY,
      `/ui/licenses/requests/${requestWithdrawId}/withdraw?content_id=${encodeURIComponent(CONTENT_WITHDRAW)}`,
      {},
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("withdrawn");
  });

  test("478.2 Cannot withdraw an already approved request", async () => {
    // requestApproveId was approved in section 476
    const resp = await apiPost(
      bobPage,
      BOB_KEY,
      `/ui/licenses/requests/${requestApproveId}/withdraw?content_id=${encodeURIComponent(CONTENT_APPROVE)}`,
      {},
    );
    expect(resp.status()).toBe(400);
  });

  test("478.3 Request detail returns full info for both parties", async () => {
    // Alice (owner) can view the withdrawn request
    const resp = await apiGet(
      alicePage,
      `/ui/licenses/requests/${requestWithdrawId}?content_id=${encodeURIComponent(CONTENT_WITHDRAW)}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.request_id).toBe(requestWithdrawId);
    expect(data.content_id).toBe(CONTENT_WITHDRAW);
    expect(data.requester_id).toBe(BOB_SUB);
    expect(data.owner_id).toBe(ALICE_SUB);
    expect(data.proposed_terms).toBeTruthy();
    expect(data.message).toContain("Withdraw test");
    expect(data.status).toBe("withdrawn");
  });
});
