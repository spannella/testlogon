/**
 * E2E tests for KYC-005: Proof of Funds / Source of Funds.
 *
 * Section 170: Submission + deterministic verification lifecycle (owner) API
 * Section 171: Submission history + summary (owner) API
 * Section 172: Reviewer ByStatus listing + adjudicate + access control
 *
 * Auth: cookie + CSRF via e2e_admin_session_setup.py (root, alice, bob,
 * charlie_admin). Owner endpoints use require_ui_session; reviewer endpoints
 * use require_admin_or_root.
 *
 * The deterministic mock verifier (app/services/kyc_proof_of_funds.py) scores a
 * submission off its content:
 *   50 base + 20 doc + 15 amount>0 + 10 known category + 5 note  (clamp 0..100)
 *   - 30 if declared_amount_cents > $10M (suspicious)
 *   score >= 75 -> verified; >= 55 -> needs_more_info; else rejected.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";

interface SessionData {
  user_sub: string;
  csrf_token: string;
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

async function injectAuth(page: Page, identity: string): Promise<void> {
  await page.context().addCookies(getSessions()[identity].cookies);
  await page.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, getSessions()[identity].user_sub);
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await injectAuth(page, identity);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}/${path}`);
}

// ─── Section 170: Submission + deterministic verification lifecycle ─────────

test.describe("170: KYC proof-of-funds submission + verification", () => {
  let alice: Page;
  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alice.close();
  });

  test("170.1 Strong submission is deterministically verified", async () => {
    const resp = await apiPost(alice, "alice", "ui/kyc/proof-of-funds/submissions", {
      source_category: "bank_statement",
      declared_amount_cents: 500000,
      currency: "USD",
      document_s3_key: "mock/s3/statement.pdf",
      note: "Quarterly bank statement",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    // 50 +20 doc +15 amount +10 known cat +5 note = 100
    expect(body.submission_id).toMatch(/^pof_/);
    expect(body.status).toBe("verified");
    expect(body.score).toBeGreaterThanOrEqual(75);
    expect(body.risk_contribution).toBe(-10);
    expect(body.currency).toBe("USD");
  });

  test("170.2 Weak submission (unknown category, no doc) is rejected", async () => {
    const resp = await apiPost(alice, "alice", "ui/kyc/proof-of-funds/submissions", {
      source_category: "lottery_winnings",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("rejected");
    expect(body.score).toBeLessThan(55);
  });

  test("170.3 Suspicious large amount lowers the score (rejected)", async () => {
    const resp = await apiPost(alice, "alice", "ui/kyc/proof-of-funds/submissions", {
      source_category: "gift",
      declared_amount_cents: 2000000000, // > $10M -> -30 penalty
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("rejected");
  });

  test("170.4 Mid-strength submission lands in needs_more_info", async () => {
    // 50 +20 doc +10 known cat = 80 -> verified; reduce: doc only known cat
    // 50 +15 amount = 65 -> needs_more_info (savings is known: +10 = 75 verified)
    const resp = await apiPost(alice, "alice", "ui/kyc/proof-of-funds/submissions", {
      source_category: "unknown_cat",
      declared_amount_cents: 1000, // 50 + 15 = 65
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("needs_more_info");
    expect(body.score).toBeGreaterThanOrEqual(55);
    expect(body.score).toBeLessThan(75);
  });

  test("170.5 negative declared_amount_cents rejected with 422", async () => {
    const resp = await apiPost(alice, "alice", "ui/kyc/proof-of-funds/submissions", {
      source_category: "savings",
      declared_amount_cents: -1,
    });
    expect(resp.status()).toBe(422);
  });
});

// ─── Section 171: Submission history + summary ──────────────────────────────

test.describe("171: KYC proof-of-funds history + summary", () => {
  let alice: Page;
  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alice.close();
  });

  test("171.1 History list returns caller submissions", async () => {
    await apiPost(alice, "alice", "ui/kyc/proof-of-funds/submissions", {
      source_category: "savings",
      declared_amount_cents: 10000,
    });
    const resp = await apiGet(alice, "ui/kyc/proof-of-funds/submissions");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.submissions)).toBe(true);
    expect(body.submissions.length).toBeGreaterThan(0);
  });

  test("171.2 Summary reflects submission counts", async () => {
    const resp = await apiGet(alice, "ui/kyc/proof-of-funds/summary");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(typeof body.count).toBe("number");
    expect(typeof body.verified_count).toBe("number");
    expect(typeof body.active_risk_contribution).toBe("number");
    expect(Array.isArray(body.verified_categories)).toBe(true);
  });

  test("171.3 Owner can fetch their own submission by id", async () => {
    const create = await apiPost(alice, "alice", "ui/kyc/proof-of-funds/submissions", {
      source_category: "savings",
    });
    const created = await create.json();
    const resp = await apiGet(alice, `ui/kyc/proof-of-funds/submissions/${created.submission_id}`);
    expect(resp.status()).toBe(200);
    expect((await resp.json()).submission_id).toBe(created.submission_id);
  });
});

// ─── Section 172: Reviewer ByStatus + adjudicate + access control ───────────

test.describe("172: KYC proof-of-funds reviewer + access control", () => {
  let alice: Page;
  let bob: Page;
  let root: Page;
  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    bob = await newIdentityPage(browser, "bob");
    root = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await alice.close();
    await bob.close();
    await root.close();
  });

  async function makeSub(): Promise<string> {
    const c = await apiPost(bob, "bob", "ui/kyc/proof-of-funds/submissions", {
      source_category: "pay_stub",
    });
    return (await c.json()).submission_id as string;
  }

  test("172.1 Reviewer lists submissions by status", async () => {
    await apiPost(bob, "bob", "ui/kyc/proof-of-funds/submissions", {
      source_category: "lottery_winnings",
    });
    const resp = await apiGet(root, "ui/kyc/proof-of-funds/review/by-status/rejected");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.submissions)).toBe(true);
  });

  test("172.2 Non-reviewer cannot list by status (403)", async () => {
    const resp = await apiGet(alice, "ui/kyc/proof-of-funds/review/by-status/pending");
    expect(resp.status()).toBe(403);
  });

  test("172.3 Reviewer can adjudicate verify / needs_more_info / reject", async () => {
    const id1 = await makeSub();
    const verify = await apiPost(root, "root", `ui/kyc/proof-of-funds/review/${id1}/adjudicate`, {
      decision: "verified",
      reviewer_note: "ok",
    });
    expect(verify.status()).toBe(200);
    const vBody = await verify.json();
    expect(vBody.status).toBe("verified");
    expect(vBody.reviewer_sub).toBeTruthy();
    expect(vBody.risk_contribution).toBe(-10);

    const id2 = await makeSub();
    const more = await apiPost(
      root,
      "root",
      `ui/kyc/proof-of-funds/review/${id2}/adjudicate`,
      { decision: "needs_more_info" },
    );
    expect(more.status()).toBe(200);
    expect((await more.json()).status).toBe("needs_more_info");

    const id3 = await makeSub();
    const reject = await apiPost(root, "root", `ui/kyc/proof-of-funds/review/${id3}/adjudicate`, {
      decision: "rejected",
    });
    expect(reject.status()).toBe(200);
    const rBody = await reject.json();
    expect(rBody.status).toBe("rejected");
    expect(rBody.risk_contribution).toBe(15);
  });

  test("172.4 Invalid adjudication decision is 400", async () => {
    const id = await makeSub();
    const resp = await apiPost(root, "root", `ui/kyc/proof-of-funds/review/${id}/adjudicate`, {
      decision: "bogus",
    });
    expect(resp.status()).toBe(400);
  });

  test("172.5 Adjudicate non-existent submission is 404", async () => {
    const resp = await apiPost(
      root,
      "root",
      "ui/kyc/proof-of-funds/review/pof_doesnotexist0000/adjudicate",
      { decision: "verified" },
    );
    expect(resp.status()).toBe(404);
  });

  test("172.6 Cross-user fetch is forbidden (403)", async () => {
    const create = await apiPost(alice, "alice", "ui/kyc/proof-of-funds/submissions", {
      source_category: "savings",
    });
    const created = await create.json();
    const resp = await apiGet(bob, `ui/kyc/proof-of-funds/submissions/${created.submission_id}`);
    expect(resp.status()).toBe(403);
  });
});
