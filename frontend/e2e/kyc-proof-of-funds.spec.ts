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
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");


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
    _sessions = loadSessions();
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

// ─── Section 173: Admin proof-of-funds review queue page (GAP-0256) ──────────

test.describe("173: Admin proof-of-funds review queue page", () => {
  let root: Page;
  let alice: Page;

  test.beforeAll(async ({ browser }) => {
    root = await newIdentityPage(browser, "root");
    alice = await newIdentityPage(browser, "alice");
    // Seed a pending submission so the queue has content to adjudicate.
    await apiPost(alice, "alice", "ui/kyc/proof-of-funds/submissions", {
      source_category: "savings",
      declared_amount_cents: 250000,
      currency: "USD",
      note: "Long-term savings",
    });
  });

  test.afterAll(async () => {
    await root.close();
    await alice.close();
  });

  test("173.1 /admin/kyc/proof-of-funds renders the queue page with status filters", async () => {
    await root.goto("http://localhost:3000/admin/kyc/proof-of-funds", {
      waitUntil: "domcontentloaded",
    });
    await expect(
      root.getByRole("heading", { name: /proof of funds review queue/i }),
    ).toBeVisible();
    await expect(root.getByTestId("status-pending")).toBeVisible();
    await expect(root.getByTestId("status-verified")).toBeVisible();
    await expect(root.getByTestId("status-rejected")).toBeVisible();
  });

  test("173.2 Adjudicate dialog opens from a queue row and submits a decision", async () => {
    await root.goto("http://localhost:3000/admin/kyc/proof-of-funds", {
      waitUntil: "domcontentloaded",
    });
    // The submission scored into 'needs_more_info' or 'verified' depending on
    // content; switch to needs_more_info where our seeded item (no doc) lands.
    await root.getByTestId("status-needs_more_info").click();
    const adjudicateBtn = root.getByTestId("proof-of-funds-adjudicate").first();
    await expect(adjudicateBtn).toBeVisible();
    await adjudicateBtn.click();

    await expect(root.getByTestId("submit-adjudication")).toBeVisible();
    await root.getByTestId("decision-verified").click();
    await root.getByTestId("reviewer-note").fill("Verified via review queue test");
    await root.getByTestId("submit-adjudication").click();

    // Dialog closes after a successful adjudication.
    await expect(root.getByTestId("submit-adjudication")).not.toBeVisible();
  });

  test("173.3 Regular user is denied the admin queue data (no rows rendered)", async () => {
    await alice.goto("http://localhost:3000/admin/kyc/proof-of-funds", {
      waitUntil: "domcontentloaded",
    });
    // Server enforces require_admin_or_root -> 403; the queue stays empty.
    await expect(alice.getByTestId("proof-of-funds-adjudicate")).toHaveCount(0);
  });
});

// ─── Section 174: GAP-0257 admin per-user submissions + Financial tab ────────
//
// Backend endpoint GET /ui/kyc/proof-of-funds/admin/submissions?user_sub= and
// the Financial Verification tab on the KYC admin case detail page.

const GAP257_BASE = "http://localhost:3000";

const GAP257_DDB_PRELUDE = `
import boto3, os
ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
cases_table = ddb.Table('kyc_cases')
`;

function gap257Py(script: string, timeout = 15_000): void {
  execSync(`python3 -c '${script.replace(/'/g, "'\"'\"'")}'`, {
    cwd: REPO_ROOT,
    timeout,
  });
}

function gap257SeedKycCase(caseId: string, userSub: string): void {
  const ts = Math.floor(Date.now() / 1000);
  gap257Py(`
${GAP257_DDB_PRELUDE}
ts = ${ts}
case_id = "${caseId}"
user_sub = "${userSub}"
updated_sk = f"UPDATED#{str(ts).zfill(13)}#KYC#{case_id}"
cases_table.put_item(Item={
    "pk": f"KYC#{case_id}",
    "sk": "META",
    "entity_type": "kyc_case",
    "kyc_case_id": case_id,
    "user_sub": user_sub,
    "status": "under_review",
    "intake_profile": "enhanced",
    "questionnaire": {},
    "files": [],
    "signature": {},
    "submission": {"submitted_at": ts},
    "review": {"ticket_id": None, "assigned_admin_sub": None, "decision": None, "decided_at": None, "reason_codes": []},
    "created_at": ts,
    "updated_at": ts,
    "version": 1,
    "gsi_owner_pk": f"OWNER#{user_sub}",
    "gsi_owner_sk": updated_sk,
    "gsi_status_pk": "STATUS#under_review",
    "gsi_status_sk": updated_sk,
})
print(case_id)
  `);
}

function gap257DeleteKycCase(caseId: string): void {
  try {
    gap257Py(`
${GAP257_DDB_PRELUDE}
cases_table.delete_item(Key={"pk": f"KYC#${caseId}", "sk": "META"})
print("deleted")
    `, 10_000);
  } catch {
    // ignore cleanup errors
  }
}

test.describe("174: KYC proof-of-funds admin per-user submissions + tab", () => {
  let alice: Page;
  let bob: Page;
  let root: Page;
  let aliceSub: string;
  const CASE_ID = `kyc_pof_e2e_${Date.now()}`;

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    bob = await newIdentityPage(browser, "bob");
    root = await newIdentityPage(browser, "root");
    aliceSub = getSessions().alice.user_sub;
    // Ensure alice has at least one submission, then seed a case she owns.
    await apiPost(alice, "alice", "ui/kyc/proof-of-funds/submissions", {
      source_category: "bank_statement",
      declared_amount_cents: 500000,
      currency: "USD",
      document_s3_key: "mock/s3/statement.pdf",
      note: "E2E proof of funds",
    });
    gap257SeedKycCase(CASE_ID, aliceSub);
  });

  test.afterAll(async () => {
    gap257DeleteKycCase(CASE_ID);
    await alice.close();
    await bob.close();
    await root.close();
  });

  test("174.1 Admin can list submissions for a given user_sub", async () => {
    const resp = await apiGet(
      root,
      `ui/kyc/proof-of-funds/admin/submissions?user_sub=${encodeURIComponent(aliceSub)}`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.submissions)).toBe(true);
    expect(body.submissions.length).toBeGreaterThan(0);
    expect(body.submissions[0].user_sub).toBe(aliceSub);
  });

  test("174.2 Unknown user returns an empty submissions list", async () => {
    const resp = await apiGet(
      root,
      "ui/kyc/proof-of-funds/admin/submissions?user_sub=nobody_e2e_xyz",
    );
    expect(resp.status()).toBe(200);
    expect((await resp.json()).submissions).toEqual([]);
  });

  test("174.3 Non-admin cannot use the admin submissions endpoint (403)", async () => {
    const resp = await apiGet(
      bob,
      `ui/kyc/proof-of-funds/admin/submissions?user_sub=${encodeURIComponent(aliceSub)}`,
    );
    expect(resp.status()).toBe(403);
  });

  test("174.4 Case detail page exposes a Financial Verification tab", async () => {
    await root.goto(`${GAP257_BASE}/admin/kyc/cases/${CASE_ID}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(root.getByTestId("tab-financial")).toBeVisible({ timeout: 10_000 });
  });

  test("174.5 Financial Verification tab renders the submissions panel", async () => {
    await root.goto(`${GAP257_BASE}/admin/kyc/cases/${CASE_ID}`, {
      waitUntil: "domcontentloaded",
    });
    await root.getByTestId("tab-financial").click();
    await expect(root.getByTestId("financial-verification-panel")).toBeVisible({
      timeout: 10_000,
    });
    // The seeded submission should appear with its score + risk contribution.
    await expect(root.getByTestId("pof-submission-row").first()).toBeVisible();
    await expect(root.getByTestId("pof-score").first()).toBeVisible();
    await expect(root.getByTestId("risk-contribution").first()).toBeVisible();
  });
});
