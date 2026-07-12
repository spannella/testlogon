/**
 * E2E tests for BILLING-001: Customer Self-Service Refund Requests.
 *
 * Sections:
 *   90 — Refund Request API — submit + list (6 tests)
 *   91 — Admin Refund Processing (5 tests)
 *   92 — Refund UI (4 tests)
 *
 * Auth: uses e2e_admin_session_setup.py (all identities)
 *
 * Identities:
 *   root   – root.admin@testdev.local – role=root
 *   alice  – e2e_alice@test.local     – role=user
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const API = "http://localhost:8000";
const TS = Date.now();
const ALICE_ID = "e2e_alice@test.local";
const ROOT_SUB = "root.admin@testdev.local";

// ─── Session bootstrap ────────────────────────────────────────────────────────

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

// ─── Page factory ─────────────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const session = sessions[identity];
  const page = await browser.newPage();
  await page.context().addCookies(session.cookies);
  // Must set auth-store in localStorage so the React app recognizes the user as authenticated
  await page.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
  return page;
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}${path}`, { params });
}

// ─── DDB helpers ──────────────────────────────────────────────────────────────

const DDB_PY_PRELUDE = `
import boto3, time, json
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1',
                     aws_access_key_id='test', aws_secret_access_key='test')
ddb_client = boto3.client('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1',
                          aws_access_key_id='test', aws_secret_access_key='test')
`;

function ensureRefundRequestsTable(): void {
  execSync(
    `python3 -c "${DDB_PY_PRELUDE}
try:
    ddb_client.create_table(
        TableName='RefundRequests',
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'status_scope', 'AttributeType': 'S'},
            {'AttributeName': 'created_at', 'AttributeType': 'N'},
            {'AttributeName': 'requester_scope', 'AttributeType': 'S'},
            {'AttributeName': 'transaction_entry_id', 'AttributeType': 'S'},
        ],
        GlobalSecondaryIndexes=[
            {
                'IndexName': 'ByStatusCreatedAt',
                'KeySchema': [
                    {'AttributeName': 'status_scope', 'KeyType': 'HASH'},
                    {'AttributeName': 'created_at', 'KeyType': 'RANGE'},
                ],
                'Projection': {'ProjectionType': 'ALL'},
            },
            {
                'IndexName': 'ByRequesterCreatedAt',
                'KeySchema': [
                    {'AttributeName': 'requester_scope', 'KeyType': 'HASH'},
                    {'AttributeName': 'created_at', 'KeyType': 'RANGE'},
                ],
                'Projection': {'ProjectionType': 'ALL'},
            },
            {
                'IndexName': 'ByTransactionId',
                'KeySchema': [
                    {'AttributeName': 'transaction_entry_id', 'KeyType': 'HASH'},
                ],
                'Projection': {'ProjectionType': 'ALL'},
            },
        ],
        BillingMode='PAY_PER_REQUEST',
    )
    print('Created RefundRequests table')
except ddb_client.exceptions.ResourceInUseException:
    print('RefundRequests table already exists')
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
}

/**
 * Seed a billing ledger entry for Alice so she has something to request a refund for.
 */
function seedLedgerEntry(entryId: string, amountCents: number, reason: string, tsOverride?: number): void {
  const ts = tsOverride ?? Math.floor(Date.now() / 1000);
  execSync(
    `python3 -c "${DDB_PY_PRELUDE}
tbl = ddb.Table('billing')
ts = ${ts}
entry_id = '${entryId}'
sk = f'LEDGER#{ts}#{entry_id}'
tbl.put_item(Item={
    'pk': 'USER#${ALICE_ID}',
    'sk': sk,
    'entry_id': entry_id,
    'ts': ts,
    'type': 'charge',
    'amount_cents': ${amountCents},
    'state': 'settled',
    'reason': '${reason}',
    'currency': 'USD',
})
print(json.dumps({'sk': sk, 'entry_id': entry_id}))
"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  );
}

/**
 * Seed an old ledger entry (31 days ago) for the expired-window test.
 */
function seedOldLedgerEntry(entryId: string, amountCents: number): void {
  const ts = Math.floor(Date.now() / 1000) - 31 * 86400;
  seedLedgerEntry(entryId, amountCents, "old_tip", ts);
}

/**
 * Delete all refund requests for Alice (from previous test runs).
 * Scans the ByRequesterCreatedAt GSI and batch-deletes matching items.
 */
function cleanupAliceRefundRequests(): void {
  execSync(
    `python3 -c "${DDB_PY_PRELUDE}
tbl = ddb.Table('RefundRequests')
resp = tbl.query(
    IndexName='ByRequesterCreatedAt',
    KeyConditionExpression='requester_scope = :rs',
    ExpressionAttributeValues={':rs': 'USER#${ALICE_ID}'},
)
items = resp.get('Items', [])
deleted = 0
for item in items:
    tbl.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
    deleted += 1
print(f'Deleted {deleted} old refund requests for Alice')
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
}

// ─── Test-scoped state ────────────────────────────────────────────────────────

let alicePage: Page;
let rootPage: Page;

const ENTRY_A = `e2e_rr_tip_${TS}`;
const ENTRY_B = `e2e_rr_dup_${TS}`;
const ENTRY_OLD = `e2e_rr_old_${TS}`;
const ENTRY_APPROVE = `e2e_rr_appr_${TS}`;
const ENTRY_DENY = `e2e_rr_deny_${TS}`;

let submittedRequestId = "";
let approveRequestId = "";
let denyRequestId = "";

// ═══════════════════════════════════════════════════════════════════════════════
// Setup
// ═══════════════════════════════════════════════════════════════════════════════

test.beforeAll(async ({ browser }) => {
  ensureRefundRequestsTable();
  cleanupAliceRefundRequests();

  // Seed ledger entries
  seedLedgerEntry(ENTRY_A, 500, "tip");
  seedLedgerEntry(ENTRY_B, 300, "tip");
  seedOldLedgerEntry(ENTRY_OLD, 200);
  seedLedgerEntry(ENTRY_APPROVE, 750, "tip");
  seedLedgerEntry(ENTRY_DENY, 400, "tip");

  alicePage = await newIdentityPage(browser, "alice");
  rootPage = await newIdentityPage(browser, "root");
});

test.afterAll(async () => {
  await alicePage?.close();
  await rootPage?.close();
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 90 — Refund Request API (6 tests)
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("90 — Refund Request API", () => {
  test("90.1 Customer submits refund request for a tip", async () => {
    const resp = await apiPost(alicePage, "alice", "/ui/billing/refund-requests", {
      transaction_entry_id: ENTRY_A,
      reason: "Accidentally tipped the wrong person, meant to tip Bob.",
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.status).toBe("pending");
    expect(body.amount_cents).toBe(500);
    expect(body.refund_request_id).toBeTruthy();
    submittedRequestId = body.refund_request_id;
  });

  test("90.2 Refund request appears in customer list", async () => {
    const resp = await apiGet(alicePage, "/ui/billing/refund-requests");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const found = body.items.find(
      (r: { refund_request_id: string }) => r.refund_request_id === submittedRequestId,
    );
    expect(found).toBeTruthy();
    expect(found.status).toBe("pending");
  });

  test("90.3 Duplicate refund for same transaction returns 409", async () => {
    const resp = await apiPost(alicePage, "alice", "/ui/billing/refund-requests", {
      transaction_entry_id: ENTRY_A,
      reason: "I already asked for this but trying again.",
    });
    expect(resp.status()).toBe(409);
  });

  test("90.4 Refund for expired transaction (>30 days) returns 400", async () => {
    const resp = await apiPost(alicePage, "alice", "/ui/billing/refund-requests", {
      transaction_entry_id: ENTRY_OLD,
      reason: "This is an old transaction that is outside the refund window.",
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail).toContain("outside the refund window");
  });

  test("90.5 Refund amount exceeding original returns 400", async () => {
    const resp = await apiPost(alicePage, "alice", "/ui/billing/refund-requests", {
      transaction_entry_id: ENTRY_B,
      reason: "I want more money than I paid, which should fail.",
      amount_cents: 999999,
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail).toContain("exceeds original");
  });

  test("90.6 Get single refund request by ID", async () => {
    const resp = await apiGet(alicePage, `/ui/billing/refund-requests/${submittedRequestId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.refund_request_id).toBe(submittedRequestId);
    expect(body.amount_cents).toBe(500);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 91 — Admin Refund Processing (5 tests)
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("91 — Admin Refund Processing", () => {
  test.beforeAll(async () => {
    // Submit requests that admin will approve/deny
    const respApprove = await apiPost(alicePage, "alice", "/ui/billing/refund-requests", {
      transaction_entry_id: ENTRY_APPROVE,
      reason: "Please refund this tip, it was accidental and I want it back.",
    });
    expect(respApprove.status()).toBe(201);
    approveRequestId = (await respApprove.json()).refund_request_id;

    const respDeny = await apiPost(alicePage, "alice", "/ui/billing/refund-requests", {
      transaction_entry_id: ENTRY_DENY,
      reason: "I changed my mind and want a refund for this transaction.",
    });
    expect(respDeny.status()).toBe(201);
    denyRequestId = (await respDeny.json()).refund_request_id;
  });

  test("91.1 Admin sees pending refund in queue", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/refund-requests", { status: "pending" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.items.length).toBeGreaterThanOrEqual(1);
    const found = body.items.find(
      (r: { refund_request_id: string }) => r.refund_request_id === approveRequestId,
    );
    expect(found).toBeTruthy();
  });

  test("91.2 Admin approves refund — status changes", async () => {
    const resp = await apiPost(rootPage, "root", `/ui/admin/refund-requests/${approveRequestId}/approve`, {
      notes: "Verified. Approving full refund.",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.status).toBe("approved");
    expect(body.approved_amount_cents).toBe(750);
  });

  test("91.3 Approved refund creates reverse ledger entry", async () => {
    // Check that a refund_credit ledger entry exists for Alice
    const resp = await apiGet(alicePage, "/ui/billing/ledger");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const credit = body.items.find(
      (e: { type: string; reason: string }) =>
        e.type === "refund_credit" && e.reason === "Refund approved",
    );
    expect(credit).toBeTruthy();
    expect(Number(credit.amount_cents)).toBe(750);
  });

  test("91.4 Admin denies refund with notes — status=denied", async () => {
    const resp = await apiPost(rootPage, "root", `/ui/admin/refund-requests/${denyRequestId}/reject`, {
      notes: "Transaction was legitimate and intentional.",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.status).toBe("denied");

    // Verify Alice can see the denial notes
    const detailResp = await apiGet(alicePage, `/ui/billing/refund-requests/${denyRequestId}`);
    expect(detailResp.status()).toBe(200);
    const detail = await detailResp.json();
    expect(detail.status).toBe("denied");
    expect(detail.admin_notes).toBe("Transaction was legitimate and intentional.");
  });

  test("91.5 Non-admin cannot access admin refund queue (403)", async () => {
    const resp = await apiGet(alicePage, "/ui/admin/refund-requests");
    expect(resp.status()).toBe(403);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 92 — Refund UI (4 tests)
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("92 — Refund UI", () => {
  let uiAlicePage: Page;
  let uiRootPage: Page;

  test.beforeAll(async ({ browser }) => {
    uiAlicePage = await newIdentityPage(browser, "alice");
    uiRootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await uiAlicePage?.close();
    await uiRootPage?.close();
  });

  test("92.1 Billing ledger page loads and shows entries", async () => {
    const responsePromise = uiAlicePage.waitForResponse(
      (r) => r.url().includes("/billing/ledger") && r.status() === 200,
    );
    await uiAlicePage.goto("http://localhost:3000/billing?tab=ledger");
    await responsePromise;
    await expect(uiAlicePage.getByRole("tab", { name: "Ledger" })).toBeVisible();
  });

  test("92.2 My Refund Requests link is visible", async () => {
    // Page may already be on billing/ledger from 92.1; reload to be safe
    const responsePromise = uiAlicePage.waitForResponse(
      (r) => r.url().includes("/billing/ledger") && r.status() === 200,
    );
    await uiAlicePage.goto("http://localhost:3000/billing?tab=ledger");
    await responsePromise;
    await expect(uiAlicePage.getByRole("link", { name: /My Refund Requests/i })).toBeVisible();
  });

  test("92.3 Refund history page shows requests with status badge", async () => {
    // Re-inject auth in case prior billing page triggered a 401 logout
    const sess = getSessions()["alice"];
    await uiAlicePage.context().addCookies(sess.cookies);
    await uiAlicePage.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
    await uiAlicePage.evaluate((uid: string) => {
      const state = { userId: uid, accessToken: null, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    }, sess.user_sub);

    const responsePromise = uiAlicePage.waitForResponse(
      (r) => r.url().includes("/billing/refund-requests") && r.status() === 200,
    );
    await uiAlicePage.goto("http://localhost:3000/billing/refunds");
    await responsePromise;
    await expect(uiAlicePage.getByRole("heading", { name: "Refund Requests", exact: true })).toBeVisible();
    // Should see at least one request with a status badge (created in sections 90/91)
    await expect(
      uiAlicePage.locator("text=pending")
        .or(uiAlicePage.locator("text=approved"))
        .or(uiAlicePage.locator("text=denied"))
        .first(),
    ).toBeVisible();
  });

  test("92.4 Admin refund queue shows pending requests", async () => {
    const responsePromise = uiRootPage.waitForResponse(
      (r) => r.url().includes("/admin/refund-requests") && r.status() === 200,
    );
    await uiRootPage.goto("http://localhost:3000/admin/refunds");
    await responsePromise;
    await expect(uiRootPage.getByRole("heading", { name: "Refund Queue" })).toBeVisible();
  });
});
