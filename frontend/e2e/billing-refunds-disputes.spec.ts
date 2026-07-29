/**
 * E2E tests for BILLING-001: Billing Disputes & Resolution (dispute side).
 *
 * The refund-request flow is covered by refund-requests.spec.ts. This spec
 * covers the NEW dispute filing + admin resolution workflow built on the
 * BillingDisputes table and the /ui/billing/disputes + /ui/admin/disputes
 * endpoints.
 *
 * Sections:
 *   93 — Customer dispute API — file + list + get (5 tests)
 *   94 — Admin dispute resolution API — list + respond + resolve (4 tests)
 *   95 — Access control + validation (4 tests)
 *   96 — Dispute UI (2 tests)
 *
 * Auth: uses e2e_admin_session_setup.py (all identities)
 *
 * Identities:
 *   root   – root.admin@testdev.local – role=root (admin)
 *   alice  – e2e_alice@test.local     – role=user (customer)
 *   bob    – e2e_bob@test.local       – role=user (other customer)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { retryOn429 } from "./helpers/retry";
import { API } from "./cpp.config";
import { loadSessions, unauthContext } from "./helpers/session";
import {
  usingCpp,
  cppSeedLedgerEntries,
  cppPurgeUserDisputes,
} from "./helpers/cpp-seed-billing-bulk";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const TS = Date.now();
const ALICE_ID = "e2e_alice@test.local";

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
    _sessions = loadSessions();
  }
  return _sessions!;
}

// ─── Page factory ─────────────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const session = sessions[identity];
  const page = await browser.newPage();
  await page.context().addCookies(session.cookies);
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

function ensureBillingDisputesTable(): void {
  if (usingCpp()) return; // cpp's tlc_billing_disputes already exists
  execSync(
    `python3 -c "${DDB_PY_PRELUDE}
try:
    ddb_client.create_table(
        TableName='BillingDisputes',
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'status_scope', 'AttributeType': 'S'},
            {'AttributeName': 'created_at', 'AttributeType': 'N'},
            {'AttributeName': 'provider_scope', 'AttributeType': 'S'},
            {'AttributeName': 'user_scope', 'AttributeType': 'S'},
        ],
        GlobalSecondaryIndexes=[
            {'IndexName': 'ByStatusCreatedAt', 'KeySchema': [
                {'AttributeName': 'status_scope', 'KeyType': 'HASH'},
                {'AttributeName': 'created_at', 'KeyType': 'RANGE'}],
                'Projection': {'ProjectionType': 'ALL'}},
            {'IndexName': 'ByProviderCreatedAt', 'KeySchema': [
                {'AttributeName': 'provider_scope', 'KeyType': 'HASH'},
                {'AttributeName': 'created_at', 'KeyType': 'RANGE'}],
                'Projection': {'ProjectionType': 'ALL'}},
            {'IndexName': 'ByUserCreatedAt', 'KeySchema': [
                {'AttributeName': 'user_scope', 'KeyType': 'HASH'},
                {'AttributeName': 'created_at', 'KeyType': 'RANGE'}],
                'Projection': {'ProjectionType': 'ALL'}},
        ],
        BillingMode='PAY_PER_REQUEST',
    )
    print('Created BillingDisputes table')
except ddb_client.exceptions.ResourceInUseException:
    print('BillingDisputes table already exists')
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
}

/**
 * Purge every dispute this user has filed so the DISP-041 rolling-30d cap
 * (S.dispute_max_disputes_per_month, default 5) is reset before the spec files
 * new disputes. Without this, an accumulated 5+ disputes in the last 30 days
 * causes every `POST /ui/billing/disputes` to 429 (`dispute_rate_limited`),
 * which is a fixture-hygiene problem, not a product bug. Mirrors
 * creator-payouts.cleanupActivePayouts. Deletes the META rows via the
 * ByUserCreatedAt GSI.
 */
function purgeUserDisputes(userSub: string): void {
  if (usingCpp()) {
    // Reset the cap in cpp's OWN tlc_billing_disputes keyed by the SUB, not the
    // email. The caller passes ALICE_ID (email) so resolve alice's sub here.
    cppPurgeUserDisputes(getSessions()["alice"].user_sub);
    return;
  }
  execSync(
    `python3 -c "${DDB_PY_PRELUDE}
from boto3.dynamodb.conditions import Key
t = ddb.Table('BillingDisputes')
resp = t.query(IndexName='ByUserCreatedAt',
               KeyConditionExpression=Key('user_scope').eq('USER#${userSub}'))
n = 0
for it in resp.get('Items', []):
    t.delete_item(Key={'pk': it['pk'], 'sk': it['sk']})
    n += 1
print(json.dumps({'purged': n}))
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
}

function seedLedgerEntry(entryId: string, amountCents: number): void {
  const ts = Math.floor(Date.now() / 1000);
  if (usingCpp()) {
    // cpp keys the ledger by SUB and reads it from its OWN tlc_billing; the
    // dispute-file endpoint's rr_find_ledger scans that store for the entry_id.
    cppSeedLedgerEntries([
      {
        userSub: getSessions()["alice"].user_sub,
        entryId,
        ts,
        type: "charge",
        amountCents,
        state: "settled",
        reason: "test_charge",
        currency: "USD",
      },
    ]);
    return;
  }
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
    'reason': 'test_charge',
    'currency': 'USD',
})
print(json.dumps({'entry_id': entry_id}))
"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  );
}

// ─── Shared state ───────────────────────────────────────────────────────────

let alicePage: Page;
let rootPage: Page;
let disputeId = "";
const ENTRY_ID = `le_disp_${TS}`;

test.beforeAll(async ({ browser }) => {
  ensureBillingDisputesTable();
  // DISP-041: reset Alice's rolling-30d dispute count so the filings below are
  // not rejected with 429 (dispute_rate_limited) under suite accumulation.
  purgeUserDisputes(ALICE_ID);
  seedLedgerEntry(ENTRY_ID, 2500);
  alicePage = await newIdentityPage(browser, "alice");
  rootPage = await newIdentityPage(browser, "root");
});

test.afterAll(async () => {
  await alicePage?.close();
  await rootPage?.close();
});

// ─── Section 93: Customer dispute API ─────────────────────────────────────────

test.describe("93 — Customer dispute API", () => {
  test("93.1 files a dispute referencing a transaction (201)", async () => {
    const resp = await retryOn429(() =>
      apiPost(alicePage, "alice", "/ui/billing/disputes", {
        transaction_entry_id: ENTRY_ID,
        amount_cents: 2500,
        reason: "I never received the product I was charged for.",
      }),
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.dispute_id).toBeTruthy();
    expect(body.status).toBe("open");
    expect(body.amount_cents).toBe(2500);
    disputeId = body.dispute_id;
  });

  test("93.2 files a dispute without a transaction (201)", async () => {
    const resp = await retryOn429(() =>
      apiPost(alicePage, "alice", "/ui/billing/disputes", {
        amount_cents: 1000,
        reason: "Unrecognized charge on my statement.",
      }),
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.status).toBe("open");
  });

  test("93.3 lists the user's own disputes", async () => {
    const resp = await apiGet(alicePage, "/ui/billing/disputes");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.items)).toBe(true);
    expect(body.items.some((d: { dispute_id: string }) => d.dispute_id === disputeId)).toBe(true);
  });

  test("93.4 gets a single dispute by ID", async () => {
    const resp = await apiGet(alicePage, `/ui/billing/disputes/${disputeId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.dispute_id).toBe(disputeId);
    expect(body.reason).toContain("never received");
  });

  test("93.5 rejects a non-positive amount (422)", async () => {
    // DISP-010: the reason field now accepts any >=1-char string (the canonical
    // reason ENUM lives in `reason`, free text in `reason_detail`), so the old
    // "reason too short" 422 no longer fires. The current input-validation
    // rejection is a non-positive amount (DisputeFileIn.amount_cents ge=1).
    const resp = await apiPost(alicePage, "alice", "/ui/billing/disputes", {
      amount_cents: 0,
      reason: "Attempting to dispute a zero-dollar charge.",
    });
    expect(resp.status()).toBe(422);
  });
});

// ─── Section 94: Admin dispute resolution API ─────────────────────────────────

test.describe("94 — Admin dispute resolution API", () => {
  test("94.1 admin lists open disputes", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/disputes", { status: "open" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.items)).toBe(true);
    expect(body.items.some((d: { dispute_id: string }) => d.dispute_id === disputeId)).toBe(true);
  });

  test("94.2 admin submits evidence (open -> under_review)", async () => {
    const resp = await apiPost(rootPage, "root", `/ui/admin/disputes/${disputeId}/respond`, {
      evidence_text: "Delivery confirmation and signed receipt attached.",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.evidence_submitted).toBe(true);
    expect(body.status).toBe("under_review");
  });

  test("94.3 admin resolves the dispute (denied — no money move)", async () => {
    // DISP-013: the unified resolve vocabulary is refunded|partial|denied (legacy
    // won|lost|accepted are accepted + MAPPED: won -> denied). `denied` is the
    // terminal outcome that moves NO money, so it does not require a classified
    // charge or dual-approval — the correct outcome for this unclassified,
    // reason-only dispute.
    const resp = await apiPost(rootPage, "root", `/ui/admin/disputes/${disputeId}/resolve`, {
      resolution: "denied",
      notes: "Charge upheld; evidence sufficient.",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("resolved");
    expect(body.resolution).toBe("denied");
    expect(body.moved_cents).toBe(0);
  });

  test("94.4 resolving an already-resolved dispute fails (409 dispute_terminal)", async () => {
    // DISP-005: a second resolve on a terminal (resolved/withdrawn) dispute is
    // rejected with 409 `dispute_terminal` (was 400 under the old open->won store).
    const resp = await apiPost(rootPage, "root", `/ui/admin/disputes/${disputeId}/resolve`, {
      resolution: "denied",
    });
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail?.code).toBe("dispute_terminal");
  });

  test("94.5 refunding an unclassified dispute is refused (422 unclassified_charge)", async () => {
    // DISP-013 money-safety guard: `refunded`/`partial` REALLY drive the reversal
    // rail, so a dispute with no charge_type/charge_ref cannot be refunded — the
    // backend refuses with 422 rather than silently claim a refund happened. File
    // a fresh reason-only dispute (unclassified) and attempt a refund on it.
    const fileResp = await retryOn429(() =>
      apiPost(alicePage, "alice", "/ui/billing/disputes", {
        amount_cents: 800,
        reason: "Charge I do not recognize and want refunded.",
      }),
    );
    expect(fileResp.status()).toBe(201);
    const filed = await fileResp.json();

    const resp = await apiPost(rootPage, "root", `/ui/admin/disputes/${filed.dispute_id}/resolve`, {
      resolution: "refunded",
    });
    expect(resp.status()).toBe(422);
    const body = await resp.json();
    expect(body.detail?.code).toBe("unclassified_charge");
  });
});

// ─── Section 95: Access control + validation ──────────────────────────────────

test.describe("95 — Access control + validation", () => {
  test("95.1 unauthenticated dispute list returns 401", async () => {
    const anon = await unauthContext(API);
    const resp = await anon.get(`/ui/billing/disputes`);
    expect(resp.status()).toBe(401);
    await anon.dispose();
  });

  test("95.2 non-admin cannot list the admin queue (403)", async () => {
    const resp = await apiGet(alicePage, "/ui/admin/disputes", { status: "open" });
    expect(resp.status()).toBe(403);
  });

  test("95.3 non-owner cannot view another user's dispute (404)", async ({ browser }) => {
    const bobPage = await newIdentityPage(browser, "bob");
    const resp = await apiGet(bobPage, `/ui/billing/disputes/${disputeId}`);
    expect(resp.status()).toBe(404);
    await bobPage.close();
  });

  test("95.4 unknown dispute ID returns 404", async () => {
    const resp = await apiGet(alicePage, "/ui/billing/disputes/dp_nope_xxx");
    expect(resp.status()).toBe(404);
  });
});

// ─── Section 96: Dispute UI ───────────────────────────────────────────────────

test.describe("96 — Dispute UI", () => {
  test("96.1 customer disputes page loads with heading", async () => {
    await alicePage.goto("http://localhost:3000/billing/disputes", { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByRole("heading", { name: "Disputes", exact: true })).toBeVisible({ timeout: 15_000 });
  });

  test("96.2 admin dispute queue page loads with heading", async () => {
    // DISP-022: the admin queue page heading is now "Payment Dispute Queue"
    // (AdminDisputeQueuePage PageHeader → <h1>), was "Dispute Queue".
    await rootPage.goto("http://localhost:3000/admin/disputes", { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByRole("heading", { name: "Payment Dispute Queue", exact: true })).toBeVisible({ timeout: 15_000 });
  });
});
