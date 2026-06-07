/**
 * E2E tests for Creator Payout System (MON-004).
 *
 * Sections:
 *   115 — Payout Balance + Request API   (5 tests)
 *   116 — Admin Payout Workflow API       (5 tests)
 *   117 — Payout State Transitions        (4 tests)
 *   118 — PayoutDashboard UI              (4 tests)
 *
 * Total: 18 tests
 *
 * Auth:
 *   alice         - e2e_alice@test.local      - role=user  (creator requesting payouts)
 *   root          - root.admin@testdev.local  - role=root  (admin approving/rejecting)
 *
 * Uses e2e_admin_session_setup.py for both user + admin sessions.
 *
 * DDB helpers seed billing ledger credit entries to give Alice
 * an available balance for payout requests.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const PYTHON   = "/home/ubuntu/testlogon/.venv/bin/python3";
const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const TS       = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

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
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Page factory ─────────────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

// ─── Auth inject for UI tests ─────────────────────────────────────────────────

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for identity: ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    ([userId, accessToken]: [string, string]) => {
      const state = { userId, accessToken, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    [session.user_sub, session.access_token],
  );
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

/**
 * Seed CREDIT ledger entries for a user with old timestamps (past hold period).
 */
function seedOldCredits(userSub: string, count: number, amountEach: number): number {
  execSync(
    `${PYTHON} -c "
import boto3, os, uuid, time
from pathlib import Path

env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('billing')
pk = 'USER#${userSub}'
base_ts = int(time.time()) - 700000  # ~8 days ago, past 7-day hold

for i in range(${count}):
    entry_id = uuid.uuid4().hex
    ts = base_ts + i
    tbl.put_item(Item={
        'pk': pk,
        'sk': f'LEDGER#{ts}#{entry_id}',
        'entry_id': entry_id,
        'ts': ts,
        'type': 'credit',
        'amount_cents': ${amountEach},
        'currency': 'USD',
        'state': 'settled',
        'reason': 'Tip: message',
        'meta': {'content_type': 'message', 'content_id': 'payout_seed_${TS}'},
    })
print('seeded')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
  return count * amountEach;
}

/**
 * Cancel all active payouts for a user to avoid test interference.
 */
function cleanupActivePayouts(userSub: string): void {
  execSync(
    `${PYTHON} -c "
import boto3, os
from pathlib import Path

env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('CreatorPayouts')

# Collect active payouts via BOTH the GSI (eventually consistent) and a base-table
# scan (catches very-recently-created payouts the GSI hasn't propagated yet) so the
# pending-balance calculation is fully freed under full-suite accumulation.
active = {}
resp = tbl.query(
    IndexName='ByUserCreatedAt',
    KeyConditionExpression=boto3.dynamodb.conditions.Key('user_id').eq('${userSub}'),
)
for item in resp.get('Items', []):
    if item.get('status') in ('requested', 'approved', 'processing'):
        active[item['payout_id']] = item
scan_kwargs = {
    'FilterExpression': boto3.dynamodb.conditions.Attr('user_id').eq('${userSub}')
        & boto3.dynamodb.conditions.Attr('status').is_in(['requested', 'approved', 'processing']),
}
while True:
    sresp = tbl.scan(**scan_kwargs)
    for item in sresp.get('Items', []):
        active[item['payout_id']] = item
    lek = sresp.get('LastEvaluatedKey')
    if not lek:
        break
    scan_kwargs['ExclusiveStartKey'] = lek
for pid in active:
    tbl.update_item(
        Key={'payout_id': pid},
        UpdateExpression='SET #s = :s',
        ExpressionAttributeNames={'#s': 'status'},
        ExpressionAttributeValues={':s': 'cancelled'},
    )
tbl.delete_item(Key={'payout_id': 'PAYOUT_STATE#${userSub}'})
print('cleaned')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
}

/**
 * Ensure CreatorPayouts DDB table exists with required GSIs.
 */
function ensurePayoutsTable(): void {
  execSync(
    `${PYTHON} -c "
import boto3, os
from pathlib import Path

env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
try:
    ddb.meta.client.describe_table(TableName='CreatorPayouts')
    print('exists')
except Exception:
    ddb.create_table(
        TableName='CreatorPayouts',
        AttributeDefinitions=[
            {'AttributeName': 'payout_id', 'AttributeType': 'S'},
            {'AttributeName': 'user_id', 'AttributeType': 'S'},
            {'AttributeName': 'created_at', 'AttributeType': 'N'},
            {'AttributeName': 'status', 'AttributeType': 'S'},
        ],
        KeySchema=[{'AttributeName': 'payout_id', 'KeyType': 'HASH'}],
        BillingMode='PAY_PER_REQUEST',
        GlobalSecondaryIndexes=[
            {
                'IndexName': 'ByUserCreatedAt',
                'KeySchema': [
                    {'AttributeName': 'user_id', 'KeyType': 'HASH'},
                    {'AttributeName': 'created_at', 'KeyType': 'RANGE'},
                ],
                'Projection': {'ProjectionType': 'ALL'},
            },
            {
                'IndexName': 'ByStatusCreatedAt',
                'KeySchema': [
                    {'AttributeName': 'status', 'KeyType': 'HASH'},
                    {'AttributeName': 'created_at', 'KeyType': 'RANGE'},
                ],
                'Projection': {'ProjectionType': 'ALL'},
            },
        ],
    )
    import time
    time.sleep(2)
    print('created')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
}


/**
 * Reset Alice's payout state for a deterministic request: cancel all active
 * payouts + drop the sentinel, then top up settled balance so the next request
 * has funds. Survives full-suite accumulation regardless of prior pending state.
 */
function resetAndSeed(userSub: string): void {
  cleanupActivePayouts(userSub);
  seedOldCredits(userSub, 2, 5000); // +$100 settled, past-hold
}

// =============================================================================
// Test setup
// =============================================================================

let alicePage: Page;
let rootPage: Page;

test.beforeAll(async ({ browser }) => {
  ensurePayoutsTable();
  cleanupActivePayouts(ALICE_ID);

  // Seed billing ledger credits for Alice (5 entries x 5000 cents = $250)
  seedOldCredits(ALICE_ID, 5, 5000);

  alicePage = await newIdentityPage(browser, "alice");
  rootPage = await newIdentityPage(browser, "root");
});

test.afterAll(async () => {
  await alicePage?.close();
  await rootPage?.close();
});


// =============================================================================
// Section 115: Payout Balance + Request API (5 tests)
// =============================================================================

test.describe("115 - Payout Balance + Request API", () => {

  test("115.1 GET /ui/payouts/balance returns balance with all fields", async () => {
    const resp = await apiGet(alicePage, "/ui/payouts/balance");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.available_cents).toBeGreaterThan(0);
    expect(data.currency).toBe("USD");
    expect(data.minimum_payout_cents).toBeGreaterThan(0);
    expect(typeof data.pending_cents).toBe("number");
    expect(typeof data.hold_cents).toBe("number");
    expect(typeof data.total_earned_cents).toBe("number");
  });

  test("115.2 POST /ui/payouts/request creates a payout request", async () => {
    resetAndSeed(ALICE_ID);

    const resp = await apiPost(alicePage, "alice", "/ui/payouts/request", {
      amount_cents: 2000,
      method: "bank_transfer",
      notes: `E2E payout ${TS}`,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.payout_id).toBeTruthy();
    expect(data.amount_cents).toBe(2000);
    expect(data.status).toBe("requested");
  });

  test("115.3 duplicate payout request returns 409", async () => {
    // There should be an active payout from 115.2
    const resp = await apiPost(alicePage, "alice", "/ui/payouts/request", {
      amount_cents: 1000,
      method: "bank_transfer",
    });
    expect(resp.status()).toBe(409);
  });

  test("115.4 below-minimum payout returns 400 or 422", async () => {
    cleanupActivePayouts(ALICE_ID);
    const resp = await apiPost(alicePage, "alice", "/ui/payouts/request", {
      amount_cents: 50,
      method: "bank_transfer",
    });
    expect([400, 422]).toContain(resp.status());
  });

  test("115.5 GET /ui/payouts lists payouts", async () => {
    const resp = await apiGet(alicePage, "/ui/payouts");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.items)).toBe(true);
    expect(data.items.length).toBeGreaterThanOrEqual(1);
    const first = data.items[0];
    expect(first.payout_id).toBeTruthy();
    expect(typeof first.amount_cents).toBe("number");
    expect(typeof first.status).toBe("string");
    expect(typeof first.created_at).toBe("number");
  });
});


// =============================================================================
// Section 116: Admin Payout Workflow API (5 tests)
// =============================================================================

test.describe("116 - Admin Payout Workflow API", () => {
  let approvePayoutId: string;
  let rejectPayoutId: string;

  test("116.1 admin lists pending payouts", async () => {
    // Create a fresh payout
    resetAndSeed(ALICE_ID);
    const createResp = await apiPost(alicePage, "alice", "/ui/payouts/request", {
      amount_cents: 3000,
      method: "bank_transfer",
      notes: `admin_test_${TS}`,
    });
    expect(createResp.status()).toBe(201);
    approvePayoutId = (await createResp.json()).payout_id;

    const resp = await apiGet(rootPage, "/v1/admin/payouts", { status: "requested" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeInstanceOf(Array);
    const found = data.items.some(
      (p: { payout_id: string }) => p.payout_id === approvePayoutId,
    );
    expect(found).toBe(true);
  });

  test("116.2 admin approves payout", async () => {
    const resp = await apiPost(rootPage, "root", `/v1/admin/payouts/${approvePayoutId}/approve`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("approved");
  });

  test("116.3 admin marks payout paid (complete)", async () => {
    const resp = await apiPost(rootPage, "root", `/v1/admin/payouts/${approvePayoutId}/complete`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("completed");
  });

  test("116.4 admin rejects payout with reason", async () => {
    // Create another payout to reject
    resetAndSeed(ALICE_ID);
    const createResp = await apiPost(alicePage, "alice", "/ui/payouts/request", {
      amount_cents: 2000,
      method: "paypal",
    });
    expect(createResp.status()).toBe(201);
    rejectPayoutId = (await createResp.json()).payout_id;

    const resp = await apiPost(rootPage, "root", `/v1/admin/payouts/${rejectPayoutId}/reject`, {
      reason: "Test rejection reason",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("rejected");
  });

  test("116.5 admin views payout stats", async () => {
    const resp = await apiGet(rootPage, "/v1/admin/payouts/stats");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.total_requested).toBe("number");
    expect(typeof data.total_requested_amount_cents).toBe("number");
    expect(typeof data.total_approved).toBe("number");
    expect(typeof data.total_processing).toBe("number");
  });
});


// =============================================================================
// Section 117: Payout State Transitions (4 tests)
// =============================================================================

test.describe("117 - Payout State Transitions", () => {

  test("117.1 cancel payout changes status to cancelled", async () => {
    resetAndSeed(ALICE_ID);
    const createResp = await apiPost(alicePage, "alice", "/ui/payouts/request", {
      amount_cents: 1500,
      method: "bank_transfer",
    });
    expect(createResp.status()).toBe(201);
    const id = (await createResp.json()).payout_id;

    const cancelResp = await apiPost(alicePage, "alice", `/ui/payouts/${id}/cancel`);
    expect(cancelResp.status()).toBe(200);
    const data = await cancelResp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("cancelled");
  });

  test("117.2 cannot approve a cancelled payout", async () => {
    resetAndSeed(ALICE_ID);
    const createResp = await apiPost(alicePage, "alice", "/ui/payouts/request", {
      amount_cents: 1500,
      method: "bank_transfer",
    });
    expect(createResp.status()).toBe(201);
    const id = (await createResp.json()).payout_id;

    // Cancel first
    await apiPost(alicePage, "alice", `/ui/payouts/${id}/cancel`);

    // Try to approve
    const approveResp = await apiPost(rootPage, "root", `/v1/admin/payouts/${id}/approve`);
    expect(approveResp.status()).toBe(400);
  });

  test("117.3 cannot cancel a completed payout", async () => {
    resetAndSeed(ALICE_ID);
    const createResp = await apiPost(alicePage, "alice", "/ui/payouts/request", {
      amount_cents: 1500,
      method: "bank_transfer",
    });
    expect(createResp.status()).toBe(201);
    const id = (await createResp.json()).payout_id;

    await apiPost(rootPage, "root", `/v1/admin/payouts/${id}/approve`);
    await apiPost(rootPage, "root", `/v1/admin/payouts/${id}/complete`);

    const cancelResp = await apiPost(alicePage, "alice", `/ui/payouts/${id}/cancel`);
    expect(cancelResp.status()).toBe(400);
  });

  test("117.4 hold period: fresh credit is not available for payout", async () => {
    // Seed a very recent credit (within hold period)
    execSync(
      `${PYTHON} -c "
import boto3, os, uuid, time
from pathlib import Path

env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('billing')
ts = int(time.time()) - 60  # 1 minute ago, within 7-day hold
entry_id = uuid.uuid4().hex
tbl.put_item(Item={
    'pk': 'USER#${ALICE_ID}',
    'sk': f'LEDGER#{ts}#{entry_id}',
    'entry_id': entry_id,
    'ts': ts,
    'type': 'credit',
    'amount_cents': 99999,
    'currency': 'USD',
    'state': 'settled',
    'reason': 'Tip: hold_test_${TS}',
    'meta': {'content_type': 'message'},
})
print('hold credit seeded')
"`,
      { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
    );

    const resp = await apiGet(alicePage, "/ui/payouts/balance");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // The fresh credit should be in hold_cents, not available_cents
    expect(data.hold_cents).toBeGreaterThanOrEqual(99999);
  });
});


// =============================================================================
// Section 118: PayoutDashboard UI (4 tests)
// =============================================================================

test.describe("118 - PayoutDashboard UI", () => {
  let uiPage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    cleanupActivePayouts(ALICE_ID);
    uiPage = await browser.newPage();
    await injectAuth(uiPage, "alice");
  });

  test.afterAll(async () => {
    await uiPage?.close();
  });

  test("118.1 page loads with balance cards", async () => {
    await uiPage.goto(`${BASE}/payouts`, { waitUntil: "domcontentloaded" });
    await expect(uiPage.getByRole("heading", { name: "Payouts" })).toBeVisible({ timeout: 10_000 });
    await expect(uiPage.getByTestId("available-balance")).toBeVisible();
    await expect(uiPage.getByTestId("pending-balance")).toBeVisible();
    await expect(uiPage.getByTestId("hold-balance")).toBeVisible();
    await expect(uiPage.getByTestId("total-earned")).toBeVisible();
  });

  test("118.2 request payout form is visible", async () => {
    await uiPage.goto(`${BASE}/payouts`, { waitUntil: "domcontentloaded" });
    await expect(uiPage.getByText("Request Payout").first()).toBeVisible({ timeout: 10_000 });
    await expect(uiPage.locator("#payout-amount")).toBeVisible();
    await expect(uiPage.getByRole("button", { name: "Request Payout" })).toBeVisible();
  });

  test("118.3 payout history section renders", async () => {
    await uiPage.goto(`${BASE}/payouts`, { waitUntil: "domcontentloaded" });
    await expect(uiPage.getByText("Payout History").first()).toBeVisible({ timeout: 10_000 });
  });

  test("118.4 earnings breakdown section renders with date range buttons", async () => {
    await uiPage.goto(`${BASE}/payouts`, { waitUntil: "domcontentloaded" });
    await expect(uiPage.getByText("Earnings Breakdown").first()).toBeVisible({ timeout: 10_000 });
    await expect(uiPage.getByRole("button", { name: "All time" })).toBeVisible();
    await expect(uiPage.getByRole("button", { name: "Last 30 days" })).toBeVisible();
    await expect(uiPage.getByRole("button", { name: "Last 7 days" })).toBeVisible();
  });
});
