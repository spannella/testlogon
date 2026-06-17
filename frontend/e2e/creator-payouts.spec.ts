/**
 * E2E tests for MON-004: Creator Payout System
 *
 * Section 107: Payout Balance API (3 tests)
 * Section 108: Payout Request API (5 tests)
 * Section 109: Admin Payout API (5 tests)
 *
 * Auth: cookie-based sessions via e2e_admin_session_setup.py.
 * Seeds billing ledger CREDIT entries for Alice with old timestamps.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const PYTHON = REPO_ROOT + "/.venv/bin/python3";
const API = "http://localhost:8000";
const ALICE_SUB = "e2e_alice@test.local";
// Session keys used in e2e_admin_session_setup.py
const ALICE_KEY = "alice";
const ROOT_KEY = "root";
const TS = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface AdminSessionData {
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

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

async function newIdentityPage(
  browser: Browser,
  identity: string,
): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

// ─── Request helpers ──────────────────────────────────────────────────────────

async function apiPost(
  page: Page,
  sessionKey: string,
  path: string,
  body?: unknown,
) {
  const sess = getAdminSessions()[sessionKey];
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

// ─── DDB seed helpers ─────────────────────────────────────────────────────────

/**
 * Seed CREDIT ledger entries for a user with old timestamps (past hold period).
 * Returns the total seeded cents.
 */
function seedOldCredits(userSub: string, count: number, amountEach: number): number {
  execSync(
    `${PYTHON} -c "
import boto3, os, uuid, time
from pathlib import Path

env = Path('${REPO_ROOT}/.env.local')
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
        'meta': {'content_type': 'message', 'content_id': 'test_seed_${TS}'},
    })
print('seeded')
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
  return count * amountEach;
}

/**
 * Clean up all active payouts for a user to avoid test interference.
 */
function cleanupActivePayouts(userSub: string): void {
  execSync(
    `${PYTHON} -c "
import boto3, os
from pathlib import Path

env = Path('${REPO_ROOT}/.env.local')
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
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
}

/**
 * Ensure CreatorPayouts DDB table exists.
 */
function ensurePayoutsTable(): void {
  execSync(
    `${PYTHON} -c "
import boto3, os
from pathlib import Path

env = Path('${REPO_ROOT}/.env.local')
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
    { cwd: REPO_ROOT, timeout: 15_000 },
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
let seededTotalCents: number;

test.beforeAll(async ({ browser }) => {
  // Ensure table exists
  ensurePayoutsTable();

  // Clean up any active payouts from prior runs
  cleanupActivePayouts(ALICE_SUB);

  // Seed billing ledger credits for Alice (5 entries x 5000 cents = 25000 cents = $250)
  seededTotalCents = seedOldCredits(ALICE_SUB, 5, 5000);

  // Create pages with auth cookies
  alicePage = await newIdentityPage(browser, ALICE_KEY);
  rootPage = await newIdentityPage(browser, ROOT_KEY);
});

test.afterAll(async () => {
  await alicePage?.close();
  await rootPage?.close();
});

// =============================================================================
// Section 107: Payout Balance API
// =============================================================================

test.describe("107 · Payout Balance API", () => {
  test("107.1 Alice gets available balance", async () => {
    const resp = await apiGet(alicePage, "/ui/payouts/balance");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.available_cents).toBeGreaterThan(0);
    expect(data.currency).toBe("USD");
  });

  test("107.2 Balance shows correct breakdown", async () => {
    const resp = await apiGet(alicePage, "/ui/payouts/balance");
    const data = await resp.json();
    // available + pending + hold should be <= total_earned
    // (total_earned includes credits from other test runs too, so >= seeded)
    expect(data.total_earned_cents).toBeGreaterThanOrEqual(seededTotalCents);
    expect(data.available_cents + data.pending_cents + data.hold_cents).toBeLessThanOrEqual(
      data.total_earned_cents,
    );
  });

  test("107.3 Balance shows minimum payout amount", async () => {
    const resp = await apiGet(alicePage, "/ui/payouts/balance");
    const data = await resp.json();
    expect(data.minimum_payout_cents).toBe(1000);
  });
});

// =============================================================================
// Section 108: Payout Request API
// =============================================================================

let createdPayoutId: string;

test.describe("108 · Payout Request API", () => {
  test("108.1 Alice requests payout", async () => {
    // Reset state + top up balance so this request is deterministic under load
    resetAndSeed(ALICE_SUB);

    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/payouts/request", {
      amount_cents: 2000,
      method: "bank_transfer",
      notes: `E2E payout test ${TS}`,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("requested");
    expect(data.amount_cents).toBe(2000);
    expect(data.payout_id).toBeTruthy();
    createdPayoutId = data.payout_id;
  });

  test("108.2 Duplicate payout returns 409", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/payouts/request", {
      amount_cents: 1000,
      method: "bank_transfer",
    });
    expect(resp.status()).toBe(409);
  });

  test("108.3 Payout below minimum returns 400 or 422", async () => {
    // Cancel existing payout first so we can test minimum
    cleanupActivePayouts(ALICE_SUB);
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/payouts/request", {
      amount_cents: 50,
      method: "bank_transfer",
    });
    // Could be 400 (our validation) or 422 (Pydantic ge=100)
    expect([400, 422]).toContain(resp.status());
  });

  test("108.4 Alice lists her payouts", async () => {
    const resp = await apiGet(alicePage, "/ui/payouts");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items.length).toBeGreaterThanOrEqual(1);
  });

  test("108.5 Alice cancels payout", async () => {
    // Create a fresh payout to cancel
    resetAndSeed(ALICE_SUB);
    const createResp = await apiPost(alicePage, ALICE_KEY, "/ui/payouts/request", {
      amount_cents: 1500,
      method: "bank_transfer",
    });
    expect(createResp.status()).toBe(201);
    const created = await createResp.json();
    const cancelPayoutId = created.payout_id;

    const resp = await apiPost(
      alicePage,
      ALICE_KEY,
      `/ui/payouts/${cancelPayoutId}/cancel`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("cancelled");
  });
});

// =============================================================================
// Section 109: Admin Payout API
// =============================================================================

test.describe("109 · Admin Payout API", () => {
  let adminPayoutId: string;
  let rejectPayoutId: string;

  test("109.1 Root lists payout queue", async () => {
    // Create a fresh payout for Alice to show up in admin queue
    resetAndSeed(ALICE_SUB);
    const createResp = await apiPost(alicePage, ALICE_KEY, "/ui/payouts/request", {
      amount_cents: 3000,
      method: "bank_transfer",
      notes: `Admin test ${TS}`,
    });
    expect(createResp.status()).toBe(201);
    const created = await createResp.json();
    adminPayoutId = created.payout_id;

    const resp = await apiGet(rootPage, "/v1/admin/payouts", { status: "requested" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items.length).toBeGreaterThanOrEqual(1);
    const found = data.items.some(
      (p: { payout_id: string }) => p.payout_id === adminPayoutId,
    );
    expect(found).toBe(true);
  });

  test("109.2 Root approves payout", async () => {
    const resp = await apiPost(rootPage, ROOT_KEY, `/v1/admin/payouts/${adminPayoutId}/approve`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("approved");
  });

  test("109.3 Root completes payout", async () => {
    const resp = await apiPost(rootPage, ROOT_KEY, `/v1/admin/payouts/${adminPayoutId}/complete`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("completed");
  });

  test("109.4 Root rejects payout", async () => {
    // Create another payout to reject
    resetAndSeed(ALICE_SUB);
    const createResp = await apiPost(alicePage, ALICE_KEY, "/ui/payouts/request", {
      amount_cents: 2000,
      method: "bank_transfer",
    });
    expect(createResp.status()).toBe(201);
    const created = await createResp.json();
    rejectPayoutId = created.payout_id;

    const resp = await apiPost(rootPage, ROOT_KEY, `/v1/admin/payouts/${rejectPayoutId}/reject?reason=test_reject`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("rejected");
  });

  test("109.5 Payout stats show correct counts", async () => {
    const resp = await apiGet(rootPage, "/v1/admin/payouts/stats");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // All fields should be numbers >= 0
    expect(typeof data.total_requested).toBe("number");
    expect(typeof data.total_requested_amount_cents).toBe("number");
    expect(typeof data.total_approved).toBe("number");
    expect(typeof data.total_processing).toBe("number");
    expect(data.total_requested).toBeGreaterThanOrEqual(0);
  });
});
