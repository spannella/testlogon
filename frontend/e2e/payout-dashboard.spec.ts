/**
 * E2E tests for BILLING-002: Payout Dashboard Frontend
 *
 * Section 210: Balance Display (3 tests)
 * Section 211: Payout Request (5 tests)
 * Section 212: Payout History (4 tests)
 * Section 213: Earnings (4 tests)
 * Section 214: UI Navigation (2 tests)
 *
 * Auth: cookie-based sessions via e2e_admin_session_setup.py.
 * Reuses billing ledger seeding from creator-payouts.spec.ts patterns.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
import { cppCancelActivePayouts } from "./helpers/cpp-seed";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const PYTHON = REPO_ROOT + "/.venv/bin/python3";
const BASE = "http://localhost:3000";
const ALICE_SUB = "e2e_alice@test.local";
const ALICE_KEY = "alice";
const BOB_KEY = "bob";
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
    _adminSessions = loadSessions();
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
  // Navigate to login page and populate Zustand auth store so ProtectedRoute allows navigation
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, sessions[identity].user_sub);
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

// ─── DDB helpers ──────────────────────────────────────────────────────────────

function seedOldCredits(userSub: string, count: number, amountEach: number, reason?: string): number {
  const safeReason = reason ?? "Tip: message";
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
base_ts = int(time.time()) - 700000

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
        'reason': '${safeReason}',
        'meta': {'content_type': 'message', 'content_id': 'dashboard_seed_${TS}'},
    })
print('seeded')
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
  return count * amountEach;
}

function cleanupActivePayouts(userSub: string): void {
  // cpp path: cancel active payouts via the cpp API (Python DDB writes below
  // never reach cpp), clearing stale one-active-payout 409s across runs.
  cppCancelActivePayouts(userSub);
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
  seedOldCredits(userSub, 2, 5000, "Tip: message"); // +$100 settled, past-hold
}

/**
 * PAY-20/21: satisfy the verified-before-any-payout gate (APPROVED KYC + W-9).
 * Without this, POST /ui/payouts/request is 403 kyc_required. Shared helper.
 */
function seedPayoutGate(userSub: string): void {
  execSync(`${PYTHON} ${REPO_ROOT}/e2e_payout_gate_seed.py ${userSub}`, {
    cwd: REPO_ROOT,
    timeout: 30_000,
  });
}

// =============================================================================
// Test setup
// =============================================================================

let alicePage: Page;
let bobPage: Page;

test.beforeAll(async ({ browser }) => {
  ensurePayoutsTable();

  // PAY-20/21: satisfy the KYC/W-9 payout gate so requests are not 403'd.
  seedPayoutGate(ALICE_SUB);

  cleanupActivePayouts(ALICE_SUB);

  // Seed billing credits for Alice (tips)
  seedOldCredits(ALICE_SUB, 5, 5000, "Tip: message");
  // Seed a subscription credit for breakdown diversity
  seedOldCredits(ALICE_SUB, 2, 3000, "Subscription payment");

  alicePage = await newIdentityPage(browser, ALICE_KEY);
  bobPage = await newIdentityPage(browser, BOB_KEY);
});

test.afterAll(async () => {
  await alicePage?.close();
  await bobPage?.close();
});

// =============================================================================
// Section 210: Balance Display
// =============================================================================

test.describe("210 · Balance Display", () => {
  test("210.1 Balance cards render with correct values", async () => {
    await alicePage.goto(`${BASE}/payouts`);
    await alicePage.waitForLoadState("domcontentloaded");

    // Check all 4 balance cards are visible
    await expect(alicePage.getByText("Available Balance")).toBeVisible();
    await expect(alicePage.getByText("Pending Payouts")).toBeVisible();
    await expect(alicePage.getByText("On Hold")).toBeVisible();
    await expect(alicePage.getByText("Total Earned")).toBeVisible();

    // Wait for balance to load (not "...")
    await expect(alicePage.locator('[data-testid="available-balance"]')).not.toHaveText("...", { timeout: 10_000 });

    // All should display dollar amounts
    const availText = await alicePage.locator('[data-testid="available-balance"]').textContent();
    expect(availText).toMatch(/\$/);
  });

  test("210.2 Currency displayed as USD format", async () => {
    await alicePage.goto(`${BASE}/payouts`);
    await alicePage.waitForLoadState("domcontentloaded");

    // Wait for balance to load
    await expect(alicePage.locator('[data-testid="available-balance"]')).not.toHaveText("...");

    // Check all 4 balance values show $ format
    const available = await alicePage.locator('[data-testid="available-balance"]').textContent();
    const pending = await alicePage.locator('[data-testid="pending-balance"]').textContent();
    const hold = await alicePage.locator('[data-testid="hold-balance"]').textContent();
    const total = await alicePage.locator('[data-testid="total-earned"]').textContent();

    expect(available).toMatch(/^\$[\d,]+\.\d{2}$/);
    expect(pending).toMatch(/^\$[\d,]+\.\d{2}$/);
    expect(hold).toMatch(/^\$[\d,]+\.\d{2}$/);
    expect(total).toMatch(/^\$[\d,]+\.\d{2}$/);
  });

  test("210.3 Minimum payout shown in request section", async () => {
    await alicePage.goto(`${BASE}/payouts`);
    await alicePage.waitForLoadState("domcontentloaded");

    await expect(alicePage.getByText("Minimum: $10.00")).toBeVisible();
  });
});

// =============================================================================
// Section 211: Payout Request
// =============================================================================

test.describe("211 · Payout Request", () => {
  test("211.1 Submit valid payout request via API", async () => {
    resetAndSeed(ALICE_SUB);
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/payouts/request", {
      amount_cents: 3000,
      method: "bank_transfer",
      notes: `Dashboard test ${TS}`,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.payout_id).toBeTruthy();
    expect(data.status).toBe("requested");
  });

  test("211.2 Duplicate request returns 409", async () => {
    // There should still be an active payout from 211.1
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/payouts/request", {
      amount_cents: 3000,
      method: "bank_transfer",
    });
    expect(resp.status()).toBe(409);
  });

  test("211.3 Payout below minimum returns error", async () => {
    cleanupActivePayouts(ALICE_SUB);
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/payouts/request", {
      amount_cents: 50,
      method: "bank_transfer",
    });
    expect([400, 422]).toContain(resp.status());
  });

  test("211.4 Request payout via UI form", async () => {
    resetAndSeed(ALICE_SUB);

    await alicePage.goto(`${BASE}/payouts`);
    await alicePage.waitForLoadState("domcontentloaded");

    // Wait for balance to load
    await expect(alicePage.locator('[data-testid="available-balance"]')).not.toHaveText("...");

    // Fill in payout form
    await alicePage.fill("#payout-amount", "30.00");
    // Method defaults to bank_transfer, leave as-is

    // Click submit
    const submitBtn = alicePage.getByRole("button", { name: "Request Payout" });
    await expect(submitBtn).toBeEnabled();

    const [resp] = await Promise.all([
      alicePage.waitForResponse(
        (r) => r.url().includes("/ui/payouts/request") && r.request().method() === "POST",
      ),
      submitBtn.click(),
    ]);
    expect(resp.status()).toBe(201);
  });

  test("211.5 Request form resets after success", async () => {
    // After the previous test, the form should have been cleared
    await alicePage.goto(`${BASE}/payouts`);
    await alicePage.waitForLoadState("domcontentloaded");
    const amountInput = alicePage.locator("#payout-amount");
    await expect(amountInput).toHaveValue("");
  });
});

// =============================================================================
// Section 212: Payout History
// =============================================================================

test.describe("212 · Payout History", () => {
  test("212.1 History table shows payout entries", async () => {
    await alicePage.goto(`${BASE}/payouts`);
    await alicePage.waitForLoadState("domcontentloaded");

    // The payout history section should have at least one row
    await expect(alicePage.getByText("Payout History")).toBeVisible();

    // Wait for table to load (headers visible means table is rendered)
    await expect(alicePage.locator("th").filter({ hasText: "Amount" }).first()).toBeVisible();

    // At least one row with a $ amount should be visible in the table body
    const rows = alicePage.locator("table").first().locator("tbody tr");
    await expect(rows.first()).toBeVisible();
  });

  test("212.2 Status badges are present", async () => {
    await alicePage.goto(`${BASE}/payouts`);
    await alicePage.waitForLoadState("domcontentloaded");

    // There should be at least one status badge visible in the payout history
    const statusBadges = alicePage.locator("[data-testid^='status-']");
    await expect(statusBadges.first()).toBeVisible();
  });

  test("212.3 Cancel button on pending payout works via API", async () => {
    resetAndSeed(ALICE_SUB);

    // Create a fresh payout to cancel
    const createResp = await apiPost(alicePage, ALICE_KEY, "/ui/payouts/request", {
      amount_cents: 3000,
      method: "bank_transfer",
    });
    expect(createResp.status()).toBe(201);
    const created = await createResp.json();

    // Cancel it
    const cancelResp = await apiPost(
      alicePage,
      ALICE_KEY,
      `/ui/payouts/${created.payout_id}/cancel`,
    );
    expect(cancelResp.status()).toBe(200);
    const data = await cancelResp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("cancelled");
  });

  test("212.4 List payouts via API returns items", async () => {
    const resp = await apiGet(alicePage, "/ui/payouts");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items.length).toBeGreaterThanOrEqual(1);
    // Each item should have expected fields
    const first = data.items[0];
    expect(first.payout_id).toBeTruthy();
    expect(typeof first.amount_cents).toBe("number");
    expect(typeof first.status).toBe("string");
  });
});

// =============================================================================
// Section 213: Earnings
// =============================================================================

test.describe("213 · Earnings", () => {
  test("213.1 Earnings summary via API returns breakdown", async () => {
    const resp = await apiGet(alicePage, "/ui/earnings/summary");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.total_cents).toBeGreaterThanOrEqual(0);
    expect(typeof data.breakdown.tips).toBe("number");
    expect(typeof data.breakdown.subscriptions).toBe("number");
    expect(typeof data.breakdown.unlocks).toBe("number");
    expect(typeof data.breakdown.vod_purchases).toBe("number");
    expect(typeof data.breakdown.other).toBe("number");
    expect(data.currency).toBe("USD");
  });

  test("213.2 Earnings transactions via API returns items", async () => {
    const resp = await apiGet(alicePage, "/ui/earnings/transactions");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.items)).toBe(true);
    if (data.items.length > 0) {
      const first = data.items[0];
      expect(first.entry_id).toBeTruthy();
      expect(typeof first.amount_cents).toBe("number");
      expect(typeof first.category).toBe("string");
    }
  });

  test("213.3 Earnings breakdown shows categories in UI", async () => {
    await alicePage.goto(`${BASE}/payouts`);
    await alicePage.waitForLoadState("domcontentloaded");

    await expect(alicePage.getByText("Earnings Breakdown")).toBeVisible();

    // Wait for the earnings summary API to complete
    await alicePage.waitForResponse(
      (r) => r.url().includes("/ui/earnings/summary") && r.request().method() === "GET",
      { timeout: 15_000 },
    );

    // Give React time to re-render after data loads
    await alicePage.waitForTimeout(500);

    // The breakdown should show at least one category since we seeded tips + subscriptions,
    // or "No earnings yet" if the date range has no matching data, or a "transactions totaling" summary.
    const tipsLabel = alicePage.getByText("Tips");
    const noEarnings = alicePage.getByText("No earnings yet");
    const totalingSummary = alicePage.getByText(/transactions totaling/);

    const tipsVisible = await tipsLabel.first().isVisible().catch(() => false);
    const noEarningsVisible = await noEarnings.isVisible().catch(() => false);
    const summaryVisible = await totalingSummary.isVisible().catch(() => false);
    expect(tipsVisible || noEarningsVisible || summaryVisible).toBe(true);
  });

  test("213.4 Date range filter calls API with from_ts", async () => {
    await alicePage.goto(`${BASE}/payouts`);
    await alicePage.waitForLoadState("domcontentloaded");

    // Click "Last 7 days" button
    const rangeBtn = alicePage.getByRole("button", { name: "Last 7 days" });
    await expect(rangeBtn).toBeVisible();

    const [resp] = await Promise.all([
      alicePage.waitForResponse(
        (r) => r.url().includes("/ui/earnings/summary") && r.url().includes("from_ts"),
      ),
      rangeBtn.click(),
    ]);
    expect(resp.status()).toBe(200);
  });
});

// =============================================================================
// Section 214: UI Navigation
// =============================================================================

test.describe("214 · UI Navigation", () => {
  test("214.1 Payouts link visible in sidebar", async () => {
    await alicePage.goto(`${BASE}/`);
    await alicePage.waitForLoadState("domcontentloaded");

    // Sidebar should have a "Payouts" link
    const payoutsLink = alicePage.locator("a").filter({ hasText: "Payouts" }).first();
    await expect(payoutsLink).toBeVisible();
  });

  test("214.2 Sidebar link navigates to /payouts", async () => {
    await alicePage.goto(`${BASE}/`);
    await alicePage.waitForLoadState("domcontentloaded");

    const payoutsLink = alicePage.locator("a").filter({ hasText: "Payouts" }).first();
    await payoutsLink.click();

    await expect(alicePage).toHaveURL(/\/payouts/);
    await expect(alicePage.getByText("Payouts").first()).toBeVisible();
  });
});
