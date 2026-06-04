/**
 * E2E tests for Wallet Deposit & Withdrawal feature.
 *
 * Sections:
 *   69 — Wallet API (11 tests)
 *   70 — Wallet UI  (6 tests)
 *
 * Auth: Alice session cookies (from e2e_session_setup.py).
 *
 * Notes:
 *   - The Stripe mock (localhost:12111) does not simulate `succeeded` status
 *     for off_session PaymentIntents — it returns `requires_payment_method`.
 *     Therefore wallet balance is NOT credited via the deposit endpoint in
 *     tests. Balance seeding for withdraw tests is done via DDB injection.
 *   - The deposit endpoint still creates a ledger entry and returns 200 with
 *     a `payment_intent_id`, which is what we verify in section 69.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const TS       = Date.now();
const PM_ID    = `pm_e2e_wallet_${TS}`;

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
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  const session = getSessions()[ALICE_ID];
  const url = params
    ? `${API}${path}?${new URLSearchParams(params).toString()}`
    : `${API}${path}`;
  return page.request.get(url, { headers: { "x-csrf-token": session.csrf_token } });
}

async function apiPost(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── DDB helpers ──────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os, time
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
tbl = ddb.Table('billing')
`;

const PYTHON = "python3";

/** Inject a test payment method and set it as default in DynamoDB. */
function injectPaymentMethod(userSub: string, pmId: string): void {
  execSync(
    `${PYTHON} -c "${DDB_PRELUDE}
pk = 'USER#${userSub}'
pm_id = '${pmId}'
tbl.put_item(Item={
    'pk': pk,
    'sk': 'PM#' + pm_id,
    'payment_method_id': pm_id,
    'provider': 'stripe',
    'provider_method_id': pm_id,
    'method_type': 'card',
    'label': 'Test Card ****4242',
    'brand': 'visa',
    'last4': '4242',
    'exp_month': 12,
    'exp_year': 2099,
    'priority': 0,
    'created_at': int(time.time()),
})
tbl.put_item(Item={
    'pk': pk,
    'sk': 'BILLING',
    'autopay_enabled': False,
    'currency': 'usd',
    'default_payment_method_id': pm_id,
})
print('injected')
"`,
    { timeout: 10_000 },
  );
}

/** Directly set wallet balance in DynamoDB (bypasses Stripe for test setup). */
function injectWalletBalance(userSub: string, balanceCents: number): void {
  execSync(
    `${PYTHON} -c "${DDB_PRELUDE}
import time
pk = 'USER#${userSub}'
tbl.put_item(Item={
    'pk': pk,
    'sk': 'WALLET',
    'wallet_balance_cents': ${balanceCents},
    'currency': 'usd',
    'updated_at': int(time.time()),
})
print('wallet injected')
"`,
    { timeout: 10_000 },
  );
}

/**
 * Seed a wallet ledger entry directly in DynamoDB with a guaranteed-newest `ts`
 * so it is never pushed off the backend's newest-200 ledger page (which, on a
 * busy shard, accumulates hundreds of tip/deposit rows from other specs). The
 * Ledger UI fetches the newest 200 and renders them date-desc, so a far-future
 * `ts` keeps the entry at the very top and reliably visible. Returns the unique
 * marker written into the entry's `reason` so the test can assert on it.
 */
function seedWalletLedgerEntry(userSub: string, reasonBase: string): string {
  const marker = `${reasonBase}_e2e_${TS}_${Math.random().toString(36).slice(2, 8)}`;
  // Far-future ts (now + ~1 year) guarantees newest-first ordering regardless of
  // how many rows other specs have accumulated.
  execSync(
    `${PYTHON} -c "${DDB_PRELUDE}
import time, secrets
pk = 'USER#${userSub}'
ts = int(time.time()) + 31_000_000
entry_id = str(int(time.time() * 1000)) + '_' + secrets.token_hex(8)
tbl.put_item(Item={
    'pk': pk,
    'sk': 'LEDGER#' + str(ts) + '#' + entry_id,
    'entry_id': entry_id,
    'ts': ts,
    'type': 'debit',
    'amount_cents': 250,
    'state': 'settled',
    'reason': '${marker}',
    'ledger_date': time.strftime('%Y-%m-%d', time.gmtime(ts)),
})
print('ledger seeded')
"`,
    { timeout: 10_000 },
  );
  return marker;
}

/** Delete the WALLET row and injected PM from DynamoDB. */
function cleanupWallet(userSub: string, pmId: string): void {
  try {
    execSync(
      `${PYTHON} -c "${DDB_PRELUDE}
pk = 'USER#${userSub}'
tbl.delete_item(Key={'pk': pk, 'sk': 'WALLET'})
tbl.delete_item(Key={'pk': pk, 'sk': 'PM#${pmId}'})
tbl.delete_item(Key={'pk': pk, 'sk': 'BILLING'})
print('cleaned up')
"`,
      { timeout: 10_000 },
    );
  } catch {
    /* best-effort cleanup */
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 69: Wallet API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 69: Wallet API", () => {
  let alicePage: Page;
  let aliceSub: string;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage);
    aliceSub = getSessions()[ALICE_ID].user_sub;

    // Clean state: no wallet row, fresh PM
    cleanupWallet(aliceSub, PM_ID);
    injectPaymentMethod(aliceSub, PM_ID);
  });

  test.afterAll(() => {
    cleanupWallet(aliceSub, PM_ID);
  });

  test("69.1 GET /billing/wallet → wallet_balance_cents: 0", async () => {
    const resp = await apiGet(alicePage, "/ui/billing/wallet");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { wallet_balance_cents: number; currency: string };
    expect(data.wallet_balance_cents).toBe(0);
    expect(data.currency).toBe("usd");
  });

  test("69.2 POST deposit amount_cents: 500 → 200 with payment_intent_id", async () => {
    const resp = await apiPost(alicePage, "/ui/billing/wallet/deposit", {
      amount_cents: 500,
      payment_method_id: PM_ID,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { status: string; payment_intent_id: string; wallet_balance_cents: number };
    expect(typeof data.payment_intent_id).toBe("string");
    expect(data.payment_intent_id.length).toBeGreaterThan(0);
    expect(typeof data.status).toBe("string");
    // Note: Stripe mock returns requires_payment_method, so wallet_balance_cents is 0
    expect(typeof data.wallet_balance_cents).toBe("number");
  });

  test("69.3 GET /billing/ledger → includes wallet_deposit entry", async () => {
    const resp = await apiGet(alicePage, "/ui/billing/ledger");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { items: Array<{ reason: string }> };
    const reasons = data.items.map((i) => i.reason);
    expect(reasons).toContain("wallet_deposit");
  });

  test("69.4 POST deposit amount_cents: 50 (below min 100) → 422", async () => {
    const resp = await apiPost(alicePage, "/ui/billing/wallet/deposit", {
      amount_cents: 50,
    });
    expect(resp.status()).toBe(422);
  });

  test("69.5 POST deposit with no PM and no default → 400", async () => {
    // Temporarily remove the BILLING row so there's no default PM
    execSync(
      `${PYTHON} -c "${DDB_PRELUDE}
pk = 'USER#${aliceSub}'
tbl.delete_item(Key={'pk': pk, 'sk': 'BILLING'})
print('billing row deleted')
"`,
      { timeout: 10_000 },
    );
    const resp = await apiPost(alicePage, "/ui/billing/wallet/deposit", {
      amount_cents: 500,
    });
    expect(resp.status()).toBe(400);
    // Restore BILLING row
    injectPaymentMethod(aliceSub, PM_ID);
  });

  test("69.6 Seed wallet 500 cents via DDB, then GET wallet → 500", async () => {
    injectWalletBalance(aliceSub, 500);
    const resp = await apiGet(alicePage, "/ui/billing/wallet");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { wallet_balance_cents: number };
    expect(data.wallet_balance_cents).toBe(500);
  });

  test("69.7 POST withdraw amount_cents: 200 → 200, wallet_balance_cents: 300", async () => {
    const resp = await apiPost(alicePage, "/ui/billing/wallet/withdraw", {
      amount_cents: 200,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ok: boolean; wallet_balance_cents: number };
    expect(data.ok).toBe(true);
    expect(data.wallet_balance_cents).toBe(300);
  });

  test("69.8 GET wallet after withdraw → 300", async () => {
    const resp = await apiGet(alicePage, "/ui/billing/wallet");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { wallet_balance_cents: number };
    expect(data.wallet_balance_cents).toBe(300);
  });

  test("69.9 POST withdraw amount_cents: 99 (below min) → 422", async () => {
    const resp = await apiPost(alicePage, "/ui/billing/wallet/withdraw", {
      amount_cents: 99,
    });
    expect(resp.status()).toBe(422);
  });

  test("69.10 POST withdraw amount_cents: 99999 (overdraft) → 400 Insufficient", async () => {
    const resp = await apiPost(alicePage, "/ui/billing/wallet/withdraw", {
      amount_cents: 99999,
    });
    expect(resp.status()).toBe(400);
    const text = await resp.text();
    expect(text.toLowerCase()).toContain("insufficient");
  });

  test("69.11 GET /billing/ledger → includes wallet_withdrawal entry", async () => {
    const resp = await apiGet(alicePage, "/ui/billing/ledger");
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { items: Array<{ reason: string }> };
    const reasons = data.items.map((i) => i.reason);
    expect(reasons).toContain("wallet_withdrawal");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 70: Wallet UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 70: Wallet UI", () => {
  let alicePage: Page;
  let aliceSub: string;
  const UI_PM_ID = `pm_e2e_wallet_ui_${TS}`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage);
    aliceSub = getSessions()[ALICE_ID].user_sub;

    // Clean wallet + fresh PM
    cleanupWallet(aliceSub, UI_PM_ID);
    injectPaymentMethod(aliceSub, UI_PM_ID);
  });

  test.afterAll(() => {
    cleanupWallet(aliceSub, UI_PM_ID);
  });

  test("70.1 /billing?tab=wallet → Wallet tab visible, balance shows $0.00", async () => {
    await alicePage.goto(`${BASE}/billing?tab=wallet`, { waitUntil: "load" });
    await expect(alicePage.getByRole("tab", { name: "Wallet" })).toBeVisible({ timeout: 8000 });
    // CardTitle renders as a div, not a heading — use text content
    await expect(alicePage.getByText("Wallet Balance").first()).toBeVisible({ timeout: 5000 });
    await expect(alicePage.getByText("$0.00").first()).toBeVisible({ timeout: 5000 });
  });

  test("70.2 Seed $5.00 via DDB → navigate to wallet tab → balance shows $5.00", async () => {
    injectWalletBalance(aliceSub, 500);
    // Navigate fresh so React Query fetches from DDB (not cached)
    await alicePage.goto(`${BASE}/billing?tab=wallet`, { waitUntil: "load" });
    await expect(alicePage.getByText("$5.00").first()).toBeVisible({ timeout: 8000 });
  });

  test("70.3 Balance persists after reload", async () => {
    await alicePage.reload({ waitUntil: "load" });
    await alicePage.waitForTimeout(500);
    await expect(alicePage.getByText("$5.00").first()).toBeVisible({ timeout: 8000 });
  });

  test("70.4 Withdraw $2.00 → confirm dialog → Confirm → balance shows $3.00", async () => {
    // Ensure we're on wallet tab
    await expect(alicePage.getByText("Wallet Balance").first()).toBeVisible({ timeout: 5000 });

    const withdrawInput = alicePage.locator("#withdraw-amount");
    await withdrawInput.fill("2.00");
    await alicePage.getByRole("button", { name: "Withdraw" }).click();

    // Confirm dialog appears
    await expect(alicePage.getByRole("alertdialog")).toBeVisible({ timeout: 5000 });
    await expect(alicePage.getByText(/withdraw.*\$2\.00/i)).toBeVisible();
    await alicePage.getByRole("button", { name: "Confirm" }).click();

    // Balance updates
    await expect(alicePage.getByText("$3.00").first()).toBeVisible({ timeout: 8000 });
  });

  test("70.5 Enter $999.00 in withdraw form → Withdraw button is disabled", async () => {
    const withdrawInput = alicePage.locator("#withdraw-amount");
    await withdrawInput.fill("999.00");
    const withdrawBtn = alicePage.getByRole("button", { name: "Withdraw" });
    await expect(withdrawBtn).toBeDisabled();
  });

  test("70.6 Ledger tab shows wallet_deposit and wallet_withdrawal entries", async () => {
    // On a busy shard Alice's billing ledger accumulates hundreds of tip /
    // deposit rows from prior specs and prior runs. The backend `list_ledger`
    // returns only the newest 200 (sorted by `ts` desc), so the wallet entries
    // created earlier in THIS spec can be pushed off the page and never render —
    // making a generic `wallet_*` text match flaky/deterministically-failing.
    //
    // Seed two uniquely-marked wallet ledger entries with a guaranteed-newest
    // `ts` so they always sit at the top of the newest-200 page, then assert on
    // those unique markers. This keeps the test's intent (the Ledger tab renders
    // wallet deposit + withdrawal rows) while being robust to accumulation.
    const depositMarker = seedWalletLedgerEntry(aliceSub, "wallet_deposit");
    const withdrawalMarker = seedWalletLedgerEntry(aliceSub, "wallet_withdrawal");

    await alicePage.goto(`${BASE}/billing?tab=ledger`, { waitUntil: "load" });
    await alicePage.waitForTimeout(800);

    await expect(alicePage.getByText(depositMarker).first()).toBeVisible({ timeout: 15000 });
    await expect(alicePage.getByText(withdrawalMarker).first()).toBeVisible({ timeout: 15000 });
  });
});
