/**
 * E2E tests for GROUP-004 Group Treasury Management.
 *
 * Sections:
 *   459 — Treasury Balance & Contribution API (4 tests)
 *   460 — Ledger & Contributors API           (4 tests)
 *   461 — Goal & Withdrawal Block API         (4 tests)
 *   462 — Dissolution Pro-Rata API            (4 tests)
 *
 * Auth:
 *   Root   — root  (admin of test group)
 *   Alice  — alice (member of test group)
 *   Bob    — bob   (member of test group)
 *   Charlie — charlie_admin (non-member for negative tests)
 *
 * Requires: GROUP_TREASURY_ENABLED=true in .env.local
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ROOT_ID  = "root";
const ALICE_ID = "alice";
const BOB_ID   = "bob";
const CHARLIE_ID = "charlie_admin";
const TS       = Date.now();

// ── Session bootstrap ────────────────────────────────────────────────────────

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
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    (uid: string) => {
      const state = { userId: uid, accessToken: null, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    session.user_sub,
  );
}

function csrfFor(identity: string): string {
  return getSessions()[identity].csrf_token;
}

function subFor(identity: string): string {
  return getSessions()[identity].user_sub;
}

// ── API helpers ──────────────────────────────────────────────────────────────

async function apiGet(page: Page, identity: string, path: string) {
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": csrfFor(identity) },
  });
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": csrfFor(identity) },
  });
}

async function apiPatch(page: Page, identity: string, path: string, body: object) {
  return page.request.patch(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": csrfFor(identity) },
  });
}

// ── DDB helper ───────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os
from pathlib import Path
env_file = Path('${REPO_ROOT}/.env.local')
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
`;

function ddbExec(script: string): string {
  return execSync(`python3 -c "${DDB_PRELUDE}\n${script}"`, {
    timeout: 15_000,
  }).toString().trim();
}

// ── Group + wallet seeding ───────────────────────────────────────────────────

const GROUP_ID = `grp_treasury_${TS}`;
const DISSOLVE_GROUP_ID = `grp_dissolve_${TS}`;

function seedGroupAndWallets() {
  const rootSub = subFor(ROOT_ID);
  const aliceSub = subFor(ALICE_ID);
  const bobSub = subFor(BOB_ID);

  // Create user_groups table entries for the test group
  // Root = admin, Alice = member, Bob = member
  ddbExec(`
tbl = ddb.Table('user_groups')
import time
ts = int(time.time())
# Group META
tbl.put_item(Item={
    'pk': 'GROUP#${GROUP_ID}', 'sk': 'META',
    'group_id': '${GROUP_ID}', 'name': 'Treasury Test Group',
    'description': 'Test group for treasury E2E', 'visibility': 'public',
    'status': 'active', 'admin_user_id': '${rootSub}',
    'member_count': 3, 'created_at': ts, 'updated_at': ts,
    'GSI1PK': 'public', 'GSI1SK': ts, 'GSI2PK': 'active', 'GSI2SK': 3,
})
# Root as admin
tbl.put_item(Item={
    'pk': 'GROUP#${GROUP_ID}', 'sk': 'MEMBER#${rootSub}',
    'user_id': '${rootSub}', 'group_id': '${GROUP_ID}',
    'role': 'admin', 'status': 'active', 'display_name': 'Root',
    'joined_at': ts, 'promoted_at': ts, 'created_at': ts,
})
# Alice as member
tbl.put_item(Item={
    'pk': 'GROUP#${GROUP_ID}', 'sk': 'MEMBER#${aliceSub}',
    'user_id': '${aliceSub}', 'group_id': '${GROUP_ID}',
    'role': 'member', 'status': 'active', 'display_name': 'Alice',
    'joined_at': ts, 'promoted_at': ts, 'created_at': ts,
})
# Bob as member
tbl.put_item(Item={
    'pk': 'GROUP#${GROUP_ID}', 'sk': 'MEMBER#${bobSub}',
    'user_id': '${bobSub}', 'group_id': '${GROUP_ID}',
    'role': 'member', 'status': 'active', 'display_name': 'Bob',
    'joined_at': ts, 'promoted_at': ts, 'created_at': ts,
})
print('group seeded')
`);

  // Seed personal wallets for Alice ($500) and Bob ($300) and Root ($1000)
  ddbExec(`
import time
billing = ddb.Table('billing')
ts = int(time.time())
for sub, cents in [('${rootSub}', 100000), ('${aliceSub}', 50000), ('${bobSub}', 30000)]:
    billing.update_item(
        Key={'pk': f'USER#{sub}', 'sk': 'WALLET'},
        UpdateExpression='SET wallet_balance_cents = :amt, currency = :c, updated_at = :t',
        ExpressionAttributeValues={':amt': cents, ':c': 'usd', ':t': ts},
    )
print('wallets seeded')
`);
}

function seedDissolveGroup() {
  const rootSub = subFor(ROOT_ID);
  const aliceSub = subFor(ALICE_ID);
  const bobSub = subFor(BOB_ID);

  ddbExec(`
import time
tbl = ddb.Table('user_groups')
billing = ddb.Table('billing')
ts = int(time.time())
# Dissolve group META
tbl.put_item(Item={
    'pk': 'GROUP#${DISSOLVE_GROUP_ID}', 'sk': 'META',
    'group_id': '${DISSOLVE_GROUP_ID}', 'name': 'Dissolve Test Group',
    'description': 'Test group for dissolution', 'visibility': 'public',
    'status': 'active', 'admin_user_id': '${rootSub}',
    'member_count': 3, 'created_at': ts, 'updated_at': ts,
    'GSI1PK': 'public', 'GSI1SK': ts, 'GSI2PK': 'active', 'GSI2SK': 3,
})
# Root as admin
tbl.put_item(Item={
    'pk': 'GROUP#${DISSOLVE_GROUP_ID}', 'sk': 'MEMBER#${rootSub}',
    'user_id': '${rootSub}', 'group_id': '${DISSOLVE_GROUP_ID}',
    'role': 'admin', 'status': 'active', 'display_name': 'Root',
    'joined_at': ts, 'promoted_at': ts, 'created_at': ts,
})
# Alice as member
tbl.put_item(Item={
    'pk': 'GROUP#${DISSOLVE_GROUP_ID}', 'sk': 'MEMBER#${aliceSub}',
    'user_id': '${aliceSub}', 'group_id': '${DISSOLVE_GROUP_ID}',
    'role': 'member', 'status': 'active', 'display_name': 'Alice',
    'joined_at': ts, 'promoted_at': ts, 'created_at': ts,
})
# Bob as member
tbl.put_item(Item={
    'pk': 'GROUP#${DISSOLVE_GROUP_ID}', 'sk': 'MEMBER#${bobSub}',
    'user_id': '${bobSub}', 'group_id': '${DISSOLVE_GROUP_ID}',
    'role': 'member', 'status': 'active', 'display_name': 'Bob',
    'joined_at': ts, 'promoted_at': ts, 'created_at': ts,
})
# Seed treasury with contributions from Alice (6000) and Bob (4000) + donation (2000)
# Total = 12000, contributed=10000, donated=2000
billing.put_item(Item={
    'pk': 'GROUP#${DISSOLVE_GROUP_ID}', 'sk': 'WALLET',
    'wallet_balance_cents': 12000, 'currency': 'usd',
    'total_contributed_cents': 10000, 'total_donated_cents': 2000,
    'total_spent_cents': 0, 'created_at': ts, 'updated_at': ts,
})
# Contributor records
billing.put_item(Item={
    'pk': 'GROUP#${DISSOLVE_GROUP_ID}', 'sk': 'CONTRIB#${aliceSub}',
    'user_id': '${aliceSub}', 'display_name': 'Alice',
    'total_contributed_cents': 6000, 'contribution_count': 2,
    'first_contributed_at': ts - 100, 'last_contributed_at': ts,
})
billing.put_item(Item={
    'pk': 'GROUP#${DISSOLVE_GROUP_ID}', 'sk': 'CONTRIB#${bobSub}',
    'user_id': '${bobSub}', 'display_name': 'Bob',
    'total_contributed_cents': 4000, 'contribution_count': 1,
    'first_contributed_at': ts - 50, 'last_contributed_at': ts,
})
print('dissolve group seeded')
`);
}

function getWalletBalance(userSub: string): number {
  const raw = ddbExec(`
billing = ddb.Table('billing')
resp = billing.get_item(Key={'pk': 'USER#` + userSub + `', 'sk': 'WALLET'})
item = resp.get('Item', {})
print(int(item.get('wallet_balance_cents', 0)))
`);
  return parseInt(raw, 10) || 0;
}

function getEscrowBalance(): number {
  const raw = ddbExec(`
billing = ddb.Table('billing')
resp = billing.get_item(Key={'pk': 'PLATFORM#ESCROW', 'sk': 'WALLET'})
item = resp.get('Item', {})
print(int(item.get('wallet_balance_cents', 0)))
`);
  return parseInt(raw, 10) || 0;
}

// =============================================================================
// Section 459 — Treasury Balance & Contribution API
// =============================================================================

test.describe("459 — Treasury Balance & Contribution API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    // Seed groups and wallets
    seedGroupAndWallets();

    rootPage = await browser.newPage();
    await injectAuth(rootPage, ROOT_ID);

    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);

    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);
  });

  test.afterAll(async () => {
    await rootPage.close();
    await alicePage.close();
    await bobPage.close();
  });

  test("459.1 Get balance (initially zero)", async () => {
    const resp = await apiGet(rootPage, ROOT_ID, `/ui/groups/${GROUP_ID}/treasury`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.balance_cents).toBe(0);
    expect(data.currency).toBe("usd");
    expect(data.total_contributed_cents).toBe(0);
    expect(data.total_donated_cents).toBe(0);
    expect(data.total_spent_cents).toBe(0);
  });

  test("459.2 Alice contributes $50", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/groups/${GROUP_ID}/treasury/contribute`, {
      amount_cents: 5000,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.balance_cents).toBe(5000);
    expect(data.contribution_total_cents).toBe(5000);
    expect(data.ledger_entry_id).toBeTruthy();
  });

  test("459.3 Bob contributes $30", async () => {
    const resp = await apiPost(bobPage, BOB_ID, `/ui/groups/${GROUP_ID}/treasury/contribute`, {
      amount_cents: 3000,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.balance_cents).toBe(8000);
  });

  test("459.4 Insufficient wallet fails", async () => {
    // Alice's seeded wallet is $500 (50000 cents). Use an amount that passes
    // ContributeIn validation (le=10000000) but exceeds the wallet balance, so
    // the service's runtime "Insufficient wallet balance" check (400) is hit
    // rather than a 422 request-validation error.
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/groups/${GROUP_ID}/treasury/contribute`, {
      amount_cents: 9999999,
    });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail).toContain("Insufficient wallet balance");
  });
});

// =============================================================================
// Section 460 — Ledger & Contributors API
// =============================================================================

test.describe("460 — Ledger & Contributors API", () => {
  let rootPage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await browser.newPage();
    await injectAuth(rootPage, ROOT_ID);

    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);
  });

  test.afterAll(async () => {
    await rootPage.close();
    await bobPage.close();
  });

  test("460.1 Ledger shows contributions", async () => {
    const resp = await apiGet(rootPage, ROOT_ID, `/ui/groups/${GROUP_ID}/treasury/ledger`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.entries.length).toBeGreaterThanOrEqual(2);
    // Should have credit entries for contributions
    const credits = data.entries.filter((e: any) => e.direction === "credit");
    expect(credits.length).toBeGreaterThanOrEqual(2);
  });

  test("460.2 Contributors list", async () => {
    const resp = await apiGet(rootPage, ROOT_ID, `/ui/groups/${GROUP_ID}/treasury/contributors`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.count).toBe(2);
    expect(data.contributors.length).toBe(2);
    // Sorted by total_contributed desc: Alice (5000) > Bob (3000)
    expect(data.contributors[0].total_contributed_cents).toBe(5000);
    expect(data.contributors[1].total_contributed_cents).toBe(3000);
  });

  test("460.3 Admin spends treasury", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/ui/groups/${GROUP_ID}/treasury/spend`, {
      amount_cents: 2000,
      reason: "Ad campaign budget",
      category: "ad_spend",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.balance_cents).toBe(6000); // 8000 - 2000
    expect(data.total_spent_cents).toBe(2000);

    // Verify ledger has debit entry
    const ledgerResp = await apiGet(rootPage, ROOT_ID, `/ui/groups/${GROUP_ID}/treasury/ledger`);
    const ledger = await ledgerResp.json();
    const debits = ledger.entries.filter((e: any) => e.direction === "debit");
    expect(debits.length).toBeGreaterThanOrEqual(1);
    expect(debits[0].category).toBe("ad_spend");
  });

  test("460.4 Non-admin cannot spend", async () => {
    const resp = await apiPost(bobPage, BOB_ID, `/ui/groups/${GROUP_ID}/treasury/spend`, {
      amount_cents: 100,
      reason: "Try to spend",
      category: "other",
    });
    expect(resp.status()).toBe(403);
  });
});

// =============================================================================
// Section 461 — Goal & Withdrawal Block API
// =============================================================================

test.describe("461 — Goal & Withdrawal Block API", () => {
  let rootPage: Page;
  let charliePage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await browser.newPage();
    await injectAuth(rootPage, ROOT_ID);

    charliePage = await browser.newPage();
    await injectAuth(charliePage, CHARLIE_ID);
  });

  test.afterAll(async () => {
    await rootPage.close();
    await charliePage.close();
  });

  test("461.1 Set fundraising goal", async () => {
    const resp = await apiPatch(rootPage, ROOT_ID, `/ui/groups/${GROUP_ID}/treasury/goal`, {
      goal_cents: 100000,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.fundraising_goal_cents).toBe(100000);

    // Verify in balance
    const balResp = await apiGet(rootPage, ROOT_ID, `/ui/groups/${GROUP_ID}/treasury`);
    const bal = await balResp.json();
    expect(bal.fundraising_goal_cents).toBe(100000);
  });

  test("461.2 Clear goal", async () => {
    const resp = await apiPatch(rootPage, ROOT_ID, `/ui/groups/${GROUP_ID}/treasury/goal`, {
      goal_cents: null,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.fundraising_goal_cents).toBeNull();
  });

  test("461.3 Non-member cannot view treasury", async () => {
    const resp = await apiGet(charliePage, CHARLIE_ID, `/ui/groups/${GROUP_ID}/treasury`);
    expect(resp.status()).toBe(403);
  });

  test("461.4 No withdrawal endpoint", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/ui/groups/${GROUP_ID}/treasury/withdraw`, {
      amount_cents: 100,
    });
    // FastAPI returns 404 for undefined routes, or 405 for wrong method
    expect([404, 405, 422]).toContain(resp.status());
  });
});

// =============================================================================
// Section 462 — Dissolution Pro-Rata API
// =============================================================================

test.describe("462 — Dissolution Pro-Rata API", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    // Seed the dissolve group
    seedDissolveGroup();

    rootPage = await browser.newPage();
    await injectAuth(rootPage, ROOT_ID);
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("462.1 Record wallet balances before dissolution", async () => {
    const aliceSub = subFor(ALICE_ID);
    const bobSub = subFor(BOB_ID);

    const aliceBefore = getWalletBalance(aliceSub);
    const bobBefore = getWalletBalance(bobSub);
    const escrowBefore = getEscrowBalance();

    // Verify the dissolve group has balance 12000
    const balResp = await apiGet(rootPage, ROOT_ID, `/ui/groups/${DISSOLVE_GROUP_ID}/treasury`);
    expect(balResp.status()).toBe(200);
    const bal = await balResp.json();
    expect(bal.balance_cents).toBe(12000);

    // Dissolve the treasury directly via the service function
    // (dissolution is normally triggered by dissolve_group in user_groups)
    execSync(
      `${REPO_ROOT}/.venv/bin/python3 -c "
import sys, os
sys.path.insert(0, '${REPO_ROOT}')
from pathlib import Path
env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
from app.services.group_treasury import dissolve_treasury
result = dissolve_treasury('${DISSOLVE_GROUP_ID}')
print(result)
"`,
      { timeout: 15_000 },
    );

    // Check Alice got her share: 12000 * (10000/12000) * (6000/10000) = 6000
    // contribution_remaining = 12000 * 10000 / 12000 = 10000
    // alice_share = 10000 * 6000 / 10000 = 6000
    const aliceAfter = getWalletBalance(aliceSub);
    expect(aliceAfter - aliceBefore).toBe(6000);

    // Bob's share: 10000 * 4000 / 10000 = 4000
    const bobAfter = getWalletBalance(bobSub);
    expect(bobAfter - bobBefore).toBe(4000);
  });

  test("462.2 External donations to escrow", async () => {
    // donation_remaining = 12000 - 10000 = 2000
    const escrowAfter = getEscrowBalance();
    expect(escrowAfter).toBeGreaterThanOrEqual(2000);
  });

  test("462.3 Treasury balance zeroed after dissolution", async () => {
    // Check the treasury balance directly via DDB
    const raw = ddbExec(`
billing = ddb.Table('billing')
resp = billing.get_item(Key={'pk': 'GROUP#${DISSOLVE_GROUP_ID}', 'sk': 'WALLET'})
item = resp.get('Item', {})
print(int(item.get('wallet_balance_cents', 0)))
`);
    expect(parseInt(raw, 10)).toBe(0);
  });

  test("462.4 Personal wallets credited", async () => {
    // Already verified in 462.1, but also verify via the billing ledger
    const aliceSub = subFor(ALICE_ID);
    const raw = ddbExec(`
billing = ddb.Table('billing')
from boto3.dynamodb.conditions import Key
resp = billing.query(
    KeyConditionExpression=Key('pk').eq('USER#` + aliceSub + `') & Key('sk').begins_with('LEDGER#'),
    ScanIndexForward=False,
    Limit=200,
)
items = resp.get('Items', [])
refunds = [i for i in items if i.get('type') == 'dissolution_refund']
print(len(refunds))
`);
    expect(parseInt(raw, 10)).toBeGreaterThanOrEqual(1);
  });
});
