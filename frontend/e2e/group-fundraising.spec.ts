/**
 * E2E tests for GROUP-003 Group Advertising & Fundraising.
 *
 * Sections:
 *   455 — Group Advertising API        (4 tests)
 *   456 — Fundraiser CRUD API          (4 tests)
 *   457 — Public Donation API          (4 tests)
 *   458 — Ads & Fundraising UI         (4 tests)
 *   459 — Advertising Edge Cases       (4 tests)
 *   460 — Fundraising Edge Cases       (4 tests)
 *
 * Auth:
 *   Alice — alice (admin of test group)
 *   Bob   — bob   (member of test group, used for 403 checks)
 *   Charlie — charlie_admin (non-member for negative tests)
 *
 * Requires: GROUP_FUNDRAISING_ENABLED=true in .env.local
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "alice";
const BOB_ID = "bob";
const CHARLIE_ID = "charlie_admin";
const TS = Date.now();

// ── Session bootstrap ────────────────────────────────────────────────────────

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

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

function csrfFor(identity: string): string {
  return getSessions()[identity].csrf_token;
}

function subFor(identity: string): string {
  return getSessions()[identity].user_sub;
}

// ── API helpers (cookie auth) ──────────────────────────────────────────────────

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

// Public (no auth) request — uses a clean request context
async function publicGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

async function publicPost(page: Page, path: string, body: object) {
  return page.request.post(`${BASE}${path}`, { data: body });
}

// ── DDB helper ─────────────────────────────────────────────────────────────────

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
  return execSync(`python3 -c "${DDB_PRELUDE}\n${script}"`, { timeout: 20_000 })
    .toString()
    .trim();
}

// ── Group + table seeding ───────────────────────────────────────────────────────

const GROUP_ID = `grp_fund_${TS}`;
const ADVACCT = `adacc_${TS}`;

function ensureTable() {
  ddbExec(`
existing = [t.name for t in ddb.tables.all()]
name = 'group_fundraising_campaigns'
if name not in existing:
    ddb.create_table(
        TableName=name,
        KeySchema=[{'AttributeName':'pk','KeyType':'HASH'},{'AttributeName':'sk','KeyType':'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName':'pk','AttributeType':'S'},
            {'AttributeName':'sk','AttributeType':'S'},
            {'AttributeName':'group_id','AttributeType':'S'},
            {'AttributeName':'created_at','AttributeType':'N'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName':'ByGroupCreated',
            'KeySchema':[{'AttributeName':'group_id','KeyType':'HASH'},{'AttributeName':'created_at','KeyType':'RANGE'}],
            'Projection':{'ProjectionType':'ALL'},
        }],
        BillingMode='PAY_PER_REQUEST',
    )
    print('created')
else:
    print('exists')
`);
}

function seedGroup() {
  const aliceSub = subFor(ALICE_ID);
  const bobSub = subFor(BOB_ID);

  ddbExec(`
import time
tbl = ddb.Table('user_groups')
billing = ddb.Table('billing')
ts = int(time.time())
tbl.put_item(Item={
    'pk': 'GROUP#${GROUP_ID}', 'sk': 'META',
    'group_id': '${GROUP_ID}', 'name': 'Fundraising Test Group',
    'description': 'GROUP-003 E2E', 'visibility': 'public',
    'status': 'active', 'admin_user_id': '${aliceSub}',
    'member_count': 2, 'created_at': ts, 'updated_at': ts,
    'GSI1PK': 'public', 'GSI1SK': ts, 'GSI2PK': 'active', 'GSI2SK': 2,
})
tbl.put_item(Item={
    'pk': 'GROUP#${GROUP_ID}', 'sk': 'MEMBER#${aliceSub}',
    'user_id': '${aliceSub}', 'group_id': '${GROUP_ID}',
    'role': 'admin', 'status': 'active', 'display_name': 'Alice',
    'joined_at': ts, 'promoted_at': ts, 'created_at': ts,
})
tbl.put_item(Item={
    'pk': 'GROUP#${GROUP_ID}', 'sk': 'MEMBER#${bobSub}',
    'user_id': '${bobSub}', 'group_id': '${GROUP_ID}',
    'role': 'member', 'status': 'active', 'display_name': 'Bob',
    'joined_at': ts, 'promoted_at': ts, 'created_at': ts,
})
# Seed treasury with $200 balance so campaigns can reserve budget.
billing.put_item(Item={
    'pk': 'GROUP#${GROUP_ID}', 'sk': 'WALLET',
    'wallet_balance_cents': 20000, 'currency': 'usd',
    'total_contributed_cents': 20000, 'total_donated_cents': 0,
    'total_spent_cents': 0, 'created_at': ts, 'updated_at': ts,
})
print('seeded')
`);
}

function getTreasuryBalance(): number {
  const raw = ddbExec(`
billing = ddb.Table('billing')
resp = billing.get_item(Key={'pk': 'GROUP#${GROUP_ID}', 'sk': 'WALLET'})
item = resp.get('Item', {})
print(int(item.get('wallet_balance_cents', 0)))
`);
  return parseInt(raw, 10) || 0;
}

// =============================================================================
// Section 455 — Group Advertising API
// =============================================================================

test.describe("455 — Group Advertising API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    ensureTable();
    seedGroup();
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  let campaignId = "";

  test("455.1 Create group campaign reserves treasury budget", async () => {
    const before = getTreasuryBalance();
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/groups/fundraising/${GROUP_ID}/campaigns`, {
      name: "Summer Membership Drive",
      daily_budget_cents: 500,
      lifetime_budget_cents: 5000,
      creative_text: "Join our community!",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.campaign_id).toBeTruthy();
    expect(data.daily_budget_cents).toBe(500);
    expect(data.lifetime_budget_cents).toBe(5000);
    expect(data.status).toBe("active");
    campaignId = data.campaign_id;
    // Treasury debited by the lifetime budget.
    expect(getTreasuryBalance()).toBe(before - 5000);
  });

  test("455.2 List campaigns", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/groups/fundraising/${GROUP_ID}/campaigns`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.campaigns)).toBe(true);
    expect(data.campaigns.some((c: any) => c.campaign_id === campaignId)).toBe(true);
  });

  test("455.3 Campaign stats return zeros for new campaign", async () => {
    const resp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/groups/fundraising/${GROUP_ID}/campaigns/${campaignId}/stats`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.impressions).toBe(0);
    expect(data.clicks).toBe(0);
    expect(data.spent_cents).toBe(0);
    expect(data.remaining_cents).toBe(5000);
  });

  test("455.4 Pause and resume campaign", async () => {
    const pause = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/groups/fundraising/${GROUP_ID}/campaigns/${campaignId}`,
      { status: "paused" },
    );
    expect(pause.status()).toBe(200);
    expect((await pause.json()).status).toBe("paused");

    const resume = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/groups/fundraising/${GROUP_ID}/campaigns/${campaignId}`,
      { status: "active" },
    );
    expect(resume.status()).toBe(200);
    expect((await resume.json()).status).toBe("active");
  });
});

// =============================================================================
// Section 456 — Fundraiser CRUD API
// =============================================================================

const fundraiserState: { withGoal: string; openEnded: string } = { withGoal: "", openEnded: "" };

test.describe("456 — Fundraiser CRUD API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("456.1 Create fundraiser with goal", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/groups/fundraising/${GROUP_ID}/fundraisers`, {
      title: "Community Server Fund",
      description: "Help fund our servers.",
      goal_cents: 50000,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.fundraiser_id).toBeTruthy();
    expect(data.goal_cents).toBe(50000);
    expect(data.raised_cents).toBe(0);
    expect(data.status).toBe("active");
    fundraiserState.withGoal = data.fundraiser_id;
  });

  test("456.2 Create open-ended fundraiser", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/groups/fundraising/${GROUP_ID}/fundraisers`, {
      title: "General Operations",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.goal_cents).toBeNull();
    fundraiserState.openEnded = data.fundraiser_id;
  });

  test("456.3 Update fundraiser description", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/groups/fundraising/${GROUP_ID}/fundraisers/${fundraiserState.withGoal}`,
      { description: "Updated description." },
    );
    expect(resp.status()).toBe(200);
    expect((await resp.json()).description).toBe("Updated description.");
  });

  test("456.4 List fundraisers includes both", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/groups/fundraising/${GROUP_ID}/fundraisers`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const ids = data.fundraisers.map((f: any) => f.fundraiser_id);
    expect(ids).toContain(fundraiserState.withGoal);
    expect(ids).toContain(fundraiserState.openEnded);
  });
});

// =============================================================================
// Section 457 — Public Donation API
// =============================================================================

test.describe("457 — Public Donation API", () => {
  let alicePage: Page;
  let donationId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("457.1 Get public fundraiser info (no auth)", async () => {
    const resp = await publicGet(alicePage, `/public/fundraisers/${fundraiserState.withGoal}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.title).toBe("Community Server Fund");
    expect(data.group_name).toBe("Fundraising Test Group");
    expect(typeof data.raised_cents).toBe("number");
  });

  test("457.2 Submit donation credits treasury", async () => {
    const before = getTreasuryBalance();
    const resp = await publicPost(alicePage, `/public/fundraisers/${fundraiserState.withGoal}/donate`, {
      amount_cents: 2500,
      donor_name: "Jane Smith",
      donor_email: "jane@example.com",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.donation_id).toBeTruthy();
    expect(data.amount_cents).toBe(2500);
    donationId = data.donation_id;
    // Auto-confirm credits the treasury.
    expect(getTreasuryBalance()).toBe(before + 2500);
  });

  test("457.3 Donation increments raised_cents", async () => {
    const resp = await publicGet(alicePage, `/public/fundraisers/${fundraiserState.withGoal}`);
    const data = await resp.json();
    expect(data.raised_cents).toBeGreaterThanOrEqual(2500);
    expect(data.donation_count).toBeGreaterThanOrEqual(1);
  });

  test("457.4 Get donation receipt", async () => {
    const resp = await publicGet(
      alicePage,
      `/public/fundraisers/${fundraiserState.withGoal}/donations/${donationId}/receipt`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.amount_cents).toBe(2500);
    expect(data.group_name).toBe("Fundraising Test Group");
    expect(data.fundraiser_title).toBe("Community Server Fund");
    expect(data.status).toBe("completed");
  });
});

// =============================================================================
// Section 458 — Ads & Fundraising UI
// =============================================================================

test.describe("458 — Ads & Fundraising UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("458.1 Ads page shows campaigns", async () => {
    await alicePage.goto(`${BASE}/groups/${GROUP_ID}/ads`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.locator('[data-testid="group-ads-page"]')).toBeVisible();
    await expect(alicePage.locator('[data-testid="campaign-card"]').first()).toBeVisible({
      timeout: 10_000,
    });
  });

  test("458.2 Fundraising page shows progress bar", async () => {
    await alicePage.goto(`${BASE}/groups/${GROUP_ID}/fundraising`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.locator('[data-testid="group-fundraising-page"]')).toBeVisible();
    await expect(alicePage.locator('[data-testid="fundraiser-card"]').first()).toBeVisible({
      timeout: 10_000,
    });
    await expect(alicePage.locator('[data-testid="fundraiser-progress"]').first()).toBeVisible();
  });

  test("458.3 Public donation page shows form", async () => {
    const ctx = await alicePage.context().browser()!.newContext();
    const page = await ctx.newPage();
    await page.goto(`${BASE}/donate/${fundraiserState.withGoal}`, { waitUntil: "domcontentloaded" });
    await expect(page.locator('[data-testid="public-donation-page"]')).toBeVisible();
    await expect(page.locator('[data-testid="donation-amount-input"]')).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.locator('[data-testid="submit-donation-button"]')).toBeVisible();
    await ctx.close();
  });

  test("458.4 Group page shows fundraising widget", async () => {
    await alicePage.goto(`${BASE}/groups/${GROUP_ID}`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.locator('[data-testid="group-page"]')).toBeVisible();
    await expect(alicePage.locator('[data-testid="fundraising-widget"]')).toBeVisible({
      timeout: 10_000,
    });
  });
});

// =============================================================================
// Section 459 — Advertising Edge Cases
// =============================================================================

test.describe("459 — Advertising Edge Cases", () => {
  let alicePage: Page;
  let bobPage: Page;
  let charliePage: Page;

  // A separate group with an empty treasury for the insufficient-funds test.
  const POOR_GROUP = `grp_poor_${TS}`;

  test.beforeAll(async ({ browser }) => {
    const aliceSub = subFor(ALICE_ID);
    ddbExec(`
import time
tbl = ddb.Table('user_groups')
ts = int(time.time())
tbl.put_item(Item={
    'pk': 'GROUP#${POOR_GROUP}', 'sk': 'META',
    'group_id': '${POOR_GROUP}', 'name': 'Poor Group', 'description': '',
    'visibility': 'public', 'status': 'active', 'admin_user_id': '${aliceSub}',
    'member_count': 1, 'created_at': ts, 'updated_at': ts,
    'GSI1PK': 'public', 'GSI1SK': ts, 'GSI2PK': 'active', 'GSI2SK': 1,
})
tbl.put_item(Item={
    'pk': 'GROUP#${POOR_GROUP}', 'sk': 'MEMBER#${aliceSub}',
    'user_id': '${aliceSub}', 'group_id': '${POOR_GROUP}',
    'role': 'admin', 'status': 'active', 'display_name': 'Alice',
    'joined_at': ts, 'promoted_at': ts, 'created_at': ts,
})
print('poor group seeded')
`);

    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);
    charliePage = await browser.newPage();
    await injectAuth(charliePage, CHARLIE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
    await charliePage.close();
  });

  test("459.1 Create campaign with insufficient treasury fails", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/groups/fundraising/${POOR_GROUP}/campaigns`, {
      name: "Doomed Campaign",
      daily_budget_cents: 500,
      lifetime_budget_cents: 5000,
    });
    expect(resp.status()).toBe(400);
    expect((await resp.json()).detail).toContain("Insufficient");
  });

  test("459.2 Non-admin member cannot create campaign", async () => {
    const resp = await apiPost(bobPage, BOB_ID, `/ui/groups/fundraising/${GROUP_ID}/campaigns`, {
      name: "Bob Campaign",
      daily_budget_cents: 500,
      lifetime_budget_cents: 5000,
    });
    expect(resp.status()).toBe(403);
  });

  test("459.3 Non-member cannot list campaigns", async () => {
    const resp = await apiGet(charliePage, CHARLIE_ID, `/ui/groups/fundraising/${GROUP_ID}/campaigns`);
    expect(resp.status()).toBe(403);
  });

  test("459.4 Invalid budget rejected (422)", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/groups/fundraising/${GROUP_ID}/campaigns`, {
      name: "Tiny",
      daily_budget_cents: 10, // below ge=100
      lifetime_budget_cents: 5000,
    });
    expect(resp.status()).toBe(422);
  });
});

// =============================================================================
// Section 460 — Fundraising Edge Cases
// =============================================================================

test.describe("460 — Fundraising Edge Cases", () => {
  let alicePage: Page;
  let bobPage: Page;
  let pausedFundraiser = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);

    // Create + pause a fundraiser for the inactive-donation test.
    const create = await apiPost(alicePage, ALICE_ID, `/ui/groups/fundraising/${GROUP_ID}/fundraisers`, {
      title: "Paused Fundraiser",
      goal_cents: 10000,
    });
    pausedFundraiser = (await create.json()).fundraiser_id;
    await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/groups/fundraising/${GROUP_ID}/fundraisers/${pausedFundraiser}`,
      { status: "paused" },
    );
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("460.1 Donate to paused fundraiser fails", async () => {
    const resp = await publicPost(alicePage, `/public/fundraisers/${pausedFundraiser}/donate`, {
      amount_cents: 1000,
    });
    expect(resp.status()).toBe(400);
    expect((await resp.json()).detail).toContain("no longer accepting");
  });

  test("460.2 Donate below minimum fails (422)", async () => {
    const resp = await publicPost(alicePage, `/public/fundraisers/${fundraiserState.withGoal}/donate`, {
      amount_cents: 50,
    });
    expect(resp.status()).toBe(422);
  });

  test("460.3 Donate to non-existent fundraiser returns 404", async () => {
    const resp = await publicPost(alicePage, `/public/fundraisers/fr_doesnotexist/donate`, {
      amount_cents: 1000,
    });
    expect(resp.status()).toBe(404);
  });

  test("460.4 Donation list is admin-only (member 403)", async () => {
    const resp = await apiGet(
      bobPage,
      BOB_ID,
      `/ui/groups/fundraising/${GROUP_ID}/fundraisers/${fundraiserState.withGoal}/donations`,
    );
    expect(resp.status()).toBe(403);
  });
});
