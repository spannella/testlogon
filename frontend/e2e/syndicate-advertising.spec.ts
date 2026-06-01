/**
 * E2E tests for SYND-006 Syndicate Advertising.
 *
 * Sections:
 *   443 — Campaign Creation API   (4 tests)
 *   444 — Campaign Lifecycle API  (5 tests)
 *   445 — Campaign Analytics API  (4 tests)
 *   446 — Advertising UI          (3 tests)
 *
 * A syndicate runs advertising as a unit: the admin creates campaigns funded
 * from the syndicate treasury (SYND-004); all members can view campaigns +
 * analytics. Treasury is debited on create/top-up; cancel refunds the balance.
 *
 * Auth: admin session cookies (role-bearing JWT) via e2e_admin_session_setup.py.
 * All non-GET cookie requests include x-csrf-token header.
 *
 * Identities:
 *   Alice — e2e_alice@test.local (syndicate owner/admin)
 *   Bob   — e2e_bob@test.local   (member, non-admin)
 *
 * Requires: SYNDICATE_ADVERTISING_ENABLED=true; syndicate_ad_campaigns DDB table.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ─────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();

// ─── Session bootstrap ─────────────────────────────────────────────────────────

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
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sess = getSessions()[identity];
  if (!sess) throw new Error(`No session for identity "${identity}"`);
  const page = await browser.newPage();
  await page.context().addCookies(sess.cookies);
  return page;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

// ─── Request helpers ─────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body: object = {}) {
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": getSessions()[identity].csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

// ─── DDB seeding ──────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
`;

function ddbExec(script: string): string {
  return execSync(`python3 -c "${DDB_PRELUDE}\n${script}"`, { timeout: 15_000 })
    .toString()
    .trim();
}

// Seed treasury balance directly (avoids depending on the deposit flow).
function seedTreasury(syndId: string, cents: number) {
  ddbExec(`
import time
t = ddb.Table('syndicate_treasury')
t.update_item(
    Key={'pk': 'TREASURY#${syndId}', 'sk': 'BALANCE'},
    UpdateExpression='SET balance_cents = if_not_exists(balance_cents, :z) + :amt, total_deposited_cents = if_not_exists(total_deposited_cents, :z) + :amt, total_disbursed_cents = if_not_exists(total_disbursed_cents, :z), currency = :c, updated_at = :t, syndicate_id = :sid',
    ExpressionAttributeValues={':z': 0, ':amt': ${cents}, ':c': 'usd', ':t': int(time.time()), ':sid': '${syndId}'},
)
print('treasury seeded')
`);
}

function getTreasuryBalance(syndId: string): number {
  const out = ddbExec(`
t = ddb.Table('syndicate_treasury')
r = t.get_item(Key={'pk': 'TREASURY#${syndId}', 'sk': 'BALANCE'}).get('Item') or {}
print(int(r.get('balance_cents', 0)))
`);
  return parseInt(out, 10) || 0;
}

// Record impressions directly via the impression endpoint helper (drives spend).
async function recordImpressions(page: Page, syndId: string, campaignId: string, n: number, clicks: number) {
  for (let i = 0; i < n; i++) {
    await apiPost(page, "alice", `/ui/syndicates/advertising/${syndId}/campaigns/${campaignId}/impression`, {
      clicked: i < clicks,
    });
  }
}

const CREATIVE = {
  headline: "Join Creative Collective",
  body: "5 amazing creators, 1 subscription",
  cta_text: "Subscribe Now",
  cta_url: "/syndicates/promo",
};

// ─── Shared state ──────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;
let syndicateId: string;

async function bootstrapSyndicate(browser: Browser, treasuryCents: number) {
  alicePage = await newIdentityPage(browser, "alice");
  bobPage = await newIdentityPage(browser, "bob");

  const create = await apiPost(alicePage, "alice", "/ui/syndicates", {
    name: `Ad Syndicate ${TS}`,
    description: "Advertising E2E",
  });
  syndicateId = (await create.json()).syndicate_id;

  // Bob joins as a member (non-admin).
  await apiPost(alicePage, "alice", `/ui/syndicates/${syndicateId}/invite`, { user_id: BOB_ID });
  await apiPost(bobPage, "bob", `/ui/syndicates/${syndicateId}/invite/respond`, { accept: true });

  seedTreasury(syndicateId, treasuryCents);
}

// ─── Section 443: Campaign Creation API ──────────────────────────────────────

test.describe("443 — Campaign Creation API", () => {
  test.beforeAll(async ({ browser }) => {
    await bootstrapSyndicate(browser, 50000); // $500 treasury
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("443.1 Admin creates campaign with treasury budget", async () => {
    const before = getTreasuryBalance(syndicateId);
    const resp = await apiPost(alicePage, "alice", `/ui/syndicates/advertising/${syndicateId}/campaigns`, {
      name: `Summer Promo ${TS}`,
      description: "Promo",
      budget_cents: 5000,
      creative: CREATIVE,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("active");
    expect(data.budget_cents).toBe(5000);
    expect(data.remaining_cents).toBe(5000);
    expect(getTreasuryBalance(syndicateId)).toBe(before - 5000);
  });

  test("443.2 Insufficient treasury balance returns error", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/syndicates/advertising/${syndicateId}/campaigns`, {
      name: `Too Big ${TS}`,
      budget_cents: 9000000, // way over remaining treasury
      creative: CREATIVE,
    });
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(JSON.stringify(body).toLowerCase()).toContain("insufficient treasury balance");
  });

  test("443.3 Non-admin cannot create campaign", async () => {
    const resp = await apiPost(bobPage, "bob", `/ui/syndicates/advertising/${syndicateId}/campaigns`, {
      name: `Bob Campaign ${TS}`,
      budget_cents: 1000,
      creative: CREATIVE,
    });
    expect(resp.status()).toBe(403);
  });

  test("443.4 Creative validation rejects missing fields", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/syndicates/advertising/${syndicateId}/campaigns`, {
      name: `Bad Creative ${TS}`,
      budget_cents: 1000,
      creative: { headline: "", body: "x", cta_text: "x", cta_url: "x" },
    });
    expect(resp.status()).toBe(422);
  });
});

// ─── Section 444: Campaign Lifecycle API ─────────────────────────────────────

test.describe("444 — Campaign Lifecycle API", () => {
  let campaignId: string;

  test.beforeAll(async ({ browser }) => {
    await bootstrapSyndicate(browser, 50000); // $500
    const resp = await apiPost(alicePage, "alice", `/ui/syndicates/advertising/${syndicateId}/campaigns`, {
      name: `Lifecycle ${TS}`,
      budget_cents: 4000,
      creative: CREATIVE,
    });
    campaignId = (await resp.json()).campaign_id;
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("444.1 Admin pauses active campaign", async () => {
    const resp = await apiPost(
      alicePage, "alice",
      `/ui/syndicates/advertising/${syndicateId}/campaigns/${campaignId}/status`,
      { status: "paused" },
    );
    expect(resp.status()).toBe(200);
    expect((await resp.json()).status).toBe("paused");
  });

  test("444.2 Admin resumes paused campaign", async () => {
    const resp = await apiPost(
      alicePage, "alice",
      `/ui/syndicates/advertising/${syndicateId}/campaigns/${campaignId}/status`,
      { status: "active" },
    );
    expect(resp.status()).toBe(200);
    expect((await resp.json()).status).toBe("active");
  });

  test("444.3 Admin adds budget from treasury", async () => {
    const before = getTreasuryBalance(syndicateId);
    const resp = await apiPost(
      alicePage, "alice",
      `/ui/syndicates/advertising/${syndicateId}/campaigns/${campaignId}/add-budget`,
      { additional_cents: 1000 },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.budget_cents).toBe(5000); // 4000 + 1000
    expect(data.remaining_cents).toBe(5000);
    expect(getTreasuryBalance(syndicateId)).toBe(before - 1000);
  });

  test("444.4 Admin cancels campaign and gets budget refund", async () => {
    const before = getTreasuryBalance(syndicateId);
    const detail = await (await apiGet(alicePage, `/ui/syndicates/advertising/${syndicateId}/campaigns/${campaignId}`)).json();
    const remaining = detail.remaining_cents;
    const resp = await apiPost(
      alicePage, "alice",
      `/ui/syndicates/advertising/${syndicateId}/campaigns/${campaignId}/status`,
      { status: "cancelled" },
    );
    expect(resp.status()).toBe(200);
    expect((await resp.json()).status).toBe("cancelled");
    expect(getTreasuryBalance(syndicateId)).toBe(before + remaining);
  });

  test("444.5 Invalid status transition rejected", async () => {
    // Campaign is now cancelled — pausing it is invalid.
    const resp = await apiPost(
      alicePage, "alice",
      `/ui/syndicates/advertising/${syndicateId}/campaigns/${campaignId}/status`,
      { status: "paused" },
    );
    expect(resp.status()).toBe(400);
  });
});

// ─── Section 445: Campaign Analytics API ─────────────────────────────────────

test.describe("445 — Campaign Analytics API", () => {
  let campaignId: string;

  test.beforeAll(async ({ browser }) => {
    await bootstrapSyndicate(browser, 50000);
    const resp = await apiPost(alicePage, "alice", `/ui/syndicates/advertising/${syndicateId}/campaigns`, {
      name: `Analytics ${TS}`,
      budget_cents: 3000,
      creative: CREATIVE,
      targeting: { audience: "all", interests: ["art", "music"] },
    });
    campaignId = (await resp.json()).campaign_id;
    await recordImpressions(alicePage, syndicateId, campaignId, 10, 3);
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("445.1 Campaign list shows all campaigns", async () => {
    const resp = await apiGet(alicePage, `/ui/syndicates/advertising/${syndicateId}/campaigns`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(Array.isArray(data)).toBe(true);
    const found = data.find((c: any) => c.campaign_id === campaignId);
    expect(found).toBeTruthy();
    expect(found.status).toBe("active");
  });

  test("445.2 Campaign detail includes creative and targeting", async () => {
    const resp = await apiGet(alicePage, `/ui/syndicates/advertising/${syndicateId}/campaigns/${campaignId}`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.creative.headline).toBe(CREATIVE.headline);
    expect(data.targeting.audience).toBe("all");
  });

  test("445.3 Analytics shows daily breakdown", async () => {
    const resp = await apiGet(alicePage, `/ui/syndicates/advertising/${syndicateId}/campaigns/${campaignId}/analytics`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.daily.length).toBeGreaterThanOrEqual(1);
    expect(data.totals.impressions).toBe(10);
    expect(data.totals.clicks).toBe(3);
    expect(data.totals.spend_cents).toBe(10); // 1 cent per impression
  });

  test("445.4 All members can view analytics", async () => {
    const resp = await apiGet(bobPage, `/ui/syndicates/advertising/${syndicateId}/campaigns/${campaignId}/analytics`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.totals.impressions).toBe(10);
  });
});

// ─── Section 446: Advertising UI ──────────────────────────────────────────────

test.describe("446 — Advertising UI", () => {
  test.beforeAll(async ({ browser }) => {
    await bootstrapSyndicate(browser, 50000);
    const resp = await apiPost(alicePage, "alice", `/ui/syndicates/advertising/${syndicateId}/campaigns`, {
      name: `UI Campaign ${TS}`,
      budget_cents: 2500,
      creative: CREATIVE,
    });
    await resp.json();
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("446.1 Advertising tab visible on syndicate page", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/syndicates/${syndicateId}/manage`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("tab", { name: "Advertising" })).toBeVisible();
    await page.close();
  });

  test("446.2 Create campaign dialog opens for admin", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/syndicates/${syndicateId}/manage`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "Advertising" }).click();
    await page.getByRole("button", { name: "New Campaign" }).click();
    await expect(page.getByText("New Advertising Campaign")).toBeVisible();
    await expect(page.getByPlaceholder("50.00")).toBeVisible();
    await page.close();
  });

  test("446.3 Campaign list shows budget progress bar", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/syndicates/${syndicateId}/manage`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "Advertising" }).click();
    await expect(page.getByText(`UI Campaign ${TS}`)).toBeVisible();
    await expect(page.getByTestId("budget-progress").first()).toBeVisible();
    await page.close();
  });
});
