/**
 * E2E tests for SYND-004 Syndicate Treasury / Fund Management.
 *
 * Sections:
 *   435 — Deposit & Balance API          (5 tests)
 *   436 — Ledger & Contributions API     (4 tests)
 *   437 — Admin Disbursement & Role Gate (5 tests)
 *   438 — Overdraw Protection & Treasury UI (3 tests)
 *
 * Auth: admin session cookies (role-bearing JWT) via e2e_admin_session_setup.py.
 * All non-GET cookie requests include x-csrf-token header.
 *
 * Identities:
 *   Alice — e2e_alice@test.local (syndicate owner/admin)
 *   Bob   — e2e_bob@test.local   (member)
 *
 * Requires: SYNDICATE_TREASURY_ENABLED=true; syndicate_treasury DDB table.
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

// ─── DDB wallet seeding ─────────────────────────────────────────────────────

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

function seedWallet(userSub: string, cents: number) {
  ddbExec(`
import time
billing = ddb.Table('billing')
billing.update_item(
    Key={'pk': 'USER#${userSub}', 'sk': 'WALLET'},
    UpdateExpression='SET wallet_balance_cents = if_not_exists(wallet_balance_cents, :z) + :amt, currency = :c, updated_at = :t',
    ExpressionAttributeValues={':z': 0, ':amt': ${cents}, ':c': 'usd', ':t': int(time.time())},
)
print('wallet seeded')
`);
}

function getWalletBalance(userSub: string): number {
  const out = ddbExec(`
billing = ddb.Table('billing')
r = billing.get_item(Key={'pk': 'USER#${userSub}', 'sk': 'WALLET'}).get('Item') or {}
print(int(r.get('wallet_balance_cents', 0)))
`);
  return parseInt(out, 10) || 0;
}

// ─── Shared state ──────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;
let syndicateId: string;

// ─── Section 435: Deposit & Balance API ─────────────────────────────────────

test.describe("435 — Treasury Deposit & Balance API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");

    // Alice creates a syndicate (she becomes admin).
    const create = await apiPost(alicePage, "alice", "/ui/syndicates", {
      name: `Treasury Syndicate ${TS}`,
      description: "Treasury E2E",
    });
    syndicateId = (await create.json()).syndicate_id;

    // Alice invites Bob; Bob accepts → Bob becomes member.
    await apiPost(alicePage, "alice", `/ui/syndicates/${syndicateId}/invite`, {
      user_id: BOB_ID,
    });
    await apiPost(bobPage, "bob", `/ui/syndicates/${syndicateId}/invite/respond`, {
      accept: true,
    });

    // Seed personal wallets.
    seedWallet(getSessions()["alice"].user_sub, 100000); // $1000
    seedWallet(getSessions()["bob"].user_sub, 50000); // $500
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("435.1 Member deposits to treasury", async () => {
    const before = getWalletBalance(getSessions()["alice"].user_sub);
    const resp = await apiPost(alicePage, "alice", `/ui/syndicates/treasury/${syndicateId}/deposit`, {
      amount_cents: 2000,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.amount_cents).toBe(2000);
    expect(data.new_treasury_balance_cents).toBe(2000);
    const after = getWalletBalance(getSessions()["alice"].user_sub);
    expect(after).toBe(before - 2000);
  });

  test("435.2 GET treasury balance reflects deposit", async () => {
    const resp = await apiGet(alicePage, `/ui/syndicates/treasury/${syndicateId}`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.balance_cents).toBe(2000);
    expect(data.total_deposited_cents).toBe(2000);
  });

  test("435.3 Multiple deposits accumulate", async () => {
    await apiPost(bobPage, "bob", `/ui/syndicates/treasury/${syndicateId}/deposit`, {
      amount_cents: 1000,
    });
    const r2 = await apiPost(bobPage, "bob", `/ui/syndicates/treasury/${syndicateId}/deposit`, {
      amount_cents: 500,
    });
    expect(r2.status()).toBe(200);
    const bal = await (await apiGet(alicePage, `/ui/syndicates/treasury/${syndicateId}`)).json();
    expect(bal.balance_cents).toBe(3500); // 2000 + 1000 + 500
  });

  test("435.4 Deposit exceeding personal wallet rejected", async () => {
    const resp = await apiPost(bobPage, "bob", `/ui/syndicates/treasury/${syndicateId}/deposit`, {
      amount_cents: 1000000, // $10k, Bob only has ~$485 left
    });
    expect(resp.status()).toBe(400);
  });

  test("435.5 Non-member cannot deposit", async () => {
    // Charlie is not a member of this syndicate.
    const charlie = await newIdentityPage(alicePage.context().browser()!, "charlie_admin");
    const resp = await apiPost(
      charlie,
      "charlie_admin",
      `/ui/syndicates/treasury/${syndicateId}/deposit`,
      { amount_cents: 100 },
    );
    expect([403, 404]).toContain(resp.status());
    await charlie.close();
  });
});

// ─── Section 436: Ledger & Contributions API ────────────────────────────────

test.describe("436 — Treasury Ledger & Contributions API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("436.1 Ledger shows deposit entries (credits)", async () => {
    const resp = await apiGet(alicePage, `/ui/syndicates/treasury/${syndicateId}/ledger`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.entries.length).toBeGreaterThanOrEqual(3);
    const credits = data.entries.filter((e: any) => e.direction === "credit");
    expect(credits.length).toBeGreaterThanOrEqual(3);
    expect(credits[0].reason).toContain("deposit");
  });

  test("436.2 Per-member contributions breakdown", async () => {
    const resp = await apiGet(alicePage, `/ui/syndicates/treasury/${syndicateId}/contributions`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    const alice = data.find((c: any) => c.user_id === ALICE_ID);
    const bob = data.find((c: any) => c.user_id === BOB_ID);
    expect(alice.total_contributed_cents).toBe(2000);
    expect(alice.contribution_count).toBe(1);
    expect(bob.total_contributed_cents).toBe(1500);
    expect(bob.contribution_count).toBe(2);
  });

  test("436.3 My-contributions returns only caller data", async () => {
    const resp = await apiGet(bobPage, `/ui/syndicates/treasury/${syndicateId}/my-contributions`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.user_id).toBe(BOB_ID);
    expect(data.total_contributed_cents).toBe(1500);
    expect(data.net_contributed_cents).toBe(1500);
  });

  test("436.4 Non-member cannot read ledger", async () => {
    const charlie = await newIdentityPage(alicePage.context().browser()!, "charlie_admin");
    const resp = await apiGet(charlie, `/ui/syndicates/treasury/${syndicateId}/ledger`);
    expect([403, 404]).toContain(resp.status());
    await charlie.close();
  });
});

// ─── Section 437: Admin Disbursement & Role Gate ─────────────────────────────

test.describe("437 — Treasury Disbursement & Role Gate API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("437.1 Admin disburses treasury funds to a member", async () => {
    const bobBefore = getWalletBalance(getSessions()["bob"].user_sub);
    const resp = await apiPost(
      alicePage,
      "alice",
      `/ui/syndicates/treasury/${syndicateId}/disburse`,
      { recipient_user_id: BOB_ID, amount_cents: 1000, note: "Payout" },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.amount_cents).toBe(1000);
    expect(data.recipient_user_id).toBe(BOB_ID);
    expect(data.new_treasury_balance_cents).toBe(2500); // 3500 - 1000
    const bobAfter = getWalletBalance(getSessions()["bob"].user_sub);
    expect(bobAfter).toBe(bobBefore + 1000);
  });

  test("437.2 Treasury balance decreased & disbursed total tracked", async () => {
    const bal = await (await apiGet(alicePage, `/ui/syndicates/treasury/${syndicateId}`)).json();
    expect(bal.balance_cents).toBe(2500);
    expect(bal.total_disbursed_cents).toBe(1000);
  });

  test("437.3 Disbursement appears as debit in ledger", async () => {
    const data = await (
      await apiGet(alicePage, `/ui/syndicates/treasury/${syndicateId}/ledger`)
    ).json();
    const debit = data.entries.find((e: any) => e.direction === "debit");
    expect(debit).toBeTruthy();
    expect(debit.amount_cents).toBe(1000);
    expect(debit.counterparty_user_id).toBe(BOB_ID);
  });

  test("437.4 Non-admin member cannot disburse (403)", async () => {
    const resp = await apiPost(
      bobPage,
      "bob",
      `/ui/syndicates/treasury/${syndicateId}/disburse`,
      { recipient_user_id: ALICE_ID, amount_cents: 100 },
    );
    expect(resp.status()).toBe(403);
  });

  test("437.5 Disburse to non-member rejected", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      `/ui/syndicates/treasury/${syndicateId}/disburse`,
      { recipient_user_id: "e2e_charlie@test.local", amount_cents: 100 },
    );
    expect([404, 403]).toContain(resp.status());
  });
});

// ─── Section 438: Overdraw Protection & Treasury UI ──────────────────────────

test.describe("438 — Overdraw Protection & Treasury UI", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("438.1 Disbursement exceeding treasury balance rejected (overdraw)", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      `/ui/syndicates/treasury/${syndicateId}/disburse`,
      { recipient_user_id: BOB_ID, amount_cents: 999999 }, // way over $25 balance, within model cap
    );
    expect(resp.status()).toBe(409);
    // Balance unchanged.
    const bal = await (await apiGet(alicePage, `/ui/syndicates/treasury/${syndicateId}`)).json();
    expect(bal.balance_cents).toBe(2500);
  });

  test("438.2 Treasury tab shows balance and transaction history", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/syndicates/${syndicateId}/manage`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "Treasury" }).click();
    await expect(page.getByTestId("treasury-balance")).toBeVisible();
    await expect(page.getByTestId("treasury-balance")).toContainText("$25.00");
    await expect(page.getByTestId("treasury-ledger")).toBeVisible();
    await page.close();
  });

  test("438.3 Contribute dialog shows non-withdrawable warning; no member withdraw button", async ({
    browser,
  }) => {
    const page = await browser.newPage();
    await injectAuth(page, "bob");
    await page.goto(`${BASE}/syndicates/${syndicateId}/manage`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "Treasury" }).click();
    // Bob (non-admin) has Contribute but NOT Disburse.
    await expect(page.getByTestId("treasury-contribute-btn")).toBeVisible();
    await expect(page.getByTestId("treasury-disburse-btn")).toHaveCount(0);
    // Open contribute dialog → warning visible.
    await page.getByTestId("treasury-contribute-btn").click();
    await expect(page.getByTestId("treasury-contribute-warning")).toBeVisible();
    await expect(page.getByTestId("treasury-contribute-warning")).toContainText("cannot be withdrawn");
    await page.close();
  });
});
