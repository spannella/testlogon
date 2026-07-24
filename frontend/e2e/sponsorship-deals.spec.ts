/**
 * E2E tests for Sponsored Content & Creator Partnerships (ADS-013).
 *
 * Sections:
 *   396 — Deal Proposal API (4 tests)
 *   397 — Deal Acceptance & Rejection API (4 tests)
 *   398 — Content Submission API (4 tests)
 *   399 — Deal Completion & Payment API (3 tests)
 *   400 — Deal Listing & History API (3 tests)
 *
 * Auth: Alice (advertiser/brand) + Bob (creator) session cookies.
 * Wallet balance is seeded directly via DynamoDB (stripe-mock off-session
 * deposits return requires_payment_method, so we cannot fund via the API).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local"; // advertiser / brand
const BOB_ID = "e2e_bob@test.local"; // creator
const TS = Date.now();

// ─── Session bootstrap ───────────────────────────────────────────────────────

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

function csrfHeaders(userId: string) {
  return { "x-csrf-token": getSessions()[userId].csrf_token };
}

async function apiPost(page: Page, path: string, body: object, userId = ALICE_ID) {
  return page.request.post(`${BASE}${path}`, { data: body, headers: csrfHeaders(userId) });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

// ─── DDB helpers ─────────────────────────────────────────────────────────────

function pyEnvPreamble(): string {
  return `
import boto3, json, os, decimal
from pathlib import Path
env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test', aws_secret_access_key='test')
`;
}

function ddbPut(tableName: string, item: Record<string, unknown>): void {
  const script = `${pyEnvPreamble()}
item = json.loads(os.environ['DDB_ITEM'], parse_float=decimal.Decimal, parse_int=decimal.Decimal)
ddb.Table(os.environ['DDB_TABLE']).put_item(Item=item)
print('ok')
`;
  execSync("python3 -", {
    cwd: REPO_ROOT,
    timeout: 10_000,
    input: script,
    env: { ...process.env, DDB_ITEM: JSON.stringify(item), DDB_TABLE: tableName },
  });
}

function ddbGet(tableName: string, key: Record<string, string>): Record<string, unknown> | null {
  const script = `${pyEnvPreamble()}
class Enc(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            return int(o) if o == int(o) else float(o)
        return super().default(o)
key = json.loads(os.environ['DDB_KEY'])
resp = ddb.Table(os.environ['DDB_TABLE']).get_item(Key=key)
item = resp.get('Item')
print(json.dumps(item, cls=Enc) if item else 'null')
`;
  const raw = execSync("python3 -", {
    cwd: REPO_ROOT,
    timeout: 10_000,
    input: script,
    env: { ...process.env, DDB_KEY: JSON.stringify(key), DDB_TABLE: tableName },
  }).toString().trim();
  return raw === "null" ? null : JSON.parse(raw);
}

function seedWallet(userSub: string, balanceCents: number): void {
  ddbPut("billing", {
    pk: `USER#${userSub}`,
    sk: "WALLET",
    wallet_balance_cents: balanceCents,
    currency: "usd",
    updated_at: Math.floor(Date.now() / 1000),
  });
}

function ddbQueryLedger(userSub: string): Array<Record<string, unknown>> {
  const script = `${pyEnvPreamble()}
from boto3.dynamodb.conditions import Key
class Enc(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            return int(o) if o == int(o) else float(o)
        return super().default(o)
resp = ddb.Table('billing').query(
    KeyConditionExpression=Key('pk').eq('USER#${userSub}') & Key('sk').begins_with('LEDGER#'))
print(json.dumps(resp.get('Items', []), cls=Enc))
`;
  const raw = execSync(`python3 -c "${script}"`, {
    cwd: REPO_ROOT,
    timeout: 10_000,
  }).toString().trim();
  return JSON.parse(raw);
}

// ─── Test state ──────────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;
let accountId: string;
let postId: string;

async function createDeal(overrides: Record<string, unknown> = {}): Promise<string> {
  const resp = await apiPost(
    alicePage,
    "/ui/ads/sponsorships",
    {
      advertiser_account_id: accountId,
      creator_sub: BOB_ID,
      content_type: "post",
      brief: "Feature our brand new product in a dedicated post.",
      deliverables: ["1 feed post"],
      compensation_cents: 50000,
      deadline: "2026-07-01",
      ...overrides,
    },
    ALICE_ID,
  );
  expect(resp.status()).toBe(201);
  const data = (await resp.json()) as { deal_id: string };
  return data.deal_id;
}

test.beforeAll(async ({ browser }) => {
  const aCtx = await browser.newContext();
  alicePage = await aCtx.newPage();
  await injectAuth(alicePage, ALICE_ID);

  const bCtx = await browser.newContext();
  bobPage = await bCtx.newPage();
  await injectAuth(bobPage, BOB_ID);

  // Advertiser ad account for Alice.
  accountId = `adacct_spon_${TS}`;
  ddbPut("AdAccounts", {
    pk: `ACCT#${accountId}`,
    sk: "META",
    account_id: accountId,
    owner_sub: ALICE_ID,
    company_name: `Brand Co ${TS}`,
    billing_email: "billing@brand.test",
    status: "active",
    balance_cents: 0,
    lifetime_spend_cents: 0,
    created_at: Math.floor(Date.now() / 1000),
    updated_at: Math.floor(Date.now() / 1000),
  });

  // Fund Alice's wallet for escrow ($100,000).
  seedWallet(ALICE_ID, 10_000_000);

  // A newsfeed post owned by Bob for content submission.
  postId = `spon_post_${TS}`;
  ddbPut("app_single_table", {
    pk: `POST#${postId}`,
    sk: "META",
    post_id: postId,
    user_id: BOB_ID,
    body: "My sponsored content draft",
    body_format: "plain",
    visibility: "public",
    created_at: String(Math.floor(Date.now() / 1000)),
    like_count: 0,
    comment_count: 0,
  });
});

// ── Section 396: Deal Proposal API ───────────────────────────────────────────

test.describe("396 — Deal Proposal API", () => {
  test("1 — Advertiser proposes sponsorship deal", async () => {
    const dealId = await createDeal();
    expect(dealId).toBeTruthy();
    const deal = ddbGet("sponsorship_deals", { pk: `DEAL#${dealId}`, sk: "META" });
    expect(deal).not.toBeNull();
    expect(deal!.status).toBe("proposed");
  });

  test("2 — Deal creates escrow hold on advertiser wallet", async () => {
    seedWallet(ALICE_ID, 10_000_000);
    const before = ddbGet("billing", { pk: `USER#${ALICE_ID}`, sk: "WALLET" });
    const beforeBal = Number(before!.wallet_balance_cents);
    await createDeal({ compensation_cents: 50000 });
    const after = ddbGet("billing", { pk: `USER#${ALICE_ID}`, sk: "WALLET" });
    expect(Number(after!.wallet_balance_cents)).toBe(beforeBal - 50000);
  });

  test("3 — Deal with insufficient balance returns 402", async () => {
    seedWallet(ALICE_ID, 100); // $1 only
    const resp = await apiPost(
      alicePage,
      "/ui/ads/sponsorships",
      {
        advertiser_account_id: accountId,
        creator_sub: BOB_ID,
        content_type: "post",
        brief: "Too expensive for the wallet balance available.",
        deliverables: ["1 feed post"],
        compensation_cents: 5_000_000,
        deadline: "2026-07-01",
      },
      ALICE_ID,
    );
    expect(resp.status()).toBe(402);
    seedWallet(ALICE_ID, 10_000_000); // restore for later tests
  });

  test("4 — Invalid content_type rejected", async () => {
    const resp = await apiPost(
      alicePage,
      "/ui/ads/sponsorships",
      {
        advertiser_account_id: accountId,
        creator_sub: BOB_ID,
        content_type: "invalid",
        brief: "Brief that is long enough to pass validation.",
        deliverables: ["1 feed post"],
        compensation_cents: 50000,
        deadline: "2026-07-01",
      },
      ALICE_ID,
    );
    expect(resp.status()).toBe(422);
  });
});

// ── Section 397: Deal Acceptance & Rejection API ─────────────────────────────

test.describe("397 — Deal Acceptance & Rejection API", () => {
  test("5 — Creator accepts deal", async () => {
    const dealId = await createDeal();
    const resp = await apiPost(bobPage, `/ui/ads/sponsorships/${dealId}/accept`, {}, BOB_ID);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { status: string; dm_conversation_id: string | null };
    expect(data.status).toBe("accepted");
    expect(data.dm_conversation_id).toBeTruthy();
  });

  test("6 — Non-creator cannot accept deal", async () => {
    const dealId = await createDeal();
    // Alice (the advertiser) tries to accept her own proposal.
    const resp = await apiPost(alicePage, `/ui/ads/sponsorships/${dealId}/accept`, {}, ALICE_ID);
    expect(resp.status()).toBe(403);
  });

  test("7 — Creator rejects deal (escrow released)", async () => {
    seedWallet(ALICE_ID, 10_000_000);
    const before = Number(
      ddbGet("billing", { pk: `USER#${ALICE_ID}`, sk: "WALLET" })!.wallet_balance_cents,
    );
    const dealId = await createDeal({ compensation_cents: 50000 });
    const resp = await apiPost(bobPage, `/ui/ads/sponsorships/${dealId}/reject`, { reason: "no" }, BOB_ID);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { status: string };
    expect(data.status).toBe("rejected");
    const after = Number(
      ddbGet("billing", { pk: `USER#${ALICE_ID}`, sk: "WALLET" })!.wallet_balance_cents,
    );
    expect(after).toBe(before); // debited then refunded -> net zero
  });

  test("8 — Cannot accept already-rejected/cancelled deal (409)", async () => {
    const dealId = await createDeal();
    const reject = await apiPost(bobPage, `/ui/ads/sponsorships/${dealId}/reject`, {}, BOB_ID);
    expect(reject.status()).toBe(200);
    const resp = await apiPost(bobPage, `/ui/ads/sponsorships/${dealId}/accept`, {}, BOB_ID);
    expect(resp.status()).toBe(409);
  });
});

// ── Section 398: Content Submission API ──────────────────────────────────────

test.describe("398 — Content Submission API", () => {
  test("9 — Creator submits content to accepted deal", async () => {
    const dealId = await createDeal();
    await apiPost(bobPage, `/ui/ads/sponsorships/${dealId}/accept`, {}, BOB_ID);
    const resp = await apiPost(
      bobPage,
      `/ui/ads/sponsorships/${dealId}/submit-content`,
      { content_id: postId },
      BOB_ID,
    );
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { status: string; content_id: string };
    expect(data.status).toBe("content_submitted");
    expect(data.content_id).toBe(postId);
  });

  test("10 — Submitted content has FTC disclosure label", async () => {
    const dealId = await createDeal();
    await apiPost(bobPage, `/ui/ads/sponsorships/${dealId}/accept`, {}, BOB_ID);
    await apiPost(
      bobPage,
      `/ui/ads/sponsorships/${dealId}/submit-content`,
      { content_id: postId },
      BOB_ID,
    );
    const post = ddbGet("app_single_table", { pk: `POST#${postId}`, sk: "META" });
    expect(String(post!.ftc_disclosure || "")).toContain("Paid partnership with");
  });

  test("11 — Cannot submit content to non-accepted deal (409)", async () => {
    const dealId = await createDeal(); // still proposed
    const resp = await apiPost(
      bobPage,
      `/ui/ads/sponsorships/${dealId}/submit-content`,
      { content_id: postId },
      BOB_ID,
    );
    expect(resp.status()).toBe(409);
  });

  test("12 — Cannot submit content owned by another user (403)", async () => {
    // A post owned by Alice, not Bob.
    const alicePost = `spon_apost_${TS}`;
    ddbPut("app_single_table", {
      pk: `POST#${alicePost}`,
      sk: "META",
      post_id: alicePost,
      user_id: ALICE_ID,
      body: "Alice owns this",
      body_format: "plain",
      visibility: "public",
      created_at: String(Math.floor(Date.now() / 1000)),
    });
    const dealId = await createDeal();
    await apiPost(bobPage, `/ui/ads/sponsorships/${dealId}/accept`, {}, BOB_ID);
    const resp = await apiPost(
      bobPage,
      `/ui/ads/sponsorships/${dealId}/submit-content`,
      { content_id: alicePost },
      BOB_ID,
    );
    expect(resp.status()).toBe(403);
  });
});

// ── Section 399: Deal Completion & Payment API ───────────────────────────────

test.describe("399 — Deal Completion & Payment API", () => {
  test("13 — Advertiser completes deal", async () => {
    seedWallet(ALICE_ID, 10_000_000);
    const dealId = await createDeal({ compensation_cents: 100000 });
    await apiPost(bobPage, `/ui/ads/sponsorships/${dealId}/accept`, {}, BOB_ID);
    await apiPost(bobPage, `/ui/ads/sponsorships/${dealId}/submit-content`, { content_id: postId }, BOB_ID);
    const resp = await apiPost(alicePage, `/ui/ads/sponsorships/${dealId}/complete`, {}, ALICE_ID);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { status: string };
    expect(data.status).toBe("completed");
  });

  test("14 — Creator wallet credited with 85% of compensation", async () => {
    seedWallet(ALICE_ID, 10_000_000);
    const before = Number(
      ddbGet("billing", { pk: `USER#${BOB_ID}`, sk: "WALLET" })?.wallet_balance_cents || 0,
    );
    const dealId = await createDeal({ compensation_cents: 100000 });
    await apiPost(bobPage, `/ui/ads/sponsorships/${dealId}/accept`, {}, BOB_ID);
    await apiPost(bobPage, `/ui/ads/sponsorships/${dealId}/submit-content`, { content_id: postId }, BOB_ID);
    await apiPost(alicePage, `/ui/ads/sponsorships/${dealId}/complete`, {}, ALICE_ID);
    const after = Number(
      ddbGet("billing", { pk: `USER#${BOB_ID}`, sk: "WALLET" })!.wallet_balance_cents,
    );
    expect(after - before).toBe(85000); // 85% of $1,000
  });

  test("15 — Platform commission recorded in billing ledger", async () => {
    seedWallet(ALICE_ID, 10_000_000);
    const dealId = await createDeal({ compensation_cents: 100000 });
    await apiPost(bobPage, `/ui/ads/sponsorships/${dealId}/accept`, {}, BOB_ID);
    await apiPost(bobPage, `/ui/ads/sponsorships/${dealId}/submit-content`, { content_id: postId }, BOB_ID);
    await apiPost(alicePage, `/ui/ads/sponsorships/${dealId}/complete`, {}, ALICE_ID);
    const entries = ddbQueryLedger("platform");
    const commission = entries.filter(
      (e) => e.type === "sponsorship_commission" && (e.meta as Record<string, unknown>)?.deal_id === dealId,
    );
    expect(commission.length).toBeGreaterThanOrEqual(1);
    expect(Number(commission[0].amount_cents)).toBe(15000); // 15% of $1,000
  });
});

// ── Section 400: Deal Listing & History API ──────────────────────────────────

test.describe("400 — Deal Listing & History API", () => {
  test("16 — Creator lists own deals", async () => {
    const dealId = await createDeal();
    const resp = await apiGet(bobPage, "/ui/ads/sponsorships?role=creator");
    expect(resp.status()).toBe(200);
    const deals = (await resp.json()) as Array<{ deal_id: string }>;
    expect(deals.some((d) => d.deal_id === dealId)).toBe(true);
  });

  test("17 — Advertiser lists own deals", async () => {
    const dealId = await createDeal();
    const resp = await apiGet(alicePage, "/ui/ads/sponsorships?role=advertiser");
    expect(resp.status()).toBe(200);
    const deals = (await resp.json()) as Array<{ deal_id: string }>;
    expect(deals.some((d) => d.deal_id === dealId)).toBe(true);
  });

  test("18 — Deal history shows all state transitions", async () => {
    seedWallet(ALICE_ID, 10_000_000);
    const dealId = await createDeal({ compensation_cents: 100000 });
    await apiPost(bobPage, `/ui/ads/sponsorships/${dealId}/accept`, {}, BOB_ID);
    await apiPost(bobPage, `/ui/ads/sponsorships/${dealId}/submit-content`, { content_id: postId }, BOB_ID);
    await apiPost(alicePage, `/ui/ads/sponsorships/${dealId}/complete`, {}, ALICE_ID);
    const resp = await apiGet(alicePage, `/ui/ads/sponsorships/${dealId}/history`);
    expect(resp.status()).toBe(200);
    const events = (await resp.json()) as Array<{ event_type: string }>;
    const types = events.map((e) => e.event_type);
    expect(types).toContain("proposed");
    expect(types).toContain("accepted");
    expect(types).toContain("content_submitted");
    expect(types).toContain("completed");
  });
});
