/**
 * GAP-0042 E2E: serve_ad must enforce the creator's allowed_ad_categories
 * whitelist (and min_cpm_cents floor) — previously fetched but never applied.
 *
 * Flow:
 *   - Alice (advertiser) creates an account + a "sports" campaign + creative.
 *   - Root approves account, campaign, creative.
 *   - Bob (creator) sets allowed_ad_categories=["sports"]  -> sports campaign serves.
 *   - Bob sets allowed_ad_categories=["finance"]          -> sports campaign filtered (house ad).
 *
 * Auth:
 *   Alice — e2e_alice@test.local (advertiser)
 *   Bob   — e2e_bob@test.local   (creator)
 *   Root  — root.admin@testdev.local (admin reviewer)
 *
 * NOTE: This spec exercises the GAP-0042 fix end-to-end. It depends on the
 * campaign `category` field (CampaignCreateIn) being persisted at creation time.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ALICE_ID = "alice";
const BOB_ID = "bob";
const ROOT_ID = "root";
const TS = Date.now();
const SETTINGS_PATH = "/ui/ads/creator/ad-settings";

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
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    localStorage.setItem(
      "auth-store",
      JSON.stringify({
        state: { userId: uid, accessToken: null, isAuthenticated: true },
        version: 0,
      }),
    );
  }, session.user_sub);
}

function csrfFor(identity: string): string {
  return getSessions()[identity].csrf_token;
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  return page.request.post(`${BASE}${path}`, {
    headers: { "x-csrf-token": csrfFor(identity) },
    data: body,
  });
}

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  return page.request.patch(`${BASE}${path}`, {
    headers: { "x-csrf-token": csrfFor(identity) },
    data: body,
  });
}

// ─── DDB cleanup helper ───────────────────────────────────────────────────────

// GAP-0039: a user may own at most 5 (non-terminal) ad accounts; POST
// /ui/ads/accounts returns 422 once the cap is hit. E2E runs accumulate ad
// accounts for Alice/Bob across runs (and across specs in the suite), so without
// cleanup the account-creating setup below eventually trips the cap (422 →
// cascading failures). Delete all ad accounts owned by the given users (and
// their campaigns) directly in DDB before the run so the create paths always
// have headroom.
function ddbDeleteOwnerAccounts(ownerSubs: string[]): void {
  const script = `
import boto3, os
from pathlib import Path
env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
from boto3.dynamodb.conditions import Key
ddb = boto3.resource('dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'),
    region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
accts = ddb.Table('AdAccounts')
camps = ddb.Table('AdCampaigns')
owners = os.environ['OWNER_SUBS'].split(',')
for owner in owners:
    resp = accts.query(IndexName='ByOwner', KeyConditionExpression=Key('owner_sub').eq(owner))
    for item in resp.get('Items', []):
        acct_pk = item['pk']
        cresp = camps.query(KeyConditionExpression=Key('pk').eq(acct_pk))
        for c in cresp.get('Items', []):
            camps.delete_item(Key={'pk': c['pk'], 'sk': c['sk']})
        accts.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
print('ok')
`;
  execSync("python3 -", {
    cwd: REPO_ROOT,
    timeout: 20_000,
    input: script,
    env: { ...process.env, OWNER_SUBS: ownerSubs.join(",") },
  });
}

test.describe("Ad Serving — allowed_ad_categories whitelist (GAP-0042)", () => {
  let alicePage: Page;
  let bobPage: Page;
  let rootPage: Page;
  let accountId: string;
  let campaignId: string;
  let bobSub: string;

  test.beforeAll(async ({ browser }) => {
    // GAP-0039: wipe accumulated ad accounts so the 5-account cap never blocks
    // the account-creation setup below regardless of suite order.
    ddbDeleteOwnerAccounts(["e2e_alice@test.local", "e2e_bob@test.local"]);

    alicePage = await (await browser.newContext()).newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await (await browser.newContext()).newPage();
    await injectAuth(bobPage, BOB_ID);
    rootPage = await (await browser.newContext()).newPage();
    await injectAuth(rootPage, ROOT_ID);
    bobSub = getSessions()[BOB_ID].user_sub;

    // 1. Alice creates + admin approves an ad account.
    const acctResp = await apiPost(alicePage, ALICE_ID, "/ui/ads/accounts", {
      company_name: `E2E CatWhitelist Co ${TS}`,
      billing_email: "catwl@test.local",
    });
    expect(acctResp.status()).toBe(201);
    accountId = (await acctResp.json()).account_id;
    await apiPost(rootPage, ROOT_ID, `/ui/admin/ads/accounts/${accountId}/review`, {
      decision: "approve",
    });

    // 2. Create a SPORTS campaign (category persisted via CampaignCreateIn).
    const campResp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/ads/accounts/${accountId}/campaigns`,
      {
        name: `E2E Sports Campaign ${TS}`,
        objective: "awareness",
        budget_cents: 100000,
        budget_type: "lifetime",
        category: "sports",
      },
    );
    expect(campResp.status()).toBe(201);
    const camp = await campResp.json();
    campaignId = camp.campaign_id;
    expect(camp.category).toBe("sports");

    // 3. Submit + approve campaign.
    await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/ads/accounts/${accountId}/campaigns/${campaignId}/submit`,
    );
    await apiPost(rootPage, ROOT_ID, `/ui/admin/ads/campaigns/${campaignId}/review`, {
      decision: "approve",
    });

    // 4. Create + approve a creative for the campaign.
    const crResp = await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
      format: "native_post",
      title: `E2E Sports Ad ${TS}`,
      headline: "Sports headline",
      body_text: "Sports ad body",
      cta_text: "Watch",
      cta_url: "https://example.com/sports",
      rotation_weight: 50,
    });
    expect(crResp.status()).toBe(201);
    const creativeId = (await crResp.json()).creative_id;
    await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${creativeId}/submit`,
    );
    await apiPost(rootPage, ROOT_ID, `/ui/admin/ads/creatives/${creativeId}/review`, {
      decision: "approve",
    });
  });

  test.afterAll(async () => {
    // Reset Bob's whitelist so other suites see no restriction.
    await apiPatch(bobPage, BOB_ID, SETTINGS_PATH, { allowed_ad_categories: [] });
    await alicePage?.context().close();
    await bobPage?.context().close();
    await rootPage?.context().close();
  });

  test("matching category whitelist serves the campaign", async () => {
    const setResp = await apiPatch(bobPage, BOB_ID, SETTINGS_PATH, {
      allowed_ad_categories: ["sports"],
    });
    expect(setResp.status()).toBe(200);

    const resp = await apiPost(bobPage, BOB_ID, "/ui/ads/serve", {
      surface: "newsfeed",
      creator_id: bobSub,
      content_id: `post_${TS}_match`,
      slot_type: "sponsored_post",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.filled).toBe(true);
    expect(data.is_house_ad).toBe(false);
    expect(data.campaign_id).toBe(campaignId);
  });

  test("non-matching category whitelist filters the campaign (house ad)", async () => {
    const setResp = await apiPatch(bobPage, BOB_ID, SETTINGS_PATH, {
      allowed_ad_categories: ["finance"],
    });
    expect(setResp.status()).toBe(200);

    const resp = await apiPost(bobPage, BOB_ID, "/ui/ads/serve", {
      surface: "newsfeed",
      creator_id: bobSub,
      content_id: `post_${TS}_nomatch`,
      slot_type: "sponsored_post",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // Sports campaign must be filtered out -> house ad fallback.
    expect(data.is_house_ad).toBe(true);
  });

  test("empty whitelist imposes no restriction", async () => {
    const setResp = await apiPatch(bobPage, BOB_ID, SETTINGS_PATH, {
      allowed_ad_categories: [],
    });
    expect(setResp.status()).toBe(200);

    const resp = await apiPost(bobPage, BOB_ID, "/ui/ads/serve", {
      surface: "newsfeed",
      creator_id: bobSub,
      content_id: `post_${TS}_norestrict`,
      slot_type: "sponsored_post",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.filled).toBe(true);
    expect(data.is_house_ad).toBe(false);
    expect(data.campaign_id).toBe(campaignId);
  });
});
