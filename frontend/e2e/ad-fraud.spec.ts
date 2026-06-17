/**
 * E2E tests for ADS-014 Ad Fraud Prevention.
 *
 * Sections:
 *   401 — Fraud Detection Rules API   (4 tests)
 *   402 — Fraud Event Recording API   (4 tests)
 *   403 — Admin Fraud Dashboard API   (4 tests)
 *   404 — Account Suspension API      (3 tests)
 *
 * Auth:
 *   Alice — e2e_alice@test.local (advertiser + viewer, USER)
 *   Bob   — e2e_bob@test.local   (creator, USER)
 *   Root  — root.admin@testdev.local (admin reviewer, ROOT)
 *
 * Fraud detection is deterministic: rule weights are velocity=25, ip=25,
 * bot_ua=20, ivt=15, ctr=10, geo=5; threshold = 70. To flag deterministically
 * we pre-seed the velocity + IP counters in DDB (for the current time bucket)
 * above their thresholds, fix the client IP via x-forwarded-for, then send a
 * single event with a bot user-agent: 25 + 25 + 20 = 70 >= threshold.
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
const FRAUD_IP = `10.99.${(TS >> 8) & 0xff}.${TS & 0xff}`; // unique-ish per run

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
}

function csrfFor(identity: string): string {
  return getSessions()[identity].csrf_token;
}

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body?: unknown,
  extraHeaders?: Record<string, string>,
) {
  return page.request.post(`${BASE}${path}`, {
    headers: { "x-csrf-token": csrfFor(identity), ...(extraHeaders || {}) },
    data: body ?? {},
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

/**
 * Seed the velocity + IP fraud counters above threshold so that the next
 * tracked event for (userSub, creativeId, FRAUD_IP) trips velocity (25) +
 * ip clustering (25). Combined with a bot UA (20) => score 70 (flagged).
 */
function seedFraudCounters(userSub: string, creativeId: string, ip: string): void {
  execSync(
    `python3 -c "
import time, boto3, os
from pathlib import Path
env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('DDB_AD_FRAUD_EVENTS','AdFraudEvents'))
ts = int(time.time())
minute = ts // 60
five = ts // 300
tbl.put_item(Item={'pk':'VEL#${userSub}','sk':'CR#${creativeId}#'+str(minute),'event_count':99,'ttl':ts+120})
tbl.put_item(Item={'pk':'IP#${ip}','sk':'BUCKET#'+str(five),'event_count':99,'ttl':ts+600})
print('seeded')
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
}

/** Count creator ad_revenue_credit ledger entries for a user (billing table). */
function countCreatorCredits(userSub: string): number {
  const out = execSync(
    `python3 -c "
import boto3, os
from pathlib import Path
from boto3.dynamodb.conditions import Key
env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('BILLING_TABLE_NAME') or os.environ.get('DDB_TABLE') or 'billing')
resp = tbl.query(KeyConditionExpression=Key('pk').eq('USER#${userSub}'))
n = sum(1 for it in resp.get('Items', []) if it.get('entry_type')=='ad_revenue_credit')
print(n)
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  ).toString();
  return parseInt(out.trim(), 10) || 0;
}

const BOT_UA = "Selenium/4.0 (compatible; headless bot)";

test.describe("Ad Fraud Prevention (ADS-014)", () => {
  let alicePage: Page;
  let bobPage: Page;
  let rootPage: Page;

  let accountId = "";
  let campaignId = "";
  let creativeId = "";
  const creatorId = "e2e_bob@test.local";

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    // Advertiser account (Alice) -> approve -> campaign -> creative -> approve
    const acctResp = await apiPost(alicePage, ALICE_ID, "/ui/ads/accounts", {
      company_name: `E2E Fraud Co ${TS}`,
      billing_email: "fraud@test.local",
    });
    expect(acctResp.status()).toBe(201);
    accountId = (await acctResp.json()).account_id;

    await apiPost(rootPage, ROOT_ID, `/ui/admin/ads/accounts/${accountId}/review`, {
      decision: "approve",
    });

    const campResp = await apiPost(alicePage, ALICE_ID, `/ui/ads/accounts/${accountId}/campaigns`, {
      name: `E2E Fraud Campaign ${TS}`,
      objective: "awareness",
      budget_cents: 100000,
      budget_type: "lifetime",
    });
    expect(campResp.status()).toBe(201);
    campaignId = (await campResp.json()).campaign_id;

    await apiPost(alicePage, ALICE_ID, `/ui/ads/accounts/${accountId}/campaigns/${campaignId}/submit`);
    await apiPost(rootPage, ROOT_ID, `/ui/admin/ads/campaigns/${campaignId}/review`, {
      decision: "approve",
    });

    const crResp = await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
      format: "native_post",
      title: `E2E Fraud Creative ${TS}`,
      headline: "headline",
      body_text: "body",
      cta_text: "Click",
      cta_url: "https://example.com",
    });
    expect(crResp.status()).toBe(201);
    creativeId = (await crResp.json()).creative_id;
    await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives/${creativeId}/submit`);
    await apiPost(rootPage, ROOT_ID, `/ui/admin/ads/creatives/${creativeId}/review`, {
      decision: "approve",
    });
  });

  function trackBody(overrides: Record<string, unknown> = {}) {
    return {
      event: "impression",
      creative_id: creativeId,
      campaign_id: campaignId,
      account_id: accountId,
      surface: "feed",
      slot_type: "native",
      content_id: `content_${TS}`,
      creator_id: creatorId,
      ...overrides,
    };
  }

  // ── 401. Fraud Detection Rules API ──────────────────────────────────────────

  test.describe("401. Fraud Detection Rules API", () => {
    test("401.1 normal impression passes fraud check", async () => {
      const resp = await apiPost(bobPage, BOB_ID, "/ui/ads/track", trackBody());
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.ok).toBe(true);
      expect(data.flagged).toBe(false);
      expect(data.fraud_score).toBeLessThan(70);
    });

    test("401.2 bot user-agent contributes to fraud score", async () => {
      const resp = await apiPost(bobPage, BOB_ID, "/ui/ads/track", trackBody({ user_agent: BOT_UA }));
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.fraud_score).toBeGreaterThanOrEqual(20);
    });

    test("401.3 short view time on complete flagged as IVT", async () => {
      const resp = await apiPost(bobPage, BOB_ID, "/ui/ads/track", trackBody({
        event: "complete",
        view_time_ms: 100,
      }));
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      // IVT contributes 15 to score.
      expect(data.fraud_score).toBeGreaterThanOrEqual(15);
    });

    test("401.4 rapid-fire events trigger velocity check", async () => {
      const body = trackBody({ creative_id: `${creativeId}_vel${TS}` });
      let last: { fraud_score: number } = { fraud_score: 0 };
      for (let i = 0; i < 7; i++) {
        const r = await apiPost(bobPage, BOB_ID, "/ui/ads/track", body);
        last = await r.json();
      }
      // After >5 in the same minute, velocity rule adds 25.
      expect(last.fraud_score).toBeGreaterThanOrEqual(25);
    });
  });

  // ── 402. Fraud Event Recording API ──────────────────────────────────────────

  test.describe("402. Fraud Event Recording API", () => {
    let flaggedEventId = "";

    test("402.1 combined rules flag event and exclude from billing", async () => {
      const beforeCredits = countCreatorCredits(creatorId);
      seedFraudCounters(BOB_ID === "bob" ? "e2e_bob@test.local" : BOB_ID, creativeId, FRAUD_IP);

      const resp = await apiPost(bobPage, BOB_ID, "/ui/ads/track", trackBody({
        event: "complete",
        view_time_ms: 50,
        user_agent: BOT_UA,
      }), { "x-forwarded-for": FRAUD_IP });
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.flagged).toBe(true);
      expect(data.fraud_score).toBeGreaterThanOrEqual(70);
      flaggedEventId = data.event_id;

      // Flagged 'complete' must NOT credit the creator.
      const afterCredits = countCreatorCredits(creatorId);
      expect(afterCredits).toBe(beforeCredits);
    });

    test("402.2 flagged event recorded in fraud events", async () => {
      const resp = await apiGet(rootPage, "/ui/ads/fraud/events?limit=200");
      expect(resp.status()).toBe(200);
      const events = await resp.json();
      const match = events.find((e: { event_id: string }) => e.event_id === flaggedEventId);
      expect(match).toBeTruthy();
      expect(match.fraud_score).toBeGreaterThanOrEqual(70);
      expect(match.rule_scores).toBeTruthy();
    });

    test("402.3 legitimate event is recorded (not flagged)", async () => {
      const resp = await apiPost(bobPage, BOB_ID, "/ui/ads/track", trackBody({
        creative_id: `${creativeId}_legit${TS}`,
      }));
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.flagged).toBe(false);
      expect(data.event_id).toBeTruthy();
    });

    test("402.4 fraud event detail includes rule scores", async () => {
      expect(flaggedEventId).toBeTruthy();
      const resp = await apiGet(rootPage, `/ui/ads/fraud/events/${flaggedEventId}`);
      expect(resp.status()).toBe(200);
      const ev = await resp.json();
      expect(ev.rule_scores).toHaveProperty("click_velocity");
      expect(ev.rule_scores).toHaveProperty("bot_ua");
      expect(ev.rule_scores).toHaveProperty("ivt");
    });
  });

  // ── 403. Admin Fraud Dashboard API ──────────────────────────────────────────

  test.describe("403. Admin Fraud Dashboard API", () => {
    test("403.1 admin can list fraud events", async () => {
      const resp = await apiGet(rootPage, "/ui/ads/fraud/events");
      expect(resp.status()).toBe(200);
      expect(Array.isArray(await resp.json())).toBe(true);
    });

    test("403.2 admin can view fraud summary", async () => {
      const resp = await apiGet(rootPage, "/ui/ads/fraud/summary");
      expect(resp.status()).toBe(200);
      const s = await resp.json();
      expect(s).toHaveProperty("flagged_events_today");
      expect(s).toHaveProperty("fraud_rate_bps");
      expect(s).toHaveProperty("suspended_accounts");
      expect(s).toHaveProperty("top_fraud_rules");
    });

    test("403.3 admin can view account risk scores", async () => {
      const resp = await apiGet(rootPage, "/ui/ads/fraud/accounts");
      expect(resp.status()).toBe(200);
      const accts = await resp.json();
      expect(Array.isArray(accts)).toBe(true);
      const mine = accts.find((a: { account_id: string }) => a.account_id === accountId);
      expect(mine).toBeTruthy();
      expect(mine).toHaveProperty("fraud_rate_bps");
    });

    test("403.4 non-admin cannot access fraud endpoints", async () => {
      const resp = await apiGet(alicePage, "/ui/ads/fraud/events");
      expect(resp.status()).toBe(403);
    });
  });

  // ── 404. Account Suspension API ─────────────────────────────────────────────

  test.describe("404. Account Suspension API", () => {
    test("404.1 admin can suspend account", async () => {
      const resp = await apiPost(rootPage, ROOT_ID, `/ui/ads/fraud/accounts/${accountId}/suspend`, {
        reason: "e2e_manual",
      });
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.status).toBe("suspended");
    });

    test("404.2 suspended account serves no ads", async () => {
      const resp = await apiPost(bobPage, BOB_ID, "/ui/ads/serve", {
        surface: "newsfeed",
        creator_id: creatorId,
        content_id: `content_${TS}`,
        slot_type: "sponsored_post",
      });
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      // The suspended account's campaign is excluded; the only candidate was
      // Alice's campaign, so a real (non-house) ad must not be served from it.
      expect(data.campaign_id === campaignId).toBe(false);
    });

    test("404.3 admin can unsuspend account", async () => {
      const resp = await apiPost(rootPage, ROOT_ID, `/ui/ads/fraud/accounts/${accountId}/unsuspend`);
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.status).toBe("active");
    });
  });
});
