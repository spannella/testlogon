/**
 * E2E tests for Ad Performance Optimization (ADS-017).
 *
 * Sections:
 *   411 — Creative Optimization API (generate / weights / apply / underperformer)
 *   412 — A/B Test & Bid / Budget Suggestion API
 *   413 — Optimization Config + dismiss + ownership API
 *
 * Auth:
 *   Alice (USER) — advertiser who owns the account + campaign
 *   Bob (USER)   — non-owner (ownership isolation → 403)
 *   Root (ROOT)  — approves the account so it becomes active
 *
 * Sessions created by e2e_admin_session_setup.py (role-bearing JWT cookies).
 *
 * Analytics rollups are seeded directly into DynamoDB (via a python one-liner)
 * so recommendation generation is deterministic and does not depend on a timer.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
import { usingCpp, runCppShim } from "./helpers/cpp-seed";
import { cppResetOwnerAdAccounts } from "./helpers/cpp-seed-commerce-billing";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ALICE_ID = "alice";
const BOB_ID = "bob";
const ROOT_ID = "root";
const TS = Date.now();

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
function getAdminSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await page.context().addCookies(getAdminSessions()[identity].cookies);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
  });
}

async function apiPatch(page: Page, identity: string, path: string, body: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.patch(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

/** Seed a daily analytics rollup with per-creative stats directly into DDB. */
function seedRollup(
  campaignId: string,
  accountId: string,
  byCreative: Record<string, { impressions: number; clicks: number }>,
): void {
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const byCreativeJson = JSON.stringify(
    Object.fromEntries(
      Object.entries(byCreative).map(([cid, v]) => [
        cid,
        { impressions: v.impressions, clicks: v.clicks, spend_cents: v.impressions * 5 },
      ]),
    ),
  );
  const totalImpr = Object.values(byCreative).reduce((a, v) => a + v.impressions, 0);
  const totalClicks = Object.values(byCreative).reduce((a, v) => a + v.clicks, 0);
  if (usingCpp()) {
    // cpp reads campaign rollups (pk=CAMP#<cid>, sk=ROLLUP#daily#<date>,
    // by_creative map) from tlc_ad_analytics_rollups, not the Python store.
    runCppShim("seed_ad_campaign_rollup.py", {
      campaign_id: campaignId,
      account_id: accountId,
      by_creative: byCreative,
      date: today,
    });
    return;
  }
  void totalImpr; void totalClicks;
  const py = `
import json
from app.core.tables import T
from app.services.ad_optimization import _floats_to_decimal
item = {
    "pk": "CAMP#${campaignId}",
    "sk": "ROLLUP#daily#${today}",
    "campaign_id": "${campaignId}",
    "account_id": "${accountId}",
    "period": "daily",
    "date": "${today}",
    "impressions": ${totalImpr},
    "clicks": ${totalClicks},
    "skips": 0,
    "completes": 0,
    "spend_cents": ${totalImpr * 5},
    "by_creative": json.loads(r'''${byCreativeJson}'''),
}
T.ad_analytics_rollups.put_item(Item=_floats_to_decimal(item))
print("seeded")
`;
  const out = execSync(
    `bash -c 'set -a; source ${REPO_ROOT}/.env.local; set +a; cd ${REPO_ROOT} && PYTHONPATH=${REPO_ROOT} ${REPO_ROOT}/.venv/bin/python -'`,
    { timeout: 30_000, input: py },
  ).toString();
  if (!out.includes("seeded")) throw new Error(`seed failed: ${out}`);
}

let alicePage: Page;
let bobPage: Page;
let rootPage: Page;
let accountId: string;
let campaignId: string;
// Three creatives: high CTR, mid CTR, and a low-CTR underperformer.
let highId: string;
let lowId: string;

test.beforeAll(async ({ browser }) => {
  alicePage = await newIdentityPage(browser, ALICE_ID);
  bobPage = await newIdentityPage(browser, BOB_ID);
  rootPage = await newIdentityPage(browser, ROOT_ID);

  // cpp caps ad accounts per owner at 5; prior runs accumulate in cpp's own
  // store (the spec never cleans it up), so reset Alice's accounts first. No-op
  // on the Python path.
  if (usingCpp()) {
    const aliceSub = getAdminSessions()[ALICE_ID]?.user_sub;
    cppResetOwnerAdAccounts([aliceSub].filter(Boolean) as string[]);
  }

  // Create + approve an advertiser account.
  const acctResp = await apiPost(alicePage, ALICE_ID, "/ui/ads/accounts", {
    company_name: `OptCo_${TS}`,
    billing_email: `opt_${TS}@acme.test`,
  });
  expect(acctResp.status(), `account create: ${await acctResp.text()}`).toBe(201);
  accountId = (await acctResp.json()).account_id;
  expect(accountId, "account_id must be defined").toBeTruthy();

  const reviewResp = await apiPost(
    rootPage,
    ROOT_ID,
    `/ui/admin/ads/accounts/${accountId}/review`,
    { decision: "approve", notes: "ok" },
  );
  expect(reviewResp.status(), `account review: ${await reviewResp.text()}`).toBe(200);

  // Create a campaign.
  // CampaignCreateIn.start_date/end_date are Unix timestamps (int), not ISO strings.
  const campResp = await apiPost(
    alicePage,
    ALICE_ID,
    `/ui/ads/accounts/${accountId}/campaigns`,
    {
      name: `Opt Campaign ${TS}`,
      objective: "awareness",
      budget_cents: 240000,
      budget_type: "daily",
      start_date: Math.floor(Date.UTC(2026, 5, 1) / 1000),
      end_date: Math.floor(Date.UTC(2026, 5, 30) / 1000),
    },
  );
  expect(campResp.status(), `campaign create: ${await campResp.text()}`).toBe(201);
  campaignId = (await campResp.json()).campaign_id;
  expect(campaignId, "campaign_id must be defined").toBeTruthy();

  // Create 3 creatives.
  const mk = async (title: string): Promise<string> => {
    const r = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives`,
      { format: "image", title },
    );
    return (await r.json()).creative_id;
  };
  highId = await mk(`High ${TS}`);
  const midId = await mk(`Mid ${TS}`);
  lowId = await mk(`Low ${TS}`);

  // Seed analytics: high=4% CTR, mid=2% CTR, low=0.1% CTR over 2000 impressions.
  seedRollup(campaignId, accountId, {
    [highId]: { impressions: 2000, clicks: 80 },
    [midId]: { impressions: 2000, clicks: 40 },
    [lowId]: { impressions: 2000, clicks: 2 },
  });
});

test.afterAll(async () => {
  await alicePage?.close();
  await bobPage?.close();
  await rootPage?.close();
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 411: Creative Optimization API
// ═══════════════════════════════════════════════════════════════════════════

test.describe("411 — Creative Optimization API", () => {
  test("411.1 Generate optimization recommendations", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/ads/optimization/campaigns/${campaignId}/generate`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.creative_weights).toBeTruthy();
    expect(Array.isArray(data.underperformers)).toBe(true);
    expect(Array.isArray(data.recommendations)).toBe(true);
    expect(data.recommendations.length).toBeGreaterThan(0);
  });

  test("411.2 Creative weights proportional to performance", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/ads/optimization/campaigns/${campaignId}/generate`,
    );
    const data = await resp.json();
    const w = data.creative_weights as Record<string, number>;
    // Best-performing (high CTR) creative gets the highest weight.
    const maxId = Object.keys(w).reduce((a, b) => (w[a] >= w[b] ? a : b));
    expect(maxId).toBe(highId);
    expect(w[highId]).toBeGreaterThan(w[lowId]);
    const sum = Object.values(w).reduce((a, b) => a + b, 0);
    expect(sum).toBeGreaterThan(0.98);
    expect(sum).toBeLessThan(1.02);
  });

  test("411.3 Underperformer identified", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/ads/optimization/campaigns/${campaignId}/generate`,
    );
    const data = await resp.json();
    const ids = data.underperformers.map((u: { creative_id: string }) => u.creative_id);
    expect(ids).toContain(lowId);
    const pauseRecs = data.recommendations.filter(
      (r: { action: string; creative_id: string }) =>
        r.action === "pause_creative" && r.creative_id === lowId,
    );
    expect(pauseRecs.length).toBe(1);
  });

  test("411.4 Apply pause recommendation pauses the creative", async () => {
    const gen = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/ads/optimization/campaigns/${campaignId}/generate`,
    );
    const data = await gen.json();
    const rec = data.recommendations.find(
      (r: { action: string; creative_id: string }) =>
        r.action === "pause_creative" && r.creative_id === lowId,
    );
    expect(rec).toBeTruthy();
    const apply = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/ads/optimization/campaigns/${campaignId}/recommendations/${rec.recommendation_id}/apply`,
    );
    expect(apply.status()).toBe(200);
    const applyData = await apply.json();
    expect(applyData.status).toBe("applied");

    // Confirm the creative is now auto_paused.
    const cr = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${lowId}`,
    );
    expect(cr.status()).toBe(200);
    expect((await cr.json()).status).toBe("auto_paused");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 412: A/B Test & Bid / Budget Suggestion API
// ═══════════════════════════════════════════════════════════════════════════

test.describe("412 — A/B Test & Bid Suggestion API", () => {
  test("412.1 A/B test returns significance result", async () => {
    const resp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/optimization/campaigns/${campaignId}/ab-test?creative_a_id=${highId}&creative_b_id=${lowId}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data).toHaveProperty("p_value");
    expect(data).toHaveProperty("significant");
    expect(data.sample_size_sufficient).toBe(true);
    expect(data.significant).toBe(true);
    expect(data.winner).toBe("a");
  });

  test("412.2 A/B test with insufficient data marks not significant", async () => {
    // Use a non-seeded (zero-impression) creative id for variant B.
    const resp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/optimization/campaigns/${campaignId}/ab-test?creative_a_id=${highId}&creative_b_id=cr_nonexistent_${TS}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.sample_size_sufficient).toBe(false);
    expect(data.significant).toBe(false);
    expect(data.winner).toBeNull();
  });

  test("412.3 Suggested bid returns bid range", async () => {
    const resp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/optimization/campaigns/${campaignId}/suggested-bid`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.min_bid_cpm_cents).toBeLessThanOrEqual(data.suggested_bid_cpm_cents);
    expect(data.suggested_bid_cpm_cents).toBeLessThanOrEqual(data.max_bid_cpm_cents);
    expect(data.competition_level).toBeTruthy();
  });

  test("412.4 Budget recommendation scales with reach", async () => {
    const small = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/optimization/campaigns/${campaignId}/budget-recommendation?desired_daily_reach=1000`,
    );
    const big = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/optimization/campaigns/${campaignId}/budget-recommendation?desired_daily_reach=5000`,
    );
    expect(small.status()).toBe(200);
    expect(big.status()).toBe(200);
    const sb = await small.json();
    const bb = await big.json();
    expect(bb.recommended_daily_budget_cents).toBeGreaterThan(
      sb.recommended_daily_budget_cents,
    );
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Section 413: Optimization Config + dismiss + ownership API
// ═══════════════════════════════════════════════════════════════════════════

test.describe("413 — Optimization Config & Ownership API", () => {
  test("413.1 Update optimization config", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/ads/optimization/campaigns/${campaignId}/optimization-config`,
      { auto_optimize_enabled: true, ctr_threshold: 0.01 },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.auto_optimize_enabled).toBe(true);
    expect(data.optimization_config.ctr_threshold).toBeCloseTo(0.01, 5);
  });

  test("413.2 Invalid threshold rejected", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/ads/optimization/campaigns/${campaignId}/optimization-config`,
      { ctr_threshold: 5.0 },
    );
    expect(resp.status()).toBe(422);
  });

  test("413.3 Dismiss a recommendation", async () => {
    const gen = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/ads/optimization/campaigns/${campaignId}/generate`,
    );
    const data = await gen.json();
    const rec = data.recommendations[0];
    expect(rec).toBeTruthy();
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/ads/optimization/campaigns/${campaignId}/recommendations/${rec.recommendation_id}/dismiss`,
    );
    expect(resp.status()).toBe(200);
    expect((await resp.json()).status).toBe("dismissed");

    // History reflects the dismissed status.
    const hist = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/optimization/campaigns/${campaignId}/recommendations?status=dismissed`,
    );
    const histData = await hist.json();
    const found = histData.recommendations.find(
      (r: { recommendation_id: string }) =>
        r.recommendation_id === rec.recommendation_id,
    );
    expect(found?.status).toBe("dismissed");
  });

  test("413.4 Non-owner cannot access optimization (403)", async () => {
    const resp = await apiGet(
      bobPage,
      BOB_ID,
      `/ui/ads/optimization/campaigns/${campaignId}/recommendations`,
    );
    expect(resp.status()).toBe(403);
  });
});
