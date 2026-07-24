/**
 * E2E tests for Ad Creative Affiliate Discounts (ADS-015).
 *
 * An advertiser attaches an affiliate tracking code + promo discount code to an
 * ad creative. Viewers click (attribution tracked) and redeem at checkout
 * (discount validated via promo_codes, conversion recorded via affiliate_links).
 *
 * Sections:
 *   405 -- Attach / get / update / remove discount config (API)
 *   406 -- Click attribution + redirect (API)
 *   407 -- Redemption / checkout validation (API)
 *   408 -- Ownership + edge cases (API)
 *   409 -- Affiliate Discount management UI
 *
 * Auth:
 *   Alice (USER) -- advertiser; owns account + campaign + creative + codes
 *   Bob (USER)   -- viewer; clicks/redeems; ownership-isolation tests
 *   Root (ROOT)  -- approves the advertiser account
 *
 * Sessions created by e2e_admin_session_setup.py (role-bearing JWT cookies).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE     = "http://localhost:3000";
const ALICE_ID = "alice";
const BOB_ID   = "bob";
const ROOT_ID  = "root";
const TS       = Date.now();

interface SessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getAdminSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const sessions = getAdminSessions();
  const session = sessions[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, _identity: string, path: string, options?: { maxRedirects?: number }) {
  return page.request.get(`${BASE}${path}`, options);
}

async function apiPatch(page: Page, identity: string, path: string, body: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.patch(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
  });
}

// ── Shared state ──────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;
let rootPage: Page;
let aliceId: string;

let campaignId: string;
let creativeId: string;       // creative WITH affiliate + promo
let plainCreativeId: string;  // creative WITHOUT codes
let aliceAffiliateCode: string;
let bobAffiliateCode: string;
const PROMO_CODE = `ADS${TS}`.substring(0, 20);

test.beforeAll(async ({ browser }) => {
  alicePage = await newIdentityPage(browser, ALICE_ID);
  bobPage = await newIdentityPage(browser, BOB_ID);
  rootPage = await newIdentityPage(browser, ROOT_ID);
  aliceId = getAdminSessions()[ALICE_ID].user_sub;

  // Advertiser account + approval + campaign
  const acctResp = await apiPost(alicePage, ALICE_ID, "/ui/ads/accounts", {
    company_name: `AffPromoTest_${TS}`,
    billing_email: `affpromo_${TS}@test.local`,
  });
  expect(acctResp.status()).toBe(201);
  const accountId = (await acctResp.json()).account_id;

  const approveAcct = await apiPost(rootPage, ROOT_ID, `/ui/admin/ads/accounts/${accountId}/review`, {
    decision: "approve",
    notes: "Auto-approved for affiliate-promo tests",
  });
  expect(approveAcct.status()).toBe(200);

  const campResp = await apiPost(alicePage, ALICE_ID, `/ui/ads/accounts/${accountId}/campaigns`, {
    name: `AffPromoCamp_${TS}`,
    objective: "awareness",
    budget_cents: 5000,
    budget_type: "daily",
  });
  expect(campResp.status()).toBe(201);
  campaignId = (await campResp.json()).campaign_id;

  // Two creatives
  const cr1 = await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
    format: "image",
    title: `AffBanner_${TS}`,
    cta_url: "https://shop.example.com/sale",
  });
  expect(cr1.status()).toBe(201);
  creativeId = (await cr1.json()).creative_id;

  const cr2 = await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
    format: "image",
    title: `PlainBanner_${TS}`,
    cta_url: "https://shop.example.com/plain",
  });
  expect(cr2.status()).toBe(201);
  plainCreativeId = (await cr2.json()).creative_id;

  // Affiliate links (Alice + Bob) -- use "post" target_type (no catalog seed needed)
  const aff1 = await apiPost(alicePage, ALICE_ID, "/ui/affiliates/links", {
    target_type: "post",
    target_id: `affpost_${TS}`,
    commission_percent: 10,
  });
  expect(aff1.status()).toBe(201);
  aliceAffiliateCode = (await aff1.json()).tracking_code;

  const aff2 = await apiPost(bobPage, BOB_ID, "/ui/affiliates/links", {
    target_type: "post",
    target_id: `affpostbob_${TS}`,
    commission_percent: 10,
  });
  expect(aff2.status()).toBe(201);
  bobAffiliateCode = (await aff2.json()).tracking_code;

  // Promo code (Alice) -- shop, 20% off
  const promo = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes", {
    code: PROMO_CODE,
    discount_type: "percentage",
    discount_value: 20,
    applies_to: ["shop"],
    max_uses: 1000,
    max_uses_per_user: 100,
  });
  expect(promo.status()).toBe(201);
});

test.afterAll(async () => {
  await alicePage?.close();
  await bobPage?.close();
  await rootPage?.close();
});

// =============================================================================
// Section 405: Attach / get / update / remove
// =============================================================================

test.describe("405 -- Discount config CRUD API", () => {
  test("405.1 Attach affiliate + promo discount to creative", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/ads/affiliate/creatives/${creativeId}/discount`, {
      campaign_id: campaignId,
      affiliate_code: aliceAffiliateCode,
      promo_code: PROMO_CODE,
      promo_value_display: "20% OFF",
      click_through_url: "https://shop.example.com/sale",
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.creative_id).toBe(creativeId);
    expect(body.affiliate_code).toBe(aliceAffiliateCode.toUpperCase());
    expect(body.promo_code).toBe(PROMO_CODE.toUpperCase());
    expect(body.promo_value_display).toBe("20% OFF");
    expect(body.owner_sub).toBe(aliceId);
  });

  test("405.2 Get discount includes affiliate + promo fields", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/ads/affiliate/creatives/${creativeId}/discount`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.affiliate_code).toBe(aliceAffiliateCode.toUpperCase());
    expect(body.promo_code).toBe(PROMO_CODE.toUpperCase());
    expect(body.promo_value_display).toBe("20% OFF");
  });

  test("405.3 Invalid affiliate code rejected (400)", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/ads/affiliate/creatives/${plainCreativeId}/discount`, {
      campaign_id: campaignId,
      affiliate_code: "NOPE9999",
    });
    expect(resp.status()).toBe(400);
  });

  test("405.4 Another user's affiliate code rejected (403)", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/ads/affiliate/creatives/${plainCreativeId}/discount`, {
      campaign_id: campaignId,
      affiliate_code: bobAffiliateCode,
    });
    expect(resp.status()).toBe(403);
  });

  test("405.5 List discounts returns attached config", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, "/ui/ads/affiliate/discounts");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.items)).toBe(true);
    const found = body.items.find((i: { creative_id: string }) => i.creative_id === creativeId);
    expect(found).toBeTruthy();
    expect(found.promo_code).toBe(PROMO_CODE.toUpperCase());
  });
});

// =============================================================================
// Section 406: Click attribution + redirect
// =============================================================================

test.describe("406 -- Click attribution API", () => {
  test("406.1 Click preview returns ref + promo", async () => {
    const resp = await apiGet(bobPage, BOB_ID, `/ui/ads/affiliate/click/${creativeId}/preview`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.redirect_url).toContain(`ref=${aliceAffiliateCode.toUpperCase()}`);
    expect(body.promo_code).toBe(PROMO_CODE.toUpperCase());
    expect(body.promo_value_display).toBe("20% OFF");
  });

  test("406.2 Click redirect returns 302 with Location + promo cookie", async () => {
    const resp = await apiGet(bobPage, BOB_ID, `/ui/ads/affiliate/click/${creativeId}`, { maxRedirects: 0 });
    expect(resp.status()).toBe(302);
    const loc = resp.headers()["location"];
    expect(loc).toContain(`ref=${aliceAffiliateCode.toUpperCase()}`);
    const setCookie = resp.headers()["set-cookie"] ?? "";
    expect(setCookie).toContain("ad_promo_code");
    expect(setCookie).toContain(PROMO_CODE.toUpperCase());
  });

  test("406.3 Click count increments via stats", async () => {
    const before = await apiGet(alicePage, ALICE_ID, `/ui/ads/affiliate/creatives/${creativeId}/stats`);
    const beforeCount = (await before.json()).click_count as number;
    await apiGet(bobPage, BOB_ID, `/ui/ads/affiliate/click/${creativeId}/preview`);
    await apiGet(bobPage, BOB_ID, `/ui/ads/affiliate/click/${creativeId}/preview`);
    const after = await apiGet(alicePage, ALICE_ID, `/ui/ads/affiliate/creatives/${creativeId}/stats`);
    const afterCount = (await after.json()).click_count as number;
    expect(afterCount).toBeGreaterThanOrEqual(beforeCount + 2);
  });

  test("406.4 Click on creative without codes redirects, no ref, no cookie", async () => {
    // Attach a config WITHOUT codes (just a click-through url) to the plain creative.
    const attach = await apiPost(alicePage, ALICE_ID, `/ui/ads/affiliate/creatives/${plainCreativeId}/discount`, {
      campaign_id: campaignId,
      click_through_url: "https://shop.example.com/plain",
    });
    expect(attach.status()).toBe(201);
    const resp = await apiGet(bobPage, BOB_ID, `/ui/ads/affiliate/click/${plainCreativeId}`, { maxRedirects: 0 });
    expect(resp.status()).toBe(302);
    const loc = resp.headers()["location"];
    expect(loc).toBe("https://shop.example.com/plain");
    expect(loc).not.toContain("ref=");
    const setCookie = resp.headers()["set-cookie"] ?? "";
    expect(setCookie).not.toContain("ad_promo_code");
  });

  test("406.5 Click on unknown creative returns 404", async () => {
    const resp = await apiGet(bobPage, BOB_ID, `/ui/ads/affiliate/click/cr_doesnotexist/preview`);
    expect(resp.status()).toBe(404);
  });
});

// =============================================================================
// Section 407: Redemption / checkout validation
// =============================================================================

test.describe("407 -- Redemption API", () => {
  test("407.1 Redeem validates promo via promo_codes and applies discount", async () => {
    const resp = await apiPost(bobPage, BOB_ID, "/ui/ads/affiliate/redeem", {
      creative_id: creativeId,
      checkout_type: "shop",
      item_price_cents: 5000,
      creator_user_id: aliceId,
      order_id: `order_${TS}`,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.valid).toBe(true);
    expect(body.promo_code).toBe(PROMO_CODE.toUpperCase());
    expect(body.discount_cents).toBe(1000); // 20% of 5000
    expect(body.final_price_cents).toBe(4000);
  });

  test("407.2 Redemption count increments via stats", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/ads/affiliate/creatives/${creativeId}/stats`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.redemption_count).toBeGreaterThanOrEqual(1);
    expect(body.total_discount_cents).toBeGreaterThanOrEqual(1000);
  });

  test("407.3 Redeem on creative without promo returns valid=false", async () => {
    const resp = await apiPost(bobPage, BOB_ID, "/ui/ads/affiliate/redeem", {
      creative_id: plainCreativeId,
      checkout_type: "shop",
      item_price_cents: 5000,
      creator_user_id: aliceId,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.valid).toBe(false);
  });

  test("407.4 Redeem with wrong creator_user_id is invalid", async () => {
    const resp = await apiPost(bobPage, BOB_ID, "/ui/ads/affiliate/redeem", {
      creative_id: creativeId,
      checkout_type: "shop",
      item_price_cents: 5000,
      creator_user_id: getAdminSessions()[BOB_ID].user_sub,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.valid).toBe(false);
  });
});

// =============================================================================
// Section 408: Ownership + edge cases
// =============================================================================

test.describe("408 -- Ownership + edge cases API", () => {
  test("408.1 Non-owner cannot read discount config (403)", async () => {
    const resp = await apiGet(bobPage, BOB_ID, `/ui/ads/affiliate/creatives/${creativeId}/discount`);
    expect(resp.status()).toBe(403);
  });

  test("408.2 Non-owner cannot view stats (403)", async () => {
    const resp = await apiGet(bobPage, BOB_ID, `/ui/ads/affiliate/creatives/${creativeId}/stats`);
    expect(resp.status()).toBe(403);
  });

  test("408.3 Update clears affiliate code", async () => {
    const resp = await apiPatch(alicePage, ALICE_ID, `/ui/ads/affiliate/creatives/${creativeId}/discount`, {
      clear_affiliate_code: true,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.affiliate_code).toBeNull();
    // promo code retained
    expect(body.promo_code).toBe(PROMO_CODE.toUpperCase());
  });

  test("408.4 Update can re-attach affiliate code", async () => {
    const resp = await apiPatch(alicePage, ALICE_ID, `/ui/ads/affiliate/creatives/${creativeId}/discount`, {
      affiliate_code: aliceAffiliateCode,
      promo_value_display: "SAVE BIG",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.affiliate_code).toBe(aliceAffiliateCode.toUpperCase());
    expect(body.promo_value_display).toBe("SAVE BIG");
  });

  test("408.5 Remove discount; subsequent get returns 404", async () => {
    const del = await apiDelete(alicePage, ALICE_ID, `/ui/ads/affiliate/creatives/${plainCreativeId}/discount`);
    expect(del.status()).toBe(200);
    const get = await apiGet(alicePage, ALICE_ID, `/ui/ads/affiliate/creatives/${plainCreativeId}/discount`);
    expect(get.status()).toBe(404);
  });
});

// =============================================================================
// Section 409: Management UI
// =============================================================================

test.describe("409 -- Affiliate Discount UI", () => {
  test("409.1 Page loads with heading + attached discount", async () => {
    await injectAuth(alicePage, ALICE_ID);
    await alicePage.goto(`${BASE}/ads/affiliate-discounts`, { waitUntil: "domcontentloaded" });
    await expect(
      alicePage.getByRole("heading", { name: "Ad Creative Affiliate Discounts" }),
    ).toBeVisible();
    // The attached creative + promo code should render in the list.
    await expect(alicePage.getByText(creativeId, { exact: false }).first()).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.getByText(PROMO_CODE.toUpperCase(), { exact: false }).first()).toBeVisible();
  });

  test("409.2 Badge preview renders when typing display text", async () => {
    await injectAuth(alicePage, ALICE_ID);
    await alicePage.goto(`${BASE}/ads/affiliate-discounts`, { waitUntil: "domcontentloaded" });
    await alicePage.getByLabel("Promo Badge Text").fill("30% OFF");
    await expect(alicePage.getByText("Badge preview:")).toBeVisible();
  });
});
