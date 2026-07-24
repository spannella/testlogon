/**
 * E2E tests for Ad Creative Management (ADS-002).
 *
 * Sections:
 *   345 -- Creative CRUD API (5 tests)
 *   346 -- Creative Asset Upload API (3 tests)
 *   347 -- Creative Review Workflow API (4 tests)
 *   348 -- Promo & Affiliate Integration API (3 tests)
 *   349 -- Creative Editor UI (4 tests)
 *   350 -- Input Validation (5 tests)
 *   351 -- Concurrent Operations (3 tests)
 *   352 -- Authorization Boundary (5 tests)
 *   353 -- Admin Review UI (3 tests)
 *
 * Auth:
 *   Alice (USER) -- advertiser who creates account + campaign + creatives
 *   Bob (USER)   -- second user for ownership isolation tests
 *   Root (ROOT)  -- admin who reviews creatives
 *
 * Sessions created by e2e_admin_session_setup.py (role-bearing JWT cookies).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ── Constants ──────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "alice";
const BOB_ID   = "bob";
const ROOT_ID  = "root";
const TS       = Date.now();

// ── Session bootstrap ──────────────────────────────────────────────────────

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
function getAdminSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

// ── Auth helpers ────────────────────────────────────────────────────────────

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

// ── Request helpers ──────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, _identity: string, path: string) {
  return page.request.get(`${BASE}${path}`);
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

async function apiPostMultipart(
  page: Page,
  identity: string,
  path: string,
  fileData: Buffer,
  fileName: string,
  contentType: string,
  assetType: string = "image",
) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${BASE}${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
    multipart: {
      file: { name: fileName, mimeType: contentType, buffer: fileData },
      asset_type: assetType,
    },
  });
}

// ── Shared state ─────────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;
let rootPage: Page;
let accountId: string;
let campaignId: string;
let imageCreativeId: string;
let videoCreativeId: string;
let nativeCreativeId: string;

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

// ── Setup: create account + campaign ──────────────────────────────────────────

test.beforeAll(async ({ browser }) => {
  // GAP-0039: wipe accumulated ad accounts so the 5-account cap never blocks
  // the account-creation setup below regardless of suite order.
  ddbDeleteOwnerAccounts(["e2e_alice@test.local", "e2e_bob@test.local"]);

  alicePage = await newIdentityPage(browser, ALICE_ID);
  bobPage = await newIdentityPage(browser, BOB_ID);
  rootPage = await newIdentityPage(browser, ROOT_ID);

  // Create advertiser account
  const acctResp = await apiPost(alicePage, ALICE_ID, "/ui/ads/accounts", {
    company_name: `CreativeTest_${TS}`,
    billing_email: `creative_${TS}@test.local`,
  });
  expect(acctResp.status()).toBe(201);
  const acctData = await acctResp.json();
  accountId = acctData.account_id;

  // Admin approves account
  const approveAcct = await apiPost(rootPage, ROOT_ID, `/ui/admin/ads/accounts/${accountId}/review`, {
    decision: "approve",
    notes: "Auto-approved for creative tests",
  });
  expect(approveAcct.status()).toBe(200);

  // Create campaign
  const campResp = await apiPost(
    alicePage,
    ALICE_ID,
    `/ui/ads/accounts/${accountId}/campaigns`,
    {
      name: `CreativeCamp_${TS}`,
      objective: "awareness",
      budget_cents: 5000,
      budget_type: "daily",
    },
  );
  expect(campResp.status()).toBe(201);
  const campData = await campResp.json();
  campaignId = campData.campaign_id;
});

test.afterAll(async () => {
  await alicePage?.close();
  await bobPage?.close();
  await rootPage?.close();
});

// =============================================================================
// Section 345: Creative CRUD API
// =============================================================================

test.describe("345 -- Creative CRUD API", () => {
  test("345.1 Create image creative", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
      format: "image",
      title: `Banner_${TS}`,
      alt_text: "Summer sale banner",
      width: 1200,
      height: 628,
      rotation_weight: 70,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.creative_id).toBeTruthy();
    expect(data.status).toBe("draft");
    expect(data.format).toBe("image");
    expect(data.title).toBe(`Banner_${TS}`);
    expect(Number(data.rotation_weight)).toBe(70);
    imageCreativeId = data.creative_id;
  });

  test("345.2 Create video creative", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
      format: "video",
      title: `VideoAd_${TS}`,
      duration_seconds: 15,
      skip_after_seconds: 5,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.creative_id).toBeTruthy();
    expect(data.format).toBe("video");
    expect(Number(data.duration_seconds)).toBe(15);
    videoCreativeId = data.creative_id;
  });

  test("345.3 Create native_post creative", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
      format: "native_post",
      title: `NativeAd_${TS}`,
      headline: "50% Off Everything",
      body_text: "Limited time offer on all items",
      cta_text: "Shop Now",
      cta_url: "https://example.com/sale",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.creative_id).toBeTruthy();
    expect(data.format).toBe("native_post");
    expect(data.headline).toBe("50% Off Everything");
    expect(data.cta_url).toBe("https://example.com/sale");
    nativeCreativeId = data.creative_id;
  });

  test("345.4 List creatives for campaign", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data)).toBeTruthy();
    expect(data.length).toBeGreaterThanOrEqual(3);
    const formats = data.map((c: { format: string }) => c.format);
    expect(formats).toContain("image");
    expect(formats).toContain("video");
    expect(formats).toContain("native_post");
  });

  test("345.5 Update creative rotation weight", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${imageCreativeId}`,
      { rotation_weight: 80 },
    );
    expect(resp.status()).toBe(200);
    // Verify update persisted
    const getResp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${imageCreativeId}`,
    );
    const data = await getResp.json();
    expect(Number(data.rotation_weight)).toBe(80);
  });
});

// =============================================================================
// Section 346: Creative Asset Upload API
// =============================================================================

test.describe("346 -- Creative Asset Upload API", () => {
  test("346.1 Upload image asset", async () => {
    // Create a small fake JPEG (JFIF header)
    const jpegHeader = Buffer.from([
      0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00,
    ]);
    const fakeJpeg = Buffer.concat([jpegHeader, Buffer.alloc(1000, 0)]);

    const resp = await apiPostMultipart(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${imageCreativeId}/upload`,
      fakeJpeg,
      "banner.jpg",
      "image/jpeg",
      "image",
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.url).toBeTruthy();
    expect(data.url).toContain("ads/creatives/");

    // Verify image_url updated on creative record
    const getResp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${imageCreativeId}`,
    );
    const crData = await getResp.json();
    expect(crData.image_url).toBeTruthy();
  });

  test("346.2 Upload video asset", async () => {
    // Create a small fake MP4 (ftyp header)
    const mp4Header = Buffer.from([
      0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70,
      0x69, 0x73, 0x6F, 0x6D, 0x00, 0x00, 0x02, 0x00,
    ]);
    const fakeMp4 = Buffer.concat([mp4Header, Buffer.alloc(2000, 0)]);

    const resp = await apiPostMultipart(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${videoCreativeId}/upload`,
      fakeMp4,
      "ad.mp4",
      "video/mp4",
      "video",
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.url).toBeTruthy();

    // Verify video_url updated
    const getResp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${videoCreativeId}`,
    );
    const crData = await getResp.json();
    expect(crData.video_url).toBeTruthy();
  });

  test("346.3 Reject oversized image", async () => {
    // Create a 6 MB fake image
    const bigImage = Buffer.alloc(6 * 1024 * 1024, 0xFF);

    const resp = await apiPostMultipart(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${imageCreativeId}/upload`,
      bigImage,
      "huge.jpg",
      "image/jpeg",
      "image",
    );
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail).toContain("5 MB");
  });
});

// =============================================================================
// Section 347: Creative Review Workflow API
// =============================================================================

test.describe("347 -- Creative Review Workflow API", () => {
  test("347.1 Submit creative for review", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${imageCreativeId}/submit`,
    );
    expect(resp.status()).toBe(200);

    // Verify status changed
    const getResp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${imageCreativeId}`,
    );
    const data = await getResp.json();
    expect(data.status).toBe("pending_review");
  });

  test("347.2 Admin lists pending creatives", async () => {
    const resp = await apiGet(rootPage, ROOT_ID, "/ui/admin/ads/creatives/pending");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data)).toBeTruthy();
    const found = data.find((c: { creative_id: string }) => c.creative_id === imageCreativeId);
    expect(found).toBeTruthy();
  });

  test("347.3 Admin approves creative", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/ui/admin/ads/creatives/${imageCreativeId}/review`, {
      decision: "approve",
      notes: "Creative meets content policy requirements.",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("approved");
  });

  test("347.4 Admin rejects creative with notes", async () => {
    // First submit video creative for review
    await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${videoCreativeId}/submit`,
    );

    const resp = await apiPost(rootPage, ROOT_ID, `/ui/admin/ads/creatives/${videoCreativeId}/review`, {
      decision: "reject",
      notes: "Inappropriate content",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("rejected");

    // Verify review_notes stored
    const getResp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${videoCreativeId}`,
    );
    const crData = await getResp.json();
    expect(crData.review_notes).toBe("Inappropriate content");
  });
});

// =============================================================================
// Section 348: Promo & Affiliate Integration API
// =============================================================================

test.describe("348 -- Promo & Affiliate Integration API", () => {
  test("348.1 Create creative with promo_code_id", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
      format: "image",
      title: `PromoCreative_${TS}`,
      promo_code_id: "promo_abc123",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.promo_code_id).toBe("promo_abc123");
  });

  test("348.2 Create creative with affiliate_link_id", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
      format: "image",
      title: `AffiliateCreative_${TS}`,
      affiliate_link_id: "aff_xyz789",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.affiliate_link_id).toBe("aff_xyz789");
  });

  test("348.3 Get creative returns promo and affiliate IDs", async () => {
    // Create one with both
    const createResp = await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
      format: "native_post",
      title: `BothIds_${TS}`,
      headline: "Test",
      promo_code_id: "promo_both",
      affiliate_link_id: "aff_both",
    });
    expect(createResp.status()).toBe(201);
    const created = await createResp.json();

    const getResp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${created.creative_id}`,
    );
    const data = await getResp.json();
    expect(data.promo_code_id).toBe("promo_both");
    expect(data.affiliate_link_id).toBe("aff_both");
  });
});

// =============================================================================
// Section 349: Creative Editor UI
// =============================================================================

test.describe("349 -- Creative Editor UI", () => {
  test("349.1 Creative editor opens with format selector", async () => {
    await injectAuth(alicePage, ALICE_ID);
    await alicePage.goto(`${BASE}/ads/creatives?campaign=${campaignId}`, { waitUntil: "domcontentloaded" });
    await alicePage.getByRole("button", { name: /new creative/i }).click();
    await expect(alicePage.getByText("Create New Creative")).toBeVisible();
    // Format selector should be visible (combobox shows the "Image" default value)
    await expect(alicePage.getByRole("combobox").filter({ hasText: "Image" })).toBeVisible();
  });

  test("349.2 Image format shows dimension fields", async () => {
    // Format is "Image" by default
    await expect(alicePage.getByLabel("Width")).toBeVisible();
    await expect(alicePage.getByLabel("Height")).toBeVisible();
  });

  test("349.3 Native post format shows headline + CTA fields", async () => {
    // Switch to Native Post format
    await alicePage.getByRole("combobox").click();
    await alicePage.getByRole("option", { name: "Native Post" }).click();

    await expect(alicePage.getByLabel("Headline")).toBeVisible();
    await expect(alicePage.getByLabel("Body Text")).toBeVisible();
    await expect(alicePage.getByLabel("CTA Text")).toBeVisible();
    await expect(alicePage.getByLabel("CTA URL")).toBeVisible();
  });

  test("349.4 Save draft creates creative with status badge", async () => {
    // Fill in title
    await alicePage.getByLabel("Title").fill(`UICreative_${TS}`);
    await alicePage.getByLabel("Headline").fill("Test Headline");
    await alicePage.getByRole("button", { name: /save draft/i }).click();

    // Wait for dialog to close and list to update
    await alicePage.waitForTimeout(1000);
    // Verify the new creative appears in the list with draft status
    await expect(alicePage.getByText(`UICreative_${TS}`)).toBeVisible();
    await expect(alicePage.getByText("draft").first()).toBeVisible();
  });
});

// =============================================================================
// Section 350: Input Validation
// =============================================================================

test.describe("350 -- Input Validation", () => {
  test("350.1 Reject empty title", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
      format: "image",
      title: "",
    });
    expect(resp.status()).toBe(422);
  });

  test("350.2 Reject title over 200 chars", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
      format: "image",
      title: "A".repeat(201),
    });
    expect(resp.status()).toBe(422);
  });

  test("350.3 Reject invalid format", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
      format: "banner",
      title: "Test",
    });
    expect(resp.status()).toBe(422);
  });

  test("350.4 Reject CTA URL without scheme", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
      format: "native_post",
      title: "Test",
      cta_url: "example.com",
    });
    expect(resp.status()).toBe(422);
  });

  test("350.5 Reject rotation weight > 100", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
      format: "image",
      title: "Test",
      rotation_weight: 150,
    });
    expect(resp.status()).toBe(422);
  });
});

// =============================================================================
// Section 351: Concurrent Operations
// =============================================================================

test.describe("351 -- Concurrent Operations", () => {
  test("351.1 Submit already pending creative fails", async () => {
    // imageCreativeId was already submitted in 347.1
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${imageCreativeId}/submit`,
    );
    expect(resp.status()).toBe(400);
  });

  test("351.2 Submit already approved creative fails", async () => {
    // imageCreativeId was approved in 347.3
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${imageCreativeId}/submit`,
    );
    expect(resp.status()).toBe(400);
  });

  test("351.3 Two uploads in rapid succession", async () => {
    // Create a fresh creative for this test
    const createResp = await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
      format: "image",
      title: `ConcurrentUpload_${TS}`,
    });
    const cr = await createResp.json();

    const jpegHeader = Buffer.from([
      0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00,
    ]);
    const fakeJpeg1 = Buffer.concat([jpegHeader, Buffer.alloc(500, 0xAA)]);
    const fakeJpeg2 = Buffer.concat([jpegHeader, Buffer.alloc(500, 0xBB)]);

    // Upload twice rapidly
    const [resp1, resp2] = await Promise.all([
      apiPostMultipart(
        alicePage, ALICE_ID,
        `/ui/ads/campaigns/${campaignId}/creatives/${cr.creative_id}/upload`,
        fakeJpeg1, "v1.jpg", "image/jpeg", "image",
      ),
      apiPostMultipart(
        alicePage, ALICE_ID,
        `/ui/ads/campaigns/${campaignId}/creatives/${cr.creative_id}/upload`,
        fakeJpeg2, "v2.jpg", "image/jpeg", "image",
      ),
    ]);
    expect(resp1.status()).toBe(200);
    expect(resp2.status()).toBe(200);

    // Both succeed; the last write wins on image_url
    const getResp = await apiGet(
      alicePage, ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${cr.creative_id}`,
    );
    const data = await getResp.json();
    expect(data.image_url).toBeTruthy();
  });
});

// =============================================================================
// Section 352: Authorization Boundary
// =============================================================================

test.describe("352 -- Authorization Boundary", () => {
  test("352.1 Non-owner cannot create creative", async () => {
    const resp = await apiPost(bobPage, BOB_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
      format: "image",
      title: "Bob's creative",
    });
    expect(resp.status()).toBe(403);
  });

  test("352.2 Non-owner cannot list creatives", async () => {
    const resp = await apiGet(bobPage, BOB_ID, `/ui/ads/campaigns/${campaignId}/creatives`);
    expect(resp.status()).toBe(403);
  });

  test("352.3 Non-owner cannot upload asset", async () => {
    const fakeJpeg = Buffer.alloc(100, 0xFF);
    const resp = await apiPostMultipart(
      bobPage, BOB_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${imageCreativeId}/upload`,
      fakeJpeg, "hack.jpg", "image/jpeg", "image",
    );
    expect(resp.status()).toBe(403);
  });

  test("352.4 Non-admin cannot access review queue", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, "/ui/admin/ads/creatives/pending");
    expect(resp.status()).toBe(403);
  });

  test("352.5 Non-admin cannot review creative", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/admin/ads/creatives/${imageCreativeId}/review`, {
      decision: "approve",
    });
    expect(resp.status()).toBe(403);
  });
});

// =============================================================================
// Section 353: Admin Review UI
// =============================================================================

test.describe("353 -- Admin Review UI", () => {
  let pendingCreativeId: string;

  test("353.1 Review page loads pending list", async () => {
    // Create and submit a fresh creative for admin UI testing
    const createResp = await apiPost(alicePage, ALICE_ID, `/ui/ads/campaigns/${campaignId}/creatives`, {
      format: "image",
      title: `AdminUIReview_${TS}`,
    });
    const cr = await createResp.json();
    pendingCreativeId = cr.creative_id;

    await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/ads/campaigns/${campaignId}/creatives/${pendingCreativeId}/submit`,
    );

    // Root navigates to admin review page
    await injectAuth(rootPage, ROOT_ID);
    await rootPage.goto(`${BASE}/admin/ads/creatives/review`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByText("Creative Review Queue")).toBeVisible();
    await expect(rootPage.getByText(`AdminUIReview_${TS}`)).toBeVisible();
  });

  test("353.2 Approve button updates status", async () => {
    // Click on the pending creative
    await rootPage.getByText(`AdminUIReview_${TS}`).click();
    // Wait for review dialog
    await expect(rootPage.getByText(/Review Creative/)).toBeVisible();
    // Click Approve
    await rootPage.getByRole("button", { name: /approve/i }).click();
    // Wait for the dialog to close and list to refresh
    await rootPage.waitForTimeout(1000);
  });

  test("353.3 Review queue updates after action", async () => {
    // After approval, the creative should no longer appear in the pending list
    await rootPage.reload({ waitUntil: "domcontentloaded" });
    // The text should not be in the pending list anymore
    const visible = await rootPage.getByText(`AdminUIReview_${TS}`).isVisible().catch(() => false);
    expect(visible).toBe(false);
  });
});
