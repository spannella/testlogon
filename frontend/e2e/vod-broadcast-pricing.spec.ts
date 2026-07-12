/**
 * E2E tests for MON-005: Subscription-Gated VOD + LCOM-004: Broadcast Exclusive Pricing
 *
 * Section 113: Subscription-Gated VOD Access (6 tests)
 * Section 114: Broadcast Exclusive Pricing (6 tests)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const PYTHON = REPO_ROOT + "/.venv/bin/python3";
const API = "http://localhost:8000";
const ALICE_SUB = "e2e_alice@test.local";
const BOB_SUB = "e2e_bob@test.local";
const ALICE_KEY = "alice";
const BOB_KEY = "bob";
const ROOT_KEY = "root";
const TS = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface AdminSessionData {
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

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

async function newIdentityPage(
  browser: Browser,
  identity: string,
): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

// ─── Request helpers ──────────────────────────────────────────────────────────

async function apiPost(
  page: Page,
  sessionKey: string,
  path: string,
  body?: unknown,
) {
  const sess = getAdminSessions()[sessionKey];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}${path}`, { params });
}

async function apiPatch(
  page: Page,
  sessionKey: string,
  path: string,
  body?: unknown,
) {
  const sess = getAdminSessions()[sessionKey];
  return page.request.patch(`${API}${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiDelete(
  page: Page,
  sessionKey: string,
  path: string,
) {
  const sess = getAdminSessions()[sessionKey];
  return page.request.delete(`${API}${path}`, {
    headers: {
      "x-csrf-token": sess.csrf_token,
    },
  });
}

// ─── DDB seed helpers ─────────────────────────────────────────────────────────

const DDB_BOOTSTRAP = `
import boto3, os, time, uuid
from pathlib import Path

env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
`;

function runPy(script: string): string {
  return execSync(
    `${PYTHON} -c "${DDB_BOOTSTRAP}\n${script}"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  ).toString().trim();
}

function seedVideo(videoId: string, ownerSub: string, opts: { access_mode?: string; price_cents?: number } = {}): void {
  const accessMode = opts.access_mode || "free";
  const priceCents = opts.price_cents ?? 0;
  runPy(`
tbl = ddb.Table('VideoMetadata')
tbl.put_item(Item={
    'video_id': '${videoId}',
    'owner_user_id': '${ownerSub}',
    'title': 'Test VOD ${TS}',
    'status': 'published',
    'visibility': 'public',
    'access_mode': '${accessMode}',
    'price_cents': ${priceCents},
    'created_at': int(time.time()),
    'updated_at': int(time.time()),
    'duration_seconds': 120,
    'source_type': 'upload',
    'drm_enabled': False,
    'allow_download': False,
    'download_mp4_key': '',
    'download_mp4_size_bytes': 0,
    'download_mp4_status': '',
    'download_count': 0,
    'purchase_count': 0,
    'revenue_cents': 0,
})
print('seeded')
`);
}

function seedCatalogItem(itemId: string, categoryId: string, ownerSub: string, priceCents: number): void {
  runPy(`
tbl = ddb.Table('shopping_catalog')
now = str(int(time.time()))
# Ensure category exists
try:
    resp = tbl.get_item(Key={'PK': 'CAT#${categoryId}', 'SK': 'META'})
    if not resp.get('Item'):
        raise Exception('not found')
except Exception:
    tbl.put_item(Item={
        'PK': 'CAT#${categoryId}',
        'SK': 'META',
        'entity': 'category',
        'category_id': '${categoryId}',
        'creator_id': '${ownerSub}',
        'name': 'E2E Pricing Category',
        'description': 'Category for pricing tests',
        'created_at': now,
        'updated_at': now,
    })
# Seed item (overwrite if exists from prior run)
tbl.put_item(Item={
    'PK': 'CAT#${categoryId}',
    'SK': 'ITEM#${itemId}',
    'entity': 'item',
    'category_id': '${categoryId}',
    'item_id': '${itemId}',
    'creator_id': '${ownerSub}',
    'name': 'Price Test Item ${TS}',
    'description': 'For E2E pricing test',
    'price_cents': ${priceCents},
    'currency': 'USD',
    'image_urls': [],
    'attributes': {},
    'created_at': now,
    'updated_at': now,
})
print('seeded')
`);
}

// =============================================================================
// Test setup
// =============================================================================

let alicePage: Page;
let bobPage: Page;
let rootPage: Page;

test.beforeAll(async ({ browser }) => {
  alicePage = await newIdentityPage(browser, ALICE_KEY);
  bobPage = await newIdentityPage(browser, BOB_KEY);
  rootPage = await newIdentityPage(browser, ROOT_KEY);
});

test.afterAll(async () => {
  await alicePage?.close();
  await bobPage?.close();
  await rootPage?.close();
});

// =============================================================================
// Section 113: Subscription-Gated VOD Access
// =============================================================================

// The by-creator listing (list_videos_by_creator_public) now filters to
// real video IDs via Attr("video_id").begins_with("v_"), so seeded videos
// must use the "v_" prefix to appear in 113.5/113.6.
const FREE_VIDEO_ID = `v_e2e_free_vod_${TS}`;
const PAID_VIDEO_ID = `v_e2e_paid_vod_${TS}`;
const SUB_ONLY_VIDEO_ID = `v_e2e_sub_vod_${TS}`;

test.describe("113 · Subscription-Gated VOD Access", () => {
  test.beforeAll(async () => {
    seedVideo(FREE_VIDEO_ID, ALICE_SUB, { access_mode: "free", price_cents: 0 });
    seedVideo(PAID_VIDEO_ID, ALICE_SUB, { access_mode: "ppv", price_cents: 500 });
    seedVideo(SUB_ONLY_VIDEO_ID, ALICE_SUB, { access_mode: "subscriber_only", price_cents: 1000 });
  });

  test("113.1 Owner always has access", async () => {
    const resp = await apiGet(alicePage, `/ui/videos/${FREE_VIDEO_ID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.is_entitled).toBe(true);
    expect(data.access_reason).toBe("owner");
  });

  test("113.2 Free video accessible to non-owner", async () => {
    const resp = await apiGet(bobPage, `/ui/videos/${FREE_VIDEO_ID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.is_entitled).toBe(true);
    expect(data.access_reason).toBe("free");
  });

  test("113.3 Paid video shows purchase_available", async () => {
    const resp = await apiGet(bobPage, `/ui/videos/${PAID_VIDEO_ID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.is_entitled).toBe(false);
    expect(data.access_reason).toBe("none");
    expect(data.purchase_available).toBe(true);
  });

  test("113.4 Subscriber-only video shows subscription_available", async () => {
    const resp = await apiGet(bobPage, `/ui/videos/${SUB_ONLY_VIDEO_ID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.is_entitled).toBe(false);
    expect(data.subscription_available).toBe(true);
  });

  test("113.5 by-creator endpoint returns video list with access info", async () => {
    const resp = await apiGet(bobPage, `/ui/videos/by-creator/${ALICE_SUB}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.videos).toBeDefined();
    expect(Array.isArray(data.videos)).toBe(true);
    expect(data.videos.length).toBeGreaterThanOrEqual(1);
    expect(typeof data.viewer_has_subscription).toBe("boolean");
    // Each video should have entitled and access_reason fields
    for (const v of data.videos) {
      expect(typeof v.entitled).toBe("boolean");
      expect(typeof v.access_reason).toBe("string");
    }
  });

  test("113.6 by-creator shows owner entitled for own videos", async () => {
    const resp = await apiGet(alicePage, `/ui/videos/by-creator/${ALICE_SUB}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.videos.length).toBeGreaterThanOrEqual(1);
    for (const v of data.videos) {
      expect(v.entitled).toBe(true);
      expect(v.access_reason).toBe("owner");
    }
  });
});

// =============================================================================
// Section 114: Broadcast Exclusive Pricing
// =============================================================================

const BCAST_CATEGORY_ID = `e2e_bcast_cat_${TS}`;
const BCAST_ITEM_ID = `e2e_price_item_${TS}`;
const CATALOG_PRICE_CENTS = 2000;

test.describe("114 · Broadcast Exclusive Pricing", () => {
  let sessionId: string;

  test.beforeAll(async () => {
    // 1. Seed catalog item
    seedCatalogItem(BCAST_ITEM_ID, BCAST_CATEGORY_ID, ALICE_SUB, CATALOG_PRICE_CENTS);

    // 2. Create a broadcast profile for Alice
    const profileResp = await apiPost(alicePage, ALICE_KEY, "/broadcast/profiles", {
      name: `E2E Profile ${TS}`,
      region: "us-east-1",
      rendition_preset: "720p",
    });
    expect(profileResp.status()).toBe(201);
    const profile = await profileResp.json();

    // 3. Create broadcast session
    const sessionResp = await apiPost(alicePage, ALICE_KEY, "/broadcast/sessions", {
      profile_id: profile.id,
    });
    expect(sessionResp.status()).toBe(201);
    const session = await sessionResp.json();
    sessionId = session.id;

    // 4. Start the session (requires operator role - use root)
    const startResp = await apiPost(rootPage, ROOT_KEY, `/broadcast/sessions/${sessionId}/start`, {
      reason: "e2e-pricing-test",
    });
    expect(startResp.status()).toBe(202);
    const started = await startResp.json();
    expect(started.status).toBe("live");

    // 5. Add product to shelf
    const addResp = await apiPost(alicePage, ALICE_KEY, `/broadcast/sessions/${sessionId}/products`, {
      item_id: BCAST_ITEM_ID,
      category_id: BCAST_CATEGORY_ID,
    });
    expect(addResp.status()).toBe(201);
  });

  test("114.1 Set broadcast price", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_KEY,
      `/broadcast/sessions/${sessionId}/products/${BCAST_ITEM_ID}/price`,
      { broadcast_price_cents: 1500 },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.original_price_cents).toBe(CATALOG_PRICE_CENTS);
    expect(data.broadcast_price_cents).toBe(1500);
    expect(data.discount_pct).toBe(25);
  });

  test("114.2 Shelf list shows effective broadcast price", async () => {
    const resp = await apiGet(alicePage, `/broadcast/sessions/${sessionId}/products`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const item = data.items.find((i: { item_id: string }) => i.item_id === BCAST_ITEM_ID);
    expect(item).toBeDefined();
    expect(item.is_broadcast_price).toBe(true);
    expect(item.effective_price_cents).toBe(1500);
  });

  test("114.3 Set price with expiry", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_KEY,
      `/broadcast/sessions/${sessionId}/products/${BCAST_ITEM_ID}/price`,
      { broadcast_price_cents: 1000, expires_in_seconds: 3600 },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.broadcast_price_expires_at).toBeTruthy();
    const nowSec = Math.floor(Date.now() / 1000);
    expect(data.broadcast_price_expires_at).toBeGreaterThan(nowSec);
    expect(data.broadcast_price_expires_at).toBeLessThanOrEqual(nowSec + 3700);
  });

  test("114.4 Price higher than catalog rejected", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_KEY,
      `/broadcast/sessions/${sessionId}/products/${BCAST_ITEM_ID}/price`,
      { broadcast_price_cents: 3000 },
    );
    expect(resp.status()).toBe(400);
  });

  test("114.5 Clear broadcast price", async () => {
    const resp = await apiDelete(
      alicePage,
      ALICE_KEY,
      `/broadcast/sessions/${sessionId}/products/${BCAST_ITEM_ID}/price`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
  });

  test("114.6 After clear, shelf shows catalog price", async () => {
    const resp = await apiGet(alicePage, `/broadcast/sessions/${sessionId}/products`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const item = data.items.find((i: { item_id: string }) => i.item_id === BCAST_ITEM_ID);
    expect(item).toBeDefined();
    expect(item.is_broadcast_price).toBe(false);
    expect(item.effective_price_cents).toBe(CATALOG_PRICE_CENTS);
  });
});
