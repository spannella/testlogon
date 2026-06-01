/**
 * E2E tests for SHOP-003: Cart Abandonment Reminders.
 *
 * Sections:
 *   1 — Activity Tracking API (3 tests)
 *   2 — Abandonment Detection API (4 tests)
 *   3 — Reminder Limits (3 tests)
 *
 * Auth:
 *   Cart API  → session cookies + x-csrf-token header (require_ui_session)
 *   Admin API → admin session cookies + x-csrf-token header (require_admin_or_root)
 *   DDB       → direct boto3 writes for backdating timestamps
 *
 * Test users (from e2e_admin_session_setup.py):
 *   Alice          (e2e_alice@test.local)     — buyer with carts
 *   Charlie admin  (e2e_charlie@test.local)   — admin for stats endpoint
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const ROOT_ID  = "root.admin@testdev.local";
const TS       = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

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
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, sessionKey: string) {
  const session = adminSession(sessionKey);
  if (!session) throw new Error(`No session for ${sessionKey}`);
  await page.context().addCookies(session.cookies);
  const userSub = session.user_sub;
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userSub);
}

async function newIdentityPage(browser: Browser, sessionKey: string): Promise<Page> {
  const page = await browser.newPage();
  await injectAuth(page, sessionKey);
  return page;
}

// ─── Cart API helpers (cookie session + CSRF) ────────────────────────────────

function adminSession(sessionKey: string): SessionData {
  const admin = getAdminSessions();
  return admin[sessionKey]!;
}

async function cartPost(page: Page, sessionKey: string, path: string, body?: object) {
  const session = adminSession(sessionKey);
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function cartGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function cartDelete(page: Page, sessionKey: string, path: string) {
  const session = adminSession(sessionKey);
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── DynamoDB helper ─────────────────────────────────────────────────────────

function ddbUpdateCartTimestamp(userSub: string, cartId: string, lastActivityAt: number) {
  const script = `
import boto3, sys
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1',
                     aws_access_key_id='test', aws_secret_access_key='test')
table = ddb.Table('shopping_cart')
table.update_item(
    Key={'PK': 'USER#${userSub}', 'SK': 'CART#${cartId}'},
    UpdateExpression='SET last_activity_at = :ts',
    ExpressionAttributeValues={':ts': ${lastActivityAt}},
)
print('OK')
`;
  const result = execSync(
    `/home/ubuntu/testlogon/.venv/bin/python -c "${script.replace(/"/g, '\\"')}"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
  ).toString().trim();
  if (result !== "OK") throw new Error(`DDB update failed: ${result}`);
}

function ddbGetCartRaw(userSub: string, cartId: string): Record<string, unknown> {
  const script = `
import boto3, json
from decimal import Decimal
class DecEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal): return int(o) if o == int(o) else float(o)
        return super().default(o)
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1',
                     aws_access_key_id='test', aws_secret_access_key='test')
table = ddb.Table('shopping_cart')
resp = table.get_item(Key={'PK': 'USER#${userSub}', 'SK': 'CART#${cartId}'})
item = resp.get('Item', {})
print(json.dumps(item, cls=DecEncoder))
`;
  const result = execSync(
    `/home/ubuntu/testlogon/.venv/bin/python -c "${script.replace(/"/g, '\\"')}"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
  ).toString().trim();
  return JSON.parse(result);
}

function ddbSetCartReminderCount(userSub: string, cartId: string, count: number, lastReminderAt: number) {
  const script = `
import boto3
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1',
                     aws_access_key_id='test', aws_secret_access_key='test')
table = ddb.Table('shopping_cart')
table.update_item(
    Key={'PK': 'USER#${userSub}', 'SK': 'CART#${cartId}'},
    UpdateExpression='SET reminder_count = :c, last_reminder_at = :lr',
    ExpressionAttributeValues={':c': ${count}, ':lr': ${lastReminderAt}},
)
print('OK')
`;
  const result = execSync(
    `/home/ubuntu/testlogon/.venv/bin/python -c "${script.replace(/"/g, '\\"')}"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
  ).toString().trim();
  if (result !== "OK") throw new Error(`DDB update failed: ${result}`);
}

// ─── Shared state ─────────────────────────────────────────────────────────────

let alicePage: Page;
let rootPage: Page;
let cartId: string;

// ═══════════════════════════════════════════════════════════════════════════════
// Section 1: Activity Tracking API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("SHOP-003 — Section 1: Activity Tracking API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await rootPage?.close();
  });

  test("1.1 start_cart sets last_activity_at", async () => {
    const before = Math.floor(Date.now() / 1000);
    const resp = await cartPost(alicePage, "alice", "/ui/shoppingcart/carts");
    expect(resp.status()).toBe(200);
    const cart = await resp.json();
    cartId = cart.cart_id;
    expect(cart.last_activity_at).toBeGreaterThanOrEqual(before);
    expect(cart.abandoned_at).toBe(0);
    expect(cart.reminder_count).toBe(0);
  });

  test("1.2 add_item updates last_activity_at", async () => {
    // Small delay so timestamps are distinguishable
    await new Promise((r) => setTimeout(r, 1100));
    const before = Math.floor(Date.now() / 1000);
    const addResp = await cartPost(alicePage, "alice", `/ui/shoppingcart/carts/${cartId}/items`, {
      sku: `abandon_sku_${TS}`,
      name: `Abandon Test Item ${TS}`,
      quantity: 1,
      unit_price_cents: 999,
    });
    expect(addResp.status()).toBe(200);

    // Fetch cart and verify last_activity_at was updated
    const listResp = await cartGet(alicePage, "/ui/shoppingcart/carts");
    expect(listResp.status()).toBe(200);
    const carts = await listResp.json();
    const ourCart = carts.find((c: Record<string, unknown>) => c.cart_id === cartId);
    expect(ourCart).toBeDefined();
    expect(ourCart.last_activity_at).toBeGreaterThanOrEqual(before);
  });

  test("1.3 Cart list returns abandonment fields", async () => {
    const resp = await cartGet(alicePage, "/ui/shoppingcart/carts");
    expect(resp.status()).toBe(200);
    const carts = await resp.json();
    const ourCart = carts.find((c: Record<string, unknown>) => c.cart_id === cartId);
    expect(ourCart).toBeDefined();
    expect(typeof ourCart.last_activity_at).toBe("number");
    expect(typeof ourCart.abandoned_at).toBe("number");
    expect(typeof ourCart.reminder_count).toBe("number");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 2: Abandonment Detection API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("SHOP-003 — Section 2: Abandonment Detection API", () => {
  let abandonCartId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    rootPage = await newIdentityPage(browser, "root");

    // Create a cart with an item for abandonment testing
    const createResp = await cartPost(alicePage, "alice", "/ui/shoppingcart/carts");
    const cart = await createResp.json();
    abandonCartId = cart.cart_id;

    // Add item to cart
    await cartPost(alicePage, "alice", `/ui/shoppingcart/carts/${abandonCartId}/items`, {
      sku: `abandon_detect_${TS}`,
      name: `Detection Test ${TS}`,
      quantity: 2,
      unit_price_cents: 1500,
    });
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await rootPage?.close();
  });

  test("2.1 Cart with recent activity is not abandoned", async () => {
    // The admin scan endpoint should NOT find our recently active cart
    const session = adminSession("root");
    const scanResp = await rootPage.request.post(`${API}/ui/shoppingcart/admin/cart-abandonment/scan`, {
      headers: { "x-csrf-token": session.csrf_token },
    });
    expect(scanResp.status()).toBe(200);
    const scanResult = await scanResp.json();
    // The recently created cart should not appear in scan (threshold is 24h default)
    expect(scanResult.reminded).toBe(0);
  });

  test("2.2 Cart older than threshold detected", async () => {
    // Backdate last_activity_at to 25 hours ago
    const oldTs = Math.floor(Date.now() / 1000) - (25 * 3600);
    ddbUpdateCartTimestamp(ALICE_ID, abandonCartId, oldTs);

    // Trigger scan
    const session = adminSession("root");
    const scanResp = await rootPage.request.post(`${API}/ui/shoppingcart/admin/cart-abandonment/scan`, {
      headers: { "x-csrf-token": session.csrf_token },
    });
    expect(scanResp.status()).toBe(200);
    const scanResult = await scanResp.json();
    expect(scanResult.reminded).toBeGreaterThanOrEqual(1);
  });

  test("2.3 Reminder creates in-app alert", async () => {
    // Check Alice's alerts for cart.abandoned event
    const alertsResp = await cartGet(alicePage, "/ui/alerts?limit=200");
    expect(alertsResp.status()).toBe(200);
    const body = await alertsResp.json();
    const items = body.alerts ?? body.items ?? body;
    const abandonAlert = (Array.isArray(items) ? items : []).find(
      (a: Record<string, unknown>) => a.event === "cart.abandoned",
    );
    expect(abandonAlert).toBeDefined();
    expect(abandonAlert.title).toBe("You left items in your cart");
  });

  test("2.4 Alert links to correct cart", async () => {
    const alertsResp = await cartGet(alicePage, "/ui/alerts?limit=200");
    const body = await alertsResp.json();
    const items = body.alerts ?? body.items ?? body;
    const abandonAlert = (Array.isArray(items) ? items : []).find(
      (a: Record<string, unknown>) =>
        a.event === "cart.abandoned" &&
        (a.details as Record<string, unknown>)?.cart_id === abandonCartId,
    );
    expect(abandonAlert).toBeDefined();
    const details = abandonAlert.details as Record<string, unknown>;
    expect(details.link).toBe(`/cart?cartId=${abandonCartId}`);
    expect(details.cart_id).toBe(abandonCartId);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 3: Reminder Limits
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("SHOP-003 — Section 3: Reminder Limits", () => {
  let limitCartId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    rootPage = await newIdentityPage(browser, "root");

    // Create a cart with item for limit testing
    const createResp = await cartPost(alicePage, "alice", "/ui/shoppingcart/carts");
    const cart = await createResp.json();
    limitCartId = cart.cart_id;

    await cartPost(alicePage, "alice", `/ui/shoppingcart/carts/${limitCartId}/items`, {
      sku: `limit_sku_${TS}`,
      name: `Limit Test ${TS}`,
      quantity: 1,
      unit_price_cents: 500,
    });

    // Backdate to trigger abandonment
    const oldTs = Math.floor(Date.now() / 1000) - (25 * 3600);
    ddbUpdateCartTimestamp(ALICE_ID, limitCartId, oldTs);

    // Trigger first reminder via scan
    const session = adminSession("root");
    await rootPage.request.post(`${API}/ui/shoppingcart/admin/cart-abandonment/scan`, {
      headers: { "x-csrf-token": session.csrf_token },
    });
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await rootPage?.close();
  });

  test("3.1 First reminder increments count", async () => {
    const listResp = await cartGet(alicePage, "/ui/shoppingcart/carts");
    const carts = await listResp.json();
    const ourCart = carts.find((c: Record<string, unknown>) => c.cart_id === limitCartId);
    expect(ourCart).toBeDefined();
    expect(ourCart.reminder_count).toBeGreaterThanOrEqual(1);
  });

  test("3.2 Cooldown prevents immediate second reminder", async () => {
    // Re-backdate activity (just in case)
    const oldTs = Math.floor(Date.now() / 1000) - (25 * 3600);
    ddbUpdateCartTimestamp(ALICE_ID, limitCartId, oldTs);

    // Try to scan again — cooldown should prevent second reminder
    const session = adminSession("root");
    const scanResp = await rootPage.request.post(`${API}/ui/shoppingcart/admin/cart-abandonment/scan`, {
      headers: { "x-csrf-token": session.csrf_token },
    });
    expect(scanResp.status()).toBe(200);

    // Cart should NOT have been reminded again (cooldown 48h)
    const raw = ddbGetCartRaw(ALICE_ID, limitCartId);
    const count = Number(raw.reminder_count ?? 0);
    // Count should still be 1 (not incremented by the second scan)
    expect(count).toBe(1);
  });

  test("3.3 Max reminders respected", async () => {
    // Directly set reminder_count=2 and last_reminder_at far in the past
    // so it's past cooldown but at max reminders
    const pastCooldown = Math.floor(Date.now() / 1000) - (49 * 3600);
    ddbSetCartReminderCount(ALICE_ID, limitCartId, 2, pastCooldown);

    // Backdate activity
    const oldTs = Math.floor(Date.now() / 1000) - (25 * 3600);
    ddbUpdateCartTimestamp(ALICE_ID, limitCartId, oldTs);

    // Scan - should NOT send a 3rd reminder
    const session = adminSession("root");
    await rootPage.request.post(`${API}/ui/shoppingcart/admin/cart-abandonment/scan`, {
      headers: { "x-csrf-token": session.csrf_token },
    });

    // Verify count is still 2
    const raw = ddbGetCartRaw(ALICE_ID, limitCartId);
    expect(Number(raw.reminder_count ?? 0)).toBe(2);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 4: TTL & Purchase behavior
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("SHOP-003 — Section 4: TTL & Purchase", () => {
  let ttlCartId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    rootPage = await newIdentityPage(browser, "root");

    // Create a cart for TTL testing
    const createResp = await cartPost(alicePage, "alice", "/ui/shoppingcart/carts");
    const cart = await createResp.json();
    ttlCartId = cart.cart_id;
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await rootPage?.close();
  });

  test("4.1 Cart has ttl field set in DDB", async () => {
    const raw = ddbGetCartRaw(ALICE_ID, ttlCartId);
    const ttl = Number(raw.ttl ?? 0);
    const now = Math.floor(Date.now() / 1000);
    // TTL should be approximately 30 days from now
    const expectedMin = now + (29 * 86400);
    const expectedMax = now + (31 * 86400);
    expect(ttl).toBeGreaterThan(expectedMin);
    expect(ttl).toBeLessThan(expectedMax);
  });

  test("4.2 Adding item resets ttl", async () => {
    // Backdate TTL to simulate old cart
    const oldTtl = Math.floor(Date.now() / 1000) + 100; // almost expired
    execSync(
      `/home/ubuntu/testlogon/.venv/bin/python -c "
import boto3
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1',
                     aws_access_key_id='test', aws_secret_access_key='test')
table = ddb.Table('shopping_cart')
table.update_item(
    Key={'PK': 'USER#${ALICE_ID}', 'SK': 'CART#${ttlCartId}'},
    UpdateExpression='SET #ttl = :ttl',
    ExpressionAttributeNames={'#ttl': 'ttl'},
    ExpressionAttributeValues={':ttl': ${oldTtl}},
)
print('OK')
"`,
      { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
    );

    // Add item - should reset TTL
    await cartPost(alicePage, "alice", `/ui/shoppingcart/carts/${ttlCartId}/items`, {
      sku: `ttl_item_${TS}`,
      name: `TTL Test ${TS}`,
      quantity: 1,
      unit_price_cents: 100,
    });

    const raw = ddbGetCartRaw(ALICE_ID, ttlCartId);
    const newTtl = Number(raw.ttl ?? 0);
    const now = Math.floor(Date.now() / 1000);
    // TTL should now be ~30 days from now again
    expect(newTtl).toBeGreaterThan(now + (29 * 86400));
  });

  test("4.3 Admin stats endpoint returns metrics", async () => {
    const session = adminSession("root");
    const resp = await rootPage.request.get(`${API}/ui/shoppingcart/admin/cart-abandonment/stats`, {
      headers: { "x-csrf-token": session.csrf_token },
    });
    expect(resp.status()).toBe(200);
    const stats = await resp.json();
    expect(typeof stats.total_open).toBe("number");
    expect(typeof stats.total_abandoned).toBe("number");
    expect(typeof stats.total_purchased).toBe("number");
    expect(typeof stats.abandonment_rate).toBe("number");
    expect(stats.total_open).toBeGreaterThanOrEqual(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 5: Deterministic sweep (injectable now), buyer status, auto-expire
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("SHOP-003 — Section 5: Deterministic sweep & expiry", () => {
  let detCartId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    rootPage = await newIdentityPage(browser, "root");

    const createResp = await cartPost(alicePage, "alice", "/ui/shoppingcart/carts");
    detCartId = (await createResp.json()).cart_id;
    await cartPost(alicePage, "alice", `/ui/shoppingcart/carts/${detCartId}/items`, {
      sku: `det_sku_${TS}`,
      name: `Deterministic ${TS}`,
      quantity: 1,
      unit_price_cents: 700,
    });
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await rootPage?.close();
  });

  test("5.1 Sweep with injectable now reminds a backdated cart deterministically", async () => {
    // Backdate activity to a fixed point and pin `now` 25h after it.
    const baseTs = 1_700_000_000;
    ddbUpdateCartTimestamp(ALICE_ID, detCartId, baseTs);
    const pinnedNow = baseTs + 25 * 3600;

    const session = adminSession("root");
    const scanResp = await rootPage.request.post(
      `${API}/ui/shoppingcart/admin/cart-abandonment/scan`,
      {
        headers: { "x-csrf-token": session.csrf_token },
        data: { now: pinnedNow, threshold_hours: 24 },
      },
    );
    expect(scanResp.status()).toBe(200);
    const result = await scanResp.json();
    expect(result.reminded).toBeGreaterThanOrEqual(1);

    const raw = ddbGetCartRaw(ALICE_ID, detCartId);
    expect(Number(raw.reminder_count ?? 0)).toBeGreaterThanOrEqual(1);
    expect(Number(raw.last_reminder_at ?? 0)).toBe(pinnedNow);
    expect(Number(raw.abandoned_at ?? 0)).toBe(pinnedNow);
  });

  test("5.2 Buyer-facing abandonment-status reflects reminder", async () => {
    const resp = await cartGet(
      alicePage,
      `/ui/shoppingcart/carts/${detCartId}/abandonment-status`,
    );
    expect(resp.status()).toBe(200);
    const status = await resp.json();
    expect(status.cart_id).toBe(detCartId);
    expect(status.is_abandoned).toBe(true);
    expect(status.reminder_count).toBeGreaterThanOrEqual(1);
  });

  test("5.3 Auto-expire transitions a long-abandoned cart to EXPIRED", async () => {
    // Create a fresh cart, backdate far beyond the expire window, sweep with expire.
    const createResp = await cartPost(alicePage, "alice", "/ui/shoppingcart/carts");
    const expireCartId = (await createResp.json()).cart_id;
    await cartPost(alicePage, "alice", `/ui/shoppingcart/carts/${expireCartId}/items`, {
      sku: `exp_sku_${TS}`,
      name: `Expire ${TS}`,
      quantity: 1,
      unit_price_cents: 250,
    });

    const baseTs = 1_600_000_000; // very old
    ddbUpdateCartTimestamp(ALICE_ID, expireCartId, baseTs);
    const pinnedNow = baseTs + 1000 * 3600; // well past 720h expire window

    const session = adminSession("root");
    const scanResp = await rootPage.request.post(
      `${API}/ui/shoppingcart/admin/cart-abandonment/scan`,
      {
        headers: { "x-csrf-token": session.csrf_token },
        data: { now: pinnedNow, threshold_hours: 24, expire: true, expire_hours: 720 },
      },
    );
    expect(scanResp.status()).toBe(200);
    const result = await scanResp.json();
    expect(result.expired).toBeGreaterThanOrEqual(1);

    const raw = ddbGetCartRaw(ALICE_ID, expireCartId);
    expect(raw.status).toBe("EXPIRED");
  });
});
