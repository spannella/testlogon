/**
 * E2E tests for Promo Codes & Coupons (PROMO-001).
 *
 * Sections:
 *   A — Promo Code CRUD API  (6 tests)
 *   B — Promo Validation API (7 tests)
 *   C — Promo Redemption API (4 tests)
 *   D — Promo UI             (3 tests)
 *
 * Auth: Alice session cookies (from e2e_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as fs from "fs";

// ─── Constants ───────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const TS       = Date.now();

// Unique codes per run to avoid collisions
const PCT_CODE   = `PCT${TS}`.slice(0, 28);
const FIXED_CODE = `FIX${TS}`.slice(0, 28);
const TRIAL_CODE = `TRI${TS}`.slice(0, 28);
const MAX_CODE   = `MAX${TS}`.slice(0, 28);
const PER_CODE   = `PER${TS}`.slice(0, 28);
const EXP_CODE   = `EXP${TS}`.slice(0, 28);
const MINP_CODE  = `MNP${TS}`.slice(0, 28);

// ─── Session bootstrap ──────────────────────────────────────────

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
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ────────────────────────────────────────────────

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

// ─── API helpers ─────────────────────────────────────────────────

function csrf(identity: string) {
  return getSessions()[identity].csrf_token;
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": csrf(identity) },
  });
}

async function apiGet(page: Page, identity: string, path: string) {
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": csrf(identity) },
  });
}

async function apiPatch(page: Page, identity: string, path: string, body: object) {
  return page.request.patch(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": csrf(identity) },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": csrf(identity) },
  });
}

// ─── DDB helper (for seeding expired codes, redemptions, etc.) ──

function ddbPut(tableName: string, item: string) {
  const script = `
import boto3, json
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
  region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test")
tbl = ddb.Table("${tableName}")
tbl.put_item(Item=json.loads('${item.replace(/'/g, "\\'")}'))
`;
  execSync(`python3 -c '${script.replace(/'/g, "'\\''")}'`, {
    cwd: "/home/ubuntu/testlogon",
    timeout: 10_000,
  });
}

// ─── Cleanup helper (delete accumulated promo codes from prior runs) ─

function cleanupAlicePromoCodes() {
  const script = `
import boto3
from boto3.dynamodb.conditions import Key

ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
    region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test")
tbl = ddb.Table("PromoCodes")

# Query all items for Alice via GSI
items = []
params = {
    "IndexName": "ByCreatorCreatedAt",
    "KeyConditionExpression": Key("creator_scope").eq("CREATOR#e2e_alice@test.local"),
}
while True:
    resp = tbl.query(**params)
    items.extend(resp.get("Items", []))
    lek = resp.get("LastEvaluatedKey")
    if not lek:
        break
    params["ExclusiveStartKey"] = lek

# Also get all REDEEM items under each promo PK
all_pks = set(i["pk"] for i in items)
for pk in all_pks:
    resp2 = tbl.query(KeyConditionExpression=Key("pk").eq(pk))
    for it in resp2.get("Items", []):
        if it not in items:
            items.append(it)

# Delete all
with tbl.batch_writer() as batch:
    for item in items:
        batch.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
print(f"Deleted {len(items)} items")
`;
  try {
    const tmpFile = `/tmp/promo_cleanup_${Date.now()}.py`;
    fs.writeFileSync(tmpFile, script);
    execSync(`python3 ${tmpFile}`, { cwd: "/home/ubuntu/testlogon", timeout: 30_000 });
  } catch (e) {
    console.warn("Promo cleanup warning:", e);
  }
}

// ─── State shared across sections ────────────────────────────────

let alicePage: Page;
let bobPage: Page;
let pctCodeId: string;
let fixedCodeId: string;

// ═══════════════════════════════════════════════════════════════════
// Section A: Promo Code CRUD API (6 tests)
// ═══════════════════════════════════════════════════════════════════

test.describe("Section A — Promo Code CRUD API", () => {
  test.beforeAll(async ({ browser }) => {
    // Clean up accumulated promo codes from previous test runs
    cleanupAlicePromoCodes();
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("A1 — Creator creates a percentage discount code", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes", {
      code: PCT_CODE,
      discount_type: "percentage",
      discount_value: 25,
      applies_to: ["subscription", "vod"],
      max_uses: 100,
      max_uses_per_user: 1,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.code).toBe(PCT_CODE.toUpperCase());
    expect(data.discount_type).toBe("percentage");
    expect(data.discount_value).toBe(25);
    expect(data.active).toBe(true);
    expect(data.current_uses).toBe(0);
    pctCodeId = data.code_id;
  });

  test("A2 — Creator creates a fixed amount discount code", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes", {
      code: FIXED_CODE,
      discount_type: "fixed_amount",
      discount_value: 500,
      applies_to: ["shop"],
      min_purchase_cents: 1000,
      max_uses_per_user: 1,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.code).toBe(FIXED_CODE.toUpperCase());
    expect(data.discount_type).toBe("fixed_amount");
    expect(data.discount_value).toBe(500);
    fixedCodeId = data.code_id;
  });

  test("A3 — Duplicate code string returns 409", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/promo-codes", {
      code: PCT_CODE,
      discount_type: "percentage",
      discount_value: 10,
      applies_to: ["subscription"],
    });
    expect(resp.status()).toBe(409);
  });

  test("A4 — Creator lists their codes", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, "/ui/promo-codes");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeDefined();
    const codes = data.items.map((c: any) => c.code);
    expect(codes).toContain(PCT_CODE.toUpperCase());
    expect(codes).toContain(FIXED_CODE.toUpperCase());
  });

  test("A5 — Creator deactivates a code", async () => {
    const resp = await apiDelete(alicePage, ALICE_ID, `/ui/promo-codes/${fixedCodeId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.active).toBe(false);

    // Confirm GET shows inactive
    const resp2 = await apiGet(alicePage, ALICE_ID, `/ui/promo-codes/${fixedCodeId}`);
    expect(resp2.status()).toBe(200);
    const data2 = await resp2.json();
    expect(data2.active).toBe(false);
  });

  test("A6 — Creator updates code max_uses", async () => {
    const resp = await apiPatch(alicePage, ALICE_ID, `/ui/promo-codes/${pctCodeId}`, {
      max_uses: 200,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.max_uses).toBe(200);
  });
});

// ═══════════════════════════════════════════════════════════════════
// Section B: Promo Validation API (7 tests)
// ═══════════════════════════════════════════════════════════════════

test.describe("Section B — Promo Validation API", () => {
  let aliceP: Page;
  let bobP: Page;
  const aliceSub = () => getSessions()[ALICE_ID].user_sub;
  const bobSub = () => getSessions()[BOB_ID].user_sub;

  // Codes created per-section to be isolated
  let valPctCodeId: string;
  let valMaxCodeId: string;
  let valPerCodeId: string;
  let valMinPCodeId: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    aliceP = await aliceCtx.newPage();
    await injectAuth(aliceP, ALICE_ID);

    const bobCtx = await browser.newContext();
    bobP = await bobCtx.newPage();
    await injectAuth(bobP, BOB_ID);

    // Create codes for validation tests
    let resp: any;

    // Percentage code
    resp = await apiPost(aliceP, ALICE_ID, "/ui/promo-codes", {
      code: `VPCT${TS}`.slice(0, 28),
      discount_type: "percentage",
      discount_value: 20,
      applies_to: ["subscription"],
      max_uses: 0,
      max_uses_per_user: 0,
    });
    valPctCodeId = (await resp.json()).code_id;

    // Max uses code (max_uses=1)
    resp = await apiPost(aliceP, ALICE_ID, "/ui/promo-codes", {
      code: MAX_CODE,
      discount_type: "percentage",
      discount_value: 10,
      applies_to: ["subscription"],
      max_uses: 1,
      max_uses_per_user: 0,
    });
    valMaxCodeId = (await resp.json()).code_id;

    // Per-user limit code (max_uses_per_user=1)
    resp = await apiPost(aliceP, ALICE_ID, "/ui/promo-codes", {
      code: PER_CODE,
      discount_type: "percentage",
      discount_value: 15,
      applies_to: ["subscription"],
      max_uses: 0,
      max_uses_per_user: 1,
    });
    valPerCodeId = (await resp.json()).code_id;

    // Min purchase code
    resp = await apiPost(aliceP, ALICE_ID, "/ui/promo-codes", {
      code: MINP_CODE,
      discount_type: "fixed_amount",
      discount_value: 500,
      applies_to: ["subscription"],
      min_purchase_cents: 1000,
      max_uses_per_user: 0,
    });
    valMinPCodeId = (await resp.json()).code_id;
  });

  test.afterAll(async () => {
    await aliceP.context().close();
    await bobP.context().close();
  });

  test("B1 — Valid percentage code returns correct discount preview", async () => {
    const resp = await apiPost(bobP, BOB_ID, "/ui/promo-codes/validate", {
      code: `VPCT${TS}`.slice(0, 28),
      checkout_type: "subscription",
      item_price_cents: 1000,
      creator_user_id: aliceSub(),
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.valid).toBe(true);
    expect(data.discount_cents).toBe(200); // 20% of 1000
    expect(data.final_price_cents).toBe(800);
  });

  test("B2 — Valid fixed amount code returns correct discount", async () => {
    // Re-create a fresh fixed code since the one from Section A was deactivated
    const freshFixedCode = `VFX${TS}`.slice(0, 28);
    await apiPost(aliceP, ALICE_ID, "/ui/promo-codes", {
      code: freshFixedCode,
      discount_type: "fixed_amount",
      discount_value: 300,
      applies_to: ["subscription"],
      max_uses_per_user: 0,
    });

    const resp = await apiPost(bobP, BOB_ID, "/ui/promo-codes/validate", {
      code: freshFixedCode,
      checkout_type: "subscription",
      item_price_cents: 1000,
      creator_user_id: aliceSub(),
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.valid).toBe(true);
    expect(data.discount_cents).toBe(300);
    expect(data.final_price_cents).toBe(700);
  });

  test("B3 — Expired code returns invalid with expired message", async () => {
    // Seed an expired code directly in DDB using a Python script file
    const expCode = EXP_CODE.toUpperCase();
    const expCodeId = `pc_expired${TS}`;
    const aliceSub_ = getSessions()[ALICE_ID].user_sub;
    const pyScript = `
import boto3, json
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test")
tbl = ddb.Table("PromoCodes")
tbl.put_item(Item={
    "pk": "PROMO#${expCodeId}",
    "sk": "META",
    "code_id": "${expCodeId}",
    "code": "${expCode}",
    "code_lookup_pk": "CODE#${expCode}",
    "code_lookup_sk": "META",
    "creator_user_id": "${aliceSub_}",
    "creator_scope": "CREATOR#${aliceSub_}",
    "discount_type": "percentage",
    "discount_value": 10,
    "free_trial_days": 0,
    "applies_to": ["subscription"],
    "min_purchase_cents": 0,
    "max_uses": 0,
    "max_uses_per_user": 0,
    "current_uses": 0,
    "expires_at": 1000000,
    "active": True,
    "created_at": 1000000,
    "updated_at": 1000000,
})
print("OK")
`;
    const tmpPath = `/tmp/promo_seed_${TS}.py`;
    fs.writeFileSync(tmpPath, pyScript);
    execSync(`python3 ${tmpPath}`, {
      cwd: "/home/ubuntu/testlogon",
      timeout: 10_000,
    });

    const resp = await apiPost(bobP, BOB_ID, "/ui/promo-codes/validate", {
      code: expCode,
      checkout_type: "subscription",
      item_price_cents: 1000,
      creator_user_id: aliceSub_,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.valid).toBe(false);
    expect(data.message).toContain("expired");
  });

  test("B4 — Exhausted code (max_uses reached) returns invalid", async () => {
    // Redeem once to exhaust (max_uses=1)
    await apiPost(bobP, BOB_ID, "/ui/promo-codes/redeem", {
      code_id: valMaxCodeId,
      original_price_cents: 1000,
      final_price_cents: 900,
      checkout_type: "subscription",
    });

    const resp = await apiPost(bobP, BOB_ID, "/ui/promo-codes/validate", {
      code: MAX_CODE,
      checkout_type: "subscription",
      item_price_cents: 1000,
      creator_user_id: getSessions()[ALICE_ID].user_sub,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.valid).toBe(false);
    expect(data.message).toContain("fully redeemed");
  });

  test("B5 — Per-user limit exceeded returns invalid", async () => {
    // Redeem once as Bob
    await apiPost(bobP, BOB_ID, "/ui/promo-codes/redeem", {
      code_id: valPerCodeId,
      original_price_cents: 1000,
      final_price_cents: 850,
      checkout_type: "subscription",
    });

    const resp = await apiPost(bobP, BOB_ID, "/ui/promo-codes/validate", {
      code: PER_CODE,
      checkout_type: "subscription",
      item_price_cents: 1000,
      creator_user_id: getSessions()[ALICE_ID].user_sub,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.valid).toBe(false);
    expect(data.message).toContain("already used");
  });

  test("B6 — Code from wrong creator returns invalid", async () => {
    const resp = await apiPost(bobP, BOB_ID, "/ui/promo-codes/validate", {
      code: `VPCT${TS}`.slice(0, 28),
      checkout_type: "subscription",
      item_price_cents: 1000,
      creator_user_id: getSessions()[BOB_ID].user_sub, // Wrong creator
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.valid).toBe(false);
    expect(data.message).toContain("not valid for this creator");
  });

  test("B7 — Below minimum purchase returns invalid", async () => {
    const resp = await apiPost(bobP, BOB_ID, "/ui/promo-codes/validate", {
      code: MINP_CODE,
      checkout_type: "subscription",
      item_price_cents: 500, // Less than min_purchase_cents=1000
      creator_user_id: getSessions()[ALICE_ID].user_sub,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.valid).toBe(false);
    expect(data.message).toContain("Minimum purchase");
  });
});

// ═══════════════════════════════════════════════════════════════════
// Section C: Promo Redemption API (4 tests)
// ═══════════════════════════════════════════════════════════════════

test.describe("Section C — Promo Redemption API", () => {
  let aliceP: Page;
  let bobP: Page;
  let redeemCodeId: string;
  let redeemCodeStr: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    aliceP = await aliceCtx.newPage();
    await injectAuth(aliceP, ALICE_ID);

    const bobCtx = await browser.newContext();
    bobP = await bobCtx.newPage();
    await injectAuth(bobP, BOB_ID);

    redeemCodeStr = `RDM${TS}`.slice(0, 28);
    const resp = await apiPost(aliceP, ALICE_ID, "/ui/promo-codes", {
      code: redeemCodeStr,
      discount_type: "percentage",
      discount_value: 30,
      applies_to: ["subscription"],
      max_uses: 5,
      max_uses_per_user: 3,
    });
    redeemCodeId = (await resp.json()).code_id;
  });

  test.afterAll(async () => {
    await aliceP.context().close();
    await bobP.context().close();
  });

  test("C1 — Redeem code succeeds and returns ok", async () => {
    const resp = await apiPost(bobP, BOB_ID, "/ui/promo-codes/redeem", {
      code_id: redeemCodeId,
      original_price_cents: 1000,
      final_price_cents: 700,
      checkout_type: "subscription",
      checkout_item_id: "plan_test",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.redeemed_at).toBeGreaterThan(0);
  });

  test("C2 — Redeem increments current_uses", async () => {
    const resp = await apiGet(aliceP, ALICE_ID, `/ui/promo-codes/${redeemCodeId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.current_uses).toBeGreaterThanOrEqual(1);
  });

  test("C3 — Stats show redemption record", async () => {
    const resp = await apiGet(aliceP, ALICE_ID, `/ui/promo-codes/${redeemCodeId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.stats).toBeDefined();
    expect(data.stats.total_redemptions).toBeGreaterThanOrEqual(1);
    expect(data.stats.total_discount_cents).toBeGreaterThan(0);
    const bobRedeem = data.stats.redemptions.find(
      (r: any) => r.user_id === getSessions()[BOB_ID].user_sub,
    );
    expect(bobRedeem).toBeDefined();
    expect(bobRedeem.discount_applied_cents).toBe(300);
    expect(bobRedeem.checkout_type).toBe("subscription");
  });

  test("C4 — Deactivated code cannot be redeemed", async () => {
    // Deactivate
    await apiDelete(aliceP, ALICE_ID, `/ui/promo-codes/${redeemCodeId}`);

    // Try to validate
    const resp = await apiPost(bobP, BOB_ID, "/ui/promo-codes/validate", {
      code: redeemCodeStr,
      checkout_type: "subscription",
      item_price_cents: 1000,
      creator_user_id: getSessions()[ALICE_ID].user_sub,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.valid).toBe(false);
    expect(data.message).toBe("Code not found");
  });
});

// ═══════════════════════════════════════════════════════════════════
// Section D: Promo UI (3 tests)
// ═══════════════════════════════════════════════════════════════════

test.describe("Section D — Promo UI", () => {
  let aliceP: Page;
  const uiCode = `UITST${TS}`.slice(0, 28);

  test.beforeAll(async ({ browser }) => {
    // Seed a promo code via DDB directly (avoids CSRF/session issues on retry)
    const aliceSub_ = getSessions()[ALICE_ID].user_sub;
    const seedCodeId = `pc_ui_${TS}`;
    const seedCode = uiCode.toUpperCase();
    const seedScript = `
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001", region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test")
tbl = ddb.Table("PromoCodes")
import time
ts = int(time.time())
tbl.put_item(Item={
    "pk": "PROMO#${seedCodeId}",
    "sk": "META",
    "code_id": "${seedCodeId}",
    "code": "${seedCode}",
    "code_lookup_pk": "CODE#${seedCode}",
    "code_lookup_sk": "META",
    "creator_user_id": "${aliceSub_}",
    "creator_scope": "CREATOR#${aliceSub_}",
    "discount_type": "percentage",
    "discount_value": 15,
    "free_trial_days": 0,
    "applies_to": ["subscription"],
    "min_purchase_cents": 0,
    "max_uses": 50,
    "max_uses_per_user": 1,
    "current_uses": 0,
    "expires_at": 0,
    "active": True,
    "created_at": ts,
    "updated_at": ts,
})
print("OK")
`;
    const tmpSeed = `/tmp/promo_ui_seed_${TS}.py`;
    fs.writeFileSync(tmpSeed, seedScript);
    execSync(`python3 ${tmpSeed}`, { cwd: "/home/ubuntu/testlogon", timeout: 10_000 });

    const aliceCtx = await browser.newContext();
    aliceP = await aliceCtx.newPage();
    await injectAuth(aliceP, ALICE_ID);
  });

  test.afterAll(async () => {
    await aliceP.context().close();
  });

  test("D1 — Promo code manager page loads and lists codes", async () => {
    // Navigate and wait for GET /ui/promo-codes to return
    const [resp] = await Promise.all([
      aliceP.waitForResponse((r) => r.url().includes("/ui/promo-codes") && r.request().method() === "GET", { timeout: 15_000 }),
      aliceP.goto(`${BASE}/promo`, { waitUntil: "domcontentloaded" }),
    ]);
    expect(resp.status()).toBe(200);
    await expect(aliceP.getByRole("heading", { name: "Promo Codes" })).toBeVisible({ timeout: 10_000 });
    // Wait for table to render
    await expect(aliceP.locator('[data-testid="promo-codes-table"]')).toBeVisible({ timeout: 15_000 });
    // The seeded code should appear
    await expect(aliceP.locator(`[data-testid="promo-row-${uiCode.toUpperCase()}"]`)).toBeVisible({ timeout: 10_000 });
  });

  test("D2 — Create promo dialog submits new code", async () => {
    const [listResp] = await Promise.all([
      aliceP.waitForResponse((r) => r.url().includes("/ui/promo-codes") && r.request().method() === "GET", { timeout: 15_000 }),
      aliceP.goto(`${BASE}/promo`, { waitUntil: "domcontentloaded" }),
    ]);
    await expect(aliceP.getByRole("heading", { name: "Promo Codes" })).toBeVisible({ timeout: 10_000 });
    await aliceP.locator('[data-testid="create-promo-btn"]').click();
    await expect(aliceP.locator('[data-testid="create-promo-dialog"]')).toBeVisible();

    const dialogCode = `DLG${TS}`.slice(0, 28);
    await aliceP.locator('[data-testid="promo-code-input"]').fill(dialogCode);

    // Click submit and wait for POST response
    const [postResp] = await Promise.all([
      aliceP.waitForResponse((r) => r.url().includes("/ui/promo-codes") && r.request().method() === "POST", { timeout: 15_000 }),
      aliceP.locator('[data-testid="submit-promo-btn"]').click(),
    ]);
    expect(postResp.status()).toBe(201);

    // Wait for dialog to close
    await expect(aliceP.locator('[data-testid="create-promo-dialog"]')).not.toBeVisible({ timeout: 10_000 });

    // Reload to verify
    const [listResp2] = await Promise.all([
      aliceP.waitForResponse((r) => r.url().includes("/ui/promo-codes") && r.request().method() === "GET", { timeout: 15_000 }),
      aliceP.goto(`${BASE}/promo`, { waitUntil: "domcontentloaded" }),
    ]);
    await expect(aliceP.locator('[data-testid="promo-codes-table"]')).toBeVisible({ timeout: 15_000 });
    await expect(aliceP.locator(`[data-testid="promo-row-${dialogCode.toUpperCase()}"]`)).toBeVisible({ timeout: 10_000 });
  });

  test("D3 — Stats dialog shows redemption stats", async () => {
    const [listResp] = await Promise.all([
      aliceP.waitForResponse((r) => r.url().includes("/ui/promo-codes") && r.request().method() === "GET", { timeout: 15_000 }),
      aliceP.goto(`${BASE}/promo`, { waitUntil: "domcontentloaded" }),
    ]);
    await expect(aliceP.locator('[data-testid="promo-codes-table"]')).toBeVisible({ timeout: 15_000 });

    // Click Stats on the UI test code
    const statsBtn = aliceP.locator(`[data-testid="stats-${uiCode.toUpperCase()}"]`);
    await expect(statsBtn).toBeVisible({ timeout: 10_000 });
    await statsBtn.click();
    await expect(aliceP.locator('[data-testid="promo-stats-dialog"]')).toBeVisible({ timeout: 10_000 });
    await expect(aliceP.getByText(`Stats: ${uiCode.toUpperCase()}`)).toBeVisible();
  });
});
