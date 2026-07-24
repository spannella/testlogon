/**
 * E2E tests for KYC-009 Tiered Verification Levels.
 *
 * Sections:
 *   182 — Tier Query API            (4 tests)
 *   183 — Tier Upgrade API          (4 tests)
 *   184 — Admin Tier Override API   (4 tests)
 *   185 — Tier Progress UI          (4 tests)
 *
 * Auth:
 *   Root  — root.admin@testdev.local (for admin endpoints)
 *   Alice — e2e_alice@test.local     (for user endpoints + UI)
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ROOT_ID = "root";
const ALICE_ID = "alice";
const TS = Date.now();

// ── Session bootstrap ────────────────────────────────────────────────────────

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

// ── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    (uid: string) => {
      const state = { userId: uid, accessToken: null, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    session.user_sub,
  );
}

// ── API helpers ──────────────────────────────────────────────────────────────

function csrfFor(identity: string): string {
  return getSessions()[identity].csrf_token;
}

async function apiGet(page: Page, identity: string, path: string) {
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": csrfFor(identity) },
  });
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": csrfFor(identity) },
  });
}

// ── DDB helpers ──────────────────────────────────────────────────────────────

const PYTHON = REPO_ROOT + "/.venv/bin/python3";

const DDB_PRELUDE = `
import boto3, os
ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
users = ddb.Table('users')
`;

function setProfileField(userSub: string, field: string, value: string | number | boolean) {
  const pyVal =
    typeof value === "boolean" ? (value ? "True" : "False") :
    typeof value === "number" ? String(value) :
    `"${value}"`;
  execSync(
    `${PYTHON} -c "${DDB_PRELUDE}
users.update_item(
    Key={'user_sub': '${userSub}'},
    UpdateExpression='SET ${field} = :v',
    ExpressionAttributeValues={':v': ${pyVal}},
)
print('ok')
"`,
    { timeout: 10_000 },
  );
}

function removeProfileField(userSub: string, field: string) {
  execSync(
    `${PYTHON} -c "${DDB_PRELUDE}
users.update_item(
    Key={'user_sub': '${userSub}'},
    UpdateExpression='REMOVE ${field}',
)
print('ok')
"`,
    { timeout: 10_000 },
  );
}

function clearTierFields(userSub: string) {
  execSync(
    `${PYTHON} -c "${DDB_PRELUDE}
users.update_item(
    Key={'user_sub': '${userSub}'},
    UpdateExpression='REMOVE kyc_tier, kyc_tier_updated_at, kyc_tier_history, email_verified, phone_verified',
)
print('ok')
"`,
    { timeout: 10_000 },
  );
}

// ── Test pages ───────────────────────────────────────────────────────────────

let alicePage: Page;
let rootPage: Page;

test.beforeAll(async ({ browser }) => {
  const sessions = getSessions();

  // Reset Alice's tier + verification flags to clean state
  clearTierFields(sessions[ALICE_ID].user_sub);

  alicePage = await browser.newPage();
  await injectAuth(alicePage, ALICE_ID);

  rootPage = await browser.newPage();
  await injectAuth(rootPage, ROOT_ID);
});

test.afterAll(async () => {
  await alicePage?.close();
  await rootPage?.close();
});


// ═══════════════════════════════════════════════════════════════════════════
// Section 182: Tier Query API
// ═══════════════════════════════════════════════════════════════════════════

test.describe("182 — Tier Query API", () => {
  test("GET /v1/kyc/tiers/me returns tier 0 for new user", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    clearTierFields(aliceSub);
    const resp = await apiGet(alicePage, ALICE_ID, "/v1/kyc/tiers/me");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.current_tier).toBe(0);
    expect(data.tier_name).toBe("Unverified");
    expect(data.user_sub).toBe(aliceSub);
  });

  test("GET /v1/kyc/tiers/me/requirements/1 shows unmet requirements", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    clearTierFields(aliceSub);
    const resp = await apiGet(alicePage, ALICE_ID, "/v1/kyc/tiers/me/requirements/1");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.target_tier).toBe(1);
    expect(data.eligible).toBe(false);
    expect(data.unmet).toContain("email_verified");
    expect(data.unmet).toContain("phone_verified");
  });

  test("GET /v1/kyc/tiers/me/requirements/2 includes tier 1 prerequisites", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    clearTierFields(aliceSub);
    const resp = await apiGet(alicePage, ALICE_ID, "/v1/kyc/tiers/me/requirements/2");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.target_tier).toBe(2);
    // Tier 1 prereqs must be in unmet (we just cleared them)
    expect(data.unmet).toContain("email_verified");
    expect(data.unmet).toContain("phone_verified");
    expect(data.unmet).toContain("tier_1");
    // kyc_case_approved should be in either met or unmet depending on prior KYC case state
    const allReqs = [...data.met, ...data.unmet];
    expect(allReqs).toContain("kyc_case_approved");
  });

  test("GET /v1/kyc/tiers/me returns history after tier change", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    clearTierFields(aliceSub);

    // Admin override Alice to tier 1
    const overrideResp = await apiPost(rootPage, ROOT_ID, `/v1/kyc/tiers/admin/${aliceSub}/override`, {
      tier: 1,
      reason: `test override for history check ${TS}`,
    });
    expect(overrideResp.status()).toBe(200);

    // Now check history
    const resp = await apiGet(alicePage, ALICE_ID, "/v1/kyc/tiers/me");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.current_tier).toBe(1);
    expect(data.history.length).toBeGreaterThanOrEqual(1);
    const lastEntry = data.history[data.history.length - 1];
    expect(lastEntry.from_tier).toBe(0);
    expect(lastEntry.to_tier).toBe(1);
    expect(lastEntry.reason).toContain("test override for history check");

    // Reset
    clearTierFields(aliceSub);
  });
});


// ═══════════════════════════════════════════════════════════════════════════
// Section 183: Tier Upgrade API
// ═══════════════════════════════════════════════════════════════════════════

test.describe("183 — Tier Upgrade API", () => {
  test("POST /v1/kyc/tiers/me/evaluate does not upgrade without prerequisites", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    clearTierFields(aliceSub);

    const resp = await apiPost(alicePage, ALICE_ID, "/v1/kyc/tiers/me/evaluate", {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.current_tier).toBe(0);
  });

  test("POST /v1/kyc/tiers/me/evaluate upgrades to tier 1 when email+phone verified", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    clearTierFields(aliceSub);

    // Seed verification flags
    setProfileField(aliceSub, "email_verified", true);
    setProfileField(aliceSub, "phone_verified", true);

    const resp = await apiPost(alicePage, ALICE_ID, "/v1/kyc/tiers/me/evaluate", {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.current_tier).toBe(1);
    expect(data.tier_name).toBe("Basic");
  });

  test("POST /v1/kyc/tiers/me/evaluate is idempotent when no further upgrade possible", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    clearTierFields(aliceSub);
    setProfileField(aliceSub, "email_verified", true);
    setProfileField(aliceSub, "phone_verified", true);

    // Keep calling evaluate until the tier stabilizes (progressive upgrade per call)
    let prevTier = 0;
    let stableTier = 0;
    for (let i = 0; i < 5; i++) {
      const resp = await apiPost(alicePage, ALICE_ID, "/v1/kyc/tiers/me/evaluate", {});
      expect(resp.status()).toBe(200);
      stableTier = (await resp.json()).current_tier;
      if (stableTier === prevTier) break;
      prevTier = stableTier;
    }
    expect(stableTier).toBeGreaterThanOrEqual(1);

    // One more call — should stay at the same tier
    const finalResp = await apiPost(alicePage, ALICE_ID, "/v1/kyc/tiers/me/evaluate", {});
    expect(finalResp.status()).toBe(200);
    const finalData = await finalResp.json();
    expect(finalData.current_tier).toBe(stableTier);

    // Verify history has exactly one entry for the final stable tier
    const getResp = await apiGet(alicePage, ALICE_ID, "/v1/kyc/tiers/me");
    const hist = (await getResp.json()).history;
    const autoEvalEntries = hist.filter(
      (h: any) => h.reason === "auto_evaluation" && h.to_tier === stableTier,
    );
    expect(autoEvalEntries.length).toBe(1);
  });

  test("Tier upgrade generates alert for user", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    clearTierFields(aliceSub);

    // Set up verification and trigger upgrade to generate an alert
    setProfileField(aliceSub, "email_verified", true);
    setProfileField(aliceSub, "phone_verified", true);
    const evalResp = await apiPost(alicePage, ALICE_ID, "/v1/kyc/tiers/me/evaluate", {});
    expect(evalResp.status()).toBe(200);
    expect((await evalResp.json()).current_tier).toBe(1);

    // Now check for the alert
    const resp = await apiGet(alicePage, ALICE_ID, "/ui/alerts?limit=50");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const tierAlert = (data.alerts || []).find(
      (a: any) => a.event === "kyc.tier.upgraded",
    );
    expect(tierAlert).toBeTruthy();
    expect(tierAlert.title).toContain("Basic");

    // Clean up
    clearTierFields(aliceSub);
  });
});


// ═══════════════════════════════════════════════════════════════════════════
// Section 184: Admin Tier Override API
// ═══════════════════════════════════════════════════════════════════════════

test.describe("184 — Admin Tier Override API", () => {
  test("POST /v1/kyc/tiers/admin/{user_sub}/override sets tier directly", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    clearTierFields(aliceSub);

    const resp = await apiPost(rootPage, ROOT_ID, `/v1/kyc/tiers/admin/${aliceSub}/override`, {
      tier: 3,
      reason: `manual verification completed offline ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.current_tier).toBe(3);
    expect(data.tier_name).toBe("Enhanced");
    expect(data.history.length).toBeGreaterThanOrEqual(1);

    // Verify admin can read the tier
    const adminResp = await apiGet(rootPage, ROOT_ID, `/v1/kyc/tiers/admin/${aliceSub}`);
    expect(adminResp.status()).toBe(200);
    const adminData = await adminResp.json();
    expect(adminData.current_tier).toBe(3);

    // Reset
    clearTierFields(aliceSub);
  });

  test("Admin override with tier > 4 returns 422", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    const resp = await apiPost(rootPage, ROOT_ID, `/v1/kyc/tiers/admin/${aliceSub}/override`, {
      tier: 5,
      reason: "should fail validation",
    });
    expect(resp.status()).toBe(422);
  });

  test("Admin override with short reason returns 422", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    const resp = await apiPost(rootPage, ROOT_ID, `/v1/kyc/tiers/admin/${aliceSub}/override`, {
      tier: 2,
      reason: "ok",
    });
    expect(resp.status()).toBe(422);
  });

  test("Non-root user cannot override tier", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    // Alice (USER role) tries to override
    const resp = await apiPost(alicePage, ALICE_ID, `/v1/kyc/tiers/admin/${aliceSub}/override`, {
      tier: 4,
      reason: "should be denied by role check",
    });
    expect(resp.status()).toBe(403);
  });
});


// ═══════════════════════════════════════════════════════════════════════════
// Section 185: Tier Progress UI
// ═══════════════════════════════════════════════════════════════════════════

test.describe("185 — Tier Progress UI", () => {
  test("KYC Tier Progress page shows current tier badge", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    clearTierFields(aliceSub);

    await alicePage.goto(`${BASE}/kyc/tiers`, { waitUntil: "domcontentloaded" });

    const badge = alicePage.locator('[data-testid="kyc-tier-badge"]');
    await expect(badge).toBeVisible({ timeout: 15_000 });
    await expect(badge).toContainText("Unverified");
  });

  test("Requirements checklist shows met/unmet items", async () => {
    await alicePage.goto(`${BASE}/kyc/tiers`, { waitUntil: "domcontentloaded" });

    const checklist = alicePage.locator('[data-testid="requirements-checklist"]');
    await expect(checklist).toBeVisible({ timeout: 15_000 });

    // Should have unmet items (circles) for a tier-0 user
    const unmetIcons = alicePage.locator('[data-testid="req-unmet"]');
    await expect(unmetIcons.first()).toBeVisible();
  });

  test("Evaluate button triggers tier check", async () => {
    await alicePage.goto(`${BASE}/kyc/tiers`, { waitUntil: "domcontentloaded" });

    const evaluateBtn = alicePage.locator('[data-testid="evaluate-tier-btn"]');
    await expect(evaluateBtn).toBeVisible({ timeout: 15_000 });

    // Click and wait for the evaluate API call
    const [evalResp] = await Promise.all([
      alicePage.waitForResponse(
        (r) => r.url().includes("/v1/kyc/tiers/me/evaluate") && r.status() === 200,
      ),
      evaluateBtn.click(),
    ]);
    expect(evalResp.status()).toBe(200);
  });

  test("Tier badge updates after admin override", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    clearTierFields(aliceSub);

    // Admin sets Alice to tier 2
    const overrideResp = await apiPost(rootPage, ROOT_ID, `/v1/kyc/tiers/admin/${aliceSub}/override`, {
      tier: 2,
      reason: `testing badge update in UI ${TS}`,
    });
    expect(overrideResp.status()).toBe(200);

    // Reload page
    await alicePage.goto(`${BASE}/kyc/tiers`, { waitUntil: "domcontentloaded" });

    const badge = alicePage.locator('[data-testid="kyc-tier-badge"]');
    await expect(badge).toBeVisible({ timeout: 15_000 });
    await expect(badge).toContainText("ID Verified");

    // Check history renders
    const historyList = alicePage.locator('[data-testid="tier-history"]');
    await expect(historyList).toBeVisible();

    // Clean up
    clearTierFields(aliceSub);
  });
});
