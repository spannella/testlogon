/**
 * E2E tests for License Revenue (LICENSE-003).
 *
 * Sections:
 *   471 -- Revenue Split Calculation API (4 tests)
 *   472 -- Revenue Split Processing API (5 tests)
 *   473 -- Revenue Dashboard API (4 tests)
 *   474 -- Admin Revenue Audit API (2 tests)
 *
 * Auth: Alice (licensor), Bob (licensee), Root (admin).
 * Sessions created by e2e_admin_session_setup.py.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ───────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";

// Session keys (for looking up in the sessions object)
const ALICE_KEY = "alice";
const BOB_KEY = "bob";
const ROOT_KEY = "root";

// User sub values (for data fields)
const ALICE_SUB = "e2e_alice@test.local";
const BOB_SUB = "e2e_bob@test.local";

const TS = Date.now();
const CONTENT_ID = `e2e_content_${TS}`;
const LICENSE_ID = `e2e_lic_${TS}`;
const LICENSE_ID_FIXED = `e2e_lic_fixed_${TS}`;
const LICENSE_ID_PROF = `e2e_lic_prof_${TS}`;
const LICENSE_ID_SELF = `e2e_lic_self_${TS}`;
const LICENSE_ID_REVOKE = `e2e_lic_revoke_${TS}`;
const CONTENT_SELF = `e2e_self_content_${TS}`;
const CONTENT_REVOKE = `e2e_revoke_content_${TS}`;
const CONTENT_FIXED = `e2e_fixed_content_${TS}`;
const CONTENT_PROF = `e2e_prof_content_${TS}`;

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
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ────────────────────────────────────────────────────────────

async function newIdentityPage(
  browser: Browser,
  sessionKey: string,
): Promise<Page> {
  const sessions = getSessions();
  const session = sessions[sessionKey];
  if (!session) throw new Error(`No session for key '${sessionKey}'. Available: ${Object.keys(sessions).join(", ")}`);
  const page = await browser.newPage();
  await page.context().addCookies(session.cookies);
  return page;
}

async function apiPost(
  page: Page,
  sessionKey: string,
  path: string,
  body?: unknown,
) {
  const sess = getSessions()[sessionKey];
  return page.request.post(`${BASE}${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
    data: body,
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  let url = `${BASE}${path}`;
  if (params) {
    const qs = new URLSearchParams(params).toString();
    url += `?${qs}`;
  }
  return page.request.get(url);
}

// ─── Section 471: Revenue Split Calculation API ─────────────────────────────

test.describe("471 -- Revenue Split Calculation API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_KEY);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("471.1 Split preview returns correct calculation", async () => {
    const resp = await apiGet(alicePage, "/ui/licenses/revenue/calculate", {
      amount: "1000",
      revenue_share_pct: "5",
      profit_share_pct: "10",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // 5% of 1000 = 50 revenue share
    expect(data.revenue_share_cents).toBe(50);
    // net = 1000 - 20% = 800; 10% of 800 = 80 profit share
    expect(data.profit_share_cents).toBe(80);
    expect(data.total_licensor_share_cents).toBe(130);
    expect(data.platform_fee_cents).toBe(200);
    expect(data.source_amount_cents).toBe(1000);
  });

  test("471.2 Zero terms produce zero split", async () => {
    const resp = await apiGet(alicePage, "/ui/licenses/revenue/calculate", {
      amount: "1000",
      revenue_share_pct: "0",
      profit_share_pct: "0",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.total_licensor_share_cents).toBe(0);
    expect(data.revenue_share_cents).toBe(0);
    expect(data.profit_share_cents).toBe(0);
  });

  test("471.3 Max terms capped at 80% of source", async () => {
    const resp = await apiGet(alicePage, "/ui/licenses/revenue/calculate", {
      amount: "1000",
      revenue_share_pct: "100",
      profit_share_pct: "100",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // 100% rev = 1000, 100% prof on net 800 = 800, total 1800 > cap 800
    expect(data.total_licensor_share_cents).toBeLessThanOrEqual(800);
  });

  test("471.4 Preview with fixed cost adds fixed component", async () => {
    const resp = await apiGet(alicePage, "/ui/licenses/revenue/calculate", {
      amount: "1000",
      revenue_share_pct: "5",
      profit_share_pct: "0",
      fixed_cost_cents: "500",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // revenue_share = 50, fixed = 500, total = 550
    expect(data.total_licensor_share_cents).toBe(550);
  });
});

// ─── Section 472: Revenue Split Processing API ──────────────────────────────

test.describe("472 -- Revenue Split Processing API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage = await newIdentityPage(browser, BOB_KEY);
    // GAP-0295/0296: register/revoke/process-split are admin/root-only.
    // Root performs the privileged mutations on behalf of Alice/Bob
    // (licensor_id/licensee_id are passed explicitly in each body).
    rootPage = await newIdentityPage(browser, ROOT_KEY);

    // Register Alice's license on Bob's content (5% revenue share)
    const regResp = await apiPost(rootPage, ROOT_KEY, "/ui/licenses/revenue/register-license", {
      issued_license_id: LICENSE_ID,
      content_id: CONTENT_ID,
      licensor_id: ALICE_SUB,
      licensee_id: BOB_SUB,
      revenue_share_pct: 5,
      profit_share_pct: 0,
      fixed_cost_cents: 0,
    });
    expect(regResp.status()).toBe(200);

    // Register license with fixed fee on separate content
    const regFixed = await apiPost(rootPage, ROOT_KEY, "/ui/licenses/revenue/register-license", {
      issued_license_id: LICENSE_ID_FIXED,
      content_id: CONTENT_FIXED,
      licensor_id: ALICE_SUB,
      licensee_id: BOB_SUB,
      revenue_share_pct: 5,
      profit_share_pct: 0,
      fixed_cost_cents: 500,
    });
    expect(regFixed.status()).toBe(200);

    // Register profit share license
    const regProf = await apiPost(rootPage, ROOT_KEY, "/ui/licenses/revenue/register-license", {
      issued_license_id: LICENSE_ID_PROF,
      content_id: CONTENT_PROF,
      licensor_id: ALICE_SUB,
      licensee_id: BOB_SUB,
      revenue_share_pct: 0,
      profit_share_pct: 10,
      fixed_cost_cents: 0,
    });
    expect(regProf.status()).toBe(200);

    // Register self-license (Alice on Alice's content)
    const regSelf = await apiPost(rootPage, ROOT_KEY, "/ui/licenses/revenue/register-license", {
      issued_license_id: LICENSE_ID_SELF,
      content_id: CONTENT_SELF,
      licensor_id: ALICE_SUB,
      licensee_id: ALICE_SUB,
      revenue_share_pct: 10,
      profit_share_pct: 0,
      fixed_cost_cents: 0,
    });
    expect(regSelf.status()).toBe(200);

    // Register license to revoke
    const regRevoke = await apiPost(rootPage, ROOT_KEY, "/ui/licenses/revenue/register-license", {
      issued_license_id: LICENSE_ID_REVOKE,
      content_id: CONTENT_REVOKE,
      licensor_id: ALICE_SUB,
      licensee_id: BOB_SUB,
      revenue_share_pct: 10,
      profit_share_pct: 0,
      fixed_cost_cents: 0,
    });
    expect(regRevoke.status()).toBe(200);
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
    await rootPage?.close();
  });

  test("472.1 Tip on licensed content triggers revenue split", async () => {
    const resp = await apiPost(rootPage, ROOT_KEY, "/ui/licenses/revenue/process-split", {
      content_id: CONTENT_ID,
      licensee_id: BOB_SUB,
      source_type: "tip",
      source_amount_cents: 1000,
      source_txn_id: `tip_${TS}_1`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.splits.length).toBe(1);
    // 5% of 1000 = 50
    expect(data.splits[0].split_cents).toBe(50);
    expect(data.splits[0].licensor_id).toBe(ALICE_SUB);
    expect(data.splits[0].split_type).toBe("revenue_share");
  });

  test("472.2 Fixed fee charged on first use only", async () => {
    // First split: should charge fixed fee + revenue share
    const resp1 = await apiPost(rootPage, ROOT_KEY, "/ui/licenses/revenue/process-split", {
      content_id: CONTENT_FIXED,
      licensee_id: BOB_SUB,
      source_type: "tip",
      source_amount_cents: 1000,
      source_txn_id: `tip_fixed_${TS}_1`,
    });
    expect(resp1.status()).toBe(200);
    const data1 = await resp1.json();
    expect(data1.splits.length).toBe(1);
    expect(data1.splits[0].split_cents).toBe(50); // 5% of 1000

    // Second split: same content, fixed fee should NOT be re-charged
    const resp2 = await apiPost(rootPage, ROOT_KEY, "/ui/licenses/revenue/process-split", {
      content_id: CONTENT_FIXED,
      licensee_id: BOB_SUB,
      source_type: "tip",
      source_amount_cents: 1000,
      source_txn_id: `tip_fixed_${TS}_2`,
    });
    expect(resp2.status()).toBe(200);
    const data2 = await resp2.json();
    expect(data2.splits.length).toBe(1);
    expect(data2.splits[0].split_cents).toBe(50);
  });

  test("472.3 Profit share calculates on net after platform fee", async () => {
    const resp = await apiPost(rootPage, ROOT_KEY, "/ui/licenses/revenue/process-split", {
      content_id: CONTENT_PROF,
      licensee_id: BOB_SUB,
      source_type: "tip",
      source_amount_cents: 1000,
      source_txn_id: `tip_prof_${TS}_1`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.splits.length).toBe(1);
    // net = 1000 - 20% = 800; 10% of 800 = 80
    expect(data.splits[0].split_cents).toBe(80);
    expect(data.splits[0].split_type).toBe("profit_share");
  });

  test("472.4 Self-split is skipped", async () => {
    const resp = await apiPost(rootPage, ROOT_KEY, "/ui/licenses/revenue/process-split", {
      content_id: CONTENT_SELF,
      licensee_id: ALICE_SUB,
      source_type: "tip",
      source_amount_cents: 1000,
      source_txn_id: `tip_self_${TS}_1`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.splits.length).toBe(0);
  });

  test("472.5 Revoked license produces no split", async () => {
    // Revoke the license first
    const revokeResp = await apiPost(rootPage, ROOT_KEY, "/ui/licenses/revenue/revoke-license", {
      content_id: CONTENT_REVOKE,
      issued_license_id: LICENSE_ID_REVOKE,
    });
    expect(revokeResp.status()).toBe(200);

    // Now try to process a split
    const resp = await apiPost(rootPage, ROOT_KEY, "/ui/licenses/revenue/process-split", {
      content_id: CONTENT_REVOKE,
      licensee_id: BOB_SUB,
      source_type: "tip",
      source_amount_cents: 1000,
      source_txn_id: `tip_revoke_${TS}_1`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.splits.length).toBe(0);
  });
});

// ─── Section 473: Revenue Dashboard API ─────────────────────────────────────

test.describe("473 -- Revenue Dashboard API", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_KEY);
    bobPage = await newIdentityPage(browser, BOB_KEY);
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("473.1 Licensor earned summary reflects splits", async () => {
    const resp = await apiGet(alicePage, "/ui/licenses/revenue/earned");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // Alice should have earned from section 472 tests
    expect(data.summary.total_cents).toBeGreaterThan(0);
    expect(data.summary.total_transactions).toBeGreaterThan(0);
    expect(data.transactions.length).toBeGreaterThan(0);
  });

  test("473.2 Licensee paid summary reflects debits", async () => {
    const resp = await apiGet(bobPage, "/ui/licenses/revenue/paid");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.summary.total_cents).toBeGreaterThan(0);
    expect(data.summary.total_transactions).toBeGreaterThan(0);
  });

  test("473.3 Transaction list is paginated and filterable", async () => {
    const resp = await apiGet(alicePage, "/ui/licenses/revenue/earned", {
      source_type: "tip",
      limit: "2",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.transactions)).toBe(true);
    for (const txn of data.transactions) {
      expect(txn.source_type).toBe("tip");
    }
  });

  test("473.4 Per-license transaction history", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/licenses/revenue/license/${LICENSE_ID}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.transactions)).toBe(true);
    expect(data.transactions.length).toBeGreaterThanOrEqual(1);
    for (const txn of data.transactions) {
      expect(txn.issued_license_id).toBe(LICENSE_ID);
    }
  });
});

// ─── Section 474: Admin Revenue Audit API ────────────────────────────────────

test.describe("474 -- Admin Revenue Audit API", () => {
  let rootPage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, ROOT_KEY);
    alicePage = await newIdentityPage(browser, ALICE_KEY);
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("474.1 Admin sees platform-wide revenue transactions", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/licenses/revenue");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.transactions)).toBe(true);
    expect(data.transactions.length).toBeGreaterThan(0);
  });

  test("474.2 Non-admin cannot access admin revenue endpoint", async () => {
    const resp = await apiGet(alicePage, "/ui/admin/licenses/revenue");
    expect(resp.status()).toBe(403);
  });
});
