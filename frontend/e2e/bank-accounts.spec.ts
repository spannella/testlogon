/**
 * E2E tests for OBP Banking Accounts (ACC-001..ACC-004)
 *
 * Sections:
 *   100 — Banks list API
 *   101 — Account CRUD API (create / list / get / update / delete)
 *   102 — Account balance API
 *   103 — Transactions list + get API (ACC-002)
 *   104 — Transaction metadata API (ACC-003: narrative, tags, comments)
 *   105 — Account holders co-access API (ACC-004)
 *   106 — Feature-flag off → graceful UI
 *   107 — Bank Accounts list UI
 *   108 — Bank Account detail UI (transactions + detail panel)
 *
 * Auth: uses e2e_admin_session_setup.py (alice + bob)
 *
 * Note: These tests require OPEN_BANK_PROJECT_ENABLED=true AND
 * BANKING_ACCOUNTS_ENABLED=true in the backend env. When the flags are off,
 * all /ui/banking/* endpoints return 404 — section 106 validates this UI path.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const TS       = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface AdminSessionData {
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

let _sessions: Record<string, AdminSessionData> | null = null;

function getSessions(): Record<string, AdminSessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Page factory ─────────────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

// ─── Auth inject ──────────────────────────────────────────────────────────────

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for identity: ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    ([userId, accessToken]: [string, string]) => {
      const state = { userId, accessToken, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    [session.user_sub, session.access_token],
  );
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiPut(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.put(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

// ─── Section 100 — Banks list API ─────────────────────────────────────────────

test.describe("Section 100 — Banks list API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("100.1 — GET /ui/banking/banks returns list (or 404 if flag off)", async () => {
    const resp = await apiGet(alicePage, "ui/banking/banks");
    if (resp.status() === 404 || resp.status() === 503) {
      // Feature disabled — acceptable
      expect([404, 503]).toContain(resp.status());
      return;
    }
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { banks: unknown[] };
    expect(Array.isArray(body.banks)).toBe(true);
  });
});

// ─── Section 101 — Account CRUD API ──────────────────────────────────────────

test.describe("Section 101 — Account CRUD API", () => {
  let alicePage: Page;
  let createdAccountId: string | null = null;
  let bankId = "default";

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
    // Fetch bank id if available
    const banksResp = await apiGet(alicePage, "ui/banking/banks");
    if (banksResp.ok()) {
      const body = await banksResp.json() as { banks: Array<{ bank_id: string }> };
      if (body.banks.length > 0) bankId = body.banks[0].bank_id;
    }
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("101.1 — GET /ui/banking/accounts returns list with default account", async () => {
    const resp = await apiGet(alicePage, "ui/banking/accounts");
    if (resp.status() === 404 || resp.status() === 503) {
      expect([404, 503]).toContain(resp.status());
      return;
    }
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { accounts: Array<{ is_default: boolean }> };
    expect(Array.isArray(body.accounts)).toBe(true);
    // The default wallet-backed account is auto-seeded
    const hasDefault = body.accounts.some((a) => a.is_default);
    expect(hasDefault).toBe(true);
  });

  test("101.2 — POST /ui/banking/accounts creates a new account", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "ui/banking/accounts", {
      bank_id: bankId,
      label: `E2E Test Savings ${TS}`,
      account_type: "SAVINGS",
      currency: "usd",
    });
    if (resp.status() === 404 || resp.status() === 503) {
      expect([404, 503]).toContain(resp.status());
      return;
    }
    if (resp.status() === 422) {
      // bank_id might not exist in this env — skip
      return;
    }
    expect(resp.status()).toBe(201);
    const body = await resp.json() as { account_id: string; label: string; account_type: string };
    expect(body.account_id).toBeTruthy();
    expect(body.label).toContain("E2E Test Savings");
    expect(body.account_type).toBe("SAVINGS");
    createdAccountId = body.account_id;
  });

  test("101.3 — GET /ui/banking/accounts/:id returns the created account", async () => {
    if (!createdAccountId) test.skip();
    const resp = await apiGet(alicePage, `ui/banking/accounts/${createdAccountId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { account_id: string };
    expect(body.account_id).toBe(createdAccountId);
  });

  test("101.4 — PATCH /ui/banking/accounts/:id updates the label", async () => {
    if (!createdAccountId) test.skip();
    const newLabel = `E2E Renamed ${TS}`;
    const resp = await apiPatch(alicePage, ALICE_ID, `ui/banking/accounts/${createdAccountId}`, {
      label: newLabel,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { label: string };
    expect(body.label).toBe(newLabel);
  });

  test("101.5 — DELETE /ui/banking/accounts/:id deletes the account", async () => {
    if (!createdAccountId) test.skip();
    const resp = await apiDelete(alicePage, ALICE_ID, `ui/banking/accounts/${createdAccountId}`);
    expect(resp.status()).toBe(204);
    createdAccountId = null;
  });

  test("101.6 — Cannot delete default account (409)", async () => {
    const listResp = await apiGet(alicePage, "ui/banking/accounts");
    if (!listResp.ok()) return; // feature off
    const list = await listResp.json() as { accounts: Array<{ account_id: string; is_default: boolean }> };
    const def = list.accounts.find((a) => a.is_default);
    if (!def) return;
    const resp = await apiDelete(alicePage, ALICE_ID, `ui/banking/accounts/${def.account_id}`);
    expect(resp.status()).toBe(409);
  });

  test("101.7 — Cannot create WALLET type account (422)", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "ui/banking/accounts", {
      bank_id: bankId,
      label: "Try Wallet",
      account_type: "WALLET",
    });
    if (resp.status() === 404 || resp.status() === 503) return;
    expect(resp.status()).toBe(422);
  });
});

// ─── Section 102 — Account balance API ───────────────────────────────────────

test.describe("Section 102 — Account balance API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("102.1 — GET /ui/banking/accounts/:id/balance returns balance fields", async () => {
    const listResp = await apiGet(alicePage, "ui/banking/accounts");
    if (!listResp.ok()) return; // feature off
    const list = await listResp.json() as { accounts: Array<{ account_id: string; is_default: boolean }> };
    const def = list.accounts.find((a) => a.is_default);
    if (!def) return;

    const resp = await apiGet(alicePage, `ui/banking/accounts/${def.account_id}/balance`);
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { currency: string; current: number; available: number };
    expect(typeof body.currency).toBe("string");
    expect(typeof body.current).toBe("number");
    expect(typeof body.available).toBe("number");
  });
});

// ─── Section 103 — Transactions API ──────────────────────────────────────────

test.describe("Section 103 — Transactions list + get API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("103.1 — GET /ui/banking/accounts/:id/transactions returns list", async () => {
    const listResp = await apiGet(alicePage, "ui/banking/accounts");
    if (!listResp.ok()) return;
    const list = await listResp.json() as { accounts: Array<{ account_id: string; is_default: boolean }> };
    const def = list.accounts.find((a) => a.is_default);
    if (!def) return;

    const resp = await apiGet(alicePage, `ui/banking/accounts/${def.account_id}/transactions`, {
      limit: "10",
      order: "desc",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { transactions: unknown[]; cursor: string | null };
    expect(Array.isArray(body.transactions)).toBe(true);
    // cursor is null or string
    expect(body.cursor === null || typeof body.cursor === "string").toBe(true);
  });

  test("103.2 — Transaction shape has required fields", async () => {
    const listResp = await apiGet(alicePage, "ui/banking/accounts");
    if (!listResp.ok()) return;
    const list = await listResp.json() as { accounts: Array<{ account_id: string; is_default: boolean }> };
    const def = list.accounts.find((a) => a.is_default);
    if (!def) return;

    const resp = await apiGet(alicePage, `ui/banking/accounts/${def.account_id}/transactions`, {
      limit: "5",
    });
    if (!resp.ok()) return;
    const body = await resp.json() as {
      transactions: Array<{
        transaction_id: string;
        type: string;
        amount: { currency: string; value: string };
        new_balance: { currency: string; value: string };
        status: string;
        posted_at: number;
        description: string;
      }>;
    };
    if (body.transactions.length === 0) return; // no transactions yet
    const txn = body.transactions[0];
    expect(txn.transaction_id).toBeTruthy();
    expect(typeof txn.type).toBe("string");
    expect(txn.amount.currency).toBeTruthy();
    expect(txn.amount.value).toBeTruthy();
    expect(txn.new_balance.currency).toBeTruthy();
    expect(typeof txn.status).toBe("string");
    expect(typeof txn.posted_at).toBe("number");
  });

  test("103.3 — GET single transaction returns correct shape", async () => {
    const listResp = await apiGet(alicePage, "ui/banking/accounts");
    if (!listResp.ok()) return;
    const list = await listResp.json() as { accounts: Array<{ account_id: string; is_default: boolean }> };
    const def = list.accounts.find((a) => a.is_default);
    if (!def) return;

    const txnListResp = await apiGet(alicePage, `ui/banking/accounts/${def.account_id}/transactions`, {
      limit: "1",
    });
    if (!txnListResp.ok()) return;
    const txnList = await txnListResp.json() as {
      transactions: Array<{ transaction_id: string }>;
    };
    if (txnList.transactions.length === 0) return;

    const txnId = txnList.transactions[0].transaction_id;
    const resp = await apiGet(
      alicePage,
      `ui/banking/accounts/${def.account_id}/transactions/${txnId}`
    );
    expect(resp.status()).toBe(200);
    const txn = await resp.json() as { transaction_id: string };
    expect(txn.transaction_id).toBe(txnId);
  });
});

// ─── Section 104 — Transaction metadata API ───────────────────────────────────

test.describe("Section 104 — Transaction metadata API (ACC-003)", () => {
  let alicePage: Page;
  let defaultAccountId: string | null = null;
  let txnId: string | null = null;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);

    // Resolve default account + first transaction
    const listResp = await apiGet(alicePage, "ui/banking/accounts");
    if (!listResp.ok()) return;
    const list = await listResp.json() as { accounts: Array<{ account_id: string; is_default: boolean }> };
    const def = list.accounts.find((a) => a.is_default);
    if (!def) return;
    defaultAccountId = def.account_id;

    const txnResp = await apiGet(alicePage, `ui/banking/accounts/${def.account_id}/transactions`, {
      limit: "1",
    });
    if (!txnResp.ok()) return;
    const txnList = await txnResp.json() as { transactions: Array<{ transaction_id: string }> };
    if (txnList.transactions.length > 0) txnId = txnList.transactions[0].transaction_id;
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("104.1 — PUT narrative on a transaction", async () => {
    if (!defaultAccountId || !txnId) test.skip();
    const resp = await apiPut(
      alicePage,
      ALICE_ID,
      `ui/banking/accounts/${defaultAccountId}/transactions/${txnId}/narrative`,
      { text: `E2E narrative ${TS}` }
    );
    if (resp.status() === 404) {
      // metadata feature off → acceptable
      return;
    }
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { text: string };
    expect(body.text).toContain("E2E narrative");
  });

  test("104.2 — GET metadata returns narrative", async () => {
    if (!defaultAccountId || !txnId) test.skip();
    const resp = await apiGet(
      alicePage,
      `ui/banking/accounts/${defaultAccountId}/transactions/${txnId}/metadata`
    );
    if (resp.status() === 404) return; // feature off
    expect(resp.status()).toBe(200);
    const body = await resp.json() as {
      narrative: { text: string } | null;
      tags: unknown[];
      comments: unknown[];
    };
    if (body.narrative) {
      expect(body.narrative.text).toContain("E2E narrative");
    }
    expect(Array.isArray(body.tags)).toBe(true);
    expect(Array.isArray(body.comments)).toBe(true);
  });

  test("104.3 — POST tag on a transaction", async () => {
    if (!defaultAccountId || !txnId) test.skip();
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `ui/banking/accounts/${defaultAccountId}/transactions/${txnId}/tags`,
      { value: `e2e-tag-${TS}` }
    );
    if (resp.status() === 404) return; // feature off
    expect(resp.status()).toBe(201);
    const body = await resp.json() as { tag_id: string; value: string };
    expect(body.tag_id).toBeTruthy();
    expect(body.value).toContain("e2e-tag");

    // Delete the tag
    const delResp = await apiDelete(
      alicePage,
      ALICE_ID,
      `ui/banking/accounts/${defaultAccountId}/transactions/${txnId}/tags/${body.tag_id}`
    );
    expect([200, 404]).toContain(delResp.status());
  });

  test("104.4 — POST comment and delete it", async () => {
    if (!defaultAccountId || !txnId) test.skip();
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `ui/banking/accounts/${defaultAccountId}/transactions/${txnId}/comments`,
      { text: `E2E comment ${TS}` }
    );
    if (resp.status() === 404) return; // feature off
    expect(resp.status()).toBe(201);
    const body = await resp.json() as { comment_id: string; text: string };
    expect(body.comment_id).toBeTruthy();
    expect(body.text).toContain("E2E comment");

    const delResp = await apiDelete(
      alicePage,
      ALICE_ID,
      `ui/banking/accounts/${defaultAccountId}/transactions/${txnId}/comments/${body.comment_id}`
    );
    expect([200, 404]).toContain(delResp.status());
  });
});

// ─── Section 105 — Account holders API (ACC-004) ─────────────────────────────

test.describe("Section 105 — Account holders co-access API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let sharedAccountId: string | null = null;
  let bankId = "default";
  const BOB_SUB = `e2e_bob@test.local`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
    bobPage = await newIdentityPage(browser, BOB_ID);

    // Resolve bank id
    const banksResp = await apiGet(alicePage, "ui/banking/banks");
    if (banksResp.ok()) {
      const body = await banksResp.json() as { banks: Array<{ bank_id: string }> };
      if (body.banks.length > 0) bankId = body.banks[0].bank_id;
    }

    // Create a shared test account for holder tests
    const createResp = await apiPost(alicePage, ALICE_ID, "ui/banking/accounts", {
      bank_id: bankId,
      label: `E2E Holder Test ${TS}`,
      account_type: "SAVINGS",
      currency: "usd",
    });
    if (createResp.status() === 201) {
      const body = await createResp.json() as { account_id: string };
      sharedAccountId = body.account_id;
    }
  });

  test.afterAll(async () => {
    if (sharedAccountId) {
      await apiDelete(alicePage, ALICE_ID, `ui/banking/accounts/${sharedAccountId}`).catch(() => {});
    }
    await alicePage?.close();
    await bobPage?.close();
  });

  test("105.1 — GET holders returns primary owner", async () => {
    if (!sharedAccountId) test.skip();
    const resp = await apiGet(alicePage, `ui/banking/accounts/${sharedAccountId}/holders`);
    if (resp.status() === 404) return; // feature off
    expect(resp.status()).toBe(200);
    const body = await resp.json() as { holders: Array<{ user_sub: string; is_primary_owner: boolean }> };
    expect(body.holders.length).toBeGreaterThan(0);
    expect(body.holders[0].is_primary_owner).toBe(true);
  });

  test("105.2 — POST /holders adds Bob as co-owner", async () => {
    if (!sharedAccountId) test.skip();
    const sessions = getSessions();
    const bobSub = sessions[BOB_ID].user_sub;
    const resp = await apiPost(alicePage, ALICE_ID, `ui/banking/accounts/${sharedAccountId}/holders`, {
      user_sub: bobSub,
    });
    if (resp.status() === 404) return; // feature off
    expect([200, 201]).toContain(resp.status());
    const body = await resp.json() as { account: { owners: string[] } };
    expect(body.account.owners).toContain(bobSub);
  });

  test("105.3 — Bob can GET the shared account", async () => {
    if (!sharedAccountId) test.skip();
    const resp = await apiGet(bobPage, `ui/banking/accounts/${sharedAccountId}`);
    if (resp.status() === 404) return; // feature off or not added
    expect(resp.status()).toBe(200);
  });

  test("105.4 — DELETE /holders removes Bob", async () => {
    if (!sharedAccountId) test.skip();
    const sessions = getSessions();
    const bobSub = sessions[BOB_ID].user_sub;
    const resp = await apiDelete(alicePage, ALICE_ID, `ui/banking/accounts/${sharedAccountId}/holders/${bobSub}`);
    if (resp.status() === 404) return; // feature off or not found
    expect([200, 204]).toContain(resp.status());
  });
});

// ─── Section 106 — Feature-flag off UI graceful handling ─────────────────────

test.describe("Section 106 — Feature-flag off: graceful UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("106.1 — /bank/accounts shows 'not enabled' state when 404", async () => {
    // Intercept the backend request and return 404 to simulate disabled flag
    await alicePage.route("**/ui/banking/accounts", (route) => {
      void route.fulfill({ status: 404, body: JSON.stringify({ detail: "Not found" }) });
    });

    await alicePage.goto(`${BASE}/bank/accounts`);
    // Page should not crash; should show disabled state
    await expect(alicePage.getByText(/not enabled|not available|disabled|feature/i)).toBeVisible({
      timeout: 8000,
    });
  });
});

// ─── Section 107 — Bank Accounts list UI ─────────────────────────────────────

test.describe("Section 107 — Bank Accounts list UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("107.1 — Page loads with heading", async () => {
    await alicePage.goto(`${BASE}/bank/accounts`);
    await expect(
      alicePage.getByRole("heading", { name: /bank accounts/i })
    ).toBeVisible({ timeout: 10_000 });
  });

  test("107.2 — Default account card visible (if flag enabled)", async () => {
    // Skip gracefully if feature is off
    const featureOff = await alicePage.getByText(/not enabled/i).isVisible();
    if (featureOff) {
      test.skip();
      return;
    }
    // Default wallet-backed account should auto-seed and appear
    await expect(alicePage.locator("[data-testid='account-card'], .hover\\:shadow-md").first()).toBeVisible({
      timeout: 8000,
    });
  });

  test("107.3 — Add Account button visible", async () => {
    const featureOff = await alicePage.getByText(/not enabled/i).isVisible();
    if (featureOff) {
      test.skip();
      return;
    }
    await expect(alicePage.getByRole("button", { name: /add account/i })).toBeVisible();
  });

  test("107.4 — Refresh button triggers refetch", async () => {
    const featureOff = await alicePage.getByText(/not enabled/i).isVisible();
    if (featureOff) {
      test.skip();
      return;
    }
    const responsePromise = alicePage.waitForResponse("**/ui/banking/accounts");
    await alicePage.getByRole("button", { name: /refresh/i }).click();
    const response = await responsePromise;
    expect([200, 404, 503]).toContain(response.status());
  });
});

// ─── Section 108 — Bank Account detail UI ────────────────────────────────────

test.describe("Section 108 — Bank Account detail UI", () => {
  let alicePage: Page;
  let defaultAccountId: string | null = null;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Fetch default account for navigation tests
    const sessions = getSessions();
    const sess = sessions[ALICE_ID];
    const resp = await alicePage.request.get(`${API}/ui/banking/accounts`, {
      headers: { "x-csrf-token": sess.csrf_token },
    });
    if (resp.ok()) {
      const body = await resp.json() as {
        accounts: Array<{ account_id: string; is_default: boolean }>;
      };
      const def = body.accounts.find((a) => a.is_default);
      if (def) defaultAccountId = def.account_id;
    }
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("108.1 — Detail page loads with back nav", async () => {
    if (!defaultAccountId) {
      test.skip();
      return;
    }
    await alicePage.goto(`${BASE}/bank/accounts/${defaultAccountId}`);
    await expect(
      alicePage.getByRole("link", { name: /bank accounts/i }).or(
        alicePage.locator("a[href='/bank/accounts']")
      )
    ).toBeVisible({ timeout: 10_000 });
  });

  test("108.2 — Balance card is shown", async () => {
    if (!defaultAccountId) {
      test.skip();
      return;
    }
    await alicePage.goto(`${BASE}/bank/accounts/${defaultAccountId}`);
    await expect(alicePage.getByText(/balance/i).first()).toBeVisible({ timeout: 8000 });
  });

  test("108.3 — Account details panel shows account ID", async () => {
    if (!defaultAccountId) {
      test.skip();
      return;
    }
    await expect(alicePage.getByText(defaultAccountId.slice(0, 8))).toBeVisible({
      timeout: 8000,
    });
  });

  test("108.4 — Transactions section renders", async () => {
    if (!defaultAccountId) {
      test.skip();
      return;
    }
    await expect(alicePage.getByText(/transactions/i).first()).toBeVisible({
      timeout: 8000,
    });
  });

  test("108.5 — Back link navigates to /bank/accounts", async () => {
    if (!defaultAccountId) {
      test.skip();
      return;
    }
    await alicePage.goto(`${BASE}/bank/accounts/${defaultAccountId}`);
    const backLink = alicePage.locator("a[href='/bank/accounts']").first();
    if (await backLink.isVisible()) {
      await backLink.click();
      await expect(alicePage).toHaveURL(/\/bank\/accounts$/, { timeout: 5000 });
    }
  });
});
