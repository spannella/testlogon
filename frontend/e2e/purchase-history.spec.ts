/**
 * Section 101: Purchase History — transaction CRUD + state machine
 * Section 102: Purchase History — cancel request/respond workflow
 *
 * Auth: Cookie sessions via e2e_admin_session_setup.py
 * Identities: alice (USER)
 */
import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const TS = Date.now();

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function newPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await page.context().addCookies(getSessions()[identity].cookies);
  return page;
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${BASE}${path}`, { params });
}

async function apiPost(page: Page, id: string, path: string, body?: unknown, headers?: Record<string, string>) {
  const s = getSessions()[id];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json", ...headers },
  });
}

async function apiPut(page: Page, id: string, path: string, body?: unknown) {
  const s = getSessions()[id];
  return page.request.put(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiDelete(page: Page, id: string, path: string) {
  const s = getSessions()[id];
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": s.csrf_token },
  });
}

// ─── 101. Purchase History — CRUD + State Machine ────────────────────────

test.describe.serial("101 — Purchase History: transaction CRUD + state machine", () => {
  let alicePage: Page;
  let txnId: string;
  const idemKey = `idem_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("101.1 Create transaction with idempotency key", async () => {
    const resp = await apiPost(alicePage, "alice", "/ui/purchase-history/transactions", {
      money: { amount: 29.99, currency: "USD" },
      merchant_id: `merchant_${TS}`,
      external_ref: `ref_${TS}`,
      description: `E2E test purchase ${TS}`,
    }, { "X-Idempotency-Key": idemKey });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.txn_id).toBeTruthy();
    expect(data.status).toBe("PENDING");
    expect(data.created_at).toBeGreaterThan(0);
    txnId = data.txn_id;
  });

  test("101.2 Idempotent replay returns same txn_id", async () => {
    const resp = await apiPost(alicePage, "alice", "/ui/purchase-history/transactions", {
      money: { amount: 29.99, currency: "USD" },
      merchant_id: `merchant_${TS}`,
    }, { "X-Idempotency-Key": idemKey });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.txn_id).toBe(txnId);
  });

  test("101.3 Missing idempotency key returns 400", async () => {
    const resp = await apiPost(alicePage, "alice", "/ui/purchase-history/transactions", {
      money: { amount: 10, currency: "USD" },
    });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail.code).toBe("idempotency_key_required");
  });

  test("101.4 List transactions returns seeded item", async () => {
    const resp = await apiGet(alicePage, "/ui/purchase-history/transactions", { limit: "100" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data).toBeInstanceOf(Array);
    const found = data.find((t: any) => t.txn_id === txnId);
    expect(found).toBeTruthy();
    expect(found.status).toBe("PENDING");
    expect(found.amount).toBeCloseTo(29.99, 1);
    expect(found.currency).toBe("USD");
    expect(found.merchant_id).toBe(`merchant_${TS}`);
  });

  test("101.5 List transactions with status filter", async () => {
    const resp = await apiGet(alicePage, "/ui/purchase-history/transactions", { status: "PENDING", limit: "100" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.find((t: any) => t.txn_id === txnId);
    expect(found).toBeTruthy();

    const respNone = await apiGet(alicePage, "/ui/purchase-history/transactions", { status: "COMPLETED", limit: "100" });
    expect(respNone.status()).toBe(200);
    const dataNone = await respNone.json();
    const notFound = dataNone.find((t: any) => t.txn_id === txnId);
    expect(notFound).toBeUndefined();
  });

  test("101.6 Get transaction detail", async () => {
    const resp = await apiGet(alicePage, `/ui/purchase-history/transactions/${txnId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.txn_id).toBe(txnId);
    expect(data.buyer_id).toBeTruthy();
    expect(data.version).toBeGreaterThanOrEqual(1);
    expect(data.description).toBe(`E2E test purchase ${TS}`);
  });

  test("101.7 Get non-existent transaction returns 404", async () => {
    const resp = await apiGet(alicePage, `/ui/purchase-history/transactions/nonexistent_${TS}`);
    expect(resp.status()).toBe(404);
  });

  test("101.8 Search transactions by description", async () => {
    const resp = await apiGet(alicePage, "/ui/purchase-history/transactions/search", { q: `e2e test purchase ${TS}` });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.find((t: any) => t.txn_id === txnId);
    expect(found).toBeTruthy();
  });

  test("101.9 Update shipping info", async () => {
    const resp = await apiPut(alicePage, "alice", `/ui/purchase-history/transactions/${txnId}/shipping`, {
      shipping: {
        carrier: "UPS",
        tracking_number: `TRACK_${TS}`,
      },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.shipping).toBeTruthy();
    expect(data.shipping.carrier).toBe("UPS");
    expect(data.shipping.tracking_number).toBe(`TRACK_${TS}`);
  });

  test("101.10 Mark transaction completed", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/purchase-history/transactions/${txnId}/complete`, {
      processor_ref: `proc_${TS}`,
      note: "Payment confirmed",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("COMPLETED");
    expect(data.completed_at).toBeGreaterThan(0);
  });

  test("101.11 Complete already-completed returns 409", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/purchase-history/transactions/${txnId}/complete`, {
      processor_ref: "dup",
    });
    expect(resp.status()).toBe(409);
  });

  test("101.12 Revert completed transaction", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/purchase-history/transactions/${txnId}/revert`, {
      reason: "Customer requested refund",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("REVERTED");
    expect(data.reverted_at).toBeGreaterThan(0);
  });

  test("101.13 Revert already-reverted returns 409", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/purchase-history/transactions/${txnId}/revert`, {
      reason: "duplicate",
    });
    expect(resp.status()).toBe(409);
  });

  test("101.14 List audit events for transaction", async () => {
    const resp = await apiGet(alicePage, `/ui/purchase-history/transactions/${txnId}/events`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.txn_id).toBe(txnId);
    expect(data.events).toBeInstanceOf(Array);
    expect(data.events.length).toBeGreaterThanOrEqual(1);
  });
});

// ─── 102. Purchase History — Cancel Workflow ─────────────────────────────

test.describe.serial("102 — Purchase History: cancel request/respond workflow", () => {
  let alicePage: Page;
  let txnId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
    // Create a fresh PENDING transaction for cancel tests
    const resp = await apiPost(alicePage, "alice", "/ui/purchase-history/transactions", {
      money: { amount: 49.00, currency: "EUR" },
      description: `Cancel test ${TS}`,
    }, { "X-Idempotency-Key": `cancel_idem_${TS}` });
    const data = await resp.json();
    txnId = data.txn_id;
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("102.1 Request cancellation", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/purchase-history/transactions/${txnId}/cancel/request`, {
      reason: "Changed my mind",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("CANCEL_REQUESTED");
    expect(data.cancel).toBeTruthy();
    expect(data.cancel.reason).toBe("Changed my mind");
    expect(data.cancel.status).toBe("OPEN");
  });

  test("102.2 Duplicate cancel request returns 409", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/purchase-history/transactions/${txnId}/cancel/request`, {
      reason: "duplicate",
    });
    expect(resp.status()).toBe(409);
  });

  test("102.3 Deny cancellation", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/purchase-history/transactions/${txnId}/cancel/respond`, {
      decision: "DENY",
      note: "Item already shipped",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("CANCEL_DENIED");
    expect(data.cancel.decision).toBe("DENY");
    expect(data.cancel.status).toBe("DENIED");
    expect(data.cancel.note).toBe("Item already shipped");
  });

  test("102.4 Complete after cancel denied succeeds", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/purchase-history/transactions/${txnId}/complete`, {
      processor_ref: `proc_cancel_${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("COMPLETED");
  });

  test("102.5 Cancel request on completed + approve = CANCELLED", async () => {
    const resp = await apiPost(alicePage, "alice", `/ui/purchase-history/transactions/${txnId}/cancel/request`, {
      reason: "Want a refund after completion",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("CANCEL_REQUESTED");

    const respApprove = await apiPost(alicePage, "alice", `/ui/purchase-history/transactions/${txnId}/cancel/respond`, {
      decision: "APPROVE",
      note: "Refund approved",
    });
    expect(respApprove.status()).toBe(200);
    const dataApprove = await respApprove.json();
    expect(dataApprove.status).toBe("CANCELLED");
    expect(dataApprove.cancel.decision).toBe("APPROVE");
  });

  test("102.6 Invalid cancel respond decision returns 400", async () => {
    // Create a new txn for this test
    const create = await apiPost(alicePage, "alice", "/ui/purchase-history/transactions", {
      money: { amount: 5, currency: "USD" },
    }, { "X-Idempotency-Key": `inv_decision_${TS}` });
    const newTxnId = (await create.json()).txn_id;

    await apiPost(alicePage, "alice", `/ui/purchase-history/transactions/${newTxnId}/cancel/request`, {
      reason: "test",
    });

    const resp = await apiPost(alicePage, "alice", `/ui/purchase-history/transactions/${newTxnId}/cancel/respond`, {
      decision: "INVALID",
    });
    expect(resp.status()).toBe(400);
  });

  test("102.7 Cancel respond when no active request returns 409", async () => {
    // Create a PENDING txn with no cancel request
    const create = await apiPost(alicePage, "alice", "/ui/purchase-history/transactions", {
      money: { amount: 1, currency: "USD" },
    }, { "X-Idempotency-Key": `no_cancel_${TS}` });
    const newTxnId = (await create.json()).txn_id;

    const resp = await apiPost(alicePage, "alice", `/ui/purchase-history/transactions/${newTxnId}/cancel/respond`, {
      decision: "APPROVE",
    });
    expect(resp.status()).toBe(409);
  });
});
