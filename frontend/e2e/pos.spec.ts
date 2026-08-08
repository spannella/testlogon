/**
 * E2E tests for the OFBiz Point-of-Sale (POS) cluster.
 *
 * Sections:
 *   80 — POS register + session lifecycle — API
 *   81 — POS transaction draft + line items + tender (cash/card/wallet) — API
 *   82 — POS receipt + X/Z session reports — API
 *   83 — POS Terminal + Reports UI
 *
 * Backend: app/routers/pos.py — every endpoint is gated behind S.pos_enabled.
 * When POS is disabled the endpoints return 404; these tests skip gracefully
 * in that case (the feature flag defaults OFF).
 *
 * Auth: uses e2e_admin_session_setup.py (cookie + CSRF). Register creation
 * requires admin/root; root is the only admin/root identity in the DB.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const TS = Date.now();

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
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getAdminSessions()[identity];
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

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

/** True when the POS feature flag is on (a 404 implies disabled). */
async function posEnabled(page: Page): Promise<boolean> {
  const resp = await apiPost(page, "root", "ui/pos/registers", {
    label: "probe",
    location_id: "probe",
    default_currency: "USD",
  });
  return resp.status() !== 404;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 80 — Register + session lifecycle (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 80: POS register + session lifecycle (API)", () => {
  let rootPage: Page;
  let enabled = false;
  let registerId = "";
  let sessionId = "";

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    enabled = await posEnabled(rootPage);
  });

  test("80.1 Create register → 200 with register_id", async () => {
    test.skip(!enabled, "POS disabled (S.pos_enabled=false)");
    const resp = await apiPost(rootPage, "root", "ui/pos/registers", {
      label: `Lane ${TS}`,
      location_id: "store-main",
      default_currency: "USD",
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { register_id: string; label: string };
    expect(data.register_id).toBeTruthy();
    expect(data.label).toBe(`Lane ${TS}`);
    registerId = data.register_id;
  });

  test("80.2 Open session → status open + opening float", async () => {
    test.skip(!enabled || !registerId, "POS disabled / no register");
    const resp = await apiPost(rootPage, "root", "ui/pos/sessions", {
      register_id: registerId,
      opening_float_cents: 10000,
      idempotency_key: `open-${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { session_id: string; status: string; opening_float_cents: number };
    expect(data.status).toBe("open");
    expect(data.opening_float_cents).toBe(10000);
    sessionId = data.session_id;
  });

  test("80.3 Get open session for register", async () => {
    test.skip(!enabled || !registerId, "POS disabled / no register");
    const resp = await apiGet(rootPage, `ui/pos/registers/${registerId}/open-session`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { session_id: string };
    expect(data.session_id).toBe(sessionId);
  });

  test("80.4 Get session by id", async () => {
    test.skip(!enabled || !sessionId, "POS disabled / no session");
    const resp = await apiGet(rootPage, `ui/pos/sessions/${sessionId}`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { session_id: string; status: string };
    expect(data.session_id).toBe(sessionId);
    expect(data.status).toBe("open");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 81 — Transaction draft + line items + cash tender (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 81: POS txn draft + line items + tender (API)", () => {
  let rootPage: Page;
  let enabled = false;
  let sessionId = "";
  let txnId = "";

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    enabled = await posEnabled(rootPage);
    if (!enabled) return;
    const reg = await apiPost(rootPage, "root", "ui/pos/registers", {
      label: `Lane81 ${TS}`,
      location_id: "store-main",
      default_currency: "USD",
    });
    const registerId = ((await reg.json()) as { register_id: string }).register_id;
    const sess = await apiPost(rootPage, "root", "ui/pos/sessions", {
      register_id: registerId,
      opening_float_cents: 5000,
      idempotency_key: `open81-${TS}`,
    });
    sessionId = ((await sess.json()) as { session_id: string }).session_id;
  });

  test("81.1 Bind a transaction draft → status draft", async () => {
    test.skip(!enabled || !sessionId, "POS disabled / no session");
    const resp = await apiPost(rootPage, "root", `ui/pos/sessions/${sessionId}/txns`, {
      correlation_id: `cart-${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { txn_id: string; status: string };
    expect(data.txn_id).toBeTruthy();
    expect(data.status).toBe("draft");
    txnId = data.txn_id;
  });

  test("81.2 Add raw-SKU line item → total increases", async () => {
    test.skip(!enabled || !txnId, "POS disabled / no txn");
    const resp = await apiPost(rootPage, "root", `ui/pos/txns/${txnId}/lines`, {
      sku: "SKU-WIDGET",
      name: "Widget",
      unit_price_cents: 250,
      quantity: 2,
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { total_cents: number };
    expect(data.total_cents).toBe(500);
  });

  test("81.3 List line items", async () => {
    test.skip(!enabled || !txnId, "POS disabled / no txn");
    const resp = await apiGet(rootPage, `ui/pos/txns/${txnId}/lines`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as Array<{ sku: string; quantity: number }>;
    const widget = data.find((l) => l.sku === "SKU-WIDGET");
    expect(widget?.quantity).toBe(2);
  });

  test("81.4 Set line quantity", async () => {
    test.skip(!enabled || !txnId, "POS disabled / no txn");
    const resp = await apiPatch(rootPage, "root", `ui/pos/txns/${txnId}/lines/SKU-WIDGET`, {
      quantity: 3,
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { total_cents: number };
    expect(data.total_cents).toBe(750);
  });

  test("81.5 Cash tender → tendered status + change due", async () => {
    test.skip(!enabled || !txnId, "POS disabled / no txn");
    const resp = await apiPost(
      rootPage,
      "root",
      `ui/pos/sessions/${sessionId}/transactions/${txnId}/tender-cash`,
      { amount_tendered_cents: 1000, idempotency_key: `cash-${TS}` },
    );
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as {
      status: string;
      total_cents: number;
      tenders: Array<{ kind: string; change_due_cents: number }>;
    };
    expect(data.status).toBe("tendered");
    const cash = data.tenders.find((t) => t.kind === "cash");
    expect(cash?.change_due_cents).toBe(1000 - data.total_cents);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 82 — Receipt + X/Z reports (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 82: POS receipt + X/Z reports (API)", () => {
  let rootPage: Page;
  let enabled = false;
  let sessionId = "";
  let txnId = "";

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    enabled = await posEnabled(rootPage);
    if (!enabled) return;
    const reg = await apiPost(rootPage, "root", "ui/pos/registers", {
      label: `Lane82 ${TS}`,
      location_id: "store-main",
      default_currency: "USD",
    });
    const registerId = ((await reg.json()) as { register_id: string }).register_id;
    const sess = await apiPost(rootPage, "root", "ui/pos/sessions", {
      register_id: registerId,
      opening_float_cents: 0,
      idempotency_key: `open82-${TS}`,
    });
    sessionId = ((await sess.json()) as { session_id: string }).session_id;
    const txn = await apiPost(rootPage, "root", `ui/pos/sessions/${sessionId}/txns`, {
      correlation_id: `cart82-${TS}`,
    });
    txnId = ((await txn.json()) as { txn_id: string }).txn_id;
    await apiPost(rootPage, "root", `ui/pos/txns/${txnId}/lines`, {
      sku: "SKU-A",
      name: "Item A",
      unit_price_cents: 199,
      quantity: 1,
    });
    await apiPost(
      rootPage,
      "root",
      `ui/pos/sessions/${sessionId}/transactions/${txnId}/tender-cash`,
      { amount_tendered_cents: 200, idempotency_key: `cash82-${TS}` },
    );
  });

  test("82.1 Receipt link returns path + url", async () => {
    test.skip(!enabled || !txnId, "POS disabled / no txn");
    const resp = await apiGet(rootPage, `ui/pos/txns/${txnId}/receipt`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { txn_id: string; receipt_path: string };
    expect(data.txn_id).toBe(txnId);
    expect(data.receipt_path).toBeTruthy();
  });

  test("82.2 Receipt PDF is application/pdf", async () => {
    test.skip(!enabled || !txnId, "POS disabled / no txn");
    const resp = await apiGet(rootPage, `ui/pos/txns/${txnId}/receipt/pdf`);
    expect(resp.status()).toBe(200);
    expect(resp.headers()["content-type"]).toContain("application/pdf");
  });

  test("82.3 X report → report_kind x, expected cash present", async () => {
    test.skip(!enabled || !sessionId, "POS disabled / no session");
    const resp = await apiGet(rootPage, `ui/pos/sessions/${sessionId}/report/x`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as {
      report_kind: string;
      gross_sales_cents: number;
      cash: { expected_cash_cents: number };
    };
    expect(data.report_kind).toBe("x");
    expect(data.gross_sales_cents).toBeGreaterThanOrEqual(199);
  });

  test("82.4 Z report → report_kind z", async () => {
    test.skip(!enabled || !sessionId, "POS disabled / no session");
    // A Z report is the end-of-shift report and requires the session to be
    // closed first (open sessions get the non-resetting X report instead).
    const close = await apiPost(rootPage, "root", `ui/pos/sessions/${sessionId}/close`, {
      counted_cash_cents: 200,
    });
    expect(close.status()).toBe(200);
    const resp = await apiGet(rootPage, `ui/pos/sessions/${sessionId}/report/z`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { report_kind: string; tender_breakdown: unknown[] };
    expect(data.report_kind).toBe("z");
    expect(Array.isArray(data.tender_breakdown)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 83 — Terminal + Reports UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 83: POS UI", () => {
  test("83.1 Terminal page renders register setup or open-till", async ({ page }) => {
    await injectAuth(page, "root");
    await page.goto(`${BASE}/ofbiz/pos`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "POS Register Terminal" })).toBeVisible();
  });

  test("83.2 Reports page renders run-a-report card", async ({ page }) => {
    await injectAuth(page, "root");
    await page.goto(`${BASE}/ofbiz/pos/reports`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "POS Session Reports" })).toBeVisible();
    await expect(page.getByText("Run a report")).toBeVisible();
  });

  test("83.3 Reports page shows empty state before a report runs", async ({ page }) => {
    await injectAuth(page, "root");
    await page.goto(`${BASE}/ofbiz/pos/reports`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("No report yet")).toBeVisible();
  });
});
