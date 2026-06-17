/**
 * E2E tests for the Commercial Checkout and File Bundle endpoints.
 *
 * Sections:
 *   98 — Commercial Checkout API (7 tests)
 *
 * Auth: Cookie-based session for Alice (e2e_alice@test.local) with CSRF.
 *
 * Endpoints under test:
 *   POST /ui/catalog/file-bundles       — create a file bundle SKU
 *   POST /ui/catalog/api-packages       — create an API package SKU
 *   POST /ui/checkout/session            — create a unified checkout session
 *   POST /ui/checkout/session/file-bundle — create a file bundle checkout session
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// --- Constants ----------------------------------------------------------------

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

// --- Session bootstrap -------------------------------------------------------

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
      "python3 " + REPO_ROOT + "/e2e_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// --- Auth helpers -------------------------------------------------------------

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
}

// --- API helpers --------------------------------------------------------------

async function apiPost(page: Page, path: string, body?: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// --- Section 98: Commercial Checkout API -------------------------------------

test.describe.serial("98 — Commercial Checkout API", () => {
  let page: Page;

  const FILE_BUNDLE_SKU = `fb_e2e_${TS}`;
  const API_PACKAGE_SKU = `ap_e2e_${TS}`;

  // Date range for the file bundle (well into the future)
  const DATE_START = "2027-01-01T00:00:00Z";
  const DATE_END = "2027-12-31T23:59:59Z";

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("98.1 — Create a file bundle SKU", async () => {
    const resp = await apiPost(page, "/ui/catalog/file-bundles", {
      sku: FILE_BUNDLE_SKU,
      display_name: `E2E File Bundle ${TS}`,
      amount_cents: 2500,
      currency: "USD",
      date_start: DATE_START,
      date_end: DATE_END,
      access_mode: "purchase",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.sku).toBe(FILE_BUNDLE_SKU);
    expect(data.display_name).toBe(`E2E File Bundle ${TS}`);
    expect(data.amount_cents).toBe(2500);
    expect(data.currency).toBe("USD");
    expect(data.product_type).toBe("file_bundle");
    expect(data.billing_model).toBe("one_time");
    expect(data.access_mode).toBe("purchase");
    expect(data.created_by).toBeTruthy();
    expect(data.created_at).toBeTruthy();
  });

  test("98.2 — Create an API package SKU", async () => {
    const resp = await apiPost(page, "/ui/catalog/api-packages", {
      sku: API_PACKAGE_SKU,
      display_name: `E2E API Package ${TS}`,
      amount_cents: 9900,
      currency: "USD",
      billing_model: "credit_pack",
      effective_at: "2027-01-01T00:00:00Z",
      credit_grant: { credits: 1000, bucket: "general" },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.sku).toBe(API_PACKAGE_SKU);
    expect(data.product_type).toBe("api_package");
    expect(data.display_name).toBe(`E2E API Package ${TS}`);
    expect(data.amount_cents).toBe(9900);
    expect(data.currency).toBe("USD");
    expect(data.billing_model).toBe("credit_pack");
    expect(data.effective_at).toBeTruthy();
    expect(data.credit_grant).toEqual({ credits: 1000, bucket: "general" });
  });

  test("98.3 — Create a unified checkout session (direct source)", async () => {
    const resp = await apiPost(page, "/ui/checkout/session", {
      source: "direct",
      sku: FILE_BUNDLE_SKU,
      product_type: "file_bundle",
      billing_model: "one_time",
      quantity: 1,
      scope: { selection_type: "date_range", date_start: DATE_START, date_end: DATE_END },
      pricing_ref: { currency: "USD", amount_cents: 2500 },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.order_id).toBeTruthy();
    expect(data.checkout_session_id).toMatch(/^chk_/);
    expect(data.source).toBe("direct");
    expect(data.status).toBe("pending_payment");
    expect(Array.isArray(data.line_items)).toBe(true);
    expect(data.line_items.length).toBeGreaterThanOrEqual(1);
  });

  test("98.4 — Create a file bundle checkout session", async () => {
    const resp = await apiPost(page, "/ui/checkout/session/file-bundle", {
      sku: FILE_BUNDLE_SKU,
      date_start: DATE_START,
      date_end: DATE_END,
      access_mode: "purchase",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.checkout_session_id).toMatch(/^chk_/);
    expect(data.order_id).toBeTruthy();
    expect(data.status).toBe("pending_payment");
    expect(data.sku).toBe(FILE_BUNDLE_SKU);
    expect(data.amount_cents).toBe(2500);
    expect(data.currency).toBe("USD");
    expect(data.access_mode).toBe("purchase");
  });

  test("98.5 — File bundle SKU creation with missing required fields returns 422", async () => {
    // Missing sku and display_name (required fields)
    const resp = await apiPost(page, "/ui/catalog/file-bundles", {
      amount_cents: 1000,
      date_start: DATE_START,
      date_end: DATE_END,
    });
    expect(resp.status()).toBe(422);
  });

  test("98.6 — File bundle checkout with mismatched access_mode returns 400", async () => {
    // The SKU was created with access_mode "purchase" but we request "rental"
    const resp = await apiPost(page, "/ui/checkout/session/file-bundle", {
      sku: FILE_BUNDLE_SKU,
      date_start: DATE_START,
      date_end: DATE_END,
      access_mode: "rental",
    });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail).toContain("access_mode");
  });

  test("98.7 — Unified checkout session with missing direct fields returns 400", async () => {
    // "direct" source requires sku, product_type, and billing_model
    const resp = await apiPost(page, "/ui/checkout/session", {
      source: "direct",
      quantity: 1,
    });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail).toBeTruthy();
  });
});
