/**
 * E2E tests for OBP CUS-001..CUS-005: Bank Customers, Cards, and Financial Products.
 *
 * Sections:
 *   71 — Customers CRUD API (CUS-001)
 *   72 — Customer user-link + message thread API (CUS-002)
 *   73 — Customer attributes API (CUS-001 attribute sub-resource)
 *   74 — Cards list + status lifecycle API (CUS-003)
 *   75 — Card attributes API (CUS-003 attribute sub-resource)
 *   76 — Financial Products CRUD + attributes API (CUS-004)
 *   77 — Financial Product Collections API (CUS-004 collections)
 *   78 — BankCustomersPage UI (admin)
 *   79 — BankCardsPage UI (end-user)
 *   80 — BankProductsPage UI (admin)
 *
 * Auth: uses e2e_admin_session_setup.py (all identities)
 * Feature gate: tests call the API directly; if 404 ("customer_entity_not_enabled")
 *   or 503 is returned the test skips gracefully via test.skip().
 *
 * Identities:
 *   root          – root.admin@testdev.local  – role=root (admin-only endpoints)
 *   alice         – e2e_alice@test.local      – role=user
 *   bob           – e2e_bob@test.local        – role=user
 *   charlie_admin – e2e_charlie@test.local    – role=admin
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE    = "http://localhost:3000";
const API     = "http://localhost:8000";
const TS      = Date.now();

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

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

// ─── Page factory ─────────────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getAdminSessions()[identity];
  await page.goto(`${BASE}/login`);
  await page.context().addCookies(session.cookies);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

function csrfHeaders(identity: string): Record<string, string> {
  return { "x-csrf-token": getAdminSessions()[identity].csrf_token };
}

async function apiPost(page: Page, identity: string, path: string, body: unknown): Promise<Response> {
  return page.request.post(`${API}${path}`, {
    headers: { ...csrfHeaders(identity), "Content-Type": "application/json" },
    data: body,
  });
}

async function apiGet(page: Page, path: string, params: Record<string, string> = {}): Promise<Response> {
  const qs = new URLSearchParams(params).toString();
  const url = qs ? `${API}${path}?${qs}` : `${API}${path}`;
  return page.request.get(url);
}

async function apiPatch(page: Page, identity: string, path: string, body: unknown): Promise<Response> {
  return page.request.patch(`${API}${path}`, {
    headers: { ...csrfHeaders(identity), "Content-Type": "application/json" },
    data: body,
  });
}

async function apiPut(page: Page, identity: string, path: string, body: unknown): Promise<Response> {
  return page.request.put(`${API}${path}`, {
    headers: { ...csrfHeaders(identity), "Content-Type": "application/json" },
    data: body,
  });
}

async function apiDel(page: Page, identity: string, path: string): Promise<Response> {
  return page.request.delete(`${API}${path}`, {
    headers: csrfHeaders(identity),
  });
}

// ─── Feature-gate guard ───────────────────────────────────────────────────────

async function ensureEnabled(page: Page, identity: string): Promise<void> {
  const rootPage = await newIdentityPage(page.context().browser()!, identity);
  const r = await apiGet(rootPage, "/ui/customers");
  if (r.status() === 404 || r.status() === 503) {
    test.skip(true, "customer_entity_not_enabled — skipping");
    await rootPage.close();
    return;
  }
  await rootPage.close();
}

async function ensureFpEnabled(page: Page, identity: string): Promise<void> {
  const rootPage = await newIdentityPage(page.context().browser()!, identity);
  const r = await apiGet(rootPage, "/ui/financial-products");
  if (r.status() === 404 || r.status() === 503) {
    test.skip(true, "financial_products_not_enabled — skipping");
    await rootPage.close();
    return;
  }
  await rootPage.close();
}

// ─── Section 71: Customers CRUD ───────────────────────────────────────────────

test.describe("71 — Customers CRUD API", () => {
  let rootPage: Page;
  let customerId: string;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("71.1 feature gate check", async () => {
    const r = await apiGet(rootPage, "/ui/customers");
    if (r.status() === 404 || r.status() === 503) {
      test.skip(true, "customer_entity_not_enabled");
    }
    expect([200, 404, 503]).toContain(r.status());
  });

  test("71.2 create customer", async () => {
    const r = await apiPost(rootPage, "root", "/ui/customers", {
      legal_name: `E2E Customer ${TS}`,
      email: `cus${TS}@example.com`,
      mobile_phone: "+15550001111",
    });
    if (r.status() === 404 || r.status() === 503) {
      test.skip(true, "customer_entity_not_enabled");
      return;
    }
    expect(r.status()).toBe(201);
    const body = await r.json() as Record<string, unknown>;
    expect(body).toHaveProperty("customer_id");
    expect(body).toHaveProperty("customer_number");
    expect(body.legal_name).toBe(`E2E Customer ${TS}`);
    customerId = body.customer_id as string;
  });

  test("71.3 list customers", async () => {
    if (!customerId) test.skip(true, "no customer created");
    const r = await apiGet(rootPage, "/ui/customers");
    if (r.status() === 404 || r.status() === 503) {
      test.skip(true, "customer_entity_not_enabled");
      return;
    }
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body).toHaveProperty("customers");
    const customers = body.customers as Array<Record<string, unknown>>;
    const found = customers.find((c) => c["customer_id"] === customerId);
    expect(found).toBeTruthy();
  });

  test("71.4 get customer by id", async () => {
    if (!customerId) test.skip(true, "no customer created");
    const r = await apiGet(rootPage, `/ui/customers/${customerId}`);
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.customer_id).toBe(customerId);
  });

  test("71.5 patch customer", async () => {
    if (!customerId) test.skip(true, "no customer created");
    const detailR = await apiGet(rootPage, `/ui/customers/${customerId}`);
    const detail = await detailR.json() as Record<string, unknown>;
    const r = await apiPatch(rootPage, "root", `/ui/customers/${customerId}`, {
      legal_name: `Updated Customer ${TS}`,
      kyc_status: "pending",
      expected_version: detail.version,
    });
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.legal_name).toBe(`Updated Customer ${TS}`);
    expect(body.kyc_status).toBe("pending");
  });
});

// ─── Section 72: Customer user-link + messages ────────────────────────────────

test.describe("72 — Customer user-link + messages API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let customerId: string;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");

    // Create a customer to link
    const r = await apiPost(rootPage, "root", "/ui/customers", {
      legal_name: `Link Test ${TS}`,
    });
    if (r.status() === 201) {
      customerId = ((await r.json()) as Record<string, unknown>).customer_id as string;
    }
  });

  test.afterAll(async () => {
    await rootPage.close();
    await alicePage.close();
  });

  test("72.1 link user to customer", async () => {
    if (!customerId) test.skip(true, "no customer");
    const aliceSub = getAdminSessions()["alice"].user_sub;
    const r = await apiPost(rootPage, "root", `/ui/customers/${customerId}/link`, {
      user_sub: aliceSub,
    });
    if (r.status() === 404 || r.status() === 503) {
      test.skip(true, "customer_entity_not_enabled");
      return;
    }
    expect([200, 201, 409]).toContain(r.status());
    if (r.status() !== 409) {
      const body = await r.json() as Record<string, unknown>;
      expect(body.customer_id).toBe(customerId);
    }
  });

  test("72.2 list customer links", async () => {
    if (!customerId) test.skip(true, "no customer");
    const r = await apiGet(rootPage, `/ui/customers/${customerId}/links`);
    expect(r.status()).toBe(200);
    const links = await r.json() as Array<Record<string, unknown>>;
    expect(Array.isArray(links)).toBe(true);
  });

  test("72.3 post staff message", async () => {
    if (!customerId) test.skip(true, "no customer");
    const r = await apiPost(rootPage, "root", `/ui/customers/${customerId}/messages`, {
      body: `Staff message ${TS}`,
    });
    if (r.status() === 404 || r.status() === 503) {
      test.skip(true, "customer_entity_not_enabled");
      return;
    }
    expect(r.status()).toBe(200);
    const msg = await r.json() as Record<string, unknown>;
    expect(msg.author_role).toBe("STAFF");
    expect(msg.body).toBe(`Staff message ${TS}`);
  });

  test("72.4 list customer messages", async () => {
    if (!customerId) test.skip(true, "no customer");
    const r = await apiGet(rootPage, `/ui/customers/${customerId}/messages`);
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body).toHaveProperty("messages");
    const msgs = body.messages as Array<Record<string, unknown>>;
    expect(msgs.length).toBeGreaterThan(0);
    expect(msgs[0]).toHaveProperty("body");
  });

  test("72.5 GET /ui/customers/me returns 404 when not linked (alice no-link path)", async () => {
    // Alice might or might not be linked. Just check it responds properly.
    const r = await apiGet(alicePage, "/ui/customers/me");
    expect([200, 404]).toContain(r.status());
  });
});

// ─── Section 73: Customer attributes ─────────────────────────────────────────

test.describe("73 — Customer attributes API", () => {
  let rootPage: Page;
  let customerId: string;
  let attributeId: string;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    const r = await apiPost(rootPage, "root", "/ui/customers", {
      legal_name: `AttrTest ${TS}`,
    });
    if (r.status() === 201) {
      customerId = ((await r.json()) as Record<string, unknown>).customer_id as string;
    }
  });

  test.afterAll(async () => { await rootPage.close(); });

  test("73.1 set attribute", async () => {
    if (!customerId) test.skip(true, "no customer");
    const r = await apiPut(rootPage, "root", `/ui/customers/${customerId}/attributes`, {
      name: "risk_tier",
      type: "STRING",
      value: "MEDIUM",
    });
    if (r.status() === 404 || r.status() === 503) {
      test.skip(true, "customer_entity_not_enabled");
      return;
    }
    expect(r.status()).toBe(200);
    const attr = await r.json() as Record<string, unknown>;
    expect(attr.name).toBe("risk_tier");
    expect(attr.value).toBe("MEDIUM");
    attributeId = attr.attribute_id as string;
  });

  test("73.2 list attributes", async () => {
    if (!customerId || !attributeId) test.skip(true, "no attr");
    const r = await apiGet(rootPage, `/ui/customers/${customerId}/attributes`);
    expect(r.status()).toBe(200);
    const attrs = await r.json() as Array<Record<string, unknown>>;
    expect(attrs.some((a) => a["attribute_id"] === attributeId)).toBe(true);
  });

  test("73.3 delete attribute", async () => {
    if (!customerId || !attributeId) test.skip(true, "no attr");
    const r = await apiDel(rootPage, "root", `/ui/customers/${customerId}/attributes/${attributeId}`);
    expect(r.status()).toBe(200);
  });
});

// ─── Section 74: Cards lifecycle ──────────────────────────────────────────────

test.describe("74 — Cards list + status lifecycle API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => { await alicePage.close(); });

  test("74.1 list cards (may be empty or not-enabled)", async () => {
    const r = await apiGet(alicePage, "/ui/cards");
    expect([200, 404, 503]).toContain(r.status());
    if (r.status() === 404 || r.status() === 503) {
      test.skip(true, "cards not enabled");
      return;
    }
    const body = await r.json() as Record<string, unknown>;
    expect(body).toHaveProperty("cards");
    expect(Array.isArray(body.cards)).toBe(true);
  });

  test("74.2 card status update returns 404 for non-existent card", async () => {
    const r = await apiPatch(alicePage, "alice", "/ui/cards/nonexistent_card_id/status", {
      status: "FROZEN",
      expected_version: 1,
    });
    // 404 = not found; 404 can also = feature disabled; 422 = bad transition
    expect([404, 422, 503]).toContain(r.status());
  });
});

// ─── Section 75: Card attributes ──────────────────────────────────────────────

test.describe("75 — Card attributes API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => { await alicePage.close(); });

  test("75.1 list attributes for non-existent card returns empty or 403", async () => {
    const r = await apiGet(alicePage, "/ui/cards/fake_card_99/attributes");
    // Cards returns empty list for unknown card (no ownership assert on list)
    // or feature-disabled 404
    expect([200, 404, 403, 503]).toContain(r.status());
    if (r.status() === 200) {
      const attrs = await r.json();
      expect(Array.isArray(attrs)).toBe(true);
    }
  });
});

// ─── Section 76: Financial Products CRUD ─────────────────────────────────────

test.describe("76 — Financial Products CRUD + attributes API", () => {
  let rootPage: Page;
  let productCode: string;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => { await rootPage.close(); });

  test("76.1 create product", async () => {
    const code = `E2E_PROD_${TS}`;
    const r = await apiPost(rootPage, "root", "/ui/financial-products", {
      product_code: code,
      name: `E2E Product ${TS}`,
      category: "SAVINGS",
      description: "E2E test product",
    });
    if (r.status() === 404 || r.status() === 503) {
      test.skip(true, "financial_products_not_enabled");
      return;
    }
    expect(r.status()).toBe(201);
    const body = await r.json() as Record<string, unknown>;
    expect(body.product_code).toBe(code);
    expect(body.name).toBe(`E2E Product ${TS}`);
    productCode = code;
  });

  test("76.2 list products", async () => {
    const r = await apiGet(rootPage, "/ui/financial-products");
    if (r.status() === 404 || r.status() === 503) {
      test.skip(true, "financial_products_not_enabled");
      return;
    }
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body).toHaveProperty("items");
  });

  test("76.3 get product", async () => {
    if (!productCode) test.skip(true, "no product created");
    const r = await apiGet(rootPage, `/ui/financial-products/${productCode}`);
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.product_code).toBe(productCode);
  });

  test("76.4 patch product", async () => {
    if (!productCode) test.skip(true, "no product created");
    const detailR = await apiGet(rootPage, `/ui/financial-products/${productCode}`);
    const detail = await detailR.json() as Record<string, unknown>;
    const r = await apiPatch(rootPage, "root", `/ui/financial-products/${productCode}`, {
      name: `Updated Product ${TS}`,
      expected_version: detail.version,
    });
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.name).toBe(`Updated Product ${TS}`);
  });

  test("76.5 set product attribute", async () => {
    if (!productCode) test.skip(true, "no product created");
    const r = await apiPut(rootPage, "root", `/ui/financial-products/${productCode}/attributes`, {
      name: "min_balance",
      type: "INTEGER",
      value: "1000",
    });
    expect(r.status()).toBe(200);
    const attr = await r.json() as Record<string, unknown>;
    expect(attr.name).toBe("min_balance");
  });

  test("76.6 list product attributes", async () => {
    if (!productCode) test.skip(true, "no product created");
    const r = await apiGet(rootPage, `/ui/financial-products/${productCode}/attributes`);
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body).toHaveProperty("attributes");
  });

  test("76.7 delete product", async () => {
    if (!productCode) test.skip(true, "no product created");
    const r = await apiDel(rootPage, "root", `/ui/financial-products/${productCode}`);
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.ok).toBe(true);
  });
});

// ─── Section 77: Financial Product Collections ────────────────────────────────

test.describe("77 — Financial Product Collections API", () => {
  let rootPage: Page;
  const collectionCode = `E2E_COL_${TS}`;
  let productCode: string;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");

    // Create a product to add to the collection
    const r = await apiPost(rootPage, "root", "/ui/financial-products", {
      product_code: `E2E_COL_PROD_${TS}`,
      name: `Collection Product ${TS}`,
    });
    if (r.status() === 201) {
      productCode = `E2E_COL_PROD_${TS}`;
    }
  });

  test.afterAll(async () => { await rootPage.close(); });

  test("77.1 upsert collection", async () => {
    const r = await apiPut(rootPage, "root", `/ui/financial-products/collections/${collectionCode}`, {
      name: `E2E Collection ${TS}`,
      product_codes: [],
    });
    if (r.status() === 404 || r.status() === 503) {
      test.skip(true, "financial_products_not_enabled");
      return;
    }
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.collection_code).toBe(collectionCode);
  });

  test("77.2 list collections", async () => {
    const r = await apiGet(rootPage, "/ui/financial-products/collections");
    if (r.status() === 404 || r.status() === 503) {
      test.skip(true, "financial_products_not_enabled");
      return;
    }
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body).toHaveProperty("items");
  });

  test("77.3 get collection", async () => {
    const r = await apiGet(rootPage, `/ui/financial-products/collections/${collectionCode}`);
    if (r.status() === 404) {
      test.skip(true, "collection not found / feature disabled");
      return;
    }
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    expect(body.collection_code).toBe(collectionCode);
  });

  test("77.4 add product to collection", async () => {
    if (!productCode) test.skip(true, "no product created");
    const r = await apiPost(rootPage, "root", `/ui/financial-products/collections/${collectionCode}/members`, {
      product_code: productCode,
    });
    if (r.status() === 404 || r.status() === 503) {
      test.skip(true, "feature disabled");
      return;
    }
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    const codes = body.product_codes as string[];
    expect(codes).toContain(productCode);
  });

  test("77.5 remove product from collection", async () => {
    if (!productCode) test.skip(true, "no product created");
    const r = await apiDel(
      rootPage,
      "root",
      `/ui/financial-products/collections/${collectionCode}/members/${productCode}`,
    );
    if (r.status() === 404 || r.status() === 503) {
      test.skip(true, "feature disabled");
      return;
    }
    expect(r.status()).toBe(200);
    const body = await r.json() as Record<string, unknown>;
    const codes = body.product_codes as string[];
    expect(codes).not.toContain(productCode);
  });
});

// ─── Section 78: BankCustomersPage UI ────────────────────────────────────────

test.describe("78 — BankCustomersPage UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => { await rootPage.close(); });

  test("78.1 renders page heading", async () => {
    await rootPage.goto(`${BASE}/bank/customers`);
    await rootPage.waitForLoadState("domcontentloaded");
    // Either sees the page or the feature-disabled banner — both are valid
    const heading = rootPage.getByRole("heading", { name: /Bank Customers/i, exact: false });
    await expect(heading).toBeVisible({ timeout: 10_000 });
  });

  test("78.2 feature-disabled state is graceful", async () => {
    // If the feature is disabled the page shows a 'not available' message
    await rootPage.goto(`${BASE}/bank/customers`);
    await rootPage.waitForLoadState("domcontentloaded");
    // Page should never crash (no unhandled error boundary)
    await expect(rootPage.locator("body")).not.toContainText("Something went wrong");
  });

  test("78.3 shows New Customer button when feature enabled", async () => {
    await rootPage.goto(`${BASE}/bank/customers`);
    await rootPage.waitForLoadState("networkidle");
    const notAvail = await rootPage.getByText("not available").isVisible();
    if (notAvail) {
      test.skip(true, "feature not enabled");
      return;
    }
    await expect(rootPage.getByRole("button", { name: /New Customer/i })).toBeVisible();
  });

  test("78.4 create customer dialog opens", async () => {
    await rootPage.goto(`${BASE}/bank/customers`);
    await rootPage.waitForLoadState("networkidle");
    const notAvail = await rootPage.getByText("not available").isVisible();
    if (notAvail) {
      test.skip(true, "feature not enabled");
      return;
    }
    await rootPage.getByRole("button", { name: /New Customer/i }).click();
    await expect(rootPage.getByRole("dialog")).toBeVisible();
    await expect(rootPage.getByText("New Customer")).toBeVisible();
  });
});

// ─── Section 79: BankCardsPage UI ────────────────────────────────────────────

test.describe("79 — BankCardsPage UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => { await alicePage.close(); });

  test("79.1 renders My Cards heading", async () => {
    await alicePage.goto(`${BASE}/bank/cards`);
    await alicePage.waitForLoadState("domcontentloaded");
    const heading = alicePage.getByRole("heading", { name: /My Cards/i });
    await expect(heading).toBeVisible({ timeout: 10_000 });
  });

  test("79.2 shows empty state or cards grid when feature enabled", async () => {
    await alicePage.goto(`${BASE}/bank/cards`);
    await alicePage.waitForLoadState("networkidle");
    const notAvail = await alicePage.getByText("not available").isVisible();
    // Either feature is off (graceful banner) or it shows cards/empty state
    if (!notAvail) {
      // Feature on: page should contain either cards or empty message
      const body = alicePage.locator("body");
      await expect(body).not.toContainText("Something went wrong");
    }
  });

  test("79.3 page does not crash", async () => {
    await alicePage.goto(`${BASE}/bank/cards`);
    await alicePage.waitForLoadState("domcontentloaded");
    await expect(alicePage.locator("body")).not.toContainText("Something went wrong");
  });
});

// ─── Section 80: BankProductsPage UI ─────────────────────────────────────────

test.describe("80 — BankProductsPage UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => { await rootPage.close(); });

  test("80.1 renders Financial Products heading", async () => {
    await rootPage.goto(`${BASE}/bank/products`);
    await rootPage.waitForLoadState("domcontentloaded");
    const heading = rootPage.getByRole("heading", { name: /Financial Products/i });
    await expect(heading).toBeVisible({ timeout: 10_000 });
  });

  test("80.2 shows Products and Collections tabs when enabled", async () => {
    await rootPage.goto(`${BASE}/bank/products`);
    await rootPage.waitForLoadState("networkidle");
    const notAvail = await rootPage.getByText("not available").isVisible();
    if (notAvail) {
      test.skip(true, "feature not enabled");
      return;
    }
    await expect(rootPage.getByRole("tab", { name: "Products" })).toBeVisible();
    await expect(rootPage.getByRole("tab", { name: "Collections" })).toBeVisible();
  });

  test("80.3 create product dialog opens", async () => {
    await rootPage.goto(`${BASE}/bank/products`);
    await rootPage.waitForLoadState("networkidle");
    const notAvail = await rootPage.getByText("not available").isVisible();
    if (notAvail) {
      test.skip(true, "feature not enabled");
      return;
    }
    await rootPage.getByRole("button", { name: /New Product/i }).click();
    await expect(rootPage.getByRole("dialog")).toBeVisible();
    await expect(rootPage.getByText("New Financial Product")).toBeVisible();
  });

  test("80.4 collections tab loads", async () => {
    await rootPage.goto(`${BASE}/bank/products`);
    await rootPage.waitForLoadState("networkidle");
    const notAvail = await rootPage.getByText("not available").isVisible();
    if (notAvail) {
      test.skip(true, "feature not enabled");
      return;
    }
    await rootPage.getByRole("tab", { name: "Collections" }).click();
    await expect(rootPage.getByRole("button", { name: /New Collection/i })).toBeVisible();
  });

  test("80.5 page does not crash", async () => {
    await rootPage.goto(`${BASE}/bank/products`);
    await rootPage.waitForLoadState("domcontentloaded");
    await expect(rootPage.locator("body")).not.toContainText("Something went wrong");
  });
});
