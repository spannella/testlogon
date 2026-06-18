/**
 * E2E tests for the OFBiz CATALOG-DEPTH admin console (PRD-006/007/012).
 *
 * Sections:
 *   90 — Catalog category/item base CRUD (API)
 *   91 — Feature categories & values (API; flag-gated, 404-tolerant)
 *   92 — Product type / variants / price components (API; flag-gated)
 *   93 — Catalog Depth admin page (UI)
 *
 * The product-depth feature flag (S.product_depth_enabled) defaults OFF →
 * the depth endpoints return 404. These tests assert either the happy path
 * (flag on) OR a clean 404 (flag off), so they are green in both states.
 *
 * Auth: uses e2e_admin_session_setup.py (alice = user/creator).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

// ─── Session bootstrap ──────────────────────────────────────────────────────

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

let _sessions: Record<string, AdminSessionData> | null = null;
function getSessions(): Record<string, AdminSessionData> {
  if (!_sessions) {
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_admin_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await page.context().addCookies(getSessions()[identity].cookies);
  return page;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getSessions()[identity];
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

// ─── API helpers ────────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPut(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.put(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

/** True when the product-depth feature flag is enabled (probe a depth endpoint). */
let _depthEnabled: boolean | null = null;
async function depthEnabled(page: Page): Promise<boolean> {
  if (_depthEnabled === null) {
    const resp = await apiGet(page, "ui/catalog/feature-categories");
    _depthEnabled = resp.status() === 200;
  }
  return _depthEnabled;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 90 — Catalog category/item base CRUD (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 90: Catalog base CRUD (API)", () => {
  let alice: Page;
  let categoryId = "";
  let itemId = "";

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alice = await newIdentityPage(browser, "alice");
  });

  test("90.1 Create category → 200 + category_id", async () => {
    const resp = await apiPost(alice, "alice", "ui/catalog/categories", {
      name: `Depth Cat ${TS}`,
      description: "e2e",
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { category_id: string; name: string };
    expect(typeof data.category_id).toBe("string");
    categoryId = data.category_id;
  });

  test("90.2 List categories includes the new one", async () => {
    const resp = await apiGet(alice, "ui/catalog/categories", { page_size: "200" });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { items: Array<{ category_id: string }> };
    expect(data.items.some((c) => c.category_id === categoryId)).toBe(true);
  });

  test("90.3 Create item under category (integer cents)", async () => {
    const resp = await apiPost(
      alice,
      "alice",
      `ui/catalog/categories/${encodeURIComponent(categoryId)}/items`,
      { name: `Depth Item ${TS}`, price_cents: 1999, currency: "USD" },
    );
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { item_id: string; price_cents: number };
    expect(data.price_cents).toBe(1999);
    itemId = data.item_id;
  });

  test("90.4 List items returns the new item", async () => {
    const resp = await apiGet(
      alice,
      `ui/catalog/categories/${encodeURIComponent(categoryId)}/items`,
    );
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { items: Array<{ item_id: string }> };
    expect(data.items.some((i) => i.item_id === itemId)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 91 — Feature categories & values (API, flag-gated)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 91: Feature categories & values (API)", () => {
  let alice: Page;
  let fcId = "";

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
  });

  test("91.1 List feature categories → 200 (flag on) or 404 (flag off)", async () => {
    const resp = await apiGet(alice, "ui/catalog/feature-categories");
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = (await resp.json()) as { feature_categories: unknown[]; count: number };
      expect(Array.isArray(data.feature_categories)).toBe(true);
    }
  });

  test("91.2 Create feature category + value (when flag on)", async () => {
    if (!(await depthEnabled(alice))) {
      test.skip(true, "product depth flag disabled");
      return;
    }
    const created = await apiPost(alice, "alice", "ui/catalog/feature-categories", {
      name: `Color ${TS}`,
    });
    expect(created.status()).toBe(200);
    const fc = (await created.json()) as { feature_category_id: string };
    fcId = fc.feature_category_id;
    expect(fcId).toBeTruthy();

    const val = await apiPost(
      alice,
      "alice",
      `ui/catalog/feature-categories/${encodeURIComponent(fcId)}/values`,
      { name: "Red", price_delta_cents: 200, position: 0 },
    );
    expect(val.status()).toBe(200);
    const valData = (await val.json()) as { price_delta_cents: number };
    expect(valData.price_delta_cents).toBe(200);
  });

  test("91.3 Delete feature category (cleanup)", async () => {
    if (!fcId) {
      test.skip(true, "no fc created");
      return;
    }
    const resp = await apiDelete(
      alice,
      "alice",
      `ui/catalog/feature-categories/${encodeURIComponent(fcId)}`,
    );
    expect([204, 200]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 92 — Product type / variants / price components (API, flag-gated)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 92: Product type / variants / price components (API)", () => {
  let alice: Page;
  let categoryId = "";
  let itemId = "";

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    const cat = await apiPost(alice, "alice", "ui/catalog/categories", {
      name: `Variant Cat ${TS}`,
    });
    categoryId = ((await cat.json()) as { category_id: string }).category_id;
    const item = await apiPost(
      alice,
      "alice",
      `ui/catalog/categories/${encodeURIComponent(categoryId)}/items`,
      { name: `Variant Item ${TS}`, price_cents: 5000 },
    );
    itemId = ((await item.json()) as { item_id: string }).item_id;
  });

  test("92.1 Get product type → standalone (flag on) or 404 (flag off)", async () => {
    const resp = await apiGet(
      alice,
      `ui/catalog/items/${encodeURIComponent(itemId)}/product-type`,
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = (await resp.json()) as { product_type: string };
      expect(typeof data.product_type).toBe("string");
    }
  });

  test("92.2 Full variant lifecycle (when flag on)", async () => {
    if (!(await depthEnabled(alice))) {
      test.skip(true, "product depth flag disabled");
      return;
    }
    // promote to virtual
    const setType = await apiPost(
      alice,
      "alice",
      `ui/catalog/items/${encodeURIComponent(itemId)}/product-type`,
      { product_type: "virtual" },
    );
    expect(setType.status()).toBe(200);

    // create a feature axis + value
    const fc = await apiPost(alice, "alice", "ui/catalog/feature-categories", {
      name: `Size ${TS}`,
    });
    const fcId = ((await fc.json()) as { feature_category_id: string }).feature_category_id;
    const fv = await apiPost(
      alice,
      "alice",
      `ui/catalog/feature-categories/${encodeURIComponent(fcId)}/values`,
      { name: "Large", price_delta_cents: 300 },
    );
    const fvId = ((await fv.json()) as { feature_value_id: string }).feature_value_id;

    // attach axis
    const attach = await apiPost(
      alice,
      "alice",
      `ui/catalog/items/${encodeURIComponent(itemId)}/feature-categories`,
      { feature_category_id: fcId },
    );
    expect(attach.status()).toBe(200);

    // create variant
    const variant = await apiPost(
      alice,
      "alice",
      `ui/catalog/items/${encodeURIComponent(itemId)}/variants`,
      { feature_values: { [fcId]: fvId } },
    );
    expect(variant.status()).toBe(200);
    const vData = (await variant.json()) as {
      variant_id: string;
      effective_price_cents: number;
    };
    expect(vData.effective_price_cents).toBe(5300); // 5000 + 300

    // list variants
    const list = await apiGet(
      alice,
      `ui/catalog/items/${encodeURIComponent(itemId)}/variants`,
    );
    const listData = (await list.json()) as { variants: Array<{ variant_id: string }> };
    expect(listData.variants.some((v) => v.variant_id === vData.variant_id)).toBe(true);

    // delete variant
    const del = await apiDelete(
      alice,
      "alice",
      `ui/catalog/items/${encodeURIComponent(itemId)}/variants/${encodeURIComponent(vData.variant_id)}`,
    );
    expect([204, 200]).toContain(del.status());
  });

  test("92.3 Add + list price component (when flag on)", async () => {
    if (!(await depthEnabled(alice))) {
      test.skip(true, "product depth flag disabled");
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    const add = await apiPost(
      alice,
      "alice",
      `ui/catalog/items/${encodeURIComponent(itemId)}/price-components`,
      { price_type: "PROMO", amount_cents: 4200, currency: "USD", effective_at: now },
    );
    expect(add.status()).toBe(200);

    const list = await apiGet(
      alice,
      `ui/catalog/items/${encodeURIComponent(itemId)}/price-components`,
    );
    expect(list.status()).toBe(200);
    const data = (await list.json()) as { components: Array<{ amount_cents: number }> };
    expect(data.components.some((c) => c.amount_cents === 4200)).toBe(true);
  });

  test("92.4 Bulk set price components via PUT (when flag on)", async () => {
    if (!(await depthEnabled(alice))) {
      test.skip(true, "product depth flag disabled");
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    const resp = await apiPut(
      alice,
      "alice",
      `ui/catalog/items/${encodeURIComponent(itemId)}/price-components`,
      {
        price_type: "LIST",
        components: [
          { price_type: "LIST", amount_cents: 6000, currency: "USD", effective_at: now },
        ],
      },
    );
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { components: unknown[] };
    expect(Array.isArray(data.components)).toBe(true);
  });

  test("92.5 Effective price resolves (when flag on)", async () => {
    if (!(await depthEnabled(alice))) {
      test.skip(true, "product depth flag disabled");
      return;
    }
    const resp = await apiGet(
      alice,
      `ui/catalog/items/${encodeURIComponent(itemId)}/effective-price`,
      { price_type: "DEFAULT" },
    );
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { amount_cents: number; source: string };
    expect(typeof data.amount_cents).toBe("number");
    expect(typeof data.source).toBe("string");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 93 — Catalog Depth admin page (UI)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 93: Catalog Depth admin page (UI)", () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page, "alice");
  });

  test("93.1 Page renders with header and tabs", async ({ page }) => {
    await page.goto(`${BASE}/ofbiz/catalog-depth`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Catalog Depth" })).toBeVisible({
      timeout: 15_000,
    });
    await expect(page.getByRole("tab", { name: /Catalog Tree/i })).toBeVisible();
    await expect(page.getByRole("tab", { name: /Feature Categories/i })).toBeVisible();
  });

  test("93.2 Catalog tree shows category controls", async ({ page }) => {
    await page.goto(`${BASE}/ofbiz/catalog-depth`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("button", { name: /Category/i }).first()).toBeVisible({
      timeout: 15_000,
    });
  });

  test("93.3 Feature Categories tab is navigable", async ({ page }) => {
    await page.goto(`${BASE}/ofbiz/catalog-depth`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: /Feature Categories/i }).click();
    // Either the feature category panel (flag on) or the disabled empty state (flag off).
    await expect(
      page.getByText(/Feature Categories|not enabled/i).first(),
    ).toBeVisible({ timeout: 15_000 });
  });

  test("93.4 Empty item selection prompt is shown", async ({ page }) => {
    await page.goto(`${BASE}/ofbiz/catalog-depth`, { waitUntil: "domcontentloaded" });
    await expect(
      page.getByText(/Select a catalog item/i),
    ).toBeVisible({ timeout: 15_000 });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Sections 200–205 — PRD-016 depth-route guard tests (flag-agnostic)
//
// These tests probe every depth-specific endpoint and assert that only valid
// HTTP status codes are returned.  The permitted set per route is:
//
//   501  — PRODUCT_DEPTH_ENABLED is false (router-level guard, flag off)
//   404  — flag is on but the item/category has no depth data yet
//   200  — flag is on and data exists (or the route is a no-op)
//   409  — flag is on, data conflict (e.g. duplicate child)
//
// When the response is 501 the detail must equal "product_depth_not_enabled".
// This guarantees that any unexpected status code (e.g. 500, 403, 422) causes
// the test to fail.  The tests pass in both CI (flag off → 501) and local dev
// (flag on → 200 or 404 depending on data).
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 200: PRD-016 — flag-off 501 guard (setup)", () => {
  let alice200: Page;
  let cat200Id = "";
  let item200Id = "";

  test.beforeAll(async ({ browser }) => {
    alice200 = await newIdentityPage(browser, "alice");

    const catResp = await apiPost(alice200, "alice", "ui/catalog/categories", {
      name: `Depth501 Cat ${TS}`,
      description: "501 guard",
    });
    if (catResp.ok()) {
      cat200Id = ((await catResp.json()) as { category_id: string }).category_id;
    }

    if (cat200Id) {
      const itemResp = await apiPost(
        alice200,
        "alice",
        `ui/catalog/categories/${encodeURIComponent(cat200Id)}/items`,
        { name: `Depth501 Item ${TS}`, price_cents: 500 },
      );
      if (itemResp.ok()) {
        item200Id = ((await itemResp.json()) as { item_id: string }).item_id;
      }
    }
  });

  test("200.1 Create category + item for 501 probe → both IDs are non-empty", async () => {
    expect(typeof cat200Id).toBe("string");
    expect(cat200Id.length).toBeGreaterThan(0);
    expect(typeof item200Id).toBe("string");
    expect(item200Id.length).toBeGreaterThan(0);
  });
});

test.describe("Section 201: PRD-016 — Category Tree routes (flag-agnostic)", () => {
  let alice: Page;
  let catId = "";

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    const resp = await apiPost(alice, "alice", "ui/catalog/categories", {
      name: `Tree501 ${TS}`,
    });
    if (resp.ok()) {
      catId = ((await resp.json()) as { category_id: string }).category_id;
    }
  });

  test("201.1 GET /categories/{id}/tree → 200, 404, or 501", async () => {
    const resp = await alice.request.get(
      `${API}/ui/catalog/categories/${encodeURIComponent(catId)}/tree`,
    );
    // 501 = flag off; 404 = flag on, no depth data; 200 = flag on, data exists
    expect([200, 404, 501]).toContain(resp.status());
    if (resp.status() === 501) {
      const body = (await resp.json()) as { detail: string };
      expect(body.detail).toBe("product_depth_not_enabled");
    }
  });

  test("201.2 GET /categories/{id}/breadcrumb → 200, 404, or 501", async () => {
    const resp = await alice.request.get(
      `${API}/ui/catalog/categories/${encodeURIComponent(catId)}/breadcrumb`,
    );
    expect([200, 404, 501]).toContain(resp.status());
    if (resp.status() === 501) {
      const body = (await resp.json()) as { detail: string };
      expect(body.detail).toBe("product_depth_not_enabled");
    }
  });

  test("201.3 POST /categories/{id}/children → 200, 404, 409, or 501", async () => {
    const childResp = await apiPost(alice, "alice", "ui/catalog/categories", {
      name: `Child501 ${TS}`,
    });
    const childId = childResp.ok()
      ? ((await childResp.json()) as { category_id: string }).category_id
      : "child-probe";

    const sess = getSessions()["alice"];
    const resp = await alice.request.post(
      `${API}/ui/catalog/categories/${encodeURIComponent(catId)}/children`,
      {
        data: { child_category_id: childId, position: 0 },
        headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
      },
    );
    // 501 = flag off; 200/409 = flag on (data depends on tree state); 404 = not yet in tree
    expect([200, 404, 409, 501]).toContain(resp.status());
    if (resp.status() === 501) {
      const body = (await resp.json()) as { detail: string };
      expect(body.detail).toBe("product_depth_not_enabled");
    }
  });

  test("201.4 PATCH /categories/{id}/move → 200, 404, 409, or 501", async () => {
    const parentResp = await apiPost(alice, "alice", "ui/catalog/categories", {
      name: `MoveParent501 ${TS}`,
    });
    const parentId = parentResp.ok()
      ? ((await parentResp.json()) as { category_id: string }).category_id
      : "parent-probe";

    const sess = getSessions()["alice"];
    const resp = await alice.request.patch(
      `${API}/ui/catalog/categories/${encodeURIComponent(catId)}/move`,
      {
        data: { new_parent_id: parentId },
        headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
      },
    );
    expect([200, 404, 409, 501]).toContain(resp.status());
    if (resp.status() === 501) {
      const body = (await resp.json()) as { detail: string };
      expect(body.detail).toBe("product_depth_not_enabled");
    }
  });
});

test.describe("Section 202: PRD-016 — Product Features routes (flag-agnostic)", () => {
  let alice: Page;
  let itemId = "";

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    const catResp = await apiPost(alice, "alice", "ui/catalog/categories", {
      name: `Feat501Cat ${TS}`,
    });
    const catId = catResp.ok()
      ? ((await catResp.json()) as { category_id: string }).category_id
      : "probe-cat";
    const itemResp = await apiPost(
      alice,
      "alice",
      `ui/catalog/categories/${encodeURIComponent(catId)}/items`,
      { name: `Feat501Item ${TS}`, price_cents: 1000 },
    );
    if (itemResp.ok()) {
      itemId = ((await itemResp.json()) as { item_id: string }).item_id;
    }
  });

  test("202.1 GET /items/{id}/product-features → 200, 404, or 501", async () => {
    // Route delegates gating to the service (_require_enabled) which raises 404 when
    // flag is off.  Accept 200 (flag on) or 404/501 (flag off or no depth data).
    const resp = await alice.request.get(
      `${API}/ui/catalog/items/${encodeURIComponent(itemId)}/product-features`,
    );
    expect([200, 404, 501]).toContain(resp.status());
  });

  test("202.2 POST /items/{id}/mark-virtual → 200, 404, or 501", async () => {
    const sess = getSessions()["alice"];
    const resp = await alice.request.post(
      `${API}/ui/catalog/items/${encodeURIComponent(itemId)}/mark-virtual`,
      {
        data: {},
        headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
      },
    );
    // 501 = flag off; 404 = flag on but item not in depth table; 200 = success
    expect([200, 404, 501]).toContain(resp.status());
    if (resp.status() === 501) {
      const body = (await resp.json()) as { detail: string };
      expect(body.detail).toBe("product_depth_not_enabled");
    }
  });
});

test.describe("Section 203: PRD-016 — Variants routes (flag-agnostic)", () => {
  let alice: Page;
  let itemId = "";

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    const catResp = await apiPost(alice, "alice", "ui/catalog/categories", {
      name: `Var501Cat ${TS}`,
    });
    const catId = catResp.ok()
      ? ((await catResp.json()) as { category_id: string }).category_id
      : "probe-cat";
    const itemResp = await apiPost(
      alice,
      "alice",
      `ui/catalog/categories/${encodeURIComponent(catId)}/items`,
      { name: `Var501Item ${TS}`, price_cents: 2000 },
    );
    if (itemResp.ok()) {
      itemId = ((await itemResp.json()) as { item_id: string }).item_id;
    }
  });

  test("203.1 GET /items/{id}/variants → 200, 404, or 501", async () => {
    const resp = await alice.request.get(
      `${API}/ui/catalog/items/${encodeURIComponent(itemId)}/variants`,
    );
    // 501 = flag off; 404 = flag on, item has no variants; 200 = flag on, variants exist
    expect([200, 404, 501]).toContain(resp.status());
    if (resp.status() === 501) {
      const body = (await resp.json()) as { detail: string };
      expect(body.detail).toBe("product_depth_not_enabled");
    }
  });

  test("203.2 GET /items/{id}/product-type → 200 or 404 (not depth-gated)", async () => {
    // get_product_type_endpoint does NOT gate on product_depth_enabled directly —
    // the service returns "standalone" for any item.  Accept 200 or 404.
    const resp = await alice.request.get(
      `${API}/ui/catalog/items/${encodeURIComponent(itemId)}/product-type`,
    );
    expect([200, 404]).toContain(resp.status());
  });
});

test.describe("Section 204: PRD-016 — Bundle Expand route (flag-agnostic)", () => {
  let alice: Page;
  let itemId = "";

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    const catResp = await apiPost(alice, "alice", "ui/catalog/categories", {
      name: `Bundle501Cat ${TS}`,
    });
    const catId = catResp.ok()
      ? ((await catResp.json()) as { category_id: string }).category_id
      : "probe-cat";
    const itemResp = await apiPost(
      alice,
      "alice",
      `ui/catalog/categories/${encodeURIComponent(catId)}/items`,
      { name: `Bundle501Item ${TS}`, price_cents: 3000 },
    );
    if (itemResp.ok()) {
      itemId = ((await itemResp.json()) as { item_id: string }).item_id;
    }
  });

  test("204.1 GET /items/{id}/expand → 200, 404, or 501", async () => {
    const resp = await alice.request.get(
      `${API}/ui/catalog/items/${encodeURIComponent(itemId)}/expand`,
    );
    // 501 = flag off; 404 = flag on, item is not a bundle; 200 = flag on, bundle
    expect([200, 404, 501]).toContain(resp.status());
    if (resp.status() === 501) {
      const body = (await resp.json()) as { detail: string };
      expect(body.detail).toBe("product_depth_not_enabled");
    }
  });
});

test.describe("Section 205: PRD-016 — Associations routes (flag-agnostic)", () => {
  let alice: Page;
  let itemId = "";
  let item2Id = "";

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    const catResp = await apiPost(alice, "alice", "ui/catalog/categories", {
      name: `Assoc501Cat ${TS}`,
    });
    const catId = catResp.ok()
      ? ((await catResp.json()) as { category_id: string }).category_id
      : "probe-cat";

    const item1Resp = await apiPost(
      alice,
      "alice",
      `ui/catalog/categories/${encodeURIComponent(catId)}/items`,
      { name: `Assoc501ItemA ${TS}`, price_cents: 1500 },
    );
    if (item1Resp.ok()) {
      itemId = ((await item1Resp.json()) as { item_id: string }).item_id;
    }

    const item2Resp = await apiPost(
      alice,
      "alice",
      `ui/catalog/categories/${encodeURIComponent(catId)}/items`,
      { name: `Assoc501ItemB ${TS}`, price_cents: 2500 },
    );
    if (item2Resp.ok()) {
      item2Id = ((await item2Resp.json()) as { item_id: string }).item_id;
    }
  });

  test("205.1 GET /items/{id}/associations → 200, 404, or 501", async () => {
    const resp = await alice.request.get(
      `${API}/ui/catalog/items/${encodeURIComponent(itemId)}/associations`,
    );
    // 501 = flag off; 404 = flag on, item has no associations; 200 = flag on with data
    expect([200, 404, 501]).toContain(resp.status());
    if (resp.status() === 501) {
      const body = (await resp.json()) as { detail: string };
      expect(body.detail).toBe("product_depth_not_enabled");
    }
  });

  test("205.2 POST /items/{id}/associations → 200, 404, or 501", async () => {
    const sess = getSessions()["alice"];
    const resp = await alice.request.post(
      `${API}/ui/catalog/items/${encodeURIComponent(itemId)}/associations`,
      {
        data: { assoc_type: "CROSS_SELL", to_item_id: item2Id },
        headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
      },
    );
    // 501 = flag off; 200 = flag on (idempotent create); 404 = item not found in depth table
    expect([200, 404, 501]).toContain(resp.status());
    if (resp.status() === 501) {
      const body = (await resp.json()) as { detail: string };
      expect(body.detail).toBe("product_depth_not_enabled");
    }
  });

  test("205.3 DELETE /items/{id}/associations/{to} → 200, 404, or 501", async () => {
    const sess = getSessions()["alice"];
    const resp = await alice.request.delete(
      `${API}/ui/catalog/items/${encodeURIComponent(itemId)}/associations/${encodeURIComponent(item2Id)}?assoc_type=CROSS_SELL`,
      {
        headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
      },
    );
    // 501 = flag off; 200 = flag on (no-op delete is still 200); 404 = item not found
    expect([200, 404, 501]).toContain(resp.status());
    if (resp.status() === 501) {
      const body = (await resp.json()) as { detail: string };
      expect(body.detail).toBe("product_depth_not_enabled");
    }
  });
});
