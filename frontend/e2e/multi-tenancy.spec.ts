/**
 * E2E tests for Multi-Tenancy (ENTERPRISE-001):
 *
 * Section 80: Tenant CRUD API (6 tests)
 * Section 81: Domain Management (4 tests)
 * Section 82: Tenant Branding (3 tests)
 * Section 83: Tenant Update (4 tests)
 * Section 84: Tenant Admin UI (3 tests)
 * Section 85: Authorization (5 tests)
 *
 * Authentication: Root uses cookie auth via page.request (cookies injected).
 *                 Alice uses cookie auth for non-root / 403 tests.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ─────────────────────────────────────────────────────────────────

const API = "http://localhost:8000";
const TS = Date.now();

// ─── Session bootstrap ─────────────────────────────────────────────────────────

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
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Identity page factory ─────────────────────────────────────────────────────

async function newIdentityPage(
  browser: Browser,
  identity: string,
): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

/**
 * Inject auth into page for UI tests.
 * Sets cookies AND localStorage so ProtectedRoute allows access.
 */
async function injectAuthForUI(page: Page, identity: string): Promise<void> {
  const sessions = getSessions();
  const sess = sessions[identity];
  await page.context().addCookies(sess.cookies);
  // Navigate to login first to set localStorage on the correct origin
  await page.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((userSub: string) => {
    const state = { userId: userSub, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, sess.user_sub);
}

// ─── Request helpers (cookie-auth via page.request) ────────────────────────────

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body?: unknown,
) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiPatch(
  page: Page,
  identity: string,
  path: string,
  body?: unknown,
) {
  const sess = getSessions()[identity];
  return page.request.patch(`${API}${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getSessions()[identity];
  return page.request.delete(`${API}${path}`, {
    headers: {
      "x-csrf-token": sess.csrf_token,
    },
  });
}

// ─── Shared helper: ensure tenant exists ───────────────────────────────────────

async function ensureTenant(
  page: Page,
  slug: string,
  displayName: string,
  plan: string = "starter",
): Promise<string> {
  // Try to create
  const resp = await apiPost(page, "root", "/v1/admin/tenants", {
    slug,
    display_name: displayName,
    plan,
  });
  if (resp.status() === 201) {
    const data = await resp.json();
    return data.tenant_id;
  }
  // Already exists — find it
  const listResp = await apiGet(page, "/v1/admin/tenants?limit=200");
  const listData = await listResp.json();
  const found = listData.tenants.find((t: any) => t.slug === slug);
  if (found) return found.tenant_id;
  throw new Error(`Failed to create or find tenant ${slug}`);
}

// ─── Shared state ──────────────────────────────────────────────────────────────

const SLUG_A = `tenant-a-${TS}`;
const SLUG_B = `tenant-b-${TS}`;
const DISPLAY_A = `Tenant A ${TS}`;
const DISPLAY_B = `Tenant B ${TS}`;
const TEST_DOMAIN = `test-${TS}.example.com`;
const TEST_DOMAIN_2 = `alt-${TS}.example.com`;

// ═══════════════════════════════════════════════════════════════════════════════
// Section 80 . Tenant CRUD API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("80 . Tenant CRUD API", () => {
  let rootPage: Page;
  let tenantAId = "";
  let tenantBId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("80.1 Create tenant-a", async () => {
    const resp = await apiPost(rootPage, "root", "/v1/admin/tenants", {
      slug: SLUG_A,
      display_name: DISPLAY_A,
      plan: "starter",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.tenant_id).toBeTruthy();
    expect(data.slug).toBe(SLUG_A);
    expect(data.display_name).toBe(DISPLAY_A);
    expect(data.status).toBe("active");
    expect(data.plan).toBe("starter");
    tenantAId = data.tenant_id;
  });

  test("80.2 Create tenant-b", async () => {
    const resp = await apiPost(rootPage, "root", "/v1/admin/tenants", {
      slug: SLUG_B,
      display_name: DISPLAY_B,
      plan: "enterprise",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.tenant_id).toBeTruthy();
    expect(data.slug).toBe(SLUG_B);
    expect(data.plan).toBe("enterprise");
    tenantBId = data.tenant_id;
  });

  test("80.3 Duplicate slug returns 409", async () => {
    // Ensure tenant-a exists
    if (!tenantAId) {
      tenantAId = await ensureTenant(rootPage, SLUG_A, DISPLAY_A, "starter");
    }
    const resp = await apiPost(rootPage, "root", "/v1/admin/tenants", {
      slug: SLUG_A,
      display_name: "Duplicate",
      plan: "free",
    });
    expect(resp.status()).toBe(409);
  });

  test("80.4 List tenants includes both", async () => {
    if (!tenantAId) {
      tenantAId = await ensureTenant(rootPage, SLUG_A, DISPLAY_A, "starter");
    }
    if (!tenantBId) {
      tenantBId = await ensureTenant(rootPage, SLUG_B, DISPLAY_B, "enterprise");
    }
    const resp = await apiGet(rootPage, "/v1/admin/tenants?limit=200");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const slugs = data.tenants.map((t: any) => t.slug);
    expect(slugs).toContain(SLUG_A);
    expect(slugs).toContain(SLUG_B);
  });

  test("80.5 Get tenant details", async () => {
    if (!tenantAId) {
      tenantAId = await ensureTenant(rootPage, SLUG_A, DISPLAY_A, "starter");
    }
    const resp = await apiGet(
      rootPage,
      `/v1/admin/tenants/${tenantAId}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.tenant_id).toBe(tenantAId);
    expect(data.slug).toBe(SLUG_A);
    expect(data.status).toBe("active");
    expect(data.limits).toBeTruthy();
    expect(data.member_count).toBe(0);
  });

  test("80.6 Soft-delete tenant-b", async () => {
    if (!tenantBId) {
      tenantBId = await ensureTenant(rootPage, SLUG_B, DISPLAY_B, "enterprise");
    }
    const resp = await apiDelete(
      rootPage,
      "root",
      `/v1/admin/tenants/${tenantBId}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("deleted");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 81 . Domain Management
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("81 . Domain Management", () => {
  let rootPage: Page;
  let tenantAId = "";
  let tenantBId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    tenantAId = await ensureTenant(rootPage, SLUG_A, DISPLAY_A, "starter");
    tenantBId = await ensureTenant(rootPage, SLUG_B, DISPLAY_B, "enterprise");
  });

  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("81.1 Add domain", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/v1/admin/tenants/${tenantAId}/domains`,
      { domain: TEST_DOMAIN },
    );
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.domain).toBe(TEST_DOMAIN);
  });

  test("81.2 Duplicate domain returns 409", async () => {
    // Ensure domain was added (idempotent)
    await apiPost(
      rootPage,
      "root",
      `/v1/admin/tenants/${tenantAId}/domains`,
      { domain: TEST_DOMAIN },
    );
    // Now try again — should be 409
    const resp = await apiPost(
      rootPage,
      "root",
      `/v1/admin/tenants/${tenantAId}/domains`,
      { domain: TEST_DOMAIN },
    );
    expect(resp.status()).toBe(409);
  });

  test("81.3 Remove domain", async () => {
    const resp = await apiDelete(
      rootPage,
      "root",
      `/v1/admin/tenants/${tenantAId}/domains/${encodeURIComponent(TEST_DOMAIN)}`,
    );
    expect(resp.status()).toBe(204);
  });

  test("81.4 Domain for different tenant returns 409", async () => {
    // Add domain to tenant-a
    const add1 = await apiPost(
      rootPage,
      "root",
      `/v1/admin/tenants/${tenantAId}/domains`,
      { domain: TEST_DOMAIN_2 },
    );
    // May already exist from previous run
    expect([201, 409]).toContain(add1.status());

    // Try adding same domain to tenant-b
    const add2 = await apiPost(
      rootPage,
      "root",
      `/v1/admin/tenants/${tenantBId}/domains`,
      { domain: TEST_DOMAIN_2 },
    );
    expect(add2.status()).toBe(409);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 82 . Tenant Branding
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("82 . Tenant Branding", () => {
  let rootPage: Page;
  let tenantAId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    tenantAId = await ensureTenant(rootPage, SLUG_A, DISPLAY_A, "starter");
  });

  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("82.1 Set branding via PATCH", async () => {
    const resp = await apiPatch(
      rootPage,
      "root",
      `/v1/admin/tenants/${tenantAId}`,
      {
        branding: {
          logo_url: "https://example.com/logo.png",
          primary_color: "#FF0000",
          accent_color: "#00FF00",
        },
      },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.branding.logo_url).toBe("https://example.com/logo.png");
    expect(data.branding.primary_color).toBe("#FF0000");
    expect(data.branding.accent_color).toBe("#00FF00");
  });

  test("82.2 GET branding endpoint returns branding", async ({ request }) => {
    const resp = await request.get(`${API}/ui/tenant/branding`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.tenant_id).toBeTruthy();
    expect(data.primary_color).toBeTruthy();
  });

  test("82.3 Default branding for unknown tenant", async ({ request }) => {
    const resp = await request.get(`${API}/ui/tenant/branding`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.tenant_id).toBe("default");
    expect(data.display_name).toBe("Default");
    expect(data.primary_color).toBe("#2563EB");
    expect(data.accent_color).toBe("#7C3AED");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 83 . Tenant Update
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("83 . Tenant Update", () => {
  let rootPage: Page;
  let tenantAId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    tenantAId = await ensureTenant(rootPage, SLUG_A, DISPLAY_A, "starter");
  });

  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("83.1 Update display_name", async () => {
    const newName = `Updated Tenant A ${TS}`;
    const resp = await apiPatch(
      rootPage,
      "root",
      `/v1/admin/tenants/${tenantAId}`,
      { display_name: newName },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.display_name).toBe(newName);
  });

  test("83.2 Update plan", async () => {
    const resp = await apiPatch(
      rootPage,
      "root",
      `/v1/admin/tenants/${tenantAId}`,
      { plan: "enterprise" },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.plan).toBe("enterprise");
    expect(data.limits).toBeTruthy();
    expect(Number(data.limits.max_members)).toBe(10000);
  });

  test("83.3 Suspend tenant", async () => {
    const resp = await apiPatch(
      rootPage,
      "root",
      `/v1/admin/tenants/${tenantAId}`,
      { status: "suspended" },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("suspended");

    // Re-activate for subsequent tests
    const resp2 = await apiPatch(
      rootPage,
      "root",
      `/v1/admin/tenants/${tenantAId}`,
      { status: "active" },
    );
    expect(resp2.status()).toBe(200);
  });

  test("83.4 Update settings_overrides", async () => {
    const resp = await apiPatch(
      rootPage,
      "root",
      `/v1/admin/tenants/${tenantAId}`,
      { settings_overrides: { max_upload_size_mb: 100 } },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.settings_overrides).toBeTruthy();
    expect(Number(data.settings_overrides.max_upload_size_mb)).toBe(100);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 84 . Tenant Admin UI
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("84 . Tenant Admin UI", () => {
  test("84.1 Admin page loads for root user", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuthForUI(page, "root");
    await page.goto("http://localhost:3000/admin/tenants");
    await expect(
      page.getByRole("heading", { name: "Tenant Management" }),
    ).toBeVisible({ timeout: 15000 });
    await page.close();
  });

  test("84.2 Create tenant dialog works", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuthForUI(page, "root");
    await page.goto("http://localhost:3000/admin/tenants");
    await expect(
      page.getByRole("heading", { name: "Tenant Management" }),
    ).toBeVisible({ timeout: 15000 });

    // Open dialog
    await page.getByTestId("create-tenant-btn").click();
    await expect(
      page.getByRole("heading", { name: "Create New Tenant" }),
    ).toBeVisible();

    // Fill form
    const dialogSlug = `ui-test-${TS}`;
    await page.getByLabel("Slug").fill(dialogSlug);
    await page.getByLabel("Display Name").fill(`UI Test ${TS}`);

    // Submit
    await page.getByTestId("submit-create-tenant").click();

    // Wait for dialog to close
    await expect(
      page.getByRole("heading", { name: "Create New Tenant" }),
    ).not.toBeVisible({ timeout: 10000 });

    await page.close();
  });

  test("84.3 Tenant list shows created tenants", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuthForUI(page, "root");

    // Wait for the API response before asserting table rows
    const [resp] = await Promise.all([
      page.waitForResponse(
        (r) => r.url().includes("/v1/admin/tenants") && r.request().method() === "GET" && r.status() === 200,
        { timeout: 15000 },
      ),
      page.goto("http://localhost:3000/admin/tenants"),
    ]);

    await expect(
      page.getByRole("heading", { name: "Tenant Management" }),
    ).toBeVisible({ timeout: 15000 });

    // The table should contain tenant rows
    const rows = page.locator("table tbody tr");
    await expect(rows.first()).toBeVisible({ timeout: 10000 });
    const count = await rows.count();
    expect(count).toBeGreaterThanOrEqual(1);

    await page.close();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 85 . Authorization
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("85 . Authorization", () => {
  let alicePage: Page;
  let rootPage: Page;
  let tenantAId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    rootPage = await newIdentityPage(browser, "root");
    tenantAId = await ensureTenant(rootPage, SLUG_A, DISPLAY_A, "starter");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await rootPage?.close();
  });

  test("85.1 Non-root cannot create tenant", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/admin/tenants", {
      slug: `noauth-${TS}`,
      display_name: "No Auth",
      plan: "free",
    });
    expect(resp.status()).toBe(403);
  });

  test("85.2 Non-root cannot list tenants", async () => {
    const resp = await apiGet(alicePage, "/v1/admin/tenants");
    expect(resp.status()).toBe(403);
  });

  test("85.3 Non-root cannot update tenant", async () => {
    const resp = await apiPatch(
      alicePage,
      "alice",
      `/v1/admin/tenants/${tenantAId}`,
      { display_name: "Hacked" },
    );
    expect(resp.status()).toBe(403);
  });

  test("85.4 Non-root cannot delete tenant", async () => {
    const resp = await apiDelete(
      alicePage,
      "alice",
      `/v1/admin/tenants/${tenantAId}`,
    );
    expect(resp.status()).toBe(403);
  });

  test("85.5 Branding endpoint works without auth", async ({ request }) => {
    const resp = await request.get(`${API}/ui/tenant/branding`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.tenant_id).toBeTruthy();
    expect(data.primary_color).toBeTruthy();
  });
});
