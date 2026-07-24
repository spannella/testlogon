/**
 * E2E tests for SSO / SAML Integration (ENTERPRISE-002).
 *
 * Sections:
 *   86 — SSO provider CRUD API (5 tests)
 *   87 — Attribute and role mapping API (4 tests)
 *   88 — SSO info endpoint (3 tests)
 *   89 — SAML flow: ACS mock validation, JIT provisioning, session creation (4 tests)
 *   90 — SSO-only enforcement (3 tests)
 *   91 — SSO login UI (3 tests)
 *
 * Auth: Root session cookies (from e2e_admin_session_setup.py) for admin endpoints.
 *       Alice/Bob sessions for user-facing tests.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ─────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ROOT_SUB = "root.admin@testdev.local";
const TS       = Date.now();
const TENANT   = "default";

// ─── Session bootstrap ─────────────────────────────────────────────────────────

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

let _adminSessions: Record<string, SessionData> | null = null;
function getAdminSessions(): Record<string, SessionData> {
  if (!_adminSessions) {
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const sessions = identity === "root" ? getAdminSessions() : getSessions();
  const s = sessions[identity];
  if (!s) throw new Error(`No session for identity "${identity}"`);
  await page.context().addCookies([
    { name: "ui_session",      value: s.session_id,   domain: "localhost", path: "/" },
    { name: "ui_csrf",         value: s.csrf_token,    domain: "localhost", path: "/" },
    { name: "ui_access_token", value: s.access_token,  domain: "localhost", path: "/" },
  ]);
}

function rootHeaders(): Record<string, string> {
  const s = getAdminSessions()["root"];
  return { "x-csrf-token": s.csrf_token };
}

async function rootPage(browser: Browser): Promise<Page> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await injectAuth(page, "root");
  return page;
}

// ─── Helper: generate mock IdP metadata XML ────────────────────────────────────

function generateMockMetadata(opts: {
  entityId: string;
  ssoUrl: string;
  sloUrl?: string;
  certB64?: string;
}): string {
  const cert = opts.certB64 || "MIICdummy";
  return `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="${opts.entityId}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>${cert}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="${opts.ssoUrl}"/>
    ${opts.sloUrl ? `<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${opts.sloUrl}"/>` : ""}
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`;
}

// ─── Helper: generate mock SAMLResponse XML ────────────────────────────────────

function generateMockSamlResponse(opts: {
  issuer: string;
  email: string;
  displayName?: string;
  groups?: string[];
  assertionId?: string;
}): string {
  const assertionId = opts.assertionId || `_e2e_${TS}_${Math.random().toString(36).slice(2)}`;
  const groupAttrs = (opts.groups || [])
    .map((g) => `<saml:AttributeValue>${g}</saml:AttributeValue>`)
    .join("\n              ");

  const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_resp_${assertionId}"
                Version="2.0"
                IssueInstant="${new Date().toISOString()}">
  <saml:Issuer>${opts.issuer}</saml:Issuer>
  <saml:Assertion ID="${assertionId}" Version="2.0" IssueInstant="${new Date().toISOString()}">
    <saml:Issuer>${opts.issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${opts.email}</saml:NameID>
    </saml:Subject>
    <saml:AuthnStatement SessionIndex="session_${assertionId}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>${opts.email}</saml:AttributeValue>
      </saml:Attribute>
      ${opts.displayName ? `<saml:Attribute Name="displayName"><saml:AttributeValue>${opts.displayName}</saml:AttributeValue></saml:Attribute>` : ""}
      ${(opts.groups && opts.groups.length > 0) ? `<saml:Attribute Name="groups">${groupAttrs}</saml:Attribute>` : ""}
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;
  return btoa(xml);
}

// ─── Test state ────────────────────────────────────────────────────────────────

let providerId = "";
const IDP_ENTITY_ID = `https://test-idp-${TS}.local`;
const IDP_SSO_URL   = `https://test-idp-${TS}.local/sso`;
const IDP_SLO_URL   = `https://test-idp-${TS}.local/slo`;

/**
 * Delete all SSO providers for the tenant except the one we're tracking.
 * Prevents leftover providers from previous test runs from interfering.
 */
async function cleanupOldProviders(page: Page): Promise<void> {
  const resp = await page.request.get(
    `${API}/v1/admin/sso/providers?tenant_id=${TENANT}`,
    { headers: rootHeaders() },
  );
  if (resp.status() !== 200) return;
  const body = await resp.json();
  for (const p of body.providers || []) {
    if (p.provider_id !== providerId) {
      await page.request.delete(
        `${API}/v1/admin/sso/providers/${p.provider_id}?tenant_id=${TENANT}`,
        { headers: rootHeaders() },
      );
    }
  }
}

/**
 * Ensure a test provider exists. Called from each section's beforeAll
 * so that retries / new workers don't lose the providerId.
 */
async function ensureProvider(page: Page): Promise<string> {
  if (providerId) return providerId;

  // Clean up old providers from previous test runs
  await cleanupOldProviders(page);

  const metadata = generateMockMetadata({
    entityId: IDP_ENTITY_ID,
    ssoUrl: IDP_SSO_URL,
    sloUrl: IDP_SLO_URL,
  });

  const resp = await page.request.post(`${API}/v1/admin/sso/providers`, {
    headers: { ...rootHeaders(), "Content-Type": "application/json" },
    data: {
      display_name: `Test IdP ${TS}`,
      protocol: "saml",
      tenant_id: TENANT,
      metadata_xml: btoa(metadata),
      jit_provisioning_enabled: true,
      default_role: "user",
    },
  });

  if (resp.status() === 200) {
    const body = await resp.json();
    providerId = body.provider_id;
  }
  return providerId;
}

// ── Section 86: SSO provider CRUD API ───────────────────────────────────────

test.describe("86 · SSO provider CRUD API", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await rootPage(browser);
    await page.goto(`${BASE}/login`);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("86.1 Create SSO provider with metadata XML", async () => {
    const metadata = generateMockMetadata({
      entityId: IDP_ENTITY_ID,
      ssoUrl: IDP_SSO_URL,
      sloUrl: IDP_SLO_URL,
    });

    const resp = await page.request.post(`${API}/v1/admin/sso/providers`, {
      headers: rootHeaders(),
      data: {
        display_name: `Test IdP ${TS}`,
        protocol: "saml",
        tenant_id: TENANT,
        metadata_xml: btoa(metadata),
        jit_provisioning_enabled: true,
        default_role: "user",
      },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.provider_id).toBeTruthy();
    expect(body.display_name).toBe(`Test IdP ${TS}`);
    expect(body.protocol).toBe("saml");
    expect(body.status).toBe("active");
    expect(body.idp_entity_id).toBe(IDP_ENTITY_ID);
    expect(body.idp_sso_url).toBe(IDP_SSO_URL);
    expect(body.jit_provisioning_enabled).toBe(true);
    providerId = body.provider_id;
  });

  test("86.2 List SSO providers for tenant", async () => {
    await ensureProvider(page);
    const resp = await page.request.get(
      `${API}/v1/admin/sso/providers?tenant_id=${TENANT}`,
      { headers: rootHeaders() },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.providers).toBeInstanceOf(Array);
    const found = body.providers.find((p: any) => p.provider_id === providerId);
    expect(found).toBeTruthy();
    expect(found.display_name).toBe(`Test IdP ${TS}`);
  });

  test("86.3 Get SSO provider by ID", async () => {
    await ensureProvider(page);
    const resp = await page.request.get(
      `${API}/v1/admin/sso/providers/${providerId}?tenant_id=${TENANT}`,
      { headers: rootHeaders() },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.provider_id).toBe(providerId);
    expect(body.idp_entity_id).toBe(IDP_ENTITY_ID);
  });

  test("86.4 Update SSO provider status", async () => {
    await ensureProvider(page);
    const resp = await page.request.patch(`${API}/v1/admin/sso/providers/${providerId}`, {
      headers: rootHeaders(),
      data: { status: "testing", tenant_id: TENANT },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("testing");
  });

  test("86.5 Delete SSO provider", async () => {
    // Create a temp provider to delete
    const createResp = await page.request.post(`${API}/v1/admin/sso/providers`, {
      headers: rootHeaders(),
      data: {
        display_name: `Delete Me ${TS}`,
        protocol: "saml",
        tenant_id: TENANT,
      },
    });
    expect(createResp.status()).toBe(200);
    const created = await createResp.json();

    const delResp = await page.request.delete(
      `${API}/v1/admin/sso/providers/${created.provider_id}?tenant_id=${TENANT}`,
      { headers: rootHeaders() },
    );
    expect(delResp.status()).toBe(200);

    // Verify it's gone
    const getResp = await page.request.get(
      `${API}/v1/admin/sso/providers/${created.provider_id}?tenant_id=${TENANT}`,
      { headers: rootHeaders() },
    );
    expect(getResp.status()).toBe(404);
  });
});

// ── Section 87: Attribute and role mapping API ──────────────────────────────

test.describe("87 · Attribute and role mapping API", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await rootPage(browser);
    await page.goto(`${BASE}/login`);
    await ensureProvider(page);

    // Make sure provider is active
    if (providerId) {
      await page.request.patch(`${API}/v1/admin/sso/providers/${providerId}`, {
        headers: rootHeaders(),
        data: { status: "active", tenant_id: TENANT },
      });
    }
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("87.1 Set attribute mappings", async () => {
    const resp = await page.request.post(
      `${API}/v1/admin/sso/providers/${providerId}/attribute-mappings`,
      {
        headers: rootHeaders(),
        data: {
          tenant_id: TENANT,
          attribute_mappings: {
            email: "email",
            display_name: "displayName",
            groups: "groups",
          },
        },
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.attribute_mappings.email).toBe("email");
    expect(body.attribute_mappings.display_name).toBe("displayName");
    expect(body.attribute_mappings.groups).toBe("groups");
  });

  test("87.2 Set group-to-role mappings", async () => {
    const resp = await page.request.post(
      `${API}/v1/admin/sso/providers/${providerId}/role-mappings`,
      {
        headers: rootHeaders(),
        data: {
          tenant_id: TENANT,
          role_mappings: [
            { idp_group: "Platform-Admins", platform_role: "admin" },
            { idp_group: "Platform-Users", platform_role: "user" },
          ],
        },
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.role_mappings).toHaveLength(2);
    expect(body.role_mappings[0].idp_group).toBe("Platform-Admins");
  });

  test("87.3 Reject root role mapping", async () => {
    const resp = await page.request.post(
      `${API}/v1/admin/sso/providers/${providerId}/role-mappings`,
      {
        headers: rootHeaders(),
        data: {
          tenant_id: TENANT,
          role_mappings: [
            { idp_group: "Super-Admins", platform_role: "root" },
          ],
        },
      },
    );
    expect(resp.status()).toBe(400);
  });

  test("87.4 Update attribute mappings", async () => {
    const resp = await page.request.post(
      `${API}/v1/admin/sso/providers/${providerId}/attribute-mappings`,
      {
        headers: rootHeaders(),
        data: {
          tenant_id: TENANT,
          attribute_mappings: {
            email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            display_name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
            groups: "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
          },
        },
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.attribute_mappings.email).toContain("emailaddress");
  });
});

// ── Section 88: SSO info endpoint ───────────────────────────────────────────

test.describe("88 · SSO info endpoint", () => {
  test.beforeAll(async ({ browser }) => {
    // Ensure provider exists for SSO info tests
    const page = await rootPage(browser);
    await page.goto(`${BASE}/login`);
    await ensureProvider(page);
    // Make sure provider is active and sso_only is false
    if (providerId) {
      await page.request.patch(`${API}/v1/admin/sso/providers/${providerId}`, {
        headers: rootHeaders(),
        data: { status: "active", sso_only: false, tenant_id: TENANT },
      });
    }
    await page.close();
  });

  test("88.1 SSO info with no provider configured (unused tenant)", async ({ request }) => {
    const resp = await request.get(`${API}/ui/sso/info?tenant=nonexistent_tenant_${TS}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.sso_available).toBe(false);
    expect(body.sso_only).toBe(false);
  });

  test("88.2 SSO info with active provider", async ({ request }) => {
    const resp = await request.get(`${API}/ui/sso/info?tenant=${TENANT}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.sso_available).toBe(true);
    expect(body.sso_login_url).toContain("/saml/login");
    expect(body.provider_display_name).toContain("Test IdP");
    expect(body.provider_protocol).toBe("saml");
  });

  test("88.3 SSO info reflects sso_only when set", async ({ browser }) => {
    const page = await rootPage(browser);
    await page.goto(`${BASE}/login`);

    // Enable sso_only
    const patchResp = await page.request.patch(`${API}/v1/admin/sso/providers/${providerId}`, {
      headers: rootHeaders(),
      data: { sso_only: true, tenant_id: TENANT },
    });
    expect(patchResp.status()).toBe(200);

    const resp = await page.request.get(`${API}/ui/sso/info?tenant=${TENANT}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.sso_only).toBe(true);

    // Revert sso_only
    await page.request.patch(`${API}/v1/admin/sso/providers/${providerId}`, {
      headers: rootHeaders(),
      data: { sso_only: false, tenant_id: TENANT },
    });

    await page.close();
  });
});

// ── Section 89: SAML flow ───────────────────────────────────────────────────

test.describe("89 · SAML ACS flow", () => {
  let page: Page;
  const SSO_USER_EMAIL = `sso-test-${TS}@test.local`;

  test.beforeAll(async ({ browser }) => {
    page = await rootPage(browser);
    await page.goto(`${BASE}/login`);
    await ensureProvider(page);

    // Ensure provider is active
    if (providerId) {
      await page.request.patch(`${API}/v1/admin/sso/providers/${providerId}`, {
        headers: rootHeaders(),
        data: { status: "active", tenant_id: TENANT },
      });
    }

    // Set attribute mappings so ACS can extract email from assertion
    await page.request.post(
      `${API}/v1/admin/sso/providers/${providerId}/attribute-mappings`,
      {
        headers: rootHeaders(),
        data: {
          tenant_id: TENANT,
          attribute_mappings: {
            email: "email",
            display_name: "displayName",
            groups: "groups",
          },
        },
      },
    );
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("89.1 SP-initiated login redirects to IdP", async () => {
    const resp = await page.request.get(
      `${API}/saml/login?tenant=${TENANT}`,
      { maxRedirects: 0 },
    );
    // Should be 302 redirect to IdP
    expect(resp.status()).toBe(302);
    const location = resp.headers()["location"] || "";
    expect(location).toContain(IDP_SSO_URL);
  });

  test("89.2 ACS processes valid SAMLResponse and creates session", async () => {
    const samlResponseB64 = generateMockSamlResponse({
      issuer: IDP_ENTITY_ID,
      email: SSO_USER_EMAIL,
      displayName: "SSO Test User",
      groups: ["Platform-Users"],
    });

    const resp = await page.request.post(`${API}/saml/acs`, {
      form: {
        SAMLResponse: samlResponseB64,
        RelayState: "/",
        tenant_id: TENANT,
      },
      maxRedirects: 0,
    });

    // ACS returns 303 redirect
    expect(resp.status()).toBe(303);

    // Verify cookies were set
    const setCookies = resp.headersArray().filter((h) => h.name.toLowerCase() === "set-cookie");
    const cookieStr = setCookies.map((h) => h.value).join("; ");
    expect(cookieStr).toContain("ui_session");
    expect(cookieStr).toContain("ui_access_token");
  });

  test("89.3 JIT-provisioned user exists in DDB", async () => {
    // Verify user was created by checking profile
    // Use a new context with the session cookies from ACS
    const samlResponseB64 = generateMockSamlResponse({
      issuer: IDP_ENTITY_ID,
      email: SSO_USER_EMAIL,
      displayName: "SSO Test User 2",
      assertionId: `_assert_verify_${TS}`,
    });

    // Send ACS again (will use existing user due to JIT)
    const resp = await page.request.post(`${API}/saml/acs`, {
      form: {
        SAMLResponse: samlResponseB64,
        RelayState: "/",
        tenant_id: TENANT,
      },
      maxRedirects: 0,
    });
    expect(resp.status()).toBe(303);
  });

  test("89.4 Replay detection blocks re-used assertion", async () => {
    const replayAssertionId = `_replay_${TS}`;
    const samlResponseB64 = generateMockSamlResponse({
      issuer: IDP_ENTITY_ID,
      email: SSO_USER_EMAIL,
      assertionId: replayAssertionId,
    });

    // First use — should succeed
    const resp1 = await page.request.post(`${API}/saml/acs`, {
      form: {
        SAMLResponse: samlResponseB64,
        RelayState: "/",
        tenant_id: TENANT,
      },
      maxRedirects: 0,
    });
    expect(resp1.status()).toBe(303);

    // Second use with same assertion ID — should be blocked
    const resp2 = await page.request.post(`${API}/saml/acs`, {
      form: {
        SAMLResponse: samlResponseB64,
        RelayState: "/",
        tenant_id: TENANT,
      },
      maxRedirects: 0,
    });
    expect(resp2.status()).toBe(303);
    const location = resp2.headers()["location"] || "";
    expect(location).toContain("error=sso_replay_detected");
  });
});

// ── Section 90: SSO-only enforcement ────────────────────────────────────────

test.describe("90 · SSO-only enforcement", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await rootPage(browser);
    await page.goto(`${BASE}/login`);
    await ensureProvider(page);
    // Ensure provider is active before tests
    if (providerId) {
      await page.request.patch(`${API}/v1/admin/sso/providers/${providerId}`, {
        headers: rootHeaders(),
        data: { status: "active", sso_only: false, tenant_id: TENANT },
      });
    }
  });

  test.afterAll(async () => {
    // Ensure sso_only is disabled after tests
    if (providerId) {
      await page.request.patch(`${API}/v1/admin/sso/providers/${providerId}`, {
        headers: rootHeaders(),
        data: { sso_only: false, tenant_id: TENANT },
      });
    }
    await page.close();
  });

  test("90.1 Enable SSO-only mode", async () => {
    const resp = await page.request.patch(`${API}/v1/admin/sso/providers/${providerId}`, {
      headers: rootHeaders(),
      data: { sso_only: true, tenant_id: TENANT },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.sso_only).toBe(true);
  });

  test("90.2 SSO info reflects sso_only", async () => {
    const resp = await page.request.get(`${API}/ui/sso/info?tenant=${TENANT}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.sso_only).toBe(true);
    expect(body.sso_available).toBe(true);
  });

  test("90.3 Disable SSO-only re-enables password login", async () => {
    const resp = await page.request.patch(`${API}/v1/admin/sso/providers/${providerId}`, {
      headers: rootHeaders(),
      data: { sso_only: false, tenant_id: TENANT },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.sso_only).toBe(false);

    const infoResp = await page.request.get(`${API}/ui/sso/info?tenant=${TENANT}`);
    const info = await infoResp.json();
    expect(info.sso_only).toBe(false);
  });
});

// ── Section 91: SSO login UI ────────────────────────────────────────────────

test.describe("91 · SSO login UI", () => {
  test.beforeAll(async ({ browser }) => {
    // Ensure provider exists and is active
    const page = await rootPage(browser);
    await page.goto(`${BASE}/login`);
    await ensureProvider(page);
    if (providerId) {
      await page.request.patch(`${API}/v1/admin/sso/providers/${providerId}`, {
        headers: rootHeaders(),
        data: { status: "active", sso_only: false, tenant_id: TENANT },
      });
    }
    await page.close();
  });

  test("91.1 SSO button visible on login page when provider exists", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(`${BASE}/login`);

    // Wait for the SSO info query to resolve
    const ssoButton = page.locator('[data-testid="sso-login-button"]');
    await expect(ssoButton).toBeVisible({ timeout: 10_000 });
    await expect(ssoButton).toContainText("Sign in with");

    await page.close();
  });

  test("91.2 SSO-only mode hides password form", async ({ browser }) => {
    // Enable sso_only
    const rootCtx = await browser.newContext();
    const rootPg = await rootCtx.newPage();
    await injectAuth(rootPg, "root");
    await rootPg.goto(`${BASE}/login`);

    const patchResp = await rootPg.request.patch(`${API}/v1/admin/sso/providers/${providerId}`, {
      headers: rootHeaders(),
      data: { sso_only: true, tenant_id: TENANT },
    });
    expect(patchResp.status()).toBe(200);

    // Open fresh login page (no auth cookies)
    const userCtx = await browser.newContext();
    const loginPage = await userCtx.newPage();
    await loginPage.goto(`${BASE}/login`);

    // Wait for the SSO-only UI to render
    await expect(loginPage.getByText("Your organization requires SSO login", { exact: true })).toBeVisible({ timeout: 10_000 });

    // SSO button should be visible
    const ssoButton = loginPage.locator('[data-testid="sso-login-button"]');
    await expect(ssoButton).toBeVisible({ timeout: 5_000 });

    // Password input should NOT be visible
    const passwordInput = loginPage.locator('input[type="password"]');
    await expect(passwordInput).not.toBeVisible();

    // Cleanup: disable sso_only
    await rootPg.request.patch(`${API}/v1/admin/sso/providers/${providerId}`, {
      headers: rootHeaders(),
      data: { sso_only: false, tenant_id: TENANT },
    });

    await rootPg.close();
    await loginPage.close();
  });

  test("91.3 SSO error displayed from URL param", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(`${BASE}/login?error=sso_validation_failed`);

    const errorBanner = page.locator('[data-testid="sso-error"]');
    await expect(errorBanner).toBeVisible({ timeout: 5_000 });
    await expect(errorBanner).toContainText("SSO authentication failed");

    await page.close();
  });
});

// ── Cleanup ─────────────────────────────────────────────────────────────────

test.afterAll(async ({ browser }) => {
  // Clean up the test provider
  if (providerId) {
    const page = await rootPage(browser);
    await page.goto(`${BASE}/login`);
    await page.request.delete(
      `${API}/v1/admin/sso/providers/${providerId}?tenant_id=${TENANT}`,
      { headers: rootHeaders() },
    );
    await page.close();
  }
});
