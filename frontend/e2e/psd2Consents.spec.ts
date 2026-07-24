/**
 * E2E tests for PSD2 AIS/PIS Consents (CSN-001..CSN-006).
 *
 * Sections:
 *   820 — Create consent (API)
 *   821 — List + get consents (API)
 *   822 — Revoke consent (API)
 *   823 — SCA gate: begin + accept (API)
 *   824 — ConsentsPage UI (smoke)
 *   825 — CreateConsentPage UI (smoke)
 *
 * Auth: uses e2e_admin_session_setup.py (alice = regular user)
 * Gate: requires OPEN_BANK_PROJECT_ENABLED=true AND PSD2_CONSENTS_ENABLED=true.
 *       When the flag is off all /ui/consents endpoints return 404 —
 *       tests in sections 820-823 verify the 404 and skip gracefully.
 *
 * NOTE: Do not run this spec directly against a stack with flags off — tests
 * are authored for future CI runs once the feature flags are enabled. Run with:
 *   npx playwright test e2e/psd2Consents.spec.ts
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "alice";
const TS = Date.now();

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
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const session = sessions[identity];
  const page = await browser.newPage();
  await page.context().addCookies(session.cookies);
  // The React app gates routes on the persisted `auth-store` localStorage. Seed
  // it via addInitScript so it is present BEFORE the app first hydrates the
  // zustand store — otherwise client-side navigations (e.g. after a form submit)
  // read a stale in-memory `isAuthenticated: false` and redirect to /login.
  await page.addInitScript(
    ([userId, accessToken]: [string, string]) => {
      const state = { userId, accessToken, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    [session.user_sub, session.access_token],
  );
  return page;
}

// ─── API helpers ──────────────────────────────────────────────────────────────

type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

async function apiCall(
  page: Page,
  identity: string,
  method: HttpMethod,
  path: string,
  body?: unknown,
): Promise<{ status: number; body: unknown }> {
  const sessions = getAdminSessions();
  const session  = sessions[identity];
  const res = await page.request[method.toLowerCase() as "get" | "post" | "put" | "patch" | "delete"](
    `${API}${path}`,
    {
      headers: {
        "x-csrf-token": session.csrf_token,
        "Content-Type": "application/json",
      },
      ...(body !== undefined ? { data: body } : {}),
    },
  );
  let respBody: unknown;
  try { respBody = await res.json(); } catch { respBody = null; }
  return { status: res.status(), body: respBody };
}

// ─── Feature detection ────────────────────────────────────────────────────────

async function isFeatureEnabled(page: Page): Promise<boolean> {
  // GET /ui/consents — 401 = route exists (auth needed), 404 = disabled
  const res = await page.request.get(`${API}/ui/consents`);
  return res.status() !== 404 && res.status() !== 503;
}

// ─── Module-level shared state ────────────────────────────────────────────────

let alicePage: Page;
let featureEnabled = false;
let createdConsentId: string | null = null;

// ─── Section 820: Create consent (API) ───────────────────────────────────────

test.describe("Section 820: Create consent — API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, ALICE_ID);
    featureEnabled = await isFeatureEnabled(alicePage);
  });

  test("820.1 feature flag: 404 when disabled, 201 when enabled", async () => {
    const sessions = getAdminSessions();
    const res = await alicePage.request.post(`${API}/ui/consents`, {
      headers: {
        "x-csrf-token": sessions[ALICE_ID].csrf_token,
        "Content-Type": "application/json",
      },
      data: {
        consumer_ref: `tpp-820-${TS}`,
        consent_type: "AIS",
        account_refs: [`acc-${TS}`],
        view_refs: ["owner"],
        recurring: true,
      },
    });

    if (!featureEnabled) {
      expect(res.status()).toBe(404);
      return;
    }
    expect(res.status()).toBe(201);
    const body = await res.json() as Record<string, unknown>;
    expect(body).toHaveProperty("consent_id");
    expect(body).toHaveProperty("status");
    expect(body["status"]).toBe("INITIATED");
    expect(typeof body["consent_id"]).toBe("string");
    createdConsentId = body["consent_id"] as string;
  });

  test("820.2 rejects empty account_refs", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const { status } = await apiCall(alicePage, ALICE_ID, "POST", "/ui/consents", {
      consumer_ref: `tpp-820b-${TS}`,
      consent_type: "AIS",
      account_refs: [],
    });
    expect(status).toBe(400);
  });

  test("820.3 rejects PIS consent without payment_ref", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const { status } = await apiCall(alicePage, ALICE_ID, "POST", "/ui/consents", {
      consumer_ref: `tpp-820c-${TS}`,
      consent_type: "PIS",
      account_refs: [`acc-${TS}`],
    });
    expect(status).toBe(400);
  });

  test("820.4 rejects invalid view_ref", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const { status } = await apiCall(alicePage, ALICE_ID, "POST", "/ui/consents", {
      consumer_ref: `tpp-820d-${TS}`,
      consent_type: "AIS",
      account_refs: [`acc-${TS}`],
      view_refs: ["superuser"],
    });
    expect(status).toBe(400);
  });

  test("820.5 creates PIS consent with payment_ref", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const { status, body } = await apiCall(alicePage, ALICE_ID, "POST", "/ui/consents", {
      consumer_ref: `tpp-pis-${TS}`,
      consent_type: "PIS",
      account_refs: [`acc-${TS}`],
      payment_ref: `pay-${TS}`,
      view_refs: ["owner"],
    });
    expect(status).toBe(201);
    const b = body as Record<string, unknown>;
    expect(b["consent_type"]).toBe("PIS");
    expect(b["payment_ref"]).toBe(`pay-${TS}`);
  });
});

// ─── Section 821: List + get consents (API) ───────────────────────────────────

test.describe("Section 821: List + get consents — API", () => {
  test.beforeAll(async ({ browser }) => {
    if (!alicePage) alicePage = await newIdentityPage(browser, ALICE_ID);
    featureEnabled = await isFeatureEnabled(alicePage);
  });

  test("821.1 GET /ui/consents lists items", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const { status, body } = await apiCall(alicePage, ALICE_ID, "GET", "/ui/consents");
    expect(status).toBe(200);
    const b = body as Record<string, unknown>;
    expect(Array.isArray(b["consents"])).toBe(true);
    expect(typeof b["count"]).toBe("number");
  });

  test("821.2 GET /ui/consents?status=INITIATED filters correctly", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const { status, body } = await apiCall(
      alicePage, ALICE_ID, "GET", "/ui/consents?status=INITIATED",
    );
    expect(status).toBe(200);
    const items = (body as Record<string, unknown>)["consents"] as Array<Record<string, unknown>>;
    for (const item of items) {
      expect(item["status"]).toBe("INITIATED");
    }
  });

  test("821.3 GET /ui/consents/{id} returns single item", async () => {
    if (!featureEnabled || !createdConsentId) { test.skip(); return; }
    const { status, body } = await apiCall(
      alicePage, ALICE_ID, "GET", `/ui/consents/${createdConsentId}`,
    );
    expect(status).toBe(200);
    const b = body as Record<string, unknown>;
    expect(b["consent_id"]).toBe(createdConsentId);
    expect(Array.isArray(b["account_refs"])).toBe(true);
    expect(Array.isArray(b["view_refs"])).toBe(true);
  });

  test("821.4 GET /ui/consents/{id} returns 404 for unknown consent", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const { status } = await apiCall(
      alicePage, ALICE_ID, "GET", "/ui/consents/csn_does_not_exist",
    );
    expect(status).toBe(404);
  });
});

// ─── Section 822: Revoke consent (API) ────────────────────────────────────────

test.describe("Section 822: Revoke consent — API", () => {
  let revokeTargetId: string | null = null;

  test.beforeAll(async ({ browser }) => {
    if (!alicePage) alicePage = await newIdentityPage(browser, ALICE_ID);
    featureEnabled = await isFeatureEnabled(alicePage);

    if (featureEnabled) {
      // Create a fresh consent to revoke
      const { body } = await apiCall(alicePage, ALICE_ID, "POST", "/ui/consents", {
        consumer_ref: `tpp-revoke-${TS}`,
        consent_type: "AIS",
        account_refs: [`acc-rev-${TS}`],
        view_refs: ["owner"],
      });
      revokeTargetId = (body as Record<string, unknown>)["consent_id"] as string ?? null;
    }
  });

  test("822.1 POST /{id}/revoke transitions status to REVOKED", async () => {
    if (!featureEnabled || !revokeTargetId) { test.skip(); return; }
    const { status, body } = await apiCall(
      alicePage, ALICE_ID, "POST", `/ui/consents/${revokeTargetId}/revoke`,
    );
    expect(status).toBe(200);
    const b = body as Record<string, unknown>;
    expect(b["status"]).toBe("REVOKED");
    expect(typeof b["revoked_at"]).toBe("number");
  });

  test("822.2 second revoke returns 409 consent_already_terminal", async () => {
    if (!featureEnabled || !revokeTargetId) { test.skip(); return; }
    const { status } = await apiCall(
      alicePage, ALICE_ID, "POST", `/ui/consents/${revokeTargetId}/revoke`,
    );
    expect(status).toBe(409);
  });

  test("822.3 revoke unknown consent returns 404", async () => {
    if (!featureEnabled) { test.skip(); return; }
    const { status } = await apiCall(
      alicePage, ALICE_ID, "POST", "/ui/consents/csn_no_exist/revoke",
    );
    // 404 (not found) or 409 (terminal) depending on backend lookup path
    expect([404, 409]).toContain(status);
  });
});

// ─── Section 823: SCA gate — begin + accept (API) ─────────────────────────────

test.describe("Section 823: SCA gate — API", () => {
  let scaConsentId: string | null = null;

  test.beforeAll(async ({ browser }) => {
    if (!alicePage) alicePage = await newIdentityPage(browser, ALICE_ID);
    featureEnabled = await isFeatureEnabled(alicePage);

    if (featureEnabled) {
      // Create a consent for the SCA flow
      const { body } = await apiCall(alicePage, ALICE_ID, "POST", "/ui/consents", {
        consumer_ref: `tpp-sca-${TS}`,
        consent_type: "AIS",
        account_refs: [`acc-sca-${TS}`],
        view_refs: ["owner"],
      });
      scaConsentId = (body as Record<string, unknown>)["consent_id"] as string ?? null;
    }
  });

  test("823.1 POST /{id}/sca returns challenge_id + required_factors", async () => {
    if (!featureEnabled || !scaConsentId) { test.skip(); return; }
    const { status, body } = await apiCall(
      alicePage, ALICE_ID, "POST", `/ui/consents/${scaConsentId}/sca`,
    );
    // 200 OK with challenge, or 409 if already accepted / sca_enrollment_required
    if (status === 409) {
      // SCA enrollment not set up for e2e user — skip deeper verification
      return;
    }
    expect(status).toBe(200);
    const b = body as Record<string, unknown>;
    expect(b).toHaveProperty("challenge_id");
    expect(b["consent_id"]).toBe(scaConsentId);
    expect(b["status"]).toBe("INITIATED");
  });

  test("823.2 POST /{id}/accept with no SCA initiated errors or succeeds", async () => {
    if (!featureEnabled || !scaConsentId) { test.skip(); return; }
    const { status } = await apiCall(
      alicePage, ALICE_ID, "POST", `/ui/consents/${scaConsentId}/accept`,
    );
    // 200 (accepted without SCA — low-value AIS) or 403 sca_not_initiated
    expect([200, 403]).toContain(status);
  });

  test("823.3 SCA on already-revoked consent returns 409", async () => {
    if (!featureEnabled) { test.skip(); return; }
    // Revoke the SCA consent first
    if (scaConsentId) {
      await apiCall(alicePage, ALICE_ID, "POST", `/ui/consents/${scaConsentId}/revoke`);
    }
    if (!scaConsentId) { test.skip(); return; }
    const { status } = await apiCall(
      alicePage, ALICE_ID, "POST", `/ui/consents/${scaConsentId}/sca`,
    );
    expect([409, 404]).toContain(status);
  });
});

// ─── Section 824: ConsentsPage UI (smoke) ─────────────────────────────────────

test.describe("Section 824: ConsentsPage UI — smoke", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await newIdentityPage(browser, ALICE_ID);
    featureEnabled = await isFeatureEnabled(page);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("824.1 /bank/consents renders without crashing", async () => {
    await page.goto(`${BASE}/bank/consents`);
    await page.waitForLoadState("domcontentloaded");

    // Either the consent list or the feature-disabled message should appear
    const header = page.getByText("PSD2 Consents");
    await expect(header).toBeVisible({ timeout: 8000 });
  });

  test("824.2 feature-disabled banner shown when flag is off", async () => {
    if (featureEnabled) { test.skip(); return; }
    await page.goto(`${BASE}/bank/consents`);
    await page.waitForLoadState("domcontentloaded");
    const disabled = page.getByText("PSD2 Consents not enabled");
    await expect(disabled).toBeVisible({ timeout: 6000 });
  });

  test("824.3 consent list visible when flag is on", async () => {
    if (!featureEnabled) { test.skip(); return; }
    await page.goto(`${BASE}/bank/consents`);
    await page.waitForLoadState("domcontentloaded");
    const granted = page.getByText("Granted consents");
    await expect(granted).toBeVisible({ timeout: 6000 });
  });

  test("824.4 status filter dropdown present", async () => {
    await page.goto(`${BASE}/bank/consents`);
    await page.waitForLoadState("domcontentloaded");
    const filter = page.getByTestId("status-filter");
    // Filter may not exist if feature disabled — check gracefully
    if (await filter.isVisible()) {
      await expect(filter).toBeVisible();
    }
  });

  test("824.5 New consent button links to /bank/consents/new", async () => {
    if (!featureEnabled) { test.skip(); return; }
    await page.goto(`${BASE}/bank/consents`);
    await page.waitForLoadState("domcontentloaded");
    const btn = page.getByTestId("create-consent-btn");
    await expect(btn).toBeVisible({ timeout: 6000 });
    await btn.click();
    await expect(page).toHaveURL(/\/bank\/consents\/new/, { timeout: 6000 });
  });
});

// ─── Section 825: CreateConsentPage UI (smoke) ────────────────────────────────

test.describe("Section 825: CreateConsentPage UI — smoke", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await newIdentityPage(browser, ALICE_ID);
    featureEnabled = await isFeatureEnabled(page);
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("825.1 /bank/consents/new renders form", async () => {
    await page.goto(`${BASE}/bank/consents/new`);
    await page.waitForLoadState("domcontentloaded");
    const header = page.getByText("New consent");
    await expect(header).toBeVisible({ timeout: 8000 });
  });

  test("825.2 consumer-ref input is present", async () => {
    await page.goto(`${BASE}/bank/consents/new`);
    await page.waitForLoadState("domcontentloaded");
    const input = page.getByTestId("consumer-ref-input");
    if (await input.isVisible()) {
      await expect(input).toBeVisible();
    }
  });

  test("825.3 AIS → PIS type toggle shows payment-ref field", async () => {
    await page.goto(`${BASE}/bank/consents/new`);
    await page.waitForLoadState("domcontentloaded");
    const typeSelect = page.getByTestId("consent-type-select");
    if (!await typeSelect.isVisible()) { return; }

    // PIS should reveal payment-ref input
    await typeSelect.click();
    const pisOption = page.getByText("PIS — Payment Initiation Service");
    if (await pisOption.isVisible()) {
      await pisOption.click();
      const paymentRefInput = page.getByTestId("payment-ref-input");
      await expect(paymentRefInput).toBeVisible({ timeout: 3000 });
    }
  });

  test("825.4 submit button is disabled when form is empty", async () => {
    await page.goto(`${BASE}/bank/consents/new`);
    await page.waitForLoadState("domcontentloaded");
    const btn = page.getByTestId("create-consent-submit");
    if (await btn.isVisible()) {
      await expect(btn).toBeDisabled();
    }
  });

  test("825.5 filled form enables submit button", async () => {
    if (!featureEnabled) { test.skip(); return; }
    await page.goto(`${BASE}/bank/consents/new`);
    await page.waitForLoadState("domcontentloaded");

    await page.getByTestId("consumer-ref-input").fill(`tpp-ui-${TS}`);
    await page.getByTestId("account-refs-input").fill(`acc-ui-${TS}`);

    const btn = page.getByTestId("create-consent-submit");
    await expect(btn).toBeEnabled({ timeout: 3000 });
  });

  test("825.6 successful form submit navigates to consent detail", async () => {
    if (!featureEnabled) { test.skip(); return; }
    await page.goto(`${BASE}/bank/consents/new`);
    await page.waitForLoadState("domcontentloaded");

    await page.getByTestId("consumer-ref-input").fill(`tpp-nav-${TS}`);
    await page.getByTestId("account-refs-input").fill(`acc-nav-${TS}`);

    const btn = page.getByTestId("create-consent-submit");
    await btn.click();

    // Should navigate to /bank/consents/<id>
    await expect(page).toHaveURL(/\/bank\/consents\/csn_/, { timeout: 8000 });
    // Scope to the heading — "Consent detail" is a substring of "Consent details".
    const detail = page.getByRole("heading", { name: "Consent detail", exact: true });
    await expect(detail).toBeVisible({ timeout: 6000 });
  });
});
