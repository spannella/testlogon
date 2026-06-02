/**
 * E2E tests for KYC-018: Address Verification Service.
 *
 * Section 790: Verify address API (deterministic mock postal provider)
 * Section 791: Postal-code validation + cross-reference (admin)
 * Section 792: Decision buckets, override, attempt history, auth (401/403)
 *
 * The service builds alongside KYC-004 (proof-of-residency) in a NEW
 * service + router (app/services/kyc_address_verification.py,
 * app/routers/kyc_address_verification.py, prefix /v1/kyc/address-verification).
 *
 * Deterministic mock provider (crc32/sha256, NOT builtin hash()):
 *   "123 Main St..."     -> verified,      confidence 1.0
 *   "456 Oak..."         -> partial_match,  confidence 0.75
 *   "999 Nonexistent..." -> unverifiable,   confidence 0.0
 *   missing street/city  -> unverifiable
 *   everything else      -> verified, deterministic confidence 0.85-0.99
 *
 * Auth: cookie + CSRF via e2e_admin_session_setup.py (root, alice, bob,
 * charlie_admin). User endpoints require_ui_session (owner or admin); admin
 * endpoints require_admin_or_root.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";

interface SessionData {
  user_sub: string;
  csrf_token: string;
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
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  await page.context().addCookies(getSessions()[identity].cookies);
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await injectAuth(page, identity);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}/${path}`);
}

const TS = Date.now();

const US_ADDRESS = {
  line_1: "123 Main St",
  line_2: "Apt 4B",
  city: "New York",
  state: "NY",
  postal_code: "10001",
  country: "US",
};

async function createCase(page: Page, identity: string): Promise<string> {
  const resp = await apiPost(page, identity, "v1/kyc/cases", {
    intake_profile: `addrverify_${TS}`,
  });
  expect(resp.status()).toBe(200);
  const data = await resp.json();
  return data.case.kyc_case_id as string;
}

const BASE = "v1/kyc/address-verification";

// ─── Section 790: Verify address API ────────────────────────────────────────

test.describe("790: KYC address verification API", () => {
  let alice: Page;
  let caseId: string;

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    caseId = await createCase(alice, "alice");
  });
  test.afterAll(async () => {
    await alice.close();
  });

  test("790.1 Verify valid US address returns verified status", async () => {
    const resp = await apiPost(alice, "alice", `${BASE}/cases/${caseId}/verify`, {
      address: US_ADDRESS,
    });
    expect(resp.status()).toBe(200);
    const { verification: v } = await resp.json();
    expect(v.status).toBe("verified");
    expect(v.confidence_score).toBeGreaterThanOrEqual(0.9);
    expect(v.decision).toBe("verified");
  });

  test("790.2 Partial-match address returns corrected standardized version", async () => {
    const resp = await apiPost(alice, "alice", `${BASE}/cases/${caseId}/verify`, {
      address: { ...US_ADDRESS, line_1: "456 Oak Ave", city: "Springfield", state: "IL", postal_code: "62704" },
    });
    expect(resp.status()).toBe(200);
    const { verification: v } = await resp.json();
    expect(v.status).toBe("partial_match");
    expect(v.confidence_score).toBeCloseTo(0.75, 2);
    expect(v.standardized_address).not.toBeNull();
    expect(v.discrepancies.length).toBeGreaterThan(0);
  });

  test("790.3 Unrecognized address returns unverifiable, confidence 0", async () => {
    const resp = await apiPost(alice, "alice", `${BASE}/cases/${caseId}/verify`, {
      address: { ...US_ADDRESS, line_1: "999 Nonexistent Rd" },
    });
    expect(resp.status()).toBe(200);
    const { verification: v } = await resp.json();
    expect(v.status).toBe("unverifiable");
    expect(v.confidence_score).toBe(0);
    expect(v.decision).toBe("failed");
  });

  test("790.4 Geocoding returns numeric lat/lng for verified address", async () => {
    const resp = await apiPost(alice, "alice", `${BASE}/cases/${caseId}/verify`, {
      address: US_ADDRESS,
    });
    const { verification: v } = await resp.json();
    expect(v.geocoding).not.toBeNull();
    expect(typeof v.geocoding.lat).toBe("number");
    expect(typeof v.geocoding.lng).toBe("number");
    expect(v.geocoding.lat).toBeGreaterThanOrEqual(-90);
    expect(v.geocoding.lat).toBeLessThanOrEqual(90);
  });

  test("790.5 Determinism: same address yields same confidence + geocoding", async () => {
    const addr = { ...US_ADDRESS, line_1: `${TS} Birch Lane`, city: "Austin", state: "TX", postal_code: "73301" };
    const r1 = await apiPost(alice, "alice", `${BASE}/cases/${caseId}/verify`, { address: addr });
    const r2 = await apiPost(alice, "alice", `${BASE}/cases/${caseId}/verify`, { address: addr });
    const v1 = (await r1.json()).verification;
    const v2 = (await r2.json()).verification;
    expect(v1.confidence_score).toBe(v2.confidence_score);
    expect(v1.geocoding.lat).toBe(v2.geocoding.lat);
    expect(v1.geocoding.lng).toBe(v2.geocoding.lng);
  });

  test("790.6 Standardized address uses uppercase formatting", async () => {
    const resp = await apiPost(alice, "alice", `${BASE}/cases/${caseId}/verify`, {
      address: { ...US_ADDRESS, line_1: "123 main st", city: "new york" },
    });
    const { verification: v } = await resp.json();
    expect(v.standardized_address.line_1).toBe(v.standardized_address.line_1.toUpperCase());
    expect(v.standardized_address.city).toBe("NEW YORK");
  });

  test("790.7 Malformed address (whitespace-only city) is unverifiable", async () => {
    // Single-space city passes pydantic min_length=1 but normalizes to empty,
    // so the provider returns unverifiable (missing required field).
    const resp = await apiPost(alice, "alice", `${BASE}/cases/${caseId}/verify`, {
      address: { line_1: "742 Evergreen Terrace", line_2: "", city: " ", state: "", postal_code: "10001", country: "US" },
    });
    expect(resp.status()).toBe(200);
    const { verification: v } = await resp.json();
    expect(v.status).toBe("unverifiable");
  });

  test("790.8 Re-verification overwrites latest result (GET returns newest)", async () => {
    await apiPost(alice, "alice", `${BASE}/cases/${caseId}/verify`, {
      address: { ...US_ADDRESS, line_1: "999 Nonexistent Rd" },
    });
    const getResp = await apiGet(alice, `${BASE}/cases/${caseId}`);
    expect(getResp.status()).toBe(200);
    const { verification: v } = await getResp.json();
    expect(v.status).toBe("unverifiable");
  });

  test("790.9 Verify on non-existent case returns 404", async () => {
    const resp = await apiPost(alice, "alice", `${BASE}/cases/kyc_doesnotexist/verify`, {
      address: US_ADDRESS,
    });
    expect(resp.status()).toBe(404);
  });
});

// ─── Section 791: Postal validation + cross-reference ───────────────────────

test.describe("791: KYC postal validation + cross-reference", () => {
  let alice: Page;
  let root: Page;
  let caseId: string;

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    root = await newIdentityPage(browser, "root");
    caseId = await createCase(alice, "alice");
    await apiPost(alice, "alice", `${BASE}/cases/${caseId}/verify`, { address: US_ADDRESS });
  });
  test.afterAll(async () => {
    await alice.close();
    await root.close();
  });

  test("791.1 US ZIP+4 validates", async () => {
    const resp = await apiPost(alice, "alice", `${BASE}/validate-postal-code`, {
      postal_code: "10001-1234",
      country: "US",
    });
    expect(resp.status()).toBe(200);
    expect((await resp.json()).valid).toBe(true);
  });

  test("791.2 UK postcode validates", async () => {
    const resp = await apiPost(alice, "alice", `${BASE}/validate-postal-code`, {
      postal_code: "SW1A 1AA",
      country: "GB",
    });
    expect((await resp.json()).valid).toBe(true);
  });

  test("791.3 Invalid US ZIP returns valid=false with hint", async () => {
    const resp = await apiPost(alice, "alice", `${BASE}/validate-postal-code`, {
      postal_code: "ABCDE",
      country: "US",
    });
    const data = await resp.json();
    expect(data.valid).toBe(false);
    expect(data.format_hint).toContain("5 digits");
  });

  test("791.4 German PLZ validates 5 digits", async () => {
    const resp = await apiPost(alice, "alice", `${BASE}/validate-postal-code`, {
      postal_code: "10115",
      country: "DE",
    });
    expect((await resp.json()).valid).toBe(true);
  });

  test("791.5 Canadian postal code validates", async () => {
    const resp = await apiPost(alice, "alice", `${BASE}/validate-postal-code`, {
      postal_code: "K1A 0B1",
      country: "CA",
    });
    expect((await resp.json()).valid).toBe(true);
  });

  test("791.6 Japanese postal code validates", async () => {
    const resp = await apiPost(alice, "alice", `${BASE}/validate-postal-code`, {
      postal_code: "100-0001",
      country: "JP",
    });
    expect((await resp.json()).valid).toBe(true);
  });

  test("791.7 Cross-reference matching addresses returns high score", async () => {
    const resp = await apiPost(root, "root", `${BASE}/cases/${caseId}/cross-reference`, {
      document_address: US_ADDRESS,
    });
    expect(resp.status()).toBe(200);
    const { cross_reference: cr } = await resp.json();
    expect(cr.match_score).toBeGreaterThanOrEqual(0.8);
    expect(cr.discrepancies.length).toBe(0);
  });

  test("791.8 Cross-reference mismatched postal returns discrepancy", async () => {
    const resp = await apiPost(root, "root", `${BASE}/cases/${caseId}/cross-reference`, {
      document_address: { ...US_ADDRESS, postal_code: "99999", city: "Boston" },
    });
    expect(resp.status()).toBe(200);
    const { cross_reference: cr } = await resp.json();
    expect(cr.match_score).toBeLessThan(0.8);
    expect(cr.discrepancies).toContain("postal_code_differs");
  });

  test("791.9 Non-admin cannot cross-reference (403)", async () => {
    const resp = await apiPost(alice, "alice", `${BASE}/cases/${caseId}/cross-reference`, {
      document_address: US_ADDRESS,
    });
    expect(resp.status()).toBe(403);
  });
});

// ─── Section 792: Decisions, override, history, auth ────────────────────────

test.describe("792: KYC address verification decisions + auth", () => {
  let alice: Page;
  let bob: Page;
  let root: Page;
  let caseId: string;

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    bob = await newIdentityPage(browser, "bob");
    root = await newIdentityPage(browser, "root");
    caseId = await createCase(alice, "alice");
    await apiPost(alice, "alice", `${BASE}/cases/${caseId}/verify`, { address: US_ADDRESS });
  });
  test.afterAll(async () => {
    await alice.close();
    await bob.close();
    await root.close();
  });

  test("792.1 Confidence + decision bucket present on result", async () => {
    const resp = await apiGet(alice, `${BASE}/cases/${caseId}`);
    const { verification: v } = await resp.json();
    expect(typeof v.confidence_score).toBe("number");
    expect(["verified", "needs_review", "failed"]).toContain(v.decision);
    expect(v.country_format_valid).toBe(true);
  });

  test("792.2 Attempt history lists multiple attempts (newest first)", async () => {
    await apiPost(alice, "alice", `${BASE}/cases/${caseId}/verify`, {
      address: { ...US_ADDRESS, line_1: "999 Nonexistent Rd" },
    });
    const resp = await apiGet(alice, `${BASE}/cases/${caseId}/attempts`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.attempts.length).toBeGreaterThanOrEqual(2);
    expect(data.attempts[0].status).toBe("unverifiable");
  });

  test("792.3 Admin override sets decision", async () => {
    const resp = await apiPost(root, "root", `${BASE}/cases/${caseId}/override`, {
      decision: "verified",
      note: "manually confirmed",
    });
    expect(resp.status()).toBe(200);
    const { verification: v } = await resp.json();
    expect(v.decision).toBe("verified");
    expect(v.override).not.toBeNull();
    expect(v.override.decision).toBe("verified");
  });

  test("792.4 Non-admin cannot override (403)", async () => {
    const resp = await apiPost(alice, "alice", `${BASE}/cases/${caseId}/override`, {
      decision: "failed",
    });
    expect(resp.status()).toBe(403);
  });

  test("792.5 Non-owner cannot verify another user's case (403)", async () => {
    const resp = await apiPost(bob, "bob", `${BASE}/cases/${caseId}/verify`, {
      address: US_ADDRESS,
    });
    expect(resp.status()).toBe(403);
  });

  test("792.6 Unauthenticated request returns 401", async ({ request }) => {
    const resp = await request.post(`${API}/${BASE}/cases/${caseId}/verify`, {
      data: { address: US_ADDRESS },
      headers: { "Content-Type": "application/json" },
    });
    expect(resp.status()).toBe(401);
  });

  test("792.7 Verify with empty line_2 succeeds", async () => {
    const resp = await apiPost(alice, "alice", `${BASE}/cases/${caseId}/verify`, {
      address: { ...US_ADDRESS, line_2: "" },
    });
    expect(resp.status()).toBe(200);
    expect((await resp.json()).verification.status).toBe("verified");
  });

  test("792.8 Unsupported country uses generic postal validation", async () => {
    // country must be 2 chars (pydantic); "ZZ" is unknown -> generic validation
    const resp = await apiPost(alice, "alice", `${BASE}/cases/${caseId}/verify`, {
      address: { ...US_ADDRESS, country: "ZZ" },
    });
    expect(resp.status()).toBe(200);
    const { verification: v } = await resp.json();
    // generic: non-empty postal accepted
    expect(v.country).toBe("ZZ");
    expect(v.country_format_valid).toBe(true);
  });
});
