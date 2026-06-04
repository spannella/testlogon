/**
 * E2E tests for KYC-004: Proof of Residency Verification.
 *
 * Section 167: Residency upload + extraction/recency lifecycle (owner) API
 * Section 168: Address matching (deterministic mock extractor, filename-keyed)
 * Section 169: Reviewer ByStatus listing + approve/reject + access control
 *
 * Auth: cookie + CSRF via e2e_admin_session_setup.py (root, alice, bob,
 * charlie_admin). Owner endpoints use require_ui_session; reviewer endpoints
 * use require_admin_or_root.
 *
 * The deterministic mock extractor (app/services/kyc_residency.py) keys off the
 * uploaded file name:
 *   default            -> canonical matching address
 *   *_mismatchcity_*   -> different city  (=> mismatch => rejected)
 *   *_partial_*        -> different line1  (=> partial => verified)
 *   *_statecode_*      -> state "CA"
 *   *_zipplus4_*       -> postal "94105-1234"
 * The document_date drives the recency lifecycle (default window: 90 days).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";

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
  await page.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, getSessions()[identity].user_sub);
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

const TS = Date.now();

// canonical profile address used by the deterministic mock extractor
const ALICE_ADDRESS = {
  line1: "123 Main Street",
  line2: "Apartment 4B",
  city: "San Francisco",
  state: "California",
  postal_code: "94105",
  country: "US",
};

function isoDaysAgo(days: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - days);
  return d.toISOString().slice(0, 10);
}

async function uploadDoc(
  page: Page,
  identity: string,
  opts: {
    fileName: string;
    documentType?: string;
    issuingEntity?: string;
    documentDate?: string;
  },
) {
  return apiPost(page, identity, "ui/kyc/residency", {
    document_type: opts.documentType ?? "utility_bill",
    issuing_entity: opts.issuingEntity ?? "Pacific Gas & Electric",
    document_date: opts.documentDate ?? isoDaysAgo(30),
    file_name: opts.fileName,
  });
}

// ─── Section 167: Upload + extraction/recency lifecycle ─────────────────────

test.describe("167: KYC residency upload + extraction", () => {
  let alice: Page;
  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    // ensure Alice's profile address matches the deterministic mock extractor
    await apiPut(alice, "alice", "ui/profile", { mailing_address: ALICE_ADDRESS });
  });
  test.afterAll(async () => {
    await alice.close();
  });

  test("167.1 Upload utility bill -> verified with matching address", async () => {
    const resp = await uploadDoc(alice, "alice", { fileName: `${TS}_match.pdf` });
    expect(resp.status()).toBe(201);
    const doc = await resp.json();
    expect(doc.document_id).toMatch(/^kycres_/);
    expect(doc.document_type).toBe("utility_bill");
    expect(doc.recency_valid).toBe(true);
    expect(doc.status).toBe("verified");
    expect(doc.address_match.status).toBe("match");
  });

  test("167.2 Lease agreement accepted as a distinct document type", async () => {
    const resp = await uploadDoc(alice, "alice", {
      fileName: `${TS}_lease.pdf`,
      documentType: "lease_agreement",
      issuingEntity: "Riverside Property Management",
      documentDate: isoDaysAgo(10),
    });
    expect(resp.status()).toBe(201);
    const doc = await resp.json();
    expect(doc.document_type).toBe("lease_agreement");
    expect(doc.recency_valid).toBe(true);
  });

  test("167.3 Document older than the window is flagged expired", async () => {
    const resp = await uploadDoc(alice, "alice", {
      fileName: `${TS}_old.pdf`,
      documentType: "bank_statement",
      issuingEntity: "Acme Bank",
      documentDate: isoDaysAgo(120),
    });
    expect(resp.status()).toBe(201);
    const doc = await resp.json();
    expect(doc.recency_valid).toBe(false);
    expect(doc.recency_days).toBe(120);
    expect(doc.status).toBe("expired");
  });

  test("167.4 Document at the window boundary is still recent", async () => {
    const resp = await uploadDoc(alice, "alice", {
      fileName: `${TS}_boundary.pdf`,
      documentDate: isoDaysAgo(90),
    });
    expect(resp.status()).toBe(201);
    const doc = await resp.json();
    expect(doc.recency_days).toBe(90);
    expect(doc.recency_valid).toBe(true);
  });

  test("167.5 Invalid document_type rejected with 422", async () => {
    const resp = await apiPost(alice, "alice", "ui/kyc/residency", {
      document_type: "passport",
      issuing_entity: "Gov",
      document_date: isoDaysAgo(5),
      file_name: `${TS}_badtype.pdf`,
    });
    expect(resp.status()).toBe(422);
  });

  test("167.6 Invalid document_date format rejected with 422", async () => {
    const resp = await apiPost(alice, "alice", "ui/kyc/residency", {
      document_type: "utility_bill",
      issuing_entity: "PG&E",
      document_date: "May 15, 2026",
      file_name: `${TS}_baddate.pdf`,
    });
    expect(resp.status()).toBe(422);
  });

  test("167.7 Re-running extraction is idempotent for the same document", async () => {
    const upload = await uploadDoc(alice, "alice", { fileName: `${TS}_reextract.pdf` });
    const doc = await upload.json();
    const re = await apiPost(alice, "alice", `ui/kyc/residency/${doc.document_id}/extract`);
    expect(re.status()).toBe(200);
    const reJson = await re.json();
    expect(reJson.document_id).toBe(doc.document_id);
    expect(reJson.updated_at).toBeGreaterThanOrEqual(doc.updated_at);
  });
});

// ─── Section 168: Address matching ──────────────────────────────────────────

test.describe("168: KYC residency address matching", () => {
  let alice: Page;
  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    await apiPut(alice, "alice", "ui/profile", { mailing_address: ALICE_ADDRESS });
  });
  test.afterAll(async () => {
    await alice.close();
  });

  test("168.1 Different city produces mismatch -> rejected", async () => {
    const resp = await uploadDoc(alice, "alice", {
      fileName: `${TS}_mismatchcity_.pdf`,
      issuingEntity: "LA Water",
    });
    const doc = await resp.json();
    expect(doc.address_match.status).toBe("mismatch");
    expect(doc.status).toBe("rejected");
  });

  test("168.2 Different street, same city/zip -> partial match (still verified)", async () => {
    const resp = await uploadDoc(alice, "alice", { fileName: `${TS}_partial_.pdf` });
    const doc = await resp.json();
    expect(doc.address_match.status).toBe("partial");
    expect(doc.address_match.field_matches.line1).toBe("mismatch");
    expect(doc.address_match.field_matches.city).toBe("match");
    expect(doc.status).toBe("verified");
  });

  test("168.3 State abbreviation matches full profile name", async () => {
    const resp = await uploadDoc(alice, "alice", { fileName: `${TS}_statecode_.pdf` });
    const doc = await resp.json();
    expect(doc.address_match.field_matches.state).toBe("match");
  });

  test("168.4 Postal code +4 extension matches the 5-digit profile code", async () => {
    const resp = await uploadDoc(alice, "alice", { fileName: `${TS}_zipplus4_.pdf` });
    const doc = await resp.json();
    expect(doc.address_match.field_matches.postal_code).toBe("match");
  });
});

// ─── Section 169: Reviewer ByStatus + review + access control ───────────────

test.describe("169: KYC residency reviewer + access control", () => {
  let alice: Page;
  let root: Page;
  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    root = await newIdentityPage(browser, "root");
    await apiPut(alice, "alice", "ui/profile", { mailing_address: ALICE_ADDRESS });
  });
  test.afterAll(async () => {
    await alice.close();
    await root.close();
  });

  test("169.1 Owner can list their residency documents", async () => {
    const upload = await uploadDoc(alice, "alice", { fileName: `${TS}_list.pdf` });
    const created = await upload.json();
    const resp = await apiGet(alice, "ui/kyc/residency");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.documents.some((d: any) => d.document_id === created.document_id)).toBe(true);
  });

  test("169.2 Reviewer lists verified docs via ByStatus GSI and approves", async () => {
    const upload = await uploadDoc(alice, "alice", { fileName: `${TS}_review.pdf` });
    const created = await upload.json();
    expect(created.status).toBe("verified");

    const listResp = await apiGet(root, "ui/kyc/residency/admin/by-status", {
      status: "verified",
      limit: "200",
    });
    expect(listResp.status()).toBe(200);
    const list = await listResp.json();
    expect(list.documents.some((d: any) => d.document_id === created.document_id)).toBe(true);

    const reviewResp = await apiPost(
      root,
      "root",
      `ui/kyc/residency/admin/${created.document_id}/review`,
      { decision: "approve", note: "ok" },
    );
    expect(reviewResp.status()).toBe(200);
    const reviewed = await reviewResp.json();
    expect(reviewed.status).toBe("verified");
    expect(reviewed.review_decision).toBe("approve");
  });

  test("169.3 Non-admin (alice) cannot list by status (403)", async () => {
    const resp = await apiGet(alice, "ui/kyc/residency/admin/by-status", { status: "verified" });
    expect(resp.status()).toBe(403);
  });

  test("169.4 Non-owner cannot read another user's document (403)", async ({ browser }) => {
    const upload = await uploadDoc(alice, "alice", { fileName: `${TS}_owned.pdf` });
    const created = await upload.json();
    const bob = await newIdentityPage(browser, "bob");
    const resp = await apiGet(bob, `ui/kyc/residency/${created.document_id}`);
    expect(resp.status()).toBe(403);
    await bob.close();
  });

  test("169.5 Unknown document id returns 404", async () => {
    const resp = await apiGet(alice, "ui/kyc/residency/kycres_doesnotexist000");
    expect(resp.status()).toBe(404);
  });

  test("169.6 Invalid status query rejected with 422", async () => {
    const resp = await apiGet(root, "ui/kyc/residency/admin/by-status", { status: "bogus" });
    expect(resp.status()).toBe(422);
  });
});
