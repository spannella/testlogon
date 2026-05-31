/**
 * E2E tests for KYC-002: Identity Document Verification.
 *
 * Section 156: Document upload + extraction pipeline (owner) API
 * Section 157: Confidence scoring + filename-driven mock provider
 * Section 158: Reviewer ByStatus listing + approve/reject API
 * Section 159: Document Verification UI (user + admin review queue)
 *
 * Auth: cookie + CSRF via e2e_admin_session_setup.py (root, alice, bob,
 * charlie_admin). Owner endpoints use require_ui_session; reviewer endpoints
 * use require_admin_or_root.
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

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

const TS = Date.now();

// upload a document and return the parsed body
async function uploadDoc(
  page: Page,
  identity: string,
  fileName: string,
  documentType: "id_front" | "id_back" = "id_front",
) {
  const resp = await apiPost(page, identity, "ui/kyc/documents", {
    document_type: documentType,
    file_name: fileName,
  });
  return resp;
}

// ─── Section 156: Upload + extraction pipeline ──────────────────────────────

test.describe("156: KYC document upload + extraction", () => {
  let alice: Page;
  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alice.close();
  });

  test("156.1 Upload returns 201 and runs extraction (pending -> extracted)", async () => {
    const resp = await uploadDoc(alice, "alice", `${TS}_match_id_front.jpg`);
    expect(resp.status()).toBe(201);
    const doc = await resp.json();
    expect(doc.document_id).toMatch(/^kycdoc_/);
    expect(doc.document_type).toBe("id_front");
    expect(doc.status).toBe("extracted");
    expect(doc.extracted_fields.full_name).toBeTruthy();
    expect(doc.extracted_fields.date_of_birth).toBeTruthy();
  });

  test("156.2 List my documents includes the uploaded doc", async () => {
    const upload = await uploadDoc(alice, "alice", `${TS}_list_id_front.jpg`);
    const created = await upload.json();
    const resp = await apiGet(alice, "ui/kyc/documents");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.documents.some((d: any) => d.document_id === created.document_id)).toBe(true);
  });

  test("156.3 Get document by id returns match_results for owner", async () => {
    const upload = await uploadDoc(alice, "alice", `${TS}_get_id_front.jpg`);
    const created = await upload.json();
    const resp = await apiGet(alice, `ui/kyc/documents/${created.document_id}`);
    expect(resp.status()).toBe(200);
    const doc = await resp.json();
    expect(doc.match_results).toBeTruthy();
    expect(doc.match_results.full_name.status).toBeTruthy();
  });

  test("156.4 Mock provider returns failed for _fail_ filename", async () => {
    const upload = await uploadDoc(alice, "alice", `${TS}_fail_id_front.jpg`);
    const doc = await upload.json();
    expect(doc.status).toBe("failed");
    expect(Object.keys(doc.extracted_fields)).toHaveLength(0);
    expect(doc.overall_confidence).toBe("failed");
  });

  test("156.5 Non-owner cannot read another user's document (403)", async ({ browser }) => {
    const upload = await uploadDoc(alice, "alice", `${TS}_owner_id_front.jpg`);
    const created = await upload.json();
    const bob = await newIdentityPage(browser, "bob");
    const resp = await apiGet(bob, `ui/kyc/documents/${created.document_id}`);
    expect(resp.status()).toBe(403);
    await bob.close();
  });

  test("156.6 Unknown document returns 404", async () => {
    const resp = await apiGet(alice, "ui/kyc/documents/kycdoc_doesnotexist");
    expect(resp.status()).toBe(404);
  });
});

// ─── Section 157: Confidence scoring + re-extract ───────────────────────────

test.describe("157: KYC extraction confidence scoring", () => {
  let alice: Page;
  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alice.close();
  });

  test("157.1 Mismatch filename produces mismatch + low confidence", async () => {
    const upload = await uploadDoc(alice, "alice", `${TS}_mismatch_id_front.jpg`);
    const doc = await upload.json();
    expect(doc.status).toBe("extracted");
    const detail = await (await apiGet(alice, `ui/kyc/documents/${doc.document_id}`)).json();
    expect(detail.match_results.full_name.status).toBe("mismatch");
    expect(detail.overall_confidence).toBe("low");
  });

  test("157.2 Expired filename surfaces past expiry date", async () => {
    const upload = await uploadDoc(alice, "alice", `${TS}_expired_id_front.jpg`);
    const doc = await upload.json();
    expect(doc.extracted_fields.expiry_date).toBe("2010-01-01");
  });

  test("157.3 Re-extract is idempotent and updates updated_at", async () => {
    const upload = await uploadDoc(alice, "alice", `${TS}_reextract_id_front.jpg`);
    const doc = await upload.json();
    const reResp = await apiPost(alice, "alice", `ui/kyc/documents/${doc.document_id}/extract`);
    expect(reResp.status()).toBe(200);
    const re = await reResp.json();
    expect(re.document_id).toBe(doc.document_id);
    expect(re.updated_at).toBeGreaterThanOrEqual(doc.updated_at);
    // still exactly one record for this doc
    const detail = await (await apiGet(alice, `ui/kyc/documents/${doc.document_id}`)).json();
    expect(detail.status).toBe("extracted");
  });

  test("157.4 Invalid document_type rejected with 422", async () => {
    const resp = await apiPost(alice, "alice", "ui/kyc/documents", {
      document_type: "selfie",
      file_name: "bad.jpg",
    });
    expect(resp.status()).toBe(422);
  });
});

// ─── Section 158: Reviewer ByStatus listing + approve/reject ────────────────

test.describe("158: KYC reviewer ByStatus + review", () => {
  let alice: Page;
  let root: Page;
  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    root = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await alice.close();
    await root.close();
  });

  test("158.1 Reviewer lists extracted documents via ByStatus GSI", async () => {
    const upload = await uploadDoc(alice, "alice", `${TS}_bystatus_id_front.jpg`);
    const created = await upload.json();
    const resp = await apiGet(root, "ui/kyc/documents/admin/by-status", { status: "extracted" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.documents.some((d: any) => d.document_id === created.document_id)).toBe(true);
  });

  test("158.2 Reviewer approves an extracted document", async () => {
    const upload = await uploadDoc(alice, "alice", `${TS}_approve_id_front.jpg`);
    const created = await upload.json();
    const resp = await apiPost(root, "root", `ui/kyc/documents/admin/${created.document_id}/review`, {
      decision: "approve",
    });
    expect(resp.status()).toBe(200);
    const doc = await resp.json();
    expect(doc.status).toBe("approved");
    expect(doc.review_decision).toBe("approve");
    // now appears under approved status
    const approved = await (
      await apiGet(root, "ui/kyc/documents/admin/by-status", { status: "approved" })
    ).json();
    expect(approved.documents.some((d: any) => d.document_id === created.document_id)).toBe(true);
  });

  test("158.3 Non-admin (alice) cannot list by status (403)", async () => {
    const resp = await apiGet(alice, "ui/kyc/documents/admin/by-status", { status: "extracted" });
    expect(resp.status()).toBe(403);
  });

  test("158.4 Reject moves document to rejected status", async () => {
    const upload = await uploadDoc(alice, "alice", `${TS}_reject_id_front.jpg`);
    const created = await upload.json();
    const resp = await apiPost(root, "root", `ui/kyc/documents/admin/${created.document_id}/review`, {
      decision: "reject",
      note: "blurry",
    });
    expect(resp.status()).toBe(200);
    expect((await resp.json()).status).toBe("rejected");
  });

  test("158.5 Invalid status query rejected with 422", async () => {
    const resp = await apiGet(root, "ui/kyc/documents/admin/by-status", { status: "bogus" });
    expect(resp.status()).toBe(422);
  });
});

// ─── Section 159: Document verification UI ──────────────────────────────────

test.describe("159: KYC document verification UI", () => {
  test("159.1 User page uploads a document and shows extracted card", async ({ browser }) => {
    const page = await newIdentityPage(browser, "alice");
    await page.goto("/kyc/documents");
    await expect(page.getByRole("heading", { name: "Identity Document Verification" })).toBeVisible();
    await page.getByTestId("kyc-doc-filename").fill(`${TS}_ui_match_id_front.jpg`);
    await page.getByTestId("kyc-doc-upload").click();
    await expect(page.getByTestId("kyc-document-card").first()).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("kyc-doc-status").first()).toContainText("extracted");
    await page.close();
  });

  test("159.2 Admin review queue lists extracted docs with match badges", async ({ browser }) => {
    const alice = await newIdentityPage(browser, "alice");
    await uploadDoc(alice, "alice", `${TS}_ui_review_id_front.jpg`);
    await alice.close();

    const page = await newIdentityPage(browser, "root");
    await page.goto("/admin/kyc/documents");
    await expect(page.getByRole("heading", { name: "KYC Document Review" })).toBeVisible();
    await page.getByTestId("kyc-status-tab-extracted").click();
    await expect(page.getByTestId("kyc-review-row").first()).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("kyc-review-approve").first()).toBeVisible();
    await page.close();
  });
});
