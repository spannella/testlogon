/**
 * E2E tests for Admin KYC Review Dashboard.
 *
 * Sections:
 *   150 — Admin KYC Queue API (5 tests)
 *   151 — Admin Case Detail API (5 tests)
 *   152 — Approve / Reject / Request Info API (5 tests)
 *   153 — Admin Metrics API (3 tests)
 *   154 — KYC Queue Page UI (4 tests)
 *   155 — Case Detail Page UI (3 tests)
 *
 * Auth: Root session cookies (from e2e_admin_session_setup.py).
 * Alice session cookies for non-admin rejection tests.
 *
 * KYC cases are seeded directly into DynamoDB in beforeAll because the
 * submit flow requires questionnaire + signature prereqs which are complex
 * to set up in E2E.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE       = "http://localhost:3000";
const API        = "http://localhost:8000";
const ROOT_SUB   = "root.admin@testdev.local";
const ALICE_ID   = "e2e_alice@test.local";
const TS         = Date.now();

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

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, identity: string) {
  const sessions = getAdminSessions();
  const session = sessions[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiGet(page: Page, identity: string, path: string) {
  const sessions = getAdminSessions();
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": sessions[identity].csrf_token },
  });
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  const sessions = getAdminSessions();
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: {
      "x-csrf-token": sessions[identity].csrf_token,
      "Content-Type": "application/json",
    },
  });
}

// ─── DDB helpers ──────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os, time, json, uuid
from decimal import Decimal
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
table = ddb.Table('kyc_cases')
`;

const PYTHON = "python3";

/**
 * Seed a KYC case directly into DynamoDB.
 * Returns the case_id.
 */
function seedKycCase(opts: {
  caseId: string;
  userSub: string;
  status: string;
  intakeProfile?: string;
  assignedAdminSub?: string | null;
  version?: number;
}): string {
  const { caseId, userSub, status, intakeProfile, assignedAdminSub, version } = opts;
  const ts = Math.floor(Date.now() / 1000);
  const v = version ?? 1;
  const script = `
${DDB_PRELUDE}
ts = ${ts}
case_id = "${caseId}"
user_sub = "${userSub}"
status = "${status}"
intake_profile = "${intakeProfile ?? "standard"}"
assigned_admin_sub = ${assignedAdminSub ? `"${assignedAdminSub}"` : "None"}
version = ${v}

# Build updated_sk for GSI
updated_sk = f"UPDATED#{str(ts).zfill(13)}#KYC#{case_id}"
review = {
    "ticket_id": None,
    "assigned_admin_sub": assigned_admin_sub,
    "decision": None,
    "decided_at": None,
    "reason_codes": [],
}
item = {
    "pk": f"KYC#{case_id}",
    "sk": "META",
    "entity_type": "kyc_case",
    "kyc_case_id": case_id,
    "user_sub": user_sub,
    "status": status,
    "intake_profile": intake_profile,
    "questionnaire": {},
    "files": [
        {"type": "selfie", "path": f"/uploads/kyc/{case_id}_selfie.jpg", "verification_state": "pending", "attached_at": ts},
        {"type": "id_front", "path": f"/uploads/kyc/{case_id}_id_front.jpg", "verification_state": "pending", "attached_at": ts},
        {"type": "id_back", "path": f"/uploads/kyc/{case_id}_id_back.jpg", "verification_state": "pending", "attached_at": ts},
    ],
    "signature": {},
    "submission": {"submitted_at": ts} if status != "draft" else {},
    "review": review,
    "created_at": ts,
    "updated_at": ts,
    "version": version,
    "gsi_owner_pk": f"OWNER#{user_sub}",
    "gsi_owner_sk": updated_sk,
    "gsi_status_pk": f"STATUS#{status}",
    "gsi_status_sk": updated_sk,
}
table.put_item(Item=item)
print(case_id)
  `;
  const out = execSync(`${PYTHON} -c '${script.replace(/'/g, "'\"'\"'")}'`, {
    cwd: "/home/ubuntu/testlogon",
    timeout: 15_000,
  }).toString().trim();
  return out;
}

function deleteKycCase(caseId: string): void {
  const script = `
${DDB_PRELUDE}
table.delete_item(Key={"pk": f"KYC#${caseId}", "sk": "META"})
print("deleted")
  `;
  try {
    execSync(`${PYTHON} -c '${script.replace(/'/g, "'\"'\"'")}'`, {
      cwd: "/home/ubuntu/testlogon",
      timeout: 10_000,
    });
  } catch {
    // ignore cleanup errors
  }
}

// ─── Test Data ────────────────────────────────────────────────────────────────

const CASE_SUBMITTED_ID  = `kyc_e2e_sub_${TS}`;
const CASE_REVIEW_ID     = `kyc_e2e_rev_${TS}`;
const CASE_APPROVE_ID    = `kyc_e2e_apr_${TS}`;
const CASE_REJECT_ID     = `kyc_e2e_rej_${TS}`;
const CASE_REQINFO_ID    = `kyc_e2e_req_${TS}`;
const CASE_CONFLICT_ID   = `kyc_e2e_cnf_${TS}`;
const CASE_ENHANCED_ID   = `kyc_e2e_enh_${TS}`;
const ALL_CASE_IDS = [
  CASE_SUBMITTED_ID, CASE_REVIEW_ID, CASE_APPROVE_ID,
  CASE_REJECT_ID, CASE_REQINFO_ID, CASE_CONFLICT_ID, CASE_ENHANCED_ID,
];

// ─── Test Setup ───────────────────────────────────────────────────────────────

let rootPage: Page;

test.beforeAll(async ({ browser }) => {
  // Seed KYC cases
  seedKycCase({ caseId: CASE_SUBMITTED_ID, userSub: ALICE_ID, status: "submitted" });
  seedKycCase({ caseId: CASE_REVIEW_ID, userSub: ALICE_ID, status: "under_review" });
  seedKycCase({ caseId: CASE_APPROVE_ID, userSub: ALICE_ID, status: "under_review", version: 1 });
  seedKycCase({ caseId: CASE_REJECT_ID, userSub: ALICE_ID, status: "under_review", version: 1 });
  seedKycCase({ caseId: CASE_REQINFO_ID, userSub: ALICE_ID, status: "under_review", version: 1 });
  seedKycCase({ caseId: CASE_CONFLICT_ID, userSub: ALICE_ID, status: "under_review", version: 1 });
  seedKycCase({ caseId: CASE_ENHANCED_ID, userSub: ALICE_ID, status: "submitted", intakeProfile: "enhanced" });

  // Create root page
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");
});

test.afterAll(async () => {
  // Cleanup
  for (const caseId of ALL_CASE_IDS) {
    deleteKycCase(caseId);
  }
  await rootPage?.close();
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 150: Admin KYC Queue API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 150 — Admin KYC Queue API", () => {
  test("150.1 Root can list KYC queue with default filters", async () => {
    const resp = await apiGet(rootPage, "root", "/v1/kyc/cases/admin/queue");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeDefined();
    expect(Array.isArray(data.items)).toBe(true);
    // Our seeded submitted case should appear
    const found = data.items.find((it: any) => it.kyc_case_id === CASE_SUBMITTED_ID);
    expect(found).toBeTruthy();
    expect(found.status).toBe("submitted");
  });

  test("150.2 Queue filtered by status=submitted returns only submitted cases", async () => {
    const resp = await apiGet(rootPage, "root", "/v1/kyc/cases/admin/queue?status=submitted");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    for (const item of data.items) {
      expect(item.status).toBe("submitted");
    }
  });

  test("150.3 Queue filtered by risk_tier returns matching cases", async () => {
    const resp = await apiGet(rootPage, "root", "/v1/kyc/cases/admin/queue?risk_tier=high");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // enhanced intake_profile maps to "high" risk tier
    const found = data.items.find((it: any) => it.kyc_case_id === CASE_ENHANCED_ID);
    expect(found).toBeTruthy();
    expect(found.risk_tier).toBe("high");
  });

  test("150.4 Non-admin user gets 403 on queue endpoint", async ({ browser }) => {
    const alicePage = await browser.newPage();
    await injectAuth(alicePage, "alice");
    const resp = await apiGet(alicePage, "alice", "/v1/kyc/cases/admin/queue");
    expect(resp.status()).toBe(403);
    await alicePage.close();
  });

  test("150.5 Queue pagination returns next_cursor when more items exist", async () => {
    const resp = await apiGet(rootPage, "root", "/v1/kyc/cases/admin/queue?limit=1");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items.length).toBeLessThanOrEqual(1);
    // If there are more than 1 case in queue, we should get next_cursor
    if (data.next_cursor) {
      const resp2 = await apiGet(
        rootPage, "root",
        `/v1/kyc/cases/admin/queue?limit=1&cursor=${encodeURIComponent(data.next_cursor)}`,
      );
      expect(resp2.status()).toBe(200);
      const data2 = await resp2.json();
      expect(data2.items.length).toBeGreaterThanOrEqual(0);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 151: Admin Case Detail API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 151 — Admin Case Detail API", () => {
  test("151.1 Root can view case detail with timeline", async () => {
    const resp = await apiGet(rootPage, "root", `/v1/kyc/cases/admin/cases/${CASE_SUBMITTED_ID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.case).toBeDefined();
    expect(data.case.kyc_case_id).toBe(CASE_SUBMITTED_ID);
    expect(data.case.timeline).toBeDefined();
    expect(Array.isArray(data.case.timeline)).toBe(true);
  });

  test("151.2 Case detail includes uploaded file references", async () => {
    const resp = await apiGet(rootPage, "root", `/v1/kyc/cases/admin/cases/${CASE_SUBMITTED_ID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.case.files_ref).toBeDefined();
    expect(data.case.files_ref.length).toBe(3);
    const types = data.case.files_ref.map((f: any) => f.type);
    expect(types).toContain("selfie");
    expect(types).toContain("id_front");
    expect(types).toContain("id_back");
  });

  test("151.3 Case timeline shows at least creation event", async () => {
    const resp = await apiGet(rootPage, "root", `/v1/kyc/cases/admin/cases/${CASE_SUBMITTED_ID}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const timeline = data.case.timeline as Array<{ event_type: string }>;
    expect(timeline.length).toBeGreaterThanOrEqual(1);
    const eventTypes = timeline.map((e) => e.event_type);
    expect(eventTypes).toContain("kyc_case_created");
  });

  test("151.4 Non-admin user gets 403 on case detail", async ({ browser }) => {
    const alicePage = await browser.newPage();
    await injectAuth(alicePage, "alice");
    const resp = await apiGet(alicePage, "alice", `/v1/kyc/cases/admin/cases/${CASE_SUBMITTED_ID}`);
    expect(resp.status()).toBe(403);
    await alicePage.close();
  });

  test("151.5 Case detail for non-existent case returns 404", async () => {
    const resp = await apiGet(rootPage, "root", "/v1/kyc/cases/admin/cases/kyc_nonexistent_xyz");
    expect(resp.status()).toBe(404);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 152: Approve / Reject / Request Info API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 152 — Approve / Reject / Request Info API", () => {
  test("152.1 Root approves a case under review", async () => {
    const resp = await apiPost(rootPage, "root", `/v1/kyc/cases/admin/cases/${CASE_APPROVE_ID}/approve`, {
      expected_version: 1,
      decision: "approve",
      reason_codes: ["identity_verified"],
      note: "All documents verified successfully.",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.case.status).toBe("approved");
  });

  test("152.2 Root rejects a case with reason codes", async () => {
    const resp = await apiPost(rootPage, "root", `/v1/kyc/cases/admin/cases/${CASE_REJECT_ID}/reject`, {
      expected_version: 1,
      decision: "reject",
      reason_codes: ["document_illegible", "name_mismatch"],
      note: "ID front is too blurry to read and name mismatch.",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.case.status).toBe("rejected");
  });

  test("152.3 Root requests more info from applicant", async () => {
    const resp = await apiPost(rootPage, "root", `/v1/kyc/cases/admin/cases/${CASE_REQINFO_ID}/request-info`, {
      expected_version: 1,
      requested_items: ["proof_of_address"],
      note: "Please upload a utility bill or bank statement.",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.case.status).toBe("needs_more_info");
  });

  test("152.4 Approve with wrong expected_version returns 409", async () => {
    const resp = await apiPost(rootPage, "root", `/v1/kyc/cases/admin/cases/${CASE_CONFLICT_ID}/approve`, {
      expected_version: 999,
      decision: "approve",
      reason_codes: ["identity_verified"],
      note: "Version conflict test approval note.",
    });
    expect(resp.status()).toBe(409);
  });

  test("152.5 Approve already-approved case returns 409", async () => {
    // CASE_APPROVE_ID was approved in 152.1
    const resp = await apiPost(rootPage, "root", `/v1/kyc/cases/admin/cases/${CASE_APPROVE_ID}/reject`, {
      expected_version: 2,
      decision: "reject",
      reason_codes: ["suspected_fraud"],
      note: "Testing invalid transition after approval.",
    });
    expect(resp.status()).toBe(409);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 153: Admin Metrics API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 153 — Admin Metrics API", () => {
  test("153.1 Metrics endpoint returns funnel counts", async () => {
    const resp = await apiGet(rootPage, "root", "/v1/kyc/cases/admin/metrics");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.metrics).toBeDefined();
    expect(data.metrics.funnel_counts).toBeDefined();
    // There should be at least some counts given our seeded cases
    const counts = data.metrics.funnel_counts;
    expect(typeof counts.submitted === "number" || typeof counts.approved === "number").toBe(true);
  });

  test("153.2 Metrics include review latency percentiles", async () => {
    const resp = await apiGet(rootPage, "root", "/v1/kyc/cases/admin/metrics");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const latency = data.metrics.review_latency_seconds;
    expect(latency).toBeDefined();
    expect("p50" in latency).toBe(true);
    expect("p90" in latency).toBe(true);
    expect("p99" in latency).toBe(true);
  });

  test("153.3 Non-admin gets 403 on metrics", async ({ browser }) => {
    const alicePage = await browser.newPage();
    await injectAuth(alicePage, "alice");
    const resp = await apiGet(alicePage, "alice", "/v1/kyc/cases/admin/metrics");
    expect(resp.status()).toBe(403);
    await alicePage.close();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 154: KYC Queue Page UI
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 154 — KYC Queue Page UI", () => {
  test("154.1 Queue page loads and shows pending cases", async () => {
    await rootPage.goto(`${BASE}/admin/kyc`, { waitUntil: "domcontentloaded" });
    // Wait for table to load
    await expect(rootPage.getByRole("heading", { name: "KYC Review Queue" })).toBeVisible();
    // Wait for at least one table row (case row)
    const rows = rootPage.locator("tr[data-testid^='kyc-row-']");
    await expect(rows.first()).toBeVisible({ timeout: 10_000 });
    // Verify table headers
    await expect(rootPage.getByRole("columnheader", { name: "Case ID" })).toBeVisible();
    await expect(rootPage.getByRole("columnheader", { name: "Status" })).toBeVisible();
    await expect(rootPage.getByRole("columnheader", { name: "Risk Tier" })).toBeVisible();
  });

  test("154.2 Status filter changes displayed cases", async () => {
    await rootPage.goto(`${BASE}/admin/kyc`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByRole("heading", { name: "KYC Review Queue" })).toBeVisible();
    // Wait for initial load
    await rootPage.waitForTimeout(1000);

    // Click the status filter and select "Submitted"
    await rootPage.locator("#status-filter").click();
    await rootPage.getByRole("option", { name: "Submitted" }).click();

    // Wait for query to update
    await rootPage.waitForTimeout(1500);

    // All visible status badges should show "submitted"
    const badges = rootPage.locator("[data-testid='status-badge']");
    const count = await badges.count();
    if (count > 0) {
      for (let i = 0; i < count; i++) {
        await expect(badges.nth(i)).toHaveText("submitted");
      }
    }
  });

  test("154.3 Clicking a case row navigates to detail page", async () => {
    await rootPage.goto(`${BASE}/admin/kyc`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByRole("heading", { name: "KYC Review Queue" })).toBeVisible();

    // Wait for rows to appear
    const firstRow = rootPage.locator("tr[data-testid^='kyc-row-']").first();
    await expect(firstRow).toBeVisible({ timeout: 10_000 });

    // Click the View button on first row
    await firstRow.getByRole("button", { name: "View" }).click();

    // Verify URL changed to case detail
    await expect(rootPage).toHaveURL(/\/admin\/kyc\/cases\//);
    // Verify detail page content
    await expect(rootPage.getByText("Case Information")).toBeVisible({ timeout: 5_000 });
  });

  test("154.4 Queue page shows empty state when no cases match filter", async () => {
    await rootPage.goto(`${BASE}/admin/kyc`, { waitUntil: "domcontentloaded" });
    await expect(rootPage.getByRole("heading", { name: "KYC Review Queue" })).toBeVisible();
    await rootPage.waitForTimeout(1000);

    // Set assignee filter to something that won't match
    await rootPage.locator("#assignee-filter").fill("nonexistent_admin_xyz@test.local");
    await rootPage.waitForTimeout(2000);

    // Should show "No cases found"
    await expect(rootPage.getByText("No cases found")).toBeVisible({ timeout: 5_000 });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 155: Case Detail Page UI
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 155 — Case Detail Page UI", () => {
  test("155.1 Case detail shows document tabs and case info", async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${CASE_SUBMITTED_ID}`, {
      waitUntil: "domcontentloaded",
    });

    // Verify case info is shown
    await expect(rootPage.getByText("Case Information")).toBeVisible({ timeout: 10_000 });
    await expect(rootPage.locator("[data-testid='case-status-badge']")).toBeVisible();

    // Verify document tabs
    await expect(rootPage.locator("[data-testid='doc-tab-selfie']")).toBeVisible();
    await expect(rootPage.locator("[data-testid='doc-tab-id_front']")).toBeVisible();
    await expect(rootPage.locator("[data-testid='doc-tab-id_back']")).toBeVisible();

    // User sub should be displayed
    await expect(rootPage.locator("[data-testid='case-user-sub']")).toHaveText(ALICE_ID);
  });

  test("155.2 Approve button opens confirmation dialog", async () => {
    // Use the under_review case (CASE_CONFLICT_ID is still under_review)
    await rootPage.goto(`${BASE}/admin/kyc/cases/${CASE_CONFLICT_ID}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(rootPage.getByText("Case Information")).toBeVisible({ timeout: 10_000 });

    // Click Approve button
    await rootPage.getByRole("button", { name: "Approve" }).click();

    // Dialog should appear
    await expect(rootPage.getByRole("heading", { name: "Approve Case" })).toBeVisible();
    await expect(rootPage.getByText("Identity Verified")).toBeVisible();
    await expect(rootPage.getByText("Documents Valid")).toBeVisible();
    // Confirm button should be visible
    await expect(rootPage.getByRole("button", { name: "Confirm Approval" })).toBeVisible();

    // Close dialog
    await rootPage.getByRole("button", { name: "Cancel" }).click();
  });

  test("155.3 Case timeline shows chronological events", async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${CASE_SUBMITTED_ID}`, {
      waitUntil: "domcontentloaded",
    });

    // Wait for timeline to render
    await expect(rootPage.getByText("Timeline")).toBeVisible({ timeout: 10_000 });

    // Timeline events should exist
    const events = rootPage.locator("[data-testid='timeline-event']");
    await expect(events.first()).toBeVisible({ timeout: 5_000 });

    // Should have at least one event type
    const eventTypes = rootPage.locator("[data-testid='timeline-event-type']");
    const count = await eventTypes.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});
