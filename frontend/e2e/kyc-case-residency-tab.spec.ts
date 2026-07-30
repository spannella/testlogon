/**
 * E2E tests for the Residency tab + ResidencyVerificationTab on the KYC admin
 * case detail page (GAP-0254 / KYC-004).
 *
 * Section:
 *   254 — Residency tab shows, per residency document, a two-column
 *         profile-vs-document address comparison with per-field match badges and
 *         an overall match status, fetched via
 *         GET /ui/kyc/residency/admin/case/<case_id>.
 *
 * Before GAP-0254 the case detail page had no residency section at all: reviewers
 * had to leave the case and open the standalone residency review queue to see the
 * address comparison. This spec asserts the new tab renders that data inline.
 *
 * Auth: Root session cookies (from e2e_admin_session_setup.py).
 * KYC case + residency documents are seeded directly into DynamoDB.
 *
 * NOTE: do not run as part of this change — added for regression coverage only.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions, resolveIdentityId } from "./helpers/session";
import { usingCpp } from "./helpers/cpp-seed";
import { cppSeedKycCaseFull, cppSeedKycResidencyDocument } from "./helpers/cpp-seed-kyc";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS       = Date.now();

const CASE_ID       = `kyc_e2e_resid_${TS}`;
const CASE_ID_EMPTY = `kyc_e2e_resid_empty_${TS}`;

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

// ─── DDB helpers ──────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os
from pathlib import Path
env_file = Path('${REPO_ROOT}/.env.local')
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
cases_table = ddb.Table('kyc_cases')
resid_table = ddb.Table('kyc_residency_documents')
`;

function py(script: string, timeout = 15_000): void {
  execSync(`python3 -c '${script.replace(/'/g, "'\"'\"'")}'`, {
    cwd: REPO_ROOT,
    timeout,
  });
}

function seedKycCase(caseId: string): void {
  if (usingCpp()) {
    cppSeedKycCaseFull({
      caseId,
      userSub: resolveIdentityId("alice"),
      status: "under_review",
      intakeProfile: "enhanced",
      version: 1,
    });
    return;
  }
  const ts = Math.floor(Date.now() / 1000);
  py(`
${DDB_PRELUDE}
ts = ${ts}
case_id = "${caseId}"
user_sub = "${ALICE_ID}"
updated_sk = f"UPDATED#{str(ts).zfill(13)}#KYC#{case_id}"
cases_table.put_item(Item={
    "pk": f"KYC#{case_id}",
    "sk": "META",
    "entity_type": "kyc_case",
    "kyc_case_id": case_id,
    "user_sub": user_sub,
    "status": "under_review",
    "intake_profile": "enhanced",
    "questionnaire": {},
    "files": [],
    "signature": {},
    "submission": {"submitted_at": ts},
    "review": {"ticket_id": None, "assigned_admin_sub": None, "decision": None, "decided_at": None, "reason_codes": []},
    "created_at": ts,
    "updated_at": ts,
    "version": 1,
    "gsi_owner_pk": f"OWNER#{user_sub}",
    "gsi_owner_sk": updated_sk,
    "gsi_status_pk": "STATUS#under_review",
    "gsi_status_sk": updated_sk,
})
print(case_id)
  `);
}

function seedResidencyDocument(caseId: string): void {
  if (usingCpp()) {
    cppSeedKycResidencyDocument({
      documentId: `kycres_e2e_${caseId}`,
      userSub: resolveIdentityId("alice"),
      caseId,
      documentType: "utility_bill",
      status: "verified",
      issuingEntity: "Pacific Gas",
      documentDate: "2025-11-01",
      extractionId: "ext_resid_1",
      recencyValid: true,
      recencyDays: 30,
      extractedAddress: {
        line1: "123 Main Street",
        city: "San Francisco",
        state: "CA",
        postal_code: "94105",
        country: "US",
      },
      addressMatch: {
        status: "partial",
        profile_address: {
          line1: "123 Main Street",
          city: "San Francisco",
          state: "CA",
          postal_code: "94000",
          country: "US",
        },
        field_matches: {
          line1: "match",
          city: "match",
          state: "match",
          postal_code: "mismatch",
          country: "match",
        },
      },
      s3Key: `kyc-residency/${caseId}/bill.pdf`,
      bucket: "local-uploads",
      review: { decision: "approve", reviewer_sub: "root", decided_at: Math.floor(Date.now() / 1000), note: "ok" },
    });
    return;
  }
  const ts = Math.floor(Date.now() / 1000);
  py(`
${DDB_PRELUDE}
ts = ${ts}
case_id = "${caseId}"
resid_table.put_item(Item={
    "document_id": f"kycres_e2e_{case_id}",
    "user_sub": "${ALICE_ID}",
    "case_id": case_id,
    "document_type": "utility_bill",
    "issuing_entity": "Pacific Gas",
    "document_date": "2025-11-01",
    "file_name": "bill.pdf",
    "status": "verified",
    "provider": "mock",
    "s3_key": f"kyc-residency/{case_id}/bill.pdf",
    "bucket": "local-uploads",
    "document_url": None,
    "extraction_id": "ext_resid_1",
    "recency_valid": True,
    "recency_days": 30,
    "extracted_address": {
        "line1": "123 Main Street",
        "city": "San Francisco",
        "state": "CA",
        "postal_code": "94105",
        "country": "US",
    },
    "address_match": {
        "status": "partial",
        "profile_address": {
            "line1": "123 Main Street",
            "city": "San Francisco",
            "state": "CA",
            "postal_code": "94000",
            "country": "US",
        },
        "field_matches": {
            "line1": "match",
            "city": "match",
            "state": "match",
            "postal_code": "mismatch",
            "country": "match",
        },
    },
    "review": {"decision": "approve", "reviewer_sub": "root", "decided_at": ts, "note": "ok"},
    "created_at": ts,
    "updated_at": ts,
})
print("residency doc seeded")
  `);
}

function deleteKycCase(caseId: string): void {
  if (usingCpp()) return; // unique per-run TS case ids; no cpp delete needed
  try {
    py(`
${DDB_PRELUDE}
cases_table.delete_item(Key={"pk": f"KYC#${caseId}", "sk": "META"})
resid_table.delete_item(Key={"document_id": f"kycres_e2e_${caseId}"})
print("deleted")
    `, 10_000);
  } catch {
    // ignore cleanup errors
  }
}

// ─── Setup ────────────────────────────────────────────────────────────────────

let rootPage: Page;

test.beforeAll(async ({ browser }) => {
  seedKycCase(CASE_ID);
  seedResidencyDocument(CASE_ID);
  seedKycCase(CASE_ID_EMPTY); // no residency documents
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");
});

test.afterAll(async () => {
  deleteKycCase(CASE_ID);
  deleteKycCase(CASE_ID_EMPTY);
  await rootPage?.close();
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 254: Residency tab
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 254 — Residency tab", () => {
  test("254.1 case detail page exposes a Residency tab", async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${CASE_ID}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(rootPage.getByTestId("tab-residency")).toBeVisible({ timeout: 10_000 });
  });

  test("254.2 residency panel shows two-column comparison + per-field match badges", async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${CASE_ID}`, {
      waitUntil: "domcontentloaded",
    });
    await rootPage.getByTestId("tab-residency").click();

    await expect(rootPage.getByTestId("residency-verification-tab")).toBeVisible({
      timeout: 10_000,
    });
    // Document status badge.
    await expect(rootPage.getByTestId("residency-doc-status").first()).toContainText("verified");
    // Profile vs document (extracted) columns.
    await expect(rootPage.getByTestId("profile-postal_code")).toContainText("94000");
    await expect(rootPage.getByTestId("extracted-postal_code")).toContainText("94105");
    // Per-field match badges.
    await expect(rootPage.getByTestId("match-line1")).toContainText("match");
    await expect(rootPage.getByTestId("match-postal_code")).toContainText("mismatch");
  });

  test("254.3 empty state when the case has no residency documents", async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${CASE_ID_EMPTY}`, {
      waitUntil: "domcontentloaded",
    });
    await rootPage.getByTestId("tab-residency").click();
    await expect(
      rootPage.getByText("No residency documents attached to this case."),
    ).toBeVisible({ timeout: 10_000 });
  });
});
