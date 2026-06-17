/**
 * E2E tests for the Document Extraction tab + ExtractionResultsPanel on the KYC
 * admin case detail page (GAP-0247 / KYC-002).
 *
 * Section:
 *   247 — Document Extraction tab shows per-document OCR fields, per-field match
 *         status badges, and overall confidence, fetched via
 *         GET /ui/kyc/documents/admin/by-status?case_id=<id>
 *         (the case_id query param is provided by GAP-0248).
 *
 * Before GAP-0247 the case detail page had no extraction-results section at all:
 * reviewers had to leave the case and open the standalone document review queue
 * to see OCR fields / match status / confidence. This spec asserts the new tab
 * renders that data inline.
 *
 * Auth: Root session cookies (from e2e_admin_session_setup.py).
 * KYC case + documents are seeded directly into DynamoDB.
 *
 * NOTE: do not run as part of this change — added for regression coverage only.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS       = Date.now();

const CASE_ID       = `kyc_e2e_extract_${TS}`;
const CASE_ID_EMPTY = `kyc_e2e_extract_empty_${TS}`;

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
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _adminSessions = JSON.parse(raw);
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
docs_table = ddb.Table('kyc_documents')
`;

function py(script: string, timeout = 15_000): void {
  execSync(`python3 -c '${script.replace(/'/g, "'\"'\"'")}'`, {
    cwd: REPO_ROOT,
    timeout,
  });
}

function seedKycCase(caseId: string): void {
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
    "intake_profile": "standard",
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

function seedExtractedDocument(caseId: string): void {
  const ts = Math.floor(Date.now() / 1000);
  py(`
${DDB_PRELUDE}
ts = ${ts}
case_id = "${caseId}"
docs_table.put_item(Item={
    "document_id": f"kycdoc_e2e_{case_id}_front",
    "user_sub": "${ALICE_ID}",
    "case_id": case_id,
    "document_type": "id_front",
    "file_name": "id_front.jpg",
    "status": "extracted",
    "provider": "mock",
    "s3_key": f"kyc/{case_id}/front.jpg",
    "bucket": "kyc-docs",
    "image_url": None,
    "extraction_id": "ext_1",
    "extracted_fields": {
        "given_names": "ALICE",
        "surname": "EXAMPLE",
        "date_of_birth": "1990-01-01",
    },
    "match_results": {
        "given_names": {"status": "match", "profile_value": "ALICE", "extracted_value": "ALICE", "similarity": 1},
        "surname": {"status": "mismatch", "profile_value": "SMITH", "extracted_value": "EXAMPLE", "similarity": 0},
    },
    "overall_confidence": "medium",
    "review": {"decision": None, "reviewer_sub": None, "decided_at": None, "note": None},
    "created_at": ts,
    "updated_at": ts,
})
print("doc seeded")
  `);
}

function deleteKycCase(caseId: string): void {
  try {
    py(`
${DDB_PRELUDE}
cases_table.delete_item(Key={"pk": f"KYC#${caseId}", "sk": "META"})
docs_table.delete_item(Key={"document_id": f"kycdoc_e2e_${caseId}_front"})
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
  seedExtractedDocument(CASE_ID);
  seedKycCase(CASE_ID_EMPTY); // no documents
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");
});

test.afterAll(async () => {
  deleteKycCase(CASE_ID);
  deleteKycCase(CASE_ID_EMPTY);
  await rootPage?.close();
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 247: Document Extraction tab
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 247 — Document Extraction tab", () => {
  test("247.1 case detail page exposes a Document Extraction tab", async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${CASE_ID}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(rootPage.getByTestId("tab-extraction")).toBeVisible({ timeout: 10_000 });
  });

  test("247.2 extraction panel shows OCR fields, match badges, and confidence", async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${CASE_ID}`, {
      waitUntil: "domcontentloaded",
    });
    await rootPage.getByTestId("tab-extraction").click();

    await expect(rootPage.getByTestId("extraction-results-panel")).toBeVisible({
      timeout: 10_000,
    });
    // OCR fields table for the extracted document.
    await expect(
      rootPage.locator("[data-testid^='extraction-fields-']").first(),
    ).toBeVisible();
    // Extracted values rendered.
    await expect(rootPage.getByText("ALICE").first()).toBeVisible();
    // Overall confidence badge.
    await expect(rootPage.getByTestId("doc-confidence").first()).toBeVisible();
    await expect(rootPage.getByTestId("doc-confidence").first()).toContainText("medium");
    // Per-field match badges.
    await expect(rootPage.getByTestId("match-given_names")).toContainText("match");
    await expect(rootPage.getByTestId("match-surname")).toContainText("mismatch");
  });

  test("247.3 empty state when the case has no documents", async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${CASE_ID_EMPTY}`, {
      waitUntil: "domcontentloaded",
    });
    await rootPage.getByTestId("tab-extraction").click();
    await expect(rootPage.getByTestId("extraction-empty")).toBeVisible({
      timeout: 10_000,
    });
  });
});
