/**
 * E2E tests for the VerificationCallPanel on the KYC admin case detail page
 * (GAP-0250 / KYC-003).
 *
 * Section:
 *   250 — The case detail Overview tab shows a collapsible "Verification Call"
 *         panel rendering liveness-call status / outcome / recording, plus a
 *         "Schedule Call" dialog and admin conduct/cancel/record actions.
 *
 * Before GAP-0250 the case detail page rendered no liveness-call data at all:
 * reviewers had to leave the case and open the standalone /by-status queue to
 * see whether a call was scheduled, conducted, passed, or failed. This spec
 * asserts the panel renders that data inline and drives the admin actions.
 *
 * The panel resolves the case's call via the admin per-case lookup
 * (GAP-0251, GET /ui/kyc/liveness-call/admin/case/{case_id}) and falls back to
 * the admin by-status lists when that endpoint is not deployed.
 *
 * Auth: Root session cookies (from e2e_admin_session_setup.py).
 * KYC case + liveness call are seeded directly into DynamoDB.
 *
 * NOTE: do not run as part of this change — added for regression coverage only.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions, resolveIdentityId } from "./helpers/session";
import { usingCpp } from "./helpers/cpp-seed";
import { cppSeedKycCaseFull, cppSeedLivenessCall } from "./helpers/cpp-seed-kyc";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS       = Date.now();

const CASE_SCHEDULED   = `kyc_e2e_call_sched_${TS}`;
const CASE_INPROGRESS  = `kyc_e2e_call_prog_${TS}`;
const CASE_EMPTY       = `kyc_e2e_call_empty_${TS}`;

const CALL_SCHEDULED   = `kyclc_e2e_sched_${TS}`;
const CALL_INPROGRESS  = `kyclc_e2e_prog_${TS}`;

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
calls_table = ddb.Table('kyc_liveness_calls')
`;

function py(script: string, timeout = 15_000): void {
  execSync(`python3 -c '${script.replace(/'/g, "'\"'\"'")}'`, {
    cwd: REPO_ROOT,
    timeout,
  });
}

function seedKycCase(caseId: string): void {
  const ts = Math.floor(Date.now() / 1000);
  if (usingCpp()) {
    // cpp reads tlc_kyc_cases (SUB-keyed), not the Python :8001 'kyc_cases'.
    cppSeedKycCaseFull({
      caseId,
      userSub: resolveIdentityId(ALICE_ID),
      status: "under_review",
      intakeProfile: "standard",
      createdAt: ts,
      submittedAt: ts,
      files: [],
    });
    return;
  }
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

function seedLivenessCall(callId: string, caseId: string, status: string): void {
  const ts = Math.floor(Date.now() / 1000);
  if (usingCpp()) {
    // cpp reads tlc_kyc_liveness_calls (ByCase GSI), not the Python :8001 table.
    cppSeedLivenessCall({
      callId,
      caseId,
      userSub: resolveIdentityId(ALICE_ID),
      status,
      scheduledAt: ts + 3600,
      durationMinutes: 30,
      note: "E2E seeded call",
      createdAt: ts,
    });
    return;
  }
  py(`
${DDB_PRELUDE}
ts = ${ts}
calls_table.put_item(Item={
    "call_id": "${callId}",
    "case_id": "${caseId}",
    "user_sub": "${ALICE_ID}",
    "status": "${status}",
    "scheduled_at": ts + 3600,
    "duration_minutes": 30,
    "verifier_sub": "_unassigned",
    "note": "E2E seeded call",
    "result": None,
    "result_notes": None,
    "result_set_at": None,
    "recording_ref": None,
    "started_at": (ts if "${status}" == "in_progress" else None),
    "conducted_by": None,
    "created_at": ts,
    "updated_at": ts,
})
print("call seeded")
  `);
}

function deleteKycCase(caseId: string): void {
  if (usingCpp()) return; // unique per-run case ids; leftover rows are inert
  try {
    py(`
${DDB_PRELUDE}
cases_table.delete_item(Key={"pk": f"KYC#${caseId}", "sk": "META"})
print("deleted")
    `, 10_000);
  } catch {
    // ignore cleanup errors
  }
}

function deleteLivenessCallsForCase(caseId: string): void {
  if (usingCpp()) return; // unique per-run ids; leftover rows are inert
  try {
    py(`
${DDB_PRELUDE}
resp = calls_table.scan()
for it in resp.get("Items", []):
    if it.get("case_id") == "${caseId}":
        calls_table.delete_item(Key={"call_id": it["call_id"]})
print("calls deleted")
    `, 15_000);
  } catch {
    // ignore cleanup errors
  }
}

// ─── Setup ────────────────────────────────────────────────────────────────────

let rootPage: Page;

test.beforeAll(async ({ browser }) => {
  seedKycCase(CASE_SCHEDULED);
  seedLivenessCall(CALL_SCHEDULED, CASE_SCHEDULED, "scheduled");
  seedKycCase(CASE_INPROGRESS);
  seedLivenessCall(CALL_INPROGRESS, CASE_INPROGRESS, "in_progress");
  seedKycCase(CASE_EMPTY); // no liveness call
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");
});

test.afterAll(async () => {
  deleteLivenessCallsForCase(CASE_SCHEDULED);
  deleteLivenessCallsForCase(CASE_INPROGRESS);
  deleteKycCase(CASE_SCHEDULED);
  deleteKycCase(CASE_INPROGRESS);
  deleteKycCase(CASE_EMPTY);
  await rootPage?.close();
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 250: VerificationCallPanel
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 250 — Verification Call panel", () => {
  test("250.1 panel renders status + conduct/cancel actions for a scheduled call", async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${CASE_SCHEDULED}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(rootPage.getByTestId("verification-call-panel")).toBeVisible({
      timeout: 10_000,
    });
    await expect(rootPage.getByTestId("call-status-badge")).toHaveText("scheduled", {
      timeout: 10_000,
    });
    await expect(rootPage.getByTestId("conduct-call-btn")).toBeVisible();
    await expect(rootPage.getByTestId("cancel-call-btn")).toBeVisible();
  });

  test("250.2 empty state + Schedule Call dialog when no call exists", async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${CASE_EMPTY}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(rootPage.getByTestId("verification-call-panel")).toBeVisible({
      timeout: 10_000,
    });
    await expect(rootPage.getByTestId("call-none")).toBeVisible({ timeout: 10_000 });
    await expect(rootPage.getByTestId("schedule-call-btn")).toBeVisible();

    await rootPage.getByTestId("schedule-call-btn").click();
    await expect(
      rootPage.getByRole("heading", { name: "Schedule Verification Call" }),
    ).toBeVisible();
    await expect(rootPage.getByLabel("Scheduled At")).toBeVisible();
    await expect(rootPage.getByTestId("schedule-call-submit")).toBeVisible();
  });

  test("250.3 panel is collapsible", async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${CASE_SCHEDULED}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(rootPage.getByTestId("call-detail")).toBeVisible({ timeout: 10_000 });
    await rootPage.getByTestId("call-panel-toggle").click();
    await expect(rootPage.getByTestId("call-detail")).toBeHidden();
    await rootPage.getByTestId("call-panel-toggle").click();
    await expect(rootPage.getByTestId("call-detail")).toBeVisible();
  });

  test("250.4 admin can cancel a scheduled call from the panel", async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${CASE_SCHEDULED}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(rootPage.getByTestId("cancel-call-btn")).toBeVisible({ timeout: 10_000 });
    await rootPage.getByTestId("cancel-call-btn").click();
    // After cancel + refetch the call moves to a terminal state; the schedule
    // button reappears (panel allows re-scheduling).
    await expect(rootPage.getByTestId("schedule-call-btn")).toBeVisible({ timeout: 10_000 });
  });

  test("250.5 admin can record a passed outcome for an in-progress call", async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${CASE_INPROGRESS}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(rootPage.getByTestId("record-result-btn")).toBeVisible({ timeout: 10_000 });
    await rootPage.getByTestId("record-result-btn").click();
    await rootPage.getByTestId("result-passed-btn").click();
    await rootPage.getByPlaceholder("Outcome notes...").fill("Identity confirmed.");
    await rootPage.getByTestId("save-outcome-btn").click();
    await expect(rootPage.getByTestId("call-result")).toHaveText("passed", {
      timeout: 10_000,
    });
  });
});
