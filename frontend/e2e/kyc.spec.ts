/**
 * E2E tests for the KYC Cases feature.
 *
 * Sections:
 *   80 — KYC case lifecycle (create / update draft / readiness / submit)
 *   81 — File attachments
 *   82 — Admin review flow (queue / detail / approve / reject / request-info)
 *   83 — Access control (user isolation, admin-only endpoints)
 *   84 — Edge cases (duplicate submission, invalid transitions, conflict)
 *
 * Auth: uses e2e_admin_session_setup.py (root, alice, bob, charlie_admin)
 *
 * Identities:
 *   root          – root.admin@testdev.local  – role=root
 *   alice         – e2e_alice@test.local      – role=user
 *   bob           – e2e_bob@test.local        – role=user
 *   charlie_admin – e2e_charlie@test.local    – role=admin
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, resolveIdentityId, isCpp } from "./helpers/session";
import { cppSetKycCaseStatus, cppGetKycCaseVersion } from "./helpers/cpp-seed-kyc";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ──────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const TS       = Date.now();
const ALICE_ID = resolveIdentityId("e2e_alice@test.local");
const BOB_ID   = resolveIdentityId("e2e_bob@test.local");

// ─── Session bootstrap ──────────────────────────────────────────────────────

interface SessionData {
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

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

// ─── Page factory ───────────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

// ─── API helpers ────────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body: object) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiPatch(page: Page, identity: string, path: string, body: object) {
  const s = getSessions()[identity];
  return page.request.patch(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
  });
}

// ─── DDB helpers ────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os, time, json
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
`;

const PYTHON = "python3";

/**
 * Inject a fake file node into the file_manager DynamoDB table so
 * the file attachment endpoint can resolve it.
 */
function injectFileNode(userSub: string, filePath: string, contentType = "image/jpeg"): void {
  const name = filePath.split("/").pop()!;
  const parent = filePath.substring(0, filePath.lastIndexOf("/")) || "/";
  execSync(
    `${PYTHON} -c "${DDB_PRELUDE}
tbl = ddb.Table('file_manager')
tbl.put_item(Item={
    'PK': 'USER#${userSub}',
    'SK': 'NODE#${filePath}',
    'type': 'file',
    'path': '${filePath}',
    'name': '${name}',
    'name_lc': '${name.toLowerCase()}',
    'parent': '${parent}',
    'content_type': '${contentType}',
    'size': 2048,
    'upload_at': int(time.time()),
    'created_at': str(int(time.time())),
    'updated_at': str(int(time.time())),
    's3_key': 'e2e/fake/${name}',
    's3_bucket': 'test-bucket',
})
print('file node injected')
"`,
    { timeout: 10_000 },
  );
}

function cleanupFileNode(userSub: string, filePath: string): void {
  try {
    execSync(
      `${PYTHON} -c "${DDB_PRELUDE}
tbl = ddb.Table('file_manager')
tbl.delete_item(Key={'PK': 'USER#${userSub}', 'SK': 'NODE#${filePath}'})
print('cleaned up')
"`,
      { timeout: 10_000 },
    );
  } catch {
    /* best-effort */
  }
}

/**
 * Directly update a KYC case status in DynamoDB. Used to move cases to
 * `under_review` for admin decision tests (no REST endpoint for this transition).
 */
function setCaseStatusDirect(caseId: string, newStatus: string): void {
  if (isCpp()) {
    cppSetKycCaseStatus(caseId, newStatus);
    return;
  }
  execSync(
    `${PYTHON} -c "${DDB_PRELUDE}
import time as _time
tbl = ddb.Table('kyc_cases')
pk = 'KYC#' + '${caseId}'
resp = tbl.get_item(Key={'pk': pk, 'sk': 'META'})
item = resp.get('Item')
if not item:
    raise Exception('case not found: ${caseId}')
ts = int(_time.time())
ver = int(item.get('version', 0))
tbl.update_item(
    Key={'pk': pk, 'sk': 'META'},
    UpdateExpression='SET #s=:s, updated_at=:u, version=:v, gsi_status_pk=:sp, gsi_status_sk=:ss, gsi_owner_sk=:os',
    ExpressionAttributeNames={'#s': 'status'},
    ExpressionAttributeValues={
        ':s': '${newStatus}',
        ':u': ts,
        ':v': ver + 1,
        ':sp': 'STATUS#${newStatus}',
        ':ss': f'UPDATED#{ts:013d}#KYC#${caseId}',
        ':os': f'UPDATED#{ts:013d}#KYC#${caseId}',
    },
)
print('status updated to ${newStatus}')
"`,
    { timeout: 10_000 },
  );
}

/**
 * Read the current version of a KYC case directly from DynamoDB.
 */
function getCaseVersionDirect(caseId: string): number {
  if (isCpp()) return cppGetKycCaseVersion(caseId);
  const out = execSync(
    `${PYTHON} -c "${DDB_PRELUDE}
tbl = ddb.Table('kyc_cases')
resp = tbl.get_item(Key={'pk': 'KYC#${caseId}', 'sk': 'META'})
item = resp.get('Item')
if not item:
    print('-1')
else:
    print(int(item.get('version', 0)))
"`,
    { timeout: 10_000 },
  ).toString().trim();
  return parseInt(out, 10);
}

// ─── Response type helpers ──────────────────────────────────────────────────

interface KycCaseOut {
  kyc_case_id: string;
  user_sub: string;
  status: string;
  intake_profile: string | null;
  version: number;
  created_at: number;
  updated_at: number;
  files: Array<{ path: string; type: string }>;
  questionnaire: Record<string, unknown>;
  signature: Record<string, unknown>;
  review: Record<string, unknown>;
  submission: Record<string, unknown>;
  missing_requirements: string[];
}

interface KycCaseEnvelope {
  case: KycCaseOut;
}

interface KycCaseListEnvelope {
  items: KycCaseOut[];
  next_cursor: string | null;
}

interface KycReadinessEnvelope {
  readiness: {
    kyc_case_id: string;
    status: string;
    ready_to_submit: boolean;
    missing_requirements: string[];
    missing_hints: string[];
    checks: Record<string, boolean>;
    requirements: Array<Record<string, unknown>>;
  };
}

interface KycAdminQueueEnvelope {
  items: Array<{
    kyc_case_id: string;
    user_sub: string;
    status: string;
    waiting_seconds?: number;
  }>;
  next_cursor: string | null;
}

interface KycAdminCaseDetailEnvelope {
  case: {
    kyc_case_id: string;
    user_sub: string;
    status: string;
    timeline: Array<Record<string, unknown>>;
    decision_state: Record<string, unknown>;
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 80 — KYC case lifecycle (create / update draft / readiness / submit)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 80: KYC case lifecycle", () => {
  let alicePage: Page;
  let caseId: string;
  let caseVersion: number;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("80.1 Create KYC case returns 200 with draft status", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/kyc/cases", {
      intake_profile: "individual",
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as KycCaseEnvelope;
    expect(data.case.kyc_case_id).toBeTruthy();
    expect(data.case.status).toBe("draft");
    expect(data.case.user_sub).toBe(ALICE_ID);
    expect(data.case.version).toBe(1);
    expect(data.case.intake_profile).toBe("individual");
    caseId = data.case.kyc_case_id;
    caseVersion = data.case.version;
  });

  test("80.2 List user cases includes the new case", async () => {
    const resp = await apiGet(alicePage, "/v1/kyc/cases");
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as KycCaseListEnvelope;
    expect(Array.isArray(data.items)).toBe(true);
    const found = data.items.find((c) => c.kyc_case_id === caseId);
    expect(found).toBeTruthy();
    expect(found!.status).toBe("draft");
  });

  test("80.3 Get case detail returns correct fields", async () => {
    const resp = await apiGet(alicePage, `/v1/kyc/cases/${caseId}`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as KycCaseEnvelope;
    expect(data.case.kyc_case_id).toBe(caseId);
    expect(data.case.status).toBe("draft");
    expect(typeof data.case.created_at).toBe("number");
    expect(typeof data.case.updated_at).toBe("number");
  });

  test("80.4 Update draft — intake_profile changes and version increments", async () => {
    const resp = await apiPatch(alicePage, "alice", `/v1/kyc/cases/${caseId}`, {
      expected_version: caseVersion,
      intake_profile: "enhanced",
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as KycCaseEnvelope;
    expect(data.case.intake_profile).toBe("enhanced");
    expect(data.case.version).toBe(caseVersion + 1);
    caseVersion = data.case.version;
  });

  test("80.5 Readiness check — not ready (no files, questionnaire, signature)", async () => {
    const resp = await apiGet(alicePage, `/v1/kyc/cases/${caseId}/readiness`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as KycReadinessEnvelope;
    expect(data.readiness.kyc_case_id).toBe(caseId);
    expect(data.readiness.ready_to_submit).toBe(false);
    expect(data.readiness.missing_requirements.length).toBeGreaterThan(0);
  });

  test("80.6 Submit fails when prerequisites are not met", async () => {
    const resp = await apiPost(alicePage, "alice", `/v1/kyc/cases/${caseId}/submit`, {
      expected_version: caseVersion,
    });
    // Should fail with 409 (kyc_submit_prereq_failed)
    expect(resp.status()).toBe(409);
    const data = await resp.json();
    expect(data.detail.error.code).toBe("kyc_submit_prereq_failed");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 81 — File attachments
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 81: File attachments", () => {
  let alicePage: Page;
  let caseId: string;
  let caseVersion: number;
  const SELFIE_PATH = `/kyc_selfie_${TS}.jpg`;
  const ID_FRONT_PATH = `/kyc_id_front_${TS}.jpg`;
  const ID_BACK_PATH = `/kyc_id_back_${TS}.jpg`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");

    // Create a case for file attachment tests
    const resp = await apiPost(alicePage, "alice", "/v1/kyc/cases", {
      intake_profile: "standard",
    });
    expect(resp.ok()).toBe(true);
    const data = (await resp.json()) as KycCaseEnvelope;
    caseId = data.case.kyc_case_id;
    caseVersion = data.case.version;

    // Inject fake file nodes into the file_manager DDB table
    injectFileNode(ALICE_ID, SELFIE_PATH);
    injectFileNode(ALICE_ID, ID_FRONT_PATH);
    injectFileNode(ALICE_ID, ID_BACK_PATH);
  });

  test.afterAll(async () => {
    cleanupFileNode(ALICE_ID, SELFIE_PATH);
    cleanupFileNode(ALICE_ID, ID_FRONT_PATH);
    cleanupFileNode(ALICE_ID, ID_BACK_PATH);
    await alicePage?.close();
  });

  test("81.1 Attach selfie file to case", async () => {
    const resp = await apiPost(alicePage, "alice", `/v1/kyc/cases/${caseId}/files`, {
      expected_version: caseVersion,
      path: SELFIE_PATH,
      file_type: "selfie",
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as KycCaseEnvelope;
    expect(data.case.files.length).toBe(1);
    expect(data.case.files[0].type).toBe("selfie");
    caseVersion = data.case.version;
  });

  test("81.2 Attach id_front file to case", async () => {
    const resp = await apiPost(alicePage, "alice", `/v1/kyc/cases/${caseId}/files`, {
      expected_version: caseVersion,
      path: ID_FRONT_PATH,
      file_type: "id_front",
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as KycCaseEnvelope;
    expect(data.case.files.length).toBe(2);
    caseVersion = data.case.version;
  });

  test("81.3 Attach id_back file to case", async () => {
    const resp = await apiPost(alicePage, "alice", `/v1/kyc/cases/${caseId}/files`, {
      expected_version: caseVersion,
      path: ID_BACK_PATH,
      file_type: "id_back",
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as KycCaseEnvelope;
    expect(data.case.files.length).toBe(3);
    caseVersion = data.case.version;
  });

  test("81.4 File validation — all required types present", async () => {
    const resp = await apiGet(alicePage, `/v1/kyc/cases/${caseId}/files/validation`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.files.missing_types.length).toBe(0);
    expect(data.files.ready_for_submit_gate).toBe(true);
    expect(data.files.present_types).toContain("selfie");
    expect(data.files.present_types).toContain("id_front");
    expect(data.files.present_types).toContain("id_back");
  });

  test("81.5 Replacing a file type replaces the previous one", async () => {
    // Re-attach selfie (should replace, not duplicate)
    const resp = await apiPost(alicePage, "alice", `/v1/kyc/cases/${caseId}/files`, {
      expected_version: caseVersion,
      path: SELFIE_PATH,
      file_type: "selfie",
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as KycCaseEnvelope;
    // Still 3 files (selfie replaced, not added)
    expect(data.case.files.length).toBe(3);
    const selfies = data.case.files.filter((f) => f.type === "selfie");
    expect(selfies.length).toBe(1);
    caseVersion = data.case.version;
  });

  test("81.6 Cannot attach file to non-existent path", async () => {
    const resp = await apiPost(alicePage, "alice", `/v1/kyc/cases/${caseId}/files`, {
      expected_version: caseVersion,
      path: "/no/such/file.jpg",
      file_type: "selfie",
    });
    expect(resp.status()).toBe(400);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 82 — Admin review flow
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 82: Admin review flow", () => {
  let alicePage: Page;
  let rootPage: Page;
  let approveCaseId: string;
  let approveCaseVersion: number;
  let rejectCaseId: string;
  let rejectCaseVersion: number;
  let requestInfoCaseId: string;
  let requestInfoCaseVersion: number;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    rootPage = await newIdentityPage(browser, "root");

    // Create three cases: one to approve, one to reject, one for request-info
    for (const label of ["approve", "reject", "request-info"]) {
      const resp = await apiPost(alicePage, "alice", "/v1/kyc/cases", {
        intake_profile: `admin_test_${label}_${TS}`,
      });
      expect(resp.ok()).toBe(true);
      const data = (await resp.json()) as KycCaseEnvelope;
      const id = data.case.kyc_case_id;

      // Move to submitted then under_review via DDB
      setCaseStatusDirect(id, "submitted");
      setCaseStatusDirect(id, "under_review");

      const ver = getCaseVersionDirect(id);
      if (label === "approve") {
        approveCaseId = id;
        approveCaseVersion = ver;
      } else if (label === "reject") {
        rejectCaseId = id;
        rejectCaseVersion = ver;
      } else {
        requestInfoCaseId = id;
        requestInfoCaseVersion = ver;
      }
    }
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await rootPage?.close();
  });

  test("82.1 Admin queue lists submitted/under_review cases", async () => {
    const resp = await apiGet(rootPage, "/v1/kyc/cases/admin/queue");
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as KycAdminQueueEnvelope;
    expect(Array.isArray(data.items)).toBe(true);
    // At least our test cases should appear
    const ids = data.items.map((i) => i.kyc_case_id);
    expect(ids).toContain(approveCaseId);
  });

  test("82.2 Admin can view case detail", async () => {
    const resp = await apiGet(rootPage, `/v1/kyc/cases/admin/cases/${approveCaseId}`);
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as KycAdminCaseDetailEnvelope;
    expect(data.case.kyc_case_id).toBe(approveCaseId);
    expect(data.case.user_sub).toBe(ALICE_ID);
    expect(data.case.status).toBe("under_review");
    expect(Array.isArray(data.case.timeline)).toBe(true);
  });

  test("82.3 Root approves a case", async () => {
    const resp = await apiPost(rootPage, "root", `/v1/kyc/cases/admin/cases/${approveCaseId}/approve`, {
      expected_version: approveCaseVersion,
      decision: "approve",
      reason_codes: ["docs_verified"],
      note: "All documents verified successfully.",
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as KycCaseEnvelope;
    expect(data.case.status).toBe("approved");
    expect(data.case.review).toBeTruthy();
  });

  test("82.4 Approved case is no longer in admin queue", async () => {
    const resp = await apiGet(rootPage, "/v1/kyc/cases/admin/queue?status=under_review");
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as KycAdminQueueEnvelope;
    const ids = data.items.map((i) => i.kyc_case_id);
    expect(ids).not.toContain(approveCaseId);
  });

  test("82.5 Root rejects a case", async () => {
    const resp = await apiPost(rootPage, "root", `/v1/kyc/cases/admin/cases/${rejectCaseId}/reject`, {
      expected_version: rejectCaseVersion,
      decision: "reject",
      reason_codes: ["blurry_id", "name_mismatch"],
      note: "ID photo is blurry and name does not match.",
    });
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as KycCaseEnvelope;
    expect(data.case.status).toBe("rejected");
  });

  test("82.6 Root requests more info on a case", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/v1/kyc/cases/admin/cases/${requestInfoCaseId}/request-info`,
      {
        expected_version: requestInfoCaseVersion,
        requested_items: ["clearer_selfie", "utility_bill"],
        note: "Please provide a clearer selfie and a utility bill for address verification.",
      },
    );
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as KycCaseEnvelope;
    expect(data.case.status).toBe("needs_more_info");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 83 — Access control
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 83: Access control", () => {
  let alicePage: Page;
  let bobPage: Page;
  let aliceCaseId: string;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");

    // Alice creates a case
    const resp = await apiPost(alicePage, "alice", "/v1/kyc/cases", {
      intake_profile: `acl_test_${TS}`,
    });
    expect(resp.ok()).toBe(true);
    const data = (await resp.json()) as KycCaseEnvelope;
    aliceCaseId = data.case.kyc_case_id;
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("83.1 Bob cannot read Alice's case (403)", async () => {
    const resp = await apiGet(bobPage, `/v1/kyc/cases/${aliceCaseId}`);
    expect(resp.status()).toBe(403);
  });

  test("83.2 Bob cannot update Alice's case (403)", async () => {
    const resp = await apiPatch(bobPage, "bob", `/v1/kyc/cases/${aliceCaseId}`, {
      expected_version: 1,
      intake_profile: "hacked",
    });
    expect(resp.status()).toBe(403);
  });

  test("83.3 Alice cannot access admin queue (403)", async () => {
    const resp = await apiGet(alicePage, "/v1/kyc/cases/admin/queue");
    expect(resp.status()).toBe(403);
  });

  test("83.4 Alice cannot access admin case detail (403)", async () => {
    const resp = await apiGet(alicePage, `/v1/kyc/cases/admin/cases/${aliceCaseId}`);
    expect(resp.status()).toBe(403);
  });

  test("83.5 Bob's case list does not include Alice's cases", async () => {
    const resp = await apiGet(bobPage, "/v1/kyc/cases");
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as KycCaseListEnvelope;
    const ids = data.items.map((c) => c.kyc_case_id);
    expect(ids).not.toContain(aliceCaseId);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 84 — Edge cases
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 84: Edge cases", () => {
  let alicePage: Page;
  let rootPage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await rootPage?.close();
  });

  test("84.1 Get non-existent case returns 404", async () => {
    const resp = await apiGet(alicePage, "/v1/kyc/cases/kyc_nonexistent_999");
    expect(resp.status()).toBe(404);
    const data = await resp.json();
    expect(data.detail.error.code).toBe("kyc_case_not_found");
  });

  test("84.2 Update with wrong version returns 409 (conflict)", async () => {
    // Create a case first
    const createResp = await apiPost(alicePage, "alice", "/v1/kyc/cases", {
      intake_profile: `conflict_test_${TS}`,
    });
    expect(createResp.ok()).toBe(true);
    const created = (await createResp.json()) as KycCaseEnvelope;

    // Try to update with wrong version
    const resp = await apiPatch(alicePage, "alice", `/v1/kyc/cases/${created.case.kyc_case_id}`, {
      expected_version: 999,
      intake_profile: "changed",
    });
    expect(resp.status()).toBe(409);
  });

  test("84.3 Cannot update a non-draft case", async () => {
    // Create and submit a case via DDB status change
    const createResp = await apiPost(alicePage, "alice", "/v1/kyc/cases", {
      intake_profile: `nondraft_test_${TS}`,
    });
    expect(createResp.ok()).toBe(true);
    const created = (await createResp.json()) as KycCaseEnvelope;
    const id = created.case.kyc_case_id;

    // Move to submitted via DDB
    setCaseStatusDirect(id, "submitted");
    const ver = getCaseVersionDirect(id);

    // Try to patch — should fail because not draft
    const resp = await apiPatch(alicePage, "alice", `/v1/kyc/cases/${id}`, {
      expected_version: ver,
      intake_profile: "should_fail",
    });
    expect(resp.status()).toBe(409);
  });

  test("84.4 Cannot approve a case that is not under_review", async () => {
    // Create a case (status=draft)
    const createResp = await apiPost(alicePage, "alice", "/v1/kyc/cases", {
      intake_profile: `approve_draft_test_${TS}`,
    });
    expect(createResp.ok()).toBe(true);
    const created = (await createResp.json()) as KycCaseEnvelope;
    const id = created.case.kyc_case_id;
    const ver = created.case.version;

    // Root tries to approve a draft case
    const resp = await apiPost(rootPage, "root", `/v1/kyc/cases/admin/cases/${id}/approve`, {
      expected_version: ver,
      decision: "approve",
      reason_codes: ["ok"],
      note: "Trying to approve draft",
    });
    // Should fail — invalid transition (not under_review)
    expect([400, 409]).toContain(resp.status());
  });

  test("84.5 Admin queue with status filter returns only matching cases", async () => {
    const resp = await apiGet(rootPage, "/v1/kyc/cases/admin/queue?status=approved");
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as KycAdminQueueEnvelope;
    // All items in the filtered queue should have the requested status
    for (const item of data.items) {
      expect(item.status).toBe("approved");
    }
  });

  test("84.6 Admin metrics endpoint returns funnel counts", async () => {
    const resp = await apiGet(rootPage, "/v1/kyc/cases/admin/metrics");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.metrics).toBeTruthy();
    expect(data.metrics.funnel_counts).toBeTruthy();
    expect(typeof data.metrics.stale_queue_count).toBe("number");
  });

  test("84.7 File attachment with invalid file_type rejected by validation", async () => {
    // Create a case
    const createResp = await apiPost(alicePage, "alice", "/v1/kyc/cases", {
      intake_profile: `filetype_test_${TS}`,
    });
    expect(createResp.ok()).toBe(true);
    const created = (await createResp.json()) as KycCaseEnvelope;

    // Try to attach with an invalid file_type (Pydantic Literal validation)
    const resp = await apiPost(alicePage, "alice", `/v1/kyc/cases/${created.case.kyc_case_id}/files`, {
      expected_version: created.case.version,
      path: "/fake.jpg",
      file_type: "invalid_type",
    });
    expect(resp.status()).toBe(422);
  });
});
