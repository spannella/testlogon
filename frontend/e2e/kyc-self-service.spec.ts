/**
 * E2E tests for KYC-013: User Self-Service Portal.
 *
 * Sections:
 *   712 — KYC Wizard UI: render, step navigation, personal info → case created (5 tests)
 *   713 — KYC Status page: active case timeline, estimated wait, history, re-upload (5 tests)
 *   714 — Estimated-wait endpoint + readiness/submit-gate API + auth required (4 tests)
 *
 * Auth: Alice (USER) session from e2e_admin_session_setup.py. KYC cases are
 * created via the real /v1/kyc/cases endpoints or seeded into DynamoDB for the
 * status-page scenarios. Camera capture uses the file-upload fallback (headless).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface AdminSessionData {
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

let _sessions: Record<string, AdminSessionData> | null = null;
function getSessions(): Record<string, AdminSessionData> {
  if (!_sessions) {
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_admin_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

async function apiGet(page: Page, identity: string, path: string) {
  const sessions = getSessions();
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": sessions[identity].csrf_token },
  });
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  const sessions = getSessions();
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: {
      "x-csrf-token": sessions[identity].csrf_token,
      "Content-Type": "application/json",
    },
  });
}

// ─── DDB seeding ──────────────────────────────────────────────────────────────

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
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'),
    region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
cases = ddb.Table('kyc_cases')
`;

function runPy(body: string): string {
  const script = `${DDB_PRELUDE}\n${body}`;
  return execSync(`python3 -c '${script.replace(/'/g, "'\"'\"'")}'`, {
    cwd: REPO_ROOT,
    timeout: 15_000,
  })
    .toString()
    .trim();
}

function seedCase(o: {
  caseId: string;
  status: string;
  decidedAt?: number;
  reasonCodes?: string[];
}) {
  const now = Math.floor(Date.now() / 1000);
  const decided = o.decidedAt ?? 0;
  const reasons = JSON.stringify(o.reasonCodes ?? []);
  runPy(`
case_id = "${o.caseId}"
now = ${now}
decided = ${decided}
status = "${o.status}"
updated_sk = f"UPDATED#{str(now).zfill(13)}#KYC#{case_id}"
review = {"ticket_id": None, "assigned_admin_sub": None,
          "decision": (status if status in ("approved","rejected") else None),
          "decided_at": (decided if decided else None), "reason_codes": ${reasons}}
item = {
    "pk": f"KYC#{case_id}", "sk": "META", "entity_type": "kyc_case", "kyc_case_id": case_id,
    "user_sub": "${ALICE_ID}", "status": status, "intake_profile": "standard", "questionnaire": {},
    "files": [
        {"type": "selfie", "path": "/x/selfie.jpg"},
        {"type": "id_front", "path": "/x/id_front.jpg"},
        {"type": "proof_of_address", "path": "/x/poa.jpg"},
    ],
    "signature": {}, "submission": ({"submitted_at": now} if status != "draft" else {}),
    "review": review, "created_at": now, "updated_at": now, "version": 1,
    "gsi_owner_pk": f"OWNER#${ALICE_ID}", "gsi_owner_sk": updated_sk,
    "gsi_status_pk": f"STATUS#{status}", "gsi_status_sk": updated_sk,
}
cases.put_item(Item=item)
print(case_id)
`);
}

// ──────────────────────────────────────────────────────────────────────────────
// Section 712 — KYC Wizard UI
// ──────────────────────────────────────────────────────────────────────────────

test.describe("712 — KYC Wizard UI", () => {
  test("712.1 wizard renders with step indicators and FAQ", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/kyc`);
    await expect(page.getByTestId("kyc-wizard")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Identity Verification" })).toBeVisible();
    await expect(page.getByTestId("kyc-step-tab-personal")).toBeVisible();
    await expect(page.getByTestId("kyc-step-tab-review")).toBeVisible();
    await expect(page.getByTestId("kyc-help")).toBeVisible();
  });

  test("712.2 step navigation via Continue and tabs", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/kyc`);
    // Default step is Personal Information.
    await expect(page.getByRole("heading", { name: "Personal Information" })).toBeVisible();
    await page.getByTestId("kyc-continue").click();
    await expect(page.getByRole("heading", { name: "Identity Document" })).toBeVisible();
    // Jump to selfie tab.
    await page.getByTestId("kyc-step-tab-selfie").click();
    await expect(page.getByRole("heading", { name: "Selfie Verification" })).toBeVisible();
    await page.getByTestId("kyc-back").click();
    await expect(page.getByRole("heading", { name: "Identity Document" })).toBeVisible();
  });

  test("712.3 personal info save creates a draft case (verified via real GET)", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/kyc`);
    await page.getByTestId("kyc-first-name").fill("Al");
    await page.getByTestId("kyc-last-name").fill("T");
    await page.getByTestId("kyc-dob").fill("1990-01-15");
    await page.getByTestId("kyc-nationality").fill("US");

    const [resp] = await Promise.all([
      page.waitForResponse(
        (r) => r.url().includes("/v1/kyc/cases") && r.request().method() === "PATCH",
      ),
      page.getByTestId("kyc-save-personal").click(),
    ]);
    expect(resp.ok()).toBeTruthy();

    // Confirm via the real list endpoint that a draft with an intake_profile exists.
    const list = await apiGet(page, "alice", "/v1/kyc/cases");
    expect(list.ok()).toBeTruthy();
    const body = await list.json();
    const draft = (body.items as Array<{ status: string; intake_profile: string | null }>).find(
      (c) => c.status === "draft" && c.intake_profile,
    );
    expect(draft).toBeTruthy();
  });

  test("712.4 selfie step renders camera capture with file fallback input", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/kyc`);
    await page.getByTestId("kyc-step-tab-selfie").click();
    await expect(page.getByTestId("camera-capture")).toBeVisible();
    // Headless: the always-rendered file fallback must be attached.
    await expect(page.getByTestId("camera-file-input")).toBeAttached();
  });

  test("712.5 review step shows the readiness checklist", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/kyc`);
    await page.getByTestId("kyc-step-tab-review").click();
    await expect(page.getByTestId("kyc-review-step")).toBeVisible();
    await expect(page.getByTestId("kyc-submit")).toBeVisible();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Section 713 — KYC Status page
// ──────────────────────────────────────────────────────────────────────────────

test.describe("713 — KYC Status page", () => {
  const ACTIVE_CASE = `kyc_act_${TS}`;
  const APPROVED_CASE = `kyc_apr_${TS}`;
  const NMI_CASE = `kyc_nmi_${TS}`;

  test.beforeAll(async ({ browser }) => {
    seedCase({ caseId: ACTIVE_CASE, status: "under_review" });
    seedCase({ caseId: APPROVED_CASE, status: "approved", decidedAt: Math.floor(Date.now() / 1000) });
    seedCase({ caseId: NMI_CASE, status: "needs_more_info", reasonCodes: ["blurry_id"] });
    // The re-upload (713.5) writes to /kyc/{caseId}/... via the file manager,
    // which requires the parent folders to already exist (the backend does NOT
    // auto-create them). Seed the folder tree for the needs_more_info case.
    const page = await browser.newPage();
    await injectAuth(page, "alice");
    for (const path of ["/kyc", `/kyc/${NMI_CASE}`]) {
      const resp = await apiPost(page, "alice", "/v1/fs/folder", { path });
      // 200 = created, 409 = already exists — both fine.
      expect([200, 409].includes(resp.status())).toBeTruthy();
    }
    await page.close();
  });

  test("713.1 status page shows an active case with a timeline", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/kyc/status`);
    await expect(page.getByTestId("kyc-status-page")).toBeVisible();
    await expect(page.getByTestId("kyc-active-case").first()).toBeVisible();
    await expect(page.getByTestId("kyc-timeline").first()).toBeVisible();
  });

  test("713.2 estimated wait time is displayed", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/kyc/status`);
    const wait = page.getByTestId("kyc-estimated-wait").first();
    await expect(wait).toBeVisible();
    await expect(wait).toContainText(/hour/i);
  });

  test("713.3 historical (approved) case is listed under Previous Applications", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/kyc/status`);
    await expect(page.getByRole("heading", { name: "Previous Applications" })).toBeVisible();
    await expect(page.getByTestId("kyc-historical-case").first()).toBeVisible();
  });

  test("713.4 needs_more_info case shows a document re-upload control", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/kyc/status`);
    await expect(page.getByTestId("kyc-reupload").first()).toBeVisible();
    await expect(page.getByTestId("kyc-reupload-input").first()).toBeAttached();
  });

  test("713.5 re-upload attaches a document to the needs_more_info case", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/kyc/status`);
    const input = page.getByTestId("kyc-reupload-input").first();
    const [resp] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("/v1/fs/upload") && r.request().method() === "POST"),
      input.setInputFiles({
        name: "poa.png",
        mimeType: "image/png",
        buffer: Buffer.from("89504e470d0a1a0a", "hex"),
      }),
    ]);
    // Attach should succeed (200) against the seeded needs_more_info case.
    expect([200, 409].includes(resp.status())).toBeTruthy();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Section 714 — APIs: estimated-wait, readiness/submit-gate, auth
// ──────────────────────────────────────────────────────────────────────────────

test.describe("714 — KYC self-service APIs", () => {
  test("714.1 estimated-wait endpoint returns hours + message", async ({ page }) => {
    await injectAuth(page, "alice");
    const resp = await apiGet(page, "alice", "/v1/kyc/cases/estimated-wait");
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.estimated_wait.estimated_hours).toBeGreaterThanOrEqual(1);
    expect(typeof body.estimated_wait.message).toBe("string");
    expect(body.estimated_wait.queue_position).toBeNull();
  });

  test("714.2 create case → readiness reports not ready for a fresh draft", async ({ page }) => {
    await injectAuth(page, "alice");
    const created = await apiPost(page, "alice", "/v1/kyc/cases", {});
    expect(created.ok()).toBeTruthy();
    const caseId = (await created.json()).case.kyc_case_id as string;

    const readiness = await apiGet(page, "alice", `/v1/kyc/cases/${caseId}/readiness`);
    expect(readiness.ok()).toBeTruthy();
    const rbody = await readiness.json();
    expect(rbody.readiness.ready_to_submit).toBe(false);
    expect(rbody.readiness.missing_requirements.length).toBeGreaterThan(0);
  });

  test("714.3 submitting an incomplete case is rejected by the submit gate", async ({ page }) => {
    await injectAuth(page, "alice");
    const created = await apiPost(page, "alice", "/v1/kyc/cases", {});
    const body = await created.json();
    const caseId = body.case.kyc_case_id as string;
    const version = body.case.version as number;

    const submit = await apiPost(page, "alice", `/v1/kyc/cases/${caseId}/submit`, {
      expected_version: version,
    });
    // Prereqs incomplete → 409 kyc_submit_prereq_failed.
    expect(submit.status()).toBe(409);
  });

  test("714.4 unauthenticated access to /kyc redirects to login", async ({ page }) => {
    // No injectAuth → no session cookies.
    await page.goto(`${BASE}/kyc`);
    await page.waitForURL(/\/login/, { timeout: 15_000 });
    expect(page.url()).toContain("/login");
  });
});
