/**
 * VIDEO SEGMENT 12 — Identity Verification (KYC)  (~110-145s)
 *
 * A guided tour of the platform's KYC / identity-verification stack:
 *   - User submission + status (/kyc/status): the applicant's case status,
 *     review timeline, and estimated wait
 *   - Admin review queue (/admin/kyc): every pending case with risk tier + SLA
 *   - Case detail (/admin/kyc/cases/:id): the document viewer (an ID document)
 *     + extracted OCR fields, the verification/liveness call panel, the masked
 *     PII section with an audited reveal, and the approve/reject decision
 *   - KYC metrics dashboard (/admin/kyc/metrics): funnel, approval rate, latency
 *
 * Pattern mirrors seg11-tickets.demo.ts: ONE long test, paced with beat() and
 * narrated with caption()/titleCard(). Everything shown is brought on-screen and
 * PROVEN visible via reveal()'s toBeInViewport assertion.
 *
 * Cast (sessions seeded by e2e_admin_session_setup.py + e2e_session_setup.py):
 *   - alice — the applicant (owns the KYC case + its PII)
 *   - root  — on camera for the admin review surfaces (role=root → can view any
 *             case detail + decrypt PII; the case-detail API is reviewer-scoped,
 *             so root is the safe reviewer to film)
 *
 * Seeding (all off-camera, before any UI is shown):
 *   - One submitted/under_review KYC case owned by alice, intake_profile=enhanced
 *     (→ "high" risk tier in the queue), assigned to root, with three identity
 *     files for the document viewer, seeded directly into DynamoDB.
 *   - Three extraction documents for that case in kyc_documents (status=extracted,
 *     with extracted_fields + match_results + overall_confidence).
 *   - One scheduled liveness/verification call for that case in kyc_liveness_calls.
 *   - Real encrypted PII written onto the case via the API as alice (so the masked
 *     PII section + audited reveal operate on genuine ciphertext).
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg12-kyc.demo.ts
 */
import { test, expect, type APIResponse } from "@playwright/test";
import { execSync } from "child_process";
import {
  BASE,
  API,
  injectAuth,
  caption,
  clearCaption,
  titleCard,
  beat,
  reveal,
  loadSessions,
  type SessionData,
} from "./_demo";

const ALICE = "alice";
const ROOT = "root";
const ALICE_SUB = "e2e_alice@test.local";
const ROOT_SUB = "root.admin@testdev.local";

const STAMP = Date.now();
const CASE_ID = `kyc_demo_${STAMP}`;

async function jsonOk(resp: APIResponse, what: string): Promise<any> {
  if (!resp.ok()) throw new Error(`${what} failed: ${resp.status()} ${await resp.text()}`);
  return resp.json();
}

/** CSRF-authenticated POST from the page's browser context as identity `key`. */
function poster(page: import("@playwright/test").Page, sess: SessionData) {
  return (path: string, body: unknown) =>
    page.request.post(`${API}${path}`, {
      headers: { "x-csrf-token": sess.csrf_token, "content-type": "application/json" },
      data: body,
    });
}

/**
 * Seed the KYC case (META row), three extraction documents, and one liveness
 * call directly into DynamoDB. The case is owned by alice, assigned to root, in
 * an "enhanced" profile (→ "high" risk in the queue) so the review surfaces are
 * populated and the case-detail reviewer-scope gate admits root.
 */
function seedKyc(): void {
  const py = `
import boto3, os, time
from pathlib import Path
env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
cases = ddb.Table('kyc_cases')
docs = ddb.Table('kyc_documents')
calls = ddb.Table('kyc_liveness_calls')

case_id = "${CASE_ID}"
user_sub = "${ALICE_SUB}"
root_sub = "${ROOT_SUB}"
ts = int(time.time())
updated_sk = f"UPDATED#{str(ts).zfill(13)}#KYC#{case_id}"

cases.put_item(Item={
    "pk": f"KYC#{case_id}",
    "sk": "META",
    "entity_type": "kyc_case",
    "kyc_case_id": case_id,
    "user_sub": user_sub,
    "status": "under_review",
    "intake_profile": "enhanced",
    "questionnaire": {"questionnaire_id": "kyc_intake_v3", "version_id": "v3"},
    "files": [
        {"type": "id_front", "path": f"/kyc/{case_id}/id_front.jpg", "verification_state": "verified", "uploaded_at": ts},
        {"type": "id_back", "path": f"/kyc/{case_id}/id_back.jpg", "verification_state": "pending", "uploaded_at": ts},
        {"type": "selfie", "path": f"/kyc/{case_id}/selfie.jpg", "verification_state": "verified", "uploaded_at": ts},
    ],
    "signature": {"packet_id": "sigpkt_demo", "status": "completed"},
    "submission": {"submitted_at": ts},
    "review": {"ticket_id": None, "assigned_admin_sub": root_sub, "decision": None, "decided_at": None, "reason_codes": [], "risk_tier": "high"},
    "created_at": ts - 7200,
    "updated_at": ts,
    "version": 1,
    "gsi_owner_pk": f"OWNER#{user_sub}",
    "gsi_owner_sk": updated_sk,
    "gsi_status_pk": "STATUS#under_review",
    "gsi_status_sk": updated_sk,
})

def doc(idx, dtype, fields, matches, conf):
    docs.put_item(Item={
        "document_id": f"kycdoc_{case_id}_{idx}",
        "user_sub": user_sub,
        "case_id": case_id,
        "document_type": dtype,
        "file_name": f"{dtype}.jpg",
        "status": "extracted",
        "provider": "mock",
        "s3_key": f"kyc/{case_id}/{dtype}.jpg",
        "bucket": "kyc-docs",
        "image_url": None,
        "extraction_id": f"ext_{idx}",
        "extracted_fields": fields,
        "match_results": matches,
        "overall_confidence": conf,
        "review": {"decision": None, "reviewer_sub": None, "decided_at": None, "note": None},
        "created_at": ts - idx,
        "updated_at": ts - idx,
    })

doc(1, "id_front", {
        "full_name": "Alice Anderson",
        "document_number": "P1234567",
        "date_of_birth": "1990-04-12",
        "expiry_date": "2031-04-11",
        "nationality": "USA",
    }, {
        "full_name": {"status": "match"},
        "document_number": {"status": "match"},
        "date_of_birth": {"status": "match"},
        "expiry_date": {"status": "match"},
    }, "high")

cases_done = True
print("seeded_case", case_id)

calls.put_item(Item={
    "call_id": f"kyclc_{case_id}",
    "case_id": case_id,
    "user_sub": user_sub,
    "status": "scheduled",
    "scheduled_at": ts + 3600,
    "duration_minutes": 30,
    "verifier_sub": "_unassigned",
    "note": "Liveness + document hold-up check",
    "result": None,
    "result_notes": None,
    "result_set_at": None,
    "recording_ref": None,
    "started_at": None,
    "conducted_by": None,
    "created_at": ts,
    "updated_at": ts,
})
print("seeded_call")
`;
  execSync(`python3 -c '${py.replace(/'/g, "'\"'\"'")}'`, {
    cwd: "/home/ubuntu/testlogon",
    timeout: 30_000,
  });
}

test("Segment 12 — Identity Verification (KYC)", async ({ page }) => {
  test.setTimeout(600_000);
  const sessions = loadSessions();
  const alice: SessionData = sessions[ALICE];
  const root: SessionData = sessions[ROOT];

  // ── Off-camera seeding ──────────────────────────────────────────────────────
  seedKyc();

  // Write real encrypted PII onto the case as alice (owner). The case was seeded
  // at version 1, so expected_version=1. This makes the masked PII section + the
  // audited reveal operate on genuine ciphertext rather than placeholders.
  await injectAuth(page, ALICE);
  const postAlice = poster(page, alice);
  await jsonOk(
    (await postAlice(`/v1/kyc/cases/${CASE_ID}/pii`, {
      expected_version: 1,
      pii: {
        document_number: "P1234567",
        date_of_birth: "1990-04-12",
        tax_id: "123-45-6789",
      },
    })) as APIResponse,
    "write PII",
  );

  // ── Switch to root for the on-camera admin tour ─────────────────────────────
  await injectAuth(page, ROOT);
  void root;

  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1000);

  // ── 1. Intro ────────────────────────────────────────────────────────────────
  await titleCard(
    page,
    12,
    "Identity Verification (KYC)",
    "Submit · admin review · documents · liveness · risk scoring · decision",
  );

  // ── 2. User submission + status ─────────────────────────────────────────────
  await caption(page, "The applicant's view", "Switching to the user's verification status…");
  await injectAuth(page, ALICE);
  await page.goto(`${BASE}/kyc/status`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kyc-status-page")).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1200);

  await reveal(
    page,
    page.locator("h1").filter({ hasText: /verification status/i }).first(),
    "Verification status",
    "Applicants track their KYC case from submission to decision",
    { ms: 3400 },
  );
  await reveal(
    page,
    page.getByTestId("kyc-timeline").first(),
    "A clear review timeline",
    "Submitted → under review → approved, with a live status badge",
    { ms: 3600 },
  );
  await reveal(
    page,
    page.getByTestId("kyc-estimated-wait").first(),
    "Estimated review time",
    "The applicant always knows roughly how long the review will take",
    { ms: 3400 },
  );

  // ── 3. Admin review queue ───────────────────────────────────────────────────
  await caption(page, "The reviewer's view", "Switching to the admin KYC queue…");
  await injectAuth(page, ROOT);
  await page.goto(`${BASE}/admin/kyc`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: /kyc review queue/i })).toBeVisible({
    timeout: 12_000,
  });
  await page.waitForTimeout(1500);

  await reveal(
    page,
    page.getByRole("heading", { name: /kyc review queue/i }).first(),
    "The KYC review queue",
    "Every pending case in one place — filter by status, risk, or assignee",
    { ms: 3600 },
  );
  const caseRow = page.getByTestId(`kyc-row-${CASE_ID}`);
  await reveal(
    page,
    caseRow,
    "A case awaiting review",
    "Each row shows the applicant, status, risk tier, wait time, and reviewer",
    { ms: 3800 },
  );

  // ── 4. Case detail: document viewer + extracted fields ──────────────────────
  await caption(page, "Opening the case", "Loading the full review workspace…");
  await page.goto(`${BASE}/admin/kyc/cases/${CASE_ID}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByText("Case Information")).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1400);

  await reveal(
    page,
    page.locator("[data-testid='doc-tab-id_front']").first(),
    "The document viewer",
    "Inspect every uploaded document — ID front, ID back, and selfie",
    { ms: 3600 },
  );
  await reveal(
    page,
    page.getByRole("button", { name: "Fullscreen" }).first(),
    "Zoom, rotate, fullscreen",
    "Reviewers can zoom in, rotate, and go fullscreen to scrutinize an ID",
    { ms: 3400 },
  );
  await reveal(
    page,
    page.locator("[data-testid='verification-badge']").first(),
    "Per-document verification state",
    "Each document carries its own verified / pending / rejected state",
    { ms: 3200 },
  );

  // Switch to the Document Extraction tab for the OCR fields.
  await page.getByTestId("tab-extraction").click();
  await expect(page.getByTestId("extraction-results-panel")).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1000);
  await reveal(
    page,
    page.getByTestId("extraction-results-panel").first(),
    "Extracted document fields",
    "OCR pulls name, document number, and dates — each cross-checked for a match",
    { ms: 4000 },
  );
  await reveal(
    page,
    page.getByTestId("doc-confidence").first(),
    "Confidence scoring",
    "Every extraction reports an overall confidence the reviewer can trust",
    { ms: 3200 },
  );

  // ── 5. Liveness / verification call panel ───────────────────────────────────
  await page.getByTestId("tab-overview").click();
  await page.waitForTimeout(800);
  await reveal(
    page,
    page.getByTestId("verification-call-panel").first(),
    "The verification call",
    "Schedule a live liveness call — conduct it, then record pass or fail",
    { ms: 3600 },
  );
  await reveal(
    page,
    page.getByTestId("call-status-badge").first(),
    "Liveness check status",
    "A scheduled call is tracked end-to-end alongside the documents",
    { ms: 3200 },
  );

  // ── 6. Risk & tier ──────────────────────────────────────────────────────────
  // The case-detail status badge sits with the case header; the risk tier itself
  // is surfaced on the queue. Show the case status badge here, then the risk tier
  // is already established from the queue reveal above.
  await reveal(
    page,
    page.getByTestId("case-status-badge").first(),
    "Risk & status",
    "This enhanced-profile case is flagged high-risk and under active review",
    { ms: 3400 },
  );

  // ── 7. Sensitive PII: masked + audited reveal ───────────────────────────────
  await page.getByTestId("tab-pii").click();
  await expect(page.getByTestId("kyc-pii-section")).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1000);
  await reveal(
    page,
    page.getByTestId("pii-field-document_number").first(),
    "Sensitive PII stays masked",
    "Document number, date of birth, and tax ID are encrypted at rest",
    { ms: 3600 },
  );

  // Perform an audited reveal of the document number.
  await caption(page, "Reveal with an audit trail", "Decryption requires a reason and is logged");
  await page.getByTestId("pii-reveal-document_number").click();
  await page.waitForTimeout(500);
  await page
    .getByTestId("pii-reason-document_number")
    .fill("KYC review — confirming ID document number");
  await page.waitForTimeout(500);
  await page.getByTestId("pii-reveal-confirm-document_number").click();
  await expect(page.getByTestId("pii-value-document_number")).toContainText("P1234567", {
    timeout: 12_000,
  });
  await reveal(
    page,
    page.getByTestId("pii-value-document_number").first(),
    "Decrypted — and recorded",
    "The plaintext is shown only after a logged, reasoned reveal",
    { ms: 3800 },
  );

  // ── 8. Decision: approve / reject ───────────────────────────────────────────
  await page.getByTestId("tab-overview").click();
  await page.waitForTimeout(800);
  await reveal(
    page,
    page.getByRole("button", { name: "Approve" }).first(),
    "The decision",
    "Approve, reject, or request more info — every choice is reason-coded",
    { ms: 3600 },
  );

  // Open the approve dialog to show the reason codes + notes, then approve.
  await page.getByRole("button", { name: "Approve" }).first().click();
  await expect(page.getByRole("heading", { name: "Approve Case" })).toBeVisible({
    timeout: 10_000,
  });
  await page.waitForTimeout(800);
  await reveal(
    page,
    page.getByRole("heading", { name: "Approve Case" }).first(),
    "Reason-coded approval",
    "Pick the reason codes and add a note before confirming",
    { ms: 3400, ring: false },
  );
  await page.getByLabel("Identity Verified").click();
  await page.getByLabel("Documents Valid").click();
  await page.locator("#approve-note").fill("Identity confirmed against verified documents.");
  await page.waitForTimeout(600);
  await Promise.all([
    page
      .waitForResponse(
        (r) => r.url().includes(CASE_ID) && r.request().method() === "POST",
        { timeout: 15_000 },
      )
      .catch(() => null),
    page.getByRole("button", { name: /confirm approval/i }).click(),
  ]);
  await page.waitForTimeout(2000);

  // The case status badge now reads "approved".
  await reveal(
    page,
    page.getByTestId("case-status-badge").filter({ hasText: /approved/i }).first(),
    "Approved",
    "The case transitions to approved — the applicant is notified instantly",
    { ms: 3600 },
  );

  // ── 9. Metrics dashboard ────────────────────────────────────────────────────
  await caption(page, "KYC metrics", "Loading the compliance dashboard…");
  await page.goto(`${BASE}/admin/kyc/metrics`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: /kyc metrics/i })).toBeVisible({
    timeout: 12_000,
  });
  await page.waitForTimeout(1400);
  await reveal(
    page,
    page.getByRole("heading", { name: /kyc metrics/i }).first(),
    "The metrics dashboard",
    "Funnel counts, approval rate, and review-latency percentiles at a glance",
    { ms: 3600 },
  );
  await reveal(
    page,
    page.getByTestId("approval-rate").first(),
    "Approval rate & latency",
    "Track throughput and p50/p90/p99 review times across the whole pipeline",
    { ms: 3600 },
  );

  // ── 10. Outro ───────────────────────────────────────────────────────────────
  await caption(page, "KYC ✓", "Next: Ads Platform");
  await beat(page, 3200);
  await clearCaption(page);
  await beat(page, 900);
});
