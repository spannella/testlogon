/**
 * E2E tests for the shared DocumentViewer component (GAP-0246 / KYC-001).
 *
 * Section:
 *   246 — DocumentViewer component on KYC case detail (zoom / rotate / fullscreen
 *         controls + per-document tabs + VerificationStateBadge overlay)
 *
 * The DocumentViewer was previously an inline component inside KycCaseDetailPage
 * with no shared module. GAP-0246 extracts it to
 * frontend/src/components/shared/DocumentViewer.tsx so it can be reused and
 * carries a presigned-URL aware image source (falling back to the file-manager
 * proxy for legacy file_ref records).
 *
 * Auth: Root session cookies (from e2e_admin_session_setup.py).
 * KYC case seeded directly into DynamoDB (submit flow prereqs are complex).
 *
 * NOTE: do not run as part of this change — added for regression coverage only.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS       = Date.now();

const CASE_ID = `kyc_e2e_docview_${TS}`;

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

function seedKycCase(caseId: string): void {
  const ts = Math.floor(Date.now() / 1000);
  const script = `
${DDB_PRELUDE}
ts = ${ts}
case_id = "${caseId}"
user_sub = "${ALICE_ID}"
updated_sk = f"UPDATED#{str(ts).zfill(13)}#KYC#{case_id}"
item = {
    "pk": f"KYC#{case_id}",
    "sk": "META",
    "entity_type": "kyc_case",
    "kyc_case_id": case_id,
    "user_sub": user_sub,
    "status": "under_review",
    "intake_profile": "standard",
    "questionnaire": {},
    "files": [
        {"type": "selfie", "path": f"/uploads/kyc/{case_id}_selfie.jpg", "verification_state": "verified", "attached_at": ts},
        {"type": "id_front", "path": f"/uploads/kyc/{case_id}_id_front.jpg", "verification_state": "pending", "attached_at": ts},
        {"type": "id_back", "path": f"/uploads/kyc/{case_id}_id_back.jpg", "verification_state": "rejected", "attached_at": ts},
    ],
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
}
table.put_item(Item=item)
print(case_id)
  `;
  execSync(`python3 -c '${script.replace(/'/g, "'\"'\"'")}'`, {
    cwd: "/home/ubuntu/testlogon",
    timeout: 15_000,
  });
}

function deleteKycCase(caseId: string): void {
  const script = `
${DDB_PRELUDE}
table.delete_item(Key={"pk": f"KYC#${caseId}", "sk": "META"})
print("deleted")
  `;
  try {
    execSync(`python3 -c '${script.replace(/'/g, "'\"'\"'")}'`, {
      cwd: "/home/ubuntu/testlogon",
      timeout: 10_000,
    });
  } catch {
    // ignore cleanup errors
  }
}

// ─── Setup ────────────────────────────────────────────────────────────────────

let rootPage: Page;

test.beforeAll(async ({ browser }) => {
  seedKycCase(CASE_ID);
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");
});

test.afterAll(async () => {
  deleteKycCase(CASE_ID);
  await rootPage?.close();
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 246: DocumentViewer
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 246 — Shared DocumentViewer", () => {
  test.beforeEach(async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${CASE_ID}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(rootPage.getByText("Case Information")).toBeVisible({ timeout: 10_000 });
  });

  test("246.1 renders one tab per document type", async () => {
    await expect(rootPage.locator("[data-testid='doc-tab-selfie']")).toBeVisible();
    await expect(rootPage.locator("[data-testid='doc-tab-id_front']")).toBeVisible();
    await expect(rootPage.locator("[data-testid='doc-tab-id_back']")).toBeVisible();
  });

  test("246.2 exposes zoom, rotate, and fullscreen controls", async () => {
    await expect(rootPage.getByRole("button", { name: "Zoom In" })).toBeVisible();
    await expect(rootPage.getByRole("button", { name: "Zoom Out" })).toBeVisible();
    await expect(rootPage.getByRole("button", { name: "Rotate CW" })).toBeVisible();
    await expect(rootPage.getByRole("button", { name: "Rotate CCW" })).toBeVisible();
    await expect(rootPage.getByRole("button", { name: "Fullscreen" })).toBeVisible();

    // Controls should be clickable without errors.
    await rootPage.getByRole("button", { name: "Zoom In" }).click();
    await rootPage.getByRole("button", { name: "Rotate CW" }).click();
    await rootPage.getByRole("button", { name: "Rotate CCW" }).click();
    await rootPage.getByRole("button", { name: "Zoom Out" }).click();
  });

  test("246.3 fullscreen toggle shows and hides the overlay", async () => {
    const fsButton = rootPage.getByRole("button", { name: "Fullscreen" });
    await fsButton.click();
    await expect(rootPage.locator(".fixed.inset-0.z-50")).toBeVisible();
    // A transient sonner toast (top-right, high z-index) can overlap the
    // Fullscreen button in the overlay and intercept the toggle-off click.
    // Dismiss any visible toast first, then wait for it to detach.
    const toasts = rootPage.locator("[data-sonner-toast]");
    if (await toasts.count()) {
      await toasts.first().click({ force: true }).catch(() => {});
      await rootPage.locator("[data-sonner-toast]").first().waitFor({ state: "detached" }).catch(() => {});
    }
    // Toggle off (force-click guards against any residual overlay intercept).
    await fsButton.click({ force: true });
    await expect(rootPage.locator(".fixed.inset-0.z-50")).toHaveCount(0);
  });

  test("246.4 shows a verification badge on the active document", async () => {
    await expect(
      rootPage.locator("[data-testid='verification-badge']").first(),
    ).toBeVisible();
  });

  test("246.5 switching tabs reveals the corresponding document", async () => {
    await rootPage.locator("[data-testid='doc-tab-id_front']").click();
    // The active tab content should render an image element for the document.
    await expect(rootPage.locator("[data-testid='doc-image']").first()).toBeVisible({
      timeout: 5_000,
    });
  });
});
