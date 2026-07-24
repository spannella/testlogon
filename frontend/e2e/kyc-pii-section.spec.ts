/**
 * E2E tests for the "Sensitive PII" tab + KycPiiSection on the KYC admin case
 * detail page (GAP-0288 / KYC-023 §3.12).
 *
 * Section:
 *   288 — The KycPiiSection component (composing PiiFieldDisplay + PiiAuditLog)
 *         is wired into KycCaseDetailPage.tsx as a dedicated "Sensitive PII" tab.
 *         Before GAP-0288 the component existed but was imported nowhere, so
 *         admins could not view masked PII, reveal fields, or (as root) manage
 *         encryption keys / view the audit log from the UI.
 *
 * Props derivation under test:
 *   - caseId / userSub  from the loaded KycCaseDetail
 *   - canReveal         = isRoot OR viewer is the assigned admin
 *   - isRoot            = role claim in the access-token JWT === "root"
 *
 * Auth: e2e_admin_session_setup.py (root, alice, charlie_admin).
 * The PII case is created + encrypted via the real API (intake_profile kyc023).
 *
 * IMPORTANT: unlike most KYC specs, this spec injects the REAL access token into
 * the auth store so getRoleFromAccessToken() can resolve root vs admin. The PII
 * tab's root-only key-management section depends on that role claim.
 *
 * NOTE: do not run as part of this change — added for regression coverage only.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const CHARLIE_SUB = "e2e_charlie@test.local";

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

/**
 * Injects cookies AND the real access token. The access token is required so the
 * page can derive isRoot via getRoleFromAccessToken() — injecting null (as most
 * KYC specs do) would make every viewer appear non-root.
 */
async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const s = getSessions()[identity];
  if (!s) throw new Error(`No session for ${identity}`);
  const page = await browser.newPage();
  await page.context().addCookies(s.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    ({ uid, token }) => {
      const state = { userId: uid, accessToken: token, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    { uid: s.user_sub, token: s.access_token },
  );
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body?: object) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
  });
}

// ─── DDB helpers ────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os, json
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

/** Assign an admin sub onto a case's review ref (no REST endpoint for this). */
function assignAdminDirect(caseId: string, adminSub: string): void {
  execSync(
    `python3 -c "${DDB_PRELUDE}
tbl = ddb.Table('kyc_cases')
pk = 'KYC#${caseId}'
resp = tbl.get_item(Key={'pk': pk, 'sk': 'META'})
item = resp['Item']
review = dict(item.get('review') or {})
review['assigned_admin_sub'] = '${adminSub}'
tbl.update_item(Key={'pk': pk, 'sk': 'META'}, UpdateExpression='SET review=:r', ExpressionAttributeValues={':r': review})
print('assigned')
"`,
    { timeout: 10_000 },
  );
}

const SAMPLE_PII = {
  document_number: "AB1234567",
  date_of_birth: "1990-01-15",
  tax_id: "123-45-6789",
};

interface KycCaseOut {
  kyc_case_id: string;
  user_sub: string;
  version: number;
}

/** Create a draft case as alice and encrypt SAMPLE_PII onto it. */
async function createCaseWithPii(alicePage: Page): Promise<KycCaseOut> {
  const created = await apiPost(alicePage, "alice", "/v1/kyc/cases", { intake_profile: "kyc023" });
  expect(created.ok()).toBeTruthy();
  const c = (await created.json()).case as KycCaseOut;
  const wrote = await apiPost(alicePage, "alice", `/v1/kyc/cases/${c.kyc_case_id}/pii`, {
    expected_version: c.version,
    pii: SAMPLE_PII,
  });
  expect(wrote.ok()).toBeTruthy();
  return c;
}

// ─── Setup ──────────────────────────────────────────────────────────────────

let rootPage: Page;
let charliePage: Page;
let alicePage: Page;

// Case assigned to charlie_admin (charlie may reveal).
let assignedCase: KycCaseOut;
// Case with no assigned admin (charlie may NOT reveal, but root still can).
let unassignedCase: KycCaseOut;

test.beforeAll(async ({ browser }) => {
  alicePage = await newIdentityPage(browser, "alice");
  rootPage = await newIdentityPage(browser, "root");
  charliePage = await newIdentityPage(browser, "charlie_admin");

  assignedCase = await createCaseWithPii(alicePage);
  assignAdminDirect(assignedCase.kyc_case_id, CHARLIE_SUB);

  unassignedCase = await createCaseWithPii(alicePage);
});

test.afterAll(async () => {
  await alicePage?.close();
  await rootPage?.close();
  await charliePage?.close();
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 288: Sensitive PII tab (KycPiiSection wiring)
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 288 — Sensitive PII tab", () => {
  test("288.1 case detail page exposes a Sensitive PII tab", async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${assignedCase.kyc_case_id}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(rootPage.getByTestId("tab-pii")).toBeVisible({ timeout: 10_000 });
  });

  test("288.2 KycPiiSection renders masked PII fields", async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${assignedCase.kyc_case_id}`, {
      waitUntil: "domcontentloaded",
    });
    await rootPage.getByTestId("tab-pii").click();

    await expect(rootPage.getByTestId("kyc-pii-section")).toBeVisible({ timeout: 10_000 });
    // One PiiFieldDisplay row per encrypted field.
    await expect(rootPage.getByTestId("pii-field-document_number")).toBeVisible();
    await expect(rootPage.getByTestId("pii-field-date_of_birth")).toBeVisible();
    await expect(rootPage.getByTestId("pii-field-tax_id")).toBeVisible();
    // Plaintext must NOT be present while masked.
    await expect(rootPage.getByTestId("pii-value-document_number")).not.toContainText("AB1234567");
  });

  test("288.3 root sees key-management controls + audit log", async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${assignedCase.kyc_case_id}`, {
      waitUntil: "domcontentloaded",
    });
    await rootPage.getByTestId("tab-pii").click();

    await expect(rootPage.getByTestId("kyc-pii-rotate")).toBeVisible({ timeout: 10_000 });
    await expect(rootPage.getByTestId("kyc-pii-destroy")).toBeVisible();
  });

  test("288.4 root can reveal a PII field (decrypts + shows plaintext)", async () => {
    await rootPage.goto(`${BASE}/admin/kyc/cases/${assignedCase.kyc_case_id}`, {
      waitUntil: "domcontentloaded",
    });
    await rootPage.getByTestId("tab-pii").click();
    await expect(rootPage.getByTestId("kyc-pii-section")).toBeVisible({ timeout: 10_000 });

    await rootPage.getByTestId("pii-reveal-document_number").click();
    await rootPage.getByTestId("pii-reason-document_number").fill("E2E PII reveal regression check");
    await rootPage.getByTestId("pii-reveal-confirm-document_number").click();

    await expect(rootPage.getByTestId("pii-value-document_number")).toContainText("AB1234567", {
      timeout: 10_000,
    });
  });

  test("288.5 assigned admin sees Reveal buttons", async () => {
    await charliePage.goto(`${BASE}/admin/kyc/cases/${assignedCase.kyc_case_id}`, {
      waitUntil: "domcontentloaded",
    });
    await charliePage.getByTestId("tab-pii").click();
    await expect(charliePage.getByTestId("kyc-pii-section")).toBeVisible({ timeout: 10_000 });

    await expect(charliePage.getByTestId("pii-reveal-document_number")).toBeVisible();
    // Non-root admin: no key-management section.
    await expect(charliePage.getByTestId("kyc-pii-rotate")).toHaveCount(0);
  });

  test("288.6 non-assigned admin is denied case access (reviewer-scope gate)", async () => {
    // KYC-023 reviewer-scope: a non-root admin who is NOT the case's assigned
    // reviewer can no longer view the case detail at all (the admin case-detail
    // API now enforces _is_scoped_admin_for_case → kyc_access_forbidden). The
    // detail page therefore never loads, so the PII tab + Reveal buttons are
    // absent rather than rendered-but-masked.
    const apiResp = await charliePage.request.get(
      `${API}/v1/kyc/cases/admin/cases/${unassignedCase.kyc_case_id}`,
    );
    expect(apiResp.status()).toBe(403);

    await charliePage.goto(`${BASE}/admin/kyc/cases/${unassignedCase.kyc_case_id}`, {
      waitUntil: "domcontentloaded",
    });
    // Access denied → page falls back to the "Case not found." state; no tabs.
    await expect(charliePage.getByText("Case not found.")).toBeVisible({ timeout: 10_000 });
    await expect(charliePage.getByTestId("tab-pii")).toHaveCount(0);
    await expect(charliePage.locator("[data-testid^='pii-reveal-']")).toHaveCount(0);
  });
});
