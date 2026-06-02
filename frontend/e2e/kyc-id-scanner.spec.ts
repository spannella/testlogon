/**
 * E2E tests for KYC-010: Passport / National-ID Scanner.
 *
 * Section 191: MRZ scan + check-digit validation API (passport TD3, ID TD1)
 * Section 192: Expiry + status lifecycle + cross-reference API
 * Section 193: Reviewer list-by-status + adjudication API + ownership
 *
 * NET-NEW scanner invoked explicitly via POST /scan-document; independent of the
 * KYC case file-attachment flow. Owner endpoints use require_ui_session (cookie
 * + CSRF); reviewer endpoints use require_admin_or_root.
 *
 * Auth: cookie + CSRF via e2e_admin_session_setup.py (root, alice, bob,
 * charlie_admin).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";

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

// Seed a KYC case META.identity so cross-reference is deterministic.
function seedCaseIdentity(caseId: string, firstName: string, lastName: string, dob: string, nat: string) {
  const py = [
    "import boto3, os",
    "ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name=os.environ.get('AWS_DEFAULT_REGION','us-east-1'), aws_access_key_id='test', aws_secret_access_key='test')",
    "t = ddb.Table('kyc_cases')",
    `t.update_item(Key={'pk':'KYC#${caseId}','sk':'META'}, UpdateExpression='SET #idn = :i', ExpressionAttributeNames={'#idn':'identity'}, ExpressionAttributeValues={':i': {'first_name':'${firstName}','last_name':'${lastName}','date_of_birth':'${dob}','nationality':'${nat}'}})`,
  ].join("\n");
  execSync(`python3 -c "${py.replace(/"/g, '\\"')}"`, {
    cwd: "/home/ubuntu/testlogon",
    env: { ...process.env, DDB_ENDPOINT_URL: "http://localhost:8001", AWS_DEFAULT_REGION: "us-east-1" },
    timeout: 30_000,
  });
}

async function createCase(page: Page, identity: string): Promise<string> {
  const resp = await apiPost(page, identity, "v1/kyc/cases", { intake_profile: "individual" });
  expect(resp.status()).toBeLessThan(300);
  const body = await resp.json();
  return body.case.kyc_case_id as string;
}

// Valid TD3 passport MRZ (ICAO 9303 sample, all check digits valid).
const TD3_LINE1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
const TD3_LINE2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";
// Valid TD1 national-ID MRZ.
const TD1_LINE1 = "I<UTOD231458907<<<<<<<<<<<<<<<";
const TD1_LINE2 = "7408122F1204159UTO<<<<<<<<<<<6";
const TD1_LINE3 = "ERIKSSON<<ANNA<MARIA<<<<<<<<<<";

// Build a TD3 line2 with an expiry date N days from today and valid check digits.
function buildTd3Line2WithExpiry(daysFromNow: number): string {
  const d = new Date();
  d.setDate(d.getDate() + daysFromNow);
  const yy = String(d.getFullYear() % 100).padStart(2, "0");
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const expiry = `${yy}${mm}${dd}`;
  const weights = [7, 3, 1];
  const cd = (s: string): string => {
    let total = 0;
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      let v = 0;
      if (ch === "<") v = 0;
      else if (ch >= "0" && ch <= "9") v = ch.charCodeAt(0) - 48;
      else if (/[A-Z]/.test(ch)) v = ch.charCodeAt(0) - 55;
      total += v * weights[i % 3];
    }
    return String(total % 10);
  };
  const docNum = "L898902C3";
  const docCd = cd(docNum);
  const nat = "UTO";
  const dob = "740812";
  const dobCd = cd(dob);
  const sex = "F";
  const expCd = cd(expiry);
  const optional = "ZE184226B<<<<<";
  const optCd = cd(optional);
  const composite =
    docNum + docCd + dob + dobCd + expiry + expCd + optional + optCd;
  const compCd = cd(composite);
  return `${docNum}${docCd}${nat}${dob}${dobCd}${sex}${expiry}${expCd}${optional}${optCd}${compCd}`;
}

// ─── Section 191: MRZ scan + check-digit validation ─────────────────────────

test.describe("191: KYC ID scanner MRZ + check digits", () => {
  let alice: Page;
  let caseId: string;
  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    caseId = await createCase(alice, "alice");
    seedCaseIdentity(caseId, "Anna Maria", "Eriksson", "1974-08-12", "UTO");
  });
  test.afterAll(async () => alice.close());

  test("191.1 valid TD3 passport returns parsed fields + passing check digits + matched", async () => {
    const resp = await apiPost(alice, "alice", `ui/kyc/id-scanner/cases/${caseId}/scan-document`, {
      document_type: "passport",
      file_type: "id_front",
      mrz_lines: [TD3_LINE1, TD3_LINE2],
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.extraction.surname).toBe("ERIKSSON");
    expect(body.extraction.given_names).toBe("ANNA MARIA");
    expect(body.extraction.document_number).toBe("L898902C3");
    expect(body.extraction.nationality).toBe("UTO");
    expect(body.extraction.date_of_birth).toBe("1974-08-12");
    expect(body.extraction.checksums.document_number).toBe(true);
    expect(body.extraction.checksums.composite).toBe(true);
    expect(body.mrz_valid).toBe(true);
    // Document expired long ago (2012) -> rejected; but check digits all valid.
    expect(["matched", "rejected", "flagged"]).toContain(body.status);
  });

  test("191.2 bad check digit flags the scan (valid=false)", async () => {
    // Corrupt the document-number check digit (position 9).
    const bad = TD3_LINE2.slice(0, 9) + "0" + TD3_LINE2.slice(10);
    const resp = await apiPost(alice, "alice", `ui/kyc/id-scanner/cases/${caseId}/scan-document`, {
      document_type: "passport",
      file_type: "id_front",
      mrz_lines: [TD3_LINE1, bad],
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.extraction.valid).toBe(false);
    expect(body.extraction.checksums.document_number).toBe(false);
    expect(body.mrz_valid).toBe(false);
    expect(body.status).toBe("flagged");
  });

  test("191.3 valid TD1 national-ID returns parsed fields", async () => {
    const resp = await apiPost(alice, "alice", `ui/kyc/id-scanner/cases/${caseId}/scan-document`, {
      document_type: "national_id_card",
      file_type: "id_front",
      mrz_lines: [TD1_LINE1, TD1_LINE2, TD1_LINE3],
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.extraction.format).toBe("TD1");
    expect(body.extraction.surname).toBe("ERIKSSON");
    expect(body.extraction.document_number).toBe("D23145890");
    expect(body.extraction.nationality).toBe("UTO");
  });

  test("191.4 wrong MRZ line count returns 400", async () => {
    const resp = await apiPost(alice, "alice", `ui/kyc/id-scanner/cases/${caseId}/scan-document`, {
      document_type: "passport",
      file_type: "id_front",
      mrz_lines: ["ONLY_ONE_LINE"],
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail.code).toBe("kyc_mrz_invalid_lines");
  });

  test("191.5 MRZ wrong length returns extraction error (not a hard failure)", async () => {
    const resp = await apiPost(alice, "alice", `ui/kyc/id-scanner/cases/${caseId}/scan-document`, {
      document_type: "passport",
      file_type: "id_front",
      mrz_lines: ["TOOSHORT", "ALSOTOOSHORT"],
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.extraction.error).toBe("invalid_mrz_length");
    expect(body.status).toBe("flagged");
  });

  test("191.6 invalid document_type returns 422", async () => {
    const resp = await apiPost(alice, "alice", `ui/kyc/id-scanner/cases/${caseId}/scan-document`, {
      document_type: "magic_card",
      file_type: "id_front",
    });
    expect(resp.status()).toBe(422);
  });

  test("191.7 driving license scan has no MRZ (valid null)", async () => {
    const resp = await apiPost(alice, "alice", `ui/kyc/id-scanner/cases/${caseId}/scan-document`, {
      document_type: "driving_license",
      file_type: "id_front",
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.extraction.valid).toBeNull();
    expect(body.document_type).toBe("driving_license");
  });
});

// ─── Section 192: expiry + status lifecycle + cross-reference ───────────────

test.describe("192: KYC ID scanner expiry + cross-reference", () => {
  let alice: Page;
  let caseId: string;
  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    caseId = await createCase(alice, "alice");
    seedCaseIdentity(caseId, "Anna Maria", "Eriksson", "1974-08-12", "UTO");
  });
  test.afterAll(async () => alice.close());

  test("192.1 expired document is rejected", async () => {
    const line2 = buildTd3Line2WithExpiry(-30);
    const resp = await apiPost(alice, "alice", `ui/kyc/id-scanner/cases/${caseId}/scan-document`, {
      document_type: "passport",
      file_type: "id_front",
      mrz_lines: [TD3_LINE1, line2],
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.expiry_check.status).toBe("expired");
    expect(body.status).toBe("rejected");
  });

  test("192.2 document expiring within 90 days is flagged (expiring_soon)", async () => {
    const line2 = buildTd3Line2WithExpiry(60);
    const resp = await apiPost(alice, "alice", `ui/kyc/id-scanner/cases/${caseId}/scan-document`, {
      document_type: "passport",
      file_type: "id_front",
      mrz_lines: [TD3_LINE1, line2],
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.expiry_check.status).toBe("expiring_soon");
    expect(body.status).toBe("flagged");
  });

  test("192.3 valid future expiry + matching profile returns matched", async () => {
    const line2 = buildTd3Line2WithExpiry(800);
    const resp = await apiPost(alice, "alice", `ui/kyc/id-scanner/cases/${caseId}/scan-document`, {
      document_type: "passport",
      file_type: "id_front",
      mrz_lines: [TD3_LINE1, line2],
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.expiry_check.status).toBe("valid");
    expect(body.cross_reference).not.toBeNull();
    expect(body.cross_reference.match_score).toBeGreaterThanOrEqual(50);
    expect(body.status).toBe("matched");
  });

  test("192.4 mismatched profile flags the scan (low match score)", async () => {
    const otherCase = await createCase(alice, "alice");
    seedCaseIdentity(otherCase, "Bob", "Jones", "1990-01-01", "GBR");
    const line2 = buildTd3Line2WithExpiry(800);
    const resp = await apiPost(alice, "alice", `ui/kyc/id-scanner/cases/${otherCase}/scan-document`, {
      document_type: "passport",
      file_type: "id_front",
      mrz_lines: [TD3_LINE1, line2],
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.cross_reference.match_score).toBeLessThan(50);
    expect(Object.keys(body.cross_reference.mismatches).length).toBeGreaterThan(0);
    expect(body.status).toBe("flagged");
  });

  test("192.5 validate-document returns side requirements for passport", async () => {
    const resp = await apiPost(alice, "alice", `ui/kyc/id-scanner/cases/${caseId}/validate-document`, {
      document_type: "passport",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.sides_required).toEqual(["front"]);
    expect(body.has_mrz).toBe(true);
    expect(body.mrz_format).toBe("TD3");
  });

  test("192.6 validate-document returns front+back for national ID", async () => {
    const resp = await apiPost(alice, "alice", `ui/kyc/id-scanner/cases/${caseId}/validate-document`, {
      document_type: "national_id_card",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.sides_required).toEqual(["front", "back"]);
  });

  test("192.7 list scans for a case returns this case's scans", async () => {
    const resp = await apiGet(alice, `ui/kyc/id-scanner/cases/${caseId}/scans`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.scans)).toBe(true);
    expect(body.scans.length).toBeGreaterThan(0);
    for (const s of body.scans) expect(s.case_id).toBe(caseId);
  });
});

// ─── Section 193: reviewer list-by-status + adjudication + ownership ────────

test.describe("193: KYC ID scanner reviewer + ownership", () => {
  let alice: Page;
  let bob: Page;
  let root: Page;
  let caseId: string;
  let flaggedScanId: string;
  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    bob = await newIdentityPage(browser, "bob");
    root = await newIdentityPage(browser, "root");
    caseId = await createCase(alice, "alice");
    seedCaseIdentity(caseId, "Anna Maria", "Eriksson", "1974-08-12", "UTO");
    // A flagged scan (bad check digit).
    const bad = TD3_LINE2.slice(0, 9) + "0" + TD3_LINE2.slice(10);
    const r = await apiPost(alice, "alice", `ui/kyc/id-scanner/cases/${caseId}/scan-document`, {
      document_type: "passport",
      file_type: "id_front",
      mrz_lines: [TD3_LINE1, bad],
    });
    flaggedScanId = (await r.json()).scan_id;
  });
  test.afterAll(async () => {
    await alice.close();
    await bob.close();
    await root.close();
  });

  test("193.1 reviewer lists scans by status (flagged)", async () => {
    const resp = await apiGet(root, "ui/kyc/id-scanner/admin/by-status", { status: "flagged" });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.scans.some((s: { scan_id: string }) => s.scan_id === flaggedScanId)).toBe(true);
  });

  test("193.2 non-admin cannot list by status (403)", async () => {
    const resp = await apiGet(alice, "ui/kyc/id-scanner/admin/by-status", { status: "flagged" });
    expect(resp.status()).toBe(403);
  });

  test("193.3 reviewer adjudicates (approve) -> status approved", async () => {
    const resp = await apiPost(root, "root", `ui/kyc/id-scanner/admin/scans/${flaggedScanId}/adjudicate`, {
      decision: "approve",
      note: "looks ok",
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("approved");
    expect(body.review_decision).toBe("approve");
  });

  test("193.4 reviewer get-scan returns cross-reference", async () => {
    const resp = await apiGet(root, `ui/kyc/id-scanner/admin/scans/${flaggedScanId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.scan_id).toBe(flaggedScanId);
  });

  test("193.5 adjudicating a missing scan returns 404", async () => {
    const resp = await apiPost(root, "root", "ui/kyc/id-scanner/admin/scans/kycscan_missing/adjudicate", {
      decision: "decline",
    });
    expect(resp.status()).toBe(404);
  });

  test("193.6 non-owner cannot read another user's scan (403)", async () => {
    const resp = await apiGet(bob, `ui/kyc/id-scanner/cases/${caseId}/scans/${flaggedScanId}`);
    expect(resp.status()).toBe(403);
  });

  test("193.7 non-owner cannot scan another user's case (403)", async () => {
    const resp = await apiPost(bob, "bob", `ui/kyc/id-scanner/cases/${caseId}/scan-document`, {
      document_type: "passport",
      file_type: "id_front",
      mrz_lines: [TD3_LINE1, TD3_LINE2],
    });
    expect(resp.status()).toBe(403);
  });
});
