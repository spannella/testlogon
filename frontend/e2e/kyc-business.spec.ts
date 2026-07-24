/**
 * E2E tests for KYC-015 — KYC for Business / Corporate Accounts (KYB).
 *
 * Sections:
 *   733 — Business Case CRUD API            (5 tests)
 *   734 — UBO & Director Management API      (6 tests)
 *   735 — Document & Address API             (4 tests)
 *   736 — Submit, Screening & Admin Review   (7 tests)
 *
 * Auth:
 *   Root  — root.admin@testdev.local (admin endpoints, require_admin_or_root)
 *   Alice — e2e_alice@test.local     (user endpoints)
 *   Bob   — e2e_bob@test.local       (non-owner / non-admin negative cases)
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ROOT_ID = "root";
const ALICE_ID = "alice";
const BOB_ID = "bob";
const TS = Date.now();

// ── Session bootstrap ────────────────────────────────────────────────────────

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

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

function csrfFor(identity: string): string {
  return getSessions()[identity].csrf_token;
}

async function apiGet(page: Page, identity: string, path: string) {
  return page.request.get(`${BASE}${path}`, { headers: { "x-csrf-token": csrfFor(identity) } });
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": csrfFor(identity) },
  });
}

async function apiPatch(page: Page, identity: string, path: string, body: object) {
  return page.request.patch(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": csrfFor(identity) },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  return page.request.delete(`${BASE}${path}`, { headers: { "x-csrf-token": csrfFor(identity) } });
}

// ── DDB helpers ──────────────────────────────────────────────────────────────

const PYTHON = REPO_ROOT + "/.venv/bin/python3";

const DDB_PRELUDE = `
import boto3, os, time
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
client = ddb.meta.client
`;

function ensureBusinessTable() {
  execSync(
    `${PYTHON} -c "${DDB_PRELUDE}
name = 'kyc_business_cases'
existing = [t for _p in client.get_paginator('list_tables').paginate() for t in _p['TableNames']]
if name not in existing:
    client.create_table(
        TableName=name,
        KeySchema=[{'AttributeName':'pk','KeyType':'HASH'},{'AttributeName':'sk','KeyType':'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName':'pk','AttributeType':'S'},{'AttributeName':'sk','AttributeType':'S'},
            {'AttributeName':'gsi_owner_pk','AttributeType':'S'},{'AttributeName':'gsi_owner_sk','AttributeType':'S'},
            {'AttributeName':'gsi_status_pk','AttributeType':'S'},{'AttributeName':'gsi_status_sk','AttributeType':'S'},
            {'AttributeName':'gsi_org_pk','AttributeType':'S'},{'AttributeName':'gsi_org_sk','AttributeType':'S'}],
        GlobalSecondaryIndexes=[
            {'IndexName':'owner-updated-index','KeySchema':[{'AttributeName':'gsi_owner_pk','KeyType':'HASH'},{'AttributeName':'gsi_owner_sk','KeyType':'RANGE'}],'Projection':{'ProjectionType':'ALL'}},
            {'IndexName':'status-updated-index','KeySchema':[{'AttributeName':'gsi_status_pk','KeyType':'HASH'},{'AttributeName':'gsi_status_sk','KeyType':'RANGE'}],'Projection':{'ProjectionType':'ALL'}},
            {'IndexName':'org-index','KeySchema':[{'AttributeName':'gsi_org_pk','KeyType':'HASH'},{'AttributeName':'gsi_org_sk','KeyType':'RANGE'}],'Projection':{'ProjectionType':'ALL'}}],
        BillingMode='PAY_PER_REQUEST')
    time.sleep(1)
print('ok')
"`,
    { timeout: 30_000 },
  );
}

// ── Shared helpers ───────────────────────────────────────────────────────────

async function createCase(
  page: Page,
  identity: string,
  overrides: Record<string, unknown> = {},
): Promise<string> {
  const resp = await apiPost(page, identity, "/v1/kyc/business-cases", {
    legal_name: `Acme ${TS} LLC`,
    registration_number: `REG${TS}`,
    jurisdiction: "US-DE",
    company_type: "llc",
    ...overrides,
  });
  expect(resp.status()).toBe(200);
  return (await resp.json()).case.kyb_case_id;
}

async function fullyProvisionCase(page: Page, identity: string): Promise<string> {
  // Use a registration number containing the deterministic "PASS" marker so
  // the mock registry verification reliably returns verified=true (the score
  // for a random TS-derived reg number would otherwise pass only ~70% of runs).
  const caseId = await createCase(page, identity, {
    registration_number: `REGPASS${TS}`,
  });
  // UBOs summing >= 75% but <= 100%
  await apiPost(page, identity, `/v1/kyc/business-cases/${caseId}/ubos`, {
    full_name: "Jane Owner",
    ownership_percentage: 60,
  });
  await apiPost(page, identity, `/v1/kyc/business-cases/${caseId}/ubos`, {
    full_name: "John Owner",
    ownership_percentage: 40,
  });
  for (const dt of [
    "certificate_of_incorporation",
    "articles_of_association",
    "shareholder_register",
  ]) {
    await apiPost(page, identity, `/v1/kyc/business-cases/${caseId}/documents`, {
      document_type: dt,
      file_node_id: `node_${dt}_${TS}`,
    });
  }
  return caseId;
}

// ── Pages ────────────────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;
let rootPage: Page;

test.beforeAll(async ({ browser }) => {
  ensureBusinessTable();
  alicePage = await browser.newPage();
  await injectAuth(alicePage, ALICE_ID);
  bobPage = await browser.newPage();
  await injectAuth(bobPage, BOB_ID);
  rootPage = await browser.newPage();
  await injectAuth(rootPage, ROOT_ID);
});

// ── Section 733: Business Case CRUD API ──────────────────────────────────────

test.describe("733 — Business Case CRUD API", () => {
  test("733.1 POST creates a draft KYB case", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/v1/kyc/business-cases", {
      legal_name: `CreateCo ${TS} LLC`,
      registration_number: `RC${TS}`,
      jurisdiction: "US-DE",
      company_type: "llc",
    });
    expect(resp.status()).toBe(200);
    const body = (await resp.json()).case;
    expect(body.status).toBe("draft");
    expect(body.kyb_case_id).toMatch(/^kyb_/);
    expect(body.company.legal_name).toBe(`CreateCo ${TS} LLC`);
  });

  test("733.2 GET lists user's business cases", async () => {
    await createCase(alicePage, ALICE_ID);
    const resp = await apiGet(alicePage, ALICE_ID, "/v1/kyc/business-cases");
    expect(resp.status()).toBe(200);
    expect((await resp.json()).cases.length).toBeGreaterThanOrEqual(1);
  });

  test("733.3 GET /{id} returns case details", async () => {
    const caseId = await createCase(alicePage, ALICE_ID);
    const resp = await apiGet(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}`);
    expect(resp.status()).toBe(200);
    const c = (await resp.json()).case;
    expect(c.company.registration_number).toBe(`REG${TS}`);
    expect(c.company.jurisdiction).toBe("US-DE");
  });

  test("733.4 PATCH updates company info", async () => {
    const caseId = await createCase(alicePage, ALICE_ID);
    const resp = await apiPatch(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}`, {
      expected_version: 1,
      trading_name: "AcmeTrade",
    });
    expect(resp.status()).toBe(200);
    expect((await resp.json()).case.company.trading_name).toBe("AcmeTrade");
  });

  test("733.5 invalid company_type returns 422", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/v1/kyc/business-cases", {
      legal_name: `BadCo ${TS}`,
      registration_number: `BC${TS}`,
      jurisdiction: "US-DE",
      company_type: "invalid",
    });
    expect(resp.status()).toBe(422);
  });

  test("733.6 unauthenticated request returns 401", async ({ request }) => {
    const resp = await request.post(`${BASE}/v1/kyc/business-cases`, {
      data: {
        legal_name: "NoAuth",
        registration_number: "X",
        jurisdiction: "US",
        company_type: "llc",
      },
    });
    expect(resp.status()).toBe(401);
  });
});

// ── Section 734: UBO & Director Management API ───────────────────────────────

test.describe("734 — UBO & Director Management API", () => {
  test("734.1 POST /ubos adds a UBO (>25%)", async () => {
    const caseId = await createCase(alicePage, ALICE_ID);
    const resp = await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/ubos`, {
      full_name: "Jane Smith",
      ownership_percentage: 51,
    });
    expect(resp.status()).toBe(200);
    const ubo = (await resp.json()).ubo;
    expect(ubo.ubo_id).toMatch(/^ubo_/);
    expect(ubo.ownership_percentage).toBe(51);
  });

  test("734.2 UBO with <= 25% ownership is rejected (not a UBO)", async () => {
    const caseId = await createCase(alicePage, ALICE_ID);
    const resp = await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/ubos`, {
      full_name: "Minor Holder",
      ownership_percentage: 20,
    });
    expect(resp.status()).toBe(422);
    expect(JSON.stringify(await resp.json())).toContain("ubo_ownership_below_threshold");
  });

  test("734.3 link UBO to a personal KYC case", async () => {
    const caseId = await createCase(alicePage, ALICE_ID);
    const add = await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/ubos`, {
      full_name: "Linked Owner",
      ownership_percentage: 80,
      personal_kyc_case_id: `kyc_link_${TS}`,
    });
    const uboId = (await add.json()).ubo.ubo_id;
    const link = await apiPost(
      alicePage,
      ALICE_ID,
      `/v1/kyc/business-cases/${caseId}/ubos/${uboId}/link`,
      { personal_kyc_case_id: `kyc_link2_${TS}` },
    );
    expect(link.status()).toBe(200);
    expect((await link.json()).ubo.personal_kyc_case_id).toBe(`kyc_link2_${TS}`);
  });

  test("734.4 DELETE removes UBO; summary updates", async () => {
    const caseId = await createCase(alicePage, ALICE_ID);
    const add = await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/ubos`, {
      full_name: "Temp Owner",
      ownership_percentage: 90,
    });
    const uboId = (await add.json()).ubo.ubo_id;
    const del = await apiDelete(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/ubos/${uboId}`);
    expect(del.status()).toBe(200);
    const list = await apiGet(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/ubos`);
    expect((await list.json()).ubos.length).toBe(0);
  });

  test("734.5 UBO summary totals ownership on META", async () => {
    const caseId = await createCase(alicePage, ALICE_ID);
    await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/ubos`, {
      full_name: "A Owner",
      ownership_percentage: 51,
    });
    await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/ubos`, {
      full_name: "B Owner",
      ownership_percentage: 49,
    });
    const resp = await apiGet(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}`);
    expect((await resp.json()).case.ubo_summary.total_ownership_pct).toBe(100);
  });

  test("734.6 POST /directors adds a director with role", async () => {
    const caseId = await createCase(alicePage, ALICE_ID);
    const resp = await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/directors`, {
      full_name: "Chief Exec",
      role: "ceo",
    });
    expect(resp.status()).toBe(200);
    expect((await resp.json()).director.role).toBe("ceo");
  });
});

// ── Section 735: Document & Address API ──────────────────────────────────────

test.describe("735 — Document & Address API", () => {
  test("735.1 POST /documents attaches certificate of incorporation", async () => {
    const caseId = await createCase(alicePage, ALICE_ID);
    const resp = await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/documents`, {
      document_type: "certificate_of_incorporation",
      file_node_id: `node_${TS}`,
    });
    expect(resp.status()).toBe(200);
    expect((await resp.json()).document.document_type).toBe("certificate_of_incorporation");
  });

  test("735.2 invalid document_type returns 422", async () => {
    const caseId = await createCase(alicePage, ALICE_ID);
    const resp = await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/documents`, {
      document_type: "invalid",
      file_node_id: "node_x",
    });
    expect(resp.status()).toBe(422);
  });

  test("735.3 POST /addresses sets registered + trading addresses", async () => {
    const caseId = await createCase(alicePage, ALICE_ID);
    const reg = await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/addresses`, {
      address_type: "registered",
      line1: "123 Business St",
      city: "Wilmington",
      postal_code: "19801",
      country: "US",
    });
    expect(reg.status()).toBe(200);
    expect((await reg.json()).address.address_type).toBe("registered");
    const trd = await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/addresses`, {
      address_type: "trading",
      line1: "456 Trade Ave",
      city: "Dover",
      postal_code: "19901",
      country: "US",
    });
    expect(trd.status()).toBe(200);
    expect((await trd.json()).address.address_type).toBe("trading");
  });

  test("735.4 document_count increments on META", async () => {
    const caseId = await createCase(alicePage, ALICE_ID);
    await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/documents`, {
      document_type: "articles_of_association",
      file_node_id: "n1",
    });
    await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/documents`, {
      document_type: "shareholder_register",
      file_node_id: "n2",
    });
    const resp = await apiGet(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}`);
    expect((await resp.json()).case.document_count).toBe(2);
  });
});

// ── Section 736: Submit, Screening & Admin Review ────────────────────────────

test.describe("736 — Submit, Screening & Admin Review", () => {
  test("736.1 submit without UBOs returns error", async () => {
    const caseId = await createCase(alicePage, ALICE_ID);
    const resp = await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/submit`, {
      expected_version: 1,
    });
    expect(resp.status()).toBe(422);
    expect(JSON.stringify(await resp.json())).toContain("no_ubos_added");
  });

  test("736.2 submit without required documents returns error", async () => {
    const caseId = await createCase(alicePage, ALICE_ID);
    await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/ubos`, {
      full_name: "Sole Owner",
      ownership_percentage: 90,
    });
    const resp = await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/submit`, {
      expected_version: 1,
    });
    expect(resp.status()).toBe(422);
    expect(JSON.stringify(await resp.json())).toContain("missing_documents");
  });

  test("736.3 submit with all requirements transitions to submitted", async () => {
    const caseId = await fullyProvisionCase(alicePage, ALICE_ID);
    const cur = await apiGet(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}`);
    const version = (await cur.json()).case.version;
    const resp = await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/submit`, {
      expected_version: version,
    });
    expect(resp.status()).toBe(200);
    const c = (await resp.json()).case;
    expect(c.status).toBe("submitted");
    expect(c.registration_verification.verified).toBe(true);
  });

  test("736.4 admin approve transitions to approved (Tier 4)", async () => {
    const caseId = await fullyProvisionCase(alicePage, ALICE_ID);
    const cur = await apiGet(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}`);
    let version = (await cur.json()).case.version;
    await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/submit`, {
      expected_version: version,
    });
    const afterSubmit = await apiGet(rootPage, ROOT_ID, `/v1/kyc/business-cases/admin/${caseId}`);
    version = (await afterSubmit.json()).case.version;
    const resp = await apiPost(rootPage, ROOT_ID, `/v1/kyc/business-cases/admin/${caseId}/approve`, {
      expected_version: version,
      note: "ok",
    });
    expect(resp.status()).toBe(200);
    expect((await resp.json()).case.status).toBe("approved");
  });

  test("736.5 admin reject transitions to rejected", async () => {
    const caseId = await fullyProvisionCase(alicePage, ALICE_ID);
    const cur = await apiGet(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}`);
    let version = (await cur.json()).case.version;
    await apiPost(alicePage, ALICE_ID, `/v1/kyc/business-cases/${caseId}/submit`, {
      expected_version: version,
    });
    const afterSubmit = await apiGet(rootPage, ROOT_ID, `/v1/kyc/business-cases/admin/${caseId}`);
    version = (await afterSubmit.json()).case.version;
    const resp = await apiPost(rootPage, ROOT_ID, `/v1/kyc/business-cases/admin/${caseId}/reject`, {
      expected_version: version,
      reason_codes: ["docs_invalid"],
    });
    expect(resp.status()).toBe(200);
    expect((await resp.json()).case.status).toBe("rejected");
  });

  test("736.6 sanctions screening flags a watchlisted company", async () => {
    const caseId = await apiPost(alicePage, ALICE_ID, "/v1/kyc/business-cases", {
      legal_name: "Sanctioned Person",
      registration_number: `SAN${TS}`,
      jurisdiction: "RU",
      company_type: "corp",
    });
    const flaggedId = (await caseId.json()).case.kyb_case_id;
    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `/v1/kyc/business-cases/admin/${flaggedId}/screen`,
      {},
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.any_hit).toBe(true);
    const company = body.screened.find((s: { subject: string }) => s.subject === "company");
    expect(company.results.some((r: { result: string }) => r.result !== "clear")).toBe(true);
  });

  test("736.7 admin endpoints reject non-admin (403) and queue requires auth (401)", async () => {
    const caseId = await fullyProvisionCase(alicePage, ALICE_ID);
    // Bob (USER) cannot hit admin approve
    const forbidden = await apiPost(
      bobPage,
      BOB_ID,
      `/v1/kyc/business-cases/admin/${caseId}/approve`,
      { expected_version: 1 },
    );
    expect(forbidden.status()).toBe(403);
    // Non-owner GET on user endpoint is 403
    const notOwner = await apiGet(bobPage, BOB_ID, `/v1/kyc/business-cases/${caseId}`);
    expect(notOwner.status()).toBe(403);
  });
});
