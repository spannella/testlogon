/**
 * E2E tests for KYC-023: KYC Data Encryption & Privacy.
 *
 * Sections:
 *   234 — Field encryption & decryption API
 *   235 — Key management & GDPR erasure
 *   236 — Audit log & masking rules
 *   237 — Concurrent access & edge cases
 *
 * Auth: uses e2e_admin_session_setup.py (root, alice, bob, charlie_admin).
 *
 * Identities:
 *   root          – root.admin@testdev.local  – role=root
 *   alice         – e2e_alice@test.local      – role=user (case owner)
 *   bob           – e2e_bob@test.local        – role=user
 *   charlie_admin – e2e_charlie@test.local    – role=admin (assigned reviewer)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
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
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body?: object) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
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

/** Read the raw encrypted_pii map for a case directly from DDB. */
function readEncryptedPii(caseId: string): Record<string, unknown> {
  const out = execSync(
    `python3 -c "${DDB_PRELUDE}
tbl = ddb.Table('kyc_cases')
resp = tbl.get_item(Key={'pk': 'KYC#${caseId}', 'sk': 'META'})
item = resp.get('Item') or {}
print(json.dumps(item.get('encrypted_pii') or {}, default=str))
"`,
    { timeout: 10_000 },
  ).toString().trim();
  return JSON.parse(out);
}

// ─── Response types ─────────────────────────────────────────────────────────

interface KycCaseOut {
  kyc_case_id: string;
  user_sub: string;
  status: string;
  version: number;
}

const SAMPLE_PII = {
  document_number: "AB1234567",
  date_of_birth: "1990-01-15",
  tax_id: "123-45-6789",
  bank_routing_number: "021000021",
};

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

// ─── Tests ──────────────────────────────────────────────────────────────────

test.describe("KYC-023 Encryption", () => {
  let alicePage: Page;
  let rootPage: Page;
  let charliePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    rootPage = await newIdentityPage(browser, "root");
    charliePage = await newIdentityPage(browser, "charlie_admin");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await rootPage?.close();
    await charliePage?.close();
  });

  // ── Section 234: Field Encryption & Decryption API ───────────────────────

  test("234.1 Encrypted PII fields stored on case creation", async () => {
    const c = await createCaseWithPii(alicePage);
    const enc = readEncryptedPii(c.kyc_case_id);
    expect(Object.keys(enc).sort()).toEqual(Object.keys(SAMPLE_PII).sort());
    const docField = enc["document_number"] as Record<string, string>;
    expect(docField.ciphertext_b64).toBeTruthy();
    expect(docField.ciphertext_b64).not.toContain("AB1234567");
    expect(docField.algorithm).toBe("AES-256-GCM");
  });

  test("234.2 Assigned admin can decrypt PII fields", async () => {
    const c = await createCaseWithPii(alicePage);
    assignAdminDirect(c.kyc_case_id, CHARLIE_SUB);
    const resp = await apiPost(charliePage, "charlie_admin", `/v1/kyc/cases/${c.kyc_case_id}/pii/decrypt`, {
      fields: ["document_number", "date_of_birth"],
      reason: "Reviewing case for Tier 2 approval",
    });
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.pii.document_number).toBe("AB1234567");
    expect(body.pii.date_of_birth).toBe("1990-01-15");
  });

  test("234.3 Non-assigned admin gets masked values", async () => {
    const c = await createCaseWithPii(alicePage);
    assignAdminDirect(c.kyc_case_id, CHARLIE_SUB);
    // root is not the assigned admin but may read masked.
    const resp = await apiGet(rootPage, `/v1/kyc/cases/${c.kyc_case_id}/pii/masked`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.pii.document_number).toBe("****4567");
    expect(body.pii.tax_id).toBe("***-**-6789");
  });

  test("234.4 Decrypt request logged in audit", async () => {
    const c = await createCaseWithPii(alicePage);
    assignAdminDirect(c.kyc_case_id, CHARLIE_SUB);
    await apiPost(charliePage, "charlie_admin", `/v1/kyc/cases/${c.kyc_case_id}/pii/decrypt`, {
      fields: ["document_number"],
      reason: "audit check",
    });
    const log = await apiGet(rootPage, `/v1/kyc/cases/${c.kyc_case_id}/pii/audit-log`);
    expect(log.ok()).toBeTruthy();
    const body = await log.json();
    const decryptEvents = body.events.filter((e: { action: string }) => e.action === "decrypt");
    expect(decryptEvents.length).toBeGreaterThanOrEqual(1);
    expect(decryptEvents[0].accessor_sub).toBe(CHARLIE_SUB);
  });

  test("234.5 Regular user sees masked PII on their own case", async () => {
    const c = await createCaseWithPii(alicePage);
    const resp = await apiGet(alicePage, `/v1/kyc/cases/${c.kyc_case_id}/pii/masked`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.pii.document_number).toBe("****4567");
  });

  test("234.6 Decrypt without reason returns 422", async () => {
    const c = await createCaseWithPii(alicePage);
    assignAdminDirect(c.kyc_case_id, CHARLIE_SUB);
    const resp = await apiPost(charliePage, "charlie_admin", `/v1/kyc/cases/${c.kyc_case_id}/pii/decrypt`, {
      fields: ["document_number"],
      reason: "",
    });
    expect(resp.status()).toBe(422);
  });

  // ── Section 235: Key Management & GDPR Erasure ───────────────────────────

  test("235.1 Root rotates user DEK", async () => {
    const c = await createCaseWithPii(alicePage);
    const resp = await apiPost(rootPage, "root", `/v1/kyc/cases/admin/encryption/rotate-key/${ALICE_ID}`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.new_version).toBeGreaterThan(1);
    expect(c.kyc_case_id).toBeTruthy();
  });

  test("235.2 Decryption works after key rotation", async () => {
    const c = await createCaseWithPii(alicePage);
    assignAdminDirect(c.kyc_case_id, CHARLIE_SUB);
    await apiPost(rootPage, "root", `/v1/kyc/cases/admin/encryption/rotate-key/${ALICE_ID}`);
    const resp = await apiPost(charliePage, "charlie_admin", `/v1/kyc/cases/${c.kyc_case_id}/pii/decrypt`, {
      fields: ["document_number"],
      reason: "post rotation",
    });
    expect(resp.ok()).toBeTruthy();
    expect((await resp.json()).pii.document_number).toBe("AB1234567");
  });

  test("235.5 Non-root cannot rotate or destroy keys", async () => {
    const rot = await apiPost(charliePage, "charlie_admin", `/v1/kyc/cases/admin/encryption/rotate-key/${ALICE_ID}`);
    expect(rot.status()).toBe(403);
    const des = await apiPost(charliePage, "charlie_admin", `/v1/kyc/cases/admin/encryption/destroy-keys/${ALICE_ID}`);
    expect(des.status()).toBe(403);
  });

  test("235.3 + 235.6 Destroy keys renders PII unrecoverable and is idempotent", async ({ browser }) => {
    // Use bob as an isolated subject so destruction doesn't break other tests.
    const bobPage = await newIdentityPage(browser, "bob");
    try {
      const created = await apiPost(bobPage, "bob", "/v1/kyc/cases", { intake_profile: "kyc023b" });
      const c = (await created.json()).case as KycCaseOut;
      await apiPost(bobPage, "bob", `/v1/kyc/cases/${c.kyc_case_id}/pii`, {
        expected_version: c.version,
        pii: { document_number: "ZZ9999999" },
      });
      assignAdminDirect(c.kyc_case_id, CHARLIE_SUB);

      const first = await apiPost(rootPage, "root", `/v1/kyc/cases/admin/encryption/destroy-keys/e2e_bob@test.local`);
      expect(first.ok()).toBeTruthy();
      expect((await first.json()).keys_destroyed).toBeGreaterThanOrEqual(1);

      // Decrypt now fails (410 keys destroyed).
      const dec = await apiPost(charliePage, "charlie_admin", `/v1/kyc/cases/${c.kyc_case_id}/pii/decrypt`, {
        fields: ["document_number"],
        reason: "should fail",
      });
      expect(dec.status()).toBe(410);

      // Second destroy is idempotent (0 keys).
      const second = await apiPost(rootPage, "root", `/v1/kyc/cases/admin/encryption/destroy-keys/e2e_bob@test.local`);
      expect(second.ok()).toBeTruthy();
      expect((await second.json()).keys_destroyed).toBe(0);
    } finally {
      await bobPage.close();
    }
  });

  // ── Section 236: Audit Log & Masking Rules ───────────────────────────────

  test("236.2 Audit log filterable by accessor", async () => {
    const c = await createCaseWithPii(alicePage);
    assignAdminDirect(c.kyc_case_id, CHARLIE_SUB);
    await apiPost(charliePage, "charlie_admin", `/v1/kyc/cases/${c.kyc_case_id}/pii/decrypt`, {
      fields: ["document_number"],
      reason: "accessor filter test",
    });
    const resp = await apiGet(rootPage, `/v1/kyc/cases/admin/pii/audit-log?accessor=${encodeURIComponent(CHARLIE_SUB)}&limit=50`);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.events.length).toBeGreaterThanOrEqual(1);
    expect(body.events.every((e: { accessor_sub: string }) => e.accessor_sub === CHARLIE_SUB)).toBe(true);
  });

  test("236.3 Masking rules applied correctly per field type", async () => {
    const c = await createCaseWithPii(alicePage);
    const resp = await apiGet(alicePage, `/v1/kyc/cases/${c.kyc_case_id}/pii/masked`);
    const { pii } = await resp.json();
    expect(pii.document_number).toBe("****4567");
    expect(pii.date_of_birth).toBe("1990-**-**");
    expect(pii.tax_id).toBe("***-**-6789");
    expect(pii.bank_routing_number).toBe("*********");
  });

  test("236.5 Audit log includes IP address of accessor", async () => {
    const c = await createCaseWithPii(alicePage);
    assignAdminDirect(c.kyc_case_id, CHARLIE_SUB);
    await apiPost(charliePage, "charlie_admin", `/v1/kyc/cases/${c.kyc_case_id}/pii/decrypt`, {
      fields: ["document_number"],
      reason: "ip check",
    });
    const log = await apiGet(rootPage, `/v1/kyc/cases/${c.kyc_case_id}/pii/audit-log`);
    const body = await log.json();
    const evt = body.events.find((e: { action: string }) => e.action === "decrypt");
    expect(evt).toBeTruthy();
    expect(typeof evt.ip_address).toBe("string");
    expect(evt.ip_address.length).toBeGreaterThan(0);
  });

  test("236.4 Audit log read by non-root is forbidden", async () => {
    const c = await createCaseWithPii(alicePage);
    const resp = await apiGet(charliePage, `/v1/kyc/cases/${c.kyc_case_id}/pii/audit-log`);
    expect(resp.status()).toBe(403);
  });

  // ── Section 237: Concurrent Access & Edge Cases ──────────────────────────

  test("237.2 Case with no PII returns empty masked map", async () => {
    const created = await apiPost(alicePage, "alice", "/v1/kyc/cases", { intake_profile: "nopii" });
    const c = (await created.json()).case as KycCaseOut;
    const resp = await apiGet(alicePage, `/v1/kyc/cases/${c.kyc_case_id}/pii/masked`);
    expect(resp.ok()).toBeTruthy();
    expect(Object.keys((await resp.json()).pii)).toHaveLength(0);
  });

  test("237.3 Re-write of a field updates the masked hint", async () => {
    const c = await createCaseWithPii(alicePage);
    const cur = (await (await apiGet(alicePage, `/v1/kyc/cases/${c.kyc_case_id}`)).json()).case as KycCaseOut;
    const upd = await apiPost(alicePage, "alice", `/v1/kyc/cases/${c.kyc_case_id}/pii`, {
      expected_version: cur.version,
      pii: { document_number: "CD7654321" },
    });
    expect(upd.ok()).toBeTruthy();
    const resp = await apiGet(alicePage, `/v1/kyc/cases/${c.kyc_case_id}/pii/masked`);
    expect((await resp.json()).pii.document_number).toBe("****4321");
  });

  test("237.4 Decrypt on non-existent case returns 404", async () => {
    const resp = await apiPost(charliePage, "charlie_admin", `/v1/kyc/cases/kyc_doesnotexist/pii/decrypt`, {
      fields: ["document_number"],
      reason: "missing case",
    });
    expect(resp.status()).toBe(404);
  });

  test("237.1 Decrypt unknown field returns 400", async () => {
    const c = await createCaseWithPii(alicePage);
    assignAdminDirect(c.kyc_case_id, CHARLIE_SUB);
    const resp = await apiPost(charliePage, "charlie_admin", `/v1/kyc/cases/${c.kyc_case_id}/pii/decrypt`, {
      fields: ["not_a_field"],
      reason: "edge",
    });
    expect(resp.status()).toBe(400);
  });
});
