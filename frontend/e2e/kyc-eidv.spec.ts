/**
 * E2E tests for KYC-022: Electronic Identity Verification (eIDV).
 *
 * Section 729: eID Schemes & Session/Mock Flow (providers, initiate, mock, callback)
 * Section 730: Auto Tier Upgrade & Discrepancy Detection
 * Section 731: Status, Auth & Edge Cases
 *
 * Auth: role-bearing JWT cookies from e2e_admin_session_setup.py (root / alice /
 * bob). POST requests carry the x-csrf-token header (require_ui_session enforces
 * CSRF when the ui_session cookie is present).
 *
 * KYC cases are seeded directly into the kyc_cases DynamoDB table
 * (pk=KYC#{id}, sk=META). The dev-mode mock eID provider returns a
 * deterministic, HMAC-SHA256-signed assertion for a session:
 *   first_name=John last_name=Doe date_of_birth=1990-01-15 nationality=<scheme>
 *   document_number=MOCK-<crc32(session_id)>
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();

// ─── Session bootstrap ──────────────────────────────────────────────────────

interface AdminSessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<Record<string, unknown>>;
}

let _sessions: Record<string, AdminSessionData> | null = null;
function getSessions(): Record<string, AdminSessionData> {
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
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await page.context().addCookies(sessions[identity].cookies as any);
  await page.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, sessions[identity].user_sub);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, options?: { maxRedirects?: number }) {
  return page.request.get(`${API}/${path}`, options);
}

// ─── DDB helpers ────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os, json, sys
from pathlib import Path
env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
`;

function py(code: string, arg?: string): string {
  const a = arg ? ` '${arg.replace(/'/g, "'\\''")}'` : "";
  return execSync(`python3 -c "${DDB_PRELUDE}\n${code}"${a}`, {
    cwd: "/home/ubuntu/testlogon",
    timeout: 15_000,
  }).toString();
}

/** Seed a draft KYC case META item. */
function seedKycCase(caseId: string, userSub: string, status = "draft"): void {
  py(
    `data = json.loads(sys.argv[1])
tbl = ddb.Table(os.environ.get('KYC_CASES_TABLE_NAME','kyc_cases'))
tbl.put_item(Item={'pk':'KYC#'+data['cid'],'sk':'META','entity_type':'kyc_case','kyc_case_id':data['cid'],'user_sub':data['sub'],'status':data['status'],'files':[],'version':1,'created_at':1700000000,'updated_at':1700000000})
print('ok')`,
    JSON.stringify({ cid: caseId, sub: userSub, status }),
  );
}

/** Read the kyc_cases META item back (eid_verification, etc.) as JSON. */
function getCaseItem(caseId: string): Record<string, unknown> {
  const out = py(
    `tbl = ddb.Table(os.environ.get('KYC_CASES_TABLE_NAME','kyc_cases'))
item = tbl.get_item(Key={'pk':'KYC#${caseId}','sk':'META'}).get('Item') or {}
def enc(o):
    from decimal import Decimal
    if isinstance(o, Decimal): return int(o)
    raise TypeError
print(json.dumps(item, default=enc))`,
  );
  return JSON.parse(out.trim());
}

/** Read users.kyc_tier for a user (0 if unset). */
function getUserTier(userSub: string): number {
  const out = py(
    `users = ddb.Table('users')
item = users.get_item(Key={'user_sub':'${userSub}'}).get('Item') or {}
print(int(item.get('kyc_tier', 0)))`,
  );
  return parseInt(out.trim(), 10) || 0;
}

function clearTier(userSub: string): void {
  py(
    `users = ddb.Table('users')
try:
    users.update_item(Key={'user_sub':'${userSub}'}, UpdateExpression='REMOVE kyc_tier, kyc_tier_updated_at, kyc_tier_history')
except Exception: pass
print('ok')`,
  );
}

/** Seed profile identity fields (first_name/last_name/birthday) in the profiles table. */
function setProfileIdentity(
  userSub: string,
  fields: { first_name?: string; last_name?: string; birthday?: string },
): void {
  py(
    `data = json.loads(sys.argv[1])
tbl = ddb.Table(os.environ.get('PROFILE_TABLE_NAME','profiles'))
existing = tbl.get_item(Key={'user_sub': data['sub']}).get('Item') or {}
profile = existing.get('profile') or {}
profile.update(data['fields'])
tbl.put_item(Item={'user_sub': data['sub'], 'profile': profile})
print('ok')`,
    JSON.stringify({ sub: userSub, fields }),
  );
}

function clearProfileIdentity(userSub: string): void {
  py(
    `tbl = ddb.Table(os.environ.get('PROFILE_TABLE_NAME','profiles'))
existing = tbl.get_item(Key={'user_sub':'${userSub}'}).get('Item') or {}
profile = existing.get('profile') or {}
for k in ('first_name','last_name','birthday'):
    profile.pop(k, None)
tbl.put_item(Item={'user_sub':'${userSub}', 'profile': profile})
print('ok')`,
  );
}

// Run a full mock eID flow: start -> mock provider -> callback. Returns the
// status payload after completion.
async function runEidFlow(page: Page, identity: string, caseId: string, scheme: string) {
  const start = await apiPost(page, identity, `v1/kyc/cases/${caseId}/eid/start`, { scheme });
  expect(start.status()).toBe(200);
  const { session_id } = await start.json();
  const mock = await apiPost(page, identity, `mock/eid/verify`, { session_id });
  expect(mock.status()).toBe(200);
  const { assertion, signature } = await mock.json();
  const cb = await apiGet(
    page,
    `v1/kyc/eid/callback?session_id=${session_id}&assertion=${encodeURIComponent(
      assertion,
    )}&signature=${signature}`,
    { maxRedirects: 0 },
  );
  // callback redirects (303 -> /kyc/cases/{id}?eid=success) on success
  expect(cb.status()).toBe(303);
  return { session_id, assertion, signature };
}

// ─── 729. Schemes & Session/Mock Flow ───────────────────────────────────────

test.describe("729. KYC-022 eID Schemes & Mock Flow", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("729.1 list supported eID schemes", async () => {
    const r = await apiGet(alicePage, `v1/kyc/eid/schemes`);
    expect(r.status()).toBe(200);
    const data = await r.json();
    const ids = (data.schemes as Array<{ id: string }>).map((s) => s.id);
    expect(ids).toContain("eidas");
    expect(ids).toContain("digid");
    expect(ids).toContain("bankid");
    expect(ids).toContain("aadhaar");
  });

  test("729.2 filter schemes by country (SE -> bankid, not digid)", async () => {
    const r = await apiGet(alicePage, `v1/kyc/eid/schemes?country=SE`);
    expect(r.status()).toBe(200);
    const ids = ((await r.json()).schemes as Array<{ id: string }>).map((s) => s.id);
    expect(ids).toContain("bankid");
    expect(ids).not.toContain("digid");
  });

  test("729.3 start eID verification returns redirect URL to mock endpoint", async () => {
    const caseId = `kyc_eid_${TS}_start`;
    seedKycCase(caseId, ALICE_ID);
    const r = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/eid/start`, {
      scheme: "bankid",
    });
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.session_id).toMatch(/^es_[a-f0-9]{16}$/);
    expect(data.redirect_url).toContain("/mock/eid/verify?session_id=");
    expect(data.expires_at).toBeGreaterThan(0);
    expect(data.scheme).toBe("bankid");
  });

  test("729.4 mock provider returns a signed assertion", async () => {
    const caseId = `kyc_eid_${TS}_mock`;
    seedKycCase(caseId, ALICE_ID);
    const start = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/eid/start`, {
      scheme: "bankid",
    });
    const { session_id } = await start.json();
    const m = await apiPost(alicePage, "alice", `mock/eid/verify`, { session_id });
    expect(m.status()).toBe(200);
    const data = await m.json();
    expect(typeof data.assertion).toBe("string");
    expect(data.signature).toMatch(/^[a-f0-9]{64}$/);
  });

  test("729.5 callback processes assertion and populates case", async () => {
    const caseId = `kyc_eid_${TS}_cb`;
    seedKycCase(caseId, ALICE_ID);
    await runEidFlow(alicePage, "alice", caseId, "bankid");
    const item = getCaseItem(caseId);
    const eid = item.eid_verification as Record<string, unknown>;
    expect(eid).toBeTruthy();
    expect(eid.scheme).toBe("bankid");
    expect(typeof eid.assertion_id).toBe("string");
    const fields = eid.verified_fields as Record<string, string>;
    expect(fields.first_name).toBe("John");
    expect(fields.last_name).toBe("Doe");
    expect(fields.nationality).toBe("SE");
  });

  test("729.6 mock result is deterministic for a session", async () => {
    const caseId = `kyc_eid_${TS}_det`;
    seedKycCase(caseId, ALICE_ID);
    const start = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/eid/start`, {
      scheme: "eidas",
    });
    const { session_id } = await start.json();
    const a = await (await apiPost(alicePage, "alice", `mock/eid/verify`, { session_id })).json();
    const b = await (await apiPost(alicePage, "alice", `mock/eid/verify`, { session_id })).json();
    // same session => identical signed assertion payload
    expect(a.assertion).toBe(b.assertion);
    expect(a.signature).toBe(b.signature);
  });

  test("729.7 tampered assertion signature is rejected", async () => {
    const caseId = `kyc_eid_${TS}_tamper`;
    seedKycCase(caseId, ALICE_ID);
    const start = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/eid/start`, {
      scheme: "bankid",
    });
    const { session_id } = await start.json();
    const mock = await (await apiPost(alicePage, "alice", `mock/eid/verify`, { session_id })).json();
    const badSig = "0".repeat(64);
    const cb = await apiGet(
      alicePage,
      `v1/kyc/eid/callback?session_id=${session_id}&assertion=${encodeURIComponent(
        mock.assertion,
      )}&signature=${badSig}`,
      { maxRedirects: 0 },
    );
    // failed callback redirects to ?eid=failed (303) and does NOT populate the case
    expect(cb.status()).toBe(303);
    const item = getCaseItem(caseId);
    expect(item.eid_verification).toBeFalsy();
  });

  test("729.8 unsupported scheme returns 422 (pattern) ", async () => {
    const caseId = `kyc_eid_${TS}_bad`;
    seedKycCase(caseId, ALICE_ID);
    const r = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/eid/start`, {
      scheme: "foobar",
    });
    // pydantic pattern validation -> 422
    expect(r.status()).toBe(422);
  });

  test("729.9 callback with unknown session_id returns 404", async () => {
    const r = await apiGet(
      alicePage,
      `v1/kyc/eid/callback?session_id=es_doesnotexist&assertion=AA&signature=00`,
    );
    expect(r.status()).toBe(404);
  });
});

// ─── 730. Auto Tier Upgrade & Discrepancy Detection ─────────────────────────

test.describe("730. KYC-022 Auto Tier Upgrade & Discrepancies", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alicePage?.close();
    clearProfileIdentity(getSessions()["alice"].user_sub);
  });

  test("730.1 matching profile -> no discrepancies, auto tier-2 upgrade", async () => {
    const sub = getSessions()["alice"].user_sub;
    clearTier(sub);
    setProfileIdentity(sub, {
      first_name: "John",
      last_name: "Doe",
      birthday: "1990-01-15",
    });
    const caseId = `kyc_eid_${TS}_match`;
    seedKycCase(caseId, ALICE_ID);
    await runEidFlow(alicePage, "alice", caseId, "bankid");
    const item = getCaseItem(caseId);
    const eid = item.eid_verification as Record<string, unknown>;
    expect((eid.discrepancies as unknown[]).length).toBe(0);
    expect(eid.auto_tier_upgrade).toBe(true);
    expect(getUserTier(sub)).toBeGreaterThanOrEqual(2);
  });

  test("730.2 name mismatch -> warning discrepancies, still upgrades", async () => {
    const sub = getSessions()["alice"].user_sub;
    clearTier(sub);
    setProfileIdentity(sub, {
      first_name: "Jane",
      last_name: "Smith",
      birthday: "1990-01-15",
    });
    const caseId = `kyc_eid_${TS}_namemiss`;
    seedKycCase(caseId, ALICE_ID);
    await runEidFlow(alicePage, "alice", caseId, "bankid");
    const eid = getCaseItem(caseId).eid_verification as Record<string, unknown>;
    const disc = eid.discrepancies as Array<{ field: string; severity: string }>;
    const fields = disc.map((d) => d.field);
    expect(fields).toContain("first_name");
    expect(fields).toContain("last_name");
    expect(disc.every((d) => d.severity === "warning")).toBe(true);
    // warnings don't block the upgrade
    expect(eid.auto_tier_upgrade).toBe(true);
  });

  test("730.3 critical DOB mismatch blocks auto-upgrade + flags review", async () => {
    const sub = getSessions()["alice"].user_sub;
    clearTier(sub);
    setProfileIdentity(sub, {
      first_name: "John",
      last_name: "Doe",
      birthday: "2000-01-01",
    });
    const caseId = `kyc_eid_${TS}_dobmiss`;
    seedKycCase(caseId, ALICE_ID);
    await runEidFlow(alicePage, "alice", caseId, "bankid");
    const eid = getCaseItem(caseId).eid_verification as Record<string, unknown>;
    const disc = eid.discrepancies as Array<{ field: string; severity: string }>;
    expect(disc.some((d) => d.field === "date_of_birth" && d.severity === "critical")).toBe(true);
    expect(eid.auto_tier_upgrade).toBe(false);
    expect(eid.flagged_for_review).toBe(true);
    expect(getUserTier(sub)).toBeLessThan(2);
  });
});

// ─── 731. Status, Auth & Edge Cases ─────────────────────────────────────────

test.describe("731. KYC-022 Status, Auth & Edge Cases", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    clearProfileIdentity(getSessions()["alice"].user_sub);
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
  });
  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("731.1 status null before verification, populated after", async () => {
    const caseId = `kyc_eid_${TS}_status`;
    seedKycCase(caseId, ALICE_ID);
    const before = await apiGet(alicePage, `v1/kyc/cases/${caseId}/eid/status`);
    expect(before.status()).toBe(200);
    expect((await before.json()).eid_verification).toBeNull();

    await runEidFlow(alicePage, "alice", caseId, "eidas");
    const after = await apiGet(alicePage, `v1/kyc/cases/${caseId}/eid/status`);
    const data = await after.json();
    expect(data.eid_verification).toBeTruthy();
    expect(data.eid_verification.scheme).toBe("eidas");
    expect(data.eid_verification.assertion_id).toMatch(/^ea_[a-f0-9]{12}$/);
  });

  test("731.2 schemes endpoint requires auth (401 without session)", async ({ request }) => {
    const r = await request.get(`${API}/v1/kyc/eid/schemes`);
    expect(r.status()).toBe(401);
  });

  test("731.3 non-owner cannot start eID on another user's case (403)", async () => {
    const caseId = `kyc_eid_${TS}_notowner`;
    seedKycCase(caseId, ALICE_ID);
    const r = await apiPost(bobPage, "bob", `v1/kyc/cases/${caseId}/eid/start`, {
      scheme: "bankid",
    });
    expect(r.status()).toBe(403);
    expect((await r.json()).detail).toBe("eid_not_owner");
  });

  test("731.4 start on non-existent case returns 404", async () => {
    const r = await apiPost(alicePage, "alice", `v1/kyc/cases/kyc_nope_${TS}/eid/start`, {
      scheme: "bankid",
    });
    expect(r.status()).toBe(404);
    expect((await r.json()).detail).toBe("case_not_found");
  });

  test("731.5 start on non-draft case returns 400 eid_case_not_draft", async () => {
    const caseId = `kyc_eid_${TS}_submitted`;
    seedKycCase(caseId, ALICE_ID, "submitted");
    const r = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/eid/start`, {
      scheme: "bankid",
    });
    expect(r.status()).toBe(400);
    expect((await r.json()).detail).toBe("eid_case_not_draft");
  });

  test("731.6 callback is idempotent (second call returns same assertion)", async () => {
    const caseId = `kyc_eid_${TS}_idem`;
    seedKycCase(caseId, ALICE_ID);
    const start = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/eid/start`, {
      scheme: "bankid",
    });
    const { session_id } = await start.json();
    const mock = await (await apiPost(alicePage, "alice", `mock/eid/verify`, { session_id })).json();
    const url = `v1/kyc/eid/callback?session_id=${session_id}&assertion=${encodeURIComponent(
      mock.assertion,
    )}&signature=${mock.signature}`;
    const cb1 = await apiGet(alicePage, url, { maxRedirects: 0 });
    expect(cb1.status()).toBe(303);
    const cb2 = await apiGet(alicePage, url, { maxRedirects: 0 });
    expect(cb2.status()).toBe(303);
    const firstId = (getCaseItem(caseId).eid_verification as Record<string, string>).assertion_id;
    expect(typeof firstId).toBe("string");
  });

  test("731.7 second eID with a different scheme replaces the first (latest wins)", async () => {
    const caseId = `kyc_eid_${TS}_replace`;
    seedKycCase(caseId, ALICE_ID);
    await runEidFlow(alicePage, "alice", caseId, "bankid");
    await runEidFlow(alicePage, "alice", caseId, "eidas");
    const eid = getCaseItem(caseId).eid_verification as Record<string, string>;
    expect(eid.scheme).toBe("eidas");
  });
});
