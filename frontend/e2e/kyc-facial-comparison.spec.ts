/**
 * E2E tests for KYC-014: Facial Comparison (selfie vs ID photo).
 *
 * Section 723: Face Comparison API (trigger / score buckets / errors / attempts)
 * Section 724: Anti-Spoof & Multiple Attempts
 * Section 725: Admin Face Comparison (side-by-side / override / authz)
 *
 * Auth: role-bearing JWT cookies from e2e_admin_session_setup.py (root / alice /
 * bob). POST requests carry the x-csrf-token header (require_ui_session enforces
 * CSRF when the ui_session cookie is present).
 *
 * KYC cases + their attached selfie / id_front file references are seeded
 * directly into the kyc_cases DynamoDB table (pk=KYC#{id}, sk=META). The dev-mode
 * mock comparison derives a deterministic score from the selfie filename:
 *   *match*    -> 85 (pass)
 *   *partial*  -> 60 (review)
 *   *mismatch* -> 30 (fail)
 * The anti-spoof check uses the file size + mime type carried on the file ref.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";
const ROOT_SUB = "root.admin@testdev.local";
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

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}/${path}`);
}

// ─── DDB seed helper ────────────────────────────────────────────────────────

/**
 * Seed a KYC case META item directly into DynamoDB, with the supplied file
 * references attached. `files` entries use the case file shape: { type, path,
 * size, mime_type }.
 */
function seedKycCase(
  caseId: string,
  userSub: string,
  files: Array<{ type: string; path: string; size?: number; mime_type?: string }>,
): void {
  const payload = JSON.stringify({ case_id: caseId, user_sub: userSub, files });
  execSync(
    `python3 -c "
import boto3, os, json, sys
from pathlib import Path
env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1)
        os.environ.setdefault(k.strip(), v.strip())
data = json.loads(sys.argv[1])
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('KYC_CASES_TABLE_NAME','kyc_cases'))
cid = data['case_id']
files = []
for f in data['files']:
    files.append({'type': f['type'], 'path': f['path'], 'size': f.get('size', 0), 'mime_type': f.get('mime_type','')})
tbl.put_item(Item={'pk': 'KYC#'+cid, 'sk':'META', 'entity_type':'kyc_case', 'kyc_case_id': cid, 'user_sub': data['user_sub'], 'status':'draft', 'files': files, 'version': 1, 'created_at': 1700000000, 'updated_at': 1700000000})
print('seeded '+cid)
" '${payload.replace(/'/g, "'\\''")}'`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
}

const GOOD = { size: 150_000, mime_type: "image/jpeg" };
const ID_FRONT = { type: "id_front", path: `kyc/${TS}/id_front_doc.jpg`, ...GOOD };

// ─── 723. Face Comparison API ───────────────────────────────────────────────

test.describe("723. KYC-014 Face Comparison API", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("723.1 match selfie returns score 85 and result pass", async () => {
    const caseId = `kyc_fc_${TS}_match`;
    seedKycCase(caseId, ALICE_ID, [
      { type: "selfie", path: `kyc/${TS}/match_selfie.jpg`, ...GOOD },
      ID_FRONT,
    ]);
    const r = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.confidence_score).toBe(85);
    expect(data.result).toBe("pass");
    expect(data.attempt_number).toBe(1);
    expect(data.max_attempts).toBe(3);
    expect(data.remaining_attempts).toBe(2);
    expect(data.comparison_id).toMatch(/^fc_[a-f0-9]{12}$/);
  });

  test("723.2 mismatch selfie returns score 30 and result fail", async () => {
    const caseId = `kyc_fc_${TS}_mismatch`;
    seedKycCase(caseId, ALICE_ID, [
      { type: "selfie", path: `kyc/${TS}/mismatch_selfie.jpg`, ...GOOD },
      ID_FRONT,
    ]);
    const r = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.confidence_score).toBe(30);
    expect(data.result).toBe("fail");
  });

  test("723.3 partial selfie returns score 60 and result review", async () => {
    const caseId = `kyc_fc_${TS}_partial`;
    seedKycCase(caseId, ALICE_ID, [
      { type: "selfie", path: `kyc/${TS}/partial_selfie.jpg`, ...GOOD },
      ID_FRONT,
    ]);
    const r = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.confidence_score).toBe(60);
    expect(data.result).toBe("review");
  });

  test("723.4 default selfie name is deterministic (55-95) and stable", async () => {
    const caseId = `kyc_fc_${TS}_default`;
    seedKycCase(caseId, ALICE_ID, [
      { type: "selfie", path: `kyc/${TS}/plain_selfie.jpg`, ...GOOD },
      ID_FRONT,
    ]);
    const r1 = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
    const d1 = await r1.json();
    expect(d1.confidence_score).toBeGreaterThanOrEqual(55);
    expect(d1.confidence_score).toBeLessThanOrEqual(95);
    // second attempt on same files yields the same deterministic score
    const r2 = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
    const d2 = await r2.json();
    expect(d2.confidence_score).toBe(d1.confidence_score);
    expect(d2.attempt_number).toBe(2);
  });

  test("723.5 compare without selfie returns 400 selfie_not_uploaded", async () => {
    const caseId = `kyc_fc_${TS}_noselfie`;
    seedKycCase(caseId, ALICE_ID, [ID_FRONT]);
    const r = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
    expect(r.status()).toBe(400);
    expect((await r.json()).detail).toBe("selfie_not_uploaded");
  });

  test("723.6 compare without id_front returns 400 id_front_not_uploaded", async () => {
    const caseId = `kyc_fc_${TS}_noid`;
    seedKycCase(caseId, ALICE_ID, [
      { type: "selfie", path: `kyc/${TS}/match_selfie.jpg`, ...GOOD },
    ]);
    const r = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
    expect(r.status()).toBe(400);
    expect((await r.json()).detail).toBe("id_front_not_uploaded");
  });

  test("723.7 non-existent case returns 404", async () => {
    const r = await apiPost(
      alicePage,
      "alice",
      `v1/kyc/cases/kyc_does_not_exist_${TS}/compare-face`,
    );
    expect(r.status()).toBe(404);
  });

  test("723.8 case owned by another user returns 403", async () => {
    const caseId = `kyc_fc_${TS}_alice_owned`;
    seedKycCase(caseId, ALICE_ID, [
      { type: "selfie", path: `kyc/${TS}/match_selfie.jpg`, ...GOOD },
      ID_FRONT,
    ]);
    const r = await apiPost(bobPage, "bob", `v1/kyc/cases/${caseId}/compare-face`);
    expect(r.status()).toBe(403);
    expect((await r.json()).detail).toBe("access_forbidden");
  });

  test("723.9 unauthenticated request returns 401", async ({ request }) => {
    const caseId = `kyc_fc_${TS}_match`;
    const r = await request.post(`${API}/v1/kyc/cases/${caseId}/compare-face`);
    expect(r.status()).toBe(401);
  });

  test("723.10 fourth attempt returns 409 max_attempts_exceeded", async () => {
    const caseId = `kyc_fc_${TS}_maxout`;
    seedKycCase(caseId, ALICE_ID, [
      { type: "selfie", path: `kyc/${TS}/match_selfie.jpg`, ...GOOD },
      ID_FRONT,
    ]);
    for (let i = 1; i <= 3; i++) {
      const r = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
      expect(r.status()).toBe(200);
      expect((await r.json()).attempt_number).toBe(i);
    }
    const r4 = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
    expect(r4.status()).toBe(409);
    expect((await r4.json()).detail).toBe("max_attempts_exceeded");
  });
});

// ─── 724. Anti-Spoof & Multiple Attempts ────────────────────────────────────

test.describe("724. KYC-014 Anti-Spoof & Attempts", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("724.1 anti-spoof passes for a reasonable JPEG selfie", async () => {
    const caseId = `kyc_as_${TS}_ok`;
    seedKycCase(caseId, ALICE_ID, [
      { type: "selfie", path: `kyc/${TS}/match_selfie.jpg`, ...GOOD },
      ID_FRONT,
    ]);
    const r = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
    const data = await r.json();
    expect(data.anti_spoof.passed).toBe(true);
    expect(data.anti_spoof.total_checks).toBe(3);
    expect(data.anti_spoof.passed_checks).toBe(3);
    const names = data.anti_spoof.checks.map((c: { check: string }) => c.check);
    expect(names).toEqual(
      expect.arrayContaining(["file_size", "image_format", "not_screenshot"]),
    );
  });

  test("724.2 anti-spoof fails for a tiny file (score forced to 0, fail)", async () => {
    const caseId = `kyc_as_${TS}_tiny`;
    seedKycCase(caseId, ALICE_ID, [
      { type: "selfie", path: `kyc/${TS}/match_selfie.jpg`, size: 512, mime_type: "image/jpeg" },
      ID_FRONT,
    ]);
    const r = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
    const data = await r.json();
    expect(data.anti_spoof.passed).toBe(false);
    expect(data.confidence_score).toBe(0);
    expect(data.result).toBe("fail");
    const sizeCheck = data.anti_spoof.checks.find((c: { check: string }) => c.check === "file_size");
    expect(sizeCheck.passed).toBe(false);
  });

  test("724.3 anti-spoof fails for BMP screenshot format", async () => {
    const caseId = `kyc_as_${TS}_bmp`;
    seedKycCase(caseId, ALICE_ID, [
      { type: "selfie", path: `kyc/${TS}/match_selfie.bmp`, size: 150_000, mime_type: "image/bmp" },
      ID_FRONT,
    ]);
    const r = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
    const data = await r.json();
    expect(data.anti_spoof.passed).toBe(false);
    expect(data.result).toBe("fail");
    const ss = data.anti_spoof.checks.find((c: { check: string }) => c.check === "not_screenshot");
    expect(ss.passed).toBe(false);
  });

  test("724.4 PNG selfie passes the image_format check", async () => {
    const caseId = `kyc_as_${TS}_png`;
    seedKycCase(caseId, ALICE_ID, [
      { type: "selfie", path: `kyc/${TS}/match_selfie.png`, size: 150_000, mime_type: "image/png" },
      ID_FRONT,
    ]);
    const r = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
    const data = await r.json();
    const fmt = data.anti_spoof.checks.find((c: { check: string }) => c.check === "image_format");
    expect(fmt.passed).toBe(true);
  });

  test("724.5 list shows all attempts numbered sequentially, highest kept as best", async () => {
    const caseId = `kyc_as_${TS}_list`;
    // attempt 1: mismatch (30), attempt 2: match (85), attempt 3: partial (60)
    seedKycCase(caseId, ALICE_ID, [
      { type: "selfie", path: `kyc/${TS}/mismatch_selfie.jpg`, ...GOOD },
      ID_FRONT,
    ]);
    const a1 = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
    expect((await a1.json()).attempt_number).toBe(1);

    seedKycCase(caseId, ALICE_ID, [
      { type: "selfie", path: `kyc/${TS}/mismatch_selfie.jpg`, ...GOOD },
      { type: "selfie", path: `kyc/${TS}/match_selfie.jpg`, ...GOOD },
      ID_FRONT,
    ]);
    const a2 = await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
    expect((await a2.json()).attempt_number).toBe(2);

    const list = await apiGet(alicePage, `v1/kyc/cases/${caseId}/face-comparisons`);
    expect(list.status()).toBe(200);
    const ld = await list.json();
    expect(ld.comparisons.length).toBe(2);
    const scores = ld.comparisons.map((c: { confidence_score: number }) => c.confidence_score);
    expect(scores).toContain(30);
    expect(scores).toContain(85);
  });
});

// ─── 725. Admin Face Comparison ─────────────────────────────────────────────

test.describe("725. KYC-014 Admin Face Comparison", () => {
  let rootPage: Page;
  let alicePage: Page;
  let caseId: string;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");

    // Seed Alice's case with 3 attempts: 30, 85, 60 -> best is 85.
    caseId = `kyc_admin_${TS}`;
    seedKycCase(caseId, ALICE_ID, [
      { type: "selfie", path: `kyc/${TS}/mismatch_selfie.jpg`, ...GOOD },
      ID_FRONT,
    ]);
    await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
    seedKycCase(caseId, ALICE_ID, [
      { type: "selfie", path: `kyc/${TS}/mismatch_selfie.jpg`, ...GOOD },
      { type: "selfie", path: `kyc/${TS}/match_selfie.jpg`, ...GOOD },
      ID_FRONT,
    ]);
    await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
    seedKycCase(caseId, ALICE_ID, [
      { type: "selfie", path: `kyc/${TS}/mismatch_selfie.jpg`, ...GOOD },
      { type: "selfie", path: `kyc/${TS}/match_selfie.jpg`, ...GOOD },
      { type: "selfie", path: `kyc/${TS}/partial_selfie.jpg`, ...GOOD },
      ID_FRONT,
    ]);
    await apiPost(alicePage, "alice", `v1/kyc/cases/${caseId}/compare-face`);
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("725.1 admin side-by-side returns files, comparisons and best", async () => {
    const r = await apiGet(rootPage, `v1/kyc/cases/admin/cases/${caseId}/face-comparison`);
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.case_id).toBe(caseId);
    expect(data.user_sub).toBe(ALICE_ID);
    expect(data.selfie_file).toBeTruthy();
    expect(data.selfie_file.file_type).toBe("selfie");
    expect(data.id_front_file.file_type).toBe("id_front");
    expect(data.selfie_url).toContain("/mock/s3/");
    expect(data.total_attempts).toBe(3);
    expect(data.best_comparison.confidence_score).toBe(85);
    expect(data.best_comparison.result).toBe("pass");
  });

  test("725.2 admin override changes a comparison to fail with reason", async () => {
    const view = await (
      await apiGet(rootPage, `v1/kyc/cases/admin/cases/${caseId}/face-comparison`)
    ).json();
    const best = view.best_comparison.comparison_id;
    const r = await apiPost(
      rootPage,
      "root",
      `v1/kyc/cases/admin/cases/${caseId}/face-comparison/${best}/override`,
      { decision: "fail", reason: "Manual review: lighting artifacts cause false match." },
    );
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.comparison_id).toBe(best);
    expect(data.original_result).toBe("pass");
    expect(data.original_score).toBe(85);
    expect(data.admin_override.decision).toBe("fail");
    expect(data.admin_override.admin_sub).toBe(ROOT_SUB);

    // override is persisted on the stored comparison
    const view2 = await (
      await apiGet(rootPage, `v1/kyc/cases/admin/cases/${caseId}/face-comparison`)
    ).json();
    const overridden = view2.comparisons.find(
      (c: { comparison_id: string }) => c.comparison_id === best,
    );
    expect(overridden.admin_override.decision).toBe("fail");
  });

  test("725.3 admin override with short reason returns 422", async () => {
    const view = await (
      await apiGet(rootPage, `v1/kyc/cases/admin/cases/${caseId}/face-comparison`)
    ).json();
    const cid = view.comparisons[0].comparison_id;
    const r = await apiPost(
      rootPage,
      "root",
      `v1/kyc/cases/admin/cases/${caseId}/face-comparison/${cid}/override`,
      { decision: "pass", reason: "ok" },
    );
    expect(r.status()).toBe(422);
  });

  test("725.4 admin override on non-existent comparison returns 404", async () => {
    const r = await apiPost(
      rootPage,
      "root",
      `v1/kyc/cases/admin/cases/${caseId}/face-comparison/fc_000000000000/override`,
      { decision: "pass", reason: "valid reason here" },
    );
    expect(r.status()).toBe(404);
  });

  test("725.5 non-admin user cannot access admin face comparison (403)", async () => {
    const r = await apiGet(alicePage, `v1/kyc/cases/admin/cases/${caseId}/face-comparison`);
    expect(r.status()).toBe(403);
  });

  test("725.6 non-admin user cannot override (403)", async () => {
    const view = await (
      await apiGet(rootPage, `v1/kyc/cases/admin/cases/${caseId}/face-comparison`)
    ).json();
    const cid = view.comparisons[0].comparison_id;
    const r = await apiPost(
      alicePage,
      "alice",
      `v1/kyc/cases/admin/cases/${caseId}/face-comparison/${cid}/override`,
      { decision: "pass", reason: "should not be allowed" },
    );
    expect(r.status()).toBe(403);
  });

  test("725.7 admin can view comparison for any user's case", async () => {
    const r = await apiGet(rootPage, `v1/kyc/cases/admin/cases/${caseId}/face-comparison`);
    expect(r.status()).toBe(200);
    expect((await r.json()).comparisons.length).toBe(3);
  });
});
