/**
 * E2E tests for KYC-019 — Case Assignment & Workload Management.
 *
 * Section 760: Auto-assignment API (routing, eligibility, auth)
 * Section 761: Manual reassign / claim / unclaim + availability
 * Section 762: SLA config + breach detection + escalation
 * Section 763: Workload dashboard API + UI
 *
 * Auth strategy mirrors admin-roles.spec.ts: role-bearing cookies seeded by
 * e2e_admin_session_setup.py (root / alice=user / charlie_admin=admin).
 * Cases + admin-availability records are seeded directly into the kyc_cases
 * DDB table so the assignment engine has data to operate on.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, resolveIdentityId, isCpp, unauthContext } from "./helpers/session";
import { cppSeedKycCaseFull } from "./helpers/cpp-seed-kyc";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const ROOT_SUB   = "root.admin@testdev.local";
const ALICE_ID   = resolveIdentityId("e2e_alice@test.local");
const CHARLIE_ID = resolveIdentityId("e2e_charlie@test.local");

const TS = Date.now();

// ─── Session bootstrap ─────────────────────────────────────────────

interface AdminSessionData {
  user_sub: string;
  csrf_token: string;
  cookies: Array<Record<string, unknown>>;
}

let _sessions: Record<string, AdminSessionData> | null = null;
function getSessions(): Record<string, AdminSessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies as never);
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

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

// ─── DDB seeding ───────────────────────────────────────────────────

/** Seed a KYC case directly into the kyc_cases table. Returns case id. */
function seedCase(opts: {
  caseId: string;
  status?: string;
  intakeProfile?: string;
  assignedAdmin?: string | null;
  slaDueAt?: number | null;
  escalationLevel?: number;
}): void {
  const status = opts.status ?? "under_review";
  const intake = opts.intakeProfile ?? "basic";
  // TRACK harness-seed (kyc): under cpp, seed cpp's tlc_kyc_cases so the
  // status_index queue + auto-assign see this case. user_sub is a placeholder
  // ("seed_user") in the python path; keep it for cpp (owner index unused here).
  if (isCpp()) {
    cppSeedKycCaseFull({
      caseId: opts.caseId,
      userSub: "seed_user",
      status,
      intakeProfile: intake,
      assignedAdminSub: opts.assignedAdmin ?? null,
      slaDueAt: opts.slaDueAt ?? null,
      escalationLevel: opts.escalationLevel ?? 0,
    });
    return;
  }
  // Build a Python dict literal (single-quoted) for `review` rather than embedding
  // JSON.stringify output — its double quotes collide with the double-quoted
  // `python3 -c "..."` shell wrapper and break the command.
  const reviewPy =
    `{'assigned_admin_sub': ${opts.assignedAdmin ? `'${opts.assignedAdmin}'` : "None"}, ` +
    `'sla_due_at': ${opts.slaDueAt ?? "None"}, ` +
    `'escalation_level': ${opts.escalationLevel ?? 0}}`;
  execSync(
    `python3 -c "
import boto3, os, json, time
from pathlib import Path
env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line=line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v=line.split('=',1); os.environ.setdefault(k.strip(), v.strip())
ddb=boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
t=ddb.Table(os.environ.get('KYC_CASES_TABLE_NAME','kyc_cases'))
now=int(time.time())
review=${reviewPy}
item={'pk':'KYC#${opts.caseId}','sk':'META','entity_type':'kyc_case','kyc_case_id':'${opts.caseId}','user_sub':'seed_user','status':'${status}','intake_profile':'${intake}','review':review,'created_at':now,'updated_at':now,'version':1,'gsi_status_pk':'STATUS#${status}','gsi_status_sk':'UPDATED#%013d#KYC#${opts.caseId}'%now}
t.put_item(Item=item)
print('seeded ${opts.caseId}')
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
}

function clearAvailabilityAndCases(adminSubs: string[]): void {
  // Python list literal (single-quoted) — avoid JSON double quotes colliding
  // with the double-quoted `python3 -c "..."` shell wrapper.
  const subsPy = "[" + adminSubs.map((s) => `'${s}'`).join(", ") + "]";
  execSync(
    `python3 -c "
import boto3, os, json
from pathlib import Path
env=Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line=line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v=line.split('=',1); os.environ.setdefault(k.strip(), v.strip())
ddb=boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
t=ddb.Table(os.environ.get('KYC_CASES_TABLE_NAME','kyc_cases'))
for s in ${subsPy}:
    t.delete_item(Key={'pk':'ADMIN#'+s,'sk':'AVAILABILITY'})
print('cleared availability')
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
}

// ─── 760. Auto-assignment API ──────────────────────────────────────

test.describe("760. KYC auto-assignment API", () => {
  let rootPage: Page;
  let charliePage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    clearAvailabilityAndCases([ROOT_SUB, CHARLIE_ID]);
    rootPage = await newIdentityPage(browser, "root");
    charliePage = await newIdentityPage(browser, "charlie_admin");
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await charliePage?.close();
    await alicePage?.close();
  });

  test("760.1 auto-assign routes to the only on-duty admin", async () => {
    // Charlie on-duty, Root off-duty.
    await apiPatch(charliePage, "charlie_admin", "v1/kyc/assignment/availability", {
      on_duty: true, expertise_tiers: ["tier_1"], languages: ["en"], max_cases: 20, seniority_level: 1,
    });
    await apiPatch(rootPage, "root", "v1/kyc/assignment/availability", {
      on_duty: false, expertise_tiers: ["tier_1"], languages: ["en"], max_cases: 20, seniority_level: 3,
    });
    const caseId = `kyc_a760a_${TS}`;
    seedCase({ caseId, status: "submitted", intakeProfile: "basic" });

    const r = await apiPost(rootPage, "root", `v1/kyc/assignment/cases/${caseId}/auto-assign`);
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.assigned_admin_sub).toBe(CHARLIE_ID);
    expect(data.tier).toBe("tier_1");
    expect(data.score).toBeGreaterThan(0);
  });

  test("760.2 auto-assign returns null when no admin is eligible", async () => {
    await apiPatch(charliePage, "charlie_admin", "v1/kyc/assignment/availability", {
      on_duty: false, expertise_tiers: ["tier_1"], languages: ["en"], max_cases: 20, seniority_level: 1,
    });
    await apiPatch(rootPage, "root", "v1/kyc/assignment/availability", {
      on_duty: false, expertise_tiers: ["tier_1"], languages: ["en"], max_cases: 20, seniority_level: 3,
    });
    const caseId = `kyc_a760b_${TS}`;
    seedCase({ caseId, status: "submitted" });
    const r = await apiPost(rootPage, "root", `v1/kyc/assignment/cases/${caseId}/auto-assign`);
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.assigned_admin_sub).toBeNull();
    expect(data.reason).toContain("No eligible");
  });

  test("760.3 auto-assign prefers the lower-workload admin", async () => {
    // Both on duty, same expertise. Root pre-loaded with 0 cases, Charlie with many.
    await apiPatch(charliePage, "charlie_admin", "v1/kyc/assignment/availability", {
      on_duty: true, expertise_tiers: ["tier_1"], languages: ["en"], max_cases: 3, seniority_level: 1,
    });
    await apiPatch(rootPage, "root", "v1/kyc/assignment/availability", {
      on_duty: true, expertise_tiers: ["tier_1"], languages: ["en"], max_cases: 20, seniority_level: 1,
    });
    // Give Charlie 3 active cases (at capacity) so he is excluded.
    for (let i = 0; i < 3; i++) {
      seedCase({ caseId: `kyc_a760c_load_${TS}_${i}`, status: "under_review", assignedAdmin: CHARLIE_ID });
    }
    const caseId = `kyc_a760c_${TS}`;
    seedCase({ caseId, status: "submitted" });
    const r = await apiPost(rootPage, "root", `v1/kyc/assignment/cases/${caseId}/auto-assign`);
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.assigned_admin_sub).toBe(ROOT_SUB);
  });

  test("760.4 non-admin (alice) cannot auto-assign (403)", async () => {
    const caseId = `kyc_a760d_${TS}`;
    seedCase({ caseId, status: "submitted" });
    const r = await apiPost(alicePage, "alice", `v1/kyc/assignment/cases/${caseId}/auto-assign`);
    expect(r.status()).toBe(403);
  });

  test("760.5 unauthenticated request is rejected (401)", async () => {
    const caseId = `kyc_a760e_${TS}`;
    seedCase({ caseId, status: "submitted" });
    const anon = await unauthContext(API);
    const r = await anon.post(`/v1/kyc/assignment/cases/${caseId}/auto-assign`);
    expect(r.status()).toBe(401);
    await anon.dispose();
  });

  test("760.6 auto-assign on a missing case returns 404", async () => {
    const r = await apiPost(rootPage, "root", `v1/kyc/assignment/cases/kyc_missing_${TS}/auto-assign`);
    expect(r.status()).toBe(404);
  });
});

// ─── 761. Manual reassign / claim / availability ───────────────────

test.describe("761. KYC manual assignment + availability API", () => {
  let rootPage: Page;
  let charliePage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    charliePage = await newIdentityPage(browser, "charlie_admin");
    // Ensure both have availability records (so reassign target exists).
    await apiPatch(charliePage, "charlie_admin", "v1/kyc/assignment/availability", {
      on_duty: true, expertise_tiers: ["tier_1", "tier_2"], languages: ["en", "es"], max_cases: 20, seniority_level: 1,
    });
    await apiPatch(rootPage, "root", "v1/kyc/assignment/availability", {
      on_duty: true, expertise_tiers: ["tier_1"], languages: ["en"], max_cases: 20, seniority_level: 3,
    });
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await charliePage?.close();
  });

  test("761.1 admin reassigns a case with a reason", async () => {
    const caseId = `kyc_b761a_${TS}`;
    seedCase({ caseId, status: "under_review", assignedAdmin: CHARLIE_ID });
    const r = await apiPost(rootPage, "root", `v1/kyc/assignment/cases/${caseId}/reassign`, {
      new_admin_sub: ROOT_SUB, reason: "Charlie on vacation",
    });
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.ok).toBe(true);
    expect(data.previous_admin_sub).toBe(CHARLIE_ID);
    expect(data.new_admin_sub).toBe(ROOT_SUB);
  });

  test("761.2 reassign with too-short reason returns 422", async () => {
    const caseId = `kyc_b761b_${TS}`;
    seedCase({ caseId, status: "under_review", assignedAdmin: CHARLIE_ID });
    const r = await apiPost(rootPage, "root", `v1/kyc/assignment/cases/${caseId}/reassign`, {
      new_admin_sub: ROOT_SUB, reason: "x",
    });
    expect(r.status()).toBe(422);
  });

  test("761.3 reassign to non-existent admin returns 404", async () => {
    const caseId = `kyc_b761c_${TS}`;
    seedCase({ caseId, status: "under_review", assignedAdmin: CHARLIE_ID });
    const r = await apiPost(rootPage, "root", `v1/kyc/assignment/cases/${caseId}/reassign`, {
      new_admin_sub: `nonexistent_${TS}`, reason: "should fail",
    });
    expect(r.status()).toBe(404);
  });

  test("761.4 claim then unclaim a case", async () => {
    const caseId = `kyc_b761d_${TS}`;
    seedCase({ caseId, status: "under_review", assignedAdmin: null });
    const claim = await apiPost(charliePage, "charlie_admin", `v1/kyc/assignment/cases/${caseId}/claim`);
    expect(claim.status()).toBe(200);
    expect((await claim.json()).assigned_admin_sub).toBe(CHARLIE_ID);
    const unclaim = await apiPost(charliePage, "charlie_admin", `v1/kyc/assignment/cases/${caseId}/unclaim`);
    expect(unclaim.status()).toBe(200);
    expect((await unclaim.json()).previous_admin_sub).toBe(CHARLIE_ID);
  });

  test("761.5 claiming an already-claimed case returns 409", async () => {
    const caseId = `kyc_b761e_${TS}`;
    seedCase({ caseId, status: "under_review", assignedAdmin: ROOT_SUB });
    const r = await apiPost(charliePage, "charlie_admin", `v1/kyc/assignment/cases/${caseId}/claim`);
    expect(r.status()).toBe(409);
  });

  test("761.6 availability toggle + read-back", async () => {
    const r = await apiPatch(charliePage, "charlie_admin", "v1/kyc/assignment/availability", {
      on_duty: false, expertise_tiers: ["tier_2"], languages: ["es"], max_cases: 15, seniority_level: 2,
    });
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.on_duty).toBe(false);
    expect(data.expertise_tiers).toContain("tier_2");
    const got = await apiGet(charliePage, "v1/kyc/assignment/availability");
    expect((await got.json()).max_cases).toBe(15);
  });

  test("761.7 assignment history records auto + manual events", async () => {
    const caseId = `kyc_b761f_${TS}`;
    seedCase({ caseId, status: "under_review", assignedAdmin: CHARLIE_ID });
    await apiPost(rootPage, "root", `v1/kyc/assignment/cases/${caseId}/reassign`, {
      new_admin_sub: ROOT_SUB, reason: "manual move for history",
    });
    const hist = await apiGet(rootPage, `v1/kyc/assignment/cases/${caseId}/history`);
    expect(hist.status()).toBe(200);
    const events = (await hist.json()).events;
    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events[0].event_type).toBe("manual_reassign");
  });
});

// ─── 762. SLA config + breach + escalation ─────────────────────────

test.describe("762. KYC SLA config + escalation API", () => {
  let rootPage: Page;
  let charliePage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    charliePage = await newIdentityPage(browser, "charlie_admin");
    await apiPatch(rootPage, "root", "v1/kyc/assignment/availability", {
      on_duty: true, expertise_tiers: ["tier_1", "tier_2", "tier_3"], languages: ["en"], max_cases: 20, seniority_level: 3,
    });
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await charliePage?.close();
  });

  test("762.1 root reads default SLA config per tier", async () => {
    const r = await apiGet(rootPage, "v1/kyc/assignment/sla-config");
    expect(r.status()).toBe(200);
    const cfg = (await r.json()).sla_config;
    expect(cfg.tier_1.target_hours).toBe(24);
    expect(cfg.tier_2.target_hours).toBe(48);
    expect(cfg.tier_3.target_hours).toBe(120);
  });

  test("762.2 root updates SLA config for tier_1", async () => {
    const r = await apiPatch(rootPage, "root", "v1/kyc/assignment/sla-config/tier_1", {
      target_hours: 12, warning_pct: 60,
    });
    expect(r.status()).toBe(200);
    expect((await r.json()).target_hours).toBe(12);
    const got = await apiGet(rootPage, "v1/kyc/assignment/sla-config");
    expect((await got.json()).sla_config.tier_1.target_hours).toBe(12);
    // restore default
    await apiPatch(rootPage, "root", "v1/kyc/assignment/sla-config/tier_1", { target_hours: 24, warning_pct: 75 });
  });

  test("762.3 non-root admin cannot update SLA config (403)", async () => {
    const r = await apiPatch(charliePage, "charlie_admin", "v1/kyc/assignment/sla-config/tier_1", {
      target_hours: 5, warning_pct: 70,
    });
    expect(r.status()).toBe(403);
  });

  test("762.4 unrecognized tier returns 400", async () => {
    const r = await apiPatch(rootPage, "root", "v1/kyc/assignment/sla-config/tier_9", {
      target_hours: 24, warning_pct: 75,
    });
    expect(r.status()).toBe(400);
  });

  test("762.5 overdue case appears in breach list and escalates", async () => {
    const caseId = `kyc_c762_${TS}`;
    const past = Math.floor(Date.now() / 1000) - 3600; // due 1h ago
    seedCase({ caseId, status: "under_review", assignedAdmin: CHARLIE_ID, slaDueAt: past, escalationLevel: 0 });

    const breaches = await apiGet(rootPage, "v1/kyc/assignment/sla/breaches");
    expect(breaches.status()).toBe(200);
    const list = (await breaches.json()).breaches as Array<Record<string, unknown>>;
    expect(list.some((b) => b.kyc_case_id === caseId)).toBe(true);

    const esc = await apiPost(rootPage, "root", `v1/kyc/assignment/cases/${caseId}/escalate`);
    expect(esc.status()).toBe(200);
    const escData = await esc.json();
    expect(escData.escalation_level).toBe(1);

    const hist = await apiGet(rootPage, `v1/kyc/assignment/cases/${caseId}/history`);
    const events = (await hist.json()).events as Array<Record<string, unknown>>;
    expect(events.some((e) => e.event_type === "escalation")).toBe(true);
  });
});

// ─── 763. Workload dashboard API + UI ──────────────────────────────

test.describe("763. KYC workload dashboard", () => {
  let rootPage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
    await apiPatch(rootPage, "root", "v1/kyc/assignment/availability", {
      on_duty: true, expertise_tiers: ["tier_1"], languages: ["en"], max_cases: 20, seniority_level: 3,
    });
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("763.1 workloads endpoint returns admins + sla_config", async () => {
    const r = await apiGet(rootPage, "v1/kyc/assignment/workloads");
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(Array.isArray(data.admins)).toBe(true);
    expect(data.sla_config.tier_1).toBeTruthy();
    expect(typeof data.total_active_cases).toBe("number");
  });

  test("763.2 workload case counts reflect a fresh assignment", async () => {
    const caseId = `kyc_d763_${TS}`;
    seedCase({ caseId, status: "under_review", assignedAdmin: null });
    await apiPost(rootPage, "root", `v1/kyc/assignment/cases/${caseId}/reassign`, {
      new_admin_sub: ROOT_SUB, reason: "count check assignment",
    });
    const r = await apiGet(rootPage, "v1/kyc/assignment/workloads");
    const data = await r.json();
    const root = (data.admins as Array<Record<string, unknown>>).find((a) => a.admin_sub === ROOT_SUB);
    expect(root).toBeTruthy();
    expect(Number(root!.current_case_count)).toBeGreaterThanOrEqual(1);
  });

  test("763.3 non-admin (alice) cannot access workloads (403)", async () => {
    const r = await apiGet(alicePage, "v1/kyc/assignment/workloads");
    expect(r.status()).toBe(403);
  });

  test("763.4 workload dashboard UI renders table + stat cards", async () => {
    await rootPage.goto("/admin/kyc-workload");
    await expect(rootPage.getByTestId("kyc-workload-page")).toBeVisible();
    await expect(rootPage.getByTestId("stat-active-cases")).toBeVisible();
    await expect(rootPage.getByTestId("workload-table")).toBeVisible();
  });

  test("763.5 SLA config tab shows three tier rows", async () => {
    await rootPage.goto("/admin/kyc-workload");
    await rootPage.getByRole("tab", { name: "SLA Config" }).click();
    await expect(rootPage.getByTestId("sla-row-tier_1")).toBeVisible();
    await expect(rootPage.getByTestId("sla-row-tier_2")).toBeVisible();
    await expect(rootPage.getByTestId("sla-row-tier_3")).toBeVisible();
  });
});
