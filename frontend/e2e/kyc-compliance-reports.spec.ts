/**
 * E2E tests for KYC-012: Compliance Reporting & Export.
 *
 * Sections:
 *   706 — Volume / Processing Time / Screening report APIs (6 tests)
 *   707 — Deadline tracker / Retention / Audit trail APIs (5 tests)
 *   708 — SAR generation, CSV/PDF export, authz (7 tests)
 *
 * Auth: Root + Charlie (admin) sessions from e2e_admin_session_setup.py;
 * Alice (USER) for non-admin rejection. KYC cases + screening results are
 * seeded directly into DynamoDB.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ROOT_SUB = "root.admin@testdev.local";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();
const RUN = `c${TS}`;

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

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_admin_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getAdminSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

async function apiGet(page: Page, identity: string, path: string) {
  const sessions = getAdminSessions();
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": sessions[identity].csrf_token },
  });
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  const sessions = getAdminSessions();
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
screening = ddb.Table('kyc_screening_results')
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

interface SeedCaseOpts {
  caseId: string;
  userSub: string;
  status: string;
  createdAt?: number; // unix seconds
  submittedAt?: number;
  decidedAt?: number;
  purgedAt?: number | null;
  assignedAdmin?: string | null;
}

function seedCase(o: SeedCaseOpts) {
  const created = o.createdAt ?? Math.floor(Date.now() / 1000);
  const submitted = o.submittedAt ?? created;
  const decided = o.decidedAt ?? 0;
  const assigned = o.assignedAdmin ? `"${o.assignedAdmin}"` : "None";
  const purged = o.purgedAt ? `${o.purgedAt}` : "None";
  // GSI sk uses the *updated_at* timestamp; align it with decided/submitted so
  // date-range queries find the case in its decided window.
  const updated = decided || submitted || created;
  runPy(`
case_id = "${o.caseId}"
created = ${created}
submitted = ${submitted}
decided = ${decided}
updated = ${updated}
status = "${o.status}"
updated_sk = f"UPDATED#{str(updated).zfill(13)}#KYC#{case_id}"
review = {"ticket_id": None, "assigned_admin_sub": ${assigned}, "decision": (status if status in ("approved","rejected") else None),
          "decided_at": (decided if decided else None), "reason_codes": [], "purged_at": ${purged}}
item = {
    "pk": f"KYC#{case_id}", "sk": "META", "entity_type": "kyc_case", "kyc_case_id": case_id,
    "user_sub": "${o.userSub}", "status": status, "intake_profile": "standard", "questionnaire": {},
    "files": [
        {"type": "selfie", "path": "/x/selfie.jpg"},
        {"type": "id_front", "path": "/x/id_front.jpg"},
        {"type": "id_back", "path": "/x/id_back.jpg"},
    ],
    "signature": {}, "submission": ({"submitted_at": submitted} if status != "draft" else {}),
    "review": review, "created_at": created, "updated_at": updated, "version": 1,
    "gsi_owner_pk": f"OWNER#${o.userSub}", "gsi_owner_sk": updated_sk,
    "gsi_status_pk": f"STATUS#{status}", "gsi_status_sk": updated_sk,
}
cases.put_item(Item=item)
print(case_id)
`);
}

function seedScreening(caseId: string, userSub: string, result: string, reviewDecision: string | null, createdAt: number) {
  const dec = reviewDecision ? `"${reviewDecision}"` : "None";
  runPy(`
screening.put_item(Item={
    "case_id": "${caseId}", "screen_key": "sanctions_ofac#${createdAt}", "screening_id": "scr_${caseId}",
    "screen_type": "sanctions_ofac", "user_sub": "${userSub}", "result": "${result}",
    "review_decision": ${dec}, "reviewed_by": (${dec} and "${ROOT_SUB}" or None),
    "match_details": [], "provider": "mock", "trigger": "manual", "created_at": ${createdAt},
})
print("ok")
`);
}

function deleteCase(caseId: string) {
  runPy(`cases.delete_item(Key={"pk": f"KYC#${caseId}", "sk": "META"}); print("d")`);
}

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const NOW = Math.floor(Date.now() / 1000);
const HOUR = 3600;
const DAY = 86400;

const APPROVED = `kyc_${RUN}_appr`;
const REJECTED = `kyc_${RUN}_rej`;
const DRAFT = `kyc_${RUN}_draft`;
const OVERDUE_WARN = `kyc_${RUN}_warn`;
const OVERDUE_CRIT = `kyc_${RUN}_crit`;
const RETENTION_OLD = `kyc_${RUN}_retold`;
const SAR_USER = `user_${RUN}_sar`;
const SAR_CASE = `kyc_${RUN}_sar`;

let rootPage: Page;

test.beforeAll(async ({ browser }) => {
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");

  // Decided cases inside a recent window (submitted 2h, decided 1h ago).
  seedCase({ caseId: APPROVED, userSub: `user_${RUN}_a`, status: "approved", createdAt: NOW - 3 * HOUR, submittedAt: NOW - 2 * HOUR, decidedAt: NOW - 1 * HOUR });
  seedCase({ caseId: REJECTED, userSub: `user_${RUN}_b`, status: "rejected", createdAt: NOW - 3 * HOUR, submittedAt: NOW - 2 * HOUR, decidedAt: NOW - 1 * HOUR + 600 });
  seedCase({ caseId: DRAFT, userSub: `user_${RUN}_c`, status: "draft", createdAt: NOW - 1 * HOUR });

  // Overdue pending cases.
  seedCase({ caseId: OVERDUE_WARN, userSub: `user_${RUN}_w`, status: "submitted", createdAt: NOW - 72 * HOUR, submittedAt: NOW - 72 * HOUR });
  seedCase({ caseId: OVERDUE_CRIT, userSub: `user_${RUN}_x`, status: "under_review", createdAt: NOW - 200 * HOUR, submittedAt: NOW - 200 * HOUR });

  // Retention: rejected case decided long ago -> purge overdue.
  seedCase({ caseId: RETENTION_OLD, userSub: `user_${RUN}_r`, status: "rejected", createdAt: NOW - 400 * DAY, submittedAt: NOW - 400 * DAY, decidedAt: NOW - 365 * DAY });

  // SAR subject with one approved case.
  seedCase({ caseId: SAR_CASE, userSub: SAR_USER, status: "approved", createdAt: NOW - 5 * DAY, submittedAt: NOW - 5 * DAY, decidedAt: NOW - 4 * DAY });

  // Screening results in the recent window: 1 clear, 1 confirmed (escalated), 1 potential (false positive/clear).
  seedScreening(`scr_${RUN}_1`, `user_${RUN}_a`, "clear", null, NOW - 2 * HOUR);
  seedScreening(`scr_${RUN}_2`, `user_${RUN}_b`, "confirmed_match", "escalate", NOW - 2 * HOUR);
  seedScreening(`scr_${RUN}_3`, `user_${RUN}_c`, "potential_match", "clear", NOW - 2 * HOUR);
});

test.afterAll(async () => {
  for (const c of [APPROVED, REJECTED, DRAFT, OVERDUE_WARN, OVERDUE_CRIT, RETENTION_OLD, SAR_CASE]) {
    try {
      deleteCase(c);
    } catch {
      /* ignore */
    }
  }
  await rootPage?.close();
});

// ─── Section 706 ──────────────────────────────────────────────────────────────

test.describe("706 — Volume / Processing / Screening report APIs", () => {
  test("706.1 volume report returns counts by status", async () => {
    const r = await apiGet(rootPage, "root", `/v1/kyc/compliance/reports/volume?start_date=${NOW - 1 * DAY}&end_date=${NOW + HOUR}`);
    expect(r.status()).toBe(200);
    const j = await r.json();
    expect(j.report_type).toBe("volume");
    expect(j.counts_by_status.approved).toBeGreaterThanOrEqual(1);
    expect(j.counts_by_status.rejected).toBeGreaterThanOrEqual(1);
    expect(j.total_cases).toBeGreaterThanOrEqual(2);
  });

  test("706.2 volume report computes approval/rejection rates", async () => {
    const r = await apiGet(rootPage, "root", `/v1/kyc/compliance/reports/volume?start_date=${NOW - 1 * DAY}&end_date=${NOW + HOUR}`);
    const j = await r.json();
    expect(j.approval_rate).toBeGreaterThan(0);
    expect(j.rejection_rate).toBeGreaterThan(0);
    expect(Math.round(j.approval_rate + j.rejection_rate)).toBe(100);
  });

  test("706.3 volume report respects far-future date range (zeros)", async () => {
    const future = NOW + 365 * DAY;
    const r = await apiGet(rootPage, "root", `/v1/kyc/compliance/reports/volume?start_date=${future}&end_date=${future + DAY}`);
    const j = await r.json();
    expect(j.total_cases).toBe(0);
    expect(j.approval_rate).toBe(0);
  });

  test("706.4 processing-time report returns percentiles", async () => {
    const r = await apiGet(rootPage, "root", `/v1/kyc/compliance/reports/processing-time?start_date=${NOW - 1 * DAY}&end_date=${NOW + HOUR}`);
    expect(r.status()).toBe(200);
    const j = await r.json();
    expect(j.report_type).toBe("processing_time");
    expect(j.total_decided).toBeGreaterThanOrEqual(2);
    expect(j.p50_seconds).not.toBeNull();
    expect(j.avg_seconds).toBeGreaterThan(0);
  });

  test("706.5 screening report returns hit-rate + resolutions", async () => {
    const r = await apiGet(rootPage, "root", `/v1/kyc/compliance/reports/screening?start_date=${NOW - 1 * DAY}&end_date=${NOW + HOUR}`);
    expect(r.status()).toBe(200);
    const j = await r.json();
    expect(j.report_type).toBe("screening");
    expect(j.total_screenings).toBeGreaterThanOrEqual(3);
    expect(j.total_hits).toBeGreaterThanOrEqual(2);
    expect(j.confirmed_count).toBeGreaterThanOrEqual(1);
    expect(j.escalated_count).toBeGreaterThanOrEqual(1);
  });

  test("706.6 non-admin user (Alice) gets 403 on volume report", async () => {
    const alicePage = await rootPage.context().browser()!.newPage();
    await injectAuth(alicePage, "alice");
    const r = await apiGet(alicePage, "alice", `/v1/kyc/compliance/reports/volume`);
    expect(r.status()).toBe(403);
    await alicePage.close();
  });
});

// ─── Section 707 ──────────────────────────────────────────────────────────────

test.describe("707 — Deadlines / Retention / Audit trail APIs", () => {
  test("707.1 deadline tracker flags warning case", async () => {
    const r = await apiGet(rootPage, "root", `/v1/kyc/compliance/reports/deadlines?warn_after_hours=48&critical_after_hours=120`);
    expect(r.status()).toBe(200);
    const j = await r.json();
    const warn = j.cases.find((c: { case_id: string }) => c.case_id === OVERDUE_WARN);
    expect(warn).toBeTruthy();
    expect(warn.severity).toBe("warning");
  });

  test("707.2 deadline tracker flags critical case", async () => {
    const r = await apiGet(rootPage, "root", `/v1/kyc/compliance/reports/deadlines`);
    const j = await r.json();
    const crit = j.cases.find((c: { case_id: string }) => c.case_id === OVERDUE_CRIT);
    expect(crit).toBeTruthy();
    expect(crit.severity).toBe("critical");
  });

  test("707.3 retention report shows purge schedule", async () => {
    const r = await apiGet(rootPage, "root", `/v1/kyc/compliance/reports/retention`);
    expect(r.status()).toBe(200);
    const j = await r.json();
    expect(j.report_type).toBe("retention");
    expect(j.policies.rejected).toContain("days");
    const item = j.inventory.find((i: { case_id: string }) => i.case_id === RETENTION_OLD);
    expect(item).toBeTruthy();
    expect(item.retention_days).toBeGreaterThan(0);
  });

  test("707.4 retention report flags overdue purge", async () => {
    const r = await apiGet(rootPage, "root", `/v1/kyc/compliance/reports/retention`);
    const j = await r.json();
    const item = j.inventory.find((i: { case_id: string }) => i.case_id === RETENTION_OLD);
    expect(item.purge_overdue).toBe(true);
  });

  test("707.5 audit trail returns events for user", async () => {
    const r = await apiGet(rootPage, "root", `/v1/kyc/compliance/reports/audit-trail/${SAR_USER}`);
    expect(r.status()).toBe(200);
    const j = await r.json();
    expect(j.report_type).toBe("audit_trail");
    expect(j.user_sub).toBe(SAR_USER);
    expect(j.total_events).toBeGreaterThanOrEqual(1);
  });
});

// ─── Section 708 ──────────────────────────────────────────────────────────────

test.describe("708 — SAR / Export / Authorization", () => {
  test("708.1 SAR generation returns sar_id + case history", async () => {
    const r = await apiPost(rootPage, "root", `/v1/kyc/compliance/sar`, {
      user_sub: SAR_USER,
      reason: `Suspicious pattern detected during run ${RUN}`,
    });
    expect(r.status()).toBe(200);
    const j = await r.json();
    expect(j.sar_id).toMatch(/^SAR_[a-f0-9]{12}$/);
    expect(j.kyc_cases.length).toBeGreaterThanOrEqual(1);
  });

  test("708.2 SAR is stored in kyc_cases table", async () => {
    const r = await apiPost(rootPage, "root", `/v1/kyc/compliance/sar`, {
      user_sub: SAR_USER,
      reason: `Stored SAR check for run ${RUN}`,
    });
    const j = await r.json();
    const out = runPy(`
it = cases.get_item(Key={"pk": "SAR#${j.sar_id}", "sk": "META"}).get("Item")
print("FOUND" if it else "MISSING")
`);
    expect(out).toBe("FOUND");
  });

  test("708.3 SAR with short reason returns 422", async () => {
    const r = await apiPost(rootPage, "root", `/v1/kyc/compliance/sar`, {
      user_sub: SAR_USER,
      reason: "bad",
    });
    expect(r.status()).toBe(422);
  });

  test("708.4 two SARs for same user get distinct ids", async () => {
    const r1 = await apiPost(rootPage, "root", `/v1/kyc/compliance/sar`, { user_sub: SAR_USER, reason: `dup-a ${RUN} 0123456789` });
    const r2 = await apiPost(rootPage, "root", `/v1/kyc/compliance/sar`, { user_sub: SAR_USER, reason: `dup-b ${RUN} 0123456789` });
    const a = await r1.json();
    const b = await r2.json();
    expect(a.sar_id).not.toBe(b.sar_id);
  });

  test("708.5 CSV export returns text/csv with Content-Disposition", async () => {
    const r = await apiPost(rootPage, "root", `/v1/kyc/compliance/reports/deadlines/export`, { format: "csv" });
    expect(r.status()).toBe(200);
    expect(r.headers()["content-type"]).toContain("text/csv");
    expect(r.headers()["content-disposition"]).toContain("attachment");
    const body = await r.text();
    expect(body.length).toBeGreaterThan(0);
  });

  test("708.6 PDF export returns application/pdf", async () => {
    const r = await apiPost(rootPage, "root", `/v1/kyc/compliance/reports/volume/export`, { format: "pdf", start_date: NOW - DAY, end_date: NOW + HOUR });
    expect(r.status()).toBe(200);
    expect(r.headers()["content-type"]).toContain("application/pdf");
    expect(r.headers()["content-disposition"]).toContain(".pdf");
    const buf = await r.body();
    expect(buf.slice(0, 4).toString()).toBe("%PDF");
  });

  test("708.7 export with unknown report type returns 400", async () => {
    const r = await apiPost(rootPage, "root", `/v1/kyc/compliance/reports/foobar/export`, { format: "csv" });
    expect(r.status()).toBe(400);
  });

  test("708.8 admin (Charlie) can access reports; unauth gets 401", async () => {
    const charlie = await rootPage.context().browser()!.newPage();
    await injectAuth(charlie, "charlie_admin");
    const ok = await apiGet(charlie, "charlie_admin", `/v1/kyc/compliance/reports/volume`);
    expect(ok.status()).toBe(200);
    await charlie.close();

    const anon = await rootPage.context().browser()!.newPage();
    const r = await anon.request.get(`${BASE}/v1/kyc/compliance/reports/volume`);
    expect(r.status()).toBe(401);
    await anon.close();
  });
});
