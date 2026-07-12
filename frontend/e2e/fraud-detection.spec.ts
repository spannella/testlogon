/**
 * E2E tests for FIN-015 Fraud Detection Dashboard.
 *
 * Section 706: Fraud review queue + velocity flag (API)
 * Section 707: Risk scoring + user freeze hook (API)
 * Section 708: Fraud case lifecycle / audit trail (API)
 * Section 709: Chargeback auto-flag + config + stats (API)
 * Section 710: Admin-only / unauth access control (API)
 * Section 711: Fraud Detection dashboard UI
 *
 * Auth: cookie sessions seeded by e2e_admin_session_setup.py.
 *   root          – role=root  (admin endpoints + config)
 *   charlie_admin – role=admin (admin endpoints, NOT config)
 *   alice         – role=user  (403 rejection)
 * POST/PATCH carry x-csrf-token (require_admin_or_root → require_ui_session).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// Load backend env (.env.local) so child python processes get the real
// DynamoDB table names + endpoint for boto3 (S.billing_table_name etc.).
function backendEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  const candidates = [
    REPO_ROOT + "/wt/fin015/.env.local",
    REPO_ROOT + "/.env.local",
  ];
  for (const p of candidates) {
    if (!fs.existsSync(p)) continue;
    for (const line of fs.readFileSync(p, "utf-8").split("\n")) {
      const t = line.trim();
      if (!t || t.startsWith("#") || !t.includes("=")) continue;
      const idx = t.indexOf("=");
      env[t.slice(0, idx).trim()] = t.slice(idx + 1).trim();
    }
    break;
  }
  env.DDB_ENDPOINT_URL = env.DDB_ENDPOINT_URL || "http://localhost:8001";
  return env;
}
const PYENV = backendEnv();

const API = "http://localhost:8000";
const BASE = "/v1/admin/fraud";
// UI base: override with FRAUD_UI_BASE when the worktree dev server runs on a
// non-default port (the shared Vite on :3000 may belong to another worktree).
const UI_BASE = process.env.FRAUD_UI_BASE || "";
const ALICE_ID = "e2e_alice@test.local";

// Unique per-run user ids to avoid cross-run interference.
const TS = Date.now();
const VEL_USER = `e2efraud_vel_${TS}`;
const CB_USER = `e2efraud_cb_${TS}`;
const FREEZE_USER = `e2efraud_frz_${TS}`;

// ─── Session bootstrap ───────────────────────────────────────────────────────

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
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_admin_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await page.context().addCookies(getSessions()[identity].cookies as any);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.patch(`${API}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}${path}`, { params });
}

// ─── DDB seed helper (Python) ────────────────────────────────────────────────

/** Run an inline Python snippet against the local DynamoDB. */
function ddbPython(body: string): void {
  const script = `
import os, time
from decimal import Decimal
import boto3
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
fraud = ddb.Table('fraud_detection')
billing = ddb.Table('billing')
now = int(time.time())
${body}
`;
  execSync(`python3 -c "${script.replace(/"/g, '\\"')}"`, {
    cwd: REPO_ROOT,
    timeout: 20_000,
    env: PYENV,
  });
}

/** Run an inline Python snippet against the worktree app and return stdout. */
function appPython(body: string): string {
  return execSync(`python3 -c "${body.replace(/"/g, '\\"')}"`, {
    cwd: REPO_ROOT,
    timeout: 20_000,
    env: PYENV,
  }).toString();
}

// Seed velocity signal: a high 24h transaction counter on the risk row plus
// best-effort billing-ledger rows. The fraud service reads ledger velocity
// when the billing table is available and falls back to the persisted 24h
// counter otherwise, so the velocity_count rule fires either way (> 20/hr).
function seedVelocityLedger(userId: string): void {
  ddbPython(`
fraud.put_item(Item={'pk':'RISK#USER#${userId}','sk':'SCORE','score':Decimal(0),'components':{},'flagged':False,'frozen':False,'chargeback_count':Decimal(0),'tx_count_24h':Decimal(600),'tx_total_24h':Decimal(60000),'last_scored_at':Decimal(now)})
try:
    for i in range(25):
        eid = 'led_%d_%d' % (now, i)
        billing.put_item(Item={'pk':'USER#${userId}','sk':'LEDGER#%d#%s' % (now - i, eid),'entry_id':eid,'ts':now - i,'type':'tip','amount_cents':100,'state':'settled','reason':'e2e velocity'})
except Exception:
    pass
`);
}

// Seed a flag row directly (status pending) for ALICE.
function seedFlag(flagId: string, userId: string, status: string): void {
  const gsi1 = status === "pending" || status === "investigating" ? "FLAGS#PENDING" : "FLAGS#RESOLVED";
  ddbPython(`
fraud.put_item(Item={'pk':'FLAG#${flagId}','sk':'META','GSI1PK':'${gsi1}','GSI1SK':Decimal(now),'GSI2PK':'FLAGS#USER#${userId}','GSI2SK':Decimal(now),'flag_id':'${flagId}','user_id':'${userId}','tx_id':'led_seed','rule_triggered':'velocity_count','risk_score':Decimal(75),'amount_cents':Decimal(500),'status':'${status}','notes':'','created_at':Decimal(now)})
`);
}

// Seed a risk SCORE row with N prior chargebacks (so the next one auto-flags).
function seedChargebackCount(userId: string, count: number): void {
  ddbPython(`
fraud.put_item(Item={'pk':'RISK#USER#${userId}','sk':'SCORE','score':Decimal(0),'components':{},'flagged':False,'frozen':False,'chargeback_count':Decimal(${count}),'tx_count_24h':Decimal(0),'tx_total_24h':Decimal(0),'last_scored_at':Decimal(now)})
`);
}

// ─── 706. Review queue + velocity flag ───────────────────────────────────────

test.describe("706. Fraud review queue + velocity flag (API)", () => {
  let rootPage: Page;
  const flagPending = `flg_e2e_p_${TS}`;
  const flagResolved = `flg_e2e_r_${TS}`;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    seedFlag(flagPending, ALICE_ID, "pending");
    seedFlag(flagResolved, ALICE_ID, "approved");
    seedVelocityLedger(VEL_USER);
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("velocity flag triggers a fraud case on evaluate_transaction", async () => {
    // Drive the rule engine through the in-process service so a real flag
    // is created from real ledger velocity data (>20 tx/hr).
    const out = appPython(`
import sys; sys.path.insert(0, '${REPO_ROOT}/wt/fin015')
import json
from app.services.fraud_detection import evaluate_transaction
r = evaluate_transaction(user_id='${VEL_USER}', amount_cents=100, entry_type='tip', tx_id='led_eval')
print(json.dumps(r))
`);
    const result = JSON.parse(out.trim().split("\n").pop() as string);
    const rules = (result.triggered_rules as Array<{ rule: string }>).map((x) => x.rule);
    expect(rules).toContain("velocity_count");
    expect(result.flagged).toBe(true);
    expect(["flag", "block"]).toContain(result.action);

    // The flagged tx must now appear in the pending review queue for that user.
    const r = await apiGet(rootPage, `${BASE}/users/${VEL_USER}/risk`);
    expect(r.status()).toBe(200);
    const profile = await r.json();
    expect((profile.recent_flags as unknown[]).length).toBeGreaterThan(0);
  });

  test("Admin retrieves the pending fraud queue", async () => {
    const r = await apiGet(rootPage, `${BASE}/queue`, { status: "pending" });
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(Array.isArray(data.flags)).toBe(true);
    const found = (data.flags as Array<Record<string, unknown>>).find((f) => f.flag_id === flagPending);
    expect(found).toBeDefined();
    expect(found!.user_id).toBe(ALICE_ID);
    expect(typeof found!.risk_score).toBe("number");
    expect(typeof found!.amount_cents).toBe("number");
    expect(found!.status).toBe("pending");
  });

  test("Queue filters by status (resolved)", async () => {
    // Reviewed flags move to the FLAGS#RESOLVED GSI partition regardless of
    // their final status (approved/blocked); query status=resolved.
    const r = await apiGet(rootPage, `${BASE}/queue`, { status: "resolved" });
    expect(r.status()).toBe(200);
    const data = await r.json();
    const found = (data.flags as Array<Record<string, unknown>>).find((f) => f.flag_id === flagResolved);
    expect(found).toBeDefined();
    expect(found!.status).toBe("approved");
  });

  test("Admin approves a flagged transaction (false_positive)", async () => {
    const r = await apiPost(rootPage, "root", `${BASE}/flags/${flagPending}/review`, {
      action: "approve",
      notes: "legit creator",
    });
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.status).toBe("approved");
    expect(data.resolution).toBe("false_positive");
  });

  test("Admin blocks a flagged transaction (confirmed_fraud)", async () => {
    const fid = `flg_e2e_block_${TS}`;
    seedFlag(fid, ALICE_ID, "pending");
    const r = await apiPost(rootPage, "root", `${BASE}/flags/${fid}/review`, {
      action: "block",
      notes: "stolen card",
    });
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.status).toBe("blocked");
    expect(data.resolution).toBe("confirmed_fraud");
  });

  test("Review of a non-existent flag returns 404", async () => {
    const r = await apiPost(rootPage, "root", `${BASE}/flags/flg_nope/review`, { action: "approve" });
    expect(r.status()).toBe(404);
  });
});

// ─── 707. Risk scoring + freeze hook ─────────────────────────────────────────

test.describe("707. Risk scoring + user freeze hook (API)", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("Risk score is computed and persisted for a user", async () => {
    const out = appPython(`
import sys; sys.path.insert(0,'${REPO_ROOT}/wt/fin015')
import json
from app.services.fraud_detection import compute_risk_score
print(json.dumps(compute_risk_score('${VEL_USER}')))
`);
    const r = JSON.parse(out.trim().split("\n").pop() as string);
    expect(typeof r.score).toBe("number");
    expect(r.score).toBeGreaterThanOrEqual(0);
    expect(r.score).toBeLessThanOrEqual(100);
    expect(r.components).toHaveProperty("velocity");
  });

  test("Admin views a user risk profile with components", async () => {
    const r = await apiGet(rootPage, `${BASE}/users/${ALICE_ID}/risk`);
    expect(r.status()).toBe(200);
    const p = await r.json();
    expect(p.user_id).toBe(ALICE_ID);
    expect(p.score).toBeGreaterThanOrEqual(0);
    expect(typeof p.components).toBe("object");
    expect(typeof p.flagged).toBe("boolean");
  });

  test("Risk profile for unknown user returns zero defaults (200)", async () => {
    const r = await apiGet(rootPage, `${BASE}/users/nonexistent_${TS}/risk`);
    expect(r.status()).toBe(200);
    const p = await r.json();
    expect(p.score).toBe(0);
    expect(p.frozen).toBe(false);
  });

  test("Admin freezes a user and the freeze hook reports frozen", async () => {
    const r = await apiPost(rootPage, "root", `${BASE}/users/${FREEZE_USER}/freeze`, {
      reason: "investigation in progress",
    });
    expect(r.status()).toBe(200);
    expect((await r.json()).frozen).toBe(true);

    // Assert the is_frozen() hook other financial flows call returns true.
    const out = appPython(`
import sys; sys.path.insert(0,'${REPO_ROOT}/wt/fin015')
from app.services.fraud_detection import is_frozen
print('FROZEN' if is_frozen('${FREEZE_USER}') else 'OK')
`);
    expect(out).toContain("FROZEN");

    const r2 = await apiGet(rootPage, `${BASE}/users/${FREEZE_USER}/risk`);
    expect((await r2.json()).frozen).toBe(true);
  });

  test("Admin unfreezes a user and the hook reports not-frozen", async () => {
    const r = await apiPost(rootPage, "root", `${BASE}/users/${FREEZE_USER}/unfreeze`);
    expect(r.status()).toBe(200);
    expect((await r.json()).frozen).toBe(false);
    const out = appPython(`
import sys; sys.path.insert(0,'${REPO_ROOT}/wt/fin015')
from app.services.fraud_detection import is_frozen
print('FROZEN' if is_frozen('${FREEZE_USER}') else 'OK')
`);
    expect(out).toContain("OK");
  });

  test("Freeze requires a non-empty reason (422)", async () => {
    const r = await apiPost(rootPage, "root", `${BASE}/users/${FREEZE_USER}/freeze`, { reason: "" });
    expect(r.status()).toBe(422);
  });

  test("Freeze idempotent — freezing twice succeeds", async () => {
    const a = await apiPost(rootPage, "root", `${BASE}/users/${FREEZE_USER}/freeze`, { reason: "x" });
    const b = await apiPost(rootPage, "root", `${BASE}/users/${FREEZE_USER}/freeze`, { reason: "x" });
    expect(a.status()).toBe(200);
    expect(b.status()).toBe(200);
    expect((await b.json()).frozen).toBe(true);
    await apiPost(rootPage, "root", `${BASE}/users/${FREEZE_USER}/unfreeze`);
  });
});

// ─── 708. Fraud case lifecycle / audit trail ─────────────────────────────────

test.describe("708. Fraud case lifecycle (API)", () => {
  let rootPage: Page;
  const caseFlag = `flg_e2e_case_${TS}`;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    seedFlag(caseFlag, ALICE_ID, "pending");
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("Admin creates a fraud case (201) with linked flags", async () => {
    const r = await apiPost(rootPage, "root", `${BASE}/cases`, {
      user_id: ALICE_ID,
      flag_ids: [caseFlag],
      notes: "velocity + new account",
    });
    expect(r.status()).toBe(201);
    const data = await r.json();
    expect(data.case_id).toBeTruthy();
    expect(data.status).toBe("open");
    expect(data.flags).toContain(caseFlag);
  });

  test("Case create with empty flag_ids returns 422", async () => {
    const r = await apiPost(rootPage, "root", `${BASE}/cases`, { user_id: ALICE_ID, flag_ids: [] });
    expect(r.status()).toBe(422);
  });

  test("Admin lists open cases and resolves one (audit trail)", async () => {
    const created = await apiPost(rootPage, "root", `${BASE}/cases`, {
      user_id: ALICE_ID,
      flag_ids: [caseFlag],
    });
    const caseId = (await created.json()).case_id;

    const list = await apiGet(rootPage, `${BASE}/cases`, { status: "open" });
    expect(list.status()).toBe(200);
    const cases = await list.json();
    expect((cases as Array<Record<string, unknown>>).some((c) => c.case_id === caseId)).toBe(true);

    const detail = await apiGet(rootPage, `${BASE}/cases/${caseId}`);
    expect(detail.status()).toBe(200);
    expect(((await detail.json()).flags as unknown[]).length).toBeGreaterThan(0);

    const resolved = await apiPost(rootPage, "root", `${BASE}/cases/${caseId}/resolve`, {
      resolution: "false_positive",
      notes: "verified",
    });
    expect(resolved.status()).toBe(200);
    expect((await resolved.json()).status).toBe("resolved");

    // Resolving again conflicts.
    const again = await apiPost(rootPage, "root", `${BASE}/cases/${caseId}/resolve`, {
      resolution: "false_positive",
    });
    expect(again.status()).toBe(409);
  });

  test("Case detail for unknown case returns 404", async () => {
    const r = await apiGet(rootPage, `${BASE}/cases/case_nope`);
    expect(r.status()).toBe(404);
  });
});

// ─── 709. Chargeback auto-flag + config + stats ──────────────────────────────

test.describe("709. Chargeback auto-flag, config & stats (API)", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    seedChargebackCount(CB_USER, 2); // threshold default = 3
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("Chargeback over threshold auto-flags the user", async () => {
    // 3rd chargeback meets default threshold (3) → auto-flag.
    const r = await apiPost(rootPage, "root", `${BASE}/chargebacks`, {
      user_id: CB_USER,
      amount_cents: 1000,
    });
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.chargeback_count).toBe(3);
    expect(data.auto_flagged).toBe(true);
    expect(data.flag_id).toBeTruthy();
  });

  test("Admin views fraud config", async () => {
    const r = await apiGet(rootPage, `${BASE}/config`);
    expect(r.status()).toBe(200);
    const c = await r.json();
    expect(typeof c.velocity_max_tx_per_hour).toBe("number");
    expect(typeof c.flag_score_threshold).toBe("number");
  });

  test("Root updates fraud thresholds", async () => {
    const r = await apiPatch(rootPage, "root", `${BASE}/config`, { flag_score_threshold: 80 });
    expect(r.status()).toBe(200);
    expect((await r.json()).flag_score_threshold).toBe(80);
    const back = await apiGet(rootPage, `${BASE}/config`);
    expect((await back.json()).flag_score_threshold).toBe(80);
  });

  test("Invalid config threshold returns 422", async () => {
    const r = await apiPatch(rootPage, "root", `${BASE}/config`, { flag_score_threshold: 5 });
    expect(r.status()).toBe(422);
  });

  test("Admin views fraud stats", async () => {
    const r = await apiGet(rootPage, `${BASE}/stats`);
    expect(r.status()).toBe(200);
    const s = await r.json();
    expect(s).toHaveProperty("pending_flags");
    expect(s).toHaveProperty("open_cases");
    expect(s).toHaveProperty("frozen_users");
  });
});

// ─── 710. Access control ─────────────────────────────────────────────────────

test.describe("710. Fraud admin access control (API)", () => {
  let alicePage: Page;
  let charliePage: Page;
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    charliePage = await newIdentityPage(browser, "charlie_admin");
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await alicePage?.close();
    await charliePage?.close();
    await rootPage?.close();
  });

  test("Non-admin (user) cannot access the fraud queue → 403", async () => {
    const r = await apiGet(alicePage, `${BASE}/queue`);
    expect(r.status()).toBe(403);
  });

  test("Unauthenticated request → 401", async ({ request }) => {
    const r = await request.get(`${API}${BASE}/queue`);
    expect(r.status()).toBe(401);
  });

  test("Admin (non-root) CAN access the queue but CANNOT update config → 403", async () => {
    const ok = await apiGet(charliePage, `${BASE}/queue`);
    expect(ok.status()).toBe(200);
    const denied = await apiPatch(charliePage, "charlie_admin", `${BASE}/config`, {
      flag_score_threshold: 75,
    });
    expect(denied.status()).toBe(403);
  });

  test("Root CAN update config", async () => {
    const r = await apiPatch(rootPage, "root", `${BASE}/config`, { velocity_max_tx_per_hour: 30 });
    expect(r.status()).toBe(200);
    expect((await r.json()).velocity_max_tx_per_hour).toBe(30);
  });
});

// ─── 711. Dashboard UI ───────────────────────────────────────────────────────

test.describe("711. Fraud Detection dashboard UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    seedFlag(`flg_e2e_ui_${TS}`, ALICE_ID, "pending");
    const sess = getSessions().root;
    const ctx = await browser.newContext();
    await ctx.addCookies(sess.cookies as any);
    // The SPA gates routes on a persisted zustand "auth-store"; cookies alone
    // are not enough for the client-side RequireAuth. Seed localStorage so the
    // app hydrates as the authenticated root user before navigation.
    await ctx.addInitScript((token: string) => {
      window.localStorage.setItem(
        "auth-store",
        JSON.stringify({
          state: {
            userId: "root.admin@testdev.local",
            accessToken: token,
            isAuthenticated: true,
            logoutReason: null,
          },
          version: 0,
        }),
      );
    }, sess.access_token);
    rootPage = await ctx.newPage();
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("Dashboard loads with stats bar", async () => {
    await rootPage.goto(`${UI_BASE}/admin/fraud`);
    await expect(rootPage.getByRole("heading", { name: "Fraud Detection" })).toBeVisible({
      timeout: 15_000,
    });
    await expect(rootPage.getByText("Pending Flags").first()).toBeVisible();
    await expect(rootPage.getByText("Open Cases").first()).toBeVisible();
    await expect(rootPage.getByText("Frozen Users").first()).toBeVisible();
  });

  test("Queue tab lists flagged transactions with risk badges", async () => {
    await rootPage.goto(`${UI_BASE}/admin/fraud`);
    await rootPage.getByRole("tab", { name: /Queue/ }).click();
    await expect(rootPage.locator('[data-testid="flag-row"]').first()).toBeVisible({ timeout: 10_000 });
    await expect(rootPage.locator('[data-testid="risk-score-badge"]').first()).toBeVisible();
  });

  test("Users tab allows risk profile search", async () => {
    await rootPage.goto(`${UI_BASE}/admin/fraud`);
    await rootPage.getByRole("tab", { name: /Users/ }).click();
    await rootPage.locator('[data-testid="user-risk-search-input"]').fill(ALICE_ID);
    await rootPage.locator('[data-testid="user-risk-search-btn"]').click();
    await expect(rootPage.locator('[data-testid="risk-profile-card"]')).toBeVisible({ timeout: 10_000 });
  });

  test("Config tab shows the threshold form", async () => {
    await rootPage.goto(`${UI_BASE}/admin/fraud`);
    await rootPage.getByRole("tab", { name: /Config/ }).click();
    await expect(rootPage.locator('[data-testid="fraud-config-form"]')).toBeVisible({ timeout: 10_000 });
    await expect(rootPage.getByText("Flag score threshold")).toBeVisible();
  });
});
