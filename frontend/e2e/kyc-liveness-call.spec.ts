/**
 * E2E tests for KYC-003: Liveness Video Verification Call.
 *
 * Section 170: Scheduling API (owner) — schedule, double-schedule 409, validation
 * Section 171: Verifier API — list-by-status, conduct, record pass/fail outcome
 * Section 172: Result feeds the KYC case + access control
 * Section 173: Owner status view (per-case) + ownership 403
 *
 * Auth: cookie + CSRF via e2e_admin_session_setup.py (root, alice, bob,
 * charlie_admin). Owner endpoints use require_ui_session; verifier endpoints use
 * require_admin_or_root (a KYC_VERIFIER scope does NOT exist — admins/root act as
 * verifiers).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

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
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_admin_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  await page.context().addCookies(getSessions()[identity].cookies);
  await page.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, getSessions()[identity].user_sub);
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

const TS = Date.now();

async function createCase(page: Page, identity: string): Promise<string> {
  const resp = await apiPost(page, identity, "v1/kyc/cases", { intake_profile: "individual" });
  expect(resp.status()).toBe(200);
  const data = await resp.json();
  return data.case.kyc_case_id as string;
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

// ─── Section 170: Scheduling API (owner) ────────────────────────────────────

test.describe("170: KYC liveness call scheduling", () => {
  let alice: Page;
  let caseId: string;

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    caseId = await createCase(alice, "alice");
  });
  test.afterAll(async () => {
    await alice.close();
  });

  test("170.1 Owner schedules a liveness call for a case", async () => {
    const resp = await apiPost(alice, "alice", "ui/kyc/liveness-call", {
      case_id: caseId,
      scheduled_at: nowSec() + 3600,
      duration_minutes: 15,
      note: `liveness ${TS}`,
    });
    expect(resp.status()).toBe(201);
    const call = await resp.json();
    expect(call.call_id).toMatch(/^kyccall_/);
    expect(call.case_id).toBe(caseId);
    expect(call.status).toBe("scheduled");
    expect(call.duration_minutes).toBe(15);
  });

  test("170.2 Double-scheduling on an already-active case returns 409", async () => {
    const resp = await apiPost(alice, "alice", "ui/kyc/liveness-call", {
      case_id: caseId,
      scheduled_at: nowSec() + 7200,
    });
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail.code).toBe("kyc_call_already_scheduled");
  });

  test("170.3 Scheduling lists the call under the owner", async () => {
    const resp = await apiGet(alice, "ui/kyc/liveness-call");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.calls.find((c: { case_id: string }) => c.case_id === caseId);
    expect(found).toBeTruthy();
  });

  test("170.4 Duration must be between 5 and 60 minutes", async () => {
    const other = await createCase(alice, "alice");
    const tooShort = await apiPost(alice, "alice", "ui/kyc/liveness-call", {
      case_id: other,
      scheduled_at: nowSec() + 3600,
      duration_minutes: 3,
    });
    expect(tooShort.status()).toBe(422);
    const tooLong = await apiPost(alice, "alice", "ui/kyc/liveness-call", {
      case_id: other,
      scheduled_at: nowSec() + 3600,
      duration_minutes: 61,
    });
    expect(tooLong.status()).toBe(422);
  });

  test("170.5 Non-owner cannot view another owner's call by id", async ({ browser }) => {
    const list = await apiGet(alice, "ui/kyc/liveness-call");
    const data = await list.json();
    const callId = data.calls.find((c: { case_id: string }) => c.case_id === caseId)?.call_id;
    expect(callId).toBeTruthy();
    const bob = await newIdentityPage(browser, "bob");
    const resp = await apiGet(bob, `ui/kyc/liveness-call/${callId}`);
    expect(resp.status()).toBe(403);
    await bob.close();
  });
});

// ─── Section 171: Verifier API ──────────────────────────────────────────────

test.describe("171: KYC liveness call verifier flow", () => {
  let alice: Page;
  let root: Page;
  let caseId: string;
  let callId: string;

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    root = await newIdentityPage(browser, "root");
    caseId = await createCase(alice, "alice");
    const resp = await apiPost(alice, "alice", "ui/kyc/liveness-call", {
      case_id: caseId,
      scheduled_at: nowSec() + 3600,
      duration_minutes: 30,
    });
    expect(resp.status()).toBe(201);
    callId = (await resp.json()).call_id;
  });
  test.afterAll(async () => {
    await alice.close();
    await root.close();
  });

  test("171.1 Verifier lists scheduled calls by status", async () => {
    const resp = await apiGet(root, "ui/kyc/liveness-call/admin/by-status", {
      status: "scheduled",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.calls.find((c: { call_id: string }) => c.call_id === callId);
    expect(found).toBeTruthy();
  });

  test("171.2 Non-admin cannot list calls by status", async () => {
    const resp = await apiGet(alice, "ui/kyc/liveness-call/admin/by-status", {
      status: "scheduled",
    });
    expect(resp.status()).toBe(403);
  });

  test("171.3 Verifier conducts the call (in_progress)", async () => {
    const resp = await apiPost(root, "root", `ui/kyc/liveness-call/admin/${callId}/conduct`);
    expect(resp.status()).toBe(200);
    const call = await resp.json();
    expect(call.status).toBe("in_progress");
    expect(call.started_at).toBeGreaterThan(0);
  });

  test("171.4 Result notes are required (empty rejected)", async () => {
    const resp = await apiPost(root, "root", `ui/kyc/liveness-call/admin/${callId}/result`, {
      result: "passed",
      notes: "",
    });
    expect(resp.status()).toBe(422);
  });

  test("171.5 Verifier records a passing outcome with recording ref", async () => {
    const resp = await apiPost(root, "root", `ui/kyc/liveness-call/admin/${callId}/result`, {
      result: "passed",
      notes: "Identity confirmed visually; matches ID photo.",
      recording_linked: true,
    });
    expect(resp.status()).toBe(200);
    const call = await resp.json();
    expect(call.status).toBe("passed");
    expect(call.result).toBe("passed");
    expect(call.recording_ref).toContain("/recording.webm");
  });

  test("171.6 Recording a verifier-only invalid result value is rejected", async () => {
    const other = await createCase(alice, "alice");
    const sched = await apiPost(alice, "alice", "ui/kyc/liveness-call", {
      case_id: other,
      scheduled_at: nowSec() + 3600,
    });
    const cid = (await sched.json()).call_id;
    const resp = await apiPost(root, "root", `ui/kyc/liveness-call/admin/${cid}/result`, {
      result: "inconclusive",
      notes: "n/a",
    });
    // "inconclusive" is not an allowed verifier outcome -> 422 (schema/state)
    expect(resp.status()).toBe(422);
  });

  test("171.7 Failed outcome recorded with notes", async () => {
    const other = await createCase(alice, "alice");
    const sched = await apiPost(alice, "alice", "ui/kyc/liveness-call", {
      case_id: other,
      scheduled_at: nowSec() + 3600,
    });
    const cid = (await sched.json()).call_id;
    const resp = await apiPost(root, "root", `ui/kyc/liveness-call/admin/${cid}/result`, {
      result: "failed",
      notes: "Person did not match the ID photo.",
    });
    expect(resp.status()).toBe(200);
    const call = await resp.json();
    expect(call.status).toBe("failed");
    expect(call.result).toBe("failed");
  });
});

// ─── Section 172: Result feeds the KYC case + access ────────────────────────

test.describe("172: KYC liveness call result feeds case", () => {
  let alice: Page;
  let root: Page;
  let caseId: string;

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    root = await newIdentityPage(browser, "root");
    caseId = await createCase(alice, "alice");
  });
  test.afterAll(async () => {
    await alice.close();
    await root.close();
  });

  test("172.1 Passing result is mirrored onto the KYC case verification_call", async () => {
    const sched = await apiPost(alice, "alice", "ui/kyc/liveness-call", {
      case_id: caseId,
      scheduled_at: nowSec() + 3600,
    });
    expect(sched.status()).toBe(201);
    const callId = (await sched.json()).call_id;

    const result = await apiPost(root, "root", `ui/kyc/liveness-call/admin/${callId}/result`, {
      result: "passed",
      notes: "Confirmed.",
    });
    expect(result.status()).toBe(200);

    // The case now carries the verification_call result.
    const caseResp = await apiGet(alice, `v1/kyc/cases/${caseId}`);
    expect(caseResp.status()).toBe(200);
    const caseData = await caseResp.json();
    expect(caseData.case.verification_call.result).toBe("passed");
    expect(caseData.case.verification_call.call_id).toBe(callId);
  });

  test("172.2 Admin can fetch the call detail by id", async () => {
    const list = await apiGet(root, "ui/kyc/liveness-call/admin/by-status", { status: "passed" });
    const data = await list.json();
    const found = data.calls.find((c: { case_id: string }) => c.case_id === caseId);
    expect(found).toBeTruthy();
    const detail = await apiGet(root, `ui/kyc/liveness-call/admin/${found.call_id}`);
    expect(detail.status()).toBe(200);
    expect((await detail.json()).call_id).toBe(found.call_id);
  });

  test("172.3 Admin get on non-existent call returns 404", async () => {
    const resp = await apiGet(root, "ui/kyc/liveness-call/admin/kyccall_doesnotexist");
    expect(resp.status()).toBe(404);
  });
});

// ─── Section 173: Owner status view + cancel/reschedule ─────────────────────

test.describe("173: KYC liveness call owner status view", () => {
  let alice: Page;
  let bob: Page;
  let caseId: string;

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    bob = await newIdentityPage(browser, "bob");
    caseId = await createCase(alice, "alice");
  });
  test.afterAll(async () => {
    await alice.close();
    await bob.close();
  });

  test("173.1 Owner sees scheduled call status for the case", async () => {
    const sched = await apiPost(alice, "alice", "ui/kyc/liveness-call", {
      case_id: caseId,
      scheduled_at: nowSec() + 3600,
    });
    expect(sched.status()).toBe(201);
    const resp = await apiGet(alice, `ui/kyc/liveness-call/case/${caseId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.verification_call.status).toBe("scheduled");
    expect(data.verification_call.scheduled_at).toBeGreaterThan(0);
    // owner view must not leak verifier identity
    expect(data.verification_call.verifier_sub).toBeUndefined();
  });

  test("173.2 Non-owner gets 403 on per-case status", async () => {
    const resp = await apiGet(bob, `ui/kyc/liveness-call/case/${caseId}`);
    expect(resp.status()).toBe(403);
  });

  test("173.3 Case with no call returns null verification_call", async () => {
    const empty = await createCase(alice, "alice");
    const resp = await apiGet(alice, `ui/kyc/liveness-call/case/${empty}`);
    expect(resp.status()).toBe(200);
    expect((await resp.json()).verification_call).toBeNull();
  });

  test("173.4 Owner cancels then can reschedule", async () => {
    const status = await apiGet(alice, `ui/kyc/liveness-call/case/${caseId}`);
    const callId = (await status.json()).verification_call.call_id;
    const cancel = await apiPost(alice, "alice", `ui/kyc/liveness-call/${callId}/cancel`);
    expect(cancel.status()).toBe(200);
    expect((await cancel.json()).status).toBe("cancelled");

    // No active call now -> rescheduling succeeds.
    const resched = await apiPost(alice, "alice", "ui/kyc/liveness-call", {
      case_id: caseId,
      scheduled_at: nowSec() + 3600,
    });
    expect(resched.status()).toBe(201);
    expect((await resched.json()).status).toBe("scheduled");
  });

  test("173.5 Join URL is present within the join window", async () => {
    const near = await createCase(alice, "alice");
    // schedule for ~1 min out, well inside the 5-minute join window
    const sched = await apiPost(alice, "alice", "ui/kyc/liveness-call", {
      case_id: near,
      scheduled_at: nowSec() + 60,
    });
    expect(sched.status()).toBe(201);
    const resp = await apiGet(alice, `ui/kyc/liveness-call/case/${near}`);
    const data = await resp.json();
    expect(data.verification_call.join_url).toContain("/call/");
  });
});
