/**
 * E2E tests for KYC Risk Scoring Engine (KYC-008).
 *
 * Sections:
 *   178 — Risk Score Computation API (6 tests)
 *   179 — Admin Risk Endpoints (4 tests)
 *   180 — Score History & Re-scoring (4 tests)
 *   181 — Risk Distribution Dashboard API (4 tests)
 *
 * Auth: Root session cookies for admin endpoints; Alice for user endpoints.
 * CSRF: POST requests include x-csrf-token header.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ─────────────────────────────────────────────────────

const BASE       = "http://localhost:3000";
const ALICE_ID   = "e2e_alice@test.local";
const ROOT_SUB   = "root.admin@testdev.local";
const TS         = Date.now();

// ─── Session bootstrap ─────────────────────────────────────────────

interface AdminSessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name:     string;
    value:    string;
    domain:   string;
    path:     string;
    httpOnly: boolean;
    secure:   boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires:  number;
  }>;
}

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

// ─── Identity page factory ─────────────────────────────────────────

type Identity = "root" | "alice" | "bob" | "charlie_admin";

async function newIdentityPage(browser: Browser, identity: Identity): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

function csrfHeaders(identity: Identity) {
  const sessions = getAdminSessions();
  return { "x-csrf-token": sessions[identity].csrf_token };
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  let url = `${BASE}${path}`;
  if (params) {
    const qs = new URLSearchParams(params).toString();
    if (qs) url += `?${qs}`;
  }
  return page.request.get(url);
}

async function apiPost(page: Page, identity: Identity, path: string, body: unknown = {}) {
  return page.request.post(`${BASE}${path}`, {
    headers: csrfHeaders(identity),
    data: body,
  });
}

// ─── Shared state ───────────────────────────────────────────────────

let rootPage: Page;
let alicePage: Page;

test.beforeAll(async ({ browser }) => {
  rootPage = await newIdentityPage(browser, "root");
  alicePage = await newIdentityPage(browser, "alice");

  // Seed a risk score for Alice via admin override
  const overrideResp = await apiPost(rootPage, "root", `/ui/admin/risk/users/${ALICE_ID}/override`, {
    score: 25,
    reason: `E2E test seed ${TS}`,
  });
  expect(overrideResp.ok()).toBe(true);
});

test.afterAll(async () => {
  await rootPage?.close();
  await alicePage?.close();
});

// ─── Section 178: Risk Score Computation API ────────────────────────

test.describe("178 — Risk Score Computation API", () => {

  test("178.1 Admin override creates a score record with all required fields", async () => {
    const resp = await apiPost(rootPage, "root", `/ui/admin/risk/users/${ALICE_ID}/override`, {
      score: 35,
      reason: `E2E override 178.1 ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.score_id).toBeTruthy();
    expect(data.total_score).toBe(35);
    expect(data.risk_tier).toBe("medium");
    expect(data.trigger).toBe("manual");
    expect(data.model_version).toBeTruthy();
    expect(data.created_at).toBeGreaterThan(0);
  });

  test("178.2 Low-risk override produces low tier", async () => {
    const resp = await apiPost(rootPage, "root", `/ui/admin/risk/users/${ALICE_ID}/override`, {
      score: 15,
      reason: `E2E low risk 178.2 ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.total_score).toBe(15);
    expect(data.risk_tier).toBe("low");
  });

  test("178.3 Critical score override produces critical tier", async () => {
    const highUser = `test_high_risk_${TS}@test.local`;
    const resp = await apiPost(rootPage, "root", `/ui/admin/risk/users/${highUser}/override`, {
      score: 90,
      reason: `E2E critical 178.3 ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.total_score).toBe(90);
    expect(data.risk_tier).toBe("critical");
  });

  test("178.4 Override stores previous_score and previous_tier", async () => {
    // Alice already has a score from 178.2 (15, low); override again
    const resp = await apiPost(rootPage, "root", `/ui/admin/risk/users/${ALICE_ID}/override`, {
      score: 45,
      reason: `E2E prev check 178.4 ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.total_score).toBe(45);
    expect(data.risk_tier).toBe("medium");
    // previous_score should be defined (from 178.2 override of 15)
    expect(data.previous_score).toBeDefined();
    expect(typeof data.previous_score).toBe("number");
    expect(data.previous_tier).toBeDefined();
  });

  test("178.5 Score boundary: 30 is low tier", async () => {
    const resp = await apiPost(rootPage, "root", `/ui/admin/risk/users/${ALICE_ID}/override`, {
      score: 30,
      reason: `E2E boundary 178.5 ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.total_score).toBe(30);
    expect(data.risk_tier).toBe("low");
  });

  test("178.6 Score boundary: 31 is medium tier", async () => {
    const resp = await apiPost(rootPage, "root", `/ui/admin/risk/users/${ALICE_ID}/override`, {
      score: 31,
      reason: `E2E boundary 178.6 ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.total_score).toBe(31);
    expect(data.risk_tier).toBe("medium");
  });
});

// ─── Section 179: Admin Risk Endpoints ──────────────────────────────

test.describe("179 — Admin Risk Endpoints", () => {

  test("179.1 Admin can view risk profile for a user", async () => {
    const resp = await apiGet(rootPage, `/ui/admin/risk/users/${ALICE_ID}/profile`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.user_sub).toBe(ALICE_ID);
    expect(data.latest_score).toBeTruthy();
    expect(data.latest_score.total_score).toBeGreaterThanOrEqual(0);
    expect(data.latest_score.total_score).toBeLessThanOrEqual(100);
    expect(data.history).toBeInstanceOf(Array);
    expect(data.history.length).toBeGreaterThan(0);
  });

  test("179.2 Admin can view risk factors for a user", async () => {
    const resp = await apiGet(rootPage, `/ui/admin/risk/users/${ALICE_ID}/factors`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.factors).toBeInstanceOf(Array);
    expect(data.factors.length).toBeGreaterThan(0);
    const first = data.factors[0];
    expect(first.factor_name).toBeTruthy();
    expect(typeof first.score).toBe("number");
    expect(typeof first.weight).toBe("number");
  });

  test("179.3 Alice (non-admin) gets 403 on admin risk profile", async () => {
    const resp = await apiGet(alicePage, `/ui/admin/risk/users/${ALICE_ID}/profile`);
    expect(resp.status()).toBe(403);
  });

  test("179.4 Alice (non-admin) gets 403 on admin distribution", async () => {
    const resp = await apiGet(alicePage, `/ui/admin/risk/distribution`);
    expect(resp.status()).toBe(403);
  });
});

// ─── Section 180: Score History & Override Tracking ──────────────────

test.describe("180 — Score History & Re-scoring", () => {

  test("180.1 Risk score history shows multiple scores for Alice", async () => {
    const resp = await apiGet(rootPage, `/ui/admin/risk/users/${ALICE_ID}/profile`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // Alice has been overridden several times in section 178
    expect(data.history.length).toBeGreaterThanOrEqual(3);
    // History should be newest first (descending by created_at)
    for (let i = 1; i < data.history.length; i++) {
      expect(data.history[i - 1].created_at).toBeGreaterThanOrEqual(data.history[i].created_at);
    }
  });

  test("180.2 Override creates new history entry with trigger=manual", async () => {
    const resp = await apiPost(rootPage, "root", `/ui/admin/risk/users/${ALICE_ID}/override`, {
      score: 55,
      reason: `E2E history 180.2 ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.trigger).toBe("manual");

    // Verify it appears in history
    const histResp = await apiGet(rootPage, `/ui/admin/risk/users/${ALICE_ID}/profile`);
    const hist = await histResp.json();
    expect(hist.history[0].total_score).toBe(55);
    expect(hist.history[0].trigger).toBe("manual");
  });

  test("180.3 Model version is recorded on each score", async () => {
    const resp = await apiGet(rootPage, `/ui/admin/risk/users/${ALICE_ID}/profile`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.latest_score.model_version).toBeTruthy();
    expect(data.latest_score.model_version).toMatch(/^v\d+/);
  });

  test("180.4 Non-admin Alice can view own risk score", async () => {
    const resp = await apiGet(alicePage, "/ui/risk/score");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // Alice has scores from previous tests
    expect(data.score).toBeTruthy();
    expect(data.score.total_score).toBeGreaterThanOrEqual(0);
  });
});

// ─── Section 181: Risk Distribution Dashboard API ───────────────────

test.describe("181 — Risk Distribution Dashboard API", () => {

  test("181.1 Risk distribution returns tier counts", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/risk/distribution");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.distribution).toBeTruthy();
    expect(typeof data.distribution.low).toBe("number");
    expect(typeof data.distribution.medium).toBe("number");
    expect(typeof data.distribution.high).toBe("number");
    expect(typeof data.distribution.critical).toBe("number");
    expect(data.total_scored).toBeGreaterThanOrEqual(0);
    expect(typeof data.auto_approve_rate).toBe("number");
    expect(typeof data.auto_escalate_rate).toBe("number");
  });

  test("181.2 List users by risk tier returns matching users", async () => {
    // Alice's latest score is 55 (medium) from 180.2
    const resp = await apiGet(rootPage, "/ui/admin/risk/tier/medium");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.tier).toBe("medium");
    expect(data.items).toBeInstanceOf(Array);
    expect(data.items.length).toBeGreaterThan(0);
    for (const item of data.items) {
      expect(item.risk_tier).toBe("medium");
    }
  });

  test("181.3 High-risk endpoint returns users above threshold", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/risk/high-risk", { threshold: "70" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeInstanceOf(Array);
    // All returned items should have score >= 70
    for (const item of data.items) {
      expect(item.total_score).toBeGreaterThanOrEqual(70);
    }
  });

  test("181.4 Invalid tier returns 422", async () => {
    const resp = await apiGet(rootPage, "/ui/admin/risk/tier/extreme");
    expect(resp.status()).toBe(422);
    const data = await resp.json();
    expect(data.detail.code).toBe("validation_error");
  });
});
