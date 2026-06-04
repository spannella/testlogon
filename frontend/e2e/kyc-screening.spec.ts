/**
 * E2E tests for KYC-006: Sanctions / PEP Screening.
 *
 * Section 170: Running screening (deterministic mock watchlist) — clear + matches
 * Section 171: Reviewer list-by-status + adjudication (clear/confirm/escalate) + 409
 * Section 172: Re-screening + screening history + access control
 *
 * Auth: cookie + CSRF via e2e_admin_session_setup.py (root, alice, bob,
 * charlie_admin). Owner endpoint uses require_ui_session; run + reviewer
 * endpoints use require_admin_or_root.
 *
 * The deterministic mock watchlist (app/services/kyc_sanctions_screening.py)
 * keys off the screened NAME (injectable on the /run request):
 *   "OFAC Test Person"        -> sanctions_ofac  potential_match (~0.92)
 *   "Sanctioned Person ..."   -> all sanctions   confirmed_match (1.0)
 *   "PEP Official ..."        -> pep_check        potential_match (~0.88)
 *   "Media Flagged ..."       -> adverse_media    potential_match (~0.75)
 *   anything else             -> all              clear
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
const SCREEN_TYPES = [
  "sanctions_ofac",
  "sanctions_eu",
  "sanctions_un",
  "pep_check",
  "adverse_media",
];

async function runScreening(
  page: Page,
  identity: string,
  body: { user_sub: string; case_id?: string; name?: string; dob?: string; country?: string },
) {
  return apiPost(page, identity, "ui/kyc/screening/run", body);
}

// ─── Section 170: Running screening ─────────────────────────────────────────

test.describe("170: KYC screening runs (deterministic mock watchlist)", () => {
  let root: Page;
  test.beforeAll(async ({ browser }) => {
    root = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await root.close();
  });

  test("170.1 Run screening produces one result per screen type", async () => {
    const caseId = `kyc_clr_${TS}`;
    const resp = await runScreening(root, "root", {
      user_sub: getSessions().alice.user_sub,
      case_id: caseId,
      name: "Jane Smith",
      dob: "1991-02-03",
      country: "US",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.case_id).toBe(caseId);
    expect(data.results_count).toBe(5);
    const types = data.results.map((r: { screen_type: string }) => r.screen_type).sort();
    expect(types).toEqual([...SCREEN_TYPES].sort());
  });

  test("170.2 Normal name -> all clear, no matches", async () => {
    const resp = await runScreening(root, "root", {
      user_sub: getSessions().alice.user_sub,
      case_id: `kyc_clr2_${TS}`,
      name: "Jordan Rivers",
    });
    const data = await resp.json();
    expect(data.matches_found).toBe(0);
    for (const r of data.results) {
      expect(r.result).toBe("clear");
      expect(r.match_details.length).toBe(0);
      expect(r.provider).toBe("mock_screening");
      expect(r.screening_id).toMatch(/^scr_[0-9a-f]{12}$/);
    }
  });

  test("170.3 OFAC-pattern name -> sanctions_ofac potential_match", async () => {
    const resp = await runScreening(root, "root", {
      user_sub: getSessions().alice.user_sub,
      case_id: `kyc_ofac_${TS}`,
      name: "OFAC Test Person",
      dob: "1990-01-15",
      country: "US",
    });
    const data = await resp.json();
    const by: Record<string, string> = {};
    for (const r of data.results) by[r.screen_type] = r.result;
    expect(by.sanctions_ofac).toBe("potential_match");
    expect(by.sanctions_eu).toBe("clear");
    const ofac = data.results.find((r: { screen_type: string }) => r.screen_type === "sanctions_ofac");
    expect(ofac.match_details.length).toBeGreaterThan(0);
    expect(ofac.match_details[0].match_score).toBeGreaterThanOrEqual(0.85);
  });

  test("170.4 Sanctioned name -> confirmed_match on all sanctions lists", async () => {
    const resp = await runScreening(root, "root", {
      user_sub: getSessions().alice.user_sub,
      case_id: `kyc_san_${TS}`,
      name: "Sanctioned Person Alpha",
      dob: "1980-06-30",
      country: "RU",
    });
    const data = await resp.json();
    const by: Record<string, string> = {};
    for (const r of data.results) by[r.screen_type] = r.result;
    expect(by.sanctions_ofac).toBe("confirmed_match");
    expect(by.sanctions_eu).toBe("confirmed_match");
    expect(by.sanctions_un).toBe("confirmed_match");
  });

  test("170.5 PEP-pattern + adverse-media-pattern names match the right list", async () => {
    const pep = await (await runScreening(root, "root", {
      user_sub: getSessions().alice.user_sub,
      case_id: `kyc_pep_${TS}`,
      name: "PEP Official Jones",
    })).json();
    expect(
      pep.results.find((r: { screen_type: string }) => r.screen_type === "pep_check").result,
    ).toBe("potential_match");

    const media = await (await runScreening(root, "root", {
      user_sub: getSessions().alice.user_sub,
      case_id: `kyc_media_${TS}`,
      name: "Media Flagged Reporter",
    })).json();
    expect(
      media.results.find((r: { screen_type: string }) => r.screen_type === "adverse_media").result,
    ).toBe("potential_match");
  });

  test("170.6 Non-admin cannot run screening (403)", async ({ browser }) => {
    const alice = await newIdentityPage(browser, "alice");
    const resp = await runScreening(alice, "alice", {
      user_sub: getSessions().alice.user_sub,
      name: "OFAC Test Person",
    });
    expect(resp.status()).toBe(403);
    await alice.close();
  });

  test("170.7 Case owner sees status but match details redacted", async ({ browser }) => {
    const caseId = `kyc_owner_${TS}`;
    await runScreening(root, "root", {
      user_sub: getSessions().alice.user_sub,
      case_id: caseId,
      name: "OFAC Test Person",
      dob: "1990-01-15",
      country: "US",
    });
    const alice = await newIdentityPage(browser, "alice");
    const resp = await apiGet(alice, `ui/kyc/screening/cases/${caseId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const ofac = data.results.find((r: { screen_type: string }) => r.screen_type === "sanctions_ofac");
    expect(ofac.result).toBe("potential_match");
    expect(ofac.match_details.length).toBe(0);
    expect(ofac.reviewed_by ?? null).toBeNull();
    await alice.close();
  });

  test("170.8 Owner cannot view another user's case (403)", async ({ browser }) => {
    const caseId = `kyc_owner2_${TS}`;
    await runScreening(root, "root", {
      user_sub: getSessions().alice.user_sub,
      case_id: caseId,
      name: "Jane Smith",
    });
    const bob = await newIdentityPage(browser, "bob");
    const resp = await apiGet(bob, `ui/kyc/screening/cases/${caseId}`);
    expect(resp.status()).toBe(403);
    await bob.close();
  });
});

// ─── Section 171: Reviewer adjudication ─────────────────────────────────────

test.describe("171: KYC screening review", () => {
  let root: Page;
  let charlie: Page;
  const caseId = `kyc_rev_${TS}`;
  let ofacKey = "";
  let euConfirmedKey = "";
  const confCaseId = `kyc_revconf_${TS}`;

  test.beforeAll(async ({ browser }) => {
    root = await newIdentityPage(browser, "root");
    charlie = await newIdentityPage(browser, "charlie_admin");
    // potential match
    await runScreening(root, "root", {
      user_sub: getSessions().alice.user_sub,
      case_id: caseId,
      name: "OFAC Test Person",
      dob: "1990-01-15",
      country: "US",
    });
    const cr = await (await apiGet(root, `ui/kyc/screening/admin/cases/${caseId}`)).json();
    ofacKey = cr.results.find((r: { screen_type: string }) => r.screen_type === "sanctions_ofac").screen_key;
    // confirmed match (for escalate test)
    await runScreening(root, "root", {
      user_sub: getSessions().alice.user_sub,
      case_id: confCaseId,
      name: "Sanctioned Person Beta",
      dob: "1980-06-30",
      country: "RU",
    });
    const cc = await (await apiGet(root, `ui/kyc/screening/admin/cases/${confCaseId}`)).json();
    euConfirmedKey = cc.results.find((r: { screen_type: string }) => r.screen_type === "sanctions_eu").screen_key;
  });
  test.afterAll(async () => {
    await root.close();
    await charlie.close();
  });

  test("171.1 Admin lists pending reviews and the case appears", async () => {
    const resp = await apiGet(root, "ui/kyc/screening/admin/pending", { result: "potential_match" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.items.find(
      (i: { case_id: string; screen_type: string }) =>
        i.case_id === caseId && i.screen_type === "sanctions_ofac",
    );
    expect(found).toBeTruthy();
  });

  test("171.2 Admin clears a potential match (false positive)", async () => {
    const resp = await apiPost(
      root,
      "root",
      `ui/kyc/screening/admin/cases/${caseId}/${encodeURIComponent(ofacKey)}/review`,
      { decision: "clear", note: "Name similarity only; different DOB and nationality." },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.review_decision).toBe("clear");
    expect(data.reviewed_by).toBe(getSessions().root.user_sub);
    expect(data.reviewed_at).toBeGreaterThan(0);
  });

  test("171.3 Reviewed match no longer appears in pending list", async () => {
    const data = await (await apiGet(root, "ui/kyc/screening/admin/pending", {
      result: "potential_match",
    })).json();
    const found = data.items.find(
      (i: { case_id: string; screen_key: string }) =>
        i.case_id === caseId && i.screen_key === ofacKey,
    );
    expect(found).toBeFalsy();
  });

  test("171.4 Re-reviewing an already-reviewed match returns 409", async () => {
    const resp = await apiPost(
      root,
      "root",
      `ui/kyc/screening/admin/cases/${caseId}/${encodeURIComponent(ofacKey)}/review`,
      { decision: "confirm", note: "Attempting to re-review." },
    );
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail.code).toBe("kyc_screening_already_reviewed");
  });

  test("171.5 Admin can escalate a confirmed match", async () => {
    const resp = await apiPost(
      root,
      "root",
      `ui/kyc/screening/admin/cases/${confCaseId}/${encodeURIComponent(euConfirmedKey)}/review`,
      { decision: "escalate", note: "Confirmed sanctioned entity — escalate to compliance." },
    );
    expect(resp.status()).toBe(200);
    expect((await resp.json()).review_decision).toBe("escalate");
  });

  test("171.6 Review with empty note rejected (422)", async () => {
    const data = await (await apiGet(root, `ui/kyc/screening/admin/cases/${confCaseId}`)).json();
    const unKey = data.results.find((r: { screen_type: string }) => r.screen_type === "sanctions_un").screen_key;
    const resp = await apiPost(
      root,
      "root",
      `ui/kyc/screening/admin/cases/${confCaseId}/${encodeURIComponent(unKey)}/review`,
      { decision: "clear", note: "" },
    );
    expect(resp.status()).toBe(422);
  });

  test("171.7 Charlie (admin) can also adjudicate", async () => {
    const data = await (await apiGet(charlie, `ui/kyc/screening/admin/cases/${confCaseId}`)).json();
    const ofacKey2 = data.results.find((r: { screen_type: string }) => r.screen_type === "sanctions_ofac").screen_key;
    const resp = await apiPost(
      charlie,
      "charlie_admin",
      `ui/kyc/screening/admin/cases/${confCaseId}/${encodeURIComponent(ofacKey2)}/review`,
      { decision: "confirm", note: "Confirmed by admin reviewer." },
    );
    expect(resp.status()).toBe(200);
  });

  test("171.8 Non-admin gets 403 on pending reviews", async ({ browser }) => {
    const alice = await newIdentityPage(browser, "alice");
    const resp = await apiGet(alice, "ui/kyc/screening/admin/pending");
    expect(resp.status()).toBe(403);
    await alice.close();
  });

  test("171.9 Review on a non-existent screen_key returns 404", async () => {
    const resp = await apiPost(
      root,
      "root",
      `ui/kyc/screening/admin/cases/${caseId}/${encodeURIComponent("sanctions_ofac#2000-01-01T00:00:00Z")}/review`,
      { decision: "clear", note: "no such key" },
    );
    expect(resp.status()).toBe(404);
  });
});

// ─── Section 172: Re-screening + history ────────────────────────────────────

test.describe("172: KYC re-screening + history", () => {
  let root: Page;
  const caseId = `kyc_hist_${TS}`;

  test.beforeAll(async ({ browser }) => {
    root = await newIdentityPage(browser, "root");
    await runScreening(root, "root", {
      user_sub: getSessions().bob.user_sub,
      case_id: caseId,
      name: "OFAC Test Person",
      dob: "1990-01-15",
      country: "US",
    });
  });
  test.afterAll(async () => {
    await root.close();
  });

  test("172.1 Re-screen creates new results alongside existing ones", async () => {
    const resp = await apiPost(root, "root", `ui/kyc/screening/admin/cases/${caseId}/rescreen`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.trigger).toBe("manual");
    expect(data.results_count).toBe(5);
    expect(data.matches_found).toBeGreaterThanOrEqual(1);

    const all = await (await apiGet(root, `ui/kyc/screening/admin/cases/${caseId}`)).json();
    expect(all.results.length).toBe(10);
    const keys = new Set(all.results.map((r: { screen_key: string }) => r.screen_key));
    expect(keys.size).toBe(10);
  });

  test("172.2 Re-screen on non-existent case returns 404", async () => {
    const resp = await apiPost(
      root,
      "root",
      `ui/kyc/screening/admin/cases/kyc_does_not_exist_${TS}/rescreen`,
    );
    expect(resp.status()).toBe(404);
  });

  test("172.3 User screening history lists all runs descending", async () => {
    const resp = await apiGet(
      root,
      `ui/kyc/screening/admin/users/${encodeURIComponent(getSessions().bob.user_sub)}/history`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.user_sub).toBe(getSessions().bob.user_sub);
    expect(data.total).toBeGreaterThanOrEqual(10);
    const times = data.results.map((r: { created_at: number }) => r.created_at);
    for (let i = 1; i < times.length; i++) expect(times[i - 1]).toBeGreaterThanOrEqual(times[i]);
  });

  test("172.4 History for an unknown user returns 200 with empty results", async () => {
    const resp = await apiGet(
      root,
      `ui/kyc/screening/admin/users/${encodeURIComponent(`nobody_${TS}@test.local`)}/history`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.total).toBe(0);
    expect(data.results.length).toBe(0);
  });

  test("172.5 Admin GET on a case with no screening returns 404", async () => {
    const resp = await apiGet(root, `ui/kyc/screening/admin/cases/kyc_empty_${TS}`);
    expect(resp.status()).toBe(404);
  });
});
