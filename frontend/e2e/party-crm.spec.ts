/**
 * E2E tests for the SuiteCRM CONTACTS-EXTRA (CCT-001..006) Party-CRM frontend.
 *
 * Sections:
 *   90 — Org account business fields + hierarchy — API (CCT-001/002)
 *   91 — Reports-to / manager chain — API (CCT-003)
 *   92 — Dedup + merge admin — API (CCT-004/005)
 *   93 — vCard import — API (CCT-006)
 *   94 — UI pages render (/crm/org-accounts, /crm/reports-to, /crm/party-dedup, /crm/vcard-import)
 *
 * NOTE: The CCT routers are gated on party_crm_enabled / party_crm_org_accounts_enabled
 * which default OFF → endpoints return 503. These tests tolerate BOTH states: when the
 * flags are off they assert a 503 "not enabled"; when on they assert the success shape.
 *
 * Auth: e2e_admin_session_setup.py (root / alice / bob / charlie_admin).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS        = Date.now();

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
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getAdminSessions()[identity];
  if (!session) throw new Error(`No session for identity: ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    ([userId, accessToken]: [string, string]) => {
      const state = { userId, accessToken, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    [session.user_sub, session.access_token],
  );
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

/** A response is acceptable if it's the success status OR a 503 "feature off". */
function okOrFeatureOff(status: number, ...successStatuses: number[]): boolean {
  return status === 503 || successStatuses.includes(status);
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 90 — Org account business fields + hierarchy (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 90: Org account business fields + hierarchy (API)", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getAdminSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("90.1 PATCH org account responds (503 when flag off, 200/4xx otherwise)", async () => {
    const resp = await apiPatch(alicePage, "alice", `ui/party/orgs/ORG%23nonexistent${TS}`, {
      name: "Acme Inc",
      industry: "Technology",
    });
    // 503 (flag off) / 404 (no such org) / 403 (not org admin) / 200 — never 500
    expect([200, 403, 404, 503]).toContain(resp.status());
  });

  test("90.2 GET org hierarchy responds", async () => {
    const resp = await apiGet(alicePage, `ui/party/orgs/ORG%23nonexistent${TS}/hierarchy`, {
      direction: "both",
    });
    expect([200, 404, 503]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = await resp.json() as { ancestors: unknown[]; children: unknown[] };
      expect(Array.isArray(data.ancestors)).toBe(true);
      expect(Array.isArray(data.children)).toBe(true);
    }
  });

  test("90.3 PUT parent-org responds", async () => {
    const resp = await apiPost(alicePage, "alice", `ui/party/orgs/ORG%23a${TS}/parent`, {
      parent_org_party_id: `ORG#b${TS}`,
    }).catch(() => null);
    // PUT not POST — re-issue as PUT
    const sess = getAdminSessions()["alice"];
    const putResp = await alicePage.request.put(
      `${API}/ui/party/orgs/ORG%23a${TS}/parent`,
      {
        data: { parent_org_party_id: `ORG#b${TS}` },
        headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
      },
    );
    expect([200, 400, 403, 404, 503]).toContain(putResp.status());
    void resp;
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 91 — Reports-to / manager chain (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 91: Reports-to / manager chain (API)", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("91.1 GET reports-to chain responds", async () => {
    const resp = await apiGet(alicePage, `ui/party/parties/p${TS}/reports-to`, {
      direction: "manager_chain",
    });
    expect([200, 404, 503]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = await resp.json() as { direction: string; chain: unknown[] };
      expect(data.direction).toBe("manager_chain");
      expect(Array.isArray(data.chain)).toBe(true);
    }
  });

  test("91.2 PUT manager responds", async () => {
    const sess = getAdminSessions()["alice"];
    const resp = await alicePage.request.put(
      `${API}/ui/party/parties/p${TS}/manager`,
      {
        data: { manager_party_id: `mgr${TS}` },
        headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
      },
    );
    expect([200, 400, 404, 503]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 92 — Dedup + merge admin (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 92: Dedup + merge admin (API)", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test("92.1 list duplicate candidates responds", async () => {
    const resp = await apiGet(rootPage, "ui/admin/party/duplicate-candidates");
    expect([200, 403, 503]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = await resp.json() as { items: unknown[]; cursor: string | null };
      expect(Array.isArray(data.items)).toBe(true);
    }
  });

  test("92.2 merge parties responds", async () => {
    const resp = await apiPost(rootPage, "root", "ui/party/parties/merge", {
      winner_party_id: `w${TS}`,
      loser_party_id: `l${TS}`,
    });
    expect([200, 400, 403, 404, 503]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 93 — vCard import (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 93: vCard import (API)", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("93.1 vCard import responds", async () => {
    const sess = getAdminSessions()["alice"];
    const vcf = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Test User\r\nN:User;Test;;;\r\nEND:VCARD\r\n";
    const resp = await alicePage.request.post(`${API}/ui/party/vcard-import`, {
      headers: { "x-csrf-token": sess.csrf_token },
      multipart: {
        file: {
          name: "test.vcf",
          mimeType: "text/vcard",
          buffer: Buffer.from(vcf, "utf-8"),
        },
      },
    });
    expect([200, 400, 503]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = await resp.json() as unknown[];
      expect(Array.isArray(data)).toBe(true);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 94 — UI pages render
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 94: Party-CRM UI pages render", () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page, "alice");
  });

  test("94.1 Org Accounts page renders", async ({ page }) => {
    await page.goto(`${BASE}/crm/org-accounts`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Org Accounts" })).toBeVisible();
    await expect(page.getByPlaceholder(/ORG#/i)).toBeVisible();
  });

  test("94.2 Reports-To page renders", async ({ page }) => {
    await page.goto(`${BASE}/crm/reports-to`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Reports-To Chain" })).toBeVisible();
  });

  test("94.3 Duplicate Contacts page renders", async ({ page }) => {
    await page.goto(`${BASE}/crm/party-dedup`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Duplicate Contacts" })).toBeVisible();
  });

  test("94.4 vCard Import page renders", async ({ page }) => {
    await page.goto(`${BASE}/crm/vcard-import`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "vCard Import" })).toBeVisible();
    await expect(page.getByLabel(/vCard file/i)).toBeVisible();
  });
});

void ALICE_ID;
