/**
 * E2E tests for the SuiteCRM CASES / PORTAL (CAS) cluster.
 *
 * CAS is purely additive fields on the tickets system (case_number, priority,
 * contact/account links, watchers, case-to-case links). The frontend "Cases"
 * view re-calls the LIVE /tickets endpoints. CAS-specific fields/routes only
 * activate when the backend `crm_cases_enabled` flag is ON; when OFF the
 * dedicated CAS routes return 404 and tickets carry null case fields. These
 * tests are written to be tolerant of either flag state.
 *
 * Sections:
 *   80 — Case CRUD over /tickets — API
 *   81 — Case fields (priority / contact-account, flag-aware) — API
 *   82 — Case watchers + links (flag-aware) — API
 *   83 — Cases UI (list + detail)
 *
 * Auth: uses e2e_admin_session_setup.py (all identities).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();

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

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

// ─── Section 80: Case CRUD over /tickets ────────────────────────────────────

test.describe("80 — Case CRUD (API)", () => {
  let bobPage: Page;
  let rootPage: Page;
  let caseId = "";

  test.beforeAll(async ({ browser }) => {
    bobPage = await newIdentityPage(browser, "bob");
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await bobPage?.close();
    await rootPage?.close();
  });

  test("80.1 create a case with priority", async () => {
    const resp = await apiPost(bobPage, "bob", "tickets", {
      subject: `CAS case ${TS}`,
      description: "Customer cannot log in to the portal.",
      priority: "high",
    });
    expect(resp.status()).toBe(200);
    const json = await resp.json();
    expect(json.ticket).toBeTruthy();
    caseId = json.ticket.ticket_id;
    expect(caseId).toBeTruthy();
    // case_number + priority only populate when crm_cases_enabled is ON.
    expect(json.ticket).toHaveProperty("case_number");
    expect(json.ticket).toHaveProperty("priority");
  });

  test("80.2 get the case by id", async () => {
    const resp = await apiGet(bobPage, `tickets/${caseId}`);
    expect(resp.status()).toBe(200);
    const json = await resp.json();
    expect(json.ticket.ticket_id).toBe(caseId);
    expect(json.ticket.subject).toContain(`CAS case ${TS}`);
  });

  test("80.3 case appears in the queue list", async () => {
    const resp = await apiGet(bobPage, "tickets");
    expect(resp.status()).toBe(200);
    const json = await resp.json();
    expect(Array.isArray(json.items)).toBe(true);
    const found = json.items.find((t: { ticket_id: string }) => t.ticket_id === caseId);
    expect(found).toBeTruthy();
  });

  test("80.4 reject short subject (validation)", async () => {
    const resp = await apiPost(bobPage, "bob", "tickets", { subject: "ab", description: "valid" });
    expect(resp.status()).toBe(422);
  });

  test("80.5 admin can filter the queue by status", async () => {
    const resp = await apiGet(rootPage, "tickets", { status: "open" });
    expect(resp.status()).toBe(200);
    const json = await resp.json();
    expect(Array.isArray(json.items)).toBe(true);
  });
});

// ─── Section 81: Case fields (priority / contact-account, flag-aware) ───────

test.describe("81 — Case fields (API)", () => {
  let bobPage: Page;
  let rootPage: Page;
  let caseId = "";

  test.beforeAll(async ({ browser }) => {
    bobPage = await newIdentityPage(browser, "bob");
    rootPage = await newIdentityPage(browser, "root");
    const resp = await apiPost(bobPage, "bob", "tickets", {
      subject: `CAS fields ${TS}`,
      description: "Field-mutation test case.",
      priority: "low",
    });
    caseId = (await resp.json()).ticket.ticket_id;
  });

  test.afterAll(async () => {
    await bobPage?.close();
    await rootPage?.close();
  });

  test("81.1 PATCH priority (admin) — 200 when enabled, else 404", async () => {
    const resp = await apiPatch(rootPage, "root", `tickets/${caseId}/priority`, {
      priority: "urgent",
    });
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const json = await resp.json();
      expect(json.ticket.priority).toBe("urgent");
    }
  });

  test("81.2 PATCH contact-account (admin) — 200 when enabled, else 404", async () => {
    const resp = await apiPatch(rootPage, "root", `tickets/${caseId}/contact-account`, {
      contact_id: `contact_${TS}`,
      account_id: `account_${TS}`,
    });
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const json = await resp.json();
      expect(json.ticket.contact_id).toBe(`contact_${TS}`);
    }
  });

  test("81.3 non-admin cannot patch priority", async () => {
    const resp = await apiPatch(bobPage, "bob", `tickets/${caseId}/priority`, {
      priority: "medium",
    });
    // 403 when enabled (admin required), 404 when flag is off.
    expect([403, 404]).toContain(resp.status());
  });

  test("81.4 list by-contact (admin) — 200 when enabled, else 404", async () => {
    const resp = await apiGet(rootPage, `tickets/by-contact/contact_${TS}`);
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const json = await resp.json();
      expect(Array.isArray(json.items)).toBe(true);
    }
  });
});

// ─── Section 82: Case watchers + links (flag-aware) ─────────────────────────

test.describe("82 — Case watchers + links (API)", () => {
  let bobPage: Page;
  let rootPage: Page;
  let caseId = "";
  let relatedId = "";

  test.beforeAll(async ({ browser }) => {
    bobPage = await newIdentityPage(browser, "bob");
    rootPage = await newIdentityPage(browser, "root");
    const r1 = await apiPost(bobPage, "bob", "tickets", {
      subject: `CAS watch ${TS}`,
      description: "Watcher / link test case.",
    });
    caseId = (await r1.json()).ticket.ticket_id;
    const r2 = await apiPost(bobPage, "bob", "tickets", {
      subject: `CAS related ${TS}`,
      description: "Related case for linking.",
    });
    relatedId = (await r2.json()).ticket.ticket_id;
  });

  test.afterAll(async () => {
    await bobPage?.close();
    await rootPage?.close();
  });

  test("82.1 add a watcher (admin) — 200 when enabled, else 404", async () => {
    const resp = await apiPost(rootPage, "root", `tickets/${caseId}/watchers`, {
      watcher_sub: BOB_ID,
    });
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const json = await resp.json();
      expect(Array.isArray(json.watchers)).toBe(true);
      expect(json.watchers.some((w: { watcher_sub: string }) => w.watcher_sub === BOB_ID)).toBe(true);
    }
  });

  test("82.2 list watchers — 200 when enabled, else 404", async () => {
    const resp = await apiGet(rootPage, `tickets/${caseId}/watchers`);
    expect([200, 404]).toContain(resp.status());
  });

  test("82.3 create a case-to-case link (admin) — 200 when enabled, else 404", async () => {
    const resp = await apiPost(rootPage, "root", `tickets/${caseId}/links`, {
      related_ticket_id: relatedId,
      link_type: "relates_to",
    });
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const json = await resp.json();
      expect(json.links.some((l: { related_ticket_id: string }) => l.related_ticket_id === relatedId)).toBe(true);
    }
  });

  test("82.4 delete a case link — 200/204 when enabled, else 404", async () => {
    const resp = await apiDelete(rootPage, "root", `tickets/${caseId}/links/${relatedId}`);
    expect([200, 204, 404]).toContain(resp.status());
  });
});

// ─── Section 83: Cases UI ────────────────────────────────────────────────────

test.describe("83 — Cases UI", () => {
  test("83.1 cases list page renders", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "bob");
    await page.goto(`${BASE}/crm/cases`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Cases", exact: true })).toBeVisible({
      timeout: 15_000,
    });
    await expect(page.getByRole("button", { name: /New Case/i })).toBeVisible();
    await page.close();
  });

  test("83.2 open the new-case form", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "bob");
    await page.goto(`${BASE}/crm/cases`, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: /New Case/i }).click();
    await expect(page.getByLabel("Subject")).toBeVisible();
    await expect(page.getByLabel("Description")).toBeVisible();
    await page.close();
  });

  test("83.3 create a case from the UI and land on detail", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "bob");
    await page.goto(`${BASE}/crm/cases`, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: /New Case/i }).click();
    const subject = `UI case ${TS}`;
    await page.getByLabel("Subject").fill(subject);
    await page.getByLabel("Description").fill("Created from the Cases UI e2e test.");
    await page.getByRole("button", { name: /^Open case$/ }).click();
    // The new case should appear in the queue table.
    await expect(page.getByText(subject).first()).toBeVisible({ timeout: 15_000 });
    await page.close();
  });

  test("83.4 detail page renders for an existing case", async ({ browser }) => {
    const bobPage = await newIdentityPage(browser, "bob");
    const resp = await apiPost(bobPage, "bob", "tickets", {
      subject: `UI detail ${TS}`,
      description: "Detail render test.",
    });
    const id = (await resp.json()).ticket.ticket_id;
    await bobPage.close();

    const page = await browser.newPage();
    await injectAuth(page, "bob");
    await page.goto(`${BASE}/crm/cases/${id}`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Conversation")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText("Case fields")).toBeVisible();
    await page.close();
  });
});
