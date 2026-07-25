/**
 * E2E tests for the SuiteCRM Leads (LED) frontend cluster.
 *
 * Sections:
 *   70 — Lead CRUD (create / list / get / update / delete) — API
 *   71 — Lead actions (assign / status transition / convert / score) — API
 *   72 — Activities + score history — API
 *   73 — Prospects CRUD — API
 *   74 — Leads UI (list / create / detail)
 *
 * Auth: uses e2e_admin_session_setup.py (all identities)
 *
 * NOTE: The Leads module is gated behind S.leads_enabled. When the flag is OFF,
 * every endpoint returns 404 and the UI renders a "Leads module not enabled"
 * state. These tests tolerate both states (skip API assertions when disabled,
 * assert the not-enabled UI otherwise).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, resolveIdentityId } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ALICE_ID = resolveIdentityId("e2e_alice@test.local");
const BOB_ID = resolveIdentityId("e2e_bob@test.local");
const ROOT_SUB = "root.admin@testdev.local";
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

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

/** Probe whether the Leads module is enabled (404 when off). */
async function leadsEnabled(page: Page): Promise<boolean> {
  const resp = await apiGet(page, "ui/leads", { limit: "1" });
  return resp.status() !== 404;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 70 — Lead CRUD — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 70: Lead CRUD (API)", () => {
  let alicePage: Page;
  let enabled = false;
  let leadId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    enabled = await leadsEnabled(alicePage);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("create a lead", async () => {
    test.skip(!enabled, "Leads module disabled");
    const resp = await apiPost(alicePage, "alice", "ui/leads", {
      first_name: "Lead",
      last_name: `Test${TS}`,
      email: `lead.${TS}@example.com`,
      company: "Acme Co",
      lead_source: "web_site",
    });
    expect(resp.status()).toBe(201);
    const lead = await resp.json();
    expect(lead.lead_id).toBeTruthy();
    expect(lead.status).toBe("new");
    leadId = lead.lead_id;
  });

  test("list leads includes created lead", async () => {
    test.skip(!enabled || !leadId, "Leads module disabled");
    const resp = await apiGet(alicePage, "ui/leads", { limit: "100" });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(Array.isArray(data.leads)).toBe(true);
    expect(data.leads.some((l: { lead_id: string }) => l.lead_id === leadId)).toBe(true);
  });

  test("get a lead by id", async () => {
    test.skip(!enabled || !leadId, "Leads module disabled");
    const resp = await apiGet(alicePage, `ui/leads/${leadId}`);
    expect(resp.ok()).toBeTruthy();
    const lead = await resp.json();
    expect(lead.email).toBe(`lead.${TS}@example.com`);
  });

  test("update a lead", async () => {
    test.skip(!enabled || !leadId, "Leads module disabled");
    const resp = await apiPatch(alicePage, "alice", `ui/leads/${leadId}`, {
      title: "VP Engineering",
    });
    expect(resp.ok()).toBeTruthy();
    const lead = await resp.json();
    expect(lead.title).toBe("VP Engineering");
  });

  test("delete a lead", async () => {
    test.skip(!enabled || !leadId, "Leads module disabled");
    const resp = await apiDelete(alicePage, "alice", `ui/leads/${leadId}`);
    expect([204, 200]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 71 — Lead actions — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 71: Lead actions (API)", () => {
  let alicePage: Page;
  let enabled = false;
  let leadId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    enabled = await leadsEnabled(alicePage);
    if (enabled) {
      const resp = await apiPost(alicePage, "alice", "ui/leads", {
        first_name: "Action",
        last_name: `Lead${TS}`,
        email: `action.${TS}@example.com`,
      });
      leadId = (await resp.json()).lead_id;
    }
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("assign a lead", async () => {
    test.skip(!enabled || !leadId, "Leads module disabled");
    const resp = await apiPost(alicePage, "alice", `ui/leads/${leadId}/assign`, {
      assignee_sub: BOB_ID,
    });
    expect(resp.ok()).toBeTruthy();
    const lead = await resp.json();
    expect(lead.assigned_to).toBe(BOB_ID);
  });

  test("transition status to in_process (qualify)", async () => {
    test.skip(!enabled || !leadId, "Leads module disabled");
    const resp = await apiPatch(alicePage, "alice", `ui/leads/${leadId}`, {
      status: "in_process",
    });
    expect(resp.ok()).toBeTruthy();
    expect((await resp.json()).status).toBe("in_process");
  });

  test("compute lead score", async () => {
    test.skip(!enabled || !leadId, "Leads module disabled");
    const resp = await apiPost(alicePage, "alice", `ui/leads/${leadId}/score`, {});
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(typeof data.score).toBe("number");
  });

  test("convert a lead", async () => {
    test.skip(!enabled || !leadId, "Leads module disabled");
    const resp = await apiPost(alicePage, "alice", `ui/leads/${leadId}/convert`, {
      create_account: false,
      create_opportunity: true,
      opportunity_name: "Acme Deal",
      opportunity_amount_cents: 500000,
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.status).toBe("converted");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 72 — Activities + score history — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 72: Activities + score history (API)", () => {
  let alicePage: Page;
  let enabled = false;
  let leadId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    enabled = await leadsEnabled(alicePage);
    if (enabled) {
      const resp = await apiPost(alicePage, "alice", "ui/leads", {
        first_name: "Act",
        last_name: `Lead${TS}`,
        email: `act.${TS}@example.com`,
      });
      leadId = (await resp.json()).lead_id;
    }
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("log and list activities", async () => {
    test.skip(!enabled || !leadId, "Leads module disabled");
    const post = await apiPost(alicePage, "alice", `ui/leads/${leadId}/activities`, {
      activity_type: "note",
      subject: "Called the lead",
      description: "Left a voicemail",
    });
    expect(post.status()).toBe(201);

    const list = await apiGet(alicePage, `ui/leads/${leadId}/activities`, { limit: "50" });
    expect(list.ok()).toBeTruthy();
    const data = await list.json();
    expect(Array.isArray(data.activities)).toBe(true);
    expect(data.activities.length).toBeGreaterThan(0);
  });

  test("get score history", async () => {
    test.skip(!enabled || !leadId, "Leads module disabled");
    await apiPost(alicePage, "alice", `ui/leads/${leadId}/score`, {});
    const resp = await apiGet(alicePage, `ui/leads/${leadId}/score-history`, { limit: "20" });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(Array.isArray(data.entries)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 73 — Prospects CRUD — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 73: Prospects CRUD (API)", () => {
  let alicePage: Page;
  let enabled = false;
  let prospectId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    enabled = await leadsEnabled(alicePage);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("create a prospect", async () => {
    test.skip(!enabled, "Leads module disabled");
    const resp = await apiPost(alicePage, "alice", "ui/leads/prospects", {
      email: `prospect.${TS}@example.com`,
      first_name: "Pro",
      last_name: "Spect",
    });
    expect(resp.status()).toBe(201);
    const p = await resp.json();
    expect(p.prospect_id).toBeTruthy();
    prospectId = p.prospect_id;
  });

  test("list prospects", async () => {
    test.skip(!enabled || !prospectId, "Leads module disabled");
    const resp = await apiGet(alicePage, "ui/leads/prospects", { limit: "50" });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(Array.isArray(data.prospects)).toBe(true);
  });

  test("delete a prospect", async () => {
    test.skip(!enabled || !prospectId, "Leads module disabled");
    const resp = await apiDelete(alicePage, "alice", `ui/leads/prospects/${prospectId}`);
    expect([204, 200]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 74 — Leads UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 74: Leads UI", () => {
  let page: Page;
  let enabled = false;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
    enabled = await leadsEnabled(page);
  });

  test.afterAll(async () => {
    await page?.close();
  });

  test("leads list page renders", async () => {
    await page.goto(`${BASE}/crm/leads`, { waitUntil: "domcontentloaded" });
    if (!enabled) {
      await expect(page.getByText("Leads module not enabled")).toBeVisible({ timeout: 10_000 });
      return;
    }
    await expect(page.getByRole("heading", { name: "Leads", exact: true })).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.getByRole("button", { name: /New Lead/i })).toBeVisible();
  });

  test("create lead page renders form", async () => {
    await page.goto(`${BASE}/crm/leads/new`, { waitUntil: "domcontentloaded" });
    if (!enabled) {
      await expect(page.getByText("Leads module not enabled")).toBeVisible({ timeout: 10_000 });
      return;
    }
    await expect(page.getByLabel(/First name/i)).toBeVisible({ timeout: 10_000 });
    await expect(page.getByLabel(/Email/i)).toBeVisible();
  });

  test("create a lead via UI and view detail", async () => {
    test.skip(!enabled, "Leads module disabled");
    await page.goto(`${BASE}/crm/leads/new`, { waitUntil: "domcontentloaded" });
    const uniq = `UI${Date.now()}`;
    await page.getByLabel(/First name/i).fill("Ui");
    await page.getByLabel(/Last name/i).fill(uniq);
    await page.getByLabel(/Email/i).fill(`ui.${Date.now()}@example.com`);
    await page.getByRole("button", { name: /Create Lead/i }).click();
    // Navigates to detail page on success.
    await expect(page.getByRole("heading", { name: new RegExp(uniq) })).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.getByRole("button", { name: /Convert/i })).toBeVisible();
  });
});

test.afterAll(() => {
  void ROOT_SUB;
});
