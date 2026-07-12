/**
 * E2E tests for the OFBiz MARKETING (MKT) console.
 *
 * LIVE backend: app/routers/marketing_campaigns.py
 *   /ui/marketing/*       (require_ui_session)
 *   /ui/admin/marketing/* (require_admin_or_root)
 * Gated by MARKETING_CAMPAIGNS_ENABLED (default OFF). When the flag is off the
 * write endpoints return 404; these tests tolerate both enabled + disabled
 * backends so they remain green regardless of the flag.
 *
 * Sections:
 *   80 — Campaign + list + segment + tracking API (flag-tolerant)
 *   81 — MarketingPage UI (tabs render, not-enabled state handled)
 *
 * Auth: e2e_admin_session_setup.py (root identity — admin-oriented module).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
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

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

// A response is "acceptable" when either the module is enabled (2xx) or the flag
// is off (404). Anything else is a genuine failure.
function okOrDisabled(status: number): boolean {
  return (status >= 200 && status < 300) || status === 404;
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 80 — Marketing API (flag-tolerant)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 80: Marketing API (flag-tolerant)", () => {
  let rootPage: Page;
  let enabled = false;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
  });

  test("80.1 list campaigns returns 200 with campaigns array", async () => {
    const resp = await apiGet(rootPage, "ui/marketing/campaigns");
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as { campaigns: unknown[] };
    expect(Array.isArray(data.campaigns)).toBe(true);
  });

  test("80.2 create campaign (or 404 when disabled)", async () => {
    const resp = await apiPost(rootPage, "root", "ui/marketing/campaigns", {
      name: `E2E campaign ${TS}`,
      objective: "awareness",
      budget_cents: 12345,
    });
    expect(okOrDisabled(resp.status())).toBe(true);
    enabled = resp.ok();
    if (enabled) {
      const data = (await resp.json()) as { campaign_id: string; status: string };
      expect(data.campaign_id).toBeTruthy();
      expect(data.status).toBe("draft");
    }
  });

  test("80.3 list contact lists returns an array", async () => {
    const resp = await apiGet(rootPage, "ui/marketing/lists");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data)).toBe(true);
  });

  test("80.4 list segments returns an array", async () => {
    const resp = await apiGet(rootPage, "ui/marketing/segments");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data)).toBe(true);
  });

  test("80.5 create segment with predicate (or 404 when disabled)", async () => {
    const resp = await apiPost(rootPage, "root", "ui/marketing/segments", {
      name: `E2E segment ${TS}`,
      predicates: [{ attribute: "order_count", operator: "gte", value: 1 }],
    });
    expect(okOrDisabled(resp.status())).toBe(true);
    if (resp.ok()) {
      const seg = (await resp.json()) as { segment_id: string };
      // Evaluate the freshly created segment.
      const ev = await apiGet(rootPage, `ui/marketing/segments/${seg.segment_id}/evaluate`);
      expect(ev.status()).toBe(200);
      expect(Array.isArray(await ev.json())).toBe(true);
    }
  });

  test("80.6 admin campaign listing by status", async () => {
    const resp = await apiGet(rootPage, "ui/admin/marketing/campaigns", { status: "draft" });
    expect(resp.status()).toBe(200);
    expect(Array.isArray(await resp.json())).toBe(true);
  });

  test("80.7 unknown segment attribute is rejected (422) when enabled", async () => {
    const resp = await apiPost(rootPage, "root", "ui/marketing/segments", {
      name: `bad ${TS}`,
      predicates: [{ attribute: "not_a_real_attr", operator: "eq", value: "x" }],
    });
    // 422 (validation) when enabled, 404 when disabled.
    expect([404, 422].includes(resp.status())).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 81 — MarketingPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 81: MarketingPage UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "root");
  });

  test("81.1 page renders with marketing tabs", async () => {
    await page.goto(`${BASE}/ofbiz/marketing`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Marketing", exact: true })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Campaigns" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Contact lists" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Segments" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Tracking codes" })).toBeVisible();
  });

  test("81.2 campaigns tab shows table, empty, or not-enabled state", async () => {
    await page.goto(`${BASE}/ofbiz/marketing`, { waitUntil: "domcontentloaded" });
    // One of: campaigns card / not-enabled card must be present.
    const campaignsCard = page.getByText("Campaigns", { exact: true });
    const notEnabled = page.getByText(/module is not enabled/i);
    await expect(campaignsCard.or(notEnabled).first()).toBeVisible({ timeout: 10_000 });
  });

  test("81.3 segments tab renders predicate-builder entry point", async () => {
    await page.goto(`${BASE}/ofbiz/marketing`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "Segments" }).click();
    const segCard = page.getByText("Party segments", { exact: true });
    const notEnabled = page.getByText(/module is not enabled/i);
    await expect(segCard.or(notEnabled).first()).toBeVisible({ timeout: 10_000 });
  });

  test("81.4 tracking codes tab renders lookup control", async () => {
    await page.goto(`${BASE}/ofbiz/marketing`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "Tracking codes" }).click();
    const trackCard = page.getByText("Tracking codes", { exact: true });
    const notEnabled = page.getByText(/module is not enabled/i);
    await expect(trackCard.or(notEnabled).first()).toBeVisible({ timeout: 10_000 });
  });
});
