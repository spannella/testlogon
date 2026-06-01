/**
 * E2E tests for FIN-018 Billing Configuration UI.
 *
 *   Section 543: Config Read API
 *   Section 544: Config Update API
 *   Section 545: Audit Log API
 *   Section 546: Impact Preview API
 *   Section 547: Billing Config UI
 *   Section 548: Validation Edge Cases
 *
 * Auth: cookie sessions seeded by e2e_admin_session_setup.py.
 *   root          – role=root  (can read + write)
 *   charlie_admin – role=admin (can read + preview, cannot write -> 403)
 *   alice         – role=user  (cannot read -> 403)
 *
 * Endpoints live under /ui/admin/billing-config. Non-GET cookie requests send
 * the x-csrf-token header.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";
const ROOT_SUB = "root.admin@testdev.local";
const BASE = "ui/admin/billing-config";

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

let _sessions: Record<string, AdminSessionData> | null = null;
function getSessions(): Record<string, AdminSessionData> {
  if (!_sessions) {
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

// ─── 543. Config Read API ───────────────────────────────────────────────────

test.describe("543. Billing config read API", () => {
  let rootPage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("admin retrieves billing config", async () => {
    const r = await apiGet(rootPage, BASE);
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body).toHaveProperty("fee_tips_bps");
    expect(body).toHaveProperty("min_payout_cents");
    expect(body).toHaveProperty("default_currency");
  });

  test("config has all expected field groups", async () => {
    const r = await apiGet(rootPage, BASE);
    const body = await r.json();
    for (const f of [
      "fee_tips_bps",
      "fee_unlocks_bps",
      "fee_subscriptions_bps",
      "fee_catalog_bps",
      "fee_ad_revenue_bps",
      "min_payout_cents",
      "payout_fee_cents",
      "payout_schedule",
      "auto_payout_enabled",
      "min_deposit_cents",
      "max_deposit_cents",
      "deposit_fee_bps",
      "default_currency",
      "supported_currencies",
      "tax_enabled",
      "default_tax_rate_bps",
    ]) {
      expect(body).toHaveProperty(f);
    }
  });

  test("config returns sensible defaults", async () => {
    const r = await apiGet(rootPage, BASE);
    const body = await r.json();
    expect(typeof body.fee_tips_bps).toBe("number");
    expect(body.fee_tips_bps).toBeGreaterThanOrEqual(0);
    expect(body.fee_tips_bps).toBeLessThanOrEqual(5000);
  });

  test("non-admin cannot read config (403)", async () => {
    const r = await apiGet(alicePage, BASE);
    expect(r.status()).toBe(403);
  });
});

// ─── 544. Config Update API ──────────────────────────────────────────────────

test.describe("544. Billing config update API", () => {
  let rootPage: Page;
  let charliePage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    charliePage = await newIdentityPage(browser, "charlie_admin");
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await charliePage?.close();
  });

  test("root updates fee configuration", async () => {
    const r = await apiPatch(rootPage, "root", BASE, { fee_tips_bps: 1500 });
    expect(r.status()).toBe(200);
    const after = await (await apiGet(rootPage, BASE)).json();
    expect(after.fee_tips_bps).toBe(1500);
  });

  test("root updates payout threshold", async () => {
    const r = await apiPatch(rootPage, "root", BASE, { min_payout_cents: 2500 });
    expect(r.status()).toBe(200);
    const after = await (await apiGet(rootPage, BASE)).json();
    expect(after.min_payout_cents).toBe(2500);
  });

  test("root updates multiple fields atomically", async () => {
    const r = await apiPatch(rootPage, "root", BASE, {
      fee_tips_bps: 1800,
      min_deposit_cents: 1000,
      tax_enabled: true,
    });
    expect(r.status()).toBe(200);
    const after = await (await apiGet(rootPage, BASE)).json();
    expect(after.fee_tips_bps).toBe(1800);
    expect(after.min_deposit_cents).toBe(1000);
    expect(after.tax_enabled).toBe(true);
  });

  test("non-root cannot update config (403)", async () => {
    const r = await apiPatch(charliePage, "charlie_admin", BASE, { fee_tips_bps: 1000 });
    expect(r.status()).toBe(403);
  });

  test("negative fee value returns 422", async () => {
    const r = await apiPatch(rootPage, "root", BASE, { fee_tips_bps: -100 });
    expect(r.status()).toBe(422);
  });
});

// ─── 545. Audit Log API ───────────────────────────────────────────────────────

test.describe("545. Billing config audit log API", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    // Generate a couple of distinct changes so the audit log has entries.
    await apiPatch(rootPage, "root", BASE, { fee_unlocks_bps: 2100 });
    await apiPatch(rootPage, "root", BASE, { fee_unlocks_bps: 2200 });
  });

  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("audit log records config changes", async () => {
    const r = await apiGet(rootPage, `${BASE}/audit`);
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(Array.isArray(body.entries)).toBe(true);
    expect(body.entries.length).toBeGreaterThanOrEqual(1);
    expect(body.entries.some((e: any) => e.admin_sub === ROOT_SUB)).toBe(true);
  });

  test("audit entry shows old and new values", async () => {
    const body = await (await apiGet(rootPage, `${BASE}/audit`)).json();
    const entry = body.entries[0];
    expect(entry.changes.length).toBeGreaterThanOrEqual(1);
    expect(entry.changes[0]).toHaveProperty("field");
    expect(entry.changes[0]).toHaveProperty("old_value");
    expect(entry.changes[0]).toHaveProperty("new_value");
  });

  test("multiple changes logged separately", async () => {
    const body = await (await apiGet(rootPage, `${BASE}/audit`)).json();
    expect(body.entries.length).toBeGreaterThanOrEqual(2);
  });

  test("audit log sorted newest first", async () => {
    const body = await (await apiGet(rootPage, `${BASE}/audit`)).json();
    if (body.entries.length >= 2) {
      expect(body.entries[0].created_at).toBeGreaterThanOrEqual(body.entries[1].created_at);
    }
  });
});

// ─── 546. Impact Preview API ─────────────────────────────────────────────────

test.describe("546. Billing config impact preview API", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("preview shows affected transaction types", async () => {
    const cur = await (await apiGet(rootPage, BASE)).json();
    const r = await apiPost(rootPage, "root", `${BASE}/preview`, {
      fee_tips_bps: cur.fee_tips_bps + 500,
    });
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.affected_tx_types).toContain("tip_debit");
  });

  test("preview shows projected daily delta", async () => {
    const r = await apiPost(rootPage, "root", `${BASE}/preview`, { fee_tips_bps: 2500 });
    const body = await r.json();
    expect(typeof body.projected_daily_delta_cents).toBe("number");
  });

  test("preview shows before/after sample", async () => {
    const r = await apiPost(rootPage, "root", `${BASE}/preview`, { fee_tips_bps: 2500 });
    const body = await r.json();
    for (const k of ["amount_cents", "fee_cents", "net_cents"]) {
      expect(body.sample_before).toHaveProperty(k);
      expect(body.sample_after).toHaveProperty(k);
    }
  });

  test("preview with no fee changes returns empty affected types", async () => {
    const cur = await (await apiGet(rootPage, BASE)).json();
    const r = await apiPost(rootPage, "root", `${BASE}/preview`, {
      fee_tips_bps: cur.fee_tips_bps,
    });
    const body = await r.json();
    expect(body.affected_tx_types).toEqual([]);
  });
});

// ─── 547. Billing Config UI ──────────────────────────────────────────────────

test.describe("547. Billing config UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("config page loads with fee cards", async () => {
    await rootPage.goto("/admin/billing-config");
    await expect(rootPage.getByText("Platform Fees")).toBeVisible();
    await expect(rootPage.getByText("Billing Configuration")).toBeVisible();
  });

  test("audit log section shows change history", async () => {
    await rootPage.goto("/admin/billing-config");
    await expect(rootPage.getByText("Change History")).toBeVisible();
  });

  test("preview impact button opens dialog", async () => {
    await rootPage.goto("/admin/billing-config");
    await rootPage.getByRole("button", { name: "Preview Impact" }).click();
    await expect(rootPage.getByText("Impact Preview")).toBeVisible();
  });
});

// ─── 548. Validation edge cases ──────────────────────────────────────────────

test.describe("548. Billing config validation edge cases", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("fee above 50% returns 422", async () => {
    const r = await apiPatch(rootPage, "root", BASE, { fee_tips_bps: 6000 });
    expect(r.status()).toBe(422);
  });

  test("unknown config key returns 422", async () => {
    const r = await apiPatch(rootPage, "root", BASE, { totally_unknown_key: 5 });
    expect(r.status()).toBe(422);
  });

  test("invalid payout schedule returns 422", async () => {
    const r = await apiPatch(rootPage, "root", BASE, { payout_schedule: "hourly" });
    expect(r.status()).toBe(422);
  });

  test("no-op update does not create a new audit entry", async () => {
    const cur = await (await apiGet(rootPage, BASE)).json();
    const before = await (await apiGet(rootPage, `${BASE}/audit`)).json();
    const r = await apiPatch(rootPage, "root", BASE, { fee_tips_bps: cur.fee_tips_bps });
    expect(r.status()).toBe(200);
    const after = await (await apiGet(rootPage, `${BASE}/audit`)).json();
    expect(after.count).toBe(before.count);
  });
});
