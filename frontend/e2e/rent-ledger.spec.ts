/**
 * E2E tests for the Rent Ledger (RNT-001..RNT-006)
 *
 * Sections:
 *   70 — Rent periods API
 *   71 — Rent summary API
 *   72 — Record payment API (RNT-002)
 *   73 — Rent ledger history + void API (RNT-003)
 *   74 — Charge-now + owner run API (RNT-005)
 *   75 — RentLedgerPage UI
 *   76 — LeaseRentPage UI
 *   77 — RentAgingPage UI
 *
 * NOTE: All tests are AUTHORED ONLY — do not run in this repo until
 * the RENT_LEDGER_ENABLED flag is set to true.
 *
 * Auth: cookie-session (alice = landlord, bob = tenant)
 * Prerequisites: at least one active lease seeded in DynamoDB for alice.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE    = "http://localhost:3000";
const API     = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const TS      = Date.now();

// ─── Session bootstrap (mirrors tickets.spec.ts) ──────────────────────────────

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
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await page.context().addCookies(getSessions()[identity].cookies);
  return page;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for: ${identity}`);
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
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

// ─── Module-level shared state ────────────────────────────────────────────────

let alicePage: Page | undefined;
let leaseId = "";  // filled in by section 70 or a beforeAll fixture
let paymentSk = "";
let chargeSk = "";

// ─────────────────────────────────────────────────────────────────────────────
// Section 70 — Rent Periods API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 70: Rent Periods API", () => {
  let page: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getSessions();
    page = await newIdentityPage(browser, "alice");
    alicePage = page;
  });

  test("70.1 GET /ui/rent/periods returns periods array", async () => {
    const resp = await apiGet(page, "ui/rent/periods");
    if (resp.status() === 404) {
      // Feature flag off — expected in CI without flag
      test.skip();
      return;
    }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { periods: string[]; count: number };
    expect(Array.isArray(data.periods)).toBe(true);
    expect(data.count).toBeGreaterThan(0);
    expect(data.periods[0]).toMatch(/^\d{4}-\d{2}$/);
  });

  test("70.2 GET /ui/rent/periods with count=3 returns at most 3 periods", async () => {
    const resp = await apiGet(page, "ui/rent/periods", { count: "3" });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { periods: string[]; count: number };
    expect(data.periods.length).toBeLessThanOrEqual(3);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 71 — Rent Summary API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 71: Rent Summary API", () => {
  let page: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await newIdentityPage(browser, "alice");
  });

  test("71.1 GET /ui/rent/summary returns period summary shape", async () => {
    const resp = await apiGet(page, "ui/rent/summary");
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(typeof data.period).toBe("string");
    expect(typeof data.charged_cents).toBe("number");
    expect(typeof data.collected_cents).toBe("number");
    expect(typeof data.outstanding_cents).toBe("number");
    expect(typeof data.overdue_cents).toBe("number");
  });

  test("71.2 GET /ui/rent/summary?period=YYYY-MM accepts valid period", async () => {
    const now = new Date();
    const period = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
    const resp = await apiGet(page, "ui/rent/summary", { period });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { period: string };
    expect(data.period).toBe(period);
  });

  test("71.3 GET /ui/rent/summary?period=invalid returns 422", async () => {
    const resp = await apiGet(page, "ui/rent/summary", { period: "not-a-period" });
    if (resp.status() === 404) { test.skip(); return; }
    // 404 (flag off) or 422 (validation error) both acceptable
    expect([404, 422]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 72 — Record Payment API (RNT-002)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 72: Record Payment API", () => {
  let page: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await newIdentityPage(browser, "alice");
  });

  test("72.1 POST /ui/rent/leases/:id/payments records a payment", async () => {
    if (!leaseId) { test.skip(); return; }
    const now = new Date();
    const period = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
    const resp = await apiPost(page, "alice", `ui/rent/leases/${leaseId}/payments`, {
      amount_cents: 120000,
      method: "bank_transfer",
      period,
      reference: `E2E-${TS}`,
    });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(201);
    const data = await resp.json() as {
      ledger_sk: string;
      amount_cents: number;
      method: string;
      period: string;
    };
    expect(data.amount_cents).toBe(120000);
    expect(data.method).toBe("bank_transfer");
    expect(data.period).toBe(period);
    expect(data.ledger_sk).toBeTruthy();
    paymentSk = data.ledger_sk;
  });

  test("72.2 POST with amount_cents=0 returns 422", async () => {
    if (!leaseId) { test.skip(); return; }
    const resp = await apiPost(page, "alice", `ui/rent/leases/${leaseId}/payments`, {
      amount_cents: 0,
      method: "cash",
    });
    if (resp.status() === 404) { test.skip(); return; }
    expect([400, 422]).toContain(resp.status());
  });

  test("72.3 GET /ui/rent/leases/:id/charges lists charge statuses", async () => {
    if (!leaseId) { test.skip(); return; }
    const resp = await apiGet(page, `ui/rent/leases/${leaseId}/charges`);
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { lease_id: string; charges: unknown[]; as_of_ts: number };
    expect(data.lease_id).toBe(leaseId);
    expect(Array.isArray(data.charges)).toBe(true);
    expect(typeof data.as_of_ts).toBe("number");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 73 — Ledger History + Void (RNT-003)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 73: Ledger History + Void", () => {
  let page: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await newIdentityPage(browser, "alice");
  });

  test("73.1 GET /ui/rent/leases/:id/ledger returns history", async () => {
    if (!leaseId) { test.skip(); return; }
    const resp = await apiGet(page, `ui/rent/leases/${leaseId}/ledger`);
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { rows: unknown[]; count: number; next_cursor: string | null };
    expect(Array.isArray(data.rows)).toBe(true);
    expect(typeof data.count).toBe("number");
  });

  test("73.2 GET /ui/rent/leases/:id/ledger?kind=payment filters to payments", async () => {
    if (!leaseId) { test.skip(); return; }
    const resp = await apiGet(page, `ui/rent/leases/${leaseId}/ledger`, { kind: "payment" });
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { rows: Array<{ rent_kind: string }> };
    for (const row of data.rows) {
      expect(row.rent_kind).toBe("payment");
    }
  });

  test("73.3 POST /ui/rent/leases/:id/ledger/:sk/void voids a payment row", async () => {
    if (!leaseId || !paymentSk) { test.skip(); return; }
    const resp = await apiPost(
      page, "alice",
      `ui/rent/leases/${leaseId}/ledger/${encodeURIComponent(paymentSk)}/void`,
      { reason: "E2E test void" },
    );
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { ok: boolean; ledger_sk: string; state: string };
    expect(data.ok).toBe(true);
    expect(data.state).toBe("reversed");
    expect(data.ledger_sk).toBe(paymentSk);
  });

  test("73.4 Void the same row again returns 409", async () => {
    if (!leaseId || !paymentSk) { test.skip(); return; }
    const resp = await apiPost(
      page, "alice",
      `ui/rent/leases/${leaseId}/ledger/${encodeURIComponent(paymentSk)}/void`,
      { reason: "duplicate" },
    );
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(409);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 74 — Charge-now + Owner Run (RNT-005)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 74: Charge-now + Owner Run", () => {
  let page: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await newIdentityPage(browser, "alice");
  });

  test("74.1 POST /ui/rent/leases/:id/charge posts or skips charge", async () => {
    if (!leaseId) { test.skip(); return; }
    const resp = await apiPost(page, "alice", `ui/rent/leases/${leaseId}/charge`, {});
    if (resp.status() === 404) { test.skip(); return; }
    // 200 (charged or skipped) or 409 (lease not active)
    expect([200, 409]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = await resp.json() as Record<string, unknown>;
      // Either a charge row or a skip sentinel
      const isSkip = data["skipped"] === true;
      const isCharge = typeof data["amount_cents"] === "number";
      expect(isSkip || isCharge).toBe(true);
      if (isCharge) {
        chargeSk = String(data["sk"] ?? "");
      }
    }
  });

  test("74.2 POST /ui/rent/run triggers owner-scoped run", async () => {
    const resp = await apiPost(page, "alice", "ui/rent/run", {});
    if (resp.status() === 404) { test.skip(); return; }
    expect(resp.status()).toBe(200);
    const data = await resp.json() as {
      period: string;
      charged: number;
      skipped: number;
      lease_count: number;
    };
    expect(typeof data.period).toBe("string");
    expect(typeof data.charged).toBe("number");
    expect(typeof data.skipped).toBe("number");
    expect(typeof data.lease_count).toBe("number");
  });

  test("74.3 POST /ui/rent/leases/:id/charge with invalid period returns 400", async () => {
    if (!leaseId) { test.skip(); return; }
    const resp = await apiPost(page, "alice", `ui/rent/leases/${leaseId}/charge`, {
      period: "bad-period",
    });
    if (resp.status() === 404) { test.skip(); return; }
    expect([400, 422]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 75 — RentLedgerPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 75: RentLedgerPage UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
  });

  test("75.1 Page renders at /property/rent", async () => {
    await page.goto(`${BASE}/property/rent`, { waitUntil: "domcontentloaded" });
    // Either the feature is enabled (shows content) or shows "not enabled"
    await expect(page.getByText("Rent Ledger")).toBeVisible({ timeout: 10_000 });
  });

  test("75.2 Period selector visible when feature enabled", async () => {
    await page.goto(`${BASE}/property/rent`, { waitUntil: "domcontentloaded" });
    // If not-enabled state, the select won't be visible — that's acceptable
    const notEnabled = await page.getByText("Rent Ledger is not enabled").isVisible();
    if (!notEnabled) {
      // Summary cards should appear
      await expect(page.getByText("Charged")).toBeVisible({ timeout: 5_000 });
    }
  });

  test("75.3 Aging View link navigates to /property/rent/aging", async () => {
    await page.goto(`${BASE}/property/rent`, { waitUntil: "domcontentloaded" });
    const agingLink = page.getByRole("link", { name: "Aging View" });
    const isVisible = await agingLink.isVisible();
    if (isVisible) {
      await agingLink.click();
      await expect(page).toHaveURL(/\/property\/rent\/aging/);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 76 — LeaseRentPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 76: LeaseRentPage UI", () => {
  let page: Page;
  const TEST_LEASE_ID = leaseId || "test-lease-id";

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
  });

  test("76.1 Page renders at /property/rent/leases/:id", async () => {
    await page.goto(`${BASE}/property/rent/leases/${TEST_LEASE_ID}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(page.getByText("Rent Ledger")).toBeVisible({ timeout: 10_000 });
  });

  test("76.2 Tabs for History and Charges are visible", async () => {
    await page.goto(`${BASE}/property/rent/leases/${TEST_LEASE_ID}`, {
      waitUntil: "domcontentloaded",
    });
    const notEnabled = await page.getByText("Rent Ledger is not enabled").isVisible();
    if (!notEnabled) {
      await expect(page.getByRole("tab", { name: "Full History" })).toBeVisible({ timeout: 5_000 });
      await expect(page.getByRole("tab", { name: "Charges" })).toBeVisible({ timeout: 5_000 });
    }
  });

  test("76.3 Record Payment button opens dialog", async () => {
    await page.goto(`${BASE}/property/rent/leases/${TEST_LEASE_ID}`, {
      waitUntil: "domcontentloaded",
    });
    const notEnabled = await page.getByText("Rent Ledger is not enabled").isVisible();
    if (!notEnabled) {
      await page.getByRole("button", { name: "Record Payment" }).click();
      await expect(page.getByRole("dialog")).toBeVisible({ timeout: 3_000 });
      await expect(page.getByText("Record Rent Payment")).toBeVisible();
    }
  });

  test("76.4 Charge Now button is visible when feature enabled", async () => {
    await page.goto(`${BASE}/property/rent/leases/${TEST_LEASE_ID}`, {
      waitUntil: "domcontentloaded",
    });
    const notEnabled = await page.getByText("Rent Ledger is not enabled").isVisible();
    if (!notEnabled) {
      await expect(page.getByRole("button", { name: "Charge Now" })).toBeVisible({ timeout: 5_000 });
    }
  });

  test("76.5 Back to Rent Ledger link works", async () => {
    await page.goto(`${BASE}/property/rent/leases/${TEST_LEASE_ID}`, {
      waitUntil: "domcontentloaded",
    });
    const backLink = page.getByRole("link", { name: /Back to Rent Ledger/i });
    const isVisible = await backLink.isVisible();
    if (isVisible) {
      await backLink.click();
      await expect(page).toHaveURL(/\/property\/rent$/);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 77 — RentAgingPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 77: RentAgingPage UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
  });

  test("77.1 Page renders at /property/rent/aging", async () => {
    await page.goto(`${BASE}/property/rent/aging`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Rent Aging View")).toBeVisible({ timeout: 10_000 });
  });

  test("77.2 Back link navigates to /property/rent", async () => {
    await page.goto(`${BASE}/property/rent/aging`, { waitUntil: "domcontentloaded" });
    const backLink = page.getByRole("link", { name: /Back to Rent Ledger/i });
    const isVisible = await backLink.isVisible();
    if (isVisible) {
      await backLink.click();
      await expect(page).toHaveURL(/\/property\/rent$/);
    }
  });

  test("77.3 Period selector shown when feature enabled", async () => {
    await page.goto(`${BASE}/property/rent/aging`, { waitUntil: "domcontentloaded" });
    const notEnabled = await page.getByText("Rent Ledger is not enabled").isVisible();
    if (!notEnabled) {
      // Period selector should be present
      await expect(page.getByText("Total Outstanding")).toBeVisible({ timeout: 5_000 });
    }
  });
});
