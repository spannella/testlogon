/**
 * E2E tests for the ATS — Job Orders feature (JOB-001..JOB-008).
 *
 * Sections:
 *   70 — Feature flag probe                          — API
 *   71 — Job Order CRUD (create / get / update)     — API
 *   72 — Status transitions (legal + illegal)        — API
 *   73 — List views (open / hot / mine)              — API
 *   74 — Openings summary                            — API
 *   75 — Soft-delete                                 — API
 *   76 — JobOrdersPage UI (list page)
 *   77 — JobOrderDetailPage UI (detail + edit)
 *
 * Prerequisites:
 *   - Backend running with ATS_ENABLED=1 JOB_ORDERS_ENABLED=1
 *   - e2e_admin_session_setup.py creates sessions for alice, root
 *
 * Auth: cookie-auth session for alice (normal user) for most tests.
 * Root used where admin access is needed.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API  = "http://localhost:8000";
const TS   = Date.now();

// Test data (unique per run to avoid DDB accumulation collisions)
const TEST_COMPANY   = `e2e-company-${TS}`;
const TEST_TITLE     = `E2E Job ${TS}`;
const TEST_TITLE_HOT = `E2E Hot Job ${TS}`;

// ─── Session bootstrap ────────────────────────────────────────────────────────

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
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
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

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body?: unknown,
) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  const url = params
    ? `${API}/${path}?${new URLSearchParams(params).toString()}`
    : `${API}/${path}`;
  return page.request.get(url);
}

async function apiPatch(
  page: Page,
  identity: string,
  path: string,
  body?: unknown,
) {
  const sess = getAdminSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
  });
}

// ─── Helper: create a job order via API ──────────────────────────────────────

async function createJobViaApi(
  page: Page,
  identity: string,
  overrides?: Partial<{
    title: string;
    type: string;
    status: string;
    openings: number;
    client_company_id: string;
    hot: boolean;
    pay_rate_cents: number;
    description: string;
  }>,
): Promise<{ job_id: string; title: string; status: string; [key: string]: unknown }> {
  const body = {
    title: TEST_TITLE,
    type: "hire",
    status: "active",
    openings: 3,
    client_company_id: TEST_COMPANY,
    recruiter_subs: [],
    hot: false,
    public: false,
    ...overrides,
  };
  const res = await apiPost(page, identity, "ui/ats/job-orders/", body);
  expect(res.status()).toBe(201);
  return res.json() as Promise<{ job_id: string; title: string; status: string }>;
}

// ─── Section 70: Feature flag probe ──────────────────────────────────────────

test.describe("Section 70 — Feature flag probe", () => {
  let alicePage: Page;
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => alicePage.close());

  test("70.1 GET /feature-status returns enabled flags", async () => {
    const res = await apiGet(alicePage, "ui/ats/job-orders/feature-status");
    expect(res.status()).toBe(200);
    const body = await res.json() as { ats_enabled: boolean; job_orders_enabled: boolean };
    // If flags off, tests below will fail with 503 — that's the expected gate.
    // This test just asserts the shape.
    expect(typeof body.ats_enabled).toBe("boolean");
    expect(typeof body.job_orders_enabled).toBe("boolean");
  });

  test("70.2 feature-status accessible without auth", async ({ page }) => {
    const res = await page.request.get(`${API}/ui/ats/job-orders/feature-status`);
    expect(res.status()).toBe(200);
  });
});

// ─── Section 71: CRUD ────────────────────────────────────────────────────────

test.describe("Section 71 — Job Order CRUD", () => {
  let alicePage: Page;
  let jobId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => alicePage.close());

  test("71.1 POST creates a job order (201)", async () => {
    const job = await createJobViaApi(alicePage, "alice", {
      title: `${TEST_TITLE} 71.1`,
      pay_rate_cents: 7500,
    });
    expect(job.job_id).toMatch(/^job_/);
    expect(job.title).toBe(`${TEST_TITLE} 71.1`);
    expect(job.status).toBe("active");
    expect(job.placed_count).toBe(0);
    expect(job.openings_remaining).toBe(3);
    jobId = job.job_id;
  });

  test("71.2 GET retrieves the created job order", async () => {
    const res = await apiGet(alicePage, `ui/ats/job-orders/${jobId}`);
    expect(res.status()).toBe(200);
    const job = await res.json() as { job_id: string; title: string };
    expect(job.job_id).toBe(jobId);
    expect(job.title).toBe(`${TEST_TITLE} 71.1`);
  });

  test("71.3 GET unknown job_id returns 404", async () => {
    const res = await apiGet(alicePage, "ui/ats/job-orders/job_doesnotexist");
    expect(res.status()).toBe(404);
  });

  test("71.4 PATCH updates title and pay_rate_cents", async () => {
    const newTitle = `${TEST_TITLE} updated`;
    const res = await apiPatch(alicePage, "alice", `ui/ats/job-orders/${jobId}`, {
      title: newTitle,
      pay_rate_cents: 9500,
    });
    expect(res.status()).toBe(200);
    const job = await res.json() as { title: string; pay_rate_cents: number };
    expect(job.title).toBe(newTitle);
    expect(job.pay_rate_cents).toBe(9500);
  });

  test("71.5 PATCH unknown job_id returns 404", async () => {
    const res = await apiPatch(alicePage, "alice", "ui/ats/job-orders/job_nope", {
      title: "x",
    });
    expect(res.status()).toBe(404);
  });

  test("71.6 POST with invalid type returns 422", async () => {
    const res = await apiPost(alicePage, "alice", "ui/ats/job-orders/", {
      title: "Bad type test",
      type: "freelance",
      status: "active",
      openings: 1,
      client_company_id: TEST_COMPANY,
    });
    expect(res.status()).toBe(422);
  });
});

// ─── Section 72: Status transitions ──────────────────────────────────────────

test.describe("Section 72 — Status transitions", () => {
  let alicePage: Page;
  let jobId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    const job = await createJobViaApi(alicePage, "alice", {
      title: `${TEST_TITLE} status-transitions`,
      status: "active",
    });
    jobId = job.job_id;
  });
  test.afterAll(async () => alicePage.close());

  test("72.1 active → on_hold is legal", async () => {
    const res = await apiPost(alicePage, "alice", `ui/ats/job-orders/${jobId}/status`, {
      status: "on_hold",
    });
    expect(res.status()).toBe(200);
    const job = await res.json() as { status: string };
    expect(job.status).toBe("on_hold");
  });

  test("72.2 on_hold → active is legal", async () => {
    const res = await apiPost(alicePage, "alice", `ui/ats/job-orders/${jobId}/status`, {
      status: "active",
    });
    expect(res.status()).toBe(200);
    const job = await res.json() as { status: string };
    expect(job.status).toBe("active");
  });

  test("72.3 active → closed is legal (terminal)", async () => {
    const res = await apiPost(alicePage, "alice", `ui/ats/job-orders/${jobId}/status`, {
      status: "closed",
    });
    expect(res.status()).toBe(200);
    const job = await res.json() as { status: string };
    expect(job.status).toBe("closed");
  });

  test("72.4 closed → full is illegal (409)", async () => {
    const res = await apiPost(alicePage, "alice", `ui/ats/job-orders/${jobId}/status`, {
      status: "full",
    });
    expect(res.status()).toBe(409);
    const body = await res.json() as { detail: { code: string } };
    expect(body.detail.code).toBe("invalid_status_transition");
  });

  test("72.5 same-status is a no-op (200)", async () => {
    const res = await apiPost(alicePage, "alice", `ui/ats/job-orders/${jobId}/status`, {
      status: "closed",
    });
    expect(res.status()).toBe(200);
  });
});

// ─── Section 73: List views ───────────────────────────────────────────────────

test.describe("Section 73 — List views", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    // Create a hot job and a regular job for list assertions
    await createJobViaApi(alicePage, "alice", {
      title: TEST_TITLE_HOT,
      hot: true,
      status: "active",
    });
    await createJobViaApi(alicePage, "alice", {
      title: `${TEST_TITLE} open`,
      hot: false,
      status: "active",
    });
  });
  test.afterAll(async () => alicePage.close());

  test("73.1 GET /open returns items array", async () => {
    const res = await apiGet(alicePage, "ui/ats/job-orders/open", { limit: "10" });
    expect(res.status()).toBe(200);
    const body = await res.json() as { items: unknown[]; next_cursor: string | null };
    expect(Array.isArray(body.items)).toBe(true);
  });

  test("73.2 GET /open with status filter", async () => {
    const res = await apiGet(alicePage, "ui/ats/job-orders/open", {
      status: "active",
      limit: "10",
    });
    expect(res.status()).toBe(200);
    const body = await res.json() as { items: Array<{ status: string }> };
    for (const item of body.items) {
      expect(item.status).toBe("active");
    }
  });

  test("73.3 GET /hot returns hot-flagged items", async () => {
    const res = await apiGet(alicePage, "ui/ats/job-orders/hot", { limit: "50" });
    expect(res.status()).toBe(200);
    const body = await res.json() as { items: Array<{ hot: boolean }> };
    expect(Array.isArray(body.items)).toBe(true);
    // Every returned item should have hot=true
    for (const item of body.items) {
      expect(item.hot).toBe(true);
    }
  });

  test("73.4 GET /mine returns items (may be empty if no assigned jobs)", async () => {
    const res = await apiGet(alicePage, "ui/ats/job-orders/mine", { limit: "10" });
    expect(res.status()).toBe(200);
    const body = await res.json() as { items: unknown[] };
    expect(Array.isArray(body.items)).toBe(true);
  });

  test("73.5 GET /open with terminal status filter returns 400", async () => {
    const res = await apiGet(alicePage, "ui/ats/job-orders/open", {
      status: "closed",
    });
    expect(res.status()).toBe(400);
  });

  test("73.6 cursor pagination - next_cursor field exists in response", async () => {
    const res = await apiGet(alicePage, "ui/ats/job-orders/open", { limit: "1" });
    expect(res.status()).toBe(200);
    const body = await res.json() as { items: unknown[]; next_cursor: unknown };
    expect("next_cursor" in body).toBe(true);
  });
});

// ─── Section 74: Openings summary ────────────────────────────────────────────

test.describe("Section 74 — Openings summary", () => {
  let alicePage: Page;
  let jobId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    const job = await createJobViaApi(alicePage, "alice", {
      title: `${TEST_TITLE} openings`,
      openings: 5,
      status: "active",
    });
    jobId = job.job_id;
  });
  test.afterAll(async () => alicePage.close());

  test("74.1 GET /openings returns correct counts", async () => {
    const res = await apiGet(alicePage, `ui/ats/job-orders/${jobId}/openings`);
    expect(res.status()).toBe(200);
    const body = await res.json() as {
      openings: number;
      placed_count: number;
      openings_remaining: number;
    };
    expect(body.openings).toBe(5);
    expect(body.placed_count).toBe(0);
    expect(body.openings_remaining).toBe(5);
  });

  test("74.2 GET /openings for unknown job_id returns 404", async () => {
    const res = await apiGet(alicePage, "ui/ats/job-orders/job_nope/openings");
    expect(res.status()).toBe(404);
  });
});

// ─── Section 75: Soft-delete ──────────────────────────────────────────────────

test.describe("Section 75 — Soft-delete", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => alicePage.close());

  test("75.1 DELETE returns 204 and subsequent GET returns 404", async () => {
    const job = await createJobViaApi(alicePage, "alice", {
      title: `${TEST_TITLE} delete-me`,
    });
    const jobId = job.job_id;

    const delRes = await apiDelete(alicePage, "alice", `ui/ats/job-orders/${jobId}`);
    expect(delRes.status()).toBe(204);

    const getRes = await apiGet(alicePage, `ui/ats/job-orders/${jobId}`);
    expect(getRes.status()).toBe(404);
  });

  test("75.2 DELETE unknown job_id returns 404", async () => {
    const res = await apiDelete(alicePage, "alice", "ui/ats/job-orders/job_nope");
    expect(res.status()).toBe(404);
  });
});

// ─── Section 76: JobOrdersPage UI ────────────────────────────────────────────

test.describe("Section 76 — JobOrdersPage UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, "alice");
    // Seed a job so the list has content
    await createJobViaApi(alicePage, "alice", {
      title: `${TEST_TITLE} UI list`,
      status: "active",
    });
  });
  test.afterAll(async () => alicePage.close());

  test("76.1 navigates to /ats/jobs and renders page header", async () => {
    await alicePage.goto(`${BASE}/ats/jobs`, { waitUntil: "domcontentloaded" });
    await expect(
      alicePage.getByRole("heading", { name: "Job Orders", exact: true }),
    ).toBeVisible();
  });

  test("76.2 shows 'Open' tab as default", async () => {
    await expect(alicePage.getByTestId("tab-open")).toBeVisible();
    await expect(alicePage.getByTestId("tab-hot")).toBeVisible();
    await expect(alicePage.getByTestId("tab-mine")).toBeVisible();
  });

  test("76.3 New Job Order button is present", async () => {
    await expect(alicePage.getByTestId("create-job-btn")).toBeVisible();
  });

  test("76.4 status filter dropdown is rendered", async () => {
    await expect(alicePage.getByTestId("status-filter")).toBeVisible();
  });

  test("76.5 clicking New Job Order opens the create dialog", async () => {
    await alicePage.getByTestId("create-job-btn").click();
    await expect(
      alicePage.getByRole("dialog"),
    ).toBeVisible();
    // Dismiss
    await alicePage.keyboard.press("Escape");
  });

  test("76.6 create dialog form fields are present", async () => {
    await alicePage.getByTestId("create-job-btn").click();
    await expect(alicePage.getByTestId("jo-title")).toBeVisible();
    await expect(alicePage.getByTestId("jo-company")).toBeVisible();
    await expect(alicePage.getByTestId("jo-openings")).toBeVisible();
    await alicePage.keyboard.press("Escape");
  });

  test("76.7 Hot tab switches to hot list", async () => {
    await alicePage.getByTestId("tab-hot").click();
    await alicePage.waitForTimeout(500);
    // Should not crash — just verify no error and correct panel visible
    await expect(alicePage.getByText("Hot Job Orders")).toBeVisible();
  });

  test("76.8 Mine tab switches to recruiter list", async () => {
    await alicePage.getByTestId("tab-mine").click();
    await alicePage.waitForTimeout(500);
    await expect(alicePage.getByText("My Job Orders")).toBeVisible();
  });

  test("76.9 feature-disabled state shows 'not enabled' message when flags off", async ({
    page,
  }) => {
    // We can't flip server flags here — just verify the component handles
    // a 503 response gracefully by checking the disabled state renders
    // (this test is informational; if ATS is on it won't hit the disabled branch)
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/ats/jobs`, { waitUntil: "domcontentloaded" });
    // With ATS on the page header renders; with flags off the disabled card renders.
    const header = page.getByRole("heading", { name: "Job Orders", exact: true });
    const disabled = page.getByText("Job Orders are not enabled");
    await expect(header.or(disabled).first()).toBeVisible({ timeout: 10_000 });
  });
});

// ─── Section 77: JobOrderDetailPage UI ───────────────────────────────────────

test.describe("Section 77 — JobOrderDetailPage UI", () => {
  let alicePage: Page;
  let jobId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, "alice");
    const job = await createJobViaApi(alicePage, "alice", {
      title: `${TEST_TITLE} detail-page`,
      openings: 4,
      pay_rate_cents: 8000,
      description: "Looking for a great engineer.",
      status: "active",
    });
    jobId = job.job_id;
  });
  test.afterAll(async () => alicePage.close());

  test("77.1 navigates to detail page and shows title", async () => {
    await alicePage.goto(`${BASE}/ats/jobs/${jobId}`, { waitUntil: "domcontentloaded" });
    await expect(
      alicePage.getByRole("heading", { name: `${TEST_TITLE} detail-page`, exact: true }),
    ).toBeVisible();
  });

  test("77.2 shows status badge", async () => {
    await expect(alicePage.getByTestId("job-status-badge")).toBeVisible();
    await expect(alicePage.getByTestId("job-status-badge")).toHaveText(/active/i);
  });

  test("77.3 openings summary cards are present", async () => {
    await expect(alicePage.getByTestId("openings-total")).toBeVisible();
    await expect(alicePage.getByTestId("openings-placed")).toBeVisible();
    await expect(alicePage.getByTestId("openings-remaining")).toBeVisible();
  });

  test("77.4 openings-total shows correct count", async () => {
    const totalText = await alicePage.getByTestId("openings-total").innerText();
    expect(totalText.trim()).toBe("4");
  });

  test("77.5 description is rendered", async () => {
    await expect(alicePage.getByTestId("job-description")).toContainText(
      "Looking for a great engineer.",
    );
  });

  test("77.6 Edit button opens edit dialog", async () => {
    await alicePage.getByTestId("edit-job-btn").click();
    await expect(alicePage.getByRole("dialog")).toBeVisible();
    await expect(alicePage.getByTestId("ejo-title")).toBeVisible();
    await alicePage.keyboard.press("Escape");
  });

  test("77.7 edit dialog pre-populates title", async () => {
    await alicePage.getByTestId("edit-job-btn").click();
    const titleVal = await alicePage.getByTestId("ejo-title").inputValue();
    expect(titleVal).toBe(`${TEST_TITLE} detail-page`);
    await alicePage.keyboard.press("Escape");
  });

  test("77.8 status select is present and shows current status", async () => {
    await expect(alicePage.getByTestId("status-select")).toBeVisible();
  });

  test("77.9 Back button navigates to job orders list", async () => {
    await alicePage.getByRole("link", { name: "Job Orders" }).first().click();
    await expect(alicePage).toHaveURL(/\/ats\/jobs$/);
  });

  test("77.10 unknown job_id shows not found message", async () => {
    await alicePage.goto(`${BASE}/ats/jobs/job_doesnotexist`, {
      waitUntil: "domcontentloaded",
    });
    await expect(
      alicePage.getByText("Job order not found or has been deleted."),
    ).toBeVisible();
  });
});
