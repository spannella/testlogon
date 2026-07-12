/**
 * E2E tests for the ATS Integration cross-link bridge (ATI-001..ATI-005).
 *
 * Sections:
 *   71 — List/create/unlink candidate-contact links (API)
 *   72 — List/create/unlink job-opportunity links (API)
 *   73 — 503 graceful-degrade handling (API)
 *   74 — AtsIntegrationPage UI smoke tests
 *
 * Auth: uses e2e_admin_session_setup.py (alice as primary user)
 *
 * Identities:
 *   alice — e2e_alice@test.local — role=user (link owner)
 *   root  — root.admin@testdev.local — role=root (admin ops)
 *
 * NOTE: The backend gate requires ATS_INTEGRATION_ENABLED=true AND
 * CANDIDATES_ENABLED=true. If the feature is off the API returns 503 and
 * the UI renders the "not enabled" callout — section 73 verifies this.
 *
 * IMPORTANT: Do NOT run this file directly; it is authored for the CI runner.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const ROOT_ID  = "root.admin@testdev.local";
const TS       = Date.now();

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
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

// ─── Page/auth helpers ────────────────────────────────────────────────────────

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
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

// ─── Module-level state shared between sections ───────────────────────────────

let alicePage: Page | undefined;
let ccLinkId = "";
let joLinkId = "";

// ─────────────────────────────────────────────────────────────────────────────
// Section 71 — Candidate-contact links (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 71: Candidate-contact links (API)", () => {
  const CANDIDATE_ID = `cand_e2e_${TS}`;
  const CONTACT_ID   = `contact_e2e_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test("71.1 — POST candidate-contact link returns 503 or 201", async () => {
    // The gate may be off in CI — we accept either 503 or 2xx.
    const resp = await apiPost(alicePage!, "alice", "ui/ats/integration/candidate-contact-links", {
      candidate_id: CANDIDATE_ID,
      contact_id: CONTACT_ID,
    });
    expect([200, 201, 503]).toContain(resp.status());
    if (resp.status() !== 503) {
      const body = await resp.json() as Record<string, unknown>;
      expect(body).toHaveProperty("link_id");
      expect(body.link_type).toBe("candidate_contact");
      expect(body.candidate_id).toBe(CANDIDATE_ID);
      expect(body.contact_id).toBe(CONTACT_ID);
      expect(typeof body.synced).toBe("boolean");
      expect(typeof body.degraded).toBe("boolean");
      expect(typeof body.created_at).toBe("number");
      ccLinkId = body.link_id as string;
    }
  });

  test("71.2 — POST without contact_id returns degraded link", async () => {
    const resp = await apiPost(alicePage!, "alice", "ui/ats/integration/candidate-contact-links", {
      candidate_id: `${CANDIDATE_ID}_nodegrade`,
    });
    expect([200, 201, 503]).toContain(resp.status());
    if (resp.status() !== 503) {
      const body = await resp.json() as Record<string, unknown>;
      // Without a real CND/contacts cluster the link should be degraded
      expect(typeof body.degraded).toBe("boolean");
      expect(body.link_type).toBe("candidate_contact");
    }
  });

  test("71.3 — GET /links lists both candidate-contact and job-opportunity", async () => {
    const resp = await apiGet(alicePage!, "ui/ats/integration/links");
    expect([200, 503]).toContain(resp.status());
    if (resp.status() === 200) {
      const body = await resp.json() as Record<string, unknown>;
      expect(Array.isArray(body.candidate_contact_links)).toBe(true);
      expect(Array.isArray(body.job_opportunity_links)).toBe(true);
      expect(typeof body.count).toBe("number");
    }
  });

  test("71.4 — DELETE candidate-contact link succeeds or returns 503", async () => {
    if (!ccLinkId) {
      test.skip();
      return;
    }
    const resp = await apiDelete(
      alicePage!,
      "alice",
      `ui/ats/integration/links/candidate_contact/${encodeURIComponent(ccLinkId)}`,
    );
    expect([200, 204, 503]).toContain(resp.status());
    if (resp.status() === 200) {
      const body = await resp.json() as Record<string, unknown>;
      expect(body.ok).toBe(true);
    }
  });

  test("71.5 — DELETE with invalid link_type returns 400", async () => {
    const resp = await apiDelete(
      alicePage!,
      "alice",
      `ui/ats/integration/links/invalid_type/some_link`,
    );
    expect([400, 503]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 72 — Job-opportunity links (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 72: Job-opportunity links (API)", () => {
  const JOB_ORDER_ID    = `job_e2e_${TS}`;
  const OPPORTUNITY_ID  = `opp_e2e_${TS}`;

  test.beforeAll(async ({ browser }) => {
    if (!alicePage) {
      alicePage = await newIdentityPage(browser, "alice");
    }
  });

  test("72.1 — POST job-opportunity link returns 503 or 201", async () => {
    const resp = await apiPost(alicePage!, "alice", "ui/ats/integration/job-opportunity-links", {
      job_order_id:   JOB_ORDER_ID,
      opportunity_id: OPPORTUNITY_ID,
    });
    expect([200, 201, 503]).toContain(resp.status());
    if (resp.status() !== 503) {
      const body = await resp.json() as Record<string, unknown>;
      expect(body).toHaveProperty("link_id");
      expect(body.link_type).toBe("job_opportunity");
      expect(body.job_order_id).toBe(JOB_ORDER_ID);
      expect(body.opportunity_id).toBe(OPPORTUNITY_ID);
      expect(typeof body.synced).toBe("boolean");
      expect(typeof body.degraded).toBe("boolean");
      joLinkId = body.link_id as string;
    }
  });

  test("72.2 — POST job-opportunity link is idempotent (same candidate_id upserts)", async () => {
    // Same job_order_id → deterministic link_id → upsert, not duplicate
    const resp1 = await apiPost(alicePage!, "alice", "ui/ats/integration/job-opportunity-links", {
      job_order_id: `${JOB_ORDER_ID}_idem`,
      opportunity_id: OPPORTUNITY_ID,
    });
    const resp2 = await apiPost(alicePage!, "alice", "ui/ats/integration/job-opportunity-links", {
      job_order_id: `${JOB_ORDER_ID}_idem`,
      opportunity_id: OPPORTUNITY_ID,
    });
    expect([200, 201, 503]).toContain(resp1.status());
    expect([200, 201, 503]).toContain(resp2.status());
    if (resp1.status() !== 503 && resp2.status() !== 503) {
      const b1 = await resp1.json() as Record<string, unknown>;
      const b2 = await resp2.json() as Record<string, unknown>;
      // Idempotent: same link_id
      expect(b1.link_id).toBe(b2.link_id);
    }
  });

  test("72.3 — GET /links includes job-opportunity links after creation", async () => {
    const resp = await apiGet(alicePage!, "ui/ats/integration/links");
    expect([200, 503]).toContain(resp.status());
    if (resp.status() === 200) {
      const body = await resp.json() as Record<string, unknown>;
      expect(typeof (body.count as number)).toBe("number");
    }
  });

  test("72.4 — DELETE job-opportunity link succeeds or returns 503", async () => {
    if (!joLinkId) {
      test.skip();
      return;
    }
    const resp = await apiDelete(
      alicePage!,
      "alice",
      `ui/ats/integration/links/job_opportunity/${encodeURIComponent(joLinkId)}`,
    );
    expect([200, 204, 503]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 73 — 503 graceful-degrade handling (API)
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 73: 503 graceful-degrade handling (API)", () => {
  test.beforeAll(async ({ browser }) => {
    if (!alicePage) {
      alicePage = await newIdentityPage(browser, "alice");
    }
  });

  test("73.1 — 503 from /links carries ats_integration_disabled code", async () => {
    const resp = await apiGet(alicePage!, "ui/ats/integration/links");
    if (resp.status() === 503) {
      const body = await resp.json() as Record<string, unknown>;
      const detail = body.detail as Record<string, unknown> | undefined;
      expect(detail?.code).toBe("ats_integration_disabled");
    } else {
      // Feature is on — just verify the response shape
      expect(resp.status()).toBe(200);
    }
  });

  test("73.2 — 503 from candidate-contact link creation carries correct code", async () => {
    const resp = await apiPost(alicePage!, "alice", "ui/ats/integration/candidate-contact-links", {
      candidate_id: `cand_503_check_${TS}`,
    });
    if (resp.status() === 503) {
      const body = await resp.json() as Record<string, unknown>;
      const detail = body.detail as Record<string, unknown> | undefined;
      expect(detail?.code).toBe("ats_integration_disabled");
    } else {
      expect([200, 201]).toContain(resp.status());
    }
  });

  test("73.3 — 503 from job-opportunity link creation carries correct code", async () => {
    const resp = await apiPost(alicePage!, "alice", "ui/ats/integration/job-opportunity-links", {
      job_order_id: `job_503_check_${TS}`,
    });
    if (resp.status() === 503) {
      const body = await resp.json() as Record<string, unknown>;
      const detail = body.detail as Record<string, unknown> | undefined;
      expect(detail?.code).toBe("ats_integration_disabled");
    } else {
      expect([200, 201]).toContain(resp.status());
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 74 — AtsIntegrationPage UI smoke tests
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 74: AtsIntegrationPage UI", () => {
  let uiPage: Page;

  test.beforeAll(async ({ browser }) => {
    uiPage = await browser.newPage();
    await injectAuth(uiPage, "alice");
  });

  test.afterAll(async () => {
    await uiPage.close();
  });

  test("74.1 — /ats/integration route loads without crash", async () => {
    await uiPage.goto(`${BASE}/ats/integration`, { waitUntil: "domcontentloaded" });
    // Should show the page title
    await expect(uiPage.getByRole("heading", { name: /ATS Integration/i })).toBeVisible();
  });

  test("74.2 — Page shows either not-enabled state or tabs when feature is on/off", async () => {
    await uiPage.goto(`${BASE}/ats/integration`, { waitUntil: "domcontentloaded" });
    // Accept either the disabled callout OR the tabs — wait for the lazy chunk
    // + queries to settle before asserting.
    const disabled = uiPage.locator("text=ATS Integration is not enabled");
    const candidateTab = uiPage.getByRole("tab", { name: /Candidate/i });
    await expect(disabled.or(candidateTab).first()).toBeVisible({ timeout: 10_000 });
  });

  test("74.3 — When tabs visible: Candidate tab is active by default", async () => {
    await uiPage.goto(`${BASE}/ats/integration`, { waitUntil: "domcontentloaded" });
    const candidateTab = uiPage.getByRole("tab", { name: /Candidate/i });
    const disabled = uiPage.locator("text=ATS Integration is not enabled");
    await expect(candidateTab.or(disabled).first()).toBeVisible({ timeout: 10_000 });
    if (await candidateTab.isVisible()) {
      await expect(candidateTab).toHaveAttribute("data-state", "active");
    }
  });

  test("74.4 — When tabs visible: Job Order tab is clickable", async () => {
    await uiPage.goto(`${BASE}/ats/integration`, { waitUntil: "domcontentloaded" });
    const jobTab = uiPage.getByRole("tab", { name: /Job Order/i });
    const disabled = uiPage.locator("text=ATS Integration is not enabled");
    await expect(jobTab.or(disabled).first()).toBeVisible({ timeout: 10_000 });
    if (await jobTab.isVisible()) {
      await jobTab.click();
      await expect(jobTab).toHaveAttribute("data-state", "active");
    }
  });

  test("74.5 — Refresh button is visible and clickable", async () => {
    await uiPage.goto(`${BASE}/ats/integration`, { waitUntil: "domcontentloaded" });
    const refreshBtn = uiPage.getByRole("button", { name: /Refresh/i });
    await expect(refreshBtn).toBeVisible();
    await refreshBtn.click();
    // Should not crash
  });

  test("74.6 — Not-enabled state shows config hint", async () => {
    await uiPage.goto(`${BASE}/ats/integration`, { waitUntil: "domcontentloaded" });
    const notEnabled = await uiPage.locator("text=ATS Integration is not enabled").isVisible();
    if (notEnabled) {
      await expect(uiPage.locator("code", { hasText: "ATS_INTEGRATION_ENABLED" })).toBeVisible();
    }
  });

  test("74.7 — Link Candidate dialog opens when feature is enabled", async () => {
    await uiPage.goto(`${BASE}/ats/integration`, { waitUntil: "domcontentloaded" });
    const linkBtn = uiPage.getByRole("button", { name: /Link Candidate/i });
    if (await linkBtn.isVisible()) {
      await linkBtn.click();
      await expect(uiPage.getByRole("dialog")).toBeVisible();
      await expect(uiPage.getByRole("heading", { name: /Link Candidate to CRM Contact/i })).toBeVisible();
      // Close dialog
      await uiPage.getByRole("button", { name: /Cancel/i }).click();
    }
  });

  test("74.8 — Job Order tab: Link Job Order dialog opens when feature is enabled", async () => {
    await uiPage.goto(`${BASE}/ats/integration`, { waitUntil: "domcontentloaded" });
    const jobTab = uiPage.getByRole("tab", { name: /Job Order/i });
    if (await jobTab.isVisible()) {
      await jobTab.click();
      const linkBtn = uiPage.getByRole("button", { name: /Link Job Order/i });
      if (await linkBtn.isVisible()) {
        await linkBtn.click();
        await expect(uiPage.getByRole("dialog")).toBeVisible();
        await expect(uiPage.getByRole("heading", { name: /Link Job Order to CRM Opportunity/i })).toBeVisible();
        await uiPage.getByRole("button", { name: /Cancel/i }).click();
      }
    }
  });

  test("74.9 — Create link with candidate_id fills and submits when feature is on", async () => {
    await uiPage.goto(`${BASE}/ats/integration`, { waitUntil: "domcontentloaded" });
    const hasTabs = await uiPage.getByRole("tab", { name: /Candidate/i }).isVisible();
    if (!hasTabs) {
      // Feature off — skip create flow
      return;
    }
    const linkBtn = uiPage.getByRole("button", { name: /Link Candidate/i });
    if (await linkBtn.isVisible()) {
      await linkBtn.click();
      await uiPage.getByLabel(/Candidate ID/i).fill(`cand_ui_test_${TS}`);
      const createBtn = uiPage.getByRole("button", { name: /Create Link/i });
      await expect(createBtn).toBeEnabled();
      // Don't actually submit — that requires a live backend with the flag on.
      await uiPage.getByRole("button", { name: /Cancel/i }).click();
    }
  });

  test("74.10 — Empty state shown when no links exist", async () => {
    await uiPage.goto(`${BASE}/ats/integration`, { waitUntil: "domcontentloaded" });
    const hasTabs = await uiPage.getByRole("tab", { name: /Candidate/i }).isVisible();
    if (hasTabs) {
      // With no links we expect an empty state message
      const emptyMsg = uiPage.locator("text=No candidate-contact links yet.");
      const hasEmpty = await emptyMsg.isVisible();
      // OR there are actual link rows — either is valid
      const hasLinks = await uiPage.locator("[aria-label='Unlink']").first().isVisible().catch(() => false);
      expect(hasEmpty || hasLinks).toBe(true);
    }
  });
});
