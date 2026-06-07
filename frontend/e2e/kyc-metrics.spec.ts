/**
 * E2E regression tests for the Admin KYC Metrics Dashboard.
 *
 * Page under test: frontend/src/pages/admin/KycMetricsDashboard.tsx
 * Route:           /admin/kyc/metrics
 * Gap ticket:      GAP-0245 (KYC-001)
 *
 * Section:
 *   800 — KycMetricsDashboard UI (7 tests)
 *
 * These guard the four components called out by GAP-0245's fix description
 * (FunnelChart, ApprovalRateCard, LatencyCards, StaleQueueAlert) plus the
 * navigation wiring between the queue page and the metrics dashboard. The
 * suite FAILS if the page/route is removed (800.1) or any card is dropped
 * (800.2–800.4), and PASSES against the current implementation.
 *
 * Auth: Root session cookies (from e2e_admin_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";

// ─── Session bootstrap ────────────────────────────────────────────────────────

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
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

async function injectAuth(page: Page, identity: string) {
  const sessions = getAdminSessions();
  const session = sessions[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

// ─── Section 800: KycMetricsDashboard UI ────────────────────────────────────────

test.describe("Section 800 — KycMetricsDashboard UI", () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page, "root");
  });

  test("800.1 /admin/kyc/metrics renders KYC Metrics heading", async ({ page }) => {
    await page.goto(`${BASE}/admin/kyc/metrics`);
    await expect(
      page.getByRole("heading", { name: /kyc metrics/i }),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("800.2 funnel counts section renders", async ({ page }) => {
    await page.goto(`${BASE}/admin/kyc/metrics`);
    await expect(
      page.getByRole("heading", { name: /kyc metrics/i }),
    ).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("Funnel Counts")).toBeVisible({ timeout: 8_000 });
    // At least the approved status row is rendered with its testid.
    await expect(page.getByTestId("funnel-approved")).toBeVisible();
  });

  test("800.3 approval rate card renders a valid figure", async ({ page }) => {
    await page.goto(`${BASE}/admin/kyc/metrics`);
    await expect(page.getByText("Approval Rate")).toBeVisible({ timeout: 10_000 });
    const rateEl = page.getByTestId("approval-rate");
    await expect(rateEl).toBeVisible();
    const text = (await rateEl.textContent())?.trim() ?? "";
    // Either a percentage (e.g. "80.0%") or the no-decisions placeholder "--".
    expect(text).toMatch(/^\d+(\.\d+)?%$|^--$/);
  });

  test("800.4 latency p50/p90/p99 cards render", async ({ page }) => {
    await page.goto(`${BASE}/admin/kyc/metrics`);
    await expect(page.getByTestId("latency-p50")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("latency-p90")).toBeVisible();
    await expect(page.getByTestId("latency-p99")).toBeVisible();
  });

  test("800.5 back to queue button navigates to /admin/kyc", async ({ page }) => {
    await page.goto(`${BASE}/admin/kyc/metrics`);
    await expect(
      page.getByRole("heading", { name: /kyc metrics/i }),
    ).toBeVisible({ timeout: 10_000 });
    await page.getByRole("button", { name: /back to queue/i }).click();
    await expect(page).toHaveURL(/\/admin\/kyc$/);
  });

  test("800.6 Metrics button on queue page navigates here", async ({ page }) => {
    await page.goto(`${BASE}/admin/kyc`);
    const metricsBtn = page.getByRole("button", { name: "Metrics" });
    await expect(metricsBtn).toBeVisible({ timeout: 10_000 });
    await metricsBtn.click();
    await expect(page).toHaveURL(/\/admin\/kyc\/metrics/);
    await expect(
      page.getByRole("heading", { name: /kyc metrics/i }),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("800.7 stale queue alert renders when stale_queue_count > 0", async ({ page }) => {
    // Mock the metrics API so the stale-queue branch is exercised deterministically.
    // The metrics API lives at /v1/kyc/cases/admin/metrics; match any KYC
    // admin metrics endpoint so the stale-queue branch is forced deterministically.
    await page.route("**/kyc/**/metrics**", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          metrics: {
            funnel_counts: {
              draft: 0,
              submitted: 3,
              under_review: 1,
              needs_more_info: 0,
              approved: 0,
              rejected: 0,
              expired: 0,
            },
            review_latency_seconds: { p50: 7200, p90: 86400, p99: 172800 },
            stale_queue_count: 2,
            ticket_sync_counters: {},
            ticket_sync_deadletter_count: 0,
          },
        }),
      }),
    );
    await page.goto(`${BASE}/admin/kyc/metrics`);
    await expect(page.getByTestId("stale-alert")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("stale-alert")).toContainText("2 stale cases");
  });
});
