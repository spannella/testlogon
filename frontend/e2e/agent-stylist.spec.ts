/**
 * E2E tests for the Stylist / UI Agent (AGENT-016).
 *
 * Section 683: UI Review CRUD API (4 tests)
 * Section 684: Design Scores & Issue Tickets API (4 tests)
 * Section 685: Design Rules API (4 tests)
 * Section 686: Design Overview UI (3 tests)
 *
 * Auth: cookie-based sessions from e2e_admin_session_setup.py.
 *   alice – role=user (platform owner; all endpoints are require_ui_session)
 * POST/PUT/DELETE requests carry an x-csrf-token header.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");


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
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  // Seed the persisted auth store so ProtectedRoute treats the page as
  // authenticated (cookie injection alone leaves isAuthenticated=false → /login
  // redirect, which hides the UI under test).
  const uid = sessions[identity].user_sub;
  await page.addInitScript((userId: string) => {
    const state = { userId, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, uid);
  return page;
}

async function apiPut(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.put(`${API}/${path}`, {
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

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

const TS = Date.now();
const PAGE_URL = `/messages?ts=${TS}`;
const PAGE_URL_RESP = `/feed?ts=${TS}`;

const ISSUES = [
  {
    category: "spacing",
    severity: "warning",
    title: "Inconsistent card padding",
    description: "Card uses p-4 while equivalent card uses p-3",
    suggestion: "Standardize to p-4 across all cards",
    screenshot_index: 0,
  },
  {
    category: "accessibility",
    severity: "error",
    title: "Low contrast text",
    description: "Body text contrast ratio is 3.1:1",
    suggestion: "Use a darker foreground token",
    screenshot_index: 0,
  },
];

// ─── 683: UI Review CRUD API ─────────────────────────────────────────────────

test.describe("683. UI Review CRUD API", () => {
  let alicePage: Page;
  let reviewId = "";

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("683.1 create UI review result", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/stylist/reviews", {
      page_url: PAGE_URL,
      page_name: "Messages",
      review_type: "full_page",
      design_score: 82.5,
      accessibility_score: 88.0,
      screenshots: [{ url: "/mock/s3/desktop.png", viewport: "1280x720", label: "desktop" }],
      issues: ISSUES,
    });
    expect(r.status()).toBe(201);
    const data = (await r.json()) as Record<string, unknown>;
    reviewId = data.review_id as string;
    expect(reviewId).toBeTruthy();
    expect(data.issues_found).toBe(2);
    expect(data.design_score).toBe(82.5);
  });

  test("683.2 create responsive review with 3 viewports", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/stylist/reviews", {
      page_url: PAGE_URL_RESP,
      page_name: "Feed",
      review_type: "responsive",
      design_score: 90,
      screenshots: [
        { url: "/mock/s3/m.png", viewport: "375x812", label: "mobile" },
        { url: "/mock/s3/t.png", viewport: "768x1024", label: "tablet" },
        { url: "/mock/s3/d.png", viewport: "1280x720", label: "desktop" },
      ],
    });
    expect(r.status()).toBe(201);
    const data = (await r.json()) as { screenshots: unknown[]; review_type: string };
    expect(data.screenshots.length).toBe(3);
    expect(data.review_type).toBe("responsive");
  });

  test("683.3 get review detail", async () => {
    const r = await apiGet(alicePage, `ui/agents/stylist/reviews/${reviewId}`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.review_id).toBe(reviewId);
    expect(Array.isArray(data.screenshots)).toBe(true);
    expect(Array.isArray(data.issues)).toBe(true);
    expect((data.issues as unknown[]).length).toBe(2);
  });

  test("683.4 list reviews by page", async () => {
    const r = await apiGet(alicePage, "ui/agents/stylist/reviews", { page_url: PAGE_URL });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { reviews: Array<{ page_url: string }> };
    expect(data.reviews.length).toBeGreaterThan(0);
    expect(data.reviews.every((rv) => rv.page_url === PAGE_URL)).toBe(true);
  });
});

// ─── 684: Design Scores & Issue Tickets API ──────────────────────────────────

test.describe("684. Design Scores & Issue Tickets API", () => {
  let alicePage: Page;
  let reviewId = "";
  let issueId = "";

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    const r = await apiPost(alicePage, "alice", "ui/agents/stylist/reviews", {
      page_url: `/billing?ts=${TS}`,
      page_name: "Billing",
      review_type: "full_page",
      design_score: 75,
      accessibility_score: 80,
      screenshots: [{ url: "/mock/s3/b.png", viewport: "1280x720", label: "desktop" }],
      issues: ISSUES,
    });
    const data = (await r.json()) as { review_id: string; issues: Array<{ issue_id: string }> };
    reviewId = data.review_id;
    issueId = data.issues[0].issue_id;
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("684.1 get per-page design scores", async () => {
    const r = await apiGet(alicePage, "ui/agents/stylist/scores");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Array<{ page_url: string; design_score: number; issues_found: number }>;
    expect(Array.isArray(data)).toBe(true);
    expect(data.length).toBeGreaterThan(0);
    expect(typeof data[0].design_score).toBe("number");
  });

  test("684.2 get overall design score", async () => {
    const r = await apiGet(alicePage, "ui/agents/stylist/scores/overall");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, number>;
    expect(typeof data.overall_design_score).toBe("number");
    expect(data.overall_accessibility_score).not.toBeUndefined();
  });

  test("684.3 create ticket from issue", async () => {
    const r = await apiPost(
      alicePage,
      "alice",
      `ui/agents/stylist/reviews/${reviewId}/issues/${issueId}/ticket`,
    );
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.ticket_id).toBeTruthy();
    // verify the review now carries created_ticket_id on the issue
    const detail = await apiGet(alicePage, `ui/agents/stylist/reviews/${reviewId}`);
    const review = (await detail.json()) as { issues: Array<{ issue_id: string; created_ticket_id?: string }> };
    const issue = review.issues.find((i) => i.issue_id === issueId);
    expect(issue?.created_ticket_id).toBe(data.ticket_id);
  });

  test("684.4 cannot create duplicate ticket for same issue", async () => {
    const r = await apiPost(
      alicePage,
      "alice",
      `ui/agents/stylist/reviews/${reviewId}/issues/${issueId}/ticket`,
    );
    expect(r.status()).toBe(409);
  });
});

// ─── 685: Design Rules API ───────────────────────────────────────────────────

test.describe("685. Design Rules API", () => {
  let alicePage: Page;
  let ruleId = "";

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("685.1 create design rule", async () => {
    const r = await apiPost(alicePage, "alice", "ui/agents/stylist/rules", {
      name: `Button spacing ${TS}`,
      category: "spacing",
      description: "Buttons must use consistent gap",
      severity: "warning",
    });
    expect(r.status()).toBe(201);
    const data = (await r.json()) as Record<string, unknown>;
    ruleId = data.rule_id as string;
    expect(ruleId).toBeTruthy();
    expect(data.category).toBe("spacing");
  });

  test("685.2 list design rules includes created rule", async () => {
    const r = await apiGet(alicePage, "ui/agents/stylist/rules");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Array<{ rule_id: string }>;
    expect(data.some((rl) => rl.rule_id === ruleId)).toBe(true);
  });

  test("685.3 update design rule severity", async () => {
    const r = await apiPut(alicePage, "alice", `ui/agents/stylist/rules/${ruleId}`, {
      severity: "error",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { severity: string };
    expect(data.severity).toBe("error");
  });

  test("685.4 delete design rule", async () => {
    const r = await apiDelete(alicePage, "alice", `ui/agents/stylist/rules/${ruleId}`);
    expect(r.status()).toBe(200);
    const list = await apiGet(alicePage, "ui/agents/stylist/rules");
    const data = (await list.json()) as Array<{ rule_id: string }>;
    expect(data.some((rl) => rl.rule_id === ruleId)).toBe(false);
  });
});

// ─── 686: Design Overview UI ─────────────────────────────────────────────────

test.describe("686. Design Overview UI", () => {
  let alicePage: Page;
  let reviewId = "";

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    const r = await apiPost(alicePage, "alice", "ui/agents/stylist/reviews", {
      page_url: `/files?ts=${TS}`,
      page_name: "Files",
      review_type: "full_page",
      design_score: 70,
      accessibility_score: 75,
      screenshots: [{ url: "/mock/s3/f.png", viewport: "1280x720", label: "desktop" }],
      issues: ISSUES,
    });
    reviewId = ((await r.json()) as { review_id: string }).review_id;
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("686.1 design overview page loads", async () => {
    await alicePage.goto("http://localhost:3000/agents/stylist");
    await expect(alicePage.locator('[data-testid="design-overview-page"]')).toBeVisible({
      timeout: 15_000,
    });
    await expect(alicePage.locator('[data-testid="page-score-card"]').first()).toBeVisible({
      timeout: 10_000,
    });
  });

  test("686.2 review detail shows screenshots", async () => {
    await alicePage.goto(`http://localhost:3000/agents/stylist/reviews/${reviewId}`);
    await expect(alicePage.locator('[data-testid="review-detail-page"]')).toBeVisible({
      timeout: 15_000,
    });
    await expect(alicePage.locator('[data-testid="review-screenshot"]').first()).toBeVisible({
      timeout: 10_000,
    });
  });

  test("686.3 design rules page CRUD via form", async () => {
    await alicePage.goto("http://localhost:3000/agents/stylist/rules");
    await expect(alicePage.locator('[data-testid="design-rules-page"]')).toBeVisible({
      timeout: 15_000,
    });
    await alicePage.locator('[data-testid="add-rule-btn"]').click();
    const ruleName = `UI rule ${TS}`;
    await alicePage.locator('[data-testid="rule-name-input"]').fill(ruleName);
    await alicePage.locator('[data-testid="rule-description-input"]').fill("UI created rule");
    await alicePage.locator('[data-testid="rule-submit-btn"]').click();
    await expect(alicePage.getByText(ruleName)).toBeVisible({ timeout: 10_000 });
  });
});
