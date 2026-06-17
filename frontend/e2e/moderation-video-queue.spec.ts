/**
 * MOD-001: Video Review Queue E2E tests.
 *
 * Section 95: Enqueue + queue listing API
 * Section 96: Claim / approve / reject / escalate workflow API
 * Section 97: Auth enforcement (403 for regular users) + validation (422) + 404/409
 * Section 98: Video Review Queue UI
 *
 * Auth: role-bearing JWT cookies from e2e_admin_session_setup.py.
 *   root          – role=root  (ADMIN moderator capabilities via require_admin_or_root)
 *   charlie_admin – role=admin
 *   alice / bob   – role=user  (asserted to receive 403)
 *
 * Endpoints under test: /ui/moderation/video-queue (require_admin_or_root + CSRF).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";

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
  // Seed the Zustand auth-store in localStorage so ProtectedRoute treats the
  // session as authenticated. Cookie auth alone is invisible to the SPA guard,
  // which reads isAuthenticated from the persisted auth-store and would
  // otherwise redirect /admin/* routes to /login.
  await page.goto("/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, sessions[identity].user_sub);
  return page;
}

type ReqParams = Record<string, string>;

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: ReqParams) {
  return page.request.get(`${API}/${path}`, { params });
}

const QUEUE = "ui/moderation/video-queue";

function uniqueVideoId(tag: string): string {
  return `v_e2e${tag}${Date.now()}${Math.floor(Math.random() * 1000)}`;
}

async function enqueue(
  page: Page,
  identity: string,
  overrides: Record<string, unknown> = {},
): Promise<{ entry_id: string; video_id: string; owner_user_id: string }> {
  const video_id = (overrides.video_id as string) ?? uniqueVideoId("q");
  const r = await apiPost(page, identity, `${QUEUE}/enqueue`, {
    video_id,
    owner_user_id: "e2e_creator@test.local",
    title: "E2E Review Video",
    priority: "high",
    source: "manual",
    ...overrides,
  });
  expect(r.status()).toBe(200);
  const data = (await r.json()) as Record<string, unknown>;
  return {
    entry_id: data.entry_id as string,
    video_id: data.video_id as string,
    owner_user_id: data.owner_user_id as string,
  };
}

// ─── 95. Enqueue + queue listing API ────────────────────────────────────────

test.describe("95. Video queue enqueue + listing API", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("enqueue creates a pending entry", async () => {
    const { entry_id } = await enqueue(rootPage, "root");
    expect(entry_id).toMatch(/^vq_/);
  });

  test("enqueue is idempotent on open entries for the same video", async () => {
    const vid = uniqueVideoId("idem");
    const a = await enqueue(rootPage, "root", { video_id: vid });
    const b = await enqueue(rootPage, "root", { video_id: vid });
    expect(b.entry_id).toBe(a.entry_id);
  });

  test("enqueue accepts a flagged source with a flag reason", async () => {
    const r = await apiPost(rootPage, "root", `${QUEUE}/enqueue`, {
      video_id: uniqueVideoId("flag"),
      owner_user_id: "flagged_owner@test.local",
      title: "Flagged clip",
      source: "flagged",
      priority: "urgent",
      flag_reason: "User report: nudity",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.source).toBe("flagged");
    expect(data.flag_reason).toBe("User report: nudity");
    expect(data.priority).toBe("urgent");
  });

  test("list pending returns the enqueued entry", async () => {
    const { entry_id } = await enqueue(rootPage, "root");
    const r = await apiGet(rootPage, QUEUE, { status: "pending", limit: "100" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { items: Array<{ entry_id: string }>; total: number };
    expect(data.items.some((it) => it.entry_id === entry_id)).toBe(true);
    expect(data.total).toBeGreaterThan(0);
  });

  test("list respects the limit parameter", async () => {
    await enqueue(rootPage, "root");
    await enqueue(rootPage, "root");
    const r = await apiGet(rootPage, QUEUE, { status: "pending", limit: "1" });
    const data = (await r.json()) as { items: unknown[] };
    expect(data.items.length).toBe(1);
  });

  test("list with owner_user_id filter returns only that owner", async () => {
    const owner = `owner_${Date.now()}@test.local`;
    await enqueue(rootPage, "root", { owner_user_id: owner });
    const r = await apiGet(rootPage, QUEUE, { status: "pending", owner_user_id: owner, limit: "100" });
    const data = (await r.json()) as { items: Array<{ owner_user_id: string }> };
    expect(data.items.length).toBeGreaterThan(0);
    expect(data.items.every((it) => it.owner_user_id === owner)).toBe(true);
  });

  test("stats returns per-status counts", async () => {
    await enqueue(rootPage, "root");
    const r = await apiGet(rootPage, `${QUEUE}/stats`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { counts: Record<string, number>; total_open: number };
    expect(typeof data.counts.pending).toBe("number");
    expect(data.total_open).toBeGreaterThan(0);
  });
});

// ─── 96. Review workflow API ────────────────────────────────────────────────

test.describe("96. Video queue review workflow API", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("claim transitions pending -> in_review", async () => {
    const { entry_id } = await enqueue(rootPage, "root");
    const r = await apiPost(rootPage, "root", `${QUEUE}/${entry_id}/claim`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { entry: { status: string; claimed_by: string } };
    expect(data.entry.status).toBe("in_review");
    expect(data.entry.claimed_by).toBeTruthy();
  });

  test("claim is idempotent for the same moderator", async () => {
    const { entry_id } = await enqueue(rootPage, "root");
    await apiPost(rootPage, "root", `${QUEUE}/${entry_id}/claim`);
    const r = await apiPost(rootPage, "root", `${QUEUE}/${entry_id}/claim`);
    expect(r.status()).toBe(200);
  });

  test("approve transitions to approved", async () => {
    const { entry_id } = await enqueue(rootPage, "root");
    const r = await apiPost(rootPage, "root", `${QUEUE}/${entry_id}/approve`, {
      review_notes: "Looks fine",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { new_status: string; decision: string; audit_id: string };
    expect(data.new_status).toBe("approved");
    expect(data.decision).toBe("approve");
    expect(data.audit_id).toMatch(/^modaudit_/);
  });

  test("reject transitions to rejected with reason persisted", async () => {
    const { entry_id } = await enqueue(rootPage, "root");
    const r = await apiPost(rootPage, "root", `${QUEUE}/${entry_id}/reject`, {
      rejection_reason: "Contains prohibited content",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { new_status: string };
    expect(data.new_status).toBe("rejected");

    const detail = await apiGet(rootPage, `${QUEUE}/${entry_id}`);
    const dd = (await detail.json()) as { entry: { review_notes: string } };
    expect(dd.entry.review_notes).toBe("Contains prohibited content");
  });

  test("escalate transitions to escalated", async () => {
    const { entry_id } = await enqueue(rootPage, "root");
    const r = await apiPost(rootPage, "root", `${QUEUE}/${entry_id}/escalate`, {
      escalation_reason: "Needs senior review",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { new_status: string };
    expect(data.new_status).toBe("escalated");
  });

  test("detail returns prior review history counts", async () => {
    const owner = `histowner_${Date.now()}@test.local`;
    const a = await enqueue(rootPage, "root", { owner_user_id: owner });
    await apiPost(rootPage, "root", `${QUEUE}/${a.entry_id}/reject`, {
      rejection_reason: "first rejection reason",
    });
    const b = await enqueue(rootPage, "root", { owner_user_id: owner });
    const detail = await apiGet(rootPage, `${QUEUE}/${b.entry_id}`);
    const dd = (await detail.json()) as { prior_rejections_count: number };
    expect(dd.prior_rejections_count).toBeGreaterThanOrEqual(1);
  });
});

// ─── 97. Auth + validation + conflict ────────────────────────────────────────

test.describe("97. Video queue auth + validation", () => {
  let rootPage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("regular user cannot list the queue (403)", async () => {
    const r = await apiGet(alicePage, QUEUE, { status: "pending" });
    expect(r.status()).toBe(403);
  });

  test("regular user cannot enqueue (403)", async () => {
    const r = await apiPost(alicePage, "alice", `${QUEUE}/enqueue`, {
      video_id: uniqueVideoId("forbidden"),
      owner_user_id: ALICE_ID,
    });
    expect(r.status()).toBe(403);
  });

  test("reject with too-short reason returns 422", async () => {
    const { entry_id } = await enqueue(rootPage, "root");
    const r = await apiPost(rootPage, "root", `${QUEUE}/${entry_id}/reject`, {
      rejection_reason: "no",
    });
    expect(r.status()).toBe(422);
  });

  test("approve a non-existent entry returns 404", async () => {
    const r = await apiPost(rootPage, "root", `${QUEUE}/vq_doesnotexist000000/approve`, {});
    expect(r.status()).toBe(404);
  });

  test("approve an already-approved entry returns 409", async () => {
    const { entry_id } = await enqueue(rootPage, "root");
    const first = await apiPost(rootPage, "root", `${QUEUE}/${entry_id}/approve`, {});
    expect(first.status()).toBe(200);
    const second = await apiPost(rootPage, "root", `${QUEUE}/${entry_id}/approve`, {});
    expect(second.status()).toBe(409);
  });
});

// ─── 98. Video Review Queue UI ────────────────────────────────────────────────

test.describe("98. Video Review Queue UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("page renders the queue and shows enqueued video", async () => {
    const title = `UI Review ${Date.now()}`;
    await enqueue(rootPage, "root", { title });
    await rootPage.goto("/admin/video-review-queue");
    await expect(rootPage.getByRole("heading", { name: "Video Review Queue" })).toBeVisible();
    await expect(rootPage.getByText(title).first()).toBeVisible({ timeout: 15_000 });
  });

  test("approve button removes the card from the pending list", async () => {
    const title = `UI Approve ${Date.now()}`;
    const { entry_id } = await enqueue(rootPage, "root", { title });
    await rootPage.goto("/admin/video-review-queue");
    const card = rootPage.getByTestId(`vrq-card-${entry_id}`);
    await expect(card).toBeVisible({ timeout: 15_000 });
    await card.getByTestId("vrq-approve").click();
    await expect(rootPage.getByText("Video approved").first()).toBeVisible({ timeout: 10_000 });
    await expect(card).toHaveCount(0, { timeout: 10_000 });
  });

  test("reject opens reason dialog and submits", async () => {
    const title = `UI Reject ${Date.now()}`;
    const { entry_id } = await enqueue(rootPage, "root", { title });
    await rootPage.goto("/admin/video-review-queue");
    const card = rootPage.getByTestId(`vrq-card-${entry_id}`);
    await expect(card).toBeVisible({ timeout: 15_000 });
    await card.getByTestId("vrq-reject").click();
    await rootPage.getByTestId("vrq-reason-input").fill("Rejected via E2E UI test");
    await rootPage.getByTestId("vrq-reason-submit").click();
    await expect(rootPage.getByText("Video rejected").first()).toBeVisible({ timeout: 10_000 });
    await expect(card).toHaveCount(0, { timeout: 10_000 });
  });
});
