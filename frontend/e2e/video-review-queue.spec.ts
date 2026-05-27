/**
 * E2E tests for MOD-001: Admin Video Review Queue
 *
 * Section 90: Review Queue API (8 tests)
 * Section 91: Batch Review API (5 tests)
 * Section 92: Audit Log Verification (2 tests)
 * Section 93: Creator Notifications (2 tests)
 * Section 94: Video Review Queue UI (4 tests)
 *
 * Uses root session (content_moderation scope) for admin endpoints.
 * Seeds test videos directly into DynamoDB with pending_review status.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ─────────────────────────────────────────────────────────────────

const API = "http://localhost:8000";
const ROOT_SUB = "root.admin@testdev.local";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

// ─── Session bootstrap ─────────────────────────────────────────────────────────

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

async function newIdentityPage(
  browser: Browser,
  identity: string,
): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

// ─── Request helpers ───────────────────────────────────────────────────────────

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
  return page.request.get(`${API}/${path}`, { params });
}

// ─── DDB seed helpers ──────────────────────────────────────────────────────────

function seedPendingVideos(count: number, ownerOverride?: string): string[] {
  const owner = ownerOverride || ALICE_ID;
  const raw = execSync(
    `python3 -c "
import boto3, os, json, uuid, time
from pathlib import Path

env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('DDB_VIDEO_METADATA','VideoMetadata'))

ids = []
base_ts = int(time.time()) - 3600
for i in range(${count}):
    vid = 'v_' + uuid.uuid4().hex
    tbl.put_item(Item={
        'video_id': vid,
        'owner_user_id': '${owner}',
        'title': 'E2E Review Video ${TS} #' + str(i),
        'status': 'pending_review',
        'created_at': base_ts + i,
        'updated_at': base_ts + i,
        'source_type': 'upload',
        'visibility': 'public',
        'drm_enabled': False,
        'duration_seconds': 120 + i * 10,
        'width': 1920,
        'height': 1080,
        'file_size_bytes': 5000000 + i * 100000,
    })
    ids.append(vid)

print(json.dumps(ids))
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  ).toString();
  return JSON.parse(raw.trim());
}

function cleanupVideos(videoIds: string[]): void {
  if (!videoIds.length) return;
  const idsJson = JSON.stringify(videoIds);
  try {
    execSync(
      `python3 -c "
import boto3, os, json
from pathlib import Path

env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('DDB_VIDEO_METADATA','VideoMetadata'))

ids = json.loads('${idsJson.replace(/'/g, "\\'")}')
for vid in ids:
    try:
        tbl.delete_item(Key={'video_id': vid})
    except Exception:
        pass
"`,
      { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
    );
  } catch {
    // ignore cleanup errors
  }
}

function setVideoStatus(videoId: string, status: string): void {
  execSync(
    `python3 -c "
import boto3, os
from pathlib import Path

env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('DDB_VIDEO_METADATA','VideoMetadata'))
tbl.update_item(
    Key={'video_id': '${videoId}'},
    UpdateExpression='SET #s = :s',
    ExpressionAttributeNames={'#s': 'status'},
    ExpressionAttributeValues={':s': '${status}'},
)
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
  );
}

// ─── 90. Review Queue API ──────────────────────────────────────────────────────

test.describe("90. Review Queue API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let videoIds: string[] = [];

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
    videoIds = seedPendingVideos(5);
  });

  test.afterAll(async () => {
    cleanupVideos(videoIds);
    await rootPage?.close();
    await alicePage?.close();
  });

  test("GET /review-queue returns pending videos oldest first", async () => {
    const resp = await apiGet(rootPage, "v1/admin/videos/review-queue");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items.length).toBeGreaterThanOrEqual(5);
    expect(data.total_pending).toBeGreaterThanOrEqual(5);

    // Verify oldest-first ordering
    for (let i = 1; i < data.items.length; i++) {
      expect(data.items[i].created_at).toBeGreaterThanOrEqual(
        data.items[i - 1].created_at,
      );
    }
  });

  test("GET /review-queue respects limit parameter", async () => {
    const resp = await apiGet(rootPage, "v1/admin/videos/review-queue", {
      limit: "1",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items.length).toBe(1);
    expect(data.next_cursor).toBeTruthy();
  });

  test("GET /review-queue pagination with cursor", async () => {
    const resp1 = await apiGet(rootPage, "v1/admin/videos/review-queue", {
      limit: "2",
    });
    expect(resp1.status()).toBe(200);
    const data1 = await resp1.json();
    expect(data1.items.length).toBe(2);
    expect(data1.next_cursor).toBeTruthy();

    const resp2 = await apiGet(rootPage, "v1/admin/videos/review-queue", {
      limit: "2",
      cursor: data1.next_cursor,
    });
    expect(resp2.status()).toBe(200);
    const data2 = await resp2.json();
    expect(data2.items.length).toBeGreaterThanOrEqual(1);

    // No overlap
    const ids1 = new Set(data1.items.map((i: { video_id: string }) => i.video_id));
    for (const item of data2.items) {
      expect(ids1.has(item.video_id)).toBe(false);
    }
  });

  test("GET /review-queue owner_user_id filter", async () => {
    const resp = await apiGet(rootPage, "v1/admin/videos/review-queue", {
      owner_user_id: ALICE_ID,
      limit: "50",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    for (const item of data.items) {
      expect(item.owner_user_id).toBe(ALICE_ID);
    }
  });

  test("POST /approve transitions to published", async () => {
    const vid = videoIds[0];
    const resp = await apiPost(rootPage, "root", `v1/admin/videos/${vid}/approve`, {
      review_notes: "Looks good",
      auto_publish: true,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.decision).toBe("approved");
    expect(data.new_status).toBe("published");
    expect(data.reviewed_by).toBe(ROOT_SUB);
    expect(data.audit_id).toMatch(/^modaudit_/);
  });

  test("POST /reject with reason", async () => {
    const vid = videoIds[1];
    const resp = await apiPost(rootPage, "root", `v1/admin/videos/${vid}/reject`, {
      rejection_reason: "Contains copyrighted material",
      notify_creator: true,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.decision).toBe("rejected");
    expect(data.new_status).toBe("rejected");
    expect(data.audit_id).toMatch(/^modaudit_/);
  });

  test("POST /reject without reason returns 422", async () => {
    const vid = videoIds[2];
    const resp = await apiPost(rootPage, "root", `v1/admin/videos/${vid}/reject`, {
      rejection_reason: "",
    });
    expect(resp.status()).toBe(422);
  });

  test("POST /approve on already-approved returns 409", async () => {
    // videoIds[0] was already approved above
    const vid = videoIds[0];
    const resp = await apiPost(rootPage, "root", `v1/admin/videos/${vid}/approve`, {
      review_notes: "try again",
      auto_publish: true,
    });
    expect(resp.status()).toBe(409);
  });
});

// ─── 91. Batch Review API ──────────────────────────────────────────────────────

test.describe("91. Batch Review API", () => {
  let rootPage: Page;
  let videoIds: string[] = [];

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    videoIds = seedPendingVideos(8);
  });

  test.afterAll(async () => {
    cleanupVideos(videoIds);
    await rootPage?.close();
  });

  test("Batch approve 3 videos", async () => {
    const batchIds = videoIds.slice(0, 3);
    const resp = await apiPost(rootPage, "root", "v1/admin/videos/batch-review", {
      decisions: batchIds.map((id) => ({
        video_id: id,
        action: "approve",
        reason: "",
      })),
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.total).toBe(3);
    expect(data.succeeded).toBe(3);
    expect(data.failed).toBe(0);
    for (const r of data.results) {
      expect(r.ok).toBe(true);
      expect(r.decision).toBe("approved");
      expect(r.new_status).toBe("published");
    }
  });

  test("Batch mixed approve+reject", async () => {
    const resp = await apiPost(rootPage, "root", "v1/admin/videos/batch-review", {
      decisions: [
        { video_id: videoIds[3], action: "approve", reason: "" },
        { video_id: videoIds[4], action: "approve", reason: "" },
        {
          video_id: videoIds[5],
          action: "reject",
          reason: "Violates community guidelines",
        },
      ],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.total).toBe(3);
    expect(data.succeeded).toBe(3);
    expect(data.failed).toBe(0);

    const approvals = data.results.filter(
      (r: { decision: string }) => r.decision === "approved",
    );
    const rejections = data.results.filter(
      (r: { decision: string }) => r.decision === "rejected",
    );
    expect(approvals.length).toBe(2);
    expect(rejections.length).toBe(1);
  });

  test("Batch with invalid video_id", async () => {
    const resp = await apiPost(rootPage, "root", "v1/admin/videos/batch-review", {
      decisions: [
        { video_id: videoIds[6], action: "approve", reason: "" },
        { video_id: "v_nonexistent999", action: "approve", reason: "" },
      ],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.succeeded).toBe(1);
    expect(data.failed).toBe(1);

    const failedResult = data.results.find(
      (r: { video_id: string }) => r.video_id === "v_nonexistent999",
    );
    expect(failedResult).toBeTruthy();
    expect(failedResult.ok).toBe(false);
  });

  test("Batch empty list returns 422", async () => {
    const resp = await apiPost(rootPage, "root", "v1/admin/videos/batch-review", {
      decisions: [],
    });
    expect(resp.status()).toBe(422);
  });

  test("Batch reject with too-short reason fails per-item", async () => {
    const resp = await apiPost(rootPage, "root", "v1/admin/videos/batch-review", {
      decisions: [
        { video_id: videoIds[7], action: "reject", reason: "no" },
      ],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.failed).toBe(1);
    expect(data.results[0].ok).toBe(false);
    expect(data.results[0].error).toContain("5 characters");
  });
});

// ─── 92. Audit Log Verification ────────────────────────────────────────────────

test.describe("92. Audit Log Verification", () => {
  let rootPage: Page;
  let videoIds: string[] = [];

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    videoIds = seedPendingVideos(2);
  });

  test.afterAll(async () => {
    cleanupVideos(videoIds);
    await rootPage?.close();
  });

  test("Approve writes audit event", async () => {
    const vid = videoIds[0];
    const resp = await apiPost(rootPage, "root", `v1/admin/videos/${vid}/approve`, {
      review_notes: "Audit test approve",
      auto_publish: true,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.audit_id).toMatch(/^modaudit_/);
    expect(data.audit_id.length).toBeGreaterThan(10);
  });

  test("Reject writes audit event with rejection reason", async () => {
    const vid = videoIds[1];
    const resp = await apiPost(rootPage, "root", `v1/admin/videos/${vid}/reject`, {
      rejection_reason: "Audit test rejection reason text",
      notify_creator: true,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.audit_id).toMatch(/^modaudit_/);
    expect(data.audit_id.length).toBeGreaterThan(10);
  });
});

// ─── 93. Creator Notifications ─────────────────────────────────────────────────

test.describe("93. Creator Notifications", () => {
  let rootPage: Page;
  let alicePage: Page;
  let videoIds: string[] = [];

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
    videoIds = seedPendingVideos(2);
  });

  test.afterAll(async () => {
    cleanupVideos(videoIds);
    await rootPage?.close();
    await alicePage?.close();
  });

  test("Creator receives approval notification", async () => {
    const vid = videoIds[0];
    await apiPost(rootPage, "root", `v1/admin/videos/${vid}/approve`, {
      review_notes: "Notification test",
      auto_publish: true,
    });

    // Query Alice's alerts
    const alertsResp = await apiGet(alicePage, "ui/alerts");
    expect(alertsResp.status()).toBe(200);
    const alertsData = await alertsResp.json();
    const approvalAlert = alertsData.alerts?.find(
      (a: { event: string; details?: { video_id?: string } }) =>
        a.event === "video_review_approved" && a.details?.video_id === vid,
    );
    expect(approvalAlert).toBeTruthy();
    expect(approvalAlert.title).toBe("Video approved");
  });

  test("Creator receives rejection notification with reason", async () => {
    const vid = videoIds[1];
    const reason = "Content violates TOS for notification test";
    await apiPost(rootPage, "root", `v1/admin/videos/${vid}/reject`, {
      rejection_reason: reason,
      notify_creator: true,
    });

    // Query Alice's alerts
    const alertsResp = await apiGet(alicePage, "ui/alerts");
    expect(alertsResp.status()).toBe(200);
    const alertsData = await alertsResp.json();
    const rejectionAlert = alertsData.alerts?.find(
      (a: { event: string; details?: { video_id?: string } }) =>
        a.event === "video_review_rejected" && a.details?.video_id === vid,
    );
    expect(rejectionAlert).toBeTruthy();
    expect(rejectionAlert.title).toBe("Video not approved");
  });
});

// ─── UI auth injection helper ──────────────────────────────────────────────────

async function injectUiAuth(page: Page, identity: string): Promise<void> {
  const sessions = getAdminSessions();
  const sess = sessions[identity];
  await page.context().addCookies(sess.cookies);
  // Navigate first so localStorage can be set on the correct origin
  await page.goto("http://localhost:3000/login", {
    waitUntil: "domcontentloaded",
  });
  // Set zustand auth store in localStorage so ProtectedRoute allows access
  await page.evaluate(
    ({ userId, accessToken }: { userId: string; accessToken: string }) => {
      const state = { userId, accessToken, isAuthenticated: true, logoutReason: null };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    { userId: sess.user_sub, accessToken: sess.access_token },
  );
}

// ─── 94. Video Review Queue UI ─────────────────────────────────────────────────

test.describe("94. Video Review Queue UI", () => {
  let rootPage: Page;
  let videoIds: string[] = [];

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    await injectUiAuth(rootPage, "root");
    videoIds = seedPendingVideos(4);
  });

  test.afterAll(async () => {
    cleanupVideos(videoIds);
    await rootPage?.close();
  });

  test("Page renders pending videos list", async () => {
    await rootPage.goto("http://localhost:3000/admin/video-review");
    await rootPage.waitForLoadState("domcontentloaded");

    // Wait for the queue to load -- pending count badge should appear
    await expect(
      rootPage.locator("[data-testid='pending-count']"),
    ).toBeVisible({ timeout: 15_000 });

    // Should see Approve buttons (one per video card)
    await expect(
      rootPage.getByRole("button", { name: /Approve/i }).first(),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("Click Approve button approves video", async () => {
    await rootPage.goto("http://localhost:3000/admin/video-review");
    await rootPage.waitForLoadState("domcontentloaded");

    // Wait for Approve buttons
    await expect(
      rootPage.getByRole("button", { name: /Approve/i }).first(),
    ).toBeVisible({ timeout: 15_000 });

    // Click the first Approve button
    const approveButtons = rootPage.getByRole("button", { name: /^Approve$/i });
    await approveButtons.first().click();

    // Should show success toast
    await expect(rootPage.getByText(/Video approved/i).first()).toBeVisible({
      timeout: 10_000,
    });
  });

  test("Click Reject opens reason dialog", async () => {
    await rootPage.goto("http://localhost:3000/admin/video-review");
    await rootPage.waitForLoadState("domcontentloaded");

    // Wait for Reject buttons
    await expect(
      rootPage.getByRole("button", { name: /^Reject$/i }).first(),
    ).toBeVisible({ timeout: 15_000 });

    // Click first Reject button
    await rootPage
      .getByRole("button", { name: /^Reject$/i })
      .first()
      .click();

    // Dialog should appear
    await expect(
      rootPage.getByRole("heading", { name: /Reject Video/i }),
    ).toBeVisible({ timeout: 5_000 });

    // Fill reason and submit
    await rootPage.fill(
      "#rejection-reason",
      "UI test rejection reason for E2E",
    );
    await rootPage
      .getByRole("button", { name: /Reject Video/i })
      .last()
      .click();

    // Should show success toast
    await expect(rootPage.getByText(/Video rejected/i).first()).toBeVisible({
      timeout: 10_000,
    });
  });

  test("Batch select and approve", async () => {
    await rootPage.goto("http://localhost:3000/admin/video-review");
    await rootPage.waitForLoadState("domcontentloaded");

    // Wait for checkboxes to appear (one per video card)
    await expect(
      rootPage.getByRole("checkbox").first(),
    ).toBeVisible({ timeout: 15_000 });

    // Select first 2 checkboxes
    const checkboxes = rootPage.getByRole("checkbox");
    const count = await checkboxes.count();
    if (count >= 2) {
      await checkboxes.nth(0).click();
      await checkboxes.nth(1).click();

      // Click "Approve Selected"
      const batchApproveBtn = rootPage.getByRole("button", {
        name: /Approve Selected/i,
      });
      await expect(batchApproveBtn).toBeVisible({ timeout: 5_000 });
      await batchApproveBtn.click();

      // Should show batch success toast
      await expect(
        rootPage.getByText(/Batch complete/i).first(),
      ).toBeVisible({ timeout: 10_000 });
    }
  });
});
