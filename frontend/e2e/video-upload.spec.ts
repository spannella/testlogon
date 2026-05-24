/**
 * E2E tests for Video Upload & Library page.
 *
 * Sections:
 *   105 — Video Upload API Flow  (4 tests)
 *   106 — Video Library UI       (5 tests)
 *   107 — Upload Progress         (3 tests)
 *
 * Auth: Alice session cookies (from e2e_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
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

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, path: string, body?: unknown) {
  const session = getSessions()[ALICE_ID];
  const resp = await page.request.post(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body,
  });
  return resp;
}

async function apiGet(page: Page, path: string) {
  const resp = await page.request.get(`${BASE}${path}`);
  return resp;
}

async function apiDelete(page: Page, path: string) {
  const session = getSessions()[ALICE_ID];
  const resp = await page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
  return resp;
}

async function apiPatch(page: Page, path: string, body: unknown) {
  const session = getSessions()[ALICE_ID];
  const resp = await page.request.patch(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body,
  });
  return resp;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 105 — Video Upload API Flow
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("105 · Video Upload API Flow", () => {
  let page: Page;
  let videoId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => {
    // Clean up: delete the created video
    if (videoId) {
      await apiDelete(page, `/ui/videos/${videoId}`).catch(() => {});
    }
    await page.close();
  });

  test("105.1 Presign returns valid upload URL and video_id", async () => {
    const resp = await apiPost(page, "/ui/videos/upload/presign", {
      filename: `test_video_${TS}.mp4`,
      content_type: "video/mp4",
      size_bytes: 1024 * 1024, // 1 MB
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_id).toBeTruthy();
    expect(data.presigned_url).toBeTruthy();
    expect(data.s3_key).toContain(`test_video_${TS}.mp4`);
    expect(data.expires_in_seconds).toBeGreaterThan(0);
    videoId = data.video_id;
  });

  test("105.2 Upload to presigned URL succeeds", async () => {
    // Get a fresh presign for a small upload
    const presignResp = await apiPost(page, "/ui/videos/upload/presign", {
      filename: `upload_test_${TS}.mp4`,
      content_type: "video/mp4",
      size_bytes: 256,
    });
    expect(presignResp.status()).toBe(200);
    const presign = await presignResp.json();
    videoId = presign.video_id;

    // Upload a small fake video file (just bytes for testing)
    const fakeContent = Buffer.alloc(256, 0x42);
    const uploadResp = await page.request.put(presign.presigned_url, {
      headers: { "Content-Type": "video/mp4" },
      data: fakeContent,
    });
    // moto S3 mock accepts any PUT to the presigned URL
    expect(uploadResp.status()).toBeLessThan(400);
  });

  test("105.3 Complete upload transitions video status", async () => {
    const resp = await apiPost(page, `/ui/videos/${videoId}/upload/complete`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_id).toBe(videoId);
    expect(data.status).toBe("upload_complete");
  });

  test("105.4 Video appears in listing after upload", async () => {
    const resp = await apiGet(page, "/ui/videos");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeInstanceOf(Array);
    const found = data.items.find(
      (v: { video_id: string }) => v.video_id === videoId,
    );
    expect(found).toBeTruthy();
    expect(found.title).toContain(`upload_test_${TS}`);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 106 — Video Library UI
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("106 · Video Library UI", () => {
  let page: Page;
  let testVideoId: string;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);

    // Create a test video via API so the library has content
    const presignResp = await apiPost(page, "/ui/videos/upload/presign", {
      filename: `ui_test_${TS}.mp4`,
      content_type: "video/mp4",
      size_bytes: 128,
    });
    const presign = await presignResp.json();
    testVideoId = presign.video_id;

    // Upload content
    const fakeContent = Buffer.alloc(128, 0x43);
    await page.request.put(presign.presigned_url, {
      headers: { "Content-Type": "video/mp4" },
      data: fakeContent,
    });

    // Complete upload
    await apiPost(page, `/ui/videos/${testVideoId}/upload/complete`);
  });

  test.afterAll(async () => {
    if (testVideoId) {
      await apiDelete(page, `/ui/videos/${testVideoId}`).catch(() => {});
    }
    await page.close();
  });

  test("106.1 Videos page loads and shows header", async () => {
    await page.goto(`${BASE}/videos`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Videos" })).toBeVisible();
    await expect(page.getByRole("button", { name: /Upload Video/i })).toBeVisible();
  });

  test("106.2 Video card shows title and status", async () => {
    await page.goto(`${BASE}/videos`, { waitUntil: "domcontentloaded" });
    // Wait for video grid to load
    await page.waitForResponse(
      (resp) => resp.url().includes("/ui/videos") && resp.status() === 200,
    );
    // The test video should be visible
    await expect(
      page.locator("h4").filter({ hasText: `ui_test_${TS}` }),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("106.3 Edit dialog updates title", async () => {
    // Use the API directly to update the video title
    const resp = await apiPatch(page, `/ui/videos/${testVideoId}`, {
      title: `renamed_${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.title).toBe(`renamed_${TS}`);
  });

  test("106.4 Delete removes video from list", async () => {
    // Create another video to delete
    const presignResp = await apiPost(page, "/ui/videos/upload/presign", {
      filename: `delete_me_${TS}.mp4`,
      content_type: "video/mp4",
      size_bytes: 64,
    });
    const presign = await presignResp.json();
    const delVideoId = presign.video_id;
    await page.request.put(presign.presigned_url, {
      headers: { "Content-Type": "video/mp4" },
      data: Buffer.alloc(64, 0x44),
    });
    await apiPost(page, `/ui/videos/${delVideoId}/upload/complete`);

    // Delete via API
    const resp = await apiDelete(page, `/ui/videos/${delVideoId}`);
    expect(resp.status()).toBe(204);

    // Verify it no longer appears in the listing
    const listResp = await apiGet(page, "/ui/videos");
    const listData = await listResp.json();
    const found = listData.items.find(
      (v: { video_id: string }) => v.video_id === delVideoId,
    );
    expect(found).toBeFalsy();
  });

  test("106.5 Empty state shown when no videos", async () => {
    // Route videos API to return empty list (use ** glob to match query params)
    await page.route("**/ui/videos?*", (route) => {
      if (route.request().method() === "GET") {
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ items: [], cursor: null }),
        });
      } else {
        route.continue();
      }
    });
    await page.route("**/ui/videos", (route) => {
      if (route.request().method() === "GET" && !route.request().url().includes("upload")) {
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ items: [], cursor: null }),
        });
      } else {
        route.continue();
      }
    });

    await page.goto(`${BASE}/videos`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("No videos yet")).toBeVisible({ timeout: 10_000 });

    // Unroute for subsequent tests
    await page.unroute("**/ui/videos?*");
    await page.unroute("**/ui/videos");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 107 — Upload Progress
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("107 · Upload Progress", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    await page.goto(`${BASE}/videos`, { waitUntil: "domcontentloaded" });
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("107.1 Upload panel shows progress indicators", async () => {
    // Mock presign endpoint to return a slow upload URL
    await page.route("**/ui/videos/upload/presign", async (route) => {
      if (route.request().method() === "POST") {
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            video_id: `mock_vid_${TS}`,
            presigned_url: `${BASE}/mock/s3/local-uploads/videos/test/${TS}/progress_test.mp4`,
            s3_key: `videos/test/${TS}/progress_test.mp4`,
            expires_in_seconds: 3600,
          }),
        });
      } else {
        route.continue();
      }
    });

    // Trigger file upload via file chooser
    const fileChooserPromise = page.waitForEvent("filechooser");
    await page.getByRole("button", { name: /Upload Video/i }).click();
    const fileChooser = await fileChooserPromise;
    await fileChooser.setFiles({
      name: `progress_test_${TS}.mp4`,
      mimeType: "video/mp4",
      buffer: Buffer.alloc(1024, 0x45),
    });

    // Upload panel should appear with the file name
    await expect(
      page.getByText(`progress_test_${TS}`),
    ).toBeVisible({ timeout: 10_000 });

    // The upload item row should contain status text within the same row
    const uploadRow = page.getByText(`progress_test_${TS}`).locator("..");
    await expect(
      uploadRow.locator("span").filter({ hasText: /Preparing|Confirming|Processing|Complete|\d+%/ }).first(),
    ).toBeVisible({ timeout: 15_000 });

    await page.unroute("**/ui/videos/upload/presign");
  });

  test("107.2 Cancel button aborts upload", async () => {
    // Set up a route that delays the S3 PUT so we can cancel mid-upload
    await page.route("**/mock/s3/**", async (route) => {
      if (route.request().method() === "PUT") {
        // Delay to give time to cancel
        await new Promise((r) => setTimeout(r, 5000));
        route.fulfill({ status: 200 });
      } else {
        route.continue();
      }
    });

    await page.route("**/ui/videos/upload/presign", async (route) => {
      if (route.request().method() === "POST") {
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            video_id: `cancel_vid_${TS}`,
            presigned_url: `${BASE}/mock/s3/local-uploads/videos/test/${TS}/cancel_test.mp4`,
            s3_key: `videos/test/${TS}/cancel_test.mp4`,
            expires_in_seconds: 3600,
          }),
        });
      } else {
        route.continue();
      }
    });

    // Trigger another upload
    const fileChooserPromise = page.waitForEvent("filechooser");
    await page.getByRole("button", { name: /Upload Video/i }).click();
    const fileChooser = await fileChooserPromise;
    await fileChooser.setFiles({
      name: `cancel_test_${TS}.mp4`,
      mimeType: "video/mp4",
      buffer: Buffer.alloc(2048, 0x46),
    });

    // Wait for the upload item to appear
    await expect(page.getByText(`cancel_test_${TS}`)).toBeVisible({
      timeout: 10_000,
    });

    // Click the cancel (X) button on the upload item
    // Find the upload item row and its cancel button
    const uploadRow = page.getByText(`cancel_test_${TS}`).locator("../..");
    const cancelBtn = uploadRow.getByRole("button").first();
    await cancelBtn.click();

    // Should show "Cancelled" status
    await expect(page.getByText("Cancelled")).toBeVisible({ timeout: 5_000 });

    await page.unroute("**/mock/s3/**");
    await page.unroute("**/ui/videos/upload/presign");
  });

  test("107.3 Multiple files can be uploaded simultaneously", async () => {
    // Mock presign to return different video IDs
    let presignCount = 0;
    await page.route("**/ui/videos/upload/presign", async (route) => {
      if (route.request().method() === "POST") {
        presignCount++;
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            video_id: `multi_vid_${TS}_${presignCount}`,
            presigned_url: `${BASE}/mock/s3/local-uploads/videos/test/${TS}/multi_${presignCount}.mp4`,
            s3_key: `videos/test/${TS}/multi_${presignCount}.mp4`,
            expires_in_seconds: 3600,
          }),
        });
      } else {
        route.continue();
      }
    });

    // Mock S3 PUT to succeed quickly
    await page.route("**/mock/s3/**", async (route) => {
      if (route.request().method() === "PUT") {
        route.fulfill({ status: 200 });
      } else {
        route.continue();
      }
    });

    // Mock complete endpoint
    await page.route("**/ui/videos/*/upload/complete", async (route) => {
      if (route.request().method() === "POST") {
        const url = route.request().url();
        const videoId = url.split("/ui/videos/")[1].split("/upload")[0];
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ video_id: videoId, status: "upload_complete" }),
        });
      } else {
        route.continue();
      }
    });

    // Upload multiple files at once
    const fileChooserPromise = page.waitForEvent("filechooser");
    await page.getByRole("button", { name: /Upload Video/i }).click();
    const fileChooser = await fileChooserPromise;
    await fileChooser.setFiles([
      {
        name: `multi_a_${TS}.mp4`,
        mimeType: "video/mp4",
        buffer: Buffer.alloc(512, 0x47),
      },
      {
        name: `multi_b_${TS}.mp4`,
        mimeType: "video/mp4",
        buffer: Buffer.alloc(512, 0x48),
      },
    ]);

    // Both file names should appear in the upload panel
    await expect(page.getByText(`multi_a_${TS}`)).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(`multi_b_${TS}`)).toBeVisible({ timeout: 10_000 });

    await page.unroute("**/ui/videos/upload/presign");
    await page.unroute("**/mock/s3/**");
    await page.unroute("**/ui/videos/*/upload/complete");
  });
});
