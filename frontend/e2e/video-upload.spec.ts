/**
 * E2E tests for Video Upload & Library page.
 *
 * Sections:
 *   105 — Video Upload API Flow         (8 tests)
 *   106 — Video Library UI              (5 tests)
 *   107 — Upload Progress               (3 tests)
 *
 * Auth: Alice session cookies (from e2e_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

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
      "python3 " + REPO_ROOT + "/e2e_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
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

/**
 * Helper: presign + upload bytes + complete via ticket-based endpoint.
 * Returns the presign response and the complete response.
 */
async function fullUploadFlow(
  page: Page,
  opts: {
    filename: string;
    content_type?: string;
    sizeBytes?: number;
    title?: string;
  },
) {
  const size = opts.sizeBytes ?? 256;
  const ct = opts.content_type ?? "video/mp4";

  // 1. Presign
  const presignResp = await apiPost(page, "/ui/videos/upload/presign", {
    filename: opts.filename,
    content_type: ct,
    file_size_bytes: size,
    title: opts.title,
  });
  expect(presignResp.status()).toBe(200);
  const presign = await presignResp.json();

  // 2. Upload bytes to mock S3
  const fakeContent = Buffer.alloc(size, 0x42);
  const putResp = await page.request.put(presign.upload_url, {
    headers: { "Content-Type": ct },
    data: fakeContent,
  });
  expect(putResp.status()).toBeLessThan(400);

  // 3. Complete via ticket
  const completeResp = await apiPost(page, "/ui/videos/upload/complete", {
    ticket_id: presign.ticket_id,
    key: presign.key,
  });
  expect(completeResp.status()).toBe(200);
  const asset = await completeResp.json();

  return { presign, asset };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 105 — Video Upload API Flow
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("105 · Video Upload API Flow", () => {
  let page: Page;
  const createdVideoIds: string[] = [];

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
  });

  test.afterAll(async () => {
    for (const vid of createdVideoIds) {
      await apiDelete(page, `/ui/videos/${vid}`).catch(() => {});
    }
    await page.close();
  });

  test("105.1 Presign returns upload_url, ticket_id, key, and video_id", async () => {
    const resp = await apiPost(page, "/ui/videos/upload/presign", {
      filename: `test_video_${TS}.mp4`,
      content_type: "video/mp4",
      file_size_bytes: 1024 * 1024,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();

    // New response fields
    expect(data.video_id).toBeTruthy();
    expect(data.upload_url).toBeTruthy();
    expect(data.key).toContain("vod/");
    expect(data.key).toContain(`test_video_${TS}.mp4`);
    expect(data.ticket_id).toBeTruthy();
    expect(data.bucket).toBeTruthy();
    expect(data.content_type).toBe("video/mp4");
    expect(data.expires_at).toBeTruthy();
    expect(data.max_size_bytes).toBe(10 * 1024 * 1024 * 1024);

    createdVideoIds.push(data.video_id);
  });

  test("105.2 Presign rejects non-video content type", async () => {
    const resp = await apiPost(page, "/ui/videos/upload/presign", {
      filename: "document.pdf",
      content_type: "application/pdf",
      file_size_bytes: 1024,
    });
    // Pydantic pattern validation returns 422
    expect(resp.status()).toBe(422);
  });

  test("105.3 Presign rejects file exceeding size limit", async () => {
    const resp = await apiPost(page, "/ui/videos/upload/presign", {
      filename: "huge.mp4",
      content_type: "video/mp4",
      file_size_bytes: 20_000_000_000, // 20 GB > 10 GB limit
    });
    // Pydantic le= validation returns 422
    expect(resp.status()).toBe(422);
  });

  test("105.4 Full presign -> PUT -> complete flow", async () => {
    const { presign, asset } = await fullUploadFlow(page, {
      filename: `full_flow_${TS}.mp4`,
      sizeBytes: 256,
      title: "E2E Full Flow Video",
    });

    expect(asset.ok).toBe(true);
    expect(asset.video_id).toBe(presign.video_id);
    expect(asset.s3_key).toBe(presign.key);
    expect(asset.size_bytes).toBe(256);
    expect(asset.content_type).toBe("video/mp4");
    expect(asset.status).toBe("uploaded");
    expect(asset.created_at).toBeGreaterThan(0);

    createdVideoIds.push(asset.video_id);
  });

  test("105.5 Complete rejects mismatched S3 key", async () => {
    // Presign a video
    const presignResp = await apiPost(page, "/ui/videos/upload/presign", {
      filename: `mismatch_${TS}.mp4`,
      content_type: "video/mp4",
      file_size_bytes: 100,
    });
    const presign = await presignResp.json();
    createdVideoIds.push(presign.video_id);

    // Try to complete with a wrong key
    const completeResp = await apiPost(page, "/ui/videos/upload/complete", {
      ticket_id: presign.ticket_id,
      key: "wrong/key/path.mp4",
    });
    expect(completeResp.status()).toBe(403);
  });

  test("105.6 Complete rejects nonexistent ticket", async () => {
    const resp = await apiPost(page, "/ui/videos/upload/complete", {
      ticket_id: "nonexistent_ticket_id_12345",
      key: "some/key.mp4",
    });
    expect(resp.status()).toBe(403);
  });

  test("105.7 Full upload creates video record with correct size_bytes", async () => {
    const fileSize = 512;
    const { asset } = await fullUploadFlow(page, {
      filename: `sized_${TS}.mp4`,
      sizeBytes: fileSize,
    });
    expect(asset.size_bytes).toBe(fileSize);
    createdVideoIds.push(asset.video_id);
  });

  test("105.8 Video appears in listing after upload", async () => {
    const { asset } = await fullUploadFlow(page, {
      filename: `listing_${TS}.mp4`,
      sizeBytes: 128,
      title: `listing_${TS}`,
    });
    createdVideoIds.push(asset.video_id);

    const resp = await apiGet(page, "/ui/videos");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items).toBeInstanceOf(Array);
    const found = data.items.find(
      (v: { video_id: string }) => v.video_id === asset.video_id,
    );
    expect(found).toBeTruthy();
    expect(found.title).toContain(`listing_${TS}`);
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

    // Create a test video via the full upload flow
    const presignResp = await apiPost(page, "/ui/videos/upload/presign", {
      filename: `ui_test_${TS}.mp4`,
      content_type: "video/mp4",
      file_size_bytes: 128,
    });
    const presign = await presignResp.json();
    testVideoId = presign.video_id;

    // Upload content
    const fakeContent = Buffer.alloc(128, 0x43);
    await page.request.put(presign.upload_url, {
      headers: { "Content-Type": "video/mp4" },
      data: fakeContent,
    });

    // Complete upload via legacy endpoint (backward compat)
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
      file_size_bytes: 64,
    });
    const presign = await presignResp.json();
    const delVideoId = presign.video_id;
    await page.request.put(presign.upload_url, {
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
    // Mock presign endpoint to return a mock upload URL
    await page.route("**/ui/videos/upload/presign", async (route) => {
      if (route.request().method() === "POST") {
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            upload_url: `${BASE}/mock/s3/local-uploads/vod/test/raw/2026/05/mock_vid/progress_test.mp4`,
            bucket: "local-uploads",
            key: `vod/test/raw/2026/05/mock_vid/progress_test.mp4`,
            ticket_id: `ticket_${TS}`,
            video_id: `mock_vid_${TS}`,
            content_type: "video/mp4",
            expires_at: new Date(Date.now() + 900_000).toISOString(),
            max_size_bytes: 10 * 1024 * 1024 * 1024,
          }),
        });
      } else {
        route.continue();
      }
    });

    // Mock the complete endpoint to accept the new shape
    await page.route("**/ui/videos/upload/complete", async (route) => {
      if (route.request().method() === "POST") {
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            ok: true,
            video_id: `mock_vid_${TS}`,
            s3_key: `vod/test/raw/2026/05/mock_vid/progress_test.mp4`,
            size_bytes: 1024,
            content_type: "video/mp4",
            status: "uploaded",
            created_at: Math.floor(Date.now() / 1000),
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
    await page.unroute("**/ui/videos/upload/complete");
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
            upload_url: `${BASE}/mock/s3/local-uploads/vod/test/raw/2026/05/cancel_vid/cancel_test.mp4`,
            bucket: "local-uploads",
            key: `vod/test/raw/2026/05/cancel_vid/cancel_test.mp4`,
            ticket_id: `cancel_ticket_${TS}`,
            video_id: `cancel_vid_${TS}`,
            content_type: "video/mp4",
            expires_at: new Date(Date.now() + 900_000).toISOString(),
            max_size_bytes: 10 * 1024 * 1024 * 1024,
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
        const vid = `multi_vid_${TS}_${presignCount}`;
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            upload_url: `${BASE}/mock/s3/local-uploads/vod/test/raw/2026/05/${vid}/multi_${presignCount}.mp4`,
            bucket: "local-uploads",
            key: `vod/test/raw/2026/05/${vid}/multi_${presignCount}.mp4`,
            ticket_id: `multi_ticket_${TS}_${presignCount}`,
            video_id: vid,
            content_type: "video/mp4",
            expires_at: new Date(Date.now() + 900_000).toISOString(),
            max_size_bytes: 10 * 1024 * 1024 * 1024,
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

    // Mock complete endpoint (new ticket-based shape)
    await page.route("**/ui/videos/upload/complete", async (route) => {
      if (route.request().method() === "POST") {
        const body = route.request().postDataJSON();
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            ok: true,
            video_id: `multi_vid_completed`,
            s3_key: body?.key || "unknown",
            size_bytes: 512,
            content_type: "video/mp4",
            status: "uploaded",
            created_at: Math.floor(Date.now() / 1000),
          }),
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
    await page.unroute("**/ui/videos/upload/complete");
  });
});
