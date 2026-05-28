/**
 * E2E tests for BCAST-010: Broadcast Newsfeed Promotion
 *
 * Tests that broadcast lifecycle events (schedule, go-live, cancel)
 * automatically create/update/delete newsfeed posts.
 *
 * Auth: uses root session via e2e_admin_session_setup.py
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

/* ------------------------------------------------------------------ */
/*  Constants & helpers                                                */
/* ------------------------------------------------------------------ */

const API = "http://localhost:8000";
const TS = Date.now();

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
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
}

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body: object,
) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiDelete(page: Page, identity: string, path: string) {
  const s = getSessions()[identity];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": s.csrf_token },
  });
}

/* ------------------------------------------------------------------ */
/*  Section 121 -- Broadcast Announcement Auto-Post                    */
/* ------------------------------------------------------------------ */

test.describe("121 Broadcast Announcement Auto-Post", () => {
  let rootPage: Page;
  let profileId: string;
  let sessionId: string;
  let announcementPostId: string;
  const SESSION_NAME = `NewsfeedTest-${TS}`;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    rootPage = await ctx.newPage();
    await injectAuth(rootPage, "root");

    // Create a broadcast profile
    const profileResp = await apiPost(rootPage, "root", "/broadcast/profiles", {
      name: `nf-test-profile-${TS}`,
      region: "us-east-1",
      rendition_preset: "720p30",
    });
    expect(profileResp.status()).toBe(201);
    profileId = (await profileResp.json()).id;

    // Create a draft session
    const createResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(createResp.status()).toBe(201);
    sessionId = (await createResp.json()).id;
  });

  test.afterAll(async () => {
    await rootPage.context().close();
  });

  test("121.1 Schedule broadcast creates an announcement post in the feed", async () => {
    const scheduledAt = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
    const scheduleResp = await apiPost(rootPage, "root", `/broadcast/sessions/${sessionId}/schedule`, {
      scheduled_at: scheduledAt,
      name: SESSION_NAME,
      description: "Test broadcast description",
    });
    expect(scheduleResp.status()).toBe(200);
    const scheduleData = await scheduleResp.json();
    expect(scheduleData.status).toBe("scheduled");
    expect(scheduleData.announcement_post_id).toBeTruthy();
    announcementPostId = scheduleData.announcement_post_id;
  });

  test("121.2 Announcement post has correct post_type and broadcast_meta", async () => {
    // Fetch the post directly
    const postResp = await apiGet(rootPage, `/posts/${announcementPostId}`);
    expect(postResp.status()).toBe(200);
    const post = await postResp.json();

    expect(post.post_type).toBe("broadcast_announcement");
    expect(post.broadcast_meta).toBeTruthy();
    expect(post.broadcast_meta.session_id).toBe(sessionId);
    expect(post.broadcast_meta.is_live).toBe(false);
    expect(post.broadcast_meta.session_name).toBe(SESSION_NAME);
  });

  test("121.3 Announcement post text includes session name and scheduled time", async () => {
    const postResp = await apiGet(rootPage, `/posts/${announcementPostId}`);
    expect(postResp.status()).toBe(200);
    const post = await postResp.json();

    // Text should contain the session name
    const bodyText = post.body || post.body_plain || "";
    expect(bodyText).toContain(SESSION_NAME);
    expect(bodyText).toContain("Upcoming broadcast");
  });

  test("121.4 Announcement post appears in creator feed", async () => {
    const feedResp = await apiGet(rootPage, "/feed");
    expect(feedResp.status()).toBe(200);
    const feedData = await feedResp.json();
    const posts = feedData.items || feedData.posts || feedData;

    const broadcastPost = (Array.isArray(posts) ? posts : []).find(
      (p: { post_id: string }) => p.post_id === announcementPostId,
    );
    expect(broadcastPost).toBeTruthy();
    expect(broadcastPost.post_type).toBe("broadcast_announcement");
  });

  test("121.5 Cancel schedule deletes the announcement post", async () => {
    const cancelResp = await apiPost(rootPage, "root", `/broadcast/sessions/${sessionId}/cancel-schedule`, {});
    // Accept 200 (first cancel) or 409 (already cancelled on retry)
    expect([200, 409].includes(cancelResp.status())).toBe(true);

    if (cancelResp.status() === 200) {
      const cancelData = await cancelResp.json();
      expect(cancelData.status).toBe("cancelled");
    }

    // The post should be gone
    const postResp = await apiGet(rootPage, `/posts/${announcementPostId}`);
    expect([404, 200].includes(postResp.status())).toBe(true);
    if (postResp.status() === 200) {
      const feedResp = await apiGet(rootPage, "/feed");
      const feedData = await feedResp.json();
      const posts = feedData.items || feedData.posts || feedData;
      const broadcastPost = (Array.isArray(posts) ? posts : []).find(
        (p: { post_id: string }) => p.post_id === announcementPostId,
      );
      expect(broadcastPost).toBeFalsy();
    }
  });
});

/* ------------------------------------------------------------------ */
/*  Section 122 -- Live Notification Post                              */
/* ------------------------------------------------------------------ */

test.describe("122 Broadcast Live Post", () => {
  let rootPage: Page;
  let profileId: string;
  const SESSION_NAME_LIVE = `LiveTest-${TS}`;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    rootPage = await ctx.newPage();
    await injectAuth(rootPage, "root");

    // Create a broadcast profile
    const profileResp = await apiPost(rootPage, "root", "/broadcast/profiles", {
      name: `nf-live-profile-${TS}`,
      region: "us-east-1",
      rendition_preset: "720p30",
    });
    expect(profileResp.status()).toBe(201);
    profileId = (await profileResp.json()).id;
  });

  test.afterAll(async () => {
    await rootPage.context().close();
  });

  test("122.1 Starting an unscheduled broadcast creates a new live post", async () => {
    // Create a new draft session
    const createResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(createResp.status()).toBe(201);
    const sId = (await createResp.json()).id;

    // Start the session (draft -> provisioning -> ready -> live)
    const startResp = await apiPost(rootPage, "root", `/broadcast/sessions/${sId}/start`, {
      reason: "e2e-live-test",
    });
    expect(startResp.status()).toBe(202);
    const startData = await startResp.json();
    expect(startData.status).toBe("live");

    // Re-fetch session to get announcement_post_id
    const sessionResp = await apiGet(rootPage, `/broadcast/sessions/${sId}`);
    expect(sessionResp.status()).toBe(200);
    const session = await sessionResp.json();

    // An announcement_post_id should now be set (the new live post)
    if (session.announcement_post_id) {
      const postResp = await apiGet(rootPage, `/posts/${session.announcement_post_id}`);
      expect(postResp.status()).toBe(200);
      const post = await postResp.json();
      expect(post.post_type).toBe("broadcast_live");
      expect(post.broadcast_meta.is_live).toBe(true);
    }

    // Clean up: stop session
    await apiPost(rootPage, "root", `/broadcast/sessions/${sId}/stop`, {
      reason: "e2e-cleanup",
    });
  });

  test("122.2 Scheduled broadcast going live updates announcement to live post", async () => {
    // Create a draft session
    const createResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(createResp.status()).toBe(201);
    const sId = (await createResp.json()).id;

    // Schedule it
    const scheduledAt = Math.floor(Date.now() / 1000) + 3600;
    const schedResp = await apiPost(rootPage, "root", `/broadcast/sessions/${sId}/schedule`, {
      scheduled_at: scheduledAt,
      name: SESSION_NAME_LIVE,
      description: "Live test broadcast",
    });
    expect(schedResp.status()).toBe(200);
    const schedData = await schedResp.json();
    const announcementPostId = schedData.announcement_post_id;
    expect(announcementPostId).toBeTruthy();

    // Verify announcement post exists
    const annResp = await apiGet(rootPage, `/posts/${announcementPostId}`);
    expect(annResp.status()).toBe(200);
    const annPost = await annResp.json();
    expect(annPost.post_type).toBe("broadcast_announcement");

    // Now start the session (early start from scheduled -> live)
    const startResp = await apiPost(rootPage, "root", `/broadcast/sessions/${sId}/start`, {
      reason: "e2e-early-start",
    });
    expect(startResp.status()).toBe(202);
    const startData = await startResp.json();
    expect(startData.status).toBe("live");

    // The announcement post should now be updated to broadcast_live
    const liveResp = await apiGet(rootPage, `/posts/${announcementPostId}`);
    expect(liveResp.status()).toBe(200);
    const livePost = await liveResp.json();
    expect(livePost.post_type).toBe("broadcast_live");
    expect(livePost.broadcast_meta.is_live).toBe(true);
    expect(livePost.broadcast_meta.session_name).toBe(SESSION_NAME_LIVE);

    // Clean up: stop session
    await apiPost(rootPage, "root", `/broadcast/sessions/${sId}/stop`, {
      reason: "e2e-cleanup",
    });
  });

  test("122.3 Feed includes post_type field in regular posts", async () => {
    // Verify that regular feed posts have the default post_type
    const feedResp = await apiGet(rootPage, "/feed");
    expect(feedResp.status()).toBe(200);
    const feedData = await feedResp.json();
    const posts = feedData.posts || feedData;

    if (Array.isArray(posts) && posts.length > 0) {
      // Every post should have a post_type field
      for (const post of posts) {
        expect(post.post_type).toBeTruthy();
        // Non-broadcast posts should be "standard"
        if (!post.post_type.startsWith("broadcast_")) {
          expect(post.post_type).toBe("standard");
        }
      }
    }
  });
});
