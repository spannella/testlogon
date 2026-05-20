import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import path from "path";

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const REPO_ROOT = path.resolve(process.cwd(), "..");

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
    const raw = execSync("python3 e2e_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions;
}

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function feedPost(page: Page, pathName: string, body: object, userId = ALICE_ID) {
  const session = getSessions()[userId];
  return page.request.post(`${API}${pathName}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function feedDelete(page: Page, pathName: string, userId = ALICE_ID) {
  const session = getSessions()[userId];
  return page.request.delete(`${API}${pathName}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function feedGet(page: Page, pathName: string) {
  return page.request.get(`${API}${pathName}`);
}

async function feedPatch(page: Page, pathName: string, body: object, userId = ALICE_ID) {
  const session = getSessions()[userId];
  return page.request.patch(`${API}${pathName}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

function runSchedulerOnce() {
  execSync(
    "bash -c 'set -a; source .env.local; set +a; PYTHONPATH=. .venv/bin/python3 scripts/newsfeed-scheduler-worker.py'",
    {
      cwd: REPO_ROOT,
      timeout: 20_000,
      env: {
        ...process.env,
        NEWSFEED_SCHEDULER_ITERATIONS: "1",
        NEWSFEED_SCHEDULER_PAGE_LIMIT: "100",
        NEWSFEED_SCHEDULER_MAX_BATCHES: "2",
        NEWSFEED_SCHEDULER_PUBLISH_RETRY_MAX: "3",
        NEWSFEED_SCHEDULER_RETRY_BACKOFF_SECONDS: "0.2",
      },
    },
  );
}

async function isPostInFeed(page: Page, postId: string): Promise<boolean> {
  const feedResp = await feedGet(page, "/feed");
  expect(feedResp.ok()).toBe(true);
  const payload = await feedResp.json();
  const items: Array<{ post_id: string }> = payload.items ?? payload;
  return items.some((it) => it.post_id === postId);
}

test.describe("Feed scheduled publish lifecycle", () => {
  test("near-future scheduled post stays hidden until due, then becomes visible", async ({ browser }) => {
    test.setTimeout(120_000);

    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    const now = Math.floor(Date.now() / 1000);
    const publishAt = now + 15; // API requires at least now + 6 seconds.
    const postBody = `e2e scheduled publish ${Date.now()}`;

    let postId: string | undefined;

    try {
      const createResp = await feedPost(page, "/posts", {
        body: postBody,
        publish_at: publishAt,
        schedule_timezone: "UTC",
        scheduled_at_local: "2026-04-05T00:00",
      });
      expect(createResp.ok()).toBe(true);
      const created = await createResp.json();
      postId = created.post_id;
      expect(postId).toBeTruthy();
      expect(created.status).toBe("scheduled");

      // Deterministic timing guard: before due time the post must not be visible.
      const preDueVisible = await isPostInFeed(page, postId);
      expect(preDueVisible).toBe(false);

      // Poll with scheduler-latency tolerance and force worker runs each cycle.
      const deadlineMs = Date.now() + 90_000;
      let published = false;
      while (Date.now() < deadlineMs) {
        runSchedulerOnce();
        if (await isPostInFeed(page, postId)) {
          published = true;
          break;
        }
        await page.waitForTimeout(2_000);
      }

      expect(published).toBe(true);
    } finally {
      if (postId) {
        const delResp = await feedDelete(page, `/posts/${postId}`);
        if (!delResp.ok()) {
          await feedPost(page, `/posts/${postId}/cancel`, {});
          await feedDelete(page, `/posts/${postId}`);
        }
      }
      await page.close();
    }
  });

  test("list scheduled posts returns pending items", async ({ browser }) => {
    test.setTimeout(60_000);

    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    const now = Math.floor(Date.now() / 1000);
    const publishAt = now + 120;
    const postBody = `e2e sched list ${Date.now()}`;
    let postId: string | undefined;

    try {
      const createResp = await feedPost(page, "/posts", {
        body: postBody,
        publish_at: publishAt,
        schedule_timezone: "UTC",
        scheduled_at_local: "2026-04-05T00:00",
      });
      expect(createResp.ok()).toBe(true);
      const created = await createResp.json();
      postId = created.post_id;
      expect(postId).toBeTruthy();
      expect(created.status).toBe("scheduled");

      const listResp = await feedGet(page, "/posts/scheduled");
      expect(listResp.ok()).toBe(true);
      const listData = await listResp.json();
      const items: Array<{ post_id: string; status: string }> = listData.items ?? listData;
      const found = items.find((it) => it.post_id === postId);
      expect(found).toBeTruthy();
      expect(found!.status).toBe("scheduled");
    } finally {
      if (postId) {
        await feedPost(page, `/posts/${postId}/cancel`, {});
        await feedDelete(page, `/posts/${postId}`);
      }
      await page.close();
    }
  });

  test("cancel scheduled post removes it from scheduled list", async ({ browser }) => {
    test.setTimeout(60_000);

    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    const now = Math.floor(Date.now() / 1000);
    const publishAt = now + 120;
    const postBody = `e2e sched cancel ${Date.now()}`;
    let postId: string | undefined;

    try {
      const createResp = await feedPost(page, "/posts", {
        body: postBody,
        publish_at: publishAt,
        schedule_timezone: "UTC",
        scheduled_at_local: "2026-04-05T00:00",
      });
      expect(createResp.ok()).toBe(true);
      const created = await createResp.json();
      postId = created.post_id;
      expect(postId).toBeTruthy();

      // Cancel the scheduled post
      const cancelResp = await feedPost(page, `/posts/${postId}/cancel`, {});
      expect(cancelResp.ok()).toBe(true);
      const cancelBody = await cancelResp.json();
      expect(cancelBody.status).toBe("cancelled");

      // Verify it is gone from the scheduled list
      const listResp = await feedGet(page, "/posts/scheduled");
      expect(listResp.ok()).toBe(true);
      const listData = await listResp.json();
      const items: Array<{ post_id: string }> = listData.items ?? listData;
      const found = items.find((it) => it.post_id === postId);
      expect(found).toBeFalsy();

      // Verify it is NOT in the main feed either
      const inFeed = await isPostInFeed(page, postId);
      expect(inFeed).toBe(false);
    } finally {
      // Best-effort cleanup — post is already cancelled so delete may 404
      if (postId) {
        await feedDelete(page, `/posts/${postId}`).catch(() => {});
      }
      await page.close();
    }
  });

  test("edit scheduled post updates content", async ({ browser }) => {
    test.setTimeout(60_000);

    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    const now = Math.floor(Date.now() / 1000);
    const publishAt = now + 120;
    const originalBody = `e2e sched edit orig ${Date.now()}`;
    const updatedBody = `e2e sched edit updated ${Date.now()}`;
    let postId: string | undefined;

    try {
      const createResp = await feedPost(page, "/posts", {
        body: originalBody,
        publish_at: publishAt,
        schedule_timezone: "UTC",
        scheduled_at_local: "2026-04-05T00:00",
      });
      expect(createResp.ok()).toBe(true);
      const created = await createResp.json();
      postId = created.post_id;
      expect(postId).toBeTruthy();

      // Patch the post body
      const patchResp = await feedPatch(page, `/posts/${postId}`, { body: updatedBody });
      expect(patchResp.ok()).toBe(true);
      const patched = await patchResp.json();
      expect(patched.body).toBe(updatedBody);

      // GET the post and verify body matches
      const getResp = await feedGet(page, `/posts/${postId}`);
      expect(getResp.ok()).toBe(true);
      const fetched = await getResp.json();
      expect(fetched.body).toBe(updatedBody);
    } finally {
      if (postId) {
        await feedPost(page, `/posts/${postId}/cancel`, {});
        await feedDelete(page, `/posts/${postId}`);
      }
      await page.close();
    }
  });
});
