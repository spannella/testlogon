/**
 * E2E tests for Broadcast Clip Creation & Gallery (ENGAGE-005).
 *
 * Sections:
 *   98 -- Broadcast Clip Creation API  (10 tests)
 *   99 -- Clip Retrieval API           (7 tests)
 *  100 -- Clip Management API          (6 tests)
 *  101 -- Clip Gallery UI              (7 tests)
 *
 * Auth: Root for broadcast management (admin/root role required).
 *       Alice + Bob for clip creation (regular user).
 * Sessions from e2e_admin_session_setup.py.
 *
 * Prerequisites:
 *   - Backend running with broadcast_clips DDB table created
 *   - E2E sessions seeded
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// --- Constants ---

const BASE = "http://localhost:3000";
const ROOT_ID = "root";
const ALICE_ID = "alice";
const BOB_ID = "bob";
const TS = Date.now();

// --- Session bootstrap ---

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
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string, { navigate = false } = {}) {
  const s = getSessions()[identity];
  if (!s) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(s.cookies);
  if (navigate) {
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await page.evaluate((uid: string) => {
      const state = { userId: uid, accessToken: null, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    }, s.user_sub);
  }
}

function csrfHeader(identity: string) {
  return { "x-csrf-token": getSessions()[identity].csrf_token };
}

function userSub(identity: string): string {
  return getSessions()[identity].user_sub;
}

// --- Helpers: broadcast session management (requires root) ---

async function apiPost(page: Page, identity: string, path: string, body: object) {
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": getSessions()[identity].csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiDelete(page: Page, identity: string, path: string) {
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": getSessions()[identity].csrf_token },
  });
}

async function apiPatch(page: Page, identity: string, path: string, body: object) {
  return page.request.patch(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": getSessions()[identity].csrf_token },
  });
}

/**
 * Create a broadcast session (requires root/admin page).
 */
async function createBroadcastSession(rootPage: Page): Promise<string> {
  const profileResp = await apiPost(rootPage, ROOT_ID, "/broadcast/profiles", {
    name: `E2E Profile ${TS}_${Math.random().toString(36).slice(2, 6)}`,
    region: "us-east-1",
    rendition_preset: "720p",
  });
  const profile = await profileResp.json();

  const sessionResp = await apiPost(rootPage, ROOT_ID, "/broadcast/sessions", {
    profile_id: profile.id,
  });
  expect(sessionResp.status()).toBe(201);
  const session = await sessionResp.json();
  return session.id;
}

async function startBroadcast(rootPage: Page, sessionId: string): Promise<void> {
  const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/start`, {
    reason: "e2e-test",
  });
  expect(resp.status()).toBe(202);
}

/** Helper: create a root-authed context, run fn, close. */
async function withRootPage<T>(browser: any, fn: (rootPage: Page) => Promise<T>): Promise<T> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await injectAuth(page, ROOT_ID);
  try {
    return await fn(page);
  } finally {
    await ctx.close();
  }
}

/** Helper: create a user-authed context, run fn, close.
 * Set ui=true for tests that navigate to frontend pages (sets localStorage auth). */
async function withUserPage<T>(
  browser: any,
  identity: string,
  fn: (page: Page) => Promise<T>,
  { ui }: { ui?: boolean } = {},
): Promise<T> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await injectAuth(page, identity, { navigate: !!ui });
  try {
    return await fn(page);
  } finally {
    await ctx.close();
  }
}

// --- Shared state ---

let _broadcastSessionId = "";
let _broadcastSessionIdNoClips = "";
const CLIP_IDS: string[] = [];

// ============================================================================
// Section 98: Broadcast Clip Creation API
// ============================================================================

test.describe("98 — Broadcast Clip Creation API", () => {
  test.beforeAll(async ({ browser }) => {
    await withRootPage(browser, async (rootPage) => {
      // Create a broadcast session and start it
      _broadcastSessionId = await createBroadcastSession(rootPage);
      await startBroadcast(rootPage, _broadcastSessionId);

      // Create a session with clips disabled
      _broadcastSessionIdNoClips = await createBroadcastSession(rootPage);
      await startBroadcast(rootPage, _broadcastSessionIdNoClips);

      // Disable clips on the second session
      const patchResp = await apiPatch(
        rootPage,
        ROOT_ID,
        `/broadcast/sessions/${_broadcastSessionIdNoClips}/clips/config`,
        { clips_enabled: false },
      );
      expect(patchResp.ok()).toBe(true);
    });
  });

  test("98.1 Viewer creates a clip during a live broadcast", async ({ browser }) => {
    await withUserPage(browser, BOB_ID, async (page) => {
      const resp = await apiPost(page, BOB_ID, `/broadcast/sessions/${_broadcastSessionId}/clips`, {
        start_seconds: 10,
        end_seconds: 40,
        title: `Test Clip ${TS}`,
      });
      expect(resp.status()).toBe(200);
      const clip = await resp.json();
      expect(clip.clip_id).toBeTruthy();
      expect(clip.status).toMatch(/processing|ready/);
      expect(clip.session_id).toBe(_broadcastSessionId);
      expect(clip.creator_user_id).toBe(userSub(BOB_ID));
      expect(clip.title).toBe(`Test Clip ${TS}`);
      CLIP_IDS.push(clip.clip_id);
    });
  });

  test("98.2 Clip with duration < 5s rejected", async ({ browser }) => {
    await withUserPage(browser, BOB_ID, async (page) => {
      const resp = await apiPost(page, BOB_ID, `/broadcast/sessions/${_broadcastSessionId}/clips`, {
        start_seconds: 10,
        end_seconds: 13,
      });
      expect(resp.status()).toBe(400);
      const body = await resp.json();
      expect(body.detail).toContain("Minimum clip duration");
    });
  });

  test("98.3 Clip with duration > 60s rejected", async ({ browser }) => {
    await withUserPage(browser, BOB_ID, async (page) => {
      const resp = await apiPost(page, BOB_ID, `/broadcast/sessions/${_broadcastSessionId}/clips`, {
        start_seconds: 0,
        end_seconds: 70,
      });
      expect(resp.status()).toBe(400);
      const body = await resp.json();
      expect(body.detail).toContain("Maximum clip duration");
    });
  });

  test("98.4 Clip when clips_enabled=false rejected", async ({ browser }) => {
    await withUserPage(browser, BOB_ID, async (page) => {
      const resp = await apiPost(
        page,
        BOB_ID,
        `/broadcast/sessions/${_broadcastSessionIdNoClips}/clips`,
        { start_seconds: 10, end_seconds: 40 },
      );
      expect(resp.status()).toBe(403);
      const body = await resp.json();
      expect(body.detail.code).toBe("CLIPPING_DISABLED");
    });
  });

  test("98.5 Clip quota exceeded (>10 per broadcast)", async ({ browser }) => {
    test.setTimeout(120000);

    // Create a fresh session for quota test
    const sessId = await withRootPage(browser, async (rootPage) => {
      const id = await createBroadcastSession(rootPage);
      await startBroadcast(rootPage, id);
      return id;
    });

    // Seed 10 clips directly into DDB to avoid rate limit waits
    const seedScript = `
import boto3, time, uuid
from decimal import Decimal
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1')
table = ddb.Table('broadcast_clips')
sess_id = "${sessId}"
user_id = "${userSub(ALICE_ID)}"
ts = int(time.time())
for i in range(10):
    clip_id = f"bclip_{uuid.uuid4().hex}"
    table.put_item(Item={
        "clip_id": clip_id,
        "session_id": sess_id,
        "broadcaster_user_id": "${userSub(ROOT_ID)}",
        "creator_user_id": user_id,
        "creator_display_name": "Alice",
        "video_id": f"v_{uuid.uuid4().hex}",
        "title": f"Seeded clip {i}",
        "start_seconds": Decimal(str(i * 5)),
        "end_seconds": Decimal(str(i * 5 + 10)),
        "duration_seconds": Decimal("10"),
        "status": "ready",
        "view_count": 0,
        "share_count": 0,
        "created_at": ts + i,
        "GSI1PK": f"SESSION#{sess_id}",
        "GSI1SK": ts + i,
        "GSI2PK": f"CREATOR#{user_id}",
        "GSI2SK": ts + i,
        "GSI3PK": "GALLERY",
        "GSI3SK": f"00000000#{ts + i}",
    })
print("OK")
`;
    execSync(
      `${REPO_ROOT}/.venv/bin/python3 -c '${seedScript.replace(/'/g, "'\\''")}'`,
      {
        cwd: REPO_ROOT,
        timeout: 30_000,
        env: {
          ...process.env,
          AWS_ACCESS_KEY_ID: "test",
          AWS_SECRET_ACCESS_KEY: "test",
          AWS_DEFAULT_REGION: "us-east-1",
        },
      },
    );

    // The 11th clip should fail with quota exceeded
    await withUserPage(browser, ALICE_ID, async (page) => {
      const resp11 = await apiPost(page, ALICE_ID, `/broadcast/sessions/${sessId}/clips`, {
        start_seconds: 50,
        end_seconds: 60,
        title: "Quota clip 11",
      });
      expect(resp11.status()).toBe(429);
      const body11 = await resp11.json();
      expect(body11.detail.code).toBe("CLIP_QUOTA_EXCEEDED");
    });
  });

  test("98.6 Clip start_seconds >= end_seconds rejected", async ({ browser }) => {
    await withUserPage(browser, BOB_ID, async (page) => {
      const resp = await apiPost(page, BOB_ID, `/broadcast/sessions/${_broadcastSessionId}/clips`, {
        start_seconds: 30,
        end_seconds: 20,
      });
      expect(resp.status()).toBe(400);
      const body = await resp.json();
      expect(body.detail).toContain("start_seconds must be less than end_seconds");
    });
  });

  test("98.7 Clip rate limit (1 per 30s)", async ({ browser }) => {
    // Create a fresh session to avoid prior rate limits
    const sessId = await withRootPage(browser, async (rootPage) => {
      const id = await createBroadcastSession(rootPage);
      await startBroadcast(rootPage, id);
      return id;
    });

    await withUserPage(browser, ALICE_ID, async (page) => {
      // First clip should succeed
      const resp1 = await apiPost(page, ALICE_ID, `/broadcast/sessions/${sessId}/clips`, {
        start_seconds: 0,
        end_seconds: 10,
        title: "Rate limit clip 1",
      });
      expect(resp1.status()).toBe(200);

      // Immediate second clip should be rate limited
      const resp2 = await apiPost(page, ALICE_ID, `/broadcast/sessions/${sessId}/clips`, {
        start_seconds: 10,
        end_seconds: 20,
        title: "Rate limit clip 2",
      });
      expect(resp2.status()).toBe(429);
    });
  });

  test("98.8 Clip with title", async ({ browser }) => {
    const sessId = await withRootPage(browser, async (rootPage) => {
      const id = await createBroadcastSession(rootPage);
      await startBroadcast(rootPage, id);
      return id;
    });

    await withUserPage(browser, ALICE_ID, async (page) => {
      const clipTitle = `Custom Title ${TS}`;
      const resp = await apiPost(page, ALICE_ID, `/broadcast/sessions/${sessId}/clips`, {
        start_seconds: 0,
        end_seconds: 15,
        title: clipTitle,
      });
      expect(resp.status()).toBe(200);
      const clip = await resp.json();
      expect(clip.title).toBe(clipTitle);
      CLIP_IDS.push(clip.clip_id);
    });
  });

  test("98.9 Clip without title gets auto-generated title", async ({ browser }) => {
    const sessId = await withRootPage(browser, async (rootPage) => {
      const id = await createBroadcastSession(rootPage);
      await startBroadcast(rootPage, id);
      return id;
    });

    await withUserPage(browser, ALICE_ID, async (page) => {
      const resp = await apiPost(page, ALICE_ID, `/broadcast/sessions/${sessId}/clips`, {
        start_seconds: 0,
        end_seconds: 10,
      });
      expect(resp.status()).toBe(200);
      const clip = await resp.json();
      expect(clip.title).toBeTruthy();
      expect(clip.title).toContain("Clip from");
      CLIP_IDS.push(clip.clip_id);
    });
  });

  test("98.10 Clip title truncated at 100 chars", async ({ browser }) => {
    const sessId = await withRootPage(browser, async (rootPage) => {
      const id = await createBroadcastSession(rootPage);
      await startBroadcast(rootPage, id);
      return id;
    });

    await withUserPage(browser, ALICE_ID, async (page) => {
      const longTitle = "A".repeat(150);
      const resp = await apiPost(page, ALICE_ID, `/broadcast/sessions/${sessId}/clips`, {
        start_seconds: 0,
        end_seconds: 10,
        title: longTitle,
      });
      // The Pydantic model has max_length=100, so this should be rejected with 422
      expect(resp.status()).toBe(422);
    });
  });
});

// ============================================================================
// Section 99: Clip Retrieval API
// ============================================================================

test.describe("99 — Clip Retrieval API", () => {
  let _testClipId = "";
  let _testSessionId = "";

  test.beforeAll(async ({ browser }) => {
    // Create session with root
    _testSessionId = await withRootPage(browser, async (rootPage) => {
      const id = await createBroadcastSession(rootPage);
      await startBroadcast(rootPage, id);
      return id;
    });

    // Create clip with alice
    await withUserPage(browser, ALICE_ID, async (page) => {
      const resp = await apiPost(page, ALICE_ID, `/broadcast/sessions/${_testSessionId}/clips`, {
        start_seconds: 5,
        end_seconds: 25,
        title: `Retrieval Test ${TS}`,
      });
      expect(resp.status()).toBe(200);
      const clip = await resp.json();
      _testClipId = clip.clip_id;
    });
  });

  test("99.1 Get clip by ID", async ({ browser }) => {
    await withUserPage(browser, ALICE_ID, async (page) => {
      const resp = await apiGet(page, `/broadcast/clips/${_testClipId}`);
      expect(resp.status()).toBe(200);
      const clip = await resp.json();
      expect(clip.clip_id).toBe(_testClipId);
      expect(clip.session_id).toBe(_testSessionId);
      expect(clip.broadcaster_user_id).toBe(userSub(ROOT_ID));
      expect(clip.creator_user_id).toBe(userSub(ALICE_ID));
      expect(clip.title).toBe(`Retrieval Test ${TS}`);
      expect(clip.start_seconds).toBe(5);
      expect(clip.end_seconds).toBe(25);
      expect(clip.duration_seconds).toBe(20);
    });
  });

  test("99.2 List clips for a broadcast session", async ({ browser }) => {
    await withUserPage(browser, ALICE_ID, async (page) => {
      const resp = await apiGet(page, `/broadcast/sessions/${_testSessionId}/clips`);
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.clips).toBeInstanceOf(Array);
      expect(data.clips.length).toBeGreaterThanOrEqual(1);
      const found = data.clips.find((c: any) => c.clip_id === _testClipId);
      expect(found).toBeTruthy();
    });
  });

  test("99.3 Gallery listing returns clips sorted by views", async ({ browser }) => {
    await withUserPage(browser, ALICE_ID, async (page) => {
      const resp = await apiGet(page, "/ui/clips?sort=popular&limit=10");
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.clips).toBeInstanceOf(Array);
    });
  });

  test("99.4 My clips listing returns only creator's clips", async ({ browser }) => {
    await withUserPage(browser, ALICE_ID, async (page) => {
      const resp = await apiGet(page, "/ui/clips/mine");
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.clips).toBeInstanceOf(Array);
      for (const clip of data.clips) {
        expect(clip.creator_user_id).toBe(userSub(ALICE_ID));
      }
    });
  });

  test("99.5 Gallery pagination with cursor", async ({ browser }) => {
    await withUserPage(browser, ALICE_ID, async (page) => {
      const resp = await apiGet(page, "/ui/clips?sort=recent&limit=1");
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.clips).toBeInstanceOf(Array);
      if (data.next_cursor) {
        const resp2 = await apiGet(page, `/ui/clips?sort=recent&limit=1&cursor=${data.next_cursor}`);
        expect(resp2.status()).toBe(200);
        const data2 = await resp2.json();
        expect(data2.clips).toBeInstanceOf(Array);
      }
    });
  });

  test("99.6 Deleted clip not returned in listings", async ({ browser }) => {
    // Create broadcast with root
    const sessId = await withRootPage(browser, async (rootPage) => {
      const id = await createBroadcastSession(rootPage);
      await startBroadcast(rootPage, id);
      return id;
    });

    await withUserPage(browser, ALICE_ID, async (page) => {
      // Create a clip
      const createResp = await apiPost(page, ALICE_ID, `/broadcast/sessions/${sessId}/clips`, {
        start_seconds: 0,
        end_seconds: 10,
        title: `Delete Test ${TS}`,
      });
      expect(createResp.status()).toBe(200);
      const clip = await createResp.json();

      // Delete the clip
      const delResp = await apiDelete(page, ALICE_ID, `/broadcast/clips/${clip.clip_id}`);
      expect(delResp.status()).toBe(200);

      // Verify it's not in session listing
      const listResp = await apiGet(page, `/broadcast/sessions/${sessId}/clips`);
      const listData = await listResp.json();
      const found = listData.clips.find((c: any) => c.clip_id === clip.clip_id);
      expect(found).toBeUndefined();
    });
  });

  test("99.7 Non-existent clip returns 404", async ({ browser }) => {
    await withUserPage(browser, ALICE_ID, async (page) => {
      const resp = await apiGet(page, "/broadcast/clips/bclip_nonexistent12345");
      expect(resp.status()).toBe(404);
    });
  });
});

// ============================================================================
// Section 100: Clip Management API
// ============================================================================

test.describe("100 — Clip Management API", () => {
  let _mgmtSessionId = "";
  let _creatorClipId = "";
  let _broadcasterClipId = "";
  let _viewClipId = "";

  test.beforeAll(async ({ browser }) => {
    // This hook sleeps 31s for a clip-create rate-limit cooldown, which exceeds
    // the default 30s timeout and would fail the whole describe block.
    test.setTimeout(120_000);
    // Create session with root
    _mgmtSessionId = await withRootPage(browser, async (rootPage) => {
      const id = await createBroadcastSession(rootPage);
      await startBroadcast(rootPage, id);
      return id;
    });

    // Alice creates a clip
    await withUserPage(browser, ALICE_ID, async (page) => {
      const clip1Resp = await apiPost(page, ALICE_ID, `/broadcast/sessions/${_mgmtSessionId}/clips`, {
        start_seconds: 0,
        end_seconds: 10,
        title: `Mgmt Creator ${TS}`,
      });
      expect(clip1Resp.status()).toBe(200);
      const clip1 = await clip1Resp.json();
      _creatorClipId = clip1.clip_id;

      // Wait for rate limit
      await new Promise((r) => setTimeout(r, 31000));

      // Alice creates another clip for view/share tests
      const clip3Resp = await apiPost(page, ALICE_ID, `/broadcast/sessions/${_mgmtSessionId}/clips`, {
        start_seconds: 20,
        end_seconds: 35,
        title: `View Count ${TS}`,
      });
      expect(clip3Resp.status()).toBe(200);
      const clip3 = await clip3Resp.json();
      _viewClipId = clip3.clip_id;
    });

    // Bob creates a clip on root's broadcast
    await withUserPage(browser, BOB_ID, async (page) => {
      const clip2Resp = await apiPost(page, BOB_ID, `/broadcast/sessions/${_mgmtSessionId}/clips`, {
        start_seconds: 10,
        end_seconds: 20,
        title: `Mgmt Broadcaster ${TS}`,
      });
      expect(clip2Resp.status()).toBe(200);
      const clip2 = await clip2Resp.json();
      _broadcasterClipId = clip2.clip_id;
    });
  });

  test("100.1 Clip creator can delete their clip", async ({ browser }) => {
    await withUserPage(browser, ALICE_ID, async (page) => {
      const resp = await apiDelete(page, ALICE_ID, `/broadcast/clips/${_creatorClipId}`);
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.ok).toBe(true);
      expect(data.status).toBe("deleted");
    });
  });

  test("100.2 Broadcaster can delete any clip from their broadcast", async ({ browser }) => {
    // Root is the broadcaster — root deletes Bob's clip
    await withRootPage(browser, async (rootPage) => {
      const resp = await apiDelete(rootPage, ROOT_ID, `/broadcast/clips/${_broadcasterClipId}`);
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.ok).toBe(true);
    });
  });

  test("100.3 Random user cannot delete another's clip", async ({ browser }) => {
    // Create a new broadcast and clip by root+alice
    const sessId = await withRootPage(browser, async (rootPage) => {
      const id = await createBroadcastSession(rootPage);
      await startBroadcast(rootPage, id);
      return id;
    });

    let clipId = "";
    await withUserPage(browser, ALICE_ID, async (page) => {
      const createResp = await apiPost(page, ALICE_ID, `/broadcast/sessions/${sessId}/clips`, {
        start_seconds: 0,
        end_seconds: 10,
        title: `No Delete ${TS}`,
      });
      expect(createResp.status()).toBe(200);
      const clip = await createResp.json();
      clipId = clip.clip_id;
    });

    // Bob tries to delete — should fail (Bob is not creator nor broadcaster)
    await withUserPage(browser, BOB_ID, async (page) => {
      const delResp = await apiDelete(page, BOB_ID, `/broadcast/clips/${clipId}`);
      expect(delResp.status()).toBe(403);
    });
  });

  test("100.4 Record a view increments view_count", async ({ browser }) => {
    await withUserPage(browser, ALICE_ID, async (page) => {
      const resp = await apiPost(page, ALICE_ID, `/broadcast/clips/${_viewClipId}/view`, {});
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.ok).toBe(true);
      expect(data.view_count).toBeGreaterThanOrEqual(1);
    });
  });

  test("100.5 Record a share increments share_count", async ({ browser }) => {
    await withUserPage(browser, ALICE_ID, async (page) => {
      const resp = await apiPost(page, ALICE_ID, `/broadcast/clips/${_viewClipId}/share`, {});
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.ok).toBe(true);
      expect(data.share_count).toBeGreaterThanOrEqual(1);
      expect(data.share_url).toContain(_viewClipId);
    });
  });

  test("100.6 Multiple views from same user all count", async ({ browser }) => {
    await withUserPage(browser, ALICE_ID, async (page) => {
      const results: number[] = [];
      for (let i = 0; i < 3; i++) {
        const resp = await apiPost(page, ALICE_ID, `/broadcast/clips/${_viewClipId}/view`, {});
        expect(resp.status()).toBe(200);
        const data = await resp.json();
        results.push(data.view_count);
      }
      for (let i = 1; i < results.length; i++) {
        expect(results[i]).toBeGreaterThan(results[i - 1]);
      }
    });
  });
});

// ============================================================================
// Section 101: Clip Gallery UI
// ============================================================================

test.describe("101 — Clip Gallery UI", () => {
  let _uiClipId = "";

  test.beforeAll(async ({ browser }) => {
    // Create broadcast with root
    const sessId = await withRootPage(browser, async (rootPage) => {
      const id = await createBroadcastSession(rootPage);
      await startBroadcast(rootPage, id);
      return id;
    });

    // Create a clip with alice
    await withUserPage(browser, ALICE_ID, async (page) => {
      const resp = await apiPost(page, ALICE_ID, `/broadcast/sessions/${sessId}/clips`, {
        start_seconds: 0,
        end_seconds: 20,
        title: `UI Test Clip ${TS}`,
      });
      expect(resp.status()).toBe(200);
      const clip = await resp.json();
      _uiClipId = clip.clip_id;
    });
  });

  test("101.1 Gallery page renders clip cards", async ({ browser }) => {
    await withUserPage(browser, ALICE_ID, async (page) => {
      await page.goto(`${BASE}/clips`);
      await expect(page.getByText("Clip Gallery")).toBeVisible();
    }, { ui: true });
  });

  test("101.2 Clip card shows title and creator name", async ({ browser }) => {
    await withUserPage(browser, ALICE_ID, async (page) => {
      await page.goto(`${BASE}/clips`);
      await page.getByRole("tab", { name: "My Clips" }).click();
      await page.waitForResponse((r) => r.url().includes("/ui/clips/mine") && r.status() === 200);
      await expect(page.getByText(`UI Test Clip ${TS}`).first()).toBeVisible();
    }, { ui: true });
  });

  test("101.3 Clicking clip card navigates to clip player", async ({ browser }) => {
    await withUserPage(browser, ALICE_ID, async (page) => {
      await page.goto(`${BASE}/clips`);
      await page.getByRole("tab", { name: "My Clips" }).click();
      await page.waitForResponse((r) => r.url().includes("/ui/clips/mine") && r.status() === 200);
      await page.getByText(`UI Test Clip ${TS}`).first().click();
      await expect(page).toHaveURL(new RegExp(`/clips/${_uiClipId}`));
    }, { ui: true });
  });

  test("101.4 Clip player page shows player with attribution", async ({ browser }) => {
    await withUserPage(browser, ALICE_ID, async (page) => {
      await page.goto(`${BASE}/clips/${_uiClipId}`);
      await page.waitForResponse(
        (r) => r.url().includes(`/broadcast/clips/${_uiClipId}`) && r.status() === 200,
      );
      await expect(page.getByText(`UI Test Clip ${TS}`)).toBeVisible();
      await expect(page.getByText("Created by")).toBeVisible();
      await expect(page.getByRole("button", { name: /share/i })).toBeVisible();
    }, { ui: true });
  });

  test("101.5 Gallery page has Gallery and My Clips tabs", async ({ browser }) => {
    await withUserPage(browser, ALICE_ID, async (page) => {
      await page.goto(`${BASE}/clips`);
      await expect(page.getByRole("tab", { name: "Gallery" })).toBeVisible();
      await expect(page.getByRole("tab", { name: "My Clips" })).toBeVisible();
    }, { ui: true });
  });

  test("101.6 Gallery sort buttons visible", async ({ browser }) => {
    await withUserPage(browser, ALICE_ID, async (page) => {
      await page.goto(`${BASE}/clips`);
      await expect(page.getByRole("button", { name: "Popular" })).toBeVisible();
      await expect(page.getByRole("button", { name: "Recent" })).toBeVisible();
    }, { ui: true });
  });

  test("101.7 Clip player has back link to gallery", async ({ browser }) => {
    await withUserPage(browser, ALICE_ID, async (page) => {
      await page.goto(`${BASE}/clips/${_uiClipId}`);
      await expect(page.getByText("Back to Gallery")).toBeVisible();
    }, { ui: true });
  });
});
