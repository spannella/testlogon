import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

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
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
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
  body?: object,
) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
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

/**
 * Create a live broadcast session for testing.
 * Uses root identity to start (requires operator role).
 */
async function createLiveSession(rootPage: Page): Promise<string> {
  // Create profile
  const profileResp = await apiPost(rootPage, "root", "/broadcast/profiles", {
    name: `Health Test Profile ${TS}_${Math.random().toString(36).slice(2, 8)}`,
    region: "us-east-1",
    rendition_preset: "720p_3mbps",
  });
  expect(profileResp.status()).toBe(201);
  const profile = await profileResp.json();

  // Create session
  const sessionResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
    profile_id: profile.id,
  });
  expect(sessionResp.status()).toBe(201);
  const session = await sessionResp.json();

  // Start session (transitions: draft -> live for local provider)
  const startResp = await apiPost(
    rootPage,
    "root",
    `/broadcast/sessions/${session.id}/start`,
    { reason: "e2e-health-test" },
  );
  expect(startResp.status()).toBe(202);

  // Wait for live status
  await expect
    .poll(
      async () => {
        const r = await apiGet(rootPage, `/broadcast/sessions/${session.id}`);
        const d = await r.json();
        return d.status;
      },
      { timeout: 10000 },
    )
    .toBe("live");

  return session.id;
}

/* ------------------------------------------------------------------ */
/*  Section 90 — Viewer Join/Leave API                                */
/* ------------------------------------------------------------------ */

test.describe("Section 90: Viewer Join/Leave API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, "root");

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    sessionId = await createLiveSession(rootPage);
  });

  test.afterAll(async () => {
    // Stop the session
    await apiPost(rootPage, "root", `/broadcast/sessions/${sessionId}/stop`, {
      reason: "cleanup",
    });
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("90.1 joining a live session returns viewer_id and count", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/viewers/join`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.viewer_id).toContain(getSessions().alice.user_sub);
    expect(body.session_id).toBe(sessionId);
    expect(body.viewer_count).toBeGreaterThanOrEqual(1);
  });

  test("90.2 heartbeat extends viewer TTL and returns count", async () => {
    // First join
    const joinResp = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/viewers/join`,
    );
    const { viewer_id } = await joinResp.json();

    // Heartbeat
    const hbResp = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/viewers/heartbeat?viewer_id=${encodeURIComponent(viewer_id)}`,
    );
    expect(hbResp.status()).toBe(200);
    const hbBody = await hbResp.json();
    expect(hbBody.ok).toBe(true);
    expect(hbBody.viewer_count).toBeGreaterThanOrEqual(1);
  });

  test("90.3 explicit leave decrements viewer count", async () => {
    // Join
    const joinResp = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/viewers/join`,
    );
    const { viewer_id } = await joinResp.json();

    // Get count before leave
    const beforeResp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/viewers/count`,
    );
    const beforeCount = (await beforeResp.json()).viewer_count;

    // Leave
    const leaveResp = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/viewers/leave?viewer_id=${encodeURIComponent(viewer_id)}`,
    );
    expect(leaveResp.status()).toBe(200);
    const leaveBody = await leaveResp.json();
    expect(leaveBody.ok).toBe(true);
    expect(leaveBody.viewer_count).toBeLessThan(beforeCount);
  });

  test("90.4 joining non-existent session returns 404", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      "/broadcast/sessions/nonexistent-session-id/viewers/join",
    );
    expect(resp.status()).toBe(404);
  });

  test("90.5 multiple viewers produce accurate count", async () => {
    // Join 3 viewers
    const viewerIds: string[] = [];
    for (let i = 0; i < 3; i++) {
      const resp = await apiPost(
        alicePage,
        "alice",
        `/broadcast/sessions/${sessionId}/viewers/join`,
      );
      const body = await resp.json();
      viewerIds.push(body.viewer_id);
    }

    // Check count
    const countResp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/viewers/count`,
    );
    const countBody = await countResp.json();
    // Count should include these 3 + any leftover from previous tests
    expect(countBody.viewer_count).toBeGreaterThanOrEqual(3);

    // Cleanup
    for (const vid of viewerIds) {
      await apiPost(
        alicePage,
        "alice",
        `/broadcast/sessions/${sessionId}/viewers/leave?viewer_id=${encodeURIComponent(vid)}`,
      );
    }
  });
});

/* ------------------------------------------------------------------ */
/*  Section 91 — Viewer Count Polling                                 */
/* ------------------------------------------------------------------ */

test.describe("Section 91: Viewer Count Polling", () => {
  let rootPage: Page;
  let alicePage: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, "root");

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    sessionId = await createLiveSession(rootPage);
  });

  test.afterAll(async () => {
    await apiPost(rootPage, "root", `/broadcast/sessions/${sessionId}/stop`, {
      reason: "cleanup",
    });
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("91.1 GET viewer count returns 0 for session with no viewers", async () => {
    const resp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/viewers/count`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.session_id).toBe(sessionId);
    expect(body.viewer_count).toBe(0);
  });

  test("91.2 GET viewer count reflects active viewers", async () => {
    // Join two viewers
    const r1 = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/viewers/join`,
    );
    const vid1 = (await r1.json()).viewer_id;

    const r2 = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/viewers/join`,
    );
    const vid2 = (await r2.json()).viewer_id;

    // Count should be 2
    const countResp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/viewers/count`,
    );
    expect((await countResp.json()).viewer_count).toBe(2);

    // Cleanup
    await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/viewers/leave?viewer_id=${encodeURIComponent(vid1)}`,
    );
    await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/viewers/leave?viewer_id=${encodeURIComponent(vid2)}`,
    );
  });

  test("91.3 viewer count decreases after explicit leave", async () => {
    const r1 = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/viewers/join`,
    );
    const vid1 = (await r1.json()).viewer_id;

    const r2 = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/viewers/join`,
    );
    const vid2 = (await r2.json()).viewer_id;

    // Leave one
    await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/viewers/leave?viewer_id=${encodeURIComponent(vid1)}`,
    );

    const countResp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/viewers/count`,
    );
    expect((await countResp.json()).viewer_count).toBe(1);

    // Cleanup
    await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/viewers/leave?viewer_id=${encodeURIComponent(vid2)}`,
    );
  });

  test("91.4 viewer count is accurate with concurrent joins and leaves", async () => {
    // Join 5 viewers
    const viewerIds: string[] = [];
    for (let i = 0; i < 5; i++) {
      const resp = await apiPost(
        alicePage,
        "alice",
        `/broadcast/sessions/${sessionId}/viewers/join`,
      );
      viewerIds.push((await resp.json()).viewer_id);
    }

    // Leave 2
    await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/viewers/leave?viewer_id=${encodeURIComponent(viewerIds[0])}`,
    );
    await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/viewers/leave?viewer_id=${encodeURIComponent(viewerIds[1])}`,
    );

    const countResp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/viewers/count`,
    );
    expect((await countResp.json()).viewer_count).toBe(3);

    // Cleanup remaining
    for (let i = 2; i < 5; i++) {
      await apiPost(
        alicePage,
        "alice",
        `/broadcast/sessions/${sessionId}/viewers/leave?viewer_id=${encodeURIComponent(viewerIds[i])}`,
      );
    }
  });
});

/* ------------------------------------------------------------------ */
/*  Section 92 — Health Metrics API                                   */
/* ------------------------------------------------------------------ */

test.describe("Section 92: Health Metrics API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, "root");

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    sessionId = await createLiveSession(rootPage);
  });

  test.afterAll(async () => {
    await apiPost(rootPage, "root", `/broadcast/sessions/${sessionId}/stop`, {
      reason: "cleanup",
    });
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("92.1 POST health report stores snapshot", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${sessionId}/health/report`,
      {
        ingest_bitrate_kbps: 4500,
        ingest_framerate: 30,
        dropped_frames: 2,
        dropped_frames_pct: 0.02,
        output_errors: 0,
        input_loss_seconds: 0,
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.session_id).toBe(sessionId);
    expect(body.ingest_bitrate_kbps).toBe(4500);
    expect(body.connection_quality).toBe("excellent");
    expect(body.updated_at).toBeGreaterThan(0);
  });

  test("92.2 GET health returns latest snapshot", async () => {
    const resp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/health`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.session_id).toBe(sessionId);
    expect(body.ingest_bitrate_kbps).toBe(4500);
    expect(body.connection_quality).toBe("excellent");
  });

  test("92.3 GET health history returns multiple snapshots", async () => {
    // Wait 1s to ensure a distinct timestamp from the 92.1 report
    await new Promise((r) => setTimeout(r, 1100));

    // Report additional snapshots with distinct timestamps
    await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${sessionId}/health/report`,
      {
        ingest_bitrate_kbps: 3000,
        ingest_framerate: 30,
        dropped_frames: 10,
        dropped_frames_pct: 0.3,
        output_errors: 0,
        input_loss_seconds: 0,
      },
    );

    // Wait 1s to ensure a distinct snapshot_ts (integer seconds)
    await new Promise((r) => setTimeout(r, 1100));

    await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${sessionId}/health/report`,
      {
        ingest_bitrate_kbps: 1500,
        ingest_framerate: 24,
        dropped_frames: 50,
        dropped_frames_pct: 1.5,
        output_errors: 1,
        input_loss_seconds: 0.5,
      },
    );

    const resp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/health/history?limit=10`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.session_id).toBe(sessionId);
    expect(body.snapshots.length).toBeGreaterThanOrEqual(3);
  });

  test("92.4 connection_quality is classified correctly from report data", async () => {
    // Report critical quality metrics
    const resp = await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${sessionId}/health/report`,
      {
        ingest_bitrate_kbps: 100,
        ingest_framerate: 10,
        dropped_frames: 500,
        dropped_frames_pct: 15.0,
        output_errors: 5,
        input_loss_seconds: 10,
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.connection_quality).toBe("critical");
  });

  test("92.5 health report for non-live session returns 409", async () => {
    // Create a draft session (not started)
    const profileResp = await apiPost(rootPage, "root", "/broadcast/profiles", {
      name: `Draft Profile ${TS}_409`,
      region: "us-east-1",
      rendition_preset: "720p30",
    });
    const profile = await profileResp.json();
    const sessionResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
      profile_id: profile.id,
    });
    const draftSession = await sessionResp.json();

    const resp = await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${draftSession.id}/health/report`,
      {
        ingest_bitrate_kbps: 4500,
        ingest_framerate: 30,
        dropped_frames: 0,
        dropped_frames_pct: 0,
      },
    );
    expect(resp.status()).toBe(409);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 93 — Broadcast SSE Stream                                 */
/* ------------------------------------------------------------------ */

test.describe("Section 93: Broadcast SSE Stream", () => {
  let rootPage: Page;
  let alicePage: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, "root");

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    // Navigate alice to a page so we can run evaluate (must be same origin for SSE proxy)
    await alicePage.goto("http://localhost:3000/login");
    await alicePage.waitForLoadState("domcontentloaded");

    sessionId = await createLiveSession(rootPage);
  });

  test.afterAll(async () => {
    await apiPost(rootPage, "root", `/broadcast/sessions/${sessionId}/stop`, {
      reason: "cleanup",
    });
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("93.1 SSE stream emits hello event on connect", async () => {
    // Set up SSE listener in browser (use proxied path through Vite on same origin)
    await alicePage.evaluate((sid) => {
      (window as any).__sseEvents = [];
      (window as any).__sseHello = false;
      (window as any).__sseError = null;
      const es = new EventSource(`/broadcast/sessions/${sid}/stream`);
      es.addEventListener("hello", () => {
        (window as any).__sseHello = true;
      });
      es.addEventListener("viewer_count", (e: any) => {
        (window as any).__sseEvents.push(JSON.parse(e.data));
      });
      es.addEventListener("health_update", (e: any) => {
        (window as any).__sseEvents.push({ _type: "health_update", ...JSON.parse(e.data) });
      });
      es.onerror = (e: any) => {
        (window as any).__sseError = "error";
      };
      (window as any).__sseClose = () => es.close();
    }, sessionId);

    // Wait for hello event
    await expect
      .poll(
        async () => alicePage.evaluate(() => (window as any).__sseHello),
        { timeout: 10000 },
      )
      .toBe(true);

    // Cleanup
    await alicePage.evaluate(() => (window as any).__sseClose());
  });

  test("93.2 viewer join triggers viewer_count event on stream", async () => {
    // Set up SSE listener
    await alicePage.evaluate((sid) => {
      (window as any).__sseEvents = [];
      (window as any).__sseReady = false;
      const es = new EventSource(`/broadcast/sessions/${sid}/stream`);
      es.addEventListener("hello", () => {
        (window as any).__sseReady = true;
      });
      es.addEventListener("viewer_count", (e: any) => {
        (window as any).__sseEvents.push(JSON.parse(e.data));
      });
      (window as any).__sseClose = () => es.close();
    }, sessionId);

    // Wait for SSE to be ready (hello event received)
    await expect
      .poll(
        async () => alicePage.evaluate(() => (window as any).__sseReady),
        { timeout: 10000 },
      )
      .toBe(true);

    // Trigger viewer join (from root page)
    const joinResp = await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${sessionId}/viewers/join`,
    );
    const { viewer_id } = await joinResp.json();

    // Wait for SSE event
    await expect
      .poll(
        async () => alicePage.evaluate(() => (window as any).__sseEvents.length),
        { timeout: 10000 },
      )
      .toBeGreaterThan(0);

    const events = await alicePage.evaluate(
      () => (window as any).__sseEvents,
    );
    const vcEvent = events.find((e: any) => e.delta === 1);
    expect(vcEvent).toBeTruthy();
    expect(vcEvent.viewer_count).toBeGreaterThanOrEqual(1);

    // Cleanup
    await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${sessionId}/viewers/leave?viewer_id=${encodeURIComponent(viewer_id)}`,
    );
    await alicePage.evaluate(() => (window as any).__sseClose());
  });

  test("93.3 health report triggers health_update event on stream", async () => {
    // Set up SSE listener
    await alicePage.evaluate((sid) => {
      (window as any).__sseHealthEvents = [];
      (window as any).__sseReady2 = false;
      const es = new EventSource(`/broadcast/sessions/${sid}/stream`);
      es.addEventListener("hello", () => {
        (window as any).__sseReady2 = true;
      });
      es.addEventListener("health_update", (e: any) => {
        (window as any).__sseHealthEvents.push(JSON.parse(e.data));
      });
      (window as any).__sseClose2 = () => es.close();
    }, sessionId);

    // Wait for SSE to be ready
    await expect
      .poll(
        async () => alicePage.evaluate(() => (window as any).__sseReady2),
        { timeout: 10000 },
      )
      .toBe(true);

    // Report health
    await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${sessionId}/health/report`,
      {
        ingest_bitrate_kbps: 5000,
        ingest_framerate: 60,
        dropped_frames: 0,
        dropped_frames_pct: 0,
        output_errors: 0,
        input_loss_seconds: 0,
      },
    );

    // Wait for SSE event
    await expect
      .poll(
        async () =>
          alicePage.evaluate(
            () => (window as any).__sseHealthEvents.length,
          ),
        { timeout: 10000 },
      )
      .toBeGreaterThan(0);

    const events = await alicePage.evaluate(
      () => (window as any).__sseHealthEvents,
    );
    expect(events[0].ingest_bitrate_kbps).toBe(5000);
    expect(events[0].connection_quality).toBe("excellent");

    // Cleanup
    await alicePage.evaluate(() => (window as any).__sseClose2());
  });

  test("93.4 SSE stream returns 404 for non-existent session", async () => {
    const resp = await apiGet(
      alicePage,
      "/broadcast/sessions/nonexistent-session-xyz/stream",
    );
    expect(resp.status()).toBe(404);
  });
});
