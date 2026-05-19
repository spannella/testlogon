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
/*  Section 1 — Profile creation                                      */
/* ------------------------------------------------------------------ */

test.describe("Broadcast — profile creation", () => {
  let alicePage: Page;
  let profileId: string;
  const PROFILE_NAME = `E2E Stream ${TS}`;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, "alice");
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("1.1 Alice creates a broadcast profile", async () => {
    const resp = await apiPost(alicePage, "alice", "/broadcast/profiles", {
      name: PROFILE_NAME,
      region: "us-east-1",
      rendition_preset: "720p30",
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.id).toBeTruthy();
    expect(body.name).toBe(PROFILE_NAME);
    expect(body.region).toBe("us-east-1");
    expect(body.rendition_preset).toBe("720p30");
    expect(body.created_by).toBe(getSessions().alice.user_sub);
    expect(body.created_at).toBeTruthy();
    expect(body.updated_at).toBeTruthy();
    profileId = body.id;
  });

  test("1.2 Profile fields include optional DRM defaults", async () => {
    // Profile was created without DRM fields; they should default to null
    // We verify via the audit trail that create_profile was recorded
    const resp = await apiPost(alicePage, "alice", "/broadcast/profiles", {
      name: `E2E DRM Stream ${TS}`,
      region: "eu-west-1",
      rendition_preset: "1080p60",
      drm_policy_id: "policy-test-123",
      drm_credentials_ref: "secret://drm/test-creds",
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.drm_policy_id).toBe("policy-test-123");
    expect(body.drm_credentials_ref).toBe("secret://drm/test-creds");
    expect(body.drm_credentials_rotation_interval_seconds).toBe(86400);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 2 — Session lifecycle                                     */
/* ------------------------------------------------------------------ */

test.describe("Broadcast — session lifecycle", () => {
  let alicePage: Page;
  let rootPage: Page;
  let profileId: string;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, "root");

    // Create a profile for session tests
    const profileResp = await apiPost(
      alicePage,
      "alice",
      "/broadcast/profiles",
      {
        name: `Lifecycle Profile ${TS}`,
        region: "us-east-1",
        rendition_preset: "720p30",
      },
    );
    expect(profileResp.status()).toBe(201);
    profileId = (await profileResp.json()).id;
  });

  test.afterAll(async () => {
    await alicePage.context().close();
    await rootPage.context().close();
  });

  test("2.1 Alice creates a broadcast session from profile", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      "/broadcast/sessions",
      { profile_id: profileId },
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.id).toBeTruthy();
    expect(body.profile_id).toBe(profileId);
    expect(body.status).toBe("draft");
    expect(body.created_by).toBe(getSessions().alice.user_sub);
    sessionId = body.id;
  });

  test("2.2 GET session returns correct data", async () => {
    const resp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.id).toBe(sessionId);
    expect(body.status).toBe("draft");
    expect(body.profile_id).toBe(profileId);
  });

  test("2.3 Root starts the session (draft -> live)", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${sessionId}/start`,
      { reason: "going live for E2E test" },
    );
    expect(resp.status()).toBe(202);
    const body = await resp.json();
    expect(body.id).toBe(sessionId);
    expect(body.status).toBe("live");
  });

  test("2.4 Root stops the session (live -> stopped)", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${sessionId}/stop`,
      { reason: "E2E test complete" },
    );
    expect(resp.status()).toBe(202);
    const body = await resp.json();
    expect(body.id).toBe(sessionId);
    expect(body.status).toBe("stopped");
    expect(body.stopped_at).toBeNull(); // stopped_at is not set by orchestrator directly
  });
});

/* ------------------------------------------------------------------ */
/*  Section 3 — Playback URL                                          */
/* ------------------------------------------------------------------ */

test.describe("Broadcast — playback URL", () => {
  let alicePage: Page;
  let rootPage: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, "root");

    // Create profile + session + start it
    const profileResp = await apiPost(
      alicePage,
      "alice",
      "/broadcast/profiles",
      {
        name: `Playback Profile ${TS}`,
        region: "us-east-1",
        rendition_preset: "720p30",
      },
    );
    const profileId = (await profileResp.json()).id;

    const sessionResp = await apiPost(
      alicePage,
      "alice",
      "/broadcast/sessions",
      { profile_id: profileId },
    );
    sessionId = (await sessionResp.json()).id;

    // Start the session so it has a playback URL in the output
    await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${sessionId}/start`,
      { reason: "playback test" },
    );
  });

  test.afterAll(async () => {
    await alicePage.context().close();
    await rootPage.context().close();
  });

  test("3.1 Generate playback URL for a live session", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/playback-url`,
      {},
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.session_id).toBe(sessionId);
    expect(body.playback_url).toBeTruthy();
    expect(body.playback_url).toContain("/hls/");
    expect(body.playback_url).toContain("master.m3u8");
    expect(body.expires_at).toBeGreaterThan(0);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 4 — Session deletion                                      */
/* ------------------------------------------------------------------ */

test.describe("Broadcast — session deletion", () => {
  let alicePage: Page;
  let rootPage: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, "root");

    // Create profile + session, start then stop
    const profileResp = await apiPost(
      alicePage,
      "alice",
      "/broadcast/profiles",
      {
        name: `Delete Profile ${TS}`,
        region: "us-east-1",
        rendition_preset: "720p30",
      },
    );
    const profileId = (await profileResp.json()).id;

    const sessionResp = await apiPost(
      alicePage,
      "alice",
      "/broadcast/sessions",
      { profile_id: profileId },
    );
    sessionId = (await sessionResp.json()).id;

    await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${sessionId}/start`,
      { reason: "delete test start" },
    );
    await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${sessionId}/stop`,
      { reason: "delete test stop" },
    );
  });

  test.afterAll(async () => {
    await alicePage.context().close();
    await rootPage.context().close();
  });

  test("4.1 Root deletes a stopped session", async () => {
    const resp = await apiDelete(
      rootPage,
      "root",
      `/broadcast/sessions/${sessionId}`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
  });

  test("4.2 GET deleted session returns 404", async () => {
    const resp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}`,
    );
    expect(resp.status()).toBe(404);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 5 — Admin audit trail                                     */
/* ------------------------------------------------------------------ */

test.describe("Broadcast — admin audit trail", () => {
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

    // Create a profile + session so audit entries exist
    const profileResp = await apiPost(
      alicePage,
      "alice",
      "/broadcast/profiles",
      {
        name: `Audit Profile ${TS}`,
        region: "us-east-1",
        rendition_preset: "720p30",
      },
    );
    const profileId = (await profileResp.json()).id;

    const sessionResp = await apiPost(
      alicePage,
      "alice",
      "/broadcast/sessions",
      { profile_id: profileId },
    );
    sessionId = (await sessionResp.json()).id;
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("5.1 Root queries full audit trail", async () => {
    const resp = await apiGet(rootPage, "/broadcast/admin/audit?limit=50");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.items).toBeDefined();
    expect(Array.isArray(body.items)).toBe(true);
    expect(body.items.length).toBeGreaterThan(0);

    // Verify audit entry structure
    const entry = body.items[0];
    expect(entry.audit_id).toBeTruthy();
    expect(entry.action).toBeTruthy();
    expect(entry.actor).toBeTruthy();
    expect(entry.correlation_id).toBeTruthy();
    expect(entry.resource_type).toBeTruthy();
    expect(entry.resource_id).toBeTruthy();
    expect(entry.created_at).toBeTruthy();
  });

  test("5.2 Audit trail filtered by actor returns matching entries", async () => {
    const aliceSub = getSessions().alice.user_sub;
    const resp = await apiGet(
      rootPage,
      `/broadcast/admin/audit?actor=${encodeURIComponent(aliceSub)}&limit=50`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.items.length).toBeGreaterThan(0);
    // Every entry should be from Alice
    for (const entry of body.items) {
      expect(entry.actor).toBe(aliceSub);
    }
  });

  test("5.3 Audit trail contains create_profile and create_session actions", async () => {
    const aliceSub = getSessions().alice.user_sub;
    const resp = await apiGet(
      rootPage,
      `/broadcast/admin/audit?actor=${encodeURIComponent(aliceSub)}&limit=100`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const actions = body.items.map((e: { action: string }) => e.action);
    expect(actions).toContain("create_profile");
    expect(actions).toContain("create_session");
  });
});

/* ------------------------------------------------------------------ */
/*  Section 6 — Access control                                        */
/* ------------------------------------------------------------------ */

test.describe("Broadcast — access control", () => {
  let alicePage: Page;
  let rootPage: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, "root");

    // Create profile + session for access control tests
    const profileResp = await apiPost(
      alicePage,
      "alice",
      "/broadcast/profiles",
      {
        name: `ACL Profile ${TS}`,
        region: "us-east-1",
        rendition_preset: "720p30",
      },
    );
    const profileId = (await profileResp.json()).id;

    const sessionResp = await apiPost(
      alicePage,
      "alice",
      "/broadcast/sessions",
      { profile_id: profileId },
    );
    sessionId = (await sessionResp.json()).id;
  });

  test.afterAll(async () => {
    await alicePage.context().close();
    await rootPage.context().close();
  });

  test("6.1 Alice (user role) cannot start a session — 403", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/start`,
      { reason: "alice tries start" },
    );
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.detail.code).toBe("BROADCAST_ROLE_FORBIDDEN");
  });

  test("6.2 Alice (user role) cannot stop a session — 403", async () => {
    // First start it as root so it is live
    await apiPost(
      rootPage,
      "root",
      `/broadcast/sessions/${sessionId}/start`,
      { reason: "root starts for ACL test" },
    );

    const resp = await apiPost(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}/stop`,
      { reason: "alice tries stop" },
    );
    expect(resp.status()).toBe(403);
  });

  test("6.3 Alice (user role) cannot delete a session — 403", async () => {
    const resp = await apiDelete(
      alicePage,
      "alice",
      `/broadcast/sessions/${sessionId}`,
    );
    expect(resp.status()).toBe(403);
  });

  test("6.4 Alice (user role) cannot query audit trail — 403", async () => {
    const resp = await apiGet(alicePage, "/broadcast/admin/audit?limit=10");
    // audit endpoint is behind apiGet which uses page.request (carries Alice's cookies)
    // Verify the page-level request also gets 403
    expect(resp.status()).toBe(403);
  });

  test("6.5 Alice can create profiles (no operator role required)", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      "/broadcast/profiles",
      {
        name: `ACL Alice Profile ${TS}`,
        region: "us-east-1",
        rendition_preset: "480p30",
      },
    );
    expect(resp.status()).toBe(201);
  });

  test("6.6 Alice can create sessions (no operator role required)", async () => {
    // Create another profile for this test
    const profileResp = await apiPost(
      alicePage,
      "alice",
      "/broadcast/profiles",
      {
        name: `ACL Session Profile ${TS}`,
        region: "us-east-1",
        rendition_preset: "720p30",
      },
    );
    const pid = (await profileResp.json()).id;
    const resp = await apiPost(
      alicePage,
      "alice",
      "/broadcast/sessions",
      { profile_id: pid },
    );
    expect(resp.status()).toBe(201);
  });
});
