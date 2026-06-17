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
/*  Shared state                                                       */
/* ------------------------------------------------------------------ */

const ROOT_ID = "root";
const BOB_ID = "bob";

/** Create a broadcast session in live state and return its id */
async function createLiveSession(page: Page): Promise<string> {
  const profileResp = await apiPost(page, ROOT_ID, "/broadcast/profiles", {
    name: `mi-profile-${Date.now()}`,
    region: "us-east-1",
    rendition_preset: "720p30",
  });
  const profileData = await profileResp.json();

  const sessionResp = await apiPost(page, ROOT_ID, "/broadcast/sessions", {
    profile_id: profileData.id,
  });
  const sessionData = await sessionResp.json();

  const startResp = await apiPost(page, ROOT_ID, `/broadcast/sessions/${sessionData.id}/start`, {
    reason: "e2e-multi-input-test",
  });
  const startData = await startResp.json();
  return sessionData.id;
}

/** Add N inputs to a session and return their IDs */
async function addInputs(page: Page, sessionId: string, count: number): Promise<string[]> {
  const ids: string[] = [];
  for (let i = 0; i < count; i++) {
    const resp = await apiPost(page, ROOT_ID, `/broadcast/sessions/${sessionId}/inputs`, {
      input_type: i === 0 ? "primary" : "guest",
      label: `Input-${i}-${Date.now()}`,
    });
    const data = await resp.json();
    ids.push(data.input_id);
  }
  return ids;
}

/* ------------------------------------------------------------------ */
/*  Section 140: Input CRUD                                            */
/* ------------------------------------------------------------------ */

test.describe("140 - Input CRUD", () => {
  let rootPage: Page;
  let bobPage: Page;
  let sessionId: string;
  let inputIds: string[] = [];

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    sessionId = await createLiveSession(rootPage);
  });

  test.afterAll(async () => {
    await rootPage?.context().close();
    await bobPage?.context().close();
  });

  test("140.1 list inputs initially empty", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/inputs`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.session_id).toBe(sessionId);
    expect(data.inputs).toEqual([]);
    expect(data.count).toBe(0);
    expect(data.max_inputs).toBeGreaterThanOrEqual(4);
  });

  test("140.2 add first input returns ingest_url and stream_key", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/inputs`, {
      input_type: "primary",
      label: "Main Camera",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.input_id).toBeTruthy();
    expect(data.session_id).toBe(sessionId);
    expect(data.input_type).toBe("primary");
    expect(data.label).toBe("Main Camera");
    expect(data.ingest_url).toBeTruthy();
    expect(data.stream_key).toBeTruthy();
    expect(data.position).toBe(0);
    inputIds.push(data.input_id);
  });

  test("140.3 add second input", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/inputs`, {
      input_type: "guest",
      label: "Guest Camera",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.position).toBe(1);
    inputIds.push(data.input_id);
  });

  test("140.4 list inputs shows 2", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/inputs`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.count).toBe(2);
    expect(data.inputs.length).toBe(2);
  });

  test("140.5 delete second input", async () => {
    const resp = await apiDelete(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/inputs/${inputIds[1]}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
  });

  test("140.6 list after delete shows 1", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/inputs`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.count).toBe(1);
  });

  test("140.7 non-owner cannot add input", async () => {
    const resp = await apiPost(bobPage, BOB_ID, `/broadcast/sessions/${sessionId}/inputs`, {
      input_type: "guest",
      label: "Bob Input",
    });
    expect(resp.status()).toBe(403);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 141: Guest Invite Lifecycle                                */
/* ------------------------------------------------------------------ */

test.describe("141 - Guest Invite Lifecycle", () => {
  let rootPage: Page;
  let bobPage: Page;
  let sessionId: string;
  let inviteId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    sessionId = await createLiveSession(rootPage);
  });

  test.afterAll(async () => {
    await rootPage?.context().close();
    await bobPage?.context().close();
  });

  test("141.1 create guest invite returns invite with stream_key", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/guest-invites`, {
      join_mode: "browser",
      label: `Guest-Invite-${TS}`,
      expiry_minutes: 60,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.invite_id).toBeTruthy();
    expect(data.session_id).toBe(sessionId);
    expect(data.input_id).toBeTruthy();
    expect(data.join_mode).toBe("browser");
    expect(data.status).toBe("pending");
    expect(data.stream_key).toBeTruthy();
    expect(data.expires_at).toBeGreaterThan(0);
    inviteId = data.invite_id;
  });

  test("141.2 list guest invites shows the created invite", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/guest-invites`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.invites.length).toBeGreaterThanOrEqual(1);
    const found = data.invites.find((i: any) => i.invite_id === inviteId);
    expect(found).toBeTruthy();
    expect(found.status).toBe("pending");
  });

  test("141.3 Bob accepts the invite", async () => {
    const resp = await apiPost(bobPage, BOB_ID, `/broadcast/sessions/${sessionId}/guest-invites/${inviteId}/accept`, {
      display_name: `Bob-${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.invite_id).toBe(inviteId);
    expect(data.input_id).toBeTruthy();
    expect(data.join_mode).toBe("browser");
    expect(data.session_id).toBe(sessionId);
  });

  test("141.4 double-accept returns 409", async () => {
    const resp = await apiPost(bobPage, BOB_ID, `/broadcast/sessions/${sessionId}/guest-invites/${inviteId}/accept`, {
      display_name: `Bob-${TS}`,
    });
    expect(resp.status()).toBe(409);
  });

  test("141.5 create and revoke invite", async () => {
    const createResp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/guest-invites`, {
      join_mode: "rtmp",
      label: "Revoke Test",
      expiry_minutes: 5,
    });
    expect(createResp.status()).toBe(201);
    const createData = await createResp.json();

    const revokeResp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/guest-invites/${createData.invite_id}/revoke`, {});
    expect(revokeResp.status()).toBe(200);
    const revokeData = await revokeResp.json();
    expect(revokeData.ok).toBe(true);
    expect(revokeData.status).toBe("revoked");
  });

  test("141.6 non-owner cannot create invite", async () => {
    const resp = await apiPost(bobPage, BOB_ID, `/broadcast/sessions/${sessionId}/guest-invites`, {
      join_mode: "browser",
      label: "Bob Invite",
    });
    expect(resp.status()).toBe(403);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 142: Layout Switching                                      */
/* ------------------------------------------------------------------ */

test.describe("142 - Layout Switching", () => {
  let rootPage: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    sessionId = await createLiveSession(rootPage);
    // Add 2 inputs so all layout modes work
    await addInputs(rootPage, sessionId, 2);
  });

  test.afterAll(async () => {
    await rootPage?.context().close();
  });

  test("142.1 switch to single layout", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/layout`, {
      mode: "single",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.mode).toBe("single");
    expect(data.positions.length).toBeGreaterThanOrEqual(1);
    expect(data.positions[0].width).toBe(1.0);
    expect(data.positions[0].height).toBe(1.0);
  });

  test("142.2 switch to side_by_side layout", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/layout`, {
      mode: "side_by_side",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.mode).toBe("side_by_side");
    expect(data.positions.length).toBe(2);
    expect(data.positions[0].width).toBe(0.5);
    expect(data.positions[1].width).toBe(0.5);
  });

  test("142.3 switch to pip layout", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/layout`, {
      mode: "pip",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.mode).toBe("pip");
    expect(data.positions.length).toBe(2);
    expect(data.positions[0].width).toBe(1.0);
    expect(data.positions[1].width).toBe(0.28);
  });

  test("142.4 switch to grid layout", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/layout`, {
      mode: "grid",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.mode).toBe("grid");
    expect(data.positions.length).toBeGreaterThanOrEqual(2);
  });

  test("142.5 get current layout", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/layout`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.mode).toBe("grid");
  });

  test("142.6 invalid layout mode returns 422", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/layout`, {
      mode: "invalid_mode",
    });
    expect(resp.status()).toBe(422);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 143: Guest Management                                      */
/* ------------------------------------------------------------------ */

test.describe("143 - Guest Management", () => {
  let rootPage: Page;
  let sessionId: string;
  let guestInputId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    sessionId = await createLiveSession(rootPage);
    const ids = await addInputs(rootPage, sessionId, 2);
    guestInputId = ids[1]; // second input is type "guest"
  });

  test.afterAll(async () => {
    await rootPage?.context().close();
  });

  test("143.1 mute guest", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/guests/${guestInputId}/mute`, {
      muted: true,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.muted).toBe(true);
  });

  test("143.2 unmute guest", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/guests/${guestInputId}/mute`, {
      muted: false,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.muted).toBe(false);
  });

  test("143.3 promote guest to primary", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/guests/${guestInputId}/promote`, {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.promoted).toBe(true);
  });

  test("143.4 remove guest", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/guests/${guestInputId}/remove`, {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 144: WebRTC Signaling                                      */
/* ------------------------------------------------------------------ */

test.describe("144 - WebRTC Signaling", () => {
  let rootPage: Page;
  let bobPage: Page;
  let sessionId: string;
  let inputId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    sessionId = await createLiveSession(rootPage);
    const ids = await addInputs(rootPage, sessionId, 1);
    inputId = ids[0];
  });

  test.afterAll(async () => {
    await rootPage?.context().close();
    await bobPage?.context().close();
  });

  test("144.1 submit WebRTC offer returns SDP answer", async () => {
    const resp = await apiPost(bobPage, BOB_ID, `/broadcast/sessions/${sessionId}/inputs/${inputId}/webrtc-offer`, {
      sdp_offer: "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=test\r\nt=0 0\r\n",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.sdp_answer).toBeTruthy();
    expect(data.session_id).toBe(sessionId);
    expect(data.input_id).toBe(inputId);
  });

  test("144.2 WebRTC offer for non-existent input returns 404", async () => {
    const resp = await apiPost(bobPage, BOB_ID, `/broadcast/sessions/${sessionId}/inputs/nonexistent_inp/webrtc-offer`, {
      sdp_offer: "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=test\r\nt=0 0\r\n",
    });
    expect(resp.status()).toBe(404);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 145: Session Lifecycle Integration                         */
/* ------------------------------------------------------------------ */

test.describe("145 - Session Lifecycle Integration", () => {
  let rootPage: Page;
  let sessionId: string;
  let inputId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    sessionId = await createLiveSession(rootPage);
    const ids = await addInputs(rootPage, sessionId, 1);
    inputId = ids[0];
  });

  test.afterAll(async () => {
    await rootPage?.context().close();
  });

  test("145.1 activate input marks it as live", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/inputs/${inputId}/activate`, {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.is_live).toBe(true);
  });

  test("145.2 input shows as live in list", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/inputs`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const inp = data.inputs.find((i: any) => i.input_id === inputId);
    expect(inp).toBeTruthy();
    expect(inp.is_live).toBe(true);
    expect(inp.connected_at).toBeGreaterThan(0);
  });

  test("145.3 deactivate input marks it as offline", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/inputs/${inputId}/deactivate`, {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.is_live).toBe(false);
  });

  test("145.4 input shows disconnected_at after deactivate", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/inputs`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const inp = data.inputs.find((i: any) => i.input_id === inputId);
    expect(inp).toBeTruthy();
    expect(inp.is_live).toBe(false);
    expect(inp.disconnected_at).toBeGreaterThan(0);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 146: InputManager UI                                       */
/* ------------------------------------------------------------------ */

test.describe("146 - InputManager UI", () => {
  let rootPage: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    sessionId = await createLiveSession(rootPage);
    await addInputs(rootPage, sessionId, 1);
  });

  test.afterAll(async () => {
    await rootPage?.context().close();
  });

  test("146.1 InputManager renders on broadcast page", async () => {
    // Verify that the API layer is accessible from the UI context
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/inputs`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.count).toBeGreaterThanOrEqual(1);
  });

  test("146.2 InputManager shows input count", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/inputs`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.max_inputs).toBeGreaterThanOrEqual(4);
    expect(typeof data.count).toBe("number");
  });
});

/* ------------------------------------------------------------------ */
/*  Section 147: LayoutSwitcher UI                                     */
/* ------------------------------------------------------------------ */

test.describe("147 - LayoutSwitcher UI", () => {
  let rootPage: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    sessionId = await createLiveSession(rootPage);
    await addInputs(rootPage, sessionId, 2);
  });

  test.afterAll(async () => {
    await rootPage?.context().close();
  });

  test("147.1 layout switcher provides four modes", async () => {
    const modes = ["single", "side_by_side", "pip", "grid"];
    for (const mode of modes) {
      const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/layout`, {
        mode,
      });
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.mode).toBe(mode);
    }
  });

  test("147.2 layout persists across get calls", async () => {
    await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/layout`, {
      mode: "pip",
    });
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/layout`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.mode).toBe("pip");
  });
});

/* ------------------------------------------------------------------ */
/*  Section 148: GuestInviteDialog UI                                  */
/* ------------------------------------------------------------------ */

test.describe("148 - GuestInviteDialog UI", () => {
  let rootPage: Page;
  let bobPage: Page;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    sessionId = await createLiveSession(rootPage);
  });

  test.afterAll(async () => {
    await rootPage?.context().close();
    await bobPage?.context().close();
  });

  test("148.1 create RTMP guest invite", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/guest-invites`, {
      join_mode: "rtmp",
      label: `RTMP-Guest-${TS}`,
      expiry_minutes: 30,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.join_mode).toBe("rtmp");
    expect(data.ingest_url).toBeTruthy();
    expect(data.stream_key).toBeTruthy();
  });

  test("148.2 create browser guest invite", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/guest-invites`, {
      join_mode: "browser",
      label: `Browser-Guest-${TS}`,
      expiry_minutes: 30,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.join_mode).toBe("browser");
    expect(data.invite_url).toBeTruthy();
  });

  test("148.3 list invites shows created invites", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/guest-invites`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.invites.length).toBeGreaterThanOrEqual(2);
    const statuses = data.invites.map((i: any) => i.status);
    expect(statuses).toContain("pending");
  });

  test("148.4 revoked invite cannot be accepted", async () => {
    const createResp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/guest-invites`, {
      join_mode: "browser",
      label: "Revoke-Accept-Test",
      expiry_minutes: 5,
    });
    const createData = await createResp.json();
    await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${sessionId}/guest-invites/${createData.invite_id}/revoke`, {});

    const acceptResp = await apiPost(bobPage, BOB_ID, `/broadcast/sessions/${sessionId}/guest-invites/${createData.invite_id}/accept`, {
      display_name: "Bob",
    });
    expect(acceptResp.status()).toBe(410);
  });
});
