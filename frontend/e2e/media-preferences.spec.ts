/**
 * E2E tests for Media Preferences (CALL-003).
 *
 * Sections:
 *   100 — Media Preferences API  (9 tests)
 *   101 — Media Settings Page UI (6 tests)
 *
 * Auth: Alice session cookies (from e2e_session_setup.py).
 *
 * Since Playwright cannot access real media devices, the API tests focus on
 * the backend save/get/update/defaults/validation flow.  The UI tests verify
 * the page renders correctly and handles the no-device case gracefully.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ───────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

// ─── Session bootstrap ──────────────────────────────────────────────────────

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

// ─── Auth helpers ────────────────────────────────────────────────────────────

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

// ─── API helpers ─────────────────────────────────────────────────────────────

function csrf(userId = ALICE_ID) {
  return getSessions()[userId].csrf_token;
}

async function apiGet(page: Page, path: string, userId = ALICE_ID) {
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": csrf(userId) },
  });
}

async function apiPut(page: Page, path: string, body: object, userId = ALICE_ID) {
  return page.request.put(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": csrf(userId) },
  });
}

// ─── DDB helper: clean up preferences ───────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
for line in env_file.read_text().splitlines():
    if '=' in line and not line.strip().startswith('#'):
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001',
    region_name='us-east-1',
    aws_access_key_id='test', aws_secret_access_key='test')
`;

function deletePrefs(userSub: string) {
  const script = `${DDB_PRELUDE}
table = ddb.Table('media_preferences')
try:
    table.delete_item(Key={'user_sub': '${userSub}', 'sk': 'PREFS'})
    print('deleted')
except Exception as e:
    print(f'skip: {e}')
`;
  try {
    execSync(`python3 -c "${script.replace(/"/g, '\\"')}"`, {
      cwd: "/home/ubuntu/testlogon",
      timeout: 10_000,
    });
  } catch {
    // ignore — table may not exist yet
  }
}

// =============================================================================
// Section 100 — Media Preferences API
// =============================================================================

test.describe("100 — Media Preferences API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    // Ensure table exists
    try {
      execSync(
        "/home/ubuntu/testlogon/.venv/bin/python3 scripts/local-ddb-init.py",
        {
          cwd: "/home/ubuntu/testlogon",
          timeout: 30_000,
          // local-ddb-init.py imports `app.*`; running it as a script puts
          // scripts/ (not the repo root) on sys.path[0], so `app` is not
          // importable without PYTHONPATH pointing at the repo root.
          env: { ...process.env, PYTHONPATH: "/home/ubuntu/testlogon" },
        },
      );
    } catch {
      // may already exist
    }

    // Clean up any existing prefs
    deletePrefs(ALICE_ID);
    deletePrefs(BOB_ID);

    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    deletePrefs(ALICE_ID);
    deletePrefs(BOB_ID);
    await alicePage?.context().close();
  });

  test("100.1 GET preferences returns defaults when none saved", async () => {
    const resp = await apiGet(alicePage, "/ui/media/preferences");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.user_sub).toBe(ALICE_ID);
    expect(data.default_audio_muted).toBe(false);
    expect(data.default_video_off).toBe(false);
    expect(data.video_resolution).toBe("720");
    expect(data.preferred_audio_input_id).toBeNull();
    expect(data.preferred_video_input_id).toBeNull();
    expect(data.preferred_audio_output_id).toBeNull();
  });

  test("100.2 PUT saves preferences successfully", async () => {
    const body = {
      preferred_audio_input_id: "mic-device-123",
      preferred_video_input_id: "cam-device-456",
      preferred_audio_output_id: "speaker-device-789",
      default_audio_muted: true,
      default_video_off: true,
      video_resolution: "1080",
    };
    const resp = await apiPut(alicePage, "/ui/media/preferences", body);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.user_sub).toBe(ALICE_ID);
    expect(data.preferred_audio_input_id).toBe("mic-device-123");
    expect(data.preferred_video_input_id).toBe("cam-device-456");
    expect(data.preferred_audio_output_id).toBe("speaker-device-789");
    expect(data.default_audio_muted).toBe(true);
    expect(data.default_video_off).toBe(true);
    expect(data.video_resolution).toBe("1080");
    expect(data.updated_at).toBeGreaterThan(0);
  });

  test("100.3 GET returns saved preferences", async () => {
    const resp = await apiGet(alicePage, "/ui/media/preferences");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.preferred_audio_input_id).toBe("mic-device-123");
    expect(data.default_audio_muted).toBe(true);
    expect(data.video_resolution).toBe("1080");
  });

  test("100.4 PUT updates existing preferences (partial)", async () => {
    const body = {
      preferred_audio_input_id: "new-mic-device",
      default_audio_muted: false,
      default_video_off: true,
      video_resolution: "480",
    };
    const resp = await apiPut(alicePage, "/ui/media/preferences", body);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.preferred_audio_input_id).toBe("new-mic-device");
    expect(data.default_audio_muted).toBe(false);
    expect(data.default_video_off).toBe(true);
    expect(data.video_resolution).toBe("480");
    // Fields not sent should be reset to defaults (PUT replaces the whole record)
    expect(data.preferred_video_input_id).toBeNull();
    expect(data.preferred_audio_output_id).toBeNull();
  });

  test("100.5 Preferences are per-user (Alice vs Bob isolation)", async () => {
    // Create Bob page
    const ctx = await alicePage.context().browser()!.newContext();
    const bobPage = await ctx.newPage();
    await injectAuth(bobPage, BOB_ID);

    // Bob has no prefs yet
    const bobResp = await apiGet(bobPage, "/ui/media/preferences", BOB_ID);
    expect(bobResp.status()).toBe(200);
    const bobData = await bobResp.json();
    expect(bobData.user_sub).toBe(BOB_ID);
    expect(bobData.default_audio_muted).toBe(false);

    // Save Bob prefs
    const saveResp = await apiPut(
      bobPage,
      "/ui/media/preferences",
      { default_audio_muted: true, video_resolution: "360" },
      BOB_ID,
    );
    expect(saveResp.status()).toBe(200);

    // Verify Alice prefs unchanged
    const aliceResp = await apiGet(alicePage, "/ui/media/preferences");
    const aliceData = await aliceResp.json();
    expect(aliceData.default_audio_muted).toBe(false);
    expect(aliceData.video_resolution).toBe("480"); // from test 100.4

    await ctx.close();
  });

  test("100.6 PUT with empty device IDs stores null", async () => {
    const body = {
      preferred_audio_input_id: null,
      preferred_video_input_id: null,
      preferred_audio_output_id: null,
      default_audio_muted: false,
      default_video_off: false,
      video_resolution: "720",
    };
    const resp = await apiPut(alicePage, "/ui/media/preferences", body);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.preferred_audio_input_id).toBeNull();
    expect(data.preferred_video_input_id).toBeNull();
    expect(data.preferred_audio_output_id).toBeNull();
  });

  test("100.7 PUT with invalid resolution returns 422", async () => {
    const body = {
      video_resolution: "4K",
    };
    const resp = await apiPut(alicePage, "/ui/media/preferences", body);
    expect(resp.status()).toBe(422);
  });

  test("100.8 GET without auth returns 401 or 403", async () => {
    const ctx = await alicePage.context().browser()!.newContext();
    const anonPage = await ctx.newPage();
    // Navigate to establish domain for requests
    await anonPage.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    const resp = await anonPage.request.get(`${BASE}/ui/media/preferences`);
    expect([401, 403]).toContain(resp.status());
    await ctx.close();
  });

  test("100.9 PUT replaces all fields on each save", async () => {
    // First save full prefs
    await apiPut(alicePage, "/ui/media/preferences", {
      preferred_audio_input_id: "old-mic",
      preferred_video_input_id: "old-cam",
      preferred_audio_output_id: "old-speaker",
      default_audio_muted: true,
      default_video_off: true,
      video_resolution: "1080",
    });

    // Second save with minimal fields — should reset others
    const resp = await apiPut(alicePage, "/ui/media/preferences", {
      video_resolution: "720",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_resolution).toBe("720");
    expect(data.default_audio_muted).toBe(false);
    expect(data.default_video_off).toBe(false);
    expect(data.preferred_audio_input_id).toBeNull();
  });
});

// =============================================================================
// Section 101 — Media Settings Page UI
// =============================================================================

test.describe("101 — Media Settings Page UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await injectAuth(page, ALICE_ID);
  });

  test.afterAll(async () => {
    deletePrefs(ALICE_ID);
    await page?.context().close();
  });

  test("101.1 Page loads and shows heading", async () => {
    await page.goto(`${BASE}/calls/settings`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Media Settings" })).toBeVisible();
  });

  test("101.2 Page shows permission status section", async () => {
    await expect(page.getByText("Permission Status")).toBeVisible();
    // At minimum one of the badges should be visible
    const micBadge = page.getByText(/Microphone:/);
    const camBadge = page.getByText(/Camera:/);
    await expect(micBadge.or(camBadge)).toBeVisible();
  });

  test("101.3 Page shows device selection section", async () => {
    await expect(page.getByText("Device Selection")).toBeVisible();
    // Dropdowns for mic, camera, speaker
    await expect(page.getByText("Microphone").first()).toBeVisible();
    await expect(page.getByText("Camera").first()).toBeVisible();
    await expect(page.getByText("Speaker").first()).toBeVisible();
  });

  test("101.4 Page shows call defaults section", async () => {
    await expect(page.getByText("Call Defaults")).toBeVisible();
    await expect(page.getByText("Start calls muted")).toBeVisible();
    await expect(page.getByText("Start video calls with camera off")).toBeVisible();
    await expect(page.getByText("Video Resolution")).toBeVisible();
  });

  test("101.5 Save button exists and is clickable", async () => {
    const saveBtn = page.getByRole("button", { name: "Save Preferences" });
    await expect(saveBtn).toBeVisible();
    await expect(saveBtn).toBeEnabled();
  });

  test("101.6 Page shows test device buttons", async () => {
    await expect(page.getByText("Test Devices")).toBeVisible();
    await expect(
      page.getByRole("button", { name: /Preview camera/i }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: /Test microphone/i }),
    ).toBeVisible();
  });
});
