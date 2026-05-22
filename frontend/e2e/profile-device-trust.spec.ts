/**
 * E2E tests for Profile Management and Device Trust.
 *
 * Sections:
 *   92 — Profile Management API (6 tests)
 *   93 — Device Trust API (5 tests)
 *
 * Auth: Cookie-based session for Alice (e2e_alice@test.local) with CSRF.
 *
 * Endpoints under test:
 *   GET    /ui/profile
 *   PATCH  /ui/profile
 *   PUT    /ui/profile
 *   GET    /ui/profile/audit
 *   GET    /ui/profiles/{identifier}
 *   GET    /ui/devices
 *   POST   /ui/devices/{device_id}/trust
 *   POST   /ui/devices/{device_id}/revoke
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
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
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

function refreshSessions(): Record<string, SessionData> {
  _sessions = null;
  return getSessions();
}

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
}

async function apiPost(page: Page, path: string, body?: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

async function apiPatch(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.patch(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiPut(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.put(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

const DDB_PRELUDE = `
import boto3, os, time
from pathlib import Path
for ln in Path('/home/ubuntu/testlogon/.env.local').read_text().splitlines():
    ln = ln.strip()
    if ln and not ln.startswith('#') and '=' in ln:
        k, v = ln.split('=', 1); os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
`;

function seedDeviceEntry(userSub: string, deviceId: string): void {
  const ts = Math.floor(Date.now() / 1000);
  execSync(
    `python3 -c "${DDB_PRELUDE}
tbl = ddb.Table('sessions')
tbl.put_item(Item={
    'user_sub': '${userSub}',
    'session_id': 'dev#${deviceId}',
    'device_id': '${deviceId}',
    'user_agent': 'E2E-Test-Agent/${ts}',
    'first_seen_at': ${ts - 3600},
    'last_seen_at': ${ts},
    'last_ip': '127.0.0.1',
    'last_ip_prefix': '127.0.0',
    'trusted': False,
    'token_hash': '',
})
print('device seeded')
"`,
    { timeout: 10_000 },
  );
}

function cleanupDeviceEntry(userSub: string, deviceId: string): void {
  try {
    execSync(
      `python3 -c "${DDB_PRELUDE}
tbl = ddb.Table('sessions')
tbl.delete_item(Key={'user_sub': '${userSub}', 'session_id': 'dev#${deviceId}'})
print('device cleaned')
"`,
      { timeout: 10_000 },
    );
  } catch { /* ignore cleanup failures */ }
}

test.describe.serial("92 — Profile Management API", () => {
  let page: Page;
  let aliceSub: string;
  const DISPLAY_NAME = `Alice E2E ${TS}`;
  const UPDATED_TITLE = `Engineer ${TS}`;
  const LOCATION = `Test City ${TS}`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    aliceSub = getSessions()[ALICE_ID].user_sub;
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("92.1 Get own profile returns profile object", async () => {
    const resp = await apiGet(page, "/ui/profile");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.profile).toBeTruthy();
    // Profile has standard fields (may be null initially)
    expect("display_name" in data.profile).toBe(true);
    expect("first_name" in data.profile).toBe(true);
    expect("location" in data.profile).toBe(true);
  });

  test("92.2 Patch profile updates specific fields", async () => {
    const resp = await apiPatch(page, "/ui/profile", {
      display_name: DISPLAY_NAME,
      title: UPDATED_TITLE,
      location: LOCATION,
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.profile.display_name).toBe(DISPLAY_NAME);
    expect(data.profile.title).toBe(UPDATED_TITLE);
    expect(data.profile.location).toBe(LOCATION);
  });

  test("92.3 Get profile reflects patched values", async () => {
    const resp = await apiGet(page, "/ui/profile");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.profile.display_name).toBe(DISPLAY_NAME);
    expect(data.profile.title).toBe(UPDATED_TITLE);
    expect(data.profile.location).toBe(LOCATION);
  });

  test("92.4 Put profile replaces entire profile", async () => {
    const newName = `Alice Replaced ${TS}`;
    const resp = await apiPut(page, "/ui/profile", {
      display_name: newName,
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.profile.display_name).toBe(newName);
    // PUT replaces, so previously set fields should be null
    expect(data.profile.title).toBeNull();
    expect(data.profile.location).toBeNull();
  });

  test("92.5 Profile audit log records changes", async () => {
    const resp = await apiGet(page, "/ui/profile/audit");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.audit).toBeInstanceOf(Array);
    expect(data.audit.length).toBeGreaterThanOrEqual(1);
    // Audit entries have ts and field
    const entry = data.audit[0];
    expect(entry.ts).toBeTruthy();
    expect(entry.field).toBeTruthy();
  });

  test("92.6 Public profile lookup by user_sub", async () => {
    const resp = await apiGet(page, `/ui/profiles/${aliceSub}`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.user_sub).toBe(aliceSub);
    expect(data.profile).toBeTruthy();
    expect(data.audience).toBe("owner");
    expect(data.identifier).toBe(aliceSub);
  });
});

test.describe.serial("93 — Device Trust API", () => {
  let page: Page;
  let aliceSub: string;
  const DEVICE_ID = `e2edev${TS}`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    aliceSub = getSessions()[ALICE_ID].user_sub;
    // Seed a fake device entry for Alice
    seedDeviceEntry(aliceSub, DEVICE_ID);
  });

  test.afterAll(async () => {
    cleanupDeviceEntry(aliceSub, DEVICE_ID);
    await page.close();
  });

  test("93.1 List trusted devices returns seeded device", async () => {
    const resp = await apiGet(page, "/ui/devices");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.devices).toBeInstanceOf(Array);
    const found = data.devices.find((d: any) => d.device_id === DEVICE_ID);
    expect(found).toBeTruthy();
    expect(found.trusted).toBe(false);
    expect(found.user_agent).toContain("E2E-Test-Agent");
    expect(found.last_ip).toBe("127.0.0.1");
  });

  test("93.2 Trust a device succeeds (no MFA required)", async () => {
    const resp = await apiPost(page, `/ui/devices/${DEVICE_ID}/trust`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.status).toBe("ok");
  });

  test("93.3 Device appears as trusted after trust call", async () => {
    // Trust endpoint rotates the session; create fresh sessions and re-inject
    refreshSessions();
    await injectAuth(page);
    const resp = await apiGet(page, "/ui/devices");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    const found = data.devices.find((d: any) => d.device_id === DEVICE_ID);
    expect(found).toBeTruthy();
    expect(found.trusted).toBe(true);
  });

  test("93.4 Revoke a device succeeds", async () => {
    const resp = await apiPost(page, `/ui/devices/${DEVICE_ID}/revoke`);
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.status).toBe("ok");
  });

  test("93.5 Device shows untrusted after revoke", async () => {
    const resp = await apiGet(page, "/ui/devices");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    const found = data.devices.find((d: any) => d.device_id === DEVICE_ID);
    expect(found).toBeTruthy();
    expect(found.trusted).toBe(false);
  });
});
