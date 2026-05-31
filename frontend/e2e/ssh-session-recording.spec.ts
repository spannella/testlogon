/**
 * E2E tests for SSH Session Recording & Playback (INFRA-010).
 *
 * Sections:
 *   280 — Recording lifecycle API: start → append events → stop (5 tests)
 *   281 — List & playback API (5 tests)
 *   282 — Delete & ownership isolation API (4 tests)
 *   283 — Recordings UI (4 tests)
 *
 * Auth: Alice & Bob session cookies (from e2e_admin_session_setup.py).
 * Recordings are owner-scoped — a recording started via the append API is the
 * deterministic way to seed playback content (no real SSH PTY in the mock).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const API = BASE;
const ALICE_ID = "alice";
const BOB_ID = "bob";
const TS = Date.now();
const REC_BASE = "/ui/compute/ssh-recordings";

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
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

function csrfHeaders(identity: string) {
  return { "x-csrf-token": getSessions()[identity].csrf_token };
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  return page.request.post(`${API}${path}`, { headers: csrfHeaders(identity), data: body ?? {} });
}
async function apiDelete(page: Page, identity: string, path: string) {
  return page.request.delete(`${API}${path}`, { headers: csrfHeaders(identity) });
}
async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  let url = `${API}${path}`;
  if (params) url += "?" + new URLSearchParams(params).toString();
  return page.request.get(url);
}

/** Seed a complete recording: start → append events → stop. Returns recording_id. */
async function seedRecording(
  page: Page,
  identity: string,
  opts: { hostname: string; port?: number; username?: string } = { hostname: "seed.example.com" },
): Promise<string> {
  const start = await apiPost(page, identity, REC_BASE, {
    hostname: opts.hostname,
    port: opts.port ?? 22,
    username: opts.username ?? "ubuntu",
    terminal_cols: 120,
    terminal_rows: 40,
    host_id: "host_" + TS,
  });
  const rec = await start.json();
  const id = rec.recording_id;
  await apiPost(page, identity, `${REC_BASE}/${id}/events`, {
    events: [
      { offset: 0.0, type: "o", data: "$ " },
      { offset: 0.5, type: "i", data: "ls\r" },
      { offset: 0.6, type: "o", data: "ls\r\n" },
      { offset: 0.8, type: "o", data: "file1.txt  file2.txt\r\n" },
      { offset: 1.0, type: "o", data: "$ " },
    ],
  });
  await apiPost(page, identity, `${REC_BASE}/${id}/stop`);
  return id;
}

let alicePage: Page;
let bobPage: Page;

// ─────────────────────────────────────────────────────────────────────────────
// Section 280: Recording lifecycle API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("280 — Recording lifecycle API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });
  test.afterAll(async () => {
    await alicePage.close();
  });

  test("280.1 Start recording returns recording state", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, REC_BASE, {
      hostname: `h280-${TS}.example.com`,
      port: 22,
      username: "ubuntu",
      terminal_cols: 100,
      terminal_rows: 30,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.recording_id).toBeTruthy();
    expect(data.status).toBe("recording");
    expect(data.host_key).toBe(`h280-${TS}.example.com:22`);
    expect(data.terminal_cols).toBe(100);
  });

  test("280.2 Append events increments event_count and size", async () => {
    const start = await apiPost(alicePage, ALICE_ID, REC_BASE, {
      hostname: `h280b-${TS}.example.com`,
    });
    const id = (await start.json()).recording_id;
    const resp = await apiPost(alicePage, ALICE_ID, `${REC_BASE}/${id}/events`, {
      events: [
        { offset: 0.0, type: "o", data: "hello\r\n" },
        { offset: 0.2, type: "o", data: "world\r\n" },
      ],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.event_count).toBe(2);
    expect(data.file_size_bytes).toBeGreaterThan(0);
  });

  test("280.3 Stop recording sets stopped status + duration", async () => {
    const id = await seedRecording(alicePage, ALICE_ID, {
      hostname: `h280c-${TS}.example.com`,
    });
    const resp = await apiGet(alicePage, `${REC_BASE}/${id}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("stopped");
    expect(data.duration_seconds).toBeGreaterThanOrEqual(0);
    expect(data.event_count).toBe(5);
  });

  test("280.4 Append to stopped recording returns 409", async () => {
    const id = await seedRecording(alicePage, ALICE_ID, {
      hostname: `h280d-${TS}.example.com`,
    });
    const resp = await apiPost(alicePage, ALICE_ID, `${REC_BASE}/${id}/events`, {
      events: [{ offset: 2.0, type: "o", data: "late\r\n" }],
    });
    expect(resp.status()).toBe(409);
  });

  test("280.5 Recording metadata preserves session params", async () => {
    const id = await seedRecording(alicePage, ALICE_ID, {
      hostname: `h280e-${TS}.example.com`,
      port: 2222,
      username: "deploy",
    });
    const data = await (await apiGet(alicePage, `${REC_BASE}/${id}`)).json();
    expect(data.hostname).toBe(`h280e-${TS}.example.com`);
    expect(data.port).toBe(2222);
    expect(data.username).toBe("deploy");
    expect(data.terminal_cols).toBe(120);
    expect(data.terminal_rows).toBe(40);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 281: List & playback API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("281 — List & playback API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });
  test.afterAll(async () => {
    await alicePage.close();
  });

  test("281.1 List returns user recordings", async () => {
    await seedRecording(alicePage, ALICE_ID, { hostname: `h281-${TS}.example.com` });
    const resp = await apiGet(alicePage, REC_BASE);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.recordings)).toBe(true);
    expect(data.count).toBe(data.recordings.length);
    expect(data.count).toBeGreaterThan(0);
  });

  test("281.2 List sorted newest first", async () => {
    const data = await (await apiGet(alicePage, REC_BASE)).json();
    const times = data.recordings.map((r: any) => r.created_at);
    const sorted = [...times].sort((a, b) => b - a);
    expect(times).toEqual(sorted);
  });

  test("281.3 Filter by hostname", async () => {
    const host = `h281filter-${TS}.example.com`;
    await seedRecording(alicePage, ALICE_ID, { hostname: host });
    const data = await (await apiGet(alicePage, REC_BASE, { hostname: host })).json();
    expect(data.count).toBeGreaterThan(0);
    expect(data.recordings.every((r: any) => r.hostname === host)).toBe(true);
  });

  test("281.4 Playback returns header + event stream", async () => {
    const id = await seedRecording(alicePage, ALICE_ID, {
      hostname: `h281pb-${TS}.example.com`,
    });
    const resp = await apiGet(alicePage, `${REC_BASE}/${id}/playback`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.content_type).toBe("application/x-asciicast");
    expect(data.header.version).toBe(2);
    expect(data.header.width).toBe(120);
    expect(data.event_count).toBe(5);
    // Each event: [offset, type, data]
    expect(data.events[0][1]).toBe("o");
    const output = data.events.filter((e: any) => e[1] === "o").map((e: any) => e[2]).join("");
    expect(output).toContain("file1.txt");
  });

  test("281.5 Playback for non-existent recording returns 404", async () => {
    const resp = await apiGet(alicePage, `${REC_BASE}/rec_doesnotexist/playback`);
    expect(resp.status()).toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 282: Delete & ownership isolation API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("282 — Delete & ownership isolation API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
  });
  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("282.1 Delete removes recording from list + playback 404", async () => {
    const id = await seedRecording(alicePage, ALICE_ID, {
      hostname: `h282-${TS}.example.com`,
    });
    const del = await apiDelete(alicePage, ALICE_ID, `${REC_BASE}/${id}`);
    expect(del.status()).toBe(200);
    const detail = await apiGet(alicePage, `${REC_BASE}/${id}`);
    expect(detail.status()).toBe(404);
    const pb = await apiGet(alicePage, `${REC_BASE}/${id}/playback`);
    expect(pb.status()).toBe(404);
  });

  test("282.2 Delete non-existent recording returns 404", async () => {
    const resp = await apiDelete(alicePage, ALICE_ID, `${REC_BASE}/rec_missing`);
    expect(resp.status()).toBe(404);
  });

  test("282.3 Bob cannot playback Alice's recording (404)", async () => {
    const id = await seedRecording(alicePage, ALICE_ID, {
      hostname: `h282iso-${TS}.example.com`,
    });
    const resp = await apiGet(bobPage, `${REC_BASE}/${id}/playback`);
    expect(resp.status()).toBe(404);
  });

  test("282.4 Bob cannot delete Alice's recording (404) and it survives", async () => {
    const id = await seedRecording(alicePage, ALICE_ID, {
      hostname: `h282del-${TS}.example.com`,
    });
    const del = await apiDelete(bobPage, BOB_ID, `${REC_BASE}/${id}`);
    expect(del.status()).toBe(404);
    // Alice can still see it
    const detail = await apiGet(alicePage, `${REC_BASE}/${id}`);
    expect(detail.status()).toBe(200);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 283: Recordings UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("283 — Recordings UI", () => {
  let uiHost: string;
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    uiHost = `h283ui-${TS}.example.com`;
    await seedRecording(alicePage, ALICE_ID, { hostname: uiHost, username: "ubuntu" });
  });
  test.afterAll(async () => {
    await alicePage.close();
  });

  test("283.1 RecordingsPage renders list with column headers", async () => {
    await alicePage.goto(`${BASE}/remote/recordings`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText("Session Recordings").first()).toBeVisible();
    await expect(alicePage.getByTestId("ssh-recordings-table")).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.getByRole("columnheader", { name: "Host" })).toBeVisible();
    await expect(alicePage.getByRole("columnheader", { name: "Duration" })).toBeVisible();
    await expect(alicePage.getByRole("columnheader", { name: "Size" })).toBeVisible();
  });

  test("283.2 Table shows the seeded recording host", async () => {
    await alicePage.goto(`${BASE}/remote/recordings`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText(`${uiHost}:22`).first()).toBeVisible({ timeout: 10_000 });
  });

  test("283.3 Play button opens the player with terminal output", async () => {
    await alicePage.goto(`${BASE}/remote/recordings`, { waitUntil: "domcontentloaded" });
    await alicePage.getByTestId("ssh-recording-play").first().click();
    await expect(alicePage.getByTestId("ssh-recording-player-card")).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.getByTestId("ssh-recording-terminal")).toBeVisible();
  });

  test("283.4 Delete removes the recording from the table", async () => {
    const delHost = `h283del-${TS}.example.com`;
    await seedRecording(alicePage, ALICE_ID, { hostname: delHost });
    await alicePage.goto(`${BASE}/remote/recordings`, { waitUntil: "domcontentloaded" });
    const row = alicePage.getByTestId("ssh-recording-row").filter({ hasText: `${delHost}:22` });
    await expect(row.first()).toBeVisible({ timeout: 10_000 });
    await row.first().getByTestId("ssh-recording-delete").click();
    await expect(
      alicePage.getByTestId("ssh-recording-row").filter({ hasText: `${delHost}:22` }),
    ).toHaveCount(0, { timeout: 10_000 });
  });
});
