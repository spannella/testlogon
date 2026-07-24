/**
 * E2E tests for full-text search in the Messenger:
 *
 * Section 37: User/contact search API — GET /messaging/contacts/search
 * Section 38: User search UI — "New DM" dialog in MessagesPage
 * Section 39: Per-conversation message search API — GET /messaging/conversations/{id}/messages/search
 * Section 40: Cross-conversation message search API — GET /messaging/messages/search
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ─────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const PYTHON   = REPO_ROOT + "/.venv/bin/python3";

// Unique token embedded in test messages to avoid collisions across runs.
const MSG_TOKEN = `e2emsgsrch_${Date.now()}`;

// ─── Session bootstrap ─────────────────────────────────────────────────────────

interface SessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name:     string;
    value:    string;
    domain:   string;
    path:     string;
    httpOnly: boolean;
    secure:   boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires:  number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

// ─── Auth helpers ──────────────────────────────────────────────────────────────

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

// ─── DDB helper ────────────────────────────────────────────────────────────────

const DDB_HELPER_PRELUDE = `
import boto3, os, time
from pathlib import Path
env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
`;

/**
 * Seed Bob's display name into:
 * 1. profiles table — so get_profile_identity returns "E2E Bob"
 * 2. UserSearch table — so contacts/search finds Bob by prefix tokens
 */
function seedBobProfile(): void {
  execSync(
    `${PYTHON} -c "
${DDB_HELPER_PRELUDE.trim()}
import os
profiles_tbl = ddb.Table(os.environ.get('PROFILE_TABLE_NAME', 'profiles'))
profiles_tbl.put_item(Item={
    'user_sub': '${BOB_ID}',
    'profile': {'display_name': 'E2E Bob'},
    'audit': [],
    'updated_at': int(time.time()),
})
search_tbl = ddb.Table(os.environ.get('DDB_USER_SEARCH', 'UserSearch'))
user_id = '${BOB_ID}'
display_name = 'E2E Bob'
tokens = set()
for word in display_name.lower().split():
    for i in range(1, len(word) + 1):
        tokens.add(word[:i])
for word in user_id.lower().replace('@', ' ').replace('.', ' ').split():
    for i in range(1, min(len(word) + 1, 8)):
        tokens.add(word[:i])
with search_tbl.batch_writer() as bw:
    for t in tokens:
        bw.put_item(Item={'token': t, 'user_id': user_id, 'display_name': display_name})
print('seeded')
"`,
    { timeout: 10_000 },
  );
}

// ─── Messaging API helpers ─────────────────────────────────────────────────────

/** GET /messaging/<path> using Alice's session cookies (CSRF not needed for GETs). */
async function msgGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/messaging/${path}`, { params });
}

/** POST /messaging/<path> with Alice's session cookies + CSRF header. */
async function msgPost(page: Page, path: string, body: object) {
  const csrf = getSessions()[ALICE_ID].csrf_token;
  return page.request.post(`${API}/messaging/${path}`, {
    data: body,
    headers: { "x-csrf-token": csrf },
  });
}

/** Find-or-create a DM between Alice and Bob; return the conversation_id. */
async function getOrCreateAliceBobDm(page: Page): Promise<string> {
  const bobSub = getSessions()[BOB_ID].user_sub;
  const r = await msgPost(page, "conversations/dm/find-or-create", { user_id: bobSub });
  if (!r.ok()) throw new Error(`find-or-create DM failed: ${r.status()} ${await r.text()}`);
  const data = await r.json() as { conversation_id: string };
  return data.conversation_id;
}

// ─── 37. User/contact search API ───────────────────────────────────────────────

test.describe("37. User/contact search API — GET /messaging/contacts/search", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    seedBobProfile();
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    // Warm up: ensures Alice is indexed in the UserSearch table.
    await page.request.get(`${API}/messaging/conversations`);
  });

  test.afterAll(async () => page?.close());

  test("returns results for query 'bob' including E2E Bob's user_id and display_name", async () => {
    const r = await msgGet(page, "contacts/search", { q: "bob" });
    expect(r.ok()).toBe(true);
    const results = await r.json() as Array<{ user_id: string; display_name: string }>;
    expect(Array.isArray(results)).toBe(true);
    const bob = results.find((u) => u.user_id === BOB_ID);
    expect(bob).toBeDefined();
    expect(bob!.display_name).toBe("E2E Bob");
  });

  test("prefix query 'e2e_b' also finds Bob", async () => {
    const r = await msgGet(page, "contacts/search", { q: "e2e_b" });
    expect(r.ok()).toBe(true);
    const results = await r.json() as Array<{ user_id: string }>;
    expect(results.some((u) => u.user_id === BOB_ID)).toBe(true);
  });

  test("query for a non-existent token returns an empty array", async () => {
    const r = await msgGet(page, "contacts/search", { q: "zzz_no_such_user_xyzabc" });
    expect(r.ok()).toBe(true);
    const results = await r.json() as unknown[];
    expect(Array.isArray(results)).toBe(true);
    expect(results.length).toBe(0);
  });

  test("Alice does not appear in her own search results", async () => {
    const r = await msgGet(page, "contacts/search", { q: "alice" });
    expect(r.ok()).toBe(true);
    const results = await r.json() as Array<{ user_id: string }>;
    expect(results.every((u) => u.user_id !== ALICE_ID)).toBe(true);
  });

  test("missing q parameter returns 422", async () => {
    const r = await page.request.get(`${API}/messaging/contacts/search`);
    expect(r.status()).toBe(422);
  });

  test("unauthenticated request returns 401 or 403", async () => {
    const anonCtx = await page.context().browser()!.newContext();
    const anonPage = await anonCtx.newPage();
    const r = await anonPage.request.get(`${API}/messaging/contacts/search`, { params: { q: "bob" } });
    await anonCtx.close();
    expect([401, 403]).toContain(r.status());
  });
});

// ─── 38. User search UI — New DM dialog ────────────────────────────────────────

test.describe("38. User search UI — New DM dialog on /messages", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    seedBobProfile();
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages`, { waitUntil: "load" });
    await expect(page.getByRole("button", { name: /new dm/i })).toBeVisible({ timeout: 8000 });
  });

  test.afterAll(async () => page?.close());

  test("clicking 'New DM' opens a dialog with a user search input", async () => {
    await page.getByRole("button", { name: /new dm/i }).click();
    await expect(page.getByRole("dialog")).toBeVisible({ timeout: 5000 });
    await expect(page.getByPlaceholder(/search for a user/i)).toBeVisible();
  });

  test("typing 'bob' triggers the search API and shows 'E2E Bob' in results", async () => {
    // Ensure dialog is open (may have closed between tests)
    if (!(await page.getByRole("dialog").isVisible())) {
      await page.getByRole("button", { name: /new dm/i }).click();
      await expect(page.getByRole("dialog")).toBeVisible({ timeout: 5000 });
    }
    // Register listener BEFORE filling to capture the debounced request.
    const searchResp = page.waitForResponse(
      (r) => r.url().includes("/messaging/contacts/search"),
    );
    await page.getByPlaceholder(/search for a user/i).fill("bob");
    await searchResp;

    // Scope to dialog to avoid strict-mode violation from 25+ sidebar DM
    // buttons that also contain "E2E Bob" from accumulated test runs.
    const dialog = page.getByRole("dialog");
    await expect(
      dialog.locator("button").filter({ hasText: "E2E Bob" }).first(),
    ).toBeVisible({ timeout: 5000 });
  });

  test("clicking E2E Bob in results triggers conversation creation and closes dialog", async () => {
    // Wait for the conversation creation POST.
    const createResp = page.waitForResponse(
      (r) =>
        r.url().includes("/messaging/conversations") &&
        r.request().method() === "POST",
    );
    const dialog = page.getByRole("dialog");
    await dialog.locator("button").filter({ hasText: "E2E Bob" }).first().click();
    await createResp;
    await expect(page.getByRole("dialog")).not.toBeVisible({ timeout: 5000 });
  });
});

// ─── 39. Per-conversation message search API ───────────────────────────────────

test.describe("39. Per-conversation message search API", () => {
  let page: Page;
  let dmConvoId: string;
  let aliceSub: string;
  let bobSub: string;
  const searchPhrase = `${MSG_TOKEN}_perconv`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    aliceSub = getSessions()[ALICE_ID].user_sub;
    bobSub   = getSessions()[BOB_ID].user_sub;

    // Get or create a DM between Alice and Bob.
    dmConvoId = await getOrCreateAliceBobDm(page);

    // Send a text message containing the unique search phrase.
    const sendResp = await msgPost(page, `conversations/${dmConvoId}/messages`, {
      text: `Hello from Alice. ${searchPhrase} end`,
    });
    if (!sendResp.ok()) throw new Error(`Send message failed: ${sendResp.status()}`);
  });

  test.afterAll(async () => page?.close());

  test("search returns the message containing the unique phrase", async () => {
    const r = await msgGet(page, `conversations/${dmConvoId}/messages/search`, {
      q: searchPhrase,
    });
    expect(r.ok()).toBe(true);
    const msgs = await r.json() as Array<{ message_id: string; text?: string }>;
    expect(Array.isArray(msgs)).toBe(true);
    expect(msgs.length).toBeGreaterThan(0);
    const found = msgs.find((m) => (m.text ?? "").includes(searchPhrase));
    expect(found).toBeDefined();
  });

  test("non-matching query returns an empty array", async () => {
    const r = await msgGet(page, `conversations/${dmConvoId}/messages/search`, {
      q: "zzz_impossible_string_xyz_never_matches",
    });
    expect(r.ok()).toBe(true);
    const msgs = await r.json() as unknown[];
    expect(Array.isArray(msgs)).toBe(true);
    expect(msgs.length).toBe(0);
  });

  test("kind=text filter includes the text message", async () => {
    const r = await msgGet(page, `conversations/${dmConvoId}/messages/search`, {
      q: searchPhrase,
      kind: "text",
    });
    expect(r.ok()).toBe(true);
    const msgs = await r.json() as Array<{ text?: string }>;
    expect(msgs.length).toBeGreaterThan(0);
    expect(msgs.some((m) => (m.text ?? "").includes(searchPhrase))).toBe(true);
  });

  test("kind=file filter excludes text-only messages", async () => {
    const r = await msgGet(page, `conversations/${dmConvoId}/messages/search`, {
      q: searchPhrase,
      kind: "file",
    });
    expect(r.ok()).toBe(true);
    const msgs = await r.json() as Array<{ text?: string; kind?: string }>;
    // Text messages are not returned when filtering by kind=file
    expect(msgs.every((m) => m.kind !== "text")).toBe(true);
  });

  test("sender_id=aliceSub finds Alice's message", async () => {
    const r = await msgGet(page, `conversations/${dmConvoId}/messages/search`, {
      q: searchPhrase,
      sender_id: aliceSub,
    });
    expect(r.ok()).toBe(true);
    const msgs = await r.json() as Array<{ sender_id?: string; text?: string }>;
    expect(msgs.length).toBeGreaterThan(0);
    expect(msgs.every((m) => m.sender_id === aliceSub)).toBe(true);
  });

  test("sender_id=bobSub returns empty (Bob hasn't sent this message)", async () => {
    const r = await msgGet(page, `conversations/${dmConvoId}/messages/search`, {
      q: searchPhrase,
      sender_id: bobSub,
    });
    expect(r.ok()).toBe(true);
    const msgs = await r.json() as unknown[];
    expect(msgs.length).toBe(0);
  });

  test("after_ts in the past includes the message", async () => {
    const pastTs = String(Math.floor(Date.now() / 1000) - 120); // 2 minutes ago
    const r = await msgGet(page, `conversations/${dmConvoId}/messages/search`, {
      q: searchPhrase,
      after_ts: pastTs,
    });
    expect(r.ok()).toBe(true);
    const msgs = await r.json() as Array<{ text?: string }>;
    expect(msgs.some((m) => (m.text ?? "").includes(searchPhrase))).toBe(true);
  });

  test("after_ts far in the future excludes the message", async () => {
    const futureTs = String(Math.floor(Date.now() / 1000) + 86400); // 24 hours from now
    const r = await msgGet(page, `conversations/${dmConvoId}/messages/search`, {
      q: searchPhrase,
      after_ts: futureTs,
    });
    expect(r.ok()).toBe(true);
    const msgs = await r.json() as unknown[];
    expect(msgs.length).toBe(0);
  });

  test("searching in a conversation the user is not part of returns 403/404", async () => {
    const r = await msgGet(page, "conversations/nonexistent_conv_id_xyz/messages/search", {
      q: searchPhrase,
    });
    expect([403, 404]).toContain(r.status());
  });
});

// ─── 40. Cross-conversation message search API ─────────────────────────────────

test.describe("40. Cross-conversation message search API — GET /messaging/messages/search", () => {
  let page: Page;
  const searchPhrase = `${MSG_TOKEN}_crossconv`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    // Send a message with the unique phrase into Alice's DM with Bob.
    const dmConvoId = await getOrCreateAliceBobDm(page);
    const sendResp = await msgPost(page, `conversations/${dmConvoId}/messages`, {
      text: `Cross-conv search probe. ${searchPhrase} end`,
    });
    if (!sendResp.ok()) throw new Error(`Send message failed: ${sendResp.status()}`);
  });

  test.afterAll(async () => page?.close());

  test("search finds the message across all conversations", async () => {
    const r = await msgGet(page, "messages/search", { q: searchPhrase });
    expect(r.ok()).toBe(true);
    const msgs = await r.json() as Array<{ text?: string; conversation_id?: string }>;
    expect(Array.isArray(msgs)).toBe(true);
    expect(msgs.length).toBeGreaterThan(0);
    expect(msgs.some((m) => (m.text ?? "").includes(searchPhrase))).toBe(true);
  });

  test("non-matching query returns empty array", async () => {
    const r = await msgGet(page, "messages/search", { q: "zzz_impossible_xyz_nomatch_abc" });
    expect(r.ok()).toBe(true);
    const msgs = await r.json() as unknown[];
    expect(Array.isArray(msgs)).toBe(true);
    expect(msgs.length).toBe(0);
  });

  test("unauthenticated request returns 401 or 403", async () => {
    const anonCtx = await page.context().browser()!.newContext();
    const anonPage = await anonCtx.newPage();
    const r = await anonPage.request.get(`${API}/messaging/messages/search`, {
      params: { q: searchPhrase },
    });
    await anonCtx.close();
    expect([401, 403]).toContain(r.status());
  });

  test("result items include conversation_id and message_id fields", async () => {
    const r = await msgGet(page, "messages/search", { q: searchPhrase });
    expect(r.ok()).toBe(true);
    const msgs = await r.json() as Array<Record<string, unknown>>;
    if (msgs.length > 0) {
      expect(msgs[0]).toHaveProperty("conversation_id");
      expect(msgs[0]).toHaveProperty("message_id");
    }
  });
});
