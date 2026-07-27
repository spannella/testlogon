/**
 * E2E tests for Contact Management:
 *
 * Section 30: Page navigation and empty state
 * Section 31: Add contact via "Add Contact" dialog (search + select)
 * Section 32: Favorite / un-favorite a contact
 * Section 33: Block / unblock a contact
 * Section 34: Remove a contact
 * Section 35: "Message" quick-action — find-or-create DM then navigate
 * Section 36: find-or-create DM — API idempotency and error cases
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
import { resolveIdentityId } from "./helpers/session";
import { usingCpp, cppSeedUserSearch, cppCleanupContacts } from "./helpers/cpp-seed-alerts-broadcast-calendar";
import { cppSeedProfile } from "./helpers/cpp-seed-profile-social";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ─────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const PYTHON   = REPO_ROOT + "/.venv/bin/python3";

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

// ─── Contacts API helpers (session-auth) ───────────────────────────────────────

async function apiContactsGet(page: Page) {
  const session = getSessions()[ALICE_ID];
  return page.request.get(`${API}/ui/contacts`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiContactsPost(page: Page, userId: string) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}/ui/contacts`, {
    data: { user_id: userId },
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── DDB helpers ───────────────────────────────────────────────────────────────

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

/** Remove all contacts for Alice from the Contacts table. */
function cleanupAliceContacts(): void {
  if (usingCpp()) { cppCleanupContacts(resolveIdentityId(ALICE_ID)); return; }
  try {
    execSync(
      `${PYTHON} -c "
${DDB_HELPER_PRELUDE.trim()}
from boto3.dynamodb.conditions import Key
tbl = ddb.Table('Contacts')
resp = tbl.query(KeyConditionExpression=Key('owner_id').eq('${ALICE_ID}'))
for item in resp['Items']:
    tbl.delete_item(Key={'owner_id': item['owner_id'], 'contact_id': item['contact_id']})
print('cleaned')
"`,
      { timeout: 10_000 },
    );
  } catch {
    /* best-effort */
  }
}

/**
 * Seed Bob's display name into:
 * 1. The profiles table (so add_contact stores "E2E Bob" as display_name)
 * 2. The UserSearch table (so the dialog search for "bob" returns Bob)
 */
function seedBobProfile(): void {
  if (usingCpp()) {
    // cpp reads profile identity from tlc_profile (keyed by whatever
    // user_id is POSTed to /ui/contacts) and search from tlc_user_search.
    // The direct-API tests POST BOB_ID (email); the Add-Contact dialog
    // POSTs the search result's user_id (the cpp SUB). Seed BOTH profile
    // keys so display_name enriches to 'E2E Bob' on either path.
    const bobSub = resolveIdentityId(BOB_ID);
    cppSeedProfile({ userSub: bobSub, displayName: 'E2E Bob' });
    if (bobSub !== BOB_ID) cppSeedProfile({ userSub: BOB_ID, displayName: 'E2E Bob' });
    cppSeedUserSearch([{ userId: bobSub, displayName: 'E2E Bob', email: BOB_ID }]);
    return;
  }
  execSync(
    `${PYTHON} -c "
${DDB_HELPER_PRELUDE.trim()}
import os
# 1. Seed profiles table so get_profile_identity returns 'E2E Bob'
profiles_tbl = ddb.Table(os.environ.get('PROFILE_TABLE_NAME', 'profiles'))
profiles_tbl.put_item(Item={
    'user_sub': '${BOB_ID}',
    'profile': {'display_name': 'E2E Bob'},
    'audit': [],
    'updated_at': int(time.time()),
})
# 2. Seed UserSearch table so dialog can find Bob
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

/** Navigate to /contacts and wait for the page heading. */
async function gotoContacts(page: Page) {
  await page.goto(`${BASE}/contacts`, { waitUntil: "load" });
  await expect(page.getByRole("heading", { name: "Contacts" })).toBeVisible({ timeout: 8000 });
}

/** Locator for a contact's name paragraph in the contact list. */
function bobContactRow(page: Page) {
  return page.locator('a[href*="/u/"]').filter({ hasText: "E2E Bob" }).first();
}

// ─── 30. Contacts page — navigation and empty state ────────────────────────────

test.describe("30. Contacts page — navigation and empty state", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    cleanupAliceContacts();
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
  });

  test.afterAll(async () => {
    await page?.close();
  });

  test("sidebar shows 'Contacts' nav item linking to /contacts", async () => {
    await page.goto(`${BASE}/`, { waitUntil: "load" });
    const link = page.getByRole("link", { name: "Contacts", exact: true });
    await expect(link).toBeVisible({ timeout: 8000 });
    await expect(link).toHaveAttribute("href", "/contacts");
  });

  test("navigating to /contacts shows the Contacts heading and Add Contact button", async () => {
    await gotoContacts(page);
    await expect(page.getByRole("button", { name: /add contact/i })).toBeVisible();
  });

  test("empty state is shown when there are no contacts", async () => {
    await expect(page.getByText(/no contacts yet/i)).toBeVisible({ timeout: 5000 });
  });

  test("clicking the sidebar Contacts link navigates to /contacts", async () => {
    await page.goto(`${BASE}/`, { waitUntil: "load" });
    await page.getByRole("link", { name: "Contacts", exact: true }).click();
    await expect(page).toHaveURL(/\/contacts/, { timeout: 8000 });
    await expect(page.getByRole("heading", { name: "Contacts" })).toBeVisible();
  });
});

// ─── 31. Add contact via dialog ────────────────────────────────────────────────

test.describe("31. Add contact via 'Add Contact' dialog", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    cleanupAliceContacts();
    seedBobProfile();
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await gotoContacts(page);
  });

  test.afterAll(async () => {
    cleanupAliceContacts();
    await page?.close();
  });

  test("clicking 'Add Contact' opens a dialog with a search input", async () => {
    await page.getByRole("button", { name: /add contact/i }).click();
    await expect(page.getByRole("dialog")).toBeVisible({ timeout: 5000 });
    await expect(page.getByPlaceholder(/search by name or email/i)).toBeVisible();
  });

  test("typing 'bob' then clicking the result adds Bob to All Contacts", async () => {
    // Type in the search input (dialog is already open from previous test's state)
    const input = page.getByPlaceholder(/search by name or email/i);
    // If dialog closed between tests, re-open it
    if (!(await page.getByRole("dialog").isVisible())) {
      await page.getByRole("button", { name: /add contact/i }).click();
      await expect(page.getByRole("dialog")).toBeVisible({ timeout: 5000 });
    }

    await input.fill("bob");

    // Wait for search result
    const resultBtn = page.getByRole("button").filter({ hasText: "E2E Bob" });
    await expect(resultBtn).toBeVisible({ timeout: 8000 });

    // Register response listener BEFORE clicking
    const addResp = page.waitForResponse(
      (r) => r.url().includes("/ui/contacts") && r.request().method() === "POST",
    );
    const refetchResp = page.waitForResponse(
      (r) => r.url().includes("/ui/contacts") && r.request().method() === "GET",
    );
    await resultBtn.click();
    await addResp;
    await refetchResp;

    // Dialog should close; Bob should appear in All Contacts
    await expect(page.getByRole("dialog")).not.toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("heading", { name: /all contacts/i })).toBeVisible({ timeout: 5000 });
    await expect(bobContactRow(page)).toBeVisible({ timeout: 5000 });
  });

  test("GET /ui/contacts returns the newly added contact with display_name 'E2E Bob'", async () => {
    const resp = await apiContactsGet(page);
    expect(resp.ok()).toBe(true);
    const data = await resp.json() as {
      contacts: Array<{ contact_id: string; display_name: string; is_favorite: boolean; is_blocked: boolean }>;
    };
    const bob = data.contacts.find((c) => c.contact_id === BOB_ID);
    expect(bob).toBeDefined();
    expect(bob!.display_name).toBe("E2E Bob");
    expect(bob!.is_favorite).toBe(false);
    expect(bob!.is_blocked).toBe(false);
  });
});

test.describe("31b. Contact identity links to canonical profile", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    cleanupAliceContacts();
    seedBobProfile();
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await apiContactsPost(page, BOB_ID);
    await gotoContacts(page);
  });

  test.afterAll(async () => {
    cleanupAliceContacts();
    await page?.close();
  });

  test("contact list name navigates to canonical profile route for authenticated viewer", async () => {
    const profileLink = bobContactRow(page);
    await expect(profileLink).toBeVisible({ timeout: 8_000 });
    await profileLink.click();

    await expect(page).toHaveURL(/\/u\//, { timeout: 8_000 });
    await expect(page.getByText(/Audience: member/i)).toBeVisible({ timeout: 8_000 });
  });

  test("unauthenticated viewer sees public profile rendering on canonical route", async ({ browser }) => {
    const anon = await browser.newPage();
    await anon.goto(`${BASE}/u/${encodeURIComponent(BOB_ID)}`, { waitUntil: "load" });
    await expect(anon.getByText(/Audience: public/i)).toBeVisible({ timeout: 8_000 });
    await expect(anon.getByRole("button", { name: /sign in to view more/i })).toBeVisible({ timeout: 8_000 });
    await anon.close();
  });
});

// ─── 32. Favorite / un-favorite a contact ─────────────────────────────────────

test.describe("32. Favorite / un-favorite a contact", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    cleanupAliceContacts();
    seedBobProfile();
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    // Pre-add Bob via API so the display_name uses the seeded profile
    const resp = await apiContactsPost(page, BOB_ID);
    if (!resp.ok()) throw new Error(`Add contact failed: ${resp.status()}`);
    await gotoContacts(page);
  });

  test.afterAll(async () => {
    cleanupAliceContacts();
    await page?.close();
  });

  test("Bob starts in the All Contacts section (Favorites section not shown)", async () => {
    await expect(page.getByRole("heading", { name: /all contacts/i })).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("heading", { name: /favorites/i })).not.toBeVisible();
    await expect(bobContactRow(page)).toBeVisible();
  });

  test("clicking the star favorites Bob and moves him to the Favorites section", async () => {
    // Register both PATCH and GET listeners before clicking
    const patchResp = page.waitForResponse(
      (r) => r.url().includes("/ui/contacts/") && r.request().method() === "PATCH",
    );
    const refetchResp = page.waitForResponse(
      (r) => r.url().includes("/ui/contacts") && r.request().method() === "GET",
    );

    await page.getByTitle("Add to favorites").first().click();
    await patchResp;
    await refetchResp;

    await expect(page.getByRole("heading", { name: /⭐ favorites/i })).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("heading", { name: /all contacts/i })).not.toBeVisible();
    await expect(bobContactRow(page)).toBeVisible();
  });

  test("API confirms is_favorite=true after starring", async () => {
    const resp = await apiContactsGet(page);
    const data = await resp.json() as { contacts: Array<{ contact_id: string; is_favorite: boolean }> };
    const bob = data.contacts.find((c) => c.contact_id === BOB_ID)!;
    expect(bob.is_favorite).toBe(true);
  });

  test("clicking the star again un-favorites Bob and moves him back to All Contacts", async () => {
    const patchResp = page.waitForResponse(
      (r) => r.url().includes("/ui/contacts/") && r.request().method() === "PATCH",
    );
    const refetchResp = page.waitForResponse(
      (r) => r.url().includes("/ui/contacts") && r.request().method() === "GET",
    );

    await page.getByTitle("Remove from favorites").first().click();
    await patchResp;
    await refetchResp;

    await expect(page.getByRole("heading", { name: /all contacts/i })).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("heading", { name: /favorites/i })).not.toBeVisible();
  });

  test("API confirms is_favorite=false after un-starring", async () => {
    const resp = await apiContactsGet(page);
    const data = await resp.json() as { contacts: Array<{ contact_id: string; is_favorite: boolean }> };
    const bob = data.contacts.find((c) => c.contact_id === BOB_ID)!;
    expect(bob.is_favorite).toBe(false);
  });
});

// ─── 33. Block / unblock a contact ────────────────────────────────────────────

test.describe("33. Block / unblock a contact", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    cleanupAliceContacts();
    seedBobProfile();
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiContactsPost(page, BOB_ID);
    if (!resp.ok()) throw new Error(`Add contact failed: ${resp.status()}`);
    await gotoContacts(page);
  });

  test.afterAll(async () => {
    cleanupAliceContacts();
    await page?.close();
  });

  test("Bob starts in All Contacts (Blocked section not shown)", async () => {
    await expect(page.getByRole("heading", { name: /all contacts/i })).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("heading", { name: /blocked/i })).not.toBeVisible();
  });

  test("clicking ⋮ → Block moves Bob to the Blocked section", async () => {
    // Open the dropdown AND click Block in the same test to avoid inter-test state loss
    await page.getByTitle("More actions").first().click();
    await expect(page.getByRole("menuitem", { name: "Block" })).toBeVisible({ timeout: 3000 });

    const patchResp = page.waitForResponse(
      (r) => r.url().includes("/ui/contacts/") && r.request().method() === "PATCH",
    );
    const refetchResp = page.waitForResponse(
      (r) => r.url().includes("/ui/contacts") && r.request().method() === "GET",
    );
    await page.getByRole("menuitem", { name: "Block" }).click();
    await patchResp;
    await refetchResp;

    await expect(page.getByRole("heading", { name: /🚫 blocked/i })).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("heading", { name: /all contacts/i })).not.toBeVisible();
    await expect(bobContactRow(page)).toBeVisible();
  });

  test("API confirms is_blocked=true", async () => {
    const resp = await apiContactsGet(page);
    const data = await resp.json() as { contacts: Array<{ contact_id: string; is_blocked: boolean }> };
    const bob = data.contacts.find((c) => c.contact_id === BOB_ID)!;
    expect(bob.is_blocked).toBe(true);
  });

  test("clicking ⋮ → Unblock moves Bob back to All Contacts", async () => {
    await page.getByTitle("More actions").first().click();
    await expect(page.getByRole("menuitem", { name: "Unblock" })).toBeVisible({ timeout: 3000 });

    const patchResp = page.waitForResponse(
      (r) => r.url().includes("/ui/contacts/") && r.request().method() === "PATCH",
    );
    const refetchResp = page.waitForResponse(
      (r) => r.url().includes("/ui/contacts") && r.request().method() === "GET",
    );
    await page.getByRole("menuitem", { name: "Unblock" }).click();
    await patchResp;
    await refetchResp;

    await expect(page.getByRole("heading", { name: /all contacts/i })).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("heading", { name: /blocked/i })).not.toBeVisible();
  });

  test("API confirms is_blocked=false after unblocking", async () => {
    const resp = await apiContactsGet(page);
    const data = await resp.json() as { contacts: Array<{ contact_id: string; is_blocked: boolean }> };
    const bob = data.contacts.find((c) => c.contact_id === BOB_ID)!;
    expect(bob.is_blocked).toBe(false);
  });
});

// ─── 34. Remove a contact ──────────────────────────────────────────────────────

test.describe("34. Remove a contact", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    cleanupAliceContacts();
    seedBobProfile();
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiContactsPost(page, BOB_ID);
    if (!resp.ok()) throw new Error(`Add contact failed: ${resp.status()}`);
    await gotoContacts(page);
  });

  test.afterAll(async () => {
    cleanupAliceContacts();
    await page?.close();
  });

  test("Bob is visible in All Contacts", async () => {
    await expect(bobContactRow(page)).toBeVisible({ timeout: 5000 });
  });

  test("clicking ⋮ → Remove deletes the contact and shows empty state", async () => {
    await page.getByTitle("More actions").first().click();
    await expect(page.getByRole("menuitem", { name: "Remove" })).toBeVisible({ timeout: 3000 });

    const deleteResp = page.waitForResponse(
      (r) => r.url().includes("/ui/contacts/") && r.request().method() === "DELETE",
    );
    const refetchResp = page.waitForResponse(
      (r) => r.url().includes("/ui/contacts") && r.request().method() === "GET",
    );
    await page.getByRole("menuitem", { name: "Remove" }).click();
    await deleteResp;
    await refetchResp;

    await expect(page.getByText(/no contacts yet/i)).toBeVisible({ timeout: 5000 });
  });

  test("GET /ui/contacts returns empty list after removal", async () => {
    const resp = await apiContactsGet(page);
    const data = await resp.json() as { contacts: unknown[] };
    expect(data.contacts).toHaveLength(0);
  });
});

// ─── 35. "Message" quick-action — open DM from Contacts page ──────────────────

test.describe("35. 'Message' quick-action navigates to Messages with DM open", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    cleanupAliceContacts();
    seedBobProfile();
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiContactsPost(page, BOB_ID);
    if (!resp.ok()) throw new Error(`Add contact failed: ${resp.status()}`);
    await gotoContacts(page);
  });

  test.afterAll(async () => {
    cleanupAliceContacts();
    await page?.close();
  });

  test("clicking the Message button calls find-or-create DM and navigates to /messages", async () => {
    const findOrCreateResp = page.waitForResponse(
      (r) =>
        r.url().includes("/messaging/conversations/dm/find-or-create") &&
        r.request().method() === "POST",
    );

    await page.getByTitle("Message").first().click();
    const dmResp = await findOrCreateResp;
    expect(dmResp.ok()).toBe(true);

    // Should navigate to messages page
    await expect(page).toHaveURL(/\/messages/, { timeout: 8000 });
  });

  test("the Messages page shows the compose bar (conversation pre-opened)", async () => {
    // After navigation with openConversation router state, the ConversationView is shown
    await expect(
      page.getByPlaceholder("Type a message...").or(
        page.getByPlaceholder("Type an encrypted message..."),
      ),
    ).toBeVisible({ timeout: 8000 });
  });

  test("the find-or-create response is a DM conversation with Bob as participant", async () => {
    test.setTimeout(20_000);
    const session = getSessions()[ALICE_ID];
    const bobSub = getSessions()[BOB_ID].user_sub;

    const r = await page.request.post(`${API}/messaging/conversations/dm/find-or-create`, {
      data: { user_id: bobSub },
      headers: { "x-csrf-token": session.csrf_token },
    });
    expect(r.ok()).toBe(true);
    const convo = await r.json() as {
      conversation_id: string;
      type: string;
      participants: Array<{ user_id: string }>;
    };
    expect(convo.type).toBe("dm");
    const participantIds = convo.participants.map((p) => p.user_id);
    expect(participantIds).toContain(bobSub);
  });
});

// ─── 36. find-or-create DM — API idempotency and error cases ──────────────────

test.describe("36. find-or-create DM — API idempotency and error handling", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
  });

  test.afterAll(async () => {
    await page?.close();
  });

  test("two sequential calls return the same conversation_id", async () => {
    test.setTimeout(20_000);
    const session = getSessions()[ALICE_ID];
    const bobSub = getSessions()[BOB_ID].user_sub;

    const call = () =>
      page.request.post(`${API}/messaging/conversations/dm/find-or-create`, {
        data: { user_id: bobSub },
        headers: { "x-csrf-token": session.csrf_token },
      });

    const r1 = await call();
    const r2 = await call();

    expect(r1.ok()).toBe(true);
    expect(r2.ok()).toBe(true);

    const d1 = await r1.json() as { conversation_id: string; type: string };
    const d2 = await r2.json() as { conversation_id: string; type: string };

    expect(d1.type).toBe("dm");
    expect(d2.type).toBe("dm");
    expect(d1.conversation_id).toBe(d2.conversation_id);
  });

  test("returns 400 when trying to DM yourself", async () => {
    const session = getSessions()[ALICE_ID];
    const aliceSub = getSessions()[ALICE_ID].user_sub;

    const r = await page.request.post(`${API}/messaging/conversations/dm/find-or-create`, {
      data: { user_id: aliceSub },
      headers: { "x-csrf-token": session.csrf_token },
    });
    expect(r.status()).toBe(400);
  });

  test("contacts GET returns 401 when not authenticated", async () => {
    // A fresh request context with no cookies
    const anonCtx = await page.context().browser()!.newContext();
    const anonPage = await anonCtx.newPage();
    const r = await anonPage.request.get(`${API}/ui/contacts`);
    await anonCtx.close();
    expect([401, 403]).toContain(r.status());
  });

  test("contacts PATCH returns 404 for a non-existent contact_id", async () => {
    const session = getSessions()[ALICE_ID];
    const r = await page.request.patch(`${API}/ui/contacts/nonexistent-user-xyz`, {
      data: { is_favorite: true },
      headers: { "x-csrf-token": session.csrf_token },
    });
    expect(r.status()).toBe(404);
  });

  test("contacts POST returns 400 when trying to add yourself", async () => {
    const session = getSessions()[ALICE_ID];
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    const r = await page.request.post(`${API}/ui/contacts`, {
      data: { user_id: aliceSub },
      headers: { "x-csrf-token": session.csrf_token },
    });
    expect(r.status()).toBe(400);
  });
});
