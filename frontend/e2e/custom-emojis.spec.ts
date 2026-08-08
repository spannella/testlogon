/**
 * E2E tests for MSG-007: Custom Emojis.
 *
 * Section 729: Personal custom emoji CRUD API
 * Section 730: Global custom emoji admin API
 * Section 731: Custom emoji in messages + reactions (resolution)
 * Section 732: Custom emoji UI (EmojiPicker "Custom" tab + management page)
 *
 * ── Authentication ──────────────────────────────────────────────────────────
 * Cookie + CSRF session auth via `e2e_admin_session_setup.py` (same pattern as
 * admin-roles.spec.ts). Session keys: root, alice, bob, charlie_admin.
 * Personal emoji endpoints (`/ui/emojis/custom`) use require_ui_session.
 * Admin endpoints (`/v1/admin/emojis`) require ADMIN/ROOT.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, unauthContext } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const TS = Date.now();

// A 64x64 PNG (orange) — valid emoji image.
const PNG_B64 =
  "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAlklEQVR4nO3QQREAIAzAMEA5zoeMPGgU9LrnrlkfOzpAa4AO0BqgA7QG6ACtATpAa4AO0BqgA7QG6ACtATpAa4AO0BqgA7QG6ACtATpAa4AO0BqgA7QG6ACtATpAa4AO0BqgA7QG6ACtATpAa4AO0BqgA7QG6ACtATpAa4AO0BqgA7QG6ADtAXQVAv7c5dmmAAAAAElFTkSuQmCC";
// A 64x64 JPEG (blue) — disallowed content type.
const JPEG_B64 =
  "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCABAAEADASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDHooor9MPz0KKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooA//Z";

const PNG = Buffer.from(PNG_B64, "base64");
const JPEG = Buffer.from(JPEG_B64, "base64");
// Oversized PNG: valid magic header + padding > 256KB.
const BIG = Buffer.concat([PNG, Buffer.alloc(300 * 1024, 0)]);

// ── Session bootstrap (admin-roles pattern) ─────────────────────────────────

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
function sessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function identityPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await page.context().addCookies(sessions()[identity].cookies);
  // Seed the client-side auth store so ProtectedRoute treats the page as
  // authenticated (cookies alone only satisfy server-side API auth).
  await page.goto("/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, sessions()[identity].user_sub);
  return page;
}

function csrf(identity: string): string {
  return sessions()[identity].csrf_token;
}

// Multipart upload helper.
async function uploadEmoji(
  page: Page,
  identity: string,
  path: string,
  fields: { shortcode: string; name: string; alt_text?: string; category?: string },
  file: { name: string; mimeType: string; buffer: Buffer },
) {
  return page.request.post(`${API}/${path}`, {
    headers: { "x-csrf-token": csrf(identity) },
    multipart: {
      shortcode: fields.shortcode,
      name: fields.name,
      alt_text: fields.alt_text ?? "",
      category: fields.category ?? "Uncategorized",
      file,
    },
  });
}

const png = () => ({ name: "e.png", mimeType: "image/png", buffer: PNG });

// ════════════════════════════════════════════════════════════════════════════
// Section 729: Personal custom emoji CRUD API
// ════════════════════════════════════════════════════════════════════════════

test.describe("729: Personal custom emoji CRUD API", () => {
  let alice: Page;
  const SC = `alice_${TS}`;
  let emojiId = "";

  test.beforeAll(async ({ browser }) => {
    alice = await identityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alice.close();
  });

  test("729.1 upload personal emoji with valid PNG", async () => {
    const res = await uploadEmoji(alice, "alice", "ui/emojis/custom", { shortcode: SC, name: "Alice Cat" }, png());
    expect(res.status()).toBe(201);
    const body = await res.json();
    expect(body.emoji_id).toBeTruthy();
    expect(body.shortcode).toBe(SC);
    expect(body.image_url).toContain("/mock/s3/");
    expect(body.owner_scope).toContain("USER#");
    emojiId = body.emoji_id;
  });

  test("729.2 duplicate shortcode in same scope rejected (409)", async () => {
    const res = await uploadEmoji(alice, "alice", "ui/emojis/custom", { shortcode: SC, name: "Dup" }, png());
    expect(res.status()).toBe(409);
    const body = await res.json();
    expect(String(body.detail).toLowerCase()).toContain("shortcode already exists");
  });

  test("729.3 oversized file rejected (400)", async () => {
    const res = await uploadEmoji(
      alice,
      "alice",
      "ui/emojis/custom",
      { shortcode: `big_${TS}`, name: "Big" },
      { name: "big.png", mimeType: "image/png", buffer: BIG },
    );
    expect(res.status()).toBe(400);
    const body = await res.json();
    expect(String(body.detail).toLowerCase()).toContain("256kb");
  });

  test("729.4 invalid content type (JPEG) rejected (400)", async () => {
    const res = await uploadEmoji(
      alice,
      "alice",
      "ui/emojis/custom",
      { shortcode: `jpg_${TS}`, name: "Jpg" },
      { name: "e.jpg", mimeType: "image/jpeg", buffer: JPEG },
    );
    expect(res.status()).toBe(400);
    const body = await res.json();
    expect(String(body.detail).toLowerCase()).toContain("png");
  });

  test("729.5 invalid shortcode characters rejected (422)", async () => {
    const res = await uploadEmoji(alice, "alice", "ui/emojis/custom", { shortcode: "Bad Code!", name: "x" }, png());
    expect(res.status()).toBe(422);
  });

  test("729.6 list includes uploaded emoji", async () => {
    const res = await alice.request.get(`${API}/ui/emojis/custom`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.emojis.some((e: { shortcode: string }) => e.shortcode === SC)).toBe(true);
    expect(body.personal_count).toBeGreaterThanOrEqual(1);
  });

  test("729.7 auth required without session (401)", async () => {
    const anon = await unauthContext(API);
    const res = await anon.get(`/ui/emojis/custom`);
    expect(res.status()).toBe(401);
    await anon.dispose();
  });

  test("729.8 delete personal emoji removes it from list", async () => {
    const del = await alice.request.delete(`${API}/ui/emojis/custom/${emojiId}`, {
      headers: { "x-csrf-token": csrf("alice") },
    });
    expect(del.status()).toBe(200);
    const res = await alice.request.get(`${API}/ui/emojis/custom`);
    const body = await res.json();
    expect(body.emojis.some((e: { emoji_id: string }) => e.emoji_id === emojiId)).toBe(false);
  });

  test("729.9 delete non-existent emoji (404)", async () => {
    const del = await alice.request.delete(`${API}/ui/emojis/custom/ce_doesnotexist`, {
      headers: { "x-csrf-token": csrf("alice") },
    });
    expect(del.status()).toBe(404);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Section 730: Global custom emoji admin API
// ════════════════════════════════════════════════════════════════════════════

test.describe("730: Global custom emoji admin API", () => {
  let charlie: Page;
  let alice: Page;
  const SC = `global_${TS}`;
  let globalId = "";

  test.beforeAll(async ({ browser }) => {
    charlie = await identityPage(browser, "charlie_admin");
    alice = await identityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await charlie.close();
    await alice.close();
  });

  test("730.1 admin uploads global emoji (owner_scope GLOBAL)", async () => {
    const res = await uploadEmoji(charlie, "charlie_admin", "v1/admin/emojis", { shortcode: SC, name: "Logo" }, png());
    expect(res.status()).toBe(201);
    const body = await res.json();
    expect(body.owner_scope).toBe("GLOBAL");
    globalId = body.emoji_id;
  });

  test("730.2 non-admin cannot upload global emoji (403)", async () => {
    const res = await uploadEmoji(alice, "alice", "v1/admin/emojis", { shortcode: `na_${TS}`, name: "x" }, png());
    expect(res.status()).toBe(403);
  });

  test("730.3 global emoji appears in user's visible list", async () => {
    const res = await alice.request.get(`${API}/ui/emojis/custom`);
    const body = await res.json();
    expect(body.emojis.some((e: { shortcode: string }) => e.shortcode === SC)).toBe(true);
    expect(body.global_count).toBeGreaterThanOrEqual(1);
  });

  test("730.4 admin deletes global emoji", async () => {
    const del = await charlie.request.delete(`${API}/v1/admin/emojis/${globalId}`, {
      headers: { "x-csrf-token": csrf("charlie_admin") },
    });
    expect(del.status()).toBe(200);
    const res = await alice.request.get(`${API}/ui/emojis/custom`);
    const body = await res.json();
    expect(body.emojis.some((e: { emoji_id: string }) => e.emoji_id === globalId)).toBe(false);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Section 731: Custom emoji resolution in messages + reactions
// ════════════════════════════════════════════════════════════════════════════

test.describe("731: Custom emoji resolution", () => {
  let alice: Page;
  let bob: Page;
  let charlie: Page;
  const PERSONAL = `msg_${TS}`;
  const GLOBAL = `gmsg_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alice = await identityPage(browser, "alice");
    bob = await identityPage(browser, "bob");
    charlie = await identityPage(browser, "charlie_admin");
    await uploadEmoji(alice, "alice", "ui/emojis/custom", { shortcode: PERSONAL, name: "P" }, png());
    await uploadEmoji(charlie, "charlie_admin", "v1/admin/emojis", { shortcode: GLOBAL, name: "G" }, png());
  });
  test.afterAll(async () => {
    await alice.close();
    await bob.close();
    await charlie.close();
  });

  test("731.1 personal shortcode resolves to image URL for owner", async () => {
    const res = await alice.request.get(`${API}/ui/emojis/custom/resolve`, { params: { codes: PERSONAL } });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.resolved[PERSONAL]).toContain("/mock/s3/");
  });

  test("731.2 personal shortcode NOT resolvable by another user", async () => {
    const res = await bob.request.get(`${API}/ui/emojis/custom/resolve`, { params: { codes: PERSONAL } });
    const body = await res.json();
    expect(body.resolved[PERSONAL]).toBeUndefined();
  });

  test("731.3 global shortcode resolvable by any user", async () => {
    const res = await bob.request.get(`${API}/ui/emojis/custom/resolve`, { params: { codes: GLOBAL } });
    const body = await res.json();
    expect(body.resolved[GLOBAL]).toContain("/mock/s3/");
  });

  test("731.4 unknown shortcode resolves to empty map entry", async () => {
    const res = await alice.request.get(`${API}/ui/emojis/custom/resolve`, { params: { codes: `nope_${TS}` } });
    const body = await res.json();
    expect(Object.keys(body.resolved)).not.toContain(`nope_${TS}`);
  });

  test("731.5 message text with shortcode is stored verbatim", async () => {
    // Create a DM Alice -> Bob and send a message containing the shortcode.
    const convRes = await alice.request.post(`${API}/messaging/conversations`, {
      headers: { "x-csrf-token": csrf("alice"), "Content-Type": "application/json" },
      data: { participant_ids: [sessions().bob.user_sub], type: "dm" },
    });
    expect([200, 201]).toContain(convRes.status());
    const conv = await convRes.json();
    const convId = conv.conversation_id ?? conv.id;
    const text = `hello :${PERSONAL}: world`;
    const msgRes = await alice.request.post(`${API}/messaging/conversations/${convId}/messages`, {
      headers: { "x-csrf-token": csrf("alice"), "Content-Type": "application/json" },
      data: { text },
    });
    expect([200, 201]).toContain(msgRes.status());
    const msg = await msgRes.json();
    expect(msg.text).toContain(`:${PERSONAL}:`);

    // 731.6: react with a custom emoji (custom: prefix key).
    const reactKey = `custom:${PERSONAL}`;
    const reactRes = await alice.request.post(
      `${API}/messaging/conversations/${convId}/messages/${msg.message_id}/reactions`,
      {
        headers: { "x-csrf-token": csrf("alice"), "Content-Type": "application/json" },
        data: { emoji: reactKey },
      },
    );
    expect([200, 201]).toContain(reactRes.status());
    const listRes = await alice.request.get(`${API}/messaging/conversations/${convId}/messages`);
    const list = await listRes.json();
    const stored = (Array.isArray(list) ? list : list.messages).find(
      (m: { message_id: string }) => m.message_id === msg.message_id,
    );
    expect(Object.keys(stored.reactions_counts ?? {})).toContain(reactKey);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Section 732: Custom emoji UI
// ════════════════════════════════════════════════════════════════════════════

test.describe("732: Custom emoji UI", () => {
  let alice: Page;
  const SC = `ui_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alice = await identityPage(browser, "alice");
    await uploadEmoji(alice, "alice", "ui/emojis/custom", { shortcode: SC, name: "UI Cat" }, png());
  });
  test.afterAll(async () => {
    await alice.close();
  });

  test("732.1 management page lists the uploaded emoji", async () => {
    await alice.goto("/settings/emojis");
    await expect(alice.getByTestId("custom-emojis-page")).toBeVisible();
    await expect(alice.getByTestId(`emoji-card-${SC}`)).toBeVisible({ timeout: 10_000 });
  });

  test("732.2 EmojiPicker shows Custom tab and the emoji", async () => {
    await alice.goto("/messages");
    // Open a conversation compose bar with the emoji picker.
    // The emoji picker trigger lives in the compose bar; open via the smiley button.
    const smiley = alice.getByRole("button", { name: /emoji/i }).first();
    if ((await smiley.count()) === 0) {
      test.skip(true, "No conversation/compose bar available in this run");
    }
    await smiley.click();
    await expect(alice.getByTestId("emoji-category-custom")).toBeVisible({ timeout: 10_000 });
    await alice.getByTestId("emoji-category-custom").click();
    await expect(alice.getByTestId("emoji-custom-section").locator(`[data-custom-emoji="${SC}"]`)).toBeVisible();
  });
});
