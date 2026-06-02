/**
 * FEED-004 — Emoji / GIF / Sticker comments.
 *
 * Sections 723–728. Covers the comment API extension (kind=text|gif|sticker),
 * validation, cross-kind interactions (tips, replies), and UI rendering of
 * GIF / sticker / emoji-only comments.
 *
 * Reuses the standard cookie + CSRF auth pattern (page.request carries the
 * session cookies; non-GET requests must send the x-csrf-token header).
 */
import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import path from "path";

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();

const GIF_URL = `https://media.giphy.com/media/feed004_${TS}/giphy.gif`;
const STICKER_URL = `/mock/s3/stickers/coll_love_pack/stk_feed004_${TS}.webp`;

interface SessionData {
  user_sub: string;
  csrf_token: string;
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
    const repoRoot = process.cwd().includes("/frontend") ? path.resolve(process.cwd(), "..") : process.cwd();
    const setupScript = path.join(repoRoot, "e2e_session_setup.py");
    const raw = execSync(`python3 ${setupScript}`, { cwd: repoRoot, timeout: 30_000 }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function apiPost(page: Page, userId: string, endpoint: string, data: object) {
  const session = getSessions()[userId];
  return page.request.post(`${API}${endpoint}`, {
    data,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiPatch(page: Page, userId: string, endpoint: string, data: object) {
  const session = getSessions()[userId];
  return page.request.patch(`${API}${endpoint}`, {
    data,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGet(page: Page, userId: string, endpoint: string) {
  const session = getSessions()[userId];
  return page.request.get(`${API}${endpoint}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

interface Comment {
  comment_id: string;
  kind: string;
  text?: string | null;
  body?: string | null;
  body_plain?: string | null;
  gif_url?: string | null;
  gif_alt_text?: string | null;
  gif_width?: number | null;
  gif_height?: number | null;
  sticker_id?: string | null;
  sticker_collection_id?: string | null;
  sticker_url?: string | null;
  sticker_alt_text?: string | null;
  parent_comment_id?: string | null;
  tip_total_cents?: number;
}

let alice: Page;
let bob: Page;
let postId: string;

test.describe("FEED-004 rich comments", () => {
  test.beforeAll(async ({ browser }) => {
    alice = await browser.newPage();
    bob = await browser.newPage();
    await injectAuth(alice, ALICE_ID);
    await injectAuth(bob, BOB_ID);

    const resp = await apiPost(alice, ALICE_ID, "/posts", {
      body: `FEED-004 rich-comment host post ${TS}`,
      visibility: "public",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    postId = data.post_id;
    expect(postId).toBeTruthy();
  });

  test.afterAll(async () => {
    await alice?.close();
    await bob?.close();
  });

  // ── Section 723: GIF/Sticker comment creation API ────────────────
  test.describe("Section 723: GIF & sticker comment API", () => {
    test("723.1 create GIF comment", async () => {
      const resp = await apiPost(bob, BOB_ID, `/posts/${postId}/comments`, {
        kind: "gif",
        gif_url: GIF_URL,
        gif_alt_text: "happy dance",
        gif_width: 480,
        gif_height: 270,
      });
      expect(resp.status()).toBe(200);
      const c = (await resp.json()) as Comment;
      expect(c.kind).toBe("gif");
      expect(c.gif_url).toBe(GIF_URL);
      expect(c.gif_width).toBe(480);
      expect(c.gif_height).toBe(270);
    });

    test("723.2 create sticker comment", async () => {
      const resp = await apiPost(bob, BOB_ID, `/posts/${postId}/comments`, {
        kind: "sticker",
        sticker_id: `stk_feed004_${TS}`,
        sticker_collection_id: "coll_love_pack",
        sticker_url: STICKER_URL,
        sticker_alt_text: "love heart",
      });
      expect(resp.status()).toBe(200);
      const c = (await resp.json()) as Comment;
      expect(c.kind).toBe("sticker");
      expect(c.sticker_id).toBe(`stk_feed004_${TS}`);
      expect(c.sticker_url).toBe(STICKER_URL);
    });

    test("723.3 GIF comment appears in list with fields", async () => {
      const resp = await apiGet(alice, ALICE_ID, `/posts/${postId}/comments`);
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      const items: Comment[] = data.items ?? data.comments ?? data;
      const gif = items.find((c) => c.kind === "gif" && c.gif_url === GIF_URL);
      expect(gif).toBeTruthy();
      expect(gif!.gif_alt_text).toBe("happy dance");
    });

    test("723.4 reject GIF comment without gif_url", async () => {
      const resp = await apiPost(bob, BOB_ID, `/posts/${postId}/comments`, { kind: "gif" });
      expect(resp.status()).toBe(422);
    });

    test("723.5 reject sticker comment without sticker_id", async () => {
      const resp = await apiPost(bob, BOB_ID, `/posts/${postId}/comments`, {
        kind: "sticker",
        sticker_url: STICKER_URL,
      });
      expect(resp.status()).toBe(422);
    });
  });

  // ── Section 724: emoji / text comments ───────────────────────────
  test.describe("Section 724: emoji & text comments", () => {
    test("724.1 emoji-only text comment stored verbatim", async () => {
      const resp = await apiPost(alice, ALICE_ID, `/posts/${postId}/comments`, {
        kind: "text",
        body: "🔥🎉",
      });
      expect(resp.status()).toBe(200);
      const c = (await resp.json()) as Comment;
      expect(c.kind).toBe("text");
      expect(c.body ?? c.body_plain).toBe("🔥🎉");
    });

    test("724.2 default kind is text when omitted", async () => {
      const resp = await apiPost(alice, ALICE_ID, `/posts/${postId}/comments`, {
        body: `plain comment ${TS}`,
      });
      expect(resp.status()).toBe(200);
      const c = (await resp.json()) as Comment;
      expect(c.kind).toBe("text");
    });

    test("724.3 emoji shortcode text stored as-is", async () => {
      const resp = await apiPost(alice, ALICE_ID, `/posts/${postId}/comments`, {
        kind: "text",
        body: ":fire: launch",
      });
      expect(resp.status()).toBe(200);
      const c = (await resp.json()) as Comment;
      expect((c.body ?? c.body_plain ?? "").includes(":fire:") || (c.body ?? c.body_plain) === ":fire: launch").toBeTruthy();
    });

    test("724.4 empty text comment rejected", async () => {
      const resp = await apiPost(alice, ALICE_ID, `/posts/${postId}/comments`, {
        kind: "text",
        body: "",
      });
      expect(resp.status()).toBe(422);
    });
  });

  // ── Section 725: validation edge cases ───────────────────────────
  test.describe("Section 725: validation edge cases", () => {
    test("725.1 invalid kind rejected", async () => {
      const resp = await apiPost(bob, BOB_ID, `/posts/${postId}/comments`, {
        kind: "video",
        gif_url: GIF_URL,
      });
      expect(resp.status()).toBe(422);
    });

    test("725.2 sticker without sticker_url rejected", async () => {
      const resp = await apiPost(bob, BOB_ID, `/posts/${postId}/comments`, {
        kind: "sticker",
        sticker_id: "stk_x",
      });
      expect(resp.status()).toBe(422);
    });

    test("725.3 cannot combine gif + sticker (sticker fields ignored for gif kind, but missing gif_url for sticker)", async () => {
      // A gif+sticker hybrid: kind=sticker with only gif fields → missing sticker_id → 422
      const resp = await apiPost(bob, BOB_ID, `/posts/${postId}/comments`, {
        kind: "sticker",
        gif_url: GIF_URL,
        sticker_url: STICKER_URL,
      });
      expect(resp.status()).toBe(422);
    });

    test("725.4 GIF width/height round-trip", async () => {
      const resp = await apiPost(bob, BOB_ID, `/posts/${postId}/comments`, {
        kind: "gif",
        gif_url: `${GIF_URL}?d`,
        gif_width: 640,
        gif_height: 360,
      });
      expect(resp.status()).toBe(200);
      const c = (await resp.json()) as Comment;
      expect(c.gif_width).toBe(640);
      expect(c.gif_height).toBe(360);
    });
  });

  // ── Section 726: cross-kind interactions ─────────────────────────
  test.describe("Section 726: cross-kind interactions", () => {
    let gifCommentId: string;
    let stickerCommentId: string;

    test.beforeAll(async () => {
      const g = await apiPost(bob, BOB_ID, `/posts/${postId}/comments`, {
        kind: "gif",
        gif_url: `${GIF_URL}?x726`,
        gif_alt_text: "x726",
      });
      gifCommentId = ((await g.json()) as Comment).comment_id;
      const s = await apiPost(bob, BOB_ID, `/posts/${postId}/comments`, {
        kind: "sticker",
        sticker_id: `stk_726_${TS}`,
        sticker_collection_id: "coll_love_pack",
        sticker_url: `${STICKER_URL}?x726`,
        sticker_alt_text: "x726",
      });
      stickerCommentId = ((await s.json()) as Comment).comment_id;
    });

    test("726.1 reply to GIF comment with text", async () => {
      const resp = await apiPost(alice, ALICE_ID, `/posts/${postId}/comments`, {
        kind: "text",
        body: `reply to gif ${TS}`,
        parent_comment_id: gifCommentId,
      });
      expect(resp.status()).toBe(200);
      const c = (await resp.json()) as Comment;
      expect(c.parent_comment_id).toBe(gifCommentId);
    });

    test("726.2 tip a GIF comment", async () => {
      const resp = await apiPost(alice, ALICE_ID, `/posts/${postId}/comments/${gifCommentId}/tip`, {
        amount_cents: 50,
      });
      expect([200, 402]).toContain(resp.status());
    });

    test("726.3 reply to sticker comment with GIF", async () => {
      const resp = await apiPost(alice, ALICE_ID, `/posts/${postId}/comments`, {
        kind: "gif",
        gif_url: `${GIF_URL}?reply`,
        parent_comment_id: stickerCommentId,
      });
      expect(resp.status()).toBe(200);
      const c = (await resp.json()) as Comment;
      expect(c.kind).toBe("gif");
      expect(c.parent_comment_id).toBe(stickerCommentId);
    });

    test("726.4 thread has mixed kinds", async () => {
      const resp = await apiGet(alice, ALICE_ID, `/posts/${postId}/comments`);
      const data = await resp.json();
      const items: Comment[] = data.items ?? data.comments ?? data;
      const kinds = new Set(items.map((c) => c.kind));
      expect(kinds.has("text")).toBeTruthy();
      expect(kinds.has("gif")).toBeTruthy();
      expect(kinds.has("sticker")).toBeTruthy();
    });
  });

  // ── Section 727: edit & auth ─────────────────────────────────────
  test.describe("Section 727: edit & auth", () => {
    test("727.1 edit a text comment", async () => {
      const created = await apiPost(alice, ALICE_ID, `/posts/${postId}/comments`, {
        kind: "text",
        body: `editable ${TS}`,
      });
      const cid = ((await created.json()) as Comment).comment_id;
      const resp = await apiPatch(alice, ALICE_ID, `/posts/${postId}/comments/${cid}`, {
        body: `edited ${TS}`,
        expected_version: 1,
      });
      expect(resp.status()).toBe(200);
      const c = (await resp.json()) as Comment;
      expect(c.kind).toBe("text");
      expect(c.body ?? c.body_plain).toBe(`edited ${TS}`);
    });

    test("727.2 unauthenticated comment rejected", async ({ request }) => {
      const resp = await request.post(`${API}/posts/${postId}/comments`, {
        data: { kind: "gif", gif_url: GIF_URL },
      });
      expect(resp.status()).toBe(401);
    });
  });

  // ── Section 728: UI rendering ────────────────────────────────────
  test.describe("Section 728: UI rendering", () => {
    test("728.1 GIF & sticker comments render as images; emoji toolbar visible", async () => {
      // Seed one GIF and one sticker comment by Alice (the author) so they
      // render in her post detail view.
      const uiGif = `${GIF_URL}?ui728`;
      const uiSticker = `${STICKER_URL}?ui728`;
      await apiPost(alice, ALICE_ID, `/posts/${postId}/comments`, {
        kind: "gif",
        gif_url: uiGif,
        gif_alt_text: "ui gif 728",
      });
      await apiPost(alice, ALICE_ID, `/posts/${postId}/comments`, {
        kind: "sticker",
        sticker_id: `stk_ui728_${TS}`,
        sticker_collection_id: "coll_love_pack",
        sticker_url: uiSticker,
        sticker_alt_text: "ui sticker 728",
      });

      await alice.goto(`${BASE}/posts/${postId}`, { waitUntil: "domcontentloaded" });

      // GIF comment image
      await expect(alice.locator(`img[src="${uiGif}"]`).first()).toBeVisible({ timeout: 15_000 });
      // Sticker comment image with fixed-size container class
      const sticker = alice.locator(`img[src="${uiSticker}"]`).first();
      await expect(sticker).toBeVisible({ timeout: 15_000 });
      await expect(sticker).toHaveClass(/w-20/);
      await expect(sticker).toHaveClass(/h-20/);

      // Emoji button present in composer toolbar
      await expect(alice.getByTestId("comment-emoji-button").first()).toBeVisible();
      await expect(alice.getByTestId("comment-gif-button").first()).toBeVisible();
      await expect(alice.getByTestId("comment-sticker-button").first()).toBeVisible();
    });
  });
});
