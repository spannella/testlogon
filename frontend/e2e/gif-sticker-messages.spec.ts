/**
 * E2E tests for GIF & Sticker Messages (MSG-008).
 *
 * Two new message kinds:
 *   - gif      : searched from a MOCK GIF provider (deterministic in dev mode)
 *   - sticker  : platform-hosted image collections users browse/favorite/send
 *
 * Actors:
 *   Alice   (e2e_alice@test.local)   — sender / primary actor
 *   Bob     (e2e_bob@test.local)     — recipient
 *   Root                              — admin (creates sticker collections)
 *
 * Auth patterns:
 *   - Alice: browser-context cookies + CSRF (page.request + x-csrf-token)
 *   - Bob:   dev-mode Bearer token auth (request fixture, bypasses CSRF)
 *   - A test sticker collection is seeded directly into DynamoDB local so the
 *     send/favorite flows have a stable collection to work against.
 *
 * Sections:
 *   706. GIF Search API (mock provider)
 *   707. Sticker Collection API
 *   708. GIF Message Send/Receive API
 *   709. Sticker Message Send/Receive API
 *   710. Admin Sticker Management API
 *   711. GIF & Sticker UI
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ───────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const PYTHON = REPO_ROOT + "/.venv/bin/python";

const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

const TS = Date.now();
const TEST_COLLECTION_ID = `sc_e2e${TS}`;
const TEST_STICKER_ID = `stk_e2e${TS}`;

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None";
    expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

let _adminSessions: Record<string, SessionData> | null = null;
function getAdminSessions(): Record<string, SessionData> {
  if (!_adminSessions) {
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

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

type APIRequestContext = import("@playwright/test").APIRequestContext;

/** GET/POST/DELETE authenticated as Alice (browser cookies + Alice CSRF). */
async function apiPost(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}
async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}
async function apiDelete(page: Page, path: string) {
  const session = getSessions()[ALICE_ID];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

/** GET/POST as an arbitrary user using the dev-mode Bearer token (bypasses CSRF). */
async function apiGetBearer(req: APIRequestContext, path: string, userId: string) {
  return req.get(`${API}${path}`, { headers: { Authorization: `Bearer ${getSessions()[userId].user_sub}` } });
}

// ─── DDB seed helper ──────────────────────────────────────────────────────────

const DDB_HELPER_PRELUDE = `
import boto3, os
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

/** Seed a test sticker collection (1 META + 1 sticker) directly into DDB. */
function seedStickerCollection() {
  execSync(
    `${PYTHON} -c "${DDB_HELPER_PRELUDE}
tbl = ddb.Table(os.environ.get('DDB_STICKER_COLLECTIONS_TABLE', 'sticker_collections'))
url = '/mock/s3/my-chat-images/stickers/${TEST_COLLECTION_ID}/${TEST_STICKER_ID}.png'
tbl.put_item(Item={
    'collection_id': '${TEST_COLLECTION_ID}',
    'sk': 'META',
    'name': 'E2E Cats ${TS}',
    'description': 'E2E test collection',
    'thumbnail_url': url,
    'sticker_count': 1,
    'created_by': 'root',
    'created_at': ${Math.floor(TS / 1000)},
    'is_active': '1',
})
tbl.put_item(Item={
    'collection_id': '${TEST_COLLECTION_ID}',
    'sk': 'STICKER#${TEST_STICKER_ID}',
    'sticker_id': '${TEST_STICKER_ID}',
    'image_url': url,
    'alt_text': 'Cat waving hello',
    'sort_order': 1,
    'width': 256,
    'height': 256,
})
print('seeded')
"`,
    { timeout: 15_000 },
  );
}

/**
 * Purge a user's accumulated sticker favorites (billing table FAV_STICKER# rows).
 * Prior test runs leave stale favorites; the search endpoint caps results at 50, so
 * stale favorites can crowd out the freshly-seeded collection. Clean before seeding.
 */
function cleanupStickerFavorites(userSub: string) {
  execSync(
    `${PYTHON} -c "${DDB_HELPER_PRELUDE}
from boto3.dynamodb.conditions import Key
tbl = ddb.Table(os.environ.get('BILLING_TABLE_NAME', 'billing'))
resp = tbl.query(
    KeyConditionExpression=Key('pk').eq('USER#${userSub}') & Key('sk').begins_with('FAV_STICKER#'),
)
n = 0
for item in resp.get('Items', []):
    tbl.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
    n += 1
print('purged', n)
"`,
    { timeout: 15_000 },
  );
}

// ─── DM conversation bootstrap ────────────────────────────────────────────────

let _dmConvoId: string | null = null;
async function getOrCreateDm(page: Page): Promise<string> {
  if (_dmConvoId) return _dmConvoId;
  const bobSub = getSessions()[BOB_ID].user_sub;
  const resp = await apiPost(page, "/messaging/conversations", {
    participant_ids: [bobSub],
    type: "dm",
  });
  if (!resp.ok()) {
    const body = await resp.text().catch(() => "(unreadable)");
    throw new Error(`DM creation failed: HTTP ${resp.status()} — ${body}`);
  }
  const body = await resp.json();
  _dmConvoId = body.conversation_id as string;
  return _dmConvoId;
}

interface RawMsg {
  message_id: string;
  kind: string;
  gif_url?: string;
  gif_alt_text?: string;
  gif_width?: number;
  gif_height?: number;
  gif_provider?: string;
  sticker_id?: string;
  sticker_collection_id?: string;
  sticker_url?: string;
  sticker_alt_text?: string;
  reply_to_message_id?: string;
  text?: string | null;
}

interface GifResult {
  id: string; url: string; alt_text: string; width: number; height: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 706: GIF Search API (mock provider)
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 706: GIF Search API", () => {
  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await page.close();
  });

  test("706.1 trending GIFs returns results", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiGet(page, "/ui/stickers/gifs/trending");
    expect(resp.status()).toBe(200);
    const results = (await resp.json()) as GifResult[];
    expect(Array.isArray(results)).toBe(true);
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].url).toBeTruthy();
    expect(results[0]).toHaveProperty("alt_text");
    await page.close();
  });

  test("706.2 GIF search returns results", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiGet(page, "/ui/stickers/gifs/search?q=happy");
    expect(resp.status()).toBe(200);
    const results = (await resp.json()) as GifResult[];
    expect(results.length).toBeGreaterThan(0);
    await page.close();
  });

  test("706.3 empty query returns trending-style list", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiGet(page, "/ui/stickers/gifs/search?q=");
    expect(resp.status()).toBe(200);
    const results = (await resp.json()) as GifResult[];
    expect(results.length).toBeGreaterThan(0);
    await page.close();
  });

  test("706.4 GIF search respects limit", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiGet(page, "/ui/stickers/gifs/search?q=test&limit=5");
    expect(resp.status()).toBe(200);
    const results = (await resp.json()) as GifResult[];
    expect(results.length).toBeLessThanOrEqual(5);
    await page.close();
  });

  test("706.5 GIF search is deterministic for same query", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const r1 = await (await apiGet(page, "/ui/stickers/gifs/search?q=happy")).json() as GifResult[];
    const r2 = await (await apiGet(page, "/ui/stickers/gifs/search?q=happy")).json() as GifResult[];
    expect(r1.map((g) => g.id)).toEqual(r2.map((g) => g.id));
    await page.close();
  });

  test("706.6 GIF search requires auth (401)", async ({ request }) => {
    const resp = await request.get(`${API}/ui/stickers/gifs/trending`);
    expect(resp.status()).toBe(401);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 707: Sticker Collection API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 707: Sticker Collection API", () => {
  test.beforeAll(async ({ browser }) => {
    cleanupStickerFavorites(ALICE_ID);
    seedStickerCollection();
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await page.close();
  });

  test("707.1 list collections includes seeded collection", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiGet(page, "/ui/stickers/collections");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const ids = (body.collections as Array<{ collection_id: string }>).map((c) => c.collection_id);
    expect(ids).toContain(TEST_COLLECTION_ID);
    await page.close();
  });

  test("707.2 get stickers in collection", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiGet(page, `/ui/stickers/collections/${TEST_COLLECTION_ID}/stickers`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const sticker = (body.stickers as Array<{ sticker_id: string; image_url: string; alt_text: string }>)
      .find((s) => s.sticker_id === TEST_STICKER_ID);
    expect(sticker).toBeTruthy();
    expect(sticker!.image_url).toBeTruthy();
    expect(sticker!.alt_text).toBe("Cat waving hello");
    await page.close();
  });

  test("707.3 add collection to favorites", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiPost(page, `/ui/stickers/favorites/${TEST_COLLECTION_ID}`, {});
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    await page.close();
  });

  test("707.4 favorites list includes added collection", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await apiPost(page, `/ui/stickers/favorites/${TEST_COLLECTION_ID}`, {});
    const resp = await apiGet(page, "/ui/stickers/favorites");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const ids = (body.collections as Array<{ collection_id: string }>).map((c) => c.collection_id);
    expect(ids).toContain(TEST_COLLECTION_ID);
    await page.close();
  });

  test("707.5 add favorite is idempotent", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const r1 = await apiPost(page, `/ui/stickers/favorites/${TEST_COLLECTION_ID}`, {});
    const r2 = await apiPost(page, `/ui/stickers/favorites/${TEST_COLLECTION_ID}`, {});
    expect(r1.status()).toBe(200);
    expect(r2.status()).toBe(200);
    await page.close();
  });

  test("707.6 remove from favorites", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await apiPost(page, `/ui/stickers/favorites/${TEST_COLLECTION_ID}`, {});
    const del = await apiDelete(page, `/ui/stickers/favorites/${TEST_COLLECTION_ID}`);
    expect(del.status()).toBe(200);
    const resp = await apiGet(page, "/ui/stickers/favorites");
    const body = await resp.json();
    const ids = (body.collections as Array<{ collection_id: string }>).map((c) => c.collection_id);
    expect(ids).not.toContain(TEST_COLLECTION_ID);
    await page.close();
  });

  test("707.7 sticker search by alt text (favorited)", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await apiPost(page, `/ui/stickers/favorites/${TEST_COLLECTION_ID}`, {});
    const resp = await apiGet(page, "/ui/stickers/search?q=waving");
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const match = (body.results as Array<{ sticker_id: string }>)
      .find((r) => r.sticker_id === TEST_STICKER_ID);
    expect(match).toBeTruthy();
    await page.close();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 708: GIF Message Send/Receive API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 708: GIF Message Send/Receive API", () => {
  let convoId: string;
  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await getOrCreateDm(page);
    await page.close();
  });

  test("708.1 Alice sends a GIF message", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiPost(page, `/messaging/conversations/${convoId}/messages/gif`, {
      gif_url: `/mock/gifs/placeholder_7.gif?t=${TS}-708-1`,
      gif_alt_text: "Happy dance",
      gif_width: 320,
      gif_height: 240,
    });
    expect(resp.status()).toBe(201);
    const msg = (await resp.json()) as RawMsg;
    expect(msg.kind).toBe("gif");
    expect(msg.gif_url).toContain("placeholder_7.gif");
    expect(msg.gif_width).toBe(320);
    await page.close();
  });

  test("708.2 GIF message appears in conversation messages", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const alt = `gif-alt-${TS}-708-2`;
    await apiPost(page, `/messaging/conversations/${convoId}/messages/gif`, {
      gif_url: "/mock/gifs/placeholder_3.gif",
      gif_alt_text: alt,
    });
    const resp = await apiGet(page, `/messaging/conversations/${convoId}/messages`);
    const data = (await resp.json()) as RawMsg[];
    const found = data.find((m) => m.gif_alt_text === alt);
    expect(found).toBeTruthy();
    expect(found!.kind).toBe("gif");
    await page.close();
  });

  test("708.3 Bob receives GIF message with fields", async ({ browser, request }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const alt = `gif-bob-${TS}-708-3`;
    await apiPost(page, `/messaging/conversations/${convoId}/messages/gif`, {
      gif_url: "/mock/gifs/placeholder_5.gif",
      gif_alt_text: alt,
      gif_width: 400,
      gif_height: 300,
    });
    const resp = await apiGetBearer(request, `/messaging/conversations/${convoId}/messages`, BOB_ID);
    const data = (await resp.json()) as RawMsg[];
    const found = data.find((m) => m.gif_alt_text === alt);
    expect(found).toBeTruthy();
    expect(found!.gif_url).toContain("placeholder_5.gif");
    expect(found!.gif_height).toBe(300);
    await page.close();
  });

  test("708.4 GIF message supports reply_to", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const first = await apiPost(page, `/messaging/conversations/${convoId}/messages/gif`, {
      gif_url: "/mock/gifs/placeholder_1.gif",
      gif_alt_text: `parent-${TS}-708-4`,
    });
    const parent = (await first.json()) as RawMsg;
    const reply = await apiPost(page, `/messaging/conversations/${convoId}/messages/gif`, {
      gif_url: "/mock/gifs/placeholder_2.gif",
      gif_alt_text: `reply-${TS}-708-4`,
      reply_to_message_id: parent.message_id,
    });
    expect(reply.status()).toBe(201);
    const msg = (await reply.json()) as RawMsg;
    expect(msg.reply_to_message_id).toBe(parent.message_id);
    await page.close();
  });

  test("708.5 GIF with only url uses defaults", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiPost(page, `/messaging/conversations/${convoId}/messages/gif`, {
      gif_url: `/mock/gifs/placeholder_9.gif?t=${TS}-708-5`,
    });
    expect(resp.status()).toBe(201);
    const msg = (await resp.json()) as RawMsg;
    expect(msg.gif_width).toBe(0);
    expect(msg.gif_height).toBe(0);
    expect(msg.gif_alt_text).toBe("");
    await page.close();
  });

  test("708.6 GIF send requires auth (401)", async ({ request }) => {
    const resp = await request.post(`${API}/messaging/conversations/${convoId}/messages/gif`, {
      data: { gif_url: "/mock/gifs/placeholder_1.gif" },
    });
    expect(resp.status()).toBe(401);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 709: Sticker Message Send/Receive API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 709: Sticker Message Send/Receive API", () => {
  let convoId: string;
  test.beforeAll(async ({ browser }) => {
    seedStickerCollection();
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await getOrCreateDm(page);
    await page.close();
  });

  test("709.1 Alice sends a sticker message", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiPost(page, `/messaging/conversations/${convoId}/messages/sticker`, {
      sticker_id: TEST_STICKER_ID,
      sticker_collection_id: TEST_COLLECTION_ID,
    });
    expect(resp.status()).toBe(201);
    const msg = (await resp.json()) as RawMsg;
    expect(msg.kind).toBe("sticker");
    expect(msg.sticker_id).toBe(TEST_STICKER_ID);
    await page.close();
  });

  test("709.2 sticker message resolves collection + url", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiPost(page, `/messaging/conversations/${convoId}/messages/sticker`, {
      sticker_id: TEST_STICKER_ID,
      sticker_collection_id: TEST_COLLECTION_ID,
    });
    const msg = (await resp.json()) as RawMsg;
    expect(msg.sticker_collection_id).toBe(TEST_COLLECTION_ID);
    expect(msg.sticker_url).toContain(TEST_STICKER_ID);
    expect(msg.sticker_alt_text).toBe("Cat waving hello");
    await page.close();
  });

  test("709.3 Bob receives sticker message", async ({ browser, request }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await apiPost(page, `/messaging/conversations/${convoId}/messages/sticker`, {
      sticker_id: TEST_STICKER_ID,
      sticker_collection_id: TEST_COLLECTION_ID,
    });
    const resp = await apiGetBearer(request, `/messaging/conversations/${convoId}/messages`, BOB_ID);
    const data = (await resp.json()) as RawMsg[];
    const found = data.find((m) => m.kind === "sticker" && m.sticker_id === TEST_STICKER_ID);
    expect(found).toBeTruthy();
    expect(found!.sticker_url).toBeTruthy();
    await page.close();
  });

  test("709.4 invalid sticker_id returns 404", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiPost(page, `/messaging/conversations/${convoId}/messages/sticker`, {
      sticker_id: "stk_does_not_exist",
      sticker_collection_id: TEST_COLLECTION_ID,
    });
    expect(resp.status()).toBe(404);
    await page.close();
  });

  test("709.5 invalid collection_id returns 404", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const resp = await apiPost(page, `/messaging/conversations/${convoId}/messages/sticker`, {
      sticker_id: TEST_STICKER_ID,
      sticker_collection_id: "sc_does_not_exist",
    });
    expect(resp.status()).toBe(404);
    await page.close();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 710: Admin Sticker Management API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 710: Admin Sticker Management API", () => {
  // 1x1 transparent PNG.
  const PNG_B64 =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";

  test("710.1 admin creates sticker collection", async ({ request }) => {
    const root = getAdminSessions()["root"];
    const resp = await request.post(`${API}/v1/admin/stickers/collections`, {
      headers: {
        Cookie: root.cookies.map((c) => `${c.name}=${c.value}`).join("; "),
        "x-csrf-token": root.csrf_token,
      },
      multipart: {
        name: `Admin Pack ${TS}`,
        description: "Created by admin in E2E",
        alt_texts: "Smiley face",
        files: {
          name: "smile.png",
          mimeType: "image/png",
          buffer: Buffer.from(PNG_B64, "base64"),
        },
      },
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.collection_id).toBeTruthy();
    expect(body.sticker_count).toBe(1);
    expect(body.stickers[0].alt_text).toBe("Smiley face");
  });

  test("710.2 non-admin cannot create collection (403)", async ({ request }) => {
    const resp = await request.post(`${API}/v1/admin/stickers/collections`, {
      headers: { Authorization: `Bearer ${getSessions()[ALICE_ID].user_sub}` },
      multipart: {
        name: `Forbidden ${TS}`,
        files: {
          name: "smile.png",
          mimeType: "image/png",
          buffer: Buffer.from(PNG_B64, "base64"),
        },
      },
    });
    expect([401, 403]).toContain(resp.status());
  });

  test("710.3 admin soft-deletes collection", async ({ request }) => {
    const root = getAdminSessions()["root"];
    const cookieHeader = root.cookies.map((c) => `${c.name}=${c.value}`).join("; ");
    const create = await request.post(`${API}/v1/admin/stickers/collections`, {
      headers: { Cookie: cookieHeader, "x-csrf-token": root.csrf_token },
      multipart: {
        name: `Deletable ${TS}`,
        alt_texts: "x",
        files: {
          name: "smile.png",
          mimeType: "image/png",
          buffer: Buffer.from(PNG_B64, "base64"),
        },
      },
    });
    const created = await create.json();
    const cid = created.collection_id as string;
    const del = await request.delete(`${API}/v1/admin/stickers/collections/${cid}`, {
      headers: { Cookie: cookieHeader, "x-csrf-token": root.csrf_token },
    });
    expect(del.status()).toBe(200);

    // No longer in active list (Alice's view).
    const alice = getSessions()[ALICE_ID];
    const aliceCookie = alice.cookies.map((c) => `${c.name}=${c.value}`).join("; ");
    const listResp = await request.get(`${API}/ui/stickers/collections`, {
      headers: { Cookie: aliceCookie, "x-csrf-token": alice.csrf_token },
    });
    const body = await listResp.json();
    const ids = (body.collections as Array<{ collection_id: string }>).map((c) => c.collection_id);
    expect(ids).not.toContain(cid);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 711: GIF & Sticker UI
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("Section 711: GIF & Sticker UI", () => {
  let convoId: string;
  test.beforeAll(async ({ browser }) => {
    cleanupStickerFavorites(ALICE_ID);
    seedStickerCollection();
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    convoId = await getOrCreateDm(page);
    await apiPost(page, `/ui/stickers/favorites/${TEST_COLLECTION_ID}`, {});
    await page.close();
  });

  test("711.1 GIF picker opens from ComposeBar", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages/${convoId}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: "Send a GIF" }).click();
    await expect(page.locator('[data-testid="gif-picker"]')).toBeVisible();
    await expect(page.locator('[data-testid="gif-search-input"]')).toBeVisible();
    await page.close();
  });

  test("711.2 searching GIFs shows results in picker", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages/${convoId}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: "Send a GIF" }).click();
    await page.locator('[data-testid="gif-search-input"]').fill("happy");
    await expect(page.locator('[data-testid="gif-result"]').first()).toBeVisible({ timeout: 10_000 });
    await page.close();
  });

  test("711.3 sticker picker opens from ComposeBar", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/messages/${convoId}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: "Send a sticker" }).click();
    await expect(page.locator('[data-testid="sticker-picker"]')).toBeVisible();
    await page.close();
  });

  test("711.4 GIF message renders as image in bubble", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    const alt = `ui-gif-${TS}-711-4`;
    await apiPost(page, `/messaging/conversations/${convoId}/messages/gif`, {
      gif_url: "/mock/gifs/placeholder_4.gif",
      gif_alt_text: alt,
      gif_width: 320,
      gif_height: 240,
    });
    await page.goto(`${BASE}/messages/${convoId}`, { waitUntil: "domcontentloaded" });
    await page.evaluate(() => window.dispatchEvent(new Event("online")));
    await expect(page.locator(`img[alt="${alt}"]`)).toBeVisible({ timeout: 10_000 });
    await page.close();
  });
});
