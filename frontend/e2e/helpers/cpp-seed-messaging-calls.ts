/**
 * cpp-aware auth glue for the messaging-calls domain (TRACK: seed / auth-harness).
 *
 * OWNS ONLY this domain's cpp helpers so it never conflicts with the shared
 * helpers/cpp-seed.ts. Re-uses runCppShim / usingCpp from that module (so any
 * DDB shim inherits the per-worker ssh ControlMaster scaling).
 *
 * ── THE BUG THIS FIXES (root cause of the whole domain's red) ────────────────
 * Under E2E_USE_CPP every Playwright project inherits `storageState: admin`
 * (playwright.config.ts). So the built-in `request` fixture AND every `page`
 * before injectAuth() silently carry admin's VALID ui_access_token JWT cookie.
 *
 * The specs authenticate "as Bob/Charlie/Alice" for API calls with a DEV-mode
 * bearer whose token IS the raw user_sub (Authorization: Bearer <sub>). But
 * cpp's CurrentUser resolves auth in this order (app/main.cpp):
 *     1. Bearer token, IF it JWT-verifies  (a raw sub does NOT verify)
 *     2. else ui_access_token COOKIE, if it JWT-verifies  ← admin's cookie wins
 *     3. else (dev) the raw Bearer token is taken as the user_sub
 * A raw-sub bearer never JWT-verifies, so when the admin cookie is present cpp
 * authenticates the call as ADMIN — never as Bob. Result: Bob's accept →
 * 404 "Not invited"; Bob's send → 403 "Not a participant"; and even Alice's own
 * page.request calls run as admin, so messages land under the wrong sender and
 * the read-backs mismatch. That is the entire cascade across group-calls,
 * messaging, messaging-features, calendar/gif/countdown message sends.
 *
 * FIX: route DEV-bearer requests through a COOKIE-FREE APIRequestContext so no
 * ui_access_token cookie shadows the bearer — then cpp's step 3 (raw-sub) fires
 * and the caller is genuinely Bob/Charlie/Alice. VERIFIED live: with a clean
 * context Bob's accept + send both return 200 (were 404/403).
 *
 * The default Python path is untouched: callers gate on usingCpp() and keep
 * their original page.request / request-fixture path when false.
 */
import { request as pwRequest, type APIRequestContext } from "@playwright/test";
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp, runCppShim };

const API =
  process.env.E2E_API_BASE ?? "http://localhost:3000";

// One cookie-free context per worker process, lazily created + cached. Playwright
// tears the process down between workers, so a module-level cache is worker-local.
let _cleanCtx: APIRequestContext | null = null;
let _cleanCtxPromise: Promise<APIRequestContext> | null = null;

/**
 * A genuinely cookie-free APIRequestContext (no storageState → no admin cookie).
 * Bearer <raw-sub> requests made through this context hit cpp's dev raw-sub auth
 * path and are authenticated as the intended user, not admin.
 *
 * The context is cached for the life of the worker; do NOT dispose it per test.
 */
export async function cppCleanCtx(): Promise<APIRequestContext> {
  if (_cleanCtx) return _cleanCtx;
  if (!_cleanCtxPromise) {
    _cleanCtxPromise = pwRequest
      .newContext({
        baseURL: API,
        ignoreHTTPSErrors: true,
        // Explicit empty jar: guarantees no project-level admin cookie leaks in.
        storageState: { cookies: [], origins: [] },
      })
      .then((c) => {
        _cleanCtx = c;
        return c;
      });
  }
  return _cleanCtxPromise;
}

/** POST as <userSub> via a clean (cookie-free) context so the raw-sub bearer wins. */
export async function cppBearerPost(
  path: string,
  body: object,
  userSub: string,
  extraHeaders: Record<string, string> = {},
) {
  const ctx = await cppCleanCtx();
  return ctx.post(`${API}${path}`, {
    data: body,
    headers: { Authorization: `Bearer ${userSub}`, ...extraHeaders },
  });
}

/** GET as <userSub> via a clean (cookie-free) context so the raw-sub bearer wins. */
export async function cppBearerGet(
  path: string,
  userSub: string,
  extraHeaders: Record<string, string> = {},
) {
  const ctx = await cppCleanCtx();
  return ctx.get(`${API}${path}`, {
    headers: { Authorization: `Bearer ${userSub}`, ...extraHeaders },
  });
}

/** PATCH as <userSub> via a clean (cookie-free) context so the raw-sub bearer wins. */
export async function cppBearerPatch(
  path: string,
  body: object,
  userSub: string,
  extraHeaders: Record<string, string> = {},
) {
  const ctx = await cppCleanCtx();
  return ctx.patch(`${API}${path}`, {
    data: body,
    headers: { Authorization: `Bearer ${userSub}`, ...extraHeaders },
  });
}

/** DELETE as <userSub> via a clean (cookie-free) context so the raw-sub bearer wins. */
export async function cppBearerDelete(
  path: string,
  userSub: string,
  extraHeaders: Record<string, string> = {},
) {
  const ctx = await cppCleanCtx();
  return ctx.delete(`${API}${path}`, {
    headers: { Authorization: `Bearer ${userSub}`, ...extraHeaders },
  });
}

// ── sticker-collection seed (gif-sticker-messages) ───────────────────────────
export interface CppStickerEntry {
  sticker_id: string;
  image_url?: string;
  alt_text?: string;
  sort_order?: number;
  width?: number;
  height?: number;
}
export interface CppStickerCollectionOpts {
  collectionId: string;
  name?: string;
  description?: string;
  thumbnailUrl?: string;
  createdBy?: string;
  createdAtSec?: number;
  isActive?: string;
  stickers: CppStickerEntry[];
}

/**
 * Seed one sticker collection (META + N STICKER rows) into cpp's
 * tlc_sticker_collections (PK collection_id, SK META|STICKER#<id>). Mirrors
 * gif-sticker-messages.spec.ts seedStickerCollection() for the cpp store.
 *
 * Verified live: after this seed, GET /ui/stickers/collections (Alice UI
 * session) lists the collection and .../collections/{id}/stickers returns the
 * seeded sticker. NUMERIC fields land as numbers; is_active stays a string "1".
 */
export function cppSeedStickerCollection(opts: CppStickerCollectionOpts): void {
  runCppShim("seed_messaging-calls_sticker_collection.py", {
    collection_id: opts.collectionId,
    name: opts.name ?? "E2E Collection",
    description: opts.description ?? "E2E test collection",
    thumbnail_url: opts.thumbnailUrl ?? "",
    created_by: opts.createdBy ?? "root",
    ...(opts.createdAtSec != null ? { created_at: opts.createdAtSec } : {}),
    is_active: opts.isActive ?? "1",
    stickers: opts.stickers.map((s) => ({
      sticker_id: s.sticker_id,
      image_url: s.image_url ?? "",
      alt_text: s.alt_text ?? "",
      ...(s.sort_order != null ? { sort_order: s.sort_order } : {}),
      ...(s.width != null ? { width: s.width } : {}),
      ...(s.height != null ? { height: s.height } : {}),
    })),
  });
}

// ── webrtc.spec.ts: call-session + conversation cpp seeds ────────────────────

export interface CppCallSessionOpts {
  callId: string;
  conversationId: string;
  callerUserId: string; // cpp SUB
  calleeUserId: string; // cpp SUB
  state: string;
  initialMode?: string;
}

/**
 * Seed one call-session row into cpp's tlc_message_call_sessions (PK call_id;
 * GSI1 conversation_id/start_ts_sort). Mirrors webrtc.spec.ts seedCallSession(),
 * whose Python :8001 "MessageCallSessions" put never reaches cpp. NUMERICS land
 * as numbers, lifecycle_events as a list, idempotency_records as a map — the
 * exact shape cs_put's json_to_ddb produces, so cs_get/rec_require_call_participant
 * read it back. caller/callee/conversation ids MUST be cpp subs.
 */
export function cppSeedCallSession(opts: CppCallSessionOpts): void {
  runCppShim("seed_messaging-calls_call_session.py", {
    call_id: opts.callId,
    conversation_id: opts.conversationId,
    caller_user_id: opts.callerUserId,
    callee_user_id: opts.calleeUserId,
    state: opts.state,
    ...(opts.initialMode ? { initial_mode: opts.initialMode } : {}),
  });
}

/** Delete a call-session row from cpp's tlc_message_call_sessions. Best-effort. */
export function cppDeleteCallSession(callId: string): void {
  try {
    runCppShim("delete_call_session.py", { call_id: callId });
  } catch {
    /* ignore cleanup errors */
  }
}

/**
 * Seed a conversation + one active participant row per sub into cpp's
 * tlc_conversations + tlc_participants (GSI1PK=conversation_id). Mirrors
 * webrtc.spec.ts seedConversation(). cpp's call lifecycle resolves the
 * participant set from tlc_participants (get_participant / GSI1), requiring
 * status=="active". participantSubs MUST be cpp subs (map emails via
 * resolveIdentityId in the spec before calling).
 */
export function cppSeedConversation(conversationId: string, participantSubs: string[]): void {
  runCppShim("seed_messaging-calls_conversation.py", {
    conversation_id: conversationId,
    participant_subs: participantSubs,
    type: "dm",
  });
}

/** Delete a conversation + its participant rows from cpp. Best-effort. */
export function cppDeleteConversation(conversationId: string, participantSubs?: string[]): void {
  try {
    runCppShim("delete_conversation.py", {
      conversation_id: conversationId,
      ...(participantSubs ? { participant_subs: participantSubs } : {}),
    });
  } catch {
    /* ignore cleanup errors */
  }
}
