---
id: AND-382
title: Block / unblock
milestone: M8
epic: E50
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: []
---

# AND-382 — Block / unblock

## 1. Overview & Goal

Implement user-level **block / unblock** for the TestLogon native Android app. Blocking is a moderation/safety primitive that lets a signed-in user sever contact with another user: a blocked user's content (profile body, posts, messages) is hidden from the blocker, and the blocked user is prevented from initiating new contact (DMs, follows, comments) with the blocker. The web reference implements this in `frontend/src/api/endpoints/blocking.ts`; this ticket ports the equivalent capability to the Android stack and surfaces it inline in the **profile** and **messages** features.

Goal: ship a reusable `BlockingRepository` + `BlockApi` in `core-data`/`core-network`, a `BlockUiState`-driven interaction (overflow-menu action + confirmation) embedded in the profile screen and conversation/thread screen, and client-side content suppression so that blocked users immediately disappear from the blocker's surfaces without requiring a full app restart. The acceptance bar is: **block hides content + prevents contact, verified by tests.**

This is a self-contained feature spanning two existing features; it introduces no new screens of its own. Note: the web reference DOES ship a dedicated "Blocked Users" management screen at `frontend/src/pages/settings/BlockedUsersPage.tsx` (uses `getBlockedUsers` + `unblockUser`), but porting that standalone screen is explicitly OUT of scope for this Android ticket — see §13. Verified against `src/pages/settings/BlockedUsersPage.tsx`.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Namespace:** all packages rooted at `com.testlogon.android`.
- **Web reference:** `frontend/src/api/endpoints/blocking.ts` (authoritative request/response shapes); shared types in `frontend/src/api/types.ts`. Block/unblock UI is embedded in the web profile and messages views.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json` — confirm exact block paths against it before implementation if `blocking.ts` and OpenAPI disagree.
- **Auth:** cookie-based session (AND-027 `AuthApi`); all block calls are authenticated, ride the persistent cookie jar, and must send the `X-CSRF-Token` header (echoed from the `ui_csrf` cookie) on mutating verbs. **Verified** against `src/api/client.ts`: the web client reads the `ui_csrf` cookie via `getCookie("ui_csrf")` and sets `X-CSRF-Token` on every request, sends `credentials: "include"` (cookie jar), and additionally attaches an `Authorization: Bearer <accessToken>` header from the auth store. The OpenAPI index further lists `user_sub`, `X-SESSION-ID`, and `X-IMPERSONATION-TOKEN` as accepted params on the social endpoints; the Android port reuses whatever AND-027's client already sends and need not add impersonation headers (admin-only concern, out of scope).
- **Dependency:** **AND-027** (`AuthApi` session endpoints) — provides the authenticated, CSRF-aware OkHttp client + cookie jar this ticket reuses. No new auth work here.
- **Module layering:** `app -> feature-profile / feature-messages -> core-data -> core-network -> core-model`. ViewModels expose `StateFlow<UiState>`; network results are wrapped in typed `ApiResult<T>`.

## 3. Functional Requirements

FR-1. From a **profile** screen for any user other than self, the signed-in user can open an overflow (`⋮`) menu and select **Block @{handle}**. Selecting it shows a confirmation dialog summarizing the effects; confirming issues the block.

FR-2. From a **conversation / message thread** with another user, the same Block action is available via the thread overflow menu, with identical confirmation + effect.

FR-3. After a successful block:
- the blocked user's profile content is replaced with a "You blocked this user" empty/affordance state offering **Unblock**;
- the conversation with the blocked user is hidden from the conversation list and the thread is locked (composer disabled, "You blocked this user" banner);
- any cached feed/list items authored by the blocked user are suppressed in the blocker's current session.

FR-4. A blocked user **cannot initiate new contact**: server enforces this; client must (a) disable/hide the message composer toward a blocked-by-me or has-blocked-me user, and (b) gracefully handle the server rejecting contact attempts (see §7).

FR-5. The blocker can **Unblock** from the profile affordance. After unblock, content suppression is lifted on next refresh; contact is re-enabled.

FR-6. Block/unblock are **idempotent** from the user's perspective: re-blocking an already-blocked user or unblocking an already-unblocked user must not surface an error to the user.

FR-7. The current block relationship state for a viewed user must be derivable so screens render the correct affordance. **Corrected** against the sources: the authoritative relationship flags are `is_blocked_by_me` and `is_blocking_me` (not `is_blocked` / `blocked_by`). They are exposed two ways: (a) a dedicated `GET /ui/social/block-status/{target_user_id}` → `BlockStatusResponse { is_blocked_by_me, is_blocking_me }`, and (b) the follow-status payload `FollowStatus` returned by `GET /ui/social/follow-status/{userId}` which also carries optional `is_blocked_by_me` / `is_blocking_me`. Membership in `GET /ui/social/blocked` only captures the blocked-by-me direction. Verified against `src/api/endpoints/blocking.ts: getBlockStatus`, `src/api/endpoints/social.ts: getFollowStatus`, and schemas `BlockStatusResponse` / `FollowStatus`.

## 4. Technical Design

### 4.1 Module placement

- `core-network`: `BlockApi` Retrofit interface + DTOs.
- `core-model`: domain models `BlockRelationship`, `BlockedUser`.
- `core-data`: `BlockingRepository` (+ impl), Hilt module binding, in-memory/`StateFlow` block-set cache.
- `feature-profile`, `feature-messages`: ViewModel actions + Compose UI wiring (overflow menu, confirm dialog, suppressed states).

### 4.2 API layer (`core-network`)

> **CORRECTED (review AND-382):** the original draft assumed `POST /ui/blocks`, `DELETE /ui/blocks/{userId}`, `GET /ui/blocks` with `blocked_user_id` / `created_at` / `handle` / `items` fields. None of those are real. The verified contract (OpenAPI index + `src/api/endpoints/blocking.ts`) is: block and **unblock are both `POST` under `/ui/social/...`** (unblock is NOT a `DELETE`), the request field is `target_user_id` (block also accepts an optional `reason`), and both return `200 BlockActionResponse`. The interface and DTOs below reflect the real shapes.

```kotlin
package com.testlogon.android.core.network.api

interface BlockApi {
    // POST /ui/social/block — req=BlockRequest, resp=200:BlockActionResponse
    @POST("ui/social/block")
    suspend fun block(@Body body: BlockRequestDto): Response<BlockActionDto>

    // POST /ui/social/unblock — req=UnblockRequest, resp=200:BlockActionResponse
    @POST("ui/social/unblock")
    suspend fun unblock(@Body body: UnblockRequestDto): Response<BlockActionDto>

    // GET /ui/social/blocked — resp=200:BlockedUsersListResponse, params=limit,cursor
    @GET("ui/social/blocked")
    suspend fun listBlocks(
        @Query("limit") limit: Int = 50,
        @Query("cursor") cursor: String? = null,
    ): Response<BlockedUsersListDto>

    // GET /ui/social/block-status/{target_user_id} — resp=200:BlockStatusResponse
    @GET("ui/social/block-status/{targetUserId}")
    suspend fun blockStatus(@Path("targetUserId") targetUserId: String): Response<BlockStatusDto>
}

@JsonClass(generateAdapter = true)
data class BlockRequestDto(
    @Json(name = "target_user_id") val targetUserId: String,
    @Json(name = "reason") val reason: String? = null, // optional, server maxLength 500
)

@JsonClass(generateAdapter = true)
data class UnblockRequestDto(@Json(name = "target_user_id") val targetUserId: String)

// BlockActionResponse { ok: bool (default true), status: string, target_user_id: string }
// status is "blocked" | "unblocked" per src/api/types.ts: BlockActionResponse
@JsonClass(generateAdapter = true)
data class BlockActionDto(
    val ok: Boolean = true,
    val status: String,
    @Json(name = "target_user_id") val targetUserId: String,
)

// BlockStatusResponse { is_blocked_by_me: bool, is_blocking_me: bool }
@JsonClass(generateAdapter = true)
data class BlockStatusDto(
    @Json(name = "is_blocked_by_me") val isBlockedByMe: Boolean,
    @Json(name = "is_blocking_me") val isBlockingMe: Boolean,
)

// BlockedUsersListResponse { blocked_users: BlockedUserItem[], next_cursor?: string, total_count: int }
@JsonClass(generateAdapter = true)
data class BlockedUsersListDto(
    @Json(name = "blocked_users") val blockedUsers: List<BlockedUserDto>,
    @Json(name = "next_cursor") val nextCursor: String?,
    @Json(name = "total_count") val totalCount: Int,
)

// BlockedUserItem { user_id, display_name?, profile_photo_url?, blocked_at }  (NO `handle`, NO `created_at`)
@JsonClass(generateAdapter = true)
data class BlockedUserDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "display_name") val displayName: String?,
    @Json(name = "profile_photo_url") val profilePhotoUrl: String?,
    @Json(name = "blocked_at") val blockedAt: String,
)
```

> Note: contract verified during this review against the OpenAPI index (`POST /ui/social/block`, `POST /ui/social/unblock`, `GET /ui/social/blocked`, `GET /ui/social/block-status/{target_user_id}`) and `src/api/endpoints/blocking.ts`. There is no path-param create variant; both mutations are JSON-body POSTs.

`BlockApi` is provided via the **same authenticated Retrofit** built in AND-027 (cookie jar + `X-CSRF-Token` interceptor). It is bound in a Hilt `@Module` in `core-network`:

```kotlin
@Provides @Singleton
fun provideBlockApi(retrofit: Retrofit): BlockApi = retrofit.create(BlockApi::class.java)
```

### 4.3 Repository (`core-data`)

```kotlin
interface BlockingRepository {
    /** Reactive set of user ids the current user has blocked (best-effort cache). */
    val blockedUserIds: StateFlow<Set<String>>

    suspend fun block(userId: String): ApiResult<Unit>
    suspend fun unblock(userId: String): ApiResult<Unit>
    suspend fun refreshBlockList(): ApiResult<List<BlockedUser>>

    /** True if userId is in the local blocked set. */
    fun isBlocked(userId: String): Boolean
}
```

`BlockingRepositoryImpl` maintains a `MutableStateFlow<Set<String>>` seeded by `refreshBlockList()` and updated optimistically on `block`/`unblock` (with rollback on failure). It exposes `blockedUserIds` so feature ViewModels can `combine` it with their content flows to suppress items client-side without re-fetching.

### 4.4 Feature wiring

- **Profile:** `ProfileViewModel` injects `BlockingRepository`. `onBlockConfirmed()` / `onUnblock()` call the repo; `uiState` exposes a `BlockRelationship` derived from profile flags `combine`d with `blockedUserIds`. When blocked-by-me, the profile body composable renders `BlockedProfilePlaceholder(onUnblock = ...)`.
- **Messages:** `ConversationViewModel` filters the conversation list with `combine(conversations, blockedUserIds)`; `ThreadViewModel` disables the composer and shows a banner when the counterpart is in either block direction. Block action invoked from the thread top-bar overflow.

### 4.5 UI

```kotlin
@Composable
fun BlockUserMenuItem(handle: String, onClick: () -> Unit)

@Composable
fun BlockConfirmDialog(
    handle: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
)

@Composable
fun BlockedProfilePlaceholder(handle: String, onUnblock: () -> Unit)
```

Shared composables live in `core-ui` so profile and messages reuse identical affordances.

## 5. API Contract

All calls are authenticated (session cookies + `Authorization: Bearer`) and send `X-CSRF-Token` on mutating verbs. Base URL is the dev host; timeouts ~20s. **All four shapes below were verified against the OpenAPI spec and `src/api/endpoints/blocking.ts` during this review.**

**Block** — `POST /ui/social/block` (verified; was wrongly `POST /ui/blocks`)
Request (`BlockRequest`):
```json
{ "target_user_id": "usr_abc123", "reason": "optional, <=500 chars" }
```
Response `200` (`BlockActionResponse`):
```json
{ "ok": true, "status": "blocked", "target_user_id": "usr_abc123" }
```

**Unblock** — `POST /ui/social/unblock` (verified; was wrongly `DELETE /ui/blocks/{userId}`)
Request (`UnblockRequest`):
```json
{ "target_user_id": "usr_abc123" }
```
Response `200` (`BlockActionResponse`):
```json
{ "ok": true, "status": "unblocked", "target_user_id": "usr_abc123" }
```

**List blocks** — `GET /ui/social/blocked?limit=50&cursor=` (verified; was wrongly `GET /ui/blocks`)
Response `200` (`BlockedUsersListResponse`):
```json
{
  "blocked_users": [
    { "user_id": "usr_abc123", "display_name": "Alice", "profile_photo_url": null, "blocked_at": "2026-06-05T12:00:00Z" }
  ],
  "next_cursor": null,
  "total_count": 1
}
```
Note the array key is `blocked_users` (not `items`), the timestamp is `blocked_at` (not `created_at`), there is a required `total_count`, and there is **no `handle` field** — items expose `user_id` / `display_name?` / `profile_photo_url?` / `blocked_at` (`BlockedUserItem`).

**Block status** — `GET /ui/social/block-status/{target_user_id}` (verified; this endpoint exists and is the primary relationship read)
Response `200` (`BlockStatusResponse`):
```json
{ "is_blocked_by_me": true, "is_blocking_me": false }
```

**Idempotency (verified by analogy to follow):** the block/unblock endpoints return a `status` string in `BlockActionResponse`. The sibling follow endpoints model idempotency with statuses `already_following` / `not_following` (see `src/api/endpoints/social.ts: FollowResponse`/`UnfollowResponse`). The exact idempotent `status` literals for re-block / re-unblock are **NOT enumerated in the sources** — treat any `200` as success regardless of `status` value (FR-6) and do not branch on it. The previously-assumed `409 already_blocked` / `404 not_blocked` status codes are **unverified** (see §16).

**Contact rejection (server-enforced):** the original draft's `403 { "detail": { "code": "user_blocked", ... } }` shape is an **unverified assumption** — no `user_blocked` code, nor any block-enforcement `403` on the messaging endpoints, appears in the OpenAPI spec or frontend source. The client error mapper MUST still handle a generic FastAPI `403` defensively. The shared FastAPI `detail` mapping (`string | [{msg}] | {code,...}`) IS real and is implemented by `normalizeErrorDetail` in `src/api/client.ts`; reuse that parsing logic, but do not hard-code a `user_blocked` literal.

**Error/status mapping (corrected):**
- `200` → success (block, unblock, list, status all return `200` — there is no `201`/`204` here).
- Validation failures → `422 HTTPValidationError` (the only documented error response for these endpoints besides auth).
- `401` → trigger the AND-027 single `POST /ui/session/refresh` + retry-once path (verified: `src/api/client.ts: refreshSession` posts to `/ui/session/refresh`).
- `403` → generic permission-denied handling via the shared `detail` mapper; surface a contact-blocked UI state if a block-specific code is present, but treat the specific code as unverified.
- `5xx`/timeout → surface stale/retry state; **do not** auto-retry the mutating POSTs — only `GET /ui/social/blocked` and `GET /ui/social/block-status/{id}` are eligible for bounded backoff retry.

## 6. Data & State Management

- **Source of truth (server):** the block relationship lives in DynamoDB; the client never persists it as durable truth.
- **Local cache:** `BlockingRepositoryImpl` holds an in-memory `StateFlow<Set<String>>` of blocked ids for the session, hydrated by `refreshBlockList()` on app start / profile open. Optional Room table `blocked_users` (`core-data`) MAY cache the list for offline rendering; if added, it is keyed by `user_id` and cleared on logout. DataStore is not used (this is account data, not a preference).
- **Optimistic updates:** `block()`/`unblock()` mutate the in-memory set immediately, then reconcile with the server response; on failure the set is reverted and an error is emitted to the calling ViewModel.
- **State flows:**
  - `ProfileUiState.blockRelationship: BlockRelationship { Normal, BlockedByMe, BlockedMe }` derived from the verified `is_blocked_by_me` / `is_blocking_me` flags (`BlockedMe` == `is_blocking_me == true`). Both directions ARE observable client-side via `GET /ui/social/block-status/{id}` (or the follow-status flags), so the reverse direction does not depend on catching a contact `403`.
  - `ThreadUiState.contactBlocked: Boolean`, `ThreadUiState.composerEnabled: Boolean`.
- **Suppression:** list ViewModels `combine` their item flow with `blockedUserIds` and drop authored items — applied at the ViewModel layer so cached Room/Paging data is filtered without invalidating the cache.
- **Logout:** clears the in-memory set and any `blocked_users` rows.

## 7. Error Handling & Resilience

- All network results wrapped in `ApiResult<T>` (`Success`/`Error(type, detail)`).
- **Idempotency:** the backend models block/unblock with a `status` field in `BlockActionResponse` (mirroring follow's `already_following`/`not_following`), so re-block / re-unblock return `200`, not an error. Map any `200` to `Success` (FR-6) without branching on `status`. (The previously-assumed `409 already_blocked` / `404 not_blocked` codes are unverified — see §16 — so do not rely on specific 4xx codes for idempotency.)
- **Timeout / unreliable host:** 20s timeouts. On block/unblock timeout, revert the optimistic change and show a non-blocking snackbar "Couldn't update — tap to retry"; the user re-triggers the action (no automatic retry of the mutation).
- **`401`:** delegate to AND-027 auth interceptor (single `session/refresh` then retry once).
- **Contact attempt against a block:** the composer disables and shows the banner based on the verified `is_blocked_by_me` / `is_blocking_me` flags; if a send slips through (race) and the server returns a `403`, it is caught generically and the message marked failed. (The specific `user_blocked` detail code is unverified — see §16 — so handle any `403` rather than matching that literal.)
- **Offline:** block/unblock actions are disabled with a "No connection" hint; previously-fetched suppression state remains applied (fail-safe: still hide blocked content).
- **Stale relationship:** if a `403 user_blocked` is received while the client believed contact was allowed, the client updates local state to reflect the block and re-renders.

## 8. Security & Privacy

- All block endpoints require an authenticated session; CSRF token sent on `POST`/`DELETE`.
- Block status is **private to the blocker**: the UI never reveals to a blocked user that they were blocked beyond standard "can't contact" behavior; client must not log or display the blocker→blocked mapping for other users.
- No block data in plaintext logs; user ids in telemetry are hashed/opaque (see §10).
- Client-side suppression is **defense-in-depth, not the security boundary** — the server is authoritative for hiding content and rejecting contact. The client must not assume that absence of a `403` means contact is permitted.
- `blocked_users` Room cache (if used) lives in app-private storage and is wiped on logout; consider DB encryption inheritance from `core-data` policy.

## 9. Accessibility & i18n

- Overflow menu item, confirm dialog, unblock button, and banners have `contentDescription` / semantics; dialog is focus-trapped and announces its title via TalkBack.
- Touch targets ≥ 48dp; confirm/cancel actions clearly labeled (not icon-only).
- All strings externalized to `strings.xml` (`block_action`, `block_confirm_title`, `block_confirm_body`, `blocked_profile_placeholder`, `unblock_action`, `cannot_contact_banner`); handle interpolated via `getString(R.string.block_action, handle)`. No concatenation.
- Placeholder/banner colors meet WCAG AA contrast and do not rely on color alone (include text/icon).

## 10. Telemetry & Logging

- Emit analytics events (via the project's existing analytics abstraction): `block_user` and `unblock_user` with properties `{ source: "profile"|"thread", result: "success"|"error" }`. Do **not** include the raw blocked user id; use a hashed/opaque id if any identifier is needed.
- Emit `block_contact_rejected` when a `403 user_blocked` is handled, property `{ surface }`.
- Logging: debug-level only, no PII; never log the full block list. Network failures logged with status code + error type, not bodies containing user identifiers.

## 11. Testing Strategy

**Unit (`core-data` / `core-testing`, MockWebServer):**
- `BlockApi` paths/verbs/bodies match §5 contract (block `POST /ui/social/block`, unblock `POST /ui/social/unblock`, list `GET /ui/social/blocked`, status `GET /ui/social/block-status/{id}`), with `target_user_id` request bodies and `X-CSRF-Token` header presence on the POST mutations.
- `BlockingRepositoryImpl`: optimistic add/remove, rollback on failure, idempotent mapping of any `200` to success, `blockedUserIds` StateFlow emissions, refresh hydration from `blocked_users`.
- Error mapping: `401` → refresh path; generic `403` parsed via the FastAPI `detail` mapper; `422` validation surfaced as error.

**ViewModel (Turbine):**
- Profile: confirming block transitions `blockRelationship` to `BlockedByMe` and renders placeholder; unblock reverts.
- Messages: blocked counterpart removed from conversation list; thread composer disabled + banner shown.
- **Acceptance-critical:** a test proving **content is hidden** (suppressed list item / placeholder profile) and **contact is prevented** (composer disabled + `403` handled) after block — directly satisfying the ticket acceptance bullet.

**Compose UI tests:**
- Overflow → Block → confirm dialog → confirm flow; `BlockedProfilePlaceholder` shows Unblock; semantics/contentDescription assertions for accessibility.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (`AuthApi` session endpoints): provides the authenticated, CSRF-aware Retrofit/OkHttp client + persistent cookie jar that `BlockApi` reuses. Must merge first.
- Soft dependency on existing **feature-profile** and **feature-messages** scaffolding (M2 app shell, M3 messaging) for the host screens — block UI embeds into them; if a host screen is absent, the repository/API can land first and UI wiring follows.
- **Blocks:** nothing in the current backlog declares a hard dependency on AND-382. A future "blocked users management" screen (out of scope, §13) would depend on this ticket's `BlockingRepository` + `listBlocks`.

## 13. Risks & Open Questions

- **R1 — Exact contract drift: RESOLVED in review.** `blocking.ts` and the OpenAPI spec agree. Verified paths: `POST /ui/social/block`, `POST /ui/social/unblock` (both body POSTs with `target_user_id`), `GET /ui/social/blocked`, `GET /ui/social/block-status/{target_user_id}`. The original §5 draft (`/ui/blocks`, `DELETE`, `blocked_user_id`, `handle`, `items`) was wrong and has been corrected throughout. Residual risk is only future backend drift.
- **R2 — Relationship read source: RESOLVED in review.** The backend DOES expose a per-user relationship endpoint: `GET /ui/social/block-status/{target_user_id}` → `{ is_blocked_by_me, is_blocking_me }`, and the follow-status payload also carries those optional flags. Both block directions are therefore observable client-side; the `BlockedMe` direction does NOT depend on catching a contact `403`.
- **R3 — Cache coherence:** Paging 3 / Room caches may retain blocked-authored items; we suppress at the ViewModel layer, but pagination counts and "load more" boundaries may look off. Acceptable for v1.
- **R4 — Out of scope:** porting the dedicated "Blocked users" management/list screen (which DOES exist on web at `src/pages/settings/BlockedUsersPage.tsx`), report-and-block combined flow, and bulk operations are NOT in this ticket. The `listBlocks`/`BlockingRepository` primitives that a future Android version of that screen would need are in scope.
- **R5 — Idempotency status codes: PARTIALLY RESOLVED.** The endpoints return `200` with a `status` string (like follow's `already_following`/`not_following`), so idempotency is handled by treating any `200` as success — NOT by `409`/`404` codes (those were unverified assumptions, now removed). The exact idempotent `status` literals for re-block/re-unblock are not enumerated in the sources (open assumption, §16) but the client does not need them.

## 14. Acceptance Criteria

AC-1. From a non-self profile and from a message thread, a Block action is available, shows a confirmation dialog, and on confirm issues `POST /ui/social/block` with body `{ "target_user_id": ... }` + `X-CSRF-Token`. (UI + MockWebServer tested.)

AC-2. **Block hides content:** after blocking, the blocked user's profile renders the blocked placeholder, their conversation is removed from the conversation list, and their authored items are suppressed in the blocker's current session. (Verified by ViewModel/Compose tests.)

AC-3. **Block prevents contact:** the message composer toward a blocked counterpart is disabled with a banner (driven by `is_blocked_by_me` / `is_blocking_me`), and a generic `403` from a contact attempt is handled gracefully (no crash, message marked failed/blocked). (Tested.)

AC-4. Unblock issues `POST /ui/social/unblock` with body `{ "target_user_id": ... }`, lifts suppression on refresh, and re-enables contact. (Tested.)

AC-5. Block/unblock are idempotent in the UI: repeated block/unblock returns `200` and does not surface an error (any `200` mapped to success regardless of `status`). (Unit tested.)

AC-6. `401` during a block/unblock triggers the AND-027 refresh-and-retry path; mutating calls are not auto-retried on timeout. (Unit tested.)

## 15. Definition of Done

- `BlockApi` (`core-network`), `BlockingRepository`/impl (`core-data`), and domain models (`core-model`) implemented and Hilt-wired, reusing the AND-027 authenticated client.
- Block/unblock embedded in profile and messages with shared `core-ui` composables; content suppression + composer gating in place.
- All §11 tests written and green (unit, ViewModel/Turbine, Compose), including the acceptance-critical "hides content + prevents contact" tests.
- Strings externalized; accessibility semantics present; lint + detekt clean; module layering respected (no upward deps).
- Telemetry events emitted without PII; no block-relationship PII in logs.
- Contract reconciled against `blocking.ts` / `/openapi.json` (R1, done in this review — §5 now matches the verified `/ui/social/*` endpoints); any further backend drift documented in the PR.
- Code reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT (Verified / Corrected / Unverified-assumption) and an exact SOURCE pointer.

1. **Block endpoint is `POST /ui/social/block`.** VERDICT: Corrected (draft said `POST /ui/blocks`). SOURCE: OpenAPI `POST /ui/social/block` (op `block_user_ui_social_block_post`, req `BlockRequest`, resp `200:BlockActionResponse`); `src/api/endpoints/blocking.ts: blockUser`.
2. **Unblock is `POST /ui/social/unblock` with a JSON body (NOT `DELETE /ui/blocks/{userId}`).** VERDICT: Corrected. SOURCE: OpenAPI `POST /ui/social/unblock` (req `UnblockRequest`, resp `200:BlockActionResponse`); `src/api/endpoints/blocking.ts: unblockUser`.
3. **List blocks is `GET /ui/social/blocked` with `limit`/`cursor` params.** VERDICT: Corrected (draft said `GET /ui/blocks`). SOURCE: OpenAPI `GET /ui/social/blocked` (resp `200:BlockedUsersListResponse`, params `limit,cursor`); `src/api/endpoints/blocking.ts: getBlockedUsers`.
4. **Per-user relationship endpoint `GET /ui/social/block-status/{target_user_id}` exists.** VERDICT: Corrected/Verified (draft assumed it might not; it does). SOURCE: OpenAPI `GET /ui/social/block-status/{target_user_id}` (resp `200:BlockStatusResponse`); `src/api/endpoints/blocking.ts: getBlockStatus`.
5. **Block request field is `target_user_id` (+ optional `reason`, maxLength 500), NOT `blocked_user_id`.** VERDICT: Corrected. SOURCE: schema `BlockRequest` (`openapi.pretty.json`); `src/api/endpoints/blocking.ts: blockUser` body `{ target_user_id, reason? }`.
6. **Unblock request field is `target_user_id`.** VERDICT: Corrected (draft used a path param). SOURCE: schema `UnblockRequest`; `src/api/endpoints/blocking.ts: unblockUser`.
7. **Block/unblock response is `BlockActionResponse { ok: bool=true, status: string, target_user_id: string }` returning HTTP `200` (NOT `201`/`204`, NOT `BlockDto {blocked_user_id, created_at}`).** VERDICT: Corrected. SOURCE: schema `BlockActionResponse`; `src/api/types.ts: BlockActionResponse` (`status: "blocked" | "unblocked"`).
8. **List response is `BlockedUsersListResponse { blocked_users: BlockedUserItem[], next_cursor?, total_count }` (NOT `{ items, next_cursor }`).** VERDICT: Corrected. SOURCE: schema `BlockedUsersListResponse`; `src/api/types.ts: BlockedUsersResponse`.
9. **List item is `BlockedUserItem { user_id, display_name?, profile_photo_url?, blocked_at }` — no `handle`, no `created_at`.** VERDICT: Corrected. SOURCE: schema `BlockedUserItem`; `src/api/types.ts: BlockedUser`.
10. **Relationship flags are `is_blocked_by_me` / `is_blocking_me` (NOT `is_blocked` / `blocked_by`).** VERDICT: Corrected. SOURCE: schema `BlockStatusResponse`; `src/api/types.ts: BlockStatusResponse`; also optional on `src/api/endpoints/social.ts: FollowStatus`.
11. **Relationship flags also ride the follow-status payload via `GET /ui/social/follow-status/{userId}`.** VERDICT: Verified. SOURCE: `src/api/endpoints/social.ts: getFollowStatus`; `FollowStatus { ..., is_blocked_by_me?, is_blocking_me? }`.
12. **CSRF: client reads the `ui_csrf` cookie and sets `X-CSRF-Token` on requests, with `credentials: "include"` (cookie jar).** VERDICT: Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`; `credentials: "include"`).
13. **Auth also sends `Authorization: Bearer <accessToken>`; `401` triggers a single `POST /ui/session/refresh` + one retry.** VERDICT: Verified. SOURCE: `src/api/client.ts` (`refreshSession` posts `/ui/session/refresh`; single-flight `refreshPromise`; retry once then logout).
14. **FastAPI `detail` mapping (`string | [{msg}] | {code,...}`) is real and centralized.** VERDICT: Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail`.
15. **Documented error response for these endpoints is `422 HTTPValidationError` (plus auth `401`/`403`).** VERDICT: Verified. SOURCE: OpenAPI index lines for the four `/ui/social/*` block ops (`resp=...;422:HTTPValidationError`).
16. **Idempotency is via a `200` + `status` string, mirroring follow (`already_following`/`not_following`), NOT via `409`/`404`.** VERDICT: Corrected (codes were assumed). SOURCE: `src/api/endpoints/social.ts: FollowResponse`/`UnfollowResponse`; `BlockActionResponse.status` is a free string in the schema.
17. **A `403` contact-rejection with `detail.code == "user_blocked"`.** VERDICT: Unverified-assumption. SOURCE: no `user_blocked` token anywhere in `openapi.pretty.json` or `src/` (grep returned only `is_blocked_by_me`). Handle generic `403` instead.
18. **The web app has a dedicated Blocked Users management screen (settings) — and porting it is out of scope.** VERDICT: Verified (existence) / scope decision unchanged. SOURCE: `src/pages/settings/BlockedUsersPage.tsx` (uses `getBlockedUsers`, `unblockUser`).
19. **Server is authoritative for hiding content / rejecting contact; client suppression is defense-in-depth.** VERDICT: Unverified-assumption (reasonable; not contradicted). SOURCE: no client source can prove server enforcement; consistent with `BlockedUsersPage` copy "Blocked users cannot message you or see your content."
20. **Hilt/Retrofit/Compose module-layering choices and AND-027 client reuse.** VERDICT: Unverified-assumption (Android-side architecture, not in the web/OpenAPI sources). SOURCE: framework ref — Hilt (https://developer.android.com/training/dependency-injection/hilt-android), Retrofit (https://square.github.io/retrofit/); reuse of AND-027 client per this repo's plan, not independently verifiable here.
21. **Optional Room `blocked_users` table for offline caching.** VERDICT: Unverified-assumption (design choice). SOURCE: framework ref — Room (https://developer.android.com/training/data-storage/room).

### Corrections made

- Block path `POST /ui/blocks` → `POST /ui/social/block` (#1).
- Unblock `DELETE /ui/blocks/{userId}` → `POST /ui/social/unblock` body POST (#2).
- List path `GET /ui/blocks` → `GET /ui/social/blocked` (#3).
- Added the real `GET /ui/social/block-status/{target_user_id}` relationship endpoint (#4).
- Request field `blocked_user_id` → `target_user_id` (+ optional `reason`) (#5, #6).
- Response `201 BlockDto {blocked_user_id, created_at}` / `204` → `200 BlockActionResponse {ok, status, target_user_id}` (#7).
- List wrapper `{ items, next_cursor }` → `{ blocked_users, next_cursor?, total_count }` (#8).
- List item dropped non-existent `handle`/`created_at`; now `user_id`/`display_name?`/`profile_photo_url?`/`blocked_at` (#9).
- Relationship flags `is_blocked`/`blocked_by` → `is_blocked_by_me`/`is_blocking_me` (#10).
- Removed assumed idempotency codes `409 already_blocked` / `404 not_blocked`; idempotency now via any-`200`-is-success (#16).
- Demoted the `403 user_blocked` detail code to a generic `403` handler since it is unverified (#17).
- Corrected the "no blocked-users screen exists" framing — it exists on web but is out of scope to port (#18).
- Risks R1, R2, R5 updated to RESOLVED/PARTIALLY-RESOLVED accordingly.

### Open assumptions

- **`user_blocked` 403 detail code (#17):** not present in any source; the messaging endpoints' block-enforcement error shape is unknown from the provided references. Mitigation: handle any `403` defensively via the shared mapper.
- **Idempotent `status` literals for re-block/re-unblock (#16):** not enumerated; client treats any `200` as success and does not branch on `status`.
- **Server-side content-hiding / contact-rejection enforcement (#19):** cannot be proven from client/OpenAPI sources; assumed per product copy.
- **Android architecture decisions (#20, #21):** Hilt/Retrofit/Room/Compose and AND-027 client reuse are framework/design choices, not verifiable against the web/OpenAPI references.

## 17. Test Plan

Test targets: **JVM** = JVM/Robolectric local; **emu35** = headless emulator AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). Hardware-dependent cases prefer A15.

**TC-AND-382-01 — Block happy path (contract).**
Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues `200 BlockActionResponse {ok:true,status:"blocked",target_user_id:"usr_abc"}`; CSRF cookie `ui_csrf` present.
Steps: call `BlockApi.block(BlockRequestDto("usr_abc"))`.
Expected: request is `POST /ui/social/block`, JSON body `{"target_user_id":"usr_abc"}`, header `X-CSRF-Token` present; parsed `BlockActionDto.status == "blocked"`.
Traces: AC-1.

**TC-AND-382-02 — Unblock happy path (contract).**
Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `200 {ok:true,status:"unblocked",target_user_id:"usr_abc"}`.
Steps: call `BlockApi.unblock(UnblockRequestDto("usr_abc"))`.
Expected: request is `POST /ui/social/unblock` (a POST, not DELETE), body `{"target_user_id":"usr_abc"}`, `X-CSRF-Token` present; parsed `status == "unblocked"`.
Traces: AC-4.

**TC-AND-382-03 — List + block-status deserialization.**
Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `GET /ui/social/blocked` → `{blocked_users:[{user_id,display_name,profile_photo_url:null,blocked_at}],next_cursor:null,total_count:1}` and `GET /ui/social/block-status/usr_abc` → `{is_blocked_by_me:true,is_blocking_me:false}`.
Steps: call `listBlocks()` then `blockStatus("usr_abc")`.
Expected: `BlockedUsersListDto.blockedUsers[0].userId`/`blockedAt` populated, `totalCount==1`; `BlockStatusDto.isBlockedByMe==true`, `isBlockingMe==false`. No `handle`/`created_at`/`items` keys expected.
Traces: AC-2, AC-4.

**TC-AND-382-04 — Repository optimistic update + rollback.**
Type: unit. Target: JVM. Preconditions: repo seeded empty; first `block` enqueues network failure (`500`).
Steps: call `block("usr_x")`; observe `blockedUserIds` flow.
Expected: `usr_x` added optimistically, then removed on failure; result is `ApiResult.Error`; `isBlocked("usr_x")==false` after rollback.
Traces: AC-2, AC-5.

**TC-AND-382-05 — Idempotency (any 200 is success).**
Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue a re-block `200` (e.g. `status:"blocked"` or any status) and a re-unblock `200`.
Steps: call `block` then `block` again; `unblock` then `unblock` again.
Expected: all four map to `ApiResult.Success`; no error surfaced; code does NOT branch on `409`/`404` (those are not sent).
Traces: AC-5.

**TC-AND-382-06 — 401 triggers single refresh + retry.**
Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `401`, then (after refresh) `200`; auth interceptor from AND-027 wired; user is authenticated.
Steps: call `block("usr_x")`.
Expected: client issues one `POST /ui/session/refresh`, retries the block once, succeeds; refresh is single-flight (one refresh even on concurrent calls).
Traces: AC-6.

**TC-AND-382-07 — Mutations not auto-retried on timeout.**
Type: unit/contract. Target: JVM. Preconditions: MockWebServer set to no-response (socket timeout ~20s) for `POST /ui/social/block`.
Steps: call `block("usr_x")`.
Expected: exactly one outbound request (no automatic retry of the POST); optimistic add reverted; `ApiResult.Error(timeout)`; only GET endpoints are retry-eligible.
Traces: AC-6.

**TC-AND-382-08 — 422 validation surfaced as error.**
Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `422 HTTPValidationError` for an empty `target_user_id`.
Steps: call `block("")`.
Expected: parsed via shared FastAPI `detail` mapper into `ApiResult.Error`; no crash; user-facing message non-empty.
Traces: AC-5.

**TC-AND-382-09 — Generic 403 on contact attempt handled gracefully.**
Type: integration (ViewModel + MockWebServer). Target: JVM. Preconditions: thread with counterpart; send a message that returns `403` (generic detail, NO `user_blocked` literal required).
Steps: invoke send; observe `ThreadUiState`.
Expected: message marked failed/blocked, no crash; banner reflects block; client matches any `403` (does not require the unverified `user_blocked` code).
Traces: AC-3.

**TC-AND-382-10 — Profile block flow hides content (ViewModel).**
Type: integration (Turbine). Target: JVM. Preconditions: profile of `usr_x`; block-status `is_blocked_by_me:false` initially.
Steps: emit `onBlockConfirmed()`; `block` returns `200`.
Expected: `ProfileUiState.blockRelationship` transitions `Normal → BlockedByMe`; placeholder shown; suppressed list combine drops `usr_x`-authored items; conversation removed from list.
Traces: AC-2.

**TC-AND-382-11 — Compose UI: overflow → confirm → block; placeholder + Unblock.**
Type: Compose-UI / instrumented. Target: emu35 (fast CI). Preconditions: profile screen rendered for non-self user.
Steps: open `⋮` overflow, tap "Block @handle", confirm dialog, tap confirm; then on placeholder tap "Unblock".
Expected: confirm dialog appears with effects copy; after confirm, `BlockedProfilePlaceholder` shows with an Unblock button; Unblock invokes `POST /ui/social/unblock`.
Traces: AC-1, AC-4.

**TC-AND-382-12 — Accessibility / semantics.**
Type: Compose-UI / instrumented. Target: emu35. Preconditions: block menu item, confirm dialog, unblock button, contact-blocked banner rendered.
Steps: assert `contentDescription`/semantics on each; verify dialog is focus-trapped and announces its title; verify touch targets ≥48dp; verify state is not conveyed by color alone (text/icon present).
Expected: all semantics present; TalkBack-readable; targets meet 48dp.
Traces: AC-1, AC-3.

**TC-AND-382-13 — Offline / flaky dev-host behavior.**
Type: instrumented / integration. Target: A15 (physical — real radio toggling gives authentic offline behavior; airplane mode on hardware). Preconditions: blocked set already hydrated; toggle device to airplane mode.
Steps: attempt to block another user while offline; observe UI; then attempt with the known-unreliable plaintext dev host returning a connection drop mid-request.
Expected: block/unblock actions disabled with "No connection" hint; previously-fetched suppression remains applied (fail-safe hides blocked content); on mid-request drop, optimistic change reverts and a "Couldn't update — tap to retry" snackbar appears (no auto-retry of the POST).
Traces: AC-2, AC-6.

**TC-AND-382-14 — CSRF/security: mutation without token is rejected; status is private.**
Type: contract/MockWebServer + manual review. Target: JVM (token assertion) + A15 (log inspection). Preconditions: clear `ui_csrf` cookie for the negative case.
Steps: (a) assert `block`/`unblock` requests carry `X-CSRF-Token` when the cookie is present; (b) inspect debug logs/telemetry on-device after a block: confirm no raw blocked user id is logged and the `block_user` event omits PII (hashed/opaque only).
Expected: mutating POSTs always include `X-CSRF-Token` when available; no plaintext block-relationship PII in logs; telemetry carries only `{source,result}` with no raw id.
Traces: AC-1, AC-3.

### Coverage matrix

| AC | Covered by |
|----|-----------|
| AC-1 (Block action + `POST /ui/social/block` + CSRF) | TC-01, TC-11, TC-12, TC-14 |
| AC-2 (Block hides content / suppression) | TC-03, TC-04, TC-10, TC-13 |
| AC-3 (Block prevents contact / 403 handled) | TC-09, TC-12, TC-14 |
| AC-4 (Unblock `POST /ui/social/unblock` + lifts suppression) | TC-02, TC-03, TC-11 |
| AC-5 (Idempotent; no error on repeat) | TC-04, TC-05, TC-08 |
| AC-6 (401 refresh-retry; no auto-retry on timeout) | TC-06, TC-07, TC-13 |
