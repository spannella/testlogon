---
id: AND-382
title: Block / unblock
milestone: M8
epic: E50
priority: P1
size: M
status: draft
depends_on: [AND-027]
blocks: []
---

# AND-382 — Block / unblock

## 1. Overview & Goal

Implement user-level **block / unblock** for the TestLogon native Android app. Blocking is a moderation/safety primitive that lets a signed-in user sever contact with another user: a blocked user's content (profile body, posts, messages) is hidden from the blocker, and the blocked user is prevented from initiating new contact (DMs, follows, comments) with the blocker. The web reference implements this in `frontend/src/api/endpoints/blocking.ts`; this ticket ports the equivalent capability to the Android stack and surfaces it inline in the **profile** and **messages** features.

Goal: ship a reusable `BlockingRepository` + `BlockApi` in `core-data`/`core-network`, a `BlockUiState`-driven interaction (overflow-menu action + confirmation) embedded in the profile screen and conversation/thread screen, and client-side content suppression so that blocked users immediately disappear from the blocker's surfaces without requiring a full app restart. The acceptance bar is: **block hides content + prevents contact, verified by tests.**

This is a self-contained feature spanning two existing features; it introduces no new screens of its own (no dedicated "blocked users list" screen is in scope — see §13).

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Namespace:** all packages rooted at `com.testlogon.android`.
- **Web reference:** `frontend/src/api/endpoints/blocking.ts` (authoritative request/response shapes); shared types in `frontend/src/api/types.ts`. Block/unblock UI is embedded in the web profile and messages views.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json` — confirm exact block paths against it before implementation if `blocking.ts` and OpenAPI disagree.
- **Auth:** cookie-based session (AND-027 `AuthApi`); all block calls are authenticated, ride the persistent cookie jar, and must send the `X-CSRF-Token` header (echoed from the `ui_csrf` cookie) on mutating verbs.
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

FR-7. The current block relationship state for a viewed user must be derivable so screens render the correct affordance. This is read from the profile payload's relationship flags where available (`is_blocked` / `blocked_by`) and/or a `GET` of the block list.

## 4. Technical Design

### 4.1 Module placement

- `core-network`: `BlockApi` Retrofit interface + DTOs.
- `core-model`: domain models `BlockRelationship`, `BlockedUser`.
- `core-data`: `BlockingRepository` (+ impl), Hilt module binding, in-memory/`StateFlow` block-set cache.
- `feature-profile`, `feature-messages`: ViewModel actions + Compose UI wiring (overflow menu, confirm dialog, suppressed states).

### 4.2 API layer (`core-network`)

```kotlin
package com.testlogon.android.core.network.api

interface BlockApi {
    @POST("ui/blocks")
    suspend fun block(@Body body: BlockRequestDto): Response<BlockDto>

    @DELETE("ui/blocks/{userId}")
    suspend fun unblock(@Path("userId") userId: String): Response<Unit>

    @GET("ui/blocks")
    suspend fun listBlocks(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 50,
    ): Response<BlockListDto>
}

@JsonClass(generateAdapter = true)
data class BlockRequestDto(@Json(name = "blocked_user_id") val blockedUserId: String)

@JsonClass(generateAdapter = true)
data class BlockDto(
    @Json(name = "blocked_user_id") val blockedUserId: String,
    @Json(name = "created_at") val createdAt: String,
)

@JsonClass(generateAdapter = true)
data class BlockListDto(
    val items: List<BlockedUserDto>,
    @Json(name = "next_cursor") val nextCursor: String?,
)

@JsonClass(generateAdapter = true)
data class BlockedUserDto(
    @Json(name = "user_id") val userId: String,
    val handle: String?,
    @Json(name = "display_name") val displayName: String?,
    @Json(name = "created_at") val createdAt: String,
)
```

> Note: exact paths/verbs MUST be reconciled against `frontend/src/api/endpoints/blocking.ts` and `/openapi.json` during implementation. If the backend uses `POST /ui/blocks/{userId}` (path-param create) rather than a body, adjust `block()` accordingly; the contract in §5 is the working assumption.

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

All calls are authenticated (session cookies) and send `X-CSRF-Token` on mutating verbs. Base URL is the dev host; timeouts ~20s.

**Block** — `POST /ui/blocks`
Request:
```json
{ "blocked_user_id": "usr_abc123" }
```
Response `201`:
```json
{ "blocked_user_id": "usr_abc123", "created_at": "2026-06-05T12:00:00Z" }
```

**Unblock** — `DELETE /ui/blocks/{userId}`
Response `204` (empty body).

**List blocks** — `GET /ui/blocks?cursor=&limit=50`
Response `200`:
```json
{
  "items": [
    { "user_id": "usr_abc123", "handle": "alice", "display_name": "Alice", "created_at": "2026-06-05T12:00:00Z" }
  ],
  "next_cursor": null
}
```

**Contact rejection (server-enforced):** attempts to message/follow a user across a block boundary return `403` with FastAPI `detail`, e.g.:
```json
{ "detail": { "code": "user_blocked", "msg": "You cannot contact this user." } }
```
The `detail` field follows the standard FastAPI mapping (string | `[{msg}]` | `{code,...}`) and is parsed by the shared error mapper.

**Error/status mapping:**
- `201`/`204` → success; treat repeated block/unblock (`409`/`404`) as idempotent success (FR-6).
- `401` → trigger the AND-027 single `POST /ui/session/refresh` + retry path.
- `403` with `user_blocked` → contact-blocked UI state.
- `5xx`/timeout → surface stale/retry state; **do not** retry the mutating POST/DELETE (non-idempotent at the HTTP level) — only `GET /ui/blocks` is eligible for bounded backoff retry.

## 6. Data & State Management

- **Source of truth (server):** the block relationship lives in DynamoDB; the client never persists it as durable truth.
- **Local cache:** `BlockingRepositoryImpl` holds an in-memory `StateFlow<Set<String>>` of blocked ids for the session, hydrated by `refreshBlockList()` on app start / profile open. Optional Room table `blocked_users` (`core-data`) MAY cache the list for offline rendering; if added, it is keyed by `user_id` and cleared on logout. DataStore is not used (this is account data, not a preference).
- **Optimistic updates:** `block()`/`unblock()` mutate the in-memory set immediately, then reconcile with the server response; on failure the set is reverted and an error is emitted to the calling ViewModel.
- **State flows:**
  - `ProfileUiState.blockRelationship: BlockRelationship { Normal, BlockedByMe, BlockedMe }`
  - `ThreadUiState.contactBlocked: Boolean`, `ThreadUiState.composerEnabled: Boolean`.
- **Suppression:** list ViewModels `combine` their item flow with `blockedUserIds` and drop authored items — applied at the ViewModel layer so cached Room/Paging data is filtered without invalidating the cache.
- **Logout:** clears the in-memory set and any `blocked_users` rows.

## 7. Error Handling & Resilience

- All network results wrapped in `ApiResult<T>` (`Success`/`Error(type, detail)`).
- **Idempotency:** `409 already_blocked` on block and `404 not_blocked` on unblock map to `Success` (FR-6) so the UI never shows a confusing error.
- **Timeout / unreliable host:** 20s timeouts. On block/unblock timeout, revert the optimistic change and show a non-blocking snackbar "Couldn't update — tap to retry"; the user re-triggers the action (no automatic retry of the mutation).
- **`401`:** delegate to AND-027 auth interceptor (single `session/refresh` then retry once).
- **Contact attempt against a block (`403 user_blocked`):** the composer disables and shows the banner; if a send slips through (race), the `403` is caught and the message marked failed with the block reason.
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
- `BlockApi` paths/verbs/bodies match §5 contract (block `POST /ui/blocks`, unblock `DELETE /ui/blocks/{id}`, list `GET /ui/blocks`), including `X-CSRF-Token` header presence on mutations.
- `BlockingRepositoryImpl`: optimistic add/remove, rollback on failure, idempotent mapping of `409`/`404` to success, `blockedUserIds` StateFlow emissions, refresh hydration.
- Error mapping: `401` → refresh path; `403 user_blocked` parsed via FastAPI `detail` mapper.

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

- **R1 — Exact contract drift:** `blocking.ts` vs `/openapi.json` may differ on path shape (`POST /ui/blocks` body vs `POST /ui/blocks/{userId}`), status codes, and whether profile payloads carry `is_blocked`/`blocked_by` flags. Reconcile before coding; §5 is the working assumption.
- **R2 — Relationship read source:** if the profile endpoint does not return relationship flags, the client must rely on `listBlocks` membership only, which does not capture the `BlockedMe` (reverse) direction — that direction would then be discoverable only via `403` on contact. Open question: does the backend expose a per-user relationship endpoint?
- **R3 — Cache coherence:** Paging 3 / Room caches may retain blocked-authored items; we suppress at the ViewModel layer, but pagination counts and "load more" boundaries may look off. Acceptable for v1.
- **R4 — Out of scope:** dedicated "Blocked users" management/list screen, report-and-block combined flow, and bulk operations are NOT in this ticket.
- **R5 — Idempotency status codes:** assumption that re-block returns `409` and re-unblock returns `404`; confirm so the idempotent mapping (FR-6) is correct.

## 14. Acceptance Criteria

AC-1. From a non-self profile and from a message thread, a Block action is available, shows a confirmation dialog, and on confirm issues `POST /ui/blocks` with the correct body + `X-CSRF-Token`. (UI + MockWebServer tested.)

AC-2. **Block hides content:** after blocking, the blocked user's profile renders the blocked placeholder, their conversation is removed from the conversation list, and their authored items are suppressed in the blocker's current session. (Verified by ViewModel/Compose tests.)

AC-3. **Block prevents contact:** the message composer toward a blocked counterpart is disabled with a banner, and a `403 user_blocked` from a contact attempt is handled gracefully (no crash, message marked failed/blocked). (Tested.)

AC-4. Unblock issues `DELETE /ui/blocks/{userId}`, lifts suppression on refresh, and re-enables contact. (Tested.)

AC-5. Block/unblock are idempotent in the UI: `409`/`404` responses do not surface an error. (Unit tested.)

AC-6. `401` during a block/unblock triggers the AND-027 refresh-and-retry path; mutating calls are not auto-retried on timeout. (Unit tested.)

## 15. Definition of Done

- `BlockApi` (`core-network`), `BlockingRepository`/impl (`core-data`), and domain models (`core-model`) implemented and Hilt-wired, reusing the AND-027 authenticated client.
- Block/unblock embedded in profile and messages with shared `core-ui` composables; content suppression + composer gating in place.
- All §11 tests written and green (unit, ViewModel/Turbine, Compose), including the acceptance-critical "hides content + prevents contact" tests.
- Strings externalized; accessibility semantics present; lint + detekt clean; module layering respected (no upward deps).
- Telemetry events emitted without PII; no block-relationship PII in logs.
- Contract reconciled against `blocking.ts` / `/openapi.json` (R1) and any deviations from §5 documented in the PR.
- Code reviewed and merged to `android-port`.
