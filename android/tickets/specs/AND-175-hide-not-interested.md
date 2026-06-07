---
id: AND-175
title: Hide / not-interested
milestone: M4
epic: E24
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-099]
blocks: []
---

# AND-175 — Hide / not-interested

## 1. Overview & Goal

Give the user the ability to remove an individual post from their feed and to
record a "not interested" signal that biases future ranking away from similar
content. Both actions are reachable from the per-post overflow menu introduced
with the post item composable (AND-099). The two actions map to the two web
reference modules named in the backlog scope — `postHide.ts` and
`postInteresting.ts` — and are implemented natively as a single
`PostActionsRepository` capability surfaced through the feed `ViewModel`.

The functional bar set by the backlog acceptance criteria is narrow and
testable:

- A hidden post leaves the feed immediately and does not reappear on refresh or
  pagination within the same session.
- The user's preference (hide and not-interested) is honored — the action is
  persisted to the backend, reflected in subsequent feed responses, and survives
  process death via a local pending/applied cache so the UI is never internally
  inconsistent against an unreliable dev backend.

This is a P2 feature. It is additive to the existing feed pipeline and must not
regress like/unlike (AND-173), share/bookmark (AND-176), or core pagination
(AND-098).

## 2. Context & References

- Module layering: `feature-feed` → `core-data` → `core-network` / `core-model`,
  per the standard `app → feature-* → core-*` graph. No new module is created.
- Namespace / applicationId base: `com.testlogon.android`. All new symbols live
  under `com.testlogon.android.feature.feed.*` and
  `com.testlogon.android.core.data.posts.*`.
- Web reference (verified to exist): `src/api/endpoints/postHide.ts`
  (`hidePost`→`POST /feed/hide`, `unhidePost`→`POST /feed/unhide`,
  `listHiddenPosts`→`GET /feed/hidden`) and `src/api/endpoints/postInteresting.ts`
  (`markPostInteresting`→`POST /feed/interesting`,
  `unmarkPostInteresting`→`POST /feed/uninteresting`,
  `listInterestingPosts`→`GET /feed/interesting`). These modules are
  authoritative for response shapes because the OpenAPI 200 schemas are empty
  (`{}`). The backend OpenAPI document (dev host `http://18.222.237.167:8000`)
  defines request bodies via the `HidePostRequest` schema (`{post_id: string}`)
  and auth/validation envelopes.
- Upstream dependencies:
  - **AND-099 (Post item composable)** — owns `PostItem` and its overflow
    menu slot; this ticket adds the Hide and Not-interested menu entries and the
    callbacks they invoke. Hard dependency.
  - **AND-098 (Feed list, Paging 3)** — owns the `PagingSource` / `Pager` and
    `LazyColumn` host; this ticket filters/invalidates that stream.
  - **AND-173 (Like / unlike)** — establishes the optimistic
    `PostActionsRepository` pattern reused here.
- Auth/session, CSRF header, cookie jar, 401→refresh→retry, and the FastAPI
  `detail` error mapping are provided by `core-network` (session epic) and are
  consumed, not re-implemented, here.

## 3. Functional Requirements

FR-1. The post overflow menu exposes two new items: **Hide this post** and
**Not interested**. Both are enabled for any feed post the current user can see.

FR-2. **Hide** removes the post from the visible feed immediately (optimistic),
issues `POST /feed/hide` with body `{"post_id": "<id>"}` (CORRECTED — the path is
`/feed/hide`, not `/ui/posts/{postId}/hide`; the id travels in the JSON body, not
the URL path), and on success leaves the post hidden for the remainder of the
session and across refresh/pagination.

FR-3. **Not interested** removes the post from the visible feed immediately and
suppresses it for the session identically to a hide. **CORRECTED / IMPORTANT:**
the backend has NO "not interested / suppress this kind of content" endpoint. The
`/feed/interesting` + `/feed/uninteresting` pair the original spec mapped to this
action is a *positive* "more like this" ranking boost (toggle ON / OFF), i.e. the
semantic OPPOSITE of "not interested", and its body is `{"post_id": "<id>"}`
only — there is no `{"interested": false}` field anywhere in the contract. To
honor the backlog acceptance ("preference honored") faithfully, **Not interested
is implemented as a `POST /feed/hide`** (the only server-side suppression signal),
tagged locally with `kind = NOT_INTERESTED` for telemetry/UX copy. Calling
`/feed/uninteresting` for this action would be incorrect and is NOT done. See §13
Open Questions and §16 for the audit trail; confirm with backend whether a
dedicated negative-preference endpoint is planned.

FR-4. A dismissable Snackbar appears after a successful hide/not-interested:
"Post hidden" / "We'll show fewer posts like this" with an **Undo** action.
Undo reverses the action (see FR-6) when invoked before the Snackbar dismisses
(default 6s).

FR-5. If the backend call fails after the optimistic removal and is
non-recoverable, the post is **re-inserted at its prior index** and a transient
error Snackbar is shown: "Couldn't hide post. Tap to retry." Retry re-issues the
same request.

FR-6. **Undo** issues the inverse call. Since both Hide and Not-interested are
implemented via `/feed/hide` (see FR-3), the inverse for BOTH is
`POST /feed/unhide` with body `{"post_id": "<id>"}` (CORRECTED — path is
`/feed/unhide`, not `/ui/posts/{postId}/unhide`; there is no
`{"interested": true}` call). `/feed/unhide` is documented idempotent (unhiding a
post that is not hidden is a no-op success). On success the post is restored to
the feed at its prior index; on failure the post remains removed (undo is
best-effort) and a Snackbar reports the failure.

FR-7. Locally suppressed post ids are persisted so that suppression survives
process death within the session window and so the feed never re-renders a post
the user already hid before the backend reflects the change.

FR-8. The feed `PagingSource` and the merged in-memory feed filter out any post
whose id is in the local suppressed set, regardless of whether the backend has
yet excluded it.

## 4. Technical Design

### 4.1 Model

```kotlin
// core-model
enum class PostSuppressionKind { HIDDEN, NOT_INTERESTED }

data class PostSuppression(
    val postId: String,
    val kind: PostSuppressionKind,
    val createdAtEpochMs: Long,
    val pending: Boolean,        // true until server ack
)
```

### 4.2 Network layer (core-network)

```kotlin
// CORRECTED: real backend contract is /feed/hide and /feed/unhide with the
// post id in a JSON body ({"post_id": ...}), NOT path params under /ui/posts.
interface PostActionsApi {
    @POST("feed/hide")
    suspend fun hide(@Body body: HidePostRequest): Response<HideMutationResponse>

    @POST("feed/unhide")
    suspend fun unhide(@Body body: HidePostRequest): Response<HideMutationResponse>

    // Optional: positive "more like this" boost. NOTE this is NOT "not
    // interested"; it is the opposite signal (see FR-3). Included only if a
    // future "Show more like this" affordance is added; the Not-interested
    // action does NOT call these.
    @POST("feed/interesting")
    suspend fun markInteresting(@Body body: HidePostRequest): Response<PostInterestingResult>

    @POST("feed/uninteresting")
    suspend fun unmarkInteresting(@Body body: HidePostRequest): Response<PostInterestingResult>
}

@JsonClass(generateAdapter = true)
data class HidePostRequest(@Json(name = "post_id") val postId: String)

// Shape per frontend postHide.ts (the OpenAPI 200 schema is empty {} so the
// frontend module is authoritative): { ok, post_id, hidden }.
@JsonClass(generateAdapter = true)
data class HideMutationResponse(
    val ok: Boolean,
    @Json(name = "post_id") val postId: String,
    val hidden: Boolean,
)

// Shape per frontend postInteresting.ts: { ok, post_id, is_interesting }.
@JsonClass(generateAdapter = true)
data class PostInterestingResult(
    val ok: Boolean,
    @Json(name = "post_id") val postId: String,
    @Json(name = "is_interesting") val isInteresting: Boolean,
)
```

These are state-changing `POST`s, therefore **not** eligible for the bounded
backoff retry that `core-network` applies only to idempotent `GET`s. They get a
single attempt plus the standard one-shot 401→`/ui/session/refresh`→retry
(verified: the web client refreshes via `POST /ui/session/refresh` exactly once
on 401 then replays the request — see `src/api/client.ts`). Transport headers
applied by the shared OkHttp interceptors mirror the web client: the
`Authorization: Bearer <token>` header from the session store, the
`X-CSRF-Token` header (echo of the `ui_csrf` cookie), and the persistent cookie
jar (`credentials: include`). CORRECTED: auth is Bearer-token + CSRF + cookies,
not "cookie-only" as originally stated. The OpenAPI also lists optional
`X-SESSION-ID` (header) and `user_sub` (query) parameters and an optional
`X-IMPERSONATION-TOKEN`; these are not required for the first-party mobile flow
and are omitted unless the session epic wires them. Per-call timeout follows the
global ~20s ceiling.

### 4.3 Repository (core-data)

```kotlin
interface PostActionsRepository {
    val suppressed: StateFlow<Set<String>>           // post ids hidden/not-interested
    suspend fun hide(postId: String): ApiResult<Unit>
    suspend fun unhide(postId: String): ApiResult<Unit>
    suspend fun notInterested(postId: String): ApiResult<Unit>
    suspend fun interested(postId: String): ApiResult<Unit>   // undo for not-interested
}

@Singleton
class PostActionsRepositoryImpl @Inject constructor(
    private val api: PostActionsApi,
    private val dao: PostSuppressionDao,
    private val errorMapper: ApiErrorMapper,
    @IoDispatcher private val io: CoroutineDispatcher,
) : PostActionsRepository
```

Flow for `hide(postId)`:
1. Upsert `PostSuppression(postId, HIDDEN, now, pending = true)` into Room and
   emit the updated `suppressed` set (optimistic removal is observed by the
   feed).
2. Call `api.hide(HidePostRequest(postId))`.
3. On success → mark `pending = false`. Return `ApiResult.Success`.
4. On failure → delete the suppression row (rollback), emit, return
   `ApiResult.Error` carrying the mapped message.

`notInterested` is identical to `hide` but writes `kind = NOT_INTERESTED`; it
calls the SAME `api.hide(HidePostRequest(postId))` (CORRECTED — see FR-3: there
is no negative-preference endpoint, so Not-interested reuses `/feed/hide`; it does
NOT call `/feed/interesting`, which is a positive boost). Both `unhide`
(undo-hide) and `interested` (undo-not-interested, kept as a method name for the
ViewModel's symmetry) delete the corresponding suppression row first (optimistic
restore), then call `api.unhide(HidePostRequest(postId))`; on failure they
re-insert the suppression row.

### 4.4 ViewModel (feature-feed)

`FeedViewModel` (owned by AND-098) gains:

```kotlin
fun onHide(postId: String, index: Int)
fun onNotInterested(postId: String, index: Int)
fun onUndo(action: FeedAction)        // FeedAction.Hide | FeedAction.NotInterested
fun onRetry(action: FeedAction)
```

`index` is captured so a rollback re-inserts at the prior position. UI
side-effects (Snackbar with Undo/Retry) are delivered via a
`Channel<FeedEffect>` exposed as `Flow<FeedEffect>` and collected by the screen.

The feed item stream is derived as:

```kotlin
val items: Flow<PagingData<PostUiModel>> =
    pager.flow
        .cachedIn(viewModelScope)
        .combine(actions.suppressed) { paging, hidden ->
            paging.filter { it.id !in hidden }
        }
```

`combine` over `cachedIn` ensures suppression updates re-filter without a network
round-trip and without losing scroll position; `PagingData.filter` drops
suppressed ids from the rendered list.

### 4.5 Compose

`PostItem` (AND-099) accepts `onHide` and `onNotInterested` lambdas. The overflow
`DropdownMenu` renders `DropdownMenuItem`s for both, each with a leading icon
(`Icons.Outlined.VisibilityOff`, `Icons.Outlined.ThumbDownOffAlt`). The screen
hosts a single `SnackbarHost`; effects are mapped to `SnackbarVisuals` with an
action label for Undo/Retry.

## 5. API Contract

Base URL (dev): `http://18.222.237.167:8000`. All requests carry the
`Authorization: Bearer` header, session cookies, and `X-CSRF-Token` (verified
against `src/api/client.ts`). All paths below are CORRECTED against the OpenAPI
index and the frontend modules; the id is always in the JSON body.

**Hide** (also used for Not-interested — see FR-3)
```
POST /feed/hide
Content-Type: application/json
{ "post_id": "p_123" }                  // schema: HidePostRequest
→ 200 { "ok": true, "post_id": "p_123", "hidden": true }   // postHide.ts: HideMutationResponse
```
(The OpenAPI 200 response schema is empty `{}`; the response shape above is taken
from the authoritative frontend module `src/api/endpoints/postHide.ts`. A second
caller `src/api/endpoints/newsfeed.ts: hidePost` types the response as just
`{ ok: boolean }`, so treat `hidden` defensively as optional when deserializing.)

**Unhide (undo for both Hide and Not-interested)**
```
POST /feed/unhide
Content-Type: application/json
{ "post_id": "p_123" }                  // schema: HidePostRequest
→ 200 { "ok": true, "post_id": "p_123", "hidden": false }
```
Documented idempotent: unhiding a not-hidden post is a no-op success.

**Interesting / Uninteresting (POSITIVE "more like this" — NOT this ticket's
"Not interested")**
```
POST /feed/interesting     body { "post_id": "p_123" }   // toggle boost ON
POST /feed/uninteresting   body { "post_id": "p_123" }   // toggle boost OFF
→ 200 { "ok": true, "post_id": "p_123", "is_interesting": true|false }  // postInteresting.ts
GET  /feed/interesting?limit=200   → { "post_ids": [...], "count": N }
```
CORRECTED: there is no `{"interested": <bool>}` body and no
`interested` response field anywhere. These endpoints are a positive ranking
boost and are NOT invoked by the Hide/Not-interested actions.

Error envelope (FastAPI) — mapped by `ApiErrorMapper` (verified against
`src/api/client.ts: normalizeErrorDetail` and the `HTTPValidationError`/
`ValidationError` schemas):
```
4xx/5xx { "detail": "..." }                                   // string
       | { "detail": [ { "loc": [...], "msg": "...", "type": "..." } ] }  // 422 validation array
       | { "detail": { "code": "...", ... } }                 // structured (e.g. role_required, geo_blocked)
```
`404` (post gone) is treated as success-equivalent for hide (the post is already
absent → keep it suppressed, clear pending). `401` triggers the single
`POST /ui/session/refresh` + retry handled by `core-network` (verified). A raw
network/offline failure surfaces as `ApiError(status = 0)` in the web client and
maps to the rollback + retry path here.

## 6. Data & State Management

- **Room (cache):** `post_suppression` table via `PostSuppressionDao`.

```kotlin
@Entity(tableName = "post_suppression")
data class PostSuppressionEntity(
    @PrimaryKey val postId: String,
    val kind: String,            // PostSuppressionKind.name
    val createdAtEpochMs: Long,
    val pending: Boolean,
)

@Dao
interface PostSuppressionDao {
    @Query("SELECT * FROM post_suppression")
    fun observeAll(): Flow<List<PostSuppressionEntity>>
    @Upsert suspend fun upsert(e: PostSuppressionEntity)
    @Query("DELETE FROM post_suppression WHERE postId = :id")
    suspend fun delete(id: String)
    @Query("DELETE FROM post_suppression WHERE createdAtEpochMs < :cutoff")
    suspend fun purgeOlderThan(cutoff: Long)
}
```

- `suppressed: StateFlow<Set<String>>` is derived from `observeAll()` and is the
  single source of truth for client-side feed filtering. It is durable across
  process death (Room), satisfying FR-7.
- DataStore is **not** used here; suppression is a structured set, not a scalar
  preference. A retention purge (`purgeOlderThan`, e.g. applied entries older
  than 30 days) runs on repository init to keep the table bounded, since the
  backend is the long-term authority and reflects suppression in feed responses.
- UI state: existing `FeedUiState` is unchanged in shape; one-off effects flow
  through `FeedEffect` (Snackbar Undo/Retry) rather than the persistent state.

## 7. Error Handling & Resilience

- Optimistic-first: every action removes the post locally before the network
  call, so the unreliable dev host never blocks the UX.
- On network/5xx/timeout failure: rollback (re-insert at captured index) +
  "Tap to retry" Snackbar. No automatic retry (these are non-idempotent POSTs).
- On `404`: keep suppression (idempotent outcome).
- Undo failures are best-effort and do not rollback the rollback; a Snackbar
  informs the user.
- Pending rows (`pending = true`) that never got acked (e.g. process killed
  mid-flight) are reconciled lazily: the next successful feed load that still
  returns a pending-hidden post triggers a single re-send of the action; if the
  feed no longer returns it, the row is marked applied. This prevents
  permanently-divergent client/server state against a flaky backend.
- All errors are surfaced via `ApiErrorMapper` so the FastAPI `detail` variants
  produce a single human-readable string.

## 8. Security & Privacy

- No new auth surface. Requests reuse the existing session: the
  `Authorization: Bearer` token from the session store, session cookies
  (`credentials: include`), and the `X-CSRF-Token` header echoed from the
  `ui_csrf` cookie (CORRECTED: the web client sends Bearer + CSRF + cookies, not
  cookies alone). The state-changing POSTs require CSRF, so the header MUST be
  present (enforced by the shared interceptor).
- `postId`s are not PII; the local `post_suppression` table stores only ids,
  kind, and timestamps in the app-private Room database. No export, no logging of
  post content.
- Not-interested is a personalization signal; it is sent only to the first-party
  backend and never to third parties. No analytics payload includes post
  content (see §10).
- Plaintext HTTP dev host is a known dev-only condition; production base URL is
  configured per build type and is HTTPS. No additional handling in this ticket.

## 9. Accessibility & i18n

- Menu items have `contentDescription` / visible text "Hide this post" and
  "Not interested". Snackbar action label "Undo"/"Retry" is focusable and
  announced.
- All strings live in `feature-feed` `strings.xml`: `feed_action_hide`,
  `feed_action_not_interested`, `feed_hidden_snackbar`,
  `feed_not_interested_snackbar`, `feed_action_undo`, `feed_hide_error_retry`.
  No hardcoded UI text.
- On successful removal, emit a polite `LiveRegion`/`announceForAccessibility`
  equivalent ("Post hidden") so screen-reader users get feedback even though the
  item disappears.
- Touch targets ≥ 48dp; overflow menu opens via the existing accessible
  more-actions button from AND-099.
- RTL-safe (Compose default with start/end paddings).

## 10. Telemetry & Logging

- Events (first-party analytics sink, no content): `post_hidden`,
  `post_not_interested`, `post_hide_undo`, `post_hide_failed` — each with
  `{ post_id, source = "feed", latency_ms, result }`.
- Logging via the shared logger at `DEBUG` for request lifecycle; never log
  cookies or the CSRF token. Network logging uses the OkHttp logging
  interceptor’s redaction config already set in `core-network`.
- Failures log the mapped error message at `WARN` with the endpoint and
  HTTP status, not the post body.

## 11. Testing Strategy

Unit (core-testing, JUnit + Turbine + MockWebServer):
- `PostActionsRepositoryImpl`: success marks `pending=false`; failure rolls back
  (row deleted, `suppressed` re-emits without id); `404` keeps suppression;
  both `hide` and `notInterested` send `POST /feed/hide` with body
  `{"post_id": "<id>"}` (CORRECTED — not `{"interested": false}`; assert path and
  request body via MockWebServer `RecordedRequest`).
- 401 path: MockWebServer returns 401 then 200 after refresh → asserts single
  retry and final success (refresh handled by interceptor under test harness).
- `FeedViewModel.onHide/onNotInterested`: emits removal, then `FeedEffect`
  Snackbar; `onUndo` restores; `onRetry` re-issues.
- `PagingData.filter` against suppressed set: hidden id never present in
  collected `PagingData` (use `AsyncPagingDataDiffer` or `cachedIn` collector).

Instrumented / Compose UI (`createAndroidComposeRule`):
- Open overflow → tap "Hide this post" → assert item with test tag
  `post_{id}` is gone; assert Snackbar "Post hidden" + "Undo" shown.
- Tap "Undo" → assert item returns at prior position.
- Force network failure (MockWebServer 500) → assert item re-appears + retry
  Snackbar.
- Refresh feed after hide → assert hidden item does not return (suppressed set
  honored) — directly covers the backlog acceptance ("Hidden post leaves feed;
  preference honored").

Persistence:
- Room test: suppression survives `dao` reopen; `purgeOlderThan` removes stale
  rows.

## 12. Dependencies & Sequencing

- **Requires AND-099** (overflow menu slot + `PostItem` callbacks) — hard
  blocker; cannot render the actions without it.
- **Requires AND-098** (Paging feed + `FeedViewModel`) to host filtering and
  effects; in practice AND-099 already depends on the feed scaffolding.
- Reuses the optimistic `PostActionsRepository` pattern from **AND-173
  (Like / unlike)**; if AND-173 lands first, extend its repository rather than
  creating a parallel one.
- Sibling **AND-176 (Share / bookmark)** shares the same overflow menu and
  Snackbar host; coordinate menu ordering and the single `SnackbarHost`
  instance.
- No backend work owned here; endpoint availability on the dev host is assumed
  from the web reference and `/openapi.json`.

## 13. Risks & Open Questions

- **Endpoint shape — RESOLVED during this review.** Verified against the OpenAPI
  index and frontend modules: paths are `POST /feed/hide`, `POST /feed/unhide`,
  `POST /feed/interesting`, `POST /feed/uninteresting` (all `req=HidePostRequest`,
  body `{"post_id"}`); the original `/ui/posts/{postId}/*` paths were WRONG and
  have been corrected throughout. Risk now isolated to the empty OpenAPI 200
  schema (response field names taken from the frontend modules, not OpenAPI).
- **No "not interested" endpoint exists — KEY FINDING.** The backend only offers
  hide/unhide (suppression) and interesting/uninteresting (a *positive* boost).
  There is no negative-preference / "show fewer like this" endpoint. This ticket
  implements Not-interested via `/feed/hide`. OPEN QUESTION for backend: is a
  dedicated negative-preference endpoint planned? If yes, swap only the
  `notInterested` call in `PostActionsRepositoryImpl`.
- **Does the backend filter hidden posts from the feed?** `/feed/unhide` deletes a
  per-viewer `HIDE#{user}/POST#{post_id}` record, implying the feed query honors
  hides server-side, but this is not provable from the documents alone. Client-side
  suppression remains the guarantee; the `suppressed` set covers it either way.
  Open question for backend confirmation.
- **Reconciliation re-send (§7)** could double-apply on a backend that is not
  idempotent for hide. `/feed/unhide` is documented idempotent; `/feed/hide`
  idempotency is assumed (404 = ok) but not explicitly documented — confirm.
- Pagination edge: re-inserting at a captured index after a far scroll may place
  the item off-screen; acceptable (item returns to its logical position).

## 14. Acceptance Criteria

AC-1. Selecting **Hide this post** removes the post from the feed immediately,
calls `POST /feed/hide` with body `{"post_id": "<id>"}`, and the post does not
reappear on pull-to-refresh or further pagination in the session. (Backlog:
"Hidden post leaves feed.")

AC-2. Selecting **Not interested** removes the post immediately and calls
`POST /feed/hide` with body `{"post_id": "<id>"}` (CORRECTED — there is no
`interested` field and no negative-preference endpoint; the suppression IS the
hide); the preference is persisted and the post stays out of the feed. (Backlog:
"preference honored.")

AC-3. Suppression survives process death within the session (Room-backed
`suppressed` set); a hidden post is never re-rendered after restart while the
suppression row exists.

AC-4. A successful action shows a Snackbar with **Undo**; Undo restores the post
at its prior position and issues the inverse endpoint.

AC-5. A failed action rolls the post back to its original index and shows a
retry Snackbar; tapping Retry re-issues the request.

AC-6. A `401` causes exactly one `/ui/session/refresh` + retry; a `404` is
treated as already-hidden (success-equivalent).

AC-7. No like/unlike, share/bookmark, or pagination regression; existing feed
tests stay green.

## 15. Definition of Done

- `PostActionsApi`, `PostActionsRepository(+Impl)`, `PostSuppressionDao` +
  entity, and Room migration merged under `com.testlogon.android.*`.
- `FeedViewModel` exposes `onHide/onNotInterested/onUndo/onRetry`; `items` flow
  filters the suppressed set; `FeedEffect` Snackbar wiring complete.
- `PostItem` overflow menu renders both actions with localized strings and a11y
  labels.
- Unit + Compose UI + Room tests from §11 implemented and passing in CI;
  coverage includes the two backlog acceptance scenarios (AC-1, AC-2).
- No hardcoded strings; all new copy in `strings.xml`.
- Telemetry events emitted; no secrets/cookies/CSRF logged.
- Endpoint paths/fields reconciled against `/openapi.json` (or the open
  questions in §13 logged as follow-ups with the confirmed contract).
- `ktlint`/`detekt` clean; PR reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Hide endpoint is `POST /feed/hide` with body `{post_id}`.** VERIFIED
   (Corrected from `/ui/posts/{postId}/hide`). Source: OpenAPI `POST /feed/hide`
   (op=`hide_post_feed_hide_post`, req=`HidePostRequest`); schema
   `components.schemas.HidePostRequest` = `{ post_id: string }` (required);
   frontend `src/api/endpoints/postHide.ts: hidePost` posts `/feed/hide` with
   `{ post_id }`.
2. **Unhide endpoint is `POST /feed/unhide` with body `{post_id}`; idempotent.**
   VERIFIED (Corrected from `/ui/posts/{postId}/unhide`). Source: OpenAPI
   `POST /feed/unhide` (op=`unhide_post_feed_unhide_post`, req=`HidePostRequest`),
   description states it deletes the per-viewer `HIDE#{user}/POST#{post_id}`
   record and is a no-op success when not hidden; frontend
   `src/api/endpoints/postHide.ts: unhidePost`.
3. **Hide response shape `{ ok, post_id, hidden }`.** VERIFIED (frontend) /
   Unverified (OpenAPI). Source: frontend
   `src/api/endpoints/postHide.ts: HideMutationResponse`. The OpenAPI 200 schema
   for `/feed/hide` is empty (`{}`), so the frontend module is authoritative; a
   second caller `src/api/endpoints/newsfeed.ts: hidePost` types it as
   `{ ok: boolean }` only, hence `hidden` is treated as optional.
4. **"Not interested" maps to `POST /feed/interesting` with
   `{"interested": false}`.** CORRECTED — this claim was WRONG on two counts.
   (a) There is no `interested` field: the body schema is `HidePostRequest`
   (`{post_id}`) — OpenAPI `POST /feed/interesting` req=`HidePostRequest`;
   frontend `src/api/endpoints/postInteresting.ts: markPostInteresting` posts
   `{ post_id }`. (b) `/feed/interesting` is a POSITIVE "more like this" boost
   (toggle ON), the semantic opposite of "not interested" — OpenAPI
   `GET /feed/interesting` description ("Powers the 'more like this' feed-ranking
   boost"), `POST /feed/uninteresting` description ("Remove the viewer's
   'interesting' signal (toggle OFF)"). Resolution: Not-interested is implemented
   as `POST /feed/hide` (the only suppression signal).
5. **Interesting response field is `interested`.** CORRECTED to `is_interesting`.
   Source: frontend `src/api/endpoints/postInteresting.ts: PostInterestingResult`
   = `{ ok, post_id, is_interesting }`.
6. **Undo for not-interested calls `interesting` with `{"interested": true}`.**
   CORRECTED — undo for both Hide and Not-interested is `POST /feed/unhide`
   (since Not-interested is a hide). Source: see citations 2 and 4.
7. **Auth: cookie-based session + `X-CSRF-Token` only.** CORRECTED — the web
   client also sends `Authorization: Bearer <accessToken>`. Source:
   `src/api/client.ts` lines ~157-171 (sets `Authorization` from `authStore`,
   `X-CSRF-Token` from the `ui_csrf` cookie via `getCookie`, and uses
   `credentials: "include"`). OpenAPI additionally lists optional `X-SESSION-ID`
   (header), `X-IMPERSONATION-TOKEN` (header) and `user_sub` (query) params on
   each `/feed/*` op.
8. **401 → single `POST /ui/session/refresh` → retry once.** VERIFIED. Source:
   `src/api/client.ts: refreshSession` (POSTs `/ui/session/refresh`) and the 401
   branch that refreshes once (guarded by `refreshPromise`) then replays the
   request, logging out on a second 401.
9. **FastAPI error envelope variants (`detail` string | validation array |
   structured `{code,...}`).** VERIFIED. Source: `src/api/client.ts:
   normalizeErrorDetail` (handles string, array of `{msg}`, and object with
   `code` via `mapAuthorizationError`); OpenAPI schemas
   `components.schemas.HTTPValidationError` → `{ detail: ValidationError[] }` and
   `components.schemas.ValidationError` = `{ loc, msg, type }` (all required).
10. **Offline/network failure surfaces distinctly.** VERIFIED. Source:
    `src/api/client.ts` `catch` around `fetch` throws `new ApiError(0, "Network
    error", err)` — the basis for the rollback + "tap to retry" path.
11. **404 (post gone) treated as success-equivalent for hide.** UNVERIFIED-
    ASSUMPTION. Not stated in the sources; `/feed/hide` lists only 200 and 422
    responses in OpenAPI. Reasonable given unhide is documented idempotent, but
    `/feed/hide` idempotency/404 behavior is not documented — flagged in §13.
12. **Backend filters hidden posts out of the feed response.** UNVERIFIED-
    ASSUMPTION. Implied by the `HIDE#{user}/POST#{post_id}` record described in
    the `/feed/unhide` OpenAPI description, but the feed-read query is not in the
    provided sources. Client-side suppression is the guarantee regardless.
13. **`GET /feed/hidden` and `GET /feed/interesting` list surfaces exist.**
    VERIFIED. Source: OpenAPI `GET /feed/hidden` region and
    `GET /feed/interesting` (op=`list_interesting_posts_feed_interesting_get`,
    returns `{ post_ids, count }` per `src/api/endpoints/postInteresting.ts:
    PostInterestingList`). Not used by this ticket but available for
    reconciliation/sync.
14. **Frontend modules `postHide.ts` / `postInteresting.ts` named in the backlog
    exist.** VERIFIED. Source: `src/api/endpoints/postHide.ts`,
    `src/api/endpoints/postInteresting.ts`.
15. **Android framework choices (Paging 3 `PagingData.filter`, Room `@Upsert`,
    Compose `DropdownMenu`/`SnackbarHost`, `combine` over `cachedIn`).**
    UNVERIFIED here / standard framework usage. (framework ref) Jetpack Paging,
    Room, and Compose Material3 — not contract-bearing; correctness is a test
    concern (see §17), not a backend-contract concern.

### Corrections made

- Endpoint paths corrected from `/ui/posts/{postId}/{hide,unhide,interesting}`
  (path-param style) to `/feed/{hide,unhide,interesting,uninteresting}` with the
  id in a JSON `{post_id}` body (FR-2, FR-6, §4.2, §4.3, §5, §14 AC-1/AC-2, §11).
- Removed the non-existent `{"interested": <bool>}` request field and the
  `interested` response field everywhere; corrected the interesting response
  field to `is_interesting` (§4.2, §5).
- Reclassified `/feed/interesting` + `/feed/uninteresting` as a POSITIVE
  "more like this" boost, not "not interested"; re-implemented Not-interested as
  `POST /feed/hide` and documented the missing-endpoint finding (FR-3, §4.3, §5,
  §13, §14 AC-2).
- Corrected auth description to Bearer + CSRF + cookies (was cookie-only) and
  noted optional `X-SESSION-ID` / `user_sub` / `X-IMPERSONATION-TOKEN` (§4.2, §5,
  §8).
- Corrected response shapes to the frontend-authoritative DTOs and noted the
  empty OpenAPI 200 schemas (§4.2, §5).
- Tightened the 422 error envelope to the real `{ detail: [{loc,msg,type}] }`
  shape (§5).

### Open assumptions

- **`/feed/hide` 404 / idempotency** — assumed 404 = success-equivalent and hide
  is safe to re-send; not documented (OpenAPI lists only 200/422). Why: source
  documents do not specify hide idempotency or a 404 case.
- **Server-side feed filtering of hidden posts** — assumed the feed read excludes
  hidden ids; the feed-read query is not in the provided sources. Why: only the
  write-side hide/unhide ops and their DynamoDB key pattern are documented.
- **A dedicated negative-preference ("not interested") endpoint** — assumed none
  exists and hide is the correct substitute; confirmed absent in the index but a
  future endpoint may be planned. Why: cannot prove a negative from a snapshot.
- **Android framework behaviors** — `PagingData.filter` + `combine` over
  `cachedIn` preserving scroll position is assumed per framework docs, not
  verified against this codebase (no Android sources provided). (framework ref)

## 17. Test Plan

Test target legend: JVM = JVM unit/Robolectric (local, no device); EMU =
headless emulator AVD `test35` (x86_64, API 35); DEV = physical Samsung Galaxy
A15 5G (SM-A156U, API 34, arm64-v8a) via adb. None of this ticket's behavior is
hardware-dependent (no camera/biometrics/WebRTC/FCM/Telecom), so the emulator is
the default for instrumented/UI cases; one ABI/API-parity smoke case is pinned to
the physical device.

- **TC-AND-175-01** — Type: contract/MockWebServer (JVM). Target:
  `PostActionsRepositoryImpl.hide`. Preconditions: MockWebServer enqueues
  `200 {"ok":true,"post_id":"p1","hidden":true}`. Steps: call `hide("p1")`;
  capture `RecordedRequest`. Expected: request is `POST /feed/hide`, body equals
  `{"post_id":"p1"}`, `Content-Type: application/json`; `suppressed` emits a set
  containing `p1`; row `pending` flips `true`→`false`; returns
  `ApiResult.Success`. Traces: AC-1.
- **TC-AND-175-02** — Type: contract/MockWebServer (JVM). Target:
  `PostActionsRepositoryImpl.notInterested`. Preconditions: MockWebServer 200 as
  above. Steps: call `notInterested("p2")`; capture `RecordedRequest`. Expected:
  request is `POST /feed/hide` (NOT `/feed/interesting`), body `{"post_id":"p2"}`;
  Room row stored with `kind = NOT_INTERESTED`; `suppressed` contains `p2`.
  Traces: AC-2.
- **TC-AND-175-03** — Type: unit (JVM). Target: feed `items` flow filtering.
  Preconditions: a `PagingData` of posts `[p1,p2,p3]`; `suppressed = {p2}`.
  Steps: collect the combined flow via `AsyncPagingDataDiffer`. Expected:
  rendered list is `[p1,p3]`; `p2` absent; collection completes without a network
  call. Traces: AC-1, AC-2.
- **TC-AND-175-04** — Type: contract/MockWebServer (JVM). Target:
  rollback on failure. Preconditions: MockWebServer enqueues `500` (then a
  network-drop variant). Steps: call `hide("p1")`. Expected: `suppressed`
  transiently contains then drops `p1` (row deleted), returns `ApiResult.Error`
  with the mapped `detail` message; no retry is auto-issued (non-idempotent
  POST). Traces: AC-5.
- **TC-AND-175-05** — Type: contract/MockWebServer (JVM). Target: 401 refresh +
  retry. Preconditions: enqueue `401`, then `200` for `/ui/session/refresh`, then
  `200` for the replayed `/feed/hide`. Steps: call `hide("p1")` while
  authenticated. Expected: exactly one `POST /ui/session/refresh` then exactly one
  retry of `/feed/hide`; final `ApiResult.Success`; on a second 401 the session
  is logged out. Traces: AC-6.
- **TC-AND-175-06** — Type: contract/MockWebServer (JVM). Target: 404 handling.
  Preconditions: enqueue `404 {"detail":"not found"}`. Steps: call `hide("p1")`.
  Expected: suppression is KEPT (row remains, `pending` cleared); treated as
  success-equivalent; `p1` stays filtered. Traces: AC-6.
- **TC-AND-175-07** — Type: contract/MockWebServer (JVM). Target: 422 validation
  error mapping. Preconditions: enqueue
  `422 {"detail":[{"loc":["body","post_id"],"msg":"field required","type":"missing"}]}`.
  Steps: call `hide("")`. Expected: `ApiErrorMapper` produces the single string
  `"field required"`; `ApiResult.Error`; rollback performed. Traces: AC-5.
- **TC-AND-175-08** — Type: unit (JVM). Target: undo path
  (`unhide` / `interested`). Preconditions: row `{p1, HIDDEN}` present;
  MockWebServer 200 for `/feed/unhide`. Steps: call `unhide("p1")`. Expected:
  request is `POST /feed/unhide` body `{"post_id":"p1"}`; suppression row deleted
  (optimistic restore); on a forced failure the row is re-inserted. Traces: AC-4.
- **TC-AND-175-09** — Type: integration / Room (JVM Robolectric). Target:
  `PostSuppressionDao` durability + purge. Preconditions: in-memory→reopened Room
  DB. Steps: upsert two rows (one old, one recent), close/reopen DAO, run
  `purgeOlderThan(cutoff)`. Expected: rows survive reopen (process-death proxy);
  `purgeOlderThan` removes only the stale row; `observeAll` re-emits accordingly.
  Traces: AC-3.
- **TC-AND-175-10** — Type: Compose-UI (EMU). Target: hide-from-overflow +
  Snackbar. Preconditions: feed rendered with item test tag `post_p1`;
  MockWebServer 200. Steps: open the overflow menu, tap "Hide this post".
  Expected: `post_p1` is removed; a Snackbar "Post hidden" with an "Undo" action
  is shown. Traces: AC-1, AC-4.
- **TC-AND-175-11** — Type: Compose-UI (EMU). Target: undo restores at prior
  index. Preconditions: continues from TC-10. Steps: tap "Undo" before the
  Snackbar times out. Expected: `post_p1` reappears at its original position; a
  `POST /feed/unhide` is issued. Traces: AC-4.
- **TC-AND-175-12** — Type: Compose-UI (EMU). Target: failure rollback + retry.
  Preconditions: MockWebServer returns `500` for `/feed/hide`. Steps: hide
  `post_p1`; observe rollback; tap the "…retry" Snackbar action (then enqueue
  200). Expected: item re-appears after the 500, a retry Snackbar shows, and the
  retry tap re-issues `/feed/hide` and removes the item on success. Traces: AC-5.
- **TC-AND-175-13** — Type: instrumented/e2e (EMU). Target: backlog acceptance —
  hide persists across refresh/pagination. Preconditions: feed loaded; hide
  `post_p1` succeeds. Steps: pull-to-refresh and page forward (feed responses
  still include `p1` to test client-side suppression). Expected: `post_p1` never
  re-renders while its suppression row exists. Traces: AC-1, AC-2, AC-3.
- **TC-AND-175-14** — Type: instrumented (Compose-UI) accessibility (EMU).
  Target: a11y of menu items + Snackbar + announcement. Steps: enable TalkBack
  semantics assertions; open overflow. Expected: "Hide this post" and
  "Not interested" expose visible text / `contentDescription`; touch targets
  ≥ 48dp; on removal a polite live-region announcement ("Post hidden") is emitted;
  the "Undo"/"Retry" action is focusable. Traces: AC-1, AC-4.
- **TC-AND-175-15** — Type: instrumented/e2e (DEV — physical Galaxy A15, API 34
  arm64-v8a). Target: ABI/API-parity smoke of the full hide→undo→refresh flow.
  Why physical: validate arm64-v8a + API-34 behavior versus the x86_64/API-35
  emulator (Room/Paging/Compose parity); no emulator-only quirk masks a real
  failure. Steps: run TC-13's flow on-device against MockWebServer (or the dev
  host). Expected: identical outcome to EMU. Traces: AC-1, AC-3, AC-7.
- **TC-AND-175-16** — Type: integration (JVM, regression). Target: no
  like/share/pagination regression. Preconditions: existing AND-173/AND-176/
  AND-098 suites present. Steps: run the existing feed test suites with this
  ticket's changes applied. Expected: all pass; suppression `combine` does not
  break paging or scroll restoration. Traces: AC-7.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (Hide leaves feed, calls `/feed/hide`) | TC-01, TC-03, TC-10, TC-13, TC-14, TC-15 |
| AC-2 (Not interested = `/feed/hide`, persisted) | TC-02, TC-03, TC-13 |
| AC-3 (survives process death, Room-backed) | TC-09, TC-13, TC-15 |
| AC-4 (Snackbar + Undo restores + inverse call) | TC-08, TC-10, TC-11, TC-14 |
| AC-5 (failure rollback + retry) | TC-04, TC-07, TC-12 |
| AC-6 (401 single refresh+retry; 404 = success) | TC-05, TC-06 |
| AC-7 (no regression) | TC-15, TC-16 |
