---
id: AND-175
title: Hide / not-interested
milestone: M4
epic: E24
priority: P2
size: M
status: draft
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
- Web reference: `frontend/src/api/endpoints/postHide.ts` and
  `frontend/src/api/endpoints/postInteresting.ts` define the request/response
  contracts mirrored here; shared shapes come from `frontend/src/api/types.ts`.
  The canonical contract source at build time is the backend OpenAPI document at
  `/openapi.json` (dev host `http://18.222.237.167:8000`).
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
issues `POST /ui/posts/{postId}/hide`, and on success leaves the post hidden for
the remainder of the session and across refresh/pagination.

FR-3. **Not interested** removes the post from the visible feed immediately,
issues `POST /ui/posts/{postId}/interesting` with `{"interested": false}`, and
records a ranking-suppression preference server-side. The post is also locally
suppressed identically to a hide for the current session.

FR-4. A dismissable Snackbar appears after a successful hide/not-interested:
"Post hidden" / "We'll show fewer posts like this" with an **Undo** action.
Undo reverses the action (see FR-6) when invoked before the Snackbar dismisses
(default 6s).

FR-5. If the backend call fails after the optimistic removal and is
non-recoverable, the post is **re-inserted at its prior index** and a transient
error Snackbar is shown: "Couldn't hide post. Tap to retry." Retry re-issues the
same request.

FR-6. **Undo** issues the inverse call:
`POST /ui/posts/{postId}/unhide` for hide, and
`POST /ui/posts/{postId}/interesting` with `{"interested": true}` for
not-interested. On success the post is restored to the feed at its prior index;
on failure the post remains removed (undo is best-effort) and a Snackbar reports
the failure.

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
interface PostActionsApi {
    @POST("ui/posts/{postId}/hide")
    suspend fun hide(@Path("postId") postId: String): Response<PostActionResponse>

    @POST("ui/posts/{postId}/unhide")
    suspend fun unhide(@Path("postId") postId: String): Response<PostActionResponse>

    @POST("ui/posts/{postId}/interesting")
    suspend fun setInterested(
        @Path("postId") postId: String,
        @Body body: InterestedRequest,
    ): Response<PostActionResponse>
}

@JsonClass(generateAdapter = true)
data class InterestedRequest(val interested: Boolean)

@JsonClass(generateAdapter = true)
data class PostActionResponse(
    @Json(name = "post_id") val postId: String,
    val hidden: Boolean? = null,
    val interested: Boolean? = null,
)
```

These are state-changing `POST`s, therefore **not** eligible for the bounded
backoff retry that `core-network` applies only to idempotent `GET`s. They get a
single attempt plus the standard one-shot 401→`/ui/session/refresh`→retry. The
`X-CSRF-Token` header (echo of the `ui_csrf` cookie) and the persistent cookie
jar are applied by the shared OkHttp interceptors. Per-call timeout follows the
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
2. Call `api.hide(postId)`.
3. On success → mark `pending = false`. Return `ApiResult.Success`.
4. On failure → delete the suppression row (rollback), emit, return
   `ApiResult.Error` carrying the mapped message.

`notInterested` is identical but writes `kind = NOT_INTERESTED` and calls
`setInterested(postId, InterestedRequest(false))`. `unhide`/`interested` delete
the corresponding suppression row first (optimistic restore), then call the
inverse endpoint; on failure they re-insert the suppression row.

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

Base URL (dev): `http://18.222.237.167:8000`. All requests carry session
cookies and `X-CSRF-Token`.

**Hide**
```
POST /ui/posts/{postId}/hide
→ 200 { "post_id": "p_123", "hidden": true }
```

**Unhide (undo)**
```
POST /ui/posts/{postId}/unhide
→ 200 { "post_id": "p_123", "hidden": false }
```

**Not interested / interested (toggle)**
```
POST /ui/posts/{postId}/interesting
Content-Type: application/json
{ "interested": false }
→ 200 { "post_id": "p_123", "interested": false }
```

Error envelope (FastAPI) — mapped by `ApiErrorMapper`:
```
4xx/5xx { "detail": "..." }                         // string
       | [ { "msg": "...", "loc": [...] } ]          // validation array
       | { "code": "...", "detail": "..." }          // structured
```
`404` (post gone) is treated as success-equivalent for hide (the post is already
absent → keep it suppressed, clear pending). `401` triggers the single refresh +
retry handled by `core-network`. The exact endpoint paths and the
`interested` field name MUST be reconciled against `/openapi.json` and the
`postHide.ts`/`postInteresting.ts` reference during implementation; if they
differ, update `PostActionsApi` only — repository/ViewModel are insulated.

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

- No new auth surface. Requests reuse the cookie-based session and the
  `X-CSRF-Token` header from the persistent cookie jar; the state-changing POSTs
  require CSRF, so the header MUST be present (enforced by the shared
  interceptor).
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
  `notInterested` sends `{"interested": false}` (assert request body via
  MockWebServer `RecordedRequest`).
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

- **Endpoint shape unverified locally.** The exact paths (`/hide`, `/unhide`,
  `/interesting`) and field names are inferred from `postHide.ts` /
  `postInteresting.ts` and project conventions; they MUST be confirmed against
  `/openapi.json`. Risk isolated to `PostActionsApi`.
- **Does the backend filter hidden posts from `/ui/feed`?** If not, client-side
  suppression is the only guarantee; the `suppressed` set already covers this, so
  the feature works either way, but the Room table then grows and relies on the
  purge policy. Open question for backend.
- **Not-interested toggle semantics:** is `interested:true` a true inverse, or
  does the backend treat it as a separate positive signal? Assumed inverse for
  undo; confirm.
- **Reconciliation re-send (§7)** could double-apply on a backend that is not
  idempotent for hide. Mitigation: hide is treated as idempotent (404 = ok);
  confirm backend behavior.
- Pagination edge: re-inserting at a captured index after a far scroll may place
  the item off-screen; acceptable (item returns to its logical position).

## 14. Acceptance Criteria

AC-1. Selecting **Hide this post** removes the post from the feed immediately,
calls `POST /ui/posts/{postId}/hide`, and the post does not reappear on pull-to-
refresh or further pagination in the session. (Backlog: "Hidden post leaves
feed.")

AC-2. Selecting **Not interested** removes the post immediately and calls
`POST /ui/posts/{postId}/interesting` with body `{"interested": false}`; the
preference is persisted and the post stays out of the feed. (Backlog:
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
