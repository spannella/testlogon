---
id: AND-173
title: Like / unlike
milestone: M4
epic: E24
priority: P0
size: M
status: draft
depends_on: [AND-099]
blocks: []
---

# AND-173 — Like / unlike

## 1. Overview & Goal

Implement a like/unlike interaction on post items in the TestLogon native
Android app. Tapping the like control toggles the authenticated user's like
state on a post and adjusts the visible like count. The interaction MUST feel
instantaneous: the UI applies an **optimistic** state change on tap, fires the
mutating request to the FastAPI backend, and then **reconciles** the local
state against the server's authoritative response (or rolls back on failure).

The deliverable is the full vertical slice for a single post's like toggle:
the repository mutation, the in-memory + Room reconciliation, the ViewModel
intent handling with optimistic update and rollback, and the Compose like
button wired into the existing `PostItem` composable from AND-099. The like
state MUST survive recomposition, scroll recycling in the Paging 3 feed, and
process death (cached in Room), and MUST reconcile to the server truth so a
double-tap, a stale cache, or a lost network response cannot leave the count
permanently wrong.

This ticket owns only the like/unlike behavior. It does not own the post
rendering surface (AND-099) nor the feed list/pager that hosts the items.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, Paging 3. minSdk 24,
  compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Modules:** `feature-feed` (ViewModel + Compose), `core-data`
  (repository + Room), `core-network` (Retrofit service, `ApiResult`),
  `core-model` (domain types), `core-ui` (the like button visuals),
  `core-testing` (fakes, turbine harness). Layering: `app -> feature-* ->
  core-*`.
- **Package base:** `com.testlogon.android` everywhere.
- **Dependency AND-099 — Post item composable:** provides
  `com.testlogon.android.core.ui.post.PostItem(...)` and the domain `Post`
  model. This ticket adds a like affordance and `onLikeToggle` callback to that
  surface; the visual slot must be added to `PostItem` without regressing its
  existing render contract.
- **Auth:** cookie-based session with `ui_csrf` cookie echoed as the
  `X-CSRF-Token` header; persistent cookie jar; on 401 the network layer calls
  `POST /ui/session/refresh` once then retries. Like is a **mutating** request,
  so it is NOT eligible for the idempotent-GET backoff-retry policy.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable; ~20s timeouts). OpenAPI at `/openapi.json`.
  Web reference for the like endpoints: `frontend/src/api/endpoints/posts.ts`
  and shared types in `frontend/src/api/types.ts`. The exact endpoint paths
  below MUST be validated against `/openapi.json` before implementation
  (see Open Questions).

## 3. Functional Requirements

FR-1. Each rendered post exposes a like control showing (a) liked/unliked
state and (b) a like count.

FR-2. Tapping the control while **unliked** optimistically sets liked = true
and increments the count by 1; tapping while **liked** sets liked = false and
decrements by 1. The count MUST never display below 0.

FR-3. The optimistic change is visible within one frame of the tap (no spinner
on the button itself; the button is never disabled during the request).

FR-4. After the mutation completes, the repository reconciles local state to
the server-returned `liked` and `like_count`. The server count, not the local
arithmetic, is the source of truth on success.

FR-5. On mutation failure (network, timeout, non-2xx after a single refresh
retry), the optimistic change is rolled back to the pre-tap state and a
transient, non-blocking error is surfaced (snackbar).

FR-6. Rapid repeated taps on the same post are **coalesced**: only the latest
intended terminal state is sent. An in-flight request for a post is cancelled
and superseded by a newer tap on that post (last-write-wins per post id).

FR-7. The reconciled like state is persisted to the Room post cache so it
survives scroll recycling and process death and is consistent across every
place the post appears (feed, detail).

FR-8. While offline, a tap still applies optimistically, fails on send, rolls
back, and shows an offline message; no write queue / deferred sync is in scope
(noted as out of scope, owned by future work).

## 4. Technical Design

### 4.1 Domain model (core-model)

```kotlin
data class LikeState(
    val liked: Boolean,
    val likeCount: Long,
)
```

`Post` (from AND-099) already carries `id: String`, `liked: Boolean`, and
`likeCount: Long`. This ticket does not add fields to `Post`; it mutates those
two.

### 4.2 Network service (core-network)

```kotlin
interface PostApiService {
    @POST("ui/posts/{id}/like")
    suspend fun like(@Path("id") postId: String): Response<LikeResponseDto>

    @DELETE("ui/posts/{id}/like")
    suspend fun unlike(@Path("id") postId: String): Response<LikeResponseDto>
}

@JsonClass(generateAdapter = true)
data class LikeResponseDto(
    @Json(name = "liked") val liked: Boolean,
    @Json(name = "like_count") val likeCount: Long,
)
```

The `X-CSRF-Token` header and cookie jar are applied by the shared OkHttp
interceptors (auth ticket), not here. Calls return raw `Response<…>` so the
repository can branch on 401/4xx/5xx and map to `ApiResult<LikeState>`.

### 4.3 Repository (core-data)

```kotlin
interface PostInteractionRepository {
    /** Applies the desired terminal liked state, reconciles, persists. */
    suspend fun setLiked(postId: String, liked: Boolean): ApiResult<LikeState>
}

@Singleton
class PostInteractionRepositoryImpl @Inject constructor(
    private val api: PostApiService,
    private val dao: PostDao,
    @IoDispatcher private val io: CoroutineDispatcher,
) : PostInteractionRepository {

    override suspend fun setLiked(postId: String, liked: Boolean): ApiResult<LikeState> =
        withContext(io) {
            val resp = if (liked) api.like(postId) else api.unlike(postId)
            when {
                resp.isSuccessful && resp.body() != null -> {
                    val body = resp.body()!!
                    val state = LikeState(body.liked, body.likeCount)
                    dao.updateLike(postId, state.liked, state.likeCount) // reconcile cache
                    ApiResult.Success(state)
                }
                else -> ApiResult.Error(resp.toApiError())
            }
        }
}
```

`updateLike` is an `@Query("UPDATE posts SET liked = :liked,
like_count = :count WHERE id = :id")` partial update so we never clobber the
rest of the cached row.

### 4.4 ViewModel (feature-feed)

The feed `UiState` is produced from a Paging 3 `Flow<PagingData<PostUi>>`. The
optimistic overlay is held outside the pager (the pager is immutable) as a
per-post override map, applied via `map { it.applyOverrides(overrides.value) }`.

```kotlin
@HiltViewModel
class FeedViewModel @Inject constructor(
    private val interactions: PostInteractionRepository,
    pager: FeedPager,
) : ViewModel() {

    private val overrides = MutableStateFlow<Map<String, LikeState>>(emptyMap())
    private val likeJobs = mutableMapOf<String, Job>()   // confined to Main

    val posts: Flow<PagingData<PostUi>> =
        pager.flow
            .cachedIn(viewModelScope)
            .combine(overrides) { data, ov -> data.map { it.applyLikeOverride(ov[it.id]) } }

    fun onLikeToggle(post: PostUi) {
        val target = !post.liked
        val before = LikeState(post.liked, post.likeCount)
        val optimistic = LikeState(
            liked = target,
            likeCount = (post.likeCount + if (target) 1 else -1).coerceAtLeast(0),
        )
        overrides.update { it + (post.id to optimistic) }   // FR-2, FR-3

        likeJobs.remove(post.id)?.cancel()                  // FR-6 supersede
        likeJobs[post.id] = viewModelScope.launch {
            when (val r = interactions.setLiked(post.id, target)) {
                is ApiResult.Success ->                      // FR-4 reconcile
                    overrides.update { it + (post.id to r.value) }
                is ApiResult.Error -> {                      // FR-5 rollback
                    overrides.update { it + (post.id to before) }
                    _effects.emit(FeedEffect.ShowError(r.error.userMessage))
                }
            }
        }.also { it.invokeOnCompletion { likeJobs.remove(post.id) } }
    }

    private val _effects = MutableSharedFlow<FeedEffect>(extraBufferCapacity = 1)
    val effects: SharedFlow<FeedEffect> = _effects
}
```

The override is keyed by post id, so an entry stays applied even after the row
recycles (FR-7 at the UI layer; Room persists across process death). On the
success path the override holds the server-authoritative `LikeState`; the Room
write performed in the repository makes the same value durable, so on the next
cold pager load the override map can start empty and still show the right value.

### 4.5 UI (core-ui + feature-feed)

`PostItem` (AND-099) gains:

```kotlin
@Composable
fun LikeButton(
    liked: Boolean,
    likeCount: Long,
    onToggle: () -> Unit,
    modifier: Modifier = Modifier,
)
```

Icon is `Icons.Filled.Favorite` when liked (tinted `colorScheme.primary`),
`Icons.Outlined.FavoriteBorder` otherwise. The count is formatted via a
`CompactNumberFormat` (1.2K). State change animates with
`animateColorAsState` + a small scale `bounce`; no animation longer than 200ms.
The button itself is never in a loading/disabled state.

## 5. API Contract

Two mutating endpoints (paths to be confirmed against `/openapi.json`):

**Like**
```
POST /ui/posts/{id}/like
Headers: X-CSRF-Token: <ui_csrf>; Cookie: <session>
Body: (none)
200 OK
{ "liked": true, "like_count": 42 }
```

**Unlike**
```
DELETE /ui/posts/{id}/like
Headers: X-CSRF-Token: <ui_csrf>; Cookie: <session>
200 OK
{ "liked": false, "like_count": 41 }
```

Notable responses:
- `401 Unauthorized` — handled by the shared interceptor: one
  `POST /ui/session/refresh`, then a single retry of the original request. A
  second 401 surfaces as an auth error and rollback.
- `404 Not Found` — post deleted/unavailable; rollback + error.
- `409 Conflict` (idempotency) — if the server reports the post is already in
  the requested state, the body is still authoritative `LikeState`; treat as
  Success and reconcile.
- FastAPI `detail` error shape (`string | [{msg}] | {code,...}`) is mapped by
  the shared `Response.toApiError()` / `detail` mapper to a user message.

If `/openapi.json` reveals a single toggle endpoint (e.g.
`POST /ui/posts/{id}/like/toggle`) or a `liked` boolean body instead of
verb-by-method, the service collapses to one method; the repository contract
(`setLiked(id, liked)`) is unaffected.

## 6. Data & State Management

- **Room (`PostEntity`):** existing columns `liked INTEGER`,
  `like_count INTEGER` are the durable cache. `PostDao.updateLike(id, liked,
  count)` is the only writer for these from this ticket. Reconciliation writes
  the server values; rollback does NOT write Room (it only reverts the
  in-memory override), so the cache never holds an unconfirmed optimistic value.
- **Paging 3:** the pager flow is immutable and `cachedIn(viewModelScope)`.
  Optimistic state lives in the `overrides: MutableStateFlow<Map<String,
  LikeState>>` and is applied via `PagingData.map`. This avoids invalidating
  the pager on every tap.
- **Source-of-truth order:** server response > Room cache > optimistic
  override. The override is a short-lived UI patch reconciled within one
  request round-trip.
- **DataStore:** not used by this ticket.
- **Consistency across screens:** because reconciliation persists to Room and
  the detail screen reads the same `PostDao` row, a like performed in the feed
  is reflected when the post is opened in detail (after its next read).

## 7. Error Handling & Resilience

- Mutating requests are **not** auto-retried with backoff (idempotent-GET-only
  policy). The only automatic retry is the single auth refresh-then-retry in
  the shared interceptor.
- Timeouts: ~20s OkHttp call timeout (dev host is slow/unreliable). A timeout
  is an `ApiResult.Error` -> rollback + snackbar "Couldn't update like. Try
  again."
- Offline (no network): request fails fast -> rollback + "You're offline."
  No deferred write queue (out of scope; see Risks).
- Coalescing/superseding (FR-6): per-post `Job` is cancelled when a newer tap
  arrives; `CancellationException` is swallowed and never triggers rollback or
  a snackbar. The newest tap's request defines the terminal intent.
- Idempotency: because the API is verb-by-method (or returns authoritative
  state), a duplicate like/unlike is safe; the server count in the response
  corrects any local drift.

## 8. Security & Privacy

- All like/unlike calls ride the cookie session and MUST send the
  `X-CSRF-Token` header (mutating request); requests without it are rejected by
  the backend. CSRF wiring is owned by the auth/network ticket; this ticket
  only asserts the requests flow through the shared authenticated OkHttp client.
- No PII is added to logs. A post id is not treated as sensitive but is not
  logged at INFO in release builds (debug only).
- Dev backend is plaintext HTTP; the network security config already permits
  the dev host cleartext. No new cleartext exception is introduced here.
- No new permissions, no new stored credentials.

## 9. Accessibility & i18n

- `LikeButton` exposes a `Modifier.semantics` with
  `role = Role.Button`, a `stateDescription` of "Liked"/"Not liked", and a
  `contentDescription` combining action + count, e.g. "Like, 42 likes" /
  "Unlike, 42 likes". Toggling announces the new state via the state change.
- Minimum touch target 48x48dp.
- Count uses `LocalConfiguration` locale for compact formatting; all strings
  ("Like", "Unlike", error messages, "%d likes" plural) live in
  `strings.xml` with `<plurals>` for the like count. No hardcoded UI strings.
- Color is not the sole signal of state (filled vs outlined icon + state
  description). Contrast meets WCAG AA against the post background.

## 10. Telemetry & Logging

- Emit an analytics event `post_like_toggled` with params
  `{ post_id, target_liked, source: "feed" }` on tap, and
  `post_like_result` with `{ post_id, success: Boolean, error_code? }` on
  completion. Events route through the existing analytics abstraction (no raw
  vendor SDK calls here).
- Logging via the shared `Logger`: WARN on mutation failure with the mapped
  error code (no body, no PII), DEBUG for optimistic apply / reconcile / rollback
  transitions to aid manual QA. No network bodies logged in release.

## 11. Testing Strategy

Acceptance is "Like persists + reconciles (tested)", so tests are mandatory.

**Unit — repository (`core-data`, JUnit + MockWebServer or fake `PostApiService`):**
- success like returns `LikeState` from body and calls `dao.updateLike` with
  server values (reconcile assertion).
- non-2xx -> `ApiResult.Error`, no `dao.updateLike` call (no cache write).
- 409 with body -> treated as Success, cache reconciled.

**Unit — ViewModel (Turbine over `overrides`/effects, `MainDispatcherRule`):**
- tap when unliked -> override immediately shows liked=true, count+1
  (optimistic, FR-2/FR-3).
- success -> override updated to server `LikeState` (reconcile, FR-4).
- error -> override reverts to pre-tap state + `FeedEffect.ShowError`
  (rollback, FR-5).
- count never goes below 0 (unlike at count 0 boundary).
- rapid double tap -> first job cancelled, only latest terminal request's
  result applied (FR-6); cancellation does not emit error.

**Instrumented / Compose (`createAndroidComposeRule`):**
- `LikeButton` renders correct icon + count for liked/unliked.
- click invokes `onToggle`; `stateDescription` and `contentDescription` assert
  accessibility (FR / section 9).
- semantics-based test: tapping flips state description.

**Persistence (Room in-memory DB test):** `updateLike` mutates only liked +
like_count and survives DAO re-read (process-death proxy, FR-7).

Coverage target for new repository + ViewModel logic >= 85% lines.

## 12. Dependencies & Sequencing

- **Depends on AND-099** (Post item composable): provides `PostItem` and the
  `Post` model that this ticket extends with the like affordance/callback. Must
  be merged first.
- **Implicitly relies on** the cookie/CSRF auth + shared OkHttp client and the
  `ApiResult` / FastAPI `detail` mapper (network foundation tickets). If those
  are not yet merged, the `PostApiService` and interceptor wiring are stubbed
  behind the existing `core-network` client; no new auth code is written here.
- **Relies on** the feed Paging 3 pager (`FeedPager`) and `PostDao` already
  existing in `core-data`. If absent, the override-map mechanism still works
  against whatever list flow the feed exposes.
- **Blocks:** none recorded. Downstream like-driven features (e.g. a "liked
  posts" list, optimistic-sync write queue) are separate tickets and will
  consume `PostInteractionRepository`.

## 13. Risks & Open Questions

- **OQ-1 (endpoint shape):** Confirm against `/openapi.json` whether like is
  `POST`/`DELETE /ui/posts/{id}/like` vs a single toggle endpoint, and the
  exact response field names (`like_count` vs `likes`). The web reference
  `frontend/src/api/endpoints/posts.ts` should be cross-checked. Adapter and
  service paths depend on this; repository contract does not.
- **OQ-2 (server count semantics):** Does the like response return the global
  authoritative count, or can it be eventually-consistent (DynamoDB) and lag a
  prior write? If lagging is possible, reconciliation could briefly show a stale
  count; mitigation is last-write-wins by request completion order.
- **OQ-3 (offline writes):** Out of scope here; a deferred/queued like sync is a
  potential follow-up. Confirm product accepts rollback-on-offline for now.
- **Risk:** unreliable dev host may make manual QA of reconcile flaky; mitigate
  with MockWebServer-driven tests as the authoritative signal.
- **Risk:** Paging override map can grow unbounded over a long session; mitigate
  by pruning entries that match the underlying pager value after reconcile.

## 14. Acceptance Criteria

AC-1. Tapping the like control on an unliked post immediately shows the liked
state and count+1 without a spinner or disabled button (FR-2, FR-3).

AC-2. On a successful response, the displayed `liked`/`like_count` match the
server body, even when they differ from the optimistic arithmetic (FR-4),
verified by test.

AC-3. The reconciled state is written to the Room `posts` row and is read back
unchanged after a simulated process restart (persists), verified by test.

AC-4. On mutation failure (timeout/network/4xx-after-refresh), state rolls back
to pre-tap and a non-blocking snackbar appears (FR-5), verified by test.

AC-5. Rapid repeated taps result in exactly one terminal state matching the
last tap; superseded in-flight requests are cancelled and never roll back or
error (FR-6), verified by test.

AC-6. Like count never renders below 0 (FR-2 boundary), verified by test.

AC-7. `LikeButton` exposes correct `role`, `stateDescription`, and
`contentDescription`; touch target >= 48dp; all strings localized with plurals
(section 9), verified by Compose semantics test.

AC-8. All requests use `com.testlogon.android` package code, the shared
authenticated OkHttp client, and send `X-CSRF-Token`; no new cleartext config.

## 15. Definition of Done

- [ ] `PostInteractionRepository` + `Impl`, `PostApiService` like/unlike,
      `LikeResponseDto`, `LikeState`, and `PostDao.updateLike` implemented in
      the correct modules under `com.testlogon.android`.
- [ ] `FeedViewModel.onLikeToggle` with optimistic override, reconcile,
      rollback, and per-post supersede implemented.
- [ ] `LikeButton` added to `PostItem` (AND-099) with no regression to existing
      render tests; visuals + a11y per sections 5 and 9.
- [ ] Unit, ViewModel (Turbine), Room, and Compose tests for AC-1..AC-7 pass;
      new logic coverage >= 85%.
- [ ] Telemetry events `post_like_toggled` / `post_like_result` emitted.
- [ ] `/openapi.json` verified for endpoint paths/fields (OQ-1); deviations
      reflected in service + adapter before merge.
- [ ] Lint, detekt, ktlint, and `./gradlew :feature-feed:test
      :core-data:test` green on the `android-port` branch.
- [ ] PR reviewed; spec acceptance criteria checked off; no hardcoded strings
      or logged PII.
