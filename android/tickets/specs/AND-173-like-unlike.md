---
id: AND-173
title: Like / unlike
milestone: M4
epic: E24
priority: P0
size: M
depends_on: [AND-099]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
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
- **Auth:** [CORRECTED] cookie-based session with `ui_csrf` cookie echoed as the
  `X-CSRF-Token` header AND an `Authorization: Bearer <accessToken>` header from
  the auth store; persistent cookie jar; on 401 the network layer calls
  `POST /ui/session/refresh` once then retries. Verified against
  `src/api/client.ts` (the `api()` wrapper sets `Authorization`, `X-CSRF-Token`
  from the `ui_csrf` cookie, optional `X-IMPERSONATION-TOKEN`, and refreshes the
  session once on 401). Like is a **mutating** request, so it is NOT eligible
  for the idempotent-GET backoff-retry policy. NOTE: the OpenAPI declares these
  endpoints' auth inputs as a `user_sub` query param plus `X-SESSION-ID` /
  `X-IMPERSONATION-TOKEN` headers; the live web client instead relies on the
  Bearer token + session cookie + `X-CSRF-Token`. The Android client follows the
  web client's transport.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable; ~20s timeouts). OpenAPI at `/openapi.json`.
  [CORRECTED] Web reference for the like endpoints is
  `src/api/endpoints/newsfeed.ts` (exports `likePost` / `unlikePost`); there is
  no `posts.ts` endpoints file. The post DTO (`FeedPost`) lives in
  `src/api/types.ts`. The endpoint paths and response shape below have now been
  validated against `/openapi.json` and the web client (see §5 and §16).

## 3. Functional Requirements

FR-1. Each rendered post exposes a like control showing (a) liked/unliked
state and (b) a like count.

FR-2. Tapping the control while **unliked** optimistically sets liked = true
and increments the count by 1; tapping while **liked** sets liked = false and
decrements by 1. The count MUST never display below 0.

FR-3. The optimistic change is visible within one frame of the tap (no spinner
on the button itself; the button is never disabled during the request).

FR-4. [CORRECTED] After the mutation completes, the repository reconciles local
state to the server. NOTE: the post like/unlike endpoints return only
`{ "ok": true }` (empty/untyped 200 body in OpenAPI; `{ ok: boolean }` in the
web client) — they do NOT return `liked`/`like_count`. Therefore reconciliation
is NOT a body read. On success the optimistic `liked` is treated as confirmed
and the durable truth for the count is obtained by re-reading the post (the web
app does `invalidateQueries(["feed"])` after a successful like; the Android
client should refetch the affected post / page or the feed to pick up the
server's authoritative `like_count`). The optimistic arithmetic is only a
short-lived placeholder until that refetch lands.

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
two. NOTE [verified]: on the wire (`FeedPost` in `src/api/types.ts`) the
corresponding fields are `liked_by_me?: boolean` and `like_count: number`, and
the post identifier is `post_id`. The Android domain names (`liked`,
`likeCount`) map from those via the feed DTO adapter owned by AND-099; the
mapping `liked_by_me -> liked` must exist there.

### 4.2 Network service (core-network)

[CORRECTED] The real paths are `POST /posts/{post_id}/like` and
`POST /posts/{post_id}/unlike` (both **POST**, no `/ui` prefix; unlike is its
own POST endpoint, NOT a `DELETE`). The 200 body is untyped/empty in OpenAPI and
`{ ok: boolean }` in the web client — there is no `liked` / `like_count` field
to deserialize.

```kotlin
interface PostApiService {
    @POST("posts/{postId}/like")
    suspend fun like(@Path("postId") postId: String): Response<LikeAckDto>

    @POST("posts/{postId}/unlike")
    suspend fun unlike(@Path("postId") postId: String): Response<LikeAckDto>
}

// 200 body is just an acknowledgement; treat any 2xx as success.
@JsonClass(generateAdapter = true)
data class LikeAckDto(
    @Json(name = "ok") val ok: Boolean? = null,
)
```

The `Authorization` Bearer header, `X-CSRF-Token` header and cookie jar are
applied by the shared OkHttp interceptors (auth ticket), not here. Calls return
raw `Response<…>` so the repository can branch on 2xx vs 4xx/5xx and map to
`ApiResult<LikeState>` — where the success `LikeState` is built from the
optimistic `liked` plus the count carried forward (then corrected by a refetch),
NOT from the response body.

### 4.3 Repository (core-data)

```kotlin
interface PostInteractionRepository {
    /** Applies the desired terminal liked state, persists, returns confirmed state.
     *  [CORRECTED] takes desiredCount because the API returns no count. */
    suspend fun setLiked(postId: String, liked: Boolean, desiredCount: Long): ApiResult<LikeState>
}

@Singleton
class PostInteractionRepositoryImpl @Inject constructor(
    private val api: PostApiService,
    private val dao: PostDao,
    @IoDispatcher private val io: CoroutineDispatcher,
) : PostInteractionRepository {

    // [CORRECTED] The response has no liked/like_count. On 2xx, persist the
    // confirmed `liked` and the desired count (caller passes the optimistic
    // count to carry forward), then trigger a refetch elsewhere to pick up the
    // server-authoritative count. We do NOT read the body for state.
    override suspend fun setLiked(
        postId: String,
        liked: Boolean,
        desiredCount: Long,
    ): ApiResult<LikeState> =
        withContext(io) {
            val resp = if (liked) api.like(postId) else api.unlike(postId)
            when {
                resp.isSuccessful -> {
                    val state = LikeState(liked = liked, likeCount = desiredCount)
                    dao.updateLike(postId, state.liked, state.likeCount) // confirm cache
                    ApiResult.Success(state)
                }
                else -> ApiResult.Error(resp.toApiError())
            }
        }
}
```

`updateLike` is an `@Query("UPDATE posts SET liked = :liked,
like_count = :count WHERE id = :id")` partial update so we never clobber the
rest of the cached row. The interface signature in §4.3 becomes
`suspend fun setLiked(postId: String, liked: Boolean, desiredCount: Long): ApiResult<LikeState>`.
Because the count is not server-confirmed by this call, the canonical count is
refreshed by a subsequent feed/post refetch (see FR-4).

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
            when (val r = interactions.setLiked(post.id, target, optimistic.likeCount)) {
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

[CORRECTED against `/openapi.json` and `src/api/endpoints/newsfeed.ts`] Two
mutating endpoints, both **POST**, no `/ui` prefix, path param `post_id`:

**Like**
```
POST /posts/{post_id}/like
Headers: Authorization: Bearer <accessToken>; X-CSRF-Token: <ui_csrf>; Cookie: <session>
Body: (none)
200 OK
{ "ok": true }            # untyped {} in OpenAPI; {ok:boolean} in web client.
                          # NO liked / like_count in the body.
```

**Unlike**
```
POST /posts/{post_id}/unlike
Headers: Authorization: Bearer <accessToken>; X-CSRF-Token: <ui_csrf>; Cookie: <session>
Body: (none)
200 OK
{ "ok": true }
```

Notable responses:
- `200 OK` — success acknowledgement only; the new count must be obtained by a
  refetch, not from this body (see FR-4).
- `422 Unprocessable Entity` — the ONLY error response declared in OpenAPI for
  these two endpoints. Body is `HTTPValidationError`:
  `{ "detail": [ { "loc": [...], "msg": "...", "type": "..." } ] }` (verified:
  `components.schemas.HTTPValidationError` -> `ValidationError`).
- `401 Unauthorized` — [UNVERIFIED for these endpoints: not declared in OpenAPI]
  handled by the shared `api()` wrapper as a cross-cutting concern: one
  `POST /ui/session/refresh` (verified in `src/api/client.ts`), then a single
  retry. A second 401 logs out / surfaces an auth error and rollback.
- `404` / `409` — [CORRECTED] NOT declared in OpenAPI for like/unlike. The prior
  spec's `404 Not Found` and `409 Conflict (idempotency, authoritative body)`
  claims are removed: there is no 409 contract and no authoritative-state body to
  reconcile from. Any unexpected non-2xx is mapped to `ApiResult.Error` ->
  rollback, generically. Idempotency is still safe because like/unlike are
  separate verbs and the count is corrected by the refetch.
- FastAPI `detail` error shape (`string | [{msg}] | {code,...}`) is mapped by
  the shared `detail` normalizer (`normalizeErrorDetail` in `src/api/client.ts`,
  mirrored by Android `Response.toApiError()`) to a user message.

There is a separate **video** like endpoint, `POST /ui/videos/{video_id}/like`,
that DOES return a typed `LikeToggleOut` `{ liked, like_count }` body. That is a
different resource and out of scope here; do not confuse its contract with the
post endpoints. There is no `/ui/posts/{id}/like/toggle` endpoint.

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
- **Source-of-truth order:** [CORRECTED] refetched feed/post (server truth) >
  Room cache > optimistic override. The like/unlike *response itself* is only an
  ack and is NOT a source of truth for the count (it carries no count). The
  override is a short-lived UI patch; the authoritative count arrives on the
  next feed/post refetch.
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
- Idempotency: [CORRECTED] because like and unlike are separate POST verbs, a
  duplicate is safe server-side; local drift is corrected by the follow-up
  feed/post refetch (NOT by a count in the like response, which has none).

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
- [CORRECTED] success like (2xx ack `{ "ok": true }`, no count in body) returns
  `LikeState(liked, desiredCount)` and calls `dao.updateLike` with the confirmed
  liked + desired count.
- non-2xx (incl. 422 `HTTPValidationError`) -> `ApiResult.Error`, no
  `dao.updateLike` call (no cache write).
- [CORRECTED] removed the fabricated "409 with authoritative body" case — the
  endpoints declare no 409 and no count body. Replaced by: 422 validation error
  maps through the `detail` normalizer to a user message.

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

- **OQ-1 (endpoint shape):** [RESOLVED] Verified against `/openapi.json` and
  `src/api/endpoints/newsfeed.ts`: like is `POST /posts/{post_id}/like`, unlike
  is `POST /posts/{post_id}/unlike` (both POST, no `/ui`, no DELETE, no toggle
  endpoint). The 200 body is an untyped ack (`{ ok: boolean }`) with NO
  `liked`/`like_count`. Wire DTO fields are `liked_by_me` and `like_count`
  (`FeedPost`). Adapter/service paths updated accordingly in §4/§5.
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

AC-2. [CORRECTED] On a successful like/unlike, the confirmed `liked` is retained
and the displayed `like_count` reconciles to the server's authoritative count
obtained via the follow-up feed/post refetch (the like response itself carries
no count) — even when that count differs from the optimistic arithmetic (FR-4),
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

- [ ] `PostInteractionRepository` + `Impl`, `PostApiService` like/unlike
      (`POST /posts/{post_id}/like` and `.../unlike`), `LikeAckDto`,
      `LikeState`, and `PostDao.updateLike` implemented in the correct modules
      under `com.testlogon.android`.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Like endpoint is `POST /posts/{post_id}/like`** — VERDICT: Corrected (spec
   said `POST /ui/posts/{id}/like`). SOURCE: OpenAPI `POST /posts/{post_id}/like`
   (op `like_post_posts__post_id__like_post`); `src/api/endpoints/newsfeed.ts:
   likePost` -> `api.post(`/posts/${postId}/like`)`.
2. **Unlike endpoint is `POST /posts/{post_id}/unlike`** — VERDICT: Corrected
   (spec said `DELETE /ui/posts/{id}/like`). SOURCE: OpenAPI
   `POST /posts/{post_id}/unlike` (op `unlike_post_posts__post_id__unlike_post`);
   `src/api/endpoints/newsfeed.ts: unlikePost`.
3. **Like/unlike 200 body carries `{ liked, like_count }`** — VERDICT: Corrected
   (false). The 200 body is untyped `{}` in OpenAPI and `{ ok: boolean }` in the
   web client; there is no count in the response. SOURCE: OpenAPI
   `POST /posts/{post_id}/like` responses.200.content.application/json.schema = {}
   (openapi.pretty.json ~line 127997); `src/api/endpoints/newsfeed.ts: likePost`
   typed as `api.post<{ ok: boolean }>`.
4. **`LikeToggleOut { liked, like_count }` exists** — VERDICT: Verified but for a
   DIFFERENT resource. It is the response of the **video** like toggle
   `POST /ui/videos/{video_id}/like`, not posts. SOURCE: OpenAPI
   `POST /ui/videos/{video_id}/like | resp=200:LikeToggleOut`;
   `components.schemas.LikeToggleOut`.
5. **Reconcile = read server `liked`/`like_count` from the like response** —
   VERDICT: Corrected. Posts return no count; the web app reconciles by
   `queryClient.invalidateQueries({ queryKey: ["feed"] })` after a successful
   like. SOURCE: `src/pages/feed/PostCard.tsx: likeMutation.onSuccess`.
6. **Post DTO field names are `liked`/`like_count`** — VERDICT: Corrected/clarified.
   Wire fields are `liked_by_me?: boolean` and `like_count: number`, id is
   `post_id`. SOURCE: `src/api/types.ts: FeedPost` (`like_count`, `liked_by_me`,
   `post_id`).
7. **Web reference file is `frontend/src/api/endpoints/posts.ts`** — VERDICT:
   Corrected. No `posts.ts` exists; like/unlike live in `newsfeed.ts`. SOURCE:
   `src/api/endpoints/newsfeed.ts` (glob for `posts.ts` returns no file).
8. **Auth = cookie session + `ui_csrf` echoed as `X-CSRF-Token`; 401 ->
   `POST /ui/session/refresh` once then retry** — VERDICT: Verified (and extended:
   also sends `Authorization: Bearer <accessToken>` and optional
   `X-IMPERSONATION-TOKEN`). SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")`
   -> `X-CSRF-Token`; `Authorization` from `useAuthStore`; `refreshSession()`
   posts `/ui/session/refresh`; single retry on 401).
9. **Mutating requests must send CSRF; missing CSRF rejected** — VERDICT:
   Verified (client always sets `X-CSRF-Token` when the `ui_csrf` cookie is
   present). SOURCE: `src/api/client.ts` (CSRF block). Server-side rejection
   behavior itself is an UNVERIFIED assumption from the sources at hand.
10. **Like is a non-2xx -> error path; FastAPI `detail` shape mapping** —
    VERDICT: Verified. Only `422 HTTPValidationError` is declared for these
    endpoints; `detail` is `string | [{loc,msg,type}] | {code,...}`. SOURCE:
    OpenAPI `components.schemas.HTTPValidationError` -> `ValidationError`;
    `src/api/client.ts: normalizeErrorDetail`.
11. **404 (post deleted) and 409 (idempotency, authoritative body) responses** —
    VERDICT: Corrected (removed). Neither is declared in OpenAPI for like/unlike;
    409 had no real contract. SOURCE: OpenAPI like/unlike `resp=200:;422:...`
    (no 404/409).
12. **No new auth/cleartext config; dev host cleartext already permitted** —
    VERDICT: Unverified-assumption (network-security-config and the auth ticket
    are not in the provided sources). Plausible and consistent with the dev host
    being plaintext HTTP, but not provable here.
13. **Web Like button disables while pending / is offline-disabled** — VERDICT:
    Verified for the WEB app (`disabled={isOfflinePost || likeMutation.isPending}`),
    but the Android spec intentionally chooses a never-disabled optimistic button
    (FR-3) — a deliberate platform divergence, not an error. SOURCE:
    `src/pages/feed/PostCard.tsx` like `<button ... disabled=...>`.
14. **Android framework choices (Compose, Paging 3 override map, Room partial
    update, Hilt, Turbine)** — VERDICT: Unverified-assumption / design choice
    (framework ref). SOURCE (framework ref): Paging optimistic updates via
    `PagingData.map` — https://developer.android.com/topic/libraries/architecture/paging/v3-transform ;
    Compose semantics/accessibility —
    https://developer.android.com/jetpack/compose/semantics . Not validated
    against backend/web sources because they are client-internal.

### Corrections made
- Endpoint paths: `POST/DELETE /ui/posts/{id}/like` -> `POST /posts/{post_id}/like`
  and `POST /posts/{post_id}/unlike` (no `/ui`, unlike is POST not DELETE).
- Response shape: removed `{ liked, like_count }` for posts; it is an ack
  (`{ ok: boolean }`) with no count. `LikeResponseDto` -> `LikeAckDto`.
- Reconciliation model (FR-4, §4.2, §4.3, §6, §7, AC-2): success no longer reads
  a body count; count is reconciled via feed/post refetch
  (`invalidateQueries(["feed"])` on web). `setLiked` now takes `desiredCount`.
- Removed fabricated `404`/`409` response contracts; only `422` is declared.
- Auth: added the `Authorization: Bearer` header (and noted
  `X-IMPERSONATION-TOKEN`) alongside the cookie + `X-CSRF-Token`.
- Web reference file corrected to `src/api/endpoints/newsfeed.ts` (no `posts.ts`).
- Wire field names noted: `liked_by_me`, `like_count`, `post_id`.
- OQ-1 marked resolved.

### Open assumptions
- Server-side CSRF enforcement and rejection of missing-CSRF mutating requests
  (claim 9): inferred from client behavior; not provable from the provided
  backend artifacts.
- Network-security-config cleartext exception for the dev host and the shared
  OkHttp/auth interceptor wiring (claim 12): owned by other tickets, not present
  in these sources.
- DynamoDB eventual-consistency / count lag (OQ-2): not determinable from
  OpenAPI; remains an open product/backend question — and now more material since
  the count comes only from a refetch.
- The exact refetch mechanism on Android (invalidate pager vs targeted post
  read) is a client design choice; the web app uses query invalidation, which we
  mirror conceptually but cannot 1:1 verify against a Paging 3 implementation.

## 17. Test Plan

IDs `TC-AND-173-NN`. "Traces" links to §14 acceptance criteria (AC-1..AC-8).
Default target is the headless emulator AVD `test35` (API 35) for instrumented/
Compose suites; JVM/Robolectric for unit; physical device `SM-A156U` (API 34,
arm64) only where API-34-vs-35 / arm64-vs-x86 ABI behavior or real-network
flakiness matters.

- **TC-AND-173-01** — Type: contract/MockWebServer. Target: JVM unit (no device),
  `PostApiService` + `PostInteractionRepositoryImpl`. Preconditions: MockWebServer
  enqueues `200 { "ok": true }` for `POST /posts/p1/like`. Steps: call
  `setLiked("p1", liked=true, desiredCount=43)`. Expected: request path is
  `/posts/p1/like` (POST, no `/ui`, no body); returns
  `ApiResult.Success(LikeState(liked=true, likeCount=43))`; `dao.updateLike("p1",
  true, 43)` called exactly once. Traces: AC-2.
- **TC-AND-173-02** — Type: contract/MockWebServer. Target: JVM unit, repository.
  Preconditions: MockWebServer enqueues `200 { "ok": true }` for
  `POST /posts/p1/unlike`. Steps: call `setLiked("p1", liked=false,
  desiredCount=41)`. Expected: path `/posts/p1/unlike` (POST); Success with
  `liked=false`; `dao.updateLike("p1", false, 41)` once. Traces: AC-2.
- **TC-AND-173-03** — Type: contract/MockWebServer. Target: JVM unit, repository.
  Preconditions: enqueue `422` with body
  `{ "detail": [ { "loc": ["path","post_id"], "msg": "value is not a valid",
  "type": "value_error" } ] }`. Steps: call `setLiked("p1", true, 43)`. Expected:
  `ApiResult.Error` whose mapped message derives from `detail[0].msg` via the
  `detail` normalizer; `dao.updateLike` is NEVER called (no cache write).
  Traces: AC-4.
- **TC-AND-173-04** — Type: unit (Turbine + MainDispatcherRule). Target: JVM,
  `FeedViewModel.onLikeToggle`. Preconditions: post p1 `liked=false,
  likeCount=10`; fake repo suspends. Steps: call `onLikeToggle(p1)`; collect
  `overrides`. Expected: within one emission the override for p1 is
  `LikeState(liked=true, likeCount=11)` BEFORE the repo completes; button never
  disabled. Traces: AC-1.
- **TC-AND-173-05** — Type: unit (Turbine). Target: JVM, ViewModel.
  Preconditions: post p1 `liked=false, likeCount=10`; fake repo returns
  `Success(LikeState(true, 99))` (server count differs from optimistic 11) and
  the feed refetch surfaces count 99. Steps: toggle, await completion. Expected:
  final override/UI shows `liked=true, likeCount=99` (server truth from refetch,
  not 11). Traces: AC-2.
- **TC-AND-173-06** — Type: unit (Turbine). Target: JVM, ViewModel.
  Preconditions: post p1 `liked=false, likeCount=10`; fake repo returns
  `ApiResult.Error`. Steps: toggle, await completion; collect `overrides` and
  `effects`. Expected: override reverts to `liked=false, likeCount=10` (pre-tap)
  and exactly one `FeedEffect.ShowError` emitted. Traces: AC-4.
- **TC-AND-173-07** — Type: unit (Turbine). Target: JVM, ViewModel.
  Preconditions: post p1 `liked=false, likeCount=0`. Steps: toggle to like then
  immediately back to unlike (or unlike at 0). Expected: displayed count never <
  0 (coerced at 0). Traces: AC-6.
- **TC-AND-173-08** — Type: unit (Turbine). Target: JVM, ViewModel
  coalescing/supersede. Preconditions: post p1; repo call is slow/cancellable.
  Steps: tap p1 three times rapidly (like, unlike, like). Expected: first two
  jobs cancelled (CancellationException), only the latest terminal request runs;
  no rollback and NO `ShowError` from the cancelled jobs; terminal state =
  `liked=true`. Traces: AC-5.
- **TC-AND-173-09** — Type: integration (Room in-memory DB). Target: Robolectric
  or instrumented, `PostDao.updateLike`. Preconditions: insert full `PostEntity`
  p1. Steps: call `updateLike("p1", true, 7)`, then re-open the DAO / re-query
  (process-death proxy). Expected: only `liked` and `like_count` changed (all
  other columns intact); re-read returns `liked=true, like_count=7`. Traces: AC-3.
- **TC-AND-173-10** — Type: Compose-UI (createAndroidComposeRule). Target:
  emulator `test35`, `LikeButton`. Preconditions: render with `liked=false,
  likeCount=42`. Steps: assert icon = `FavoriteBorder`; perform click. Expected:
  `onToggle` invoked once; recompose with `liked=true` shows `Favorite` filled +
  primary tint; count formatted (e.g. "42"/"1.2K"). Traces: AC-1.
- **TC-AND-173-11** — Type: Compose-UI / accessibility (semantics). Target:
  emulator `test35`, `LikeButton`. Preconditions: render liked/unliked variants.
  Steps: assert `Role.Button`, `stateDescription` "Liked"/"Not liked",
  `contentDescription` includes action + localized plural count ("Like, 42
  likes"); assert touch target >= 48x48dp; verify strings come from `strings.xml`
  plurals (no hardcoded). Expected: all semantics present and correct. Traces:
  AC-7.
- **TC-AND-173-12** — Type: contract/MockWebServer (offline/flaky-host). Target:
  JVM unit, repository. Preconditions: MockWebServer configured to drop the
  connection / no-response so the call times out, OR simulate `IOException`
  (offline). Steps: call `setLiked("p1", true, 11)`. Expected: `ApiResult.Error`
  (timeout/offline) -> caller rolls back; no `dao.updateLike`; message resolves
  to "You're offline." / "Couldn't update like. Try again." No deferred write
  queue. Traces: AC-4.
- **TC-AND-173-13** — Type: instrumented/e2e (security/transport). Target:
  PHYSICAL DEVICE `SM-A156U` (API 34, arm64) — MUST run on the physical device to
  exercise the real network stack, real cookie jar, and arm64 ABI against the
  live dev host. Preconditions: authenticated session with `ui_csrf` cookie +
  Bearer token present. Steps: tap like on a real post; capture the outgoing
  request (debug proxy or OkHttp logging interceptor in debug build). Expected:
  request is `POST /posts/{post_id}/like` over the shared authenticated client,
  carrying `Authorization: Bearer`, `X-CSRF-Token`, and session cookie; no PII in
  logs; no new cleartext exception. Traces: AC-8.
- **TC-AND-173-14** — Type: manual. Target: PHYSICAL DEVICE `SM-A156U` against
  the unreliable dev host. Preconditions: real feed loaded. Steps: like a post,
  background/kill the app (process death), relaunch, scroll the post back into
  view; also like rapidly while toggling airplane mode. Expected: like state
  persists across process death (Room), reconciles to server count after refetch,
  and offline taps roll back with a snackbar without corrupting the count.
  Traces: AC-3, AC-4, AC-5.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (optimistic, no spinner/disable) | TC-04, TC-10 |
| AC-2 (reconcile to server count via refetch) | TC-01, TC-02, TC-05 |
| AC-3 (persist to Room across restart) | TC-09, TC-14 |
| AC-4 (failure rollback + snackbar) | TC-03, TC-06, TC-12, TC-14 |
| AC-5 (coalesce/supersede, no error on cancel) | TC-08, TC-14 |
| AC-6 (count never < 0) | TC-07 |
| AC-7 (a11y: role/state/content desc, 48dp, plurals) | TC-11 |
| AC-8 (shared auth client, CSRF, no cleartext) | TC-13 |
