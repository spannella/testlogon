---
id: AND-180
title: Interaction ViewModel updates
milestone: M4
epic: E24
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-102]
blocks: [AND-173, AND-174, AND-175, AND-176, AND-177, AND-178]
---

# AND-180 — Interaction ViewModel updates

## 1. Overview & Goal

This ticket adds **optimistic state mutation with deterministic rollback** to the feed/post
interaction surface so that every user-initiated interaction (like/unlike, comment add,
hide/not-interested, bookmark/save, paywall unlock reveal, tip) updates the UI *immediately*,
issues the network mutation in the background, and **reverts the local state cleanly** if the
mutation fails. The dev backend (`http://18.222.237.167:8000`) is plaintext HTTP and unreliable;
without optimistic UI the interaction surface feels broken under the ~20s timeouts described in
the project context. Without rollback, a failed mutation leaves the UI lying about server truth.

The deliverable is a reusable optimistic-mutation primitive plus the wiring of that primitive into
the `FeedViewModel` (extended from AND-102) and the per-post interaction state it exposes. The
feature tickets that own the *individual* network calls and screen affordances (AND-173..AND-178)
**consume** the primitive defined here; this ticket owns the ViewModel-layer state machine, the
reducer that applies/reverts interaction deltas, and the unit tests that prove optimistic apply
and rollback. The single hard acceptance bullet is: **optimistic apply and rollback are unit
tested.**

Out of scope: the screen composables, the share sheet, the payment/entitlement provider, and the
concrete Retrofit endpoints — those live in the consuming feature tickets. This ticket provides the
state contract they call.

## 2. Context & References

- Source backlog: `AND-180 — Interaction ViewModel updates`, Type Feature, Priority **P0**,
  Deps **AND-102**. Scope: "Optimistic state + rollback for all interactions." Acceptance:
  "Optimistic/rollback unit-tested."
- **AND-102** (Feed ViewModel + state): provides `FeedViewModel`, `FeedUiState`, Paging 3 flow,
  refresh, error/offline states. This ticket extends that ViewModel and its state model.
- **AND-099** (Post item composable) / **AND-100** (post detail): render the per-post interaction
  affordances that read this state.
- Consuming feature tickets that supply concrete mutations: **AND-173** like/unlike,
  **AND-174** comments, **AND-175** hide/not-interested, **AND-176** share/bookmark,
  **AND-177** paywall unlock & entitlement, **AND-178** tips.
- **AND-018** typed `ApiResult<T>`; **AND-015** FastAPI `detail` error mapping; **AND-016** retry/
  backoff for idempotent GETs only (interaction mutations are POST/DELETE and are **not** auto-
  retried). **AND-116** SWR cache repository; **AND-117** stale/reconnect hooks.
- Stack: Kotlin 2.0.21, Coroutines/Flow, Hilt (KSP), Compose/Material 3, single-Activity Nav.
  Namespace `com.testlogon.android`. Module: `feature-feed` depending on `core-data`, `core-model`,
  `core-network`, `core-ui`, `core-testing`.
- Web reference: `src/api/endpoints/*.ts` — the post/feed interaction calls actually live in
  `newsfeed.ts` (`likePost`, `unlikePost`, `createComment`, `tipPostDirect`, `unlockPost`,
  `hidePost`), with `postHide.ts` / `postInteresting.ts` wrapping `/feed/hide` and
  `/feed/interesting`, and bookmarks in `bookmarks.ts`. (There is **no** `postLike.ts`; the
  draft's filename was wrong — corrected here.) Transport/auth: `src/api/client.ts`.

## 3. Functional Requirements

FR-1 **Immediate apply.** When a user triggers an interaction, the UI-visible counter/flag updates
within the same frame (synchronously inside the ViewModel before any suspension point).

FR-2 **Single source of truth.** Optimistic deltas are layered over the Paging/repository-backed
post snapshot. The reducer never mutates the cached server entity directly; it stores a per-post
**overlay** keyed by post id and merges overlay over base when projecting `PostUiModel`.

FR-3 **Rollback on failure.** If the mutation returns `ApiResult.Failure` (any error, timeout, or
401-after-refresh), the overlay delta for that interaction is reverted to its pre-apply value and a
transient, dismissible error signal is emitted for the affected post.

FR-4 **Reconciliation on success.** On `ApiResult.Success`, the overlay value is replaced with the
authoritative server value from the response *when the response carries one* (e.g. post tip returns
`tip_total_cents`), not merely "kept." **Caveat (verified §5):** the post like/unlike, comment-add,
and bookmark responses do **not** return a count/state field, so for those interactions there is no
server value to reconcile to — the optimistic delta is kept and cleared on the next page refresh.
The reconcile lambda must tolerate a value-less success.

FR-5 **Coverage — all interactions.** The primitive must support: like toggle (boolean + count),
bookmark/save toggle (boolean), hide/not-interested (post removal flag), comment add (count
increment + pending-comment marker), unlock reveal (locked→unlocked transition), tip (no toggle;
fire-and-confirm with pending→confirmed/failed state).

FR-6 **Idempotent collapse.** Rapid repeated toggles on the same post (e.g. double-tap like) must
collapse: only the *latest* intended state is sent; an in-flight mutation for the same
(postId, interactionType) is cancelled/superseded rather than queued, and the final reconciled
state matches the user's last intent.

FR-7 **Removal interactions.** Hide/not-interested optimistically removes the post from the visible
feed; on failure the post is restored at its original position.

FR-8 **Non-toggle interactions.** Tip (AND-178) and comment-add (AND-174) are not toggles: they
apply a "pending" overlay, then on success transition to confirmed and on failure roll the pending
overlay back (tip count unchanged; pending comment removed).

FR-9 **No silent loss.** Every rollback emits a one-shot user-facing event so the consuming screen
can show a snackbar ("Couldn't like this post").

## 4. Technical Design

New code lives in `feature-feed` under
`com.testlogon.android.feature.feed.interaction`. The core primitive is reusable and stateless
except for the overlay map it manages.

### 4.1 Interaction model

```kotlin
package com.testlogon.android.feature.feed.interaction

enum class InteractionType { LIKE, BOOKMARK, HIDE, COMMENT, UNLOCK, TIP }

/** A reversible delta applied to a single post's UI projection. */
sealed interface InteractionDelta {
    val postId: String
    val type: InteractionType

    data class LikeToggle(override val postId: String, val liked: Boolean) : InteractionDelta {
        override val type get() = InteractionType.LIKE
    }
    data class BookmarkToggle(override val postId: String, val saved: Boolean) : InteractionDelta {
        override val type get() = InteractionType.BOOKMARK
    }
    data class Hide(override val postId: String) : InteractionDelta {
        override val type get() = InteractionType.HIDE
    }
    data class CommentAdded(override val postId: String, val pendingCommentId: String) : InteractionDelta {
        override val type get() = InteractionType.COMMENT
    }
    data class Unlock(override val postId: String) : InteractionDelta {
        override val type get() = InteractionType.UNLOCK
    }
    data class Tip(override val postId: String, val amountMinor: Long) : InteractionDelta {
        override val type get() = InteractionType.TIP
    }
}

/** Per-post overlay merged over the repository snapshot when projecting UI. */
data class PostOverlay(
    val likedOverride: Boolean? = null,
    val likeCountDelta: Int = 0,
    val savedOverride: Boolean? = null,
    val hidden: Boolean = false,
    val commentCountDelta: Int = 0,
    val pendingComments: List<String> = emptyList(),
    val unlockedOverride: Boolean? = null,
    val pendingTips: Int = 0,
)
```

### 4.2 The optimistic engine

```kotlin
class OptimisticInteractionEngine(
    private val scope: CoroutineScope,
) {
    private val overlays = MutableStateFlow<Map<String, PostOverlay>>(emptyMap())
    val overlayState: StateFlow<Map<String, PostOverlay>> = overlays.asStateFlow()

    private val errors = MutableSharedFlow<InteractionError>(extraBufferCapacity = 16)
    val errorEvents: SharedFlow<InteractionError> = errors.asSharedFlow()

    /** One in-flight job per (postId,type); a new request supersedes it (FR-6). */
    private val inFlight = mutableMapOf<Pair<String, InteractionType>, Job>()

    /**
     * Apply [delta] optimistically, run [mutate], reconcile or roll back.
     * @param mutate suspending network call returning the server-confirmed value.
     */
    fun <T> dispatch(
        delta: InteractionDelta,
        mutate: suspend () -> ApiResult<T>,
        reconcile: (PostOverlay, T) -> PostOverlay,
    )
}
```

`dispatch` does, synchronously: capture `previous = overlays.value[delta.postId]`, compute and emit
the optimistically-updated overlay (so the UI sees it before any suspension). It then cancels any
existing `inFlight[postId to type]` job and launches a new one on `scope` that calls `mutate()`.
On `ApiResult.Success(value)` it applies `reconcile(currentOverlay, value)`. On
`ApiResult.Failure` it restores `previous` (rollback, FR-3) — but only the fields owned by `type`,
so a concurrent different-type interaction is not clobbered — and emits an `InteractionError`.
The job removes itself from `inFlight` in a `finally` block.

### 4.3 ViewModel integration

```kotlin
@HiltViewModel
class FeedViewModel @Inject constructor(
    private val feedRepository: FeedRepository,      // AND-102 / AND-097
    private val interactions: InteractionRepository, // facade over AND-173..178 endpoints
) : ViewModel() {

    private val engine = OptimisticInteractionEngine(viewModelScope)

    /** Paging items projected with overlays merged in. */
    val pagedPosts: Flow<PagingData<PostUiModel>> =
        feedRepository.pagedPosts()
            .cachedIn(viewModelScope)
            .combineOverlay(engine.overlayState) // extension: merge + drop hidden

    val interactionErrors: SharedFlow<InteractionError> = engine.errorEvents

    fun onLikeClicked(post: PostUiModel) = engine.dispatch(
        delta = InteractionDelta.LikeToggle(post.id, liked = !post.liked),
        // Routes to POST /posts/{id}/like or /unlike depending on target state (no DELETE).
        mutate = { interactions.setLiked(post.id, liked = !post.liked) },
        // NOTE: the post like/unlike response carries NO liked/count (verified §5). reconcile is a
        // no-op for likes — keep the optimistic override+delta, clear on next refresh. Only
        // interactions whose response returns a count (e.g. tip → tip_total_cents) reconcile here.
        reconcile = { o, _ -> o },
    )

    fun onBookmarkClicked(post: PostUiModel) { /* BookmarkToggle, interactions.setSaved(...) */ }
    fun onHideClicked(post: PostUiModel) { /* Hide, interactions.hide(...) */ }
    fun onCommentSubmitted(post: PostUiModel, body: String) { /* CommentAdded + pending marker */ }
    fun onUnlockSucceeded(post: PostUiModel) { /* Unlock overlay; entitlement from AND-177 */ }
    fun onTipSubmitted(post: PostUiModel, amountMinor: Long) { /* Tip pending→confirmed */ }
}
```

`combineOverlay` is a pure function that produces `PostUiModel` by applying overlay overrides
(`likedOverride ?: base.liked`, `base.likeCount + likeCountDelta`, etc.) and filters out posts with
`hidden == true`. Because it is pure and synchronous, it is directly unit-testable without a
Paging source.

## 5. API Contract

This ticket defines **no new endpoints**. It defines the `InteractionRepository` facade interface
that the consuming tickets implement against real endpoints. The concrete request/response JSON is
owned by AND-173..AND-178; the shapes below are the *contract this ticket assumes* for reconciliation.

```kotlin
interface InteractionRepository {
    suspend fun setLiked(postId: String, liked: Boolean): ApiResult<LikeResult>   // AND-173
    suspend fun setSaved(postId: String, saved: Boolean): ApiResult<SaveResult>   // AND-176
    suspend fun hide(postId: String): ApiResult<Unit>                             // AND-175
    suspend fun addComment(postId: String, body: String): ApiResult<CommentResult>// AND-174
    suspend fun tip(postId: String, amountMinor: Long): ApiResult<TipResult>      // AND-178
}
data class LikeResult(val liked: Boolean, val likeCount: Int) // see note: post like resp carries neither field
data class SaveResult(val saved: Boolean)
data class CommentResult(val commentId: String, val commentCount: Int) // see note: comment resp has no count
data class TipResult(val tipTotalCents: Long)                          // server returns tip_total_cents, no tip_id/confirmed
```

**Verified server contract** (checked against `reference/openapi.index.txt`,
`reference/openapi.pretty.json`, and `reference/src/api/endpoints/newsfeed.ts` + `bookmarks.ts`).
The draft's contract was largely wrong; corrected shapes:

- **Like** — `POST /posts/{post_id}/like` and a *separate* `POST /posts/{post_id}/unlike`
  (op `like_post_*` / `unlike_post_*`). There is **no** `DELETE /posts/{id}/like`. Both take an
  **empty body** and the post like/unlike responses carry **no liked/count fields** — the web client
  types them as `{ ok: boolean }` (`newsfeed.ts: likePost/unlikePost`) and the OpenAPI response is
  an empty `200`. The `{ "liked", "like_count" }` shape (`LikeToggleOut`) belongs to the *video*
  endpoint `POST /ui/videos/{video_id}/like`, **not** posts. Consequence: `LikeResult.likeCount`
  cannot be reconciled from the post-like response; treat the optimistic `+1` as authoritative until
  the next page refresh (or read the count from the post GET). Flagged in R1.
- **Hide** — `POST /feed/hide` with body `{ "post_id": "…" }` (`HidePostRequest`) → `{ ok: boolean }`
  (`newsfeed.ts: hidePost`, `postHide.ts`). **Not** `POST /posts/{id}/hide`, and **not** a `204`.
  Restore uses `POST /feed/unhide` (same `HidePostRequest`). "Not interested" is the parallel pair
  `POST /feed/interesting` / `POST /feed/uninteresting`.
- **Comment add** — `POST /posts/{post_id}/comments` body `CreateCommentRequest`
  (field is `body`, plus optional `body_format`/markdown/rich/gif/sticker variants) →
  `200: CommentResponse` (web alias `FeedComment`, `newsfeed.ts: createComment`). The response
  contains `comment_id`, `post_id`, `author_id`, `created_at`, etc. but **no `comment_count`** field.
  Consequence: `CommentResult.commentCount` is **not** server-provided; the count overlay must be
  driven by the optimistic `+1` and cleared on refresh (OQ2).
- **Tip (post)** — `POST /posts/{post_id}/tip` body `PostTipRequest` `{ amount_cents, currency?,
  payment_method_id? }` → web type `{ ok: boolean, tip_total_cents: number }`
  (`newsfeed.ts: tipPostDirect`). Field is `amount_cents` (cents), **not** `amount_minor`; response
  has **no `tip_id`/`confirmed`**. (Distinct from comment tips `POST /posts/{id}/comments/{cid}/tip`
  and broadcast/messaging tips.) The engine's `TipResult` therefore reconciles a confirmed total,
  not a confirmation boolean.
- **Unlock** — `POST /posts/unlock` body `UnlockPostRequest` `{ post_id, payment_method_id?,
  idempotency_key? }` → `UnlockPostResponse { post_id, payment_intent }` (web `newsfeed.ts: unlockPost`
  types it `{ ok: boolean }`). **Not** `POST /posts/{id}/unlock`. This is the one mutation that
  *does* accept an `idempotency_key`.
- **Bookmark/save** — `POST /ui/bookmarks` body `CreateBookmarkRequest` `{ content_id, content_type
  (default "post"), collection_id? }` → `{ ok, content_type, content_id, collection_id, created_at }`,
  and remove is `DELETE /ui/bookmarks/{content_type}/{content_id}` → `{ ok }`
  (`bookmarks.ts: createBookmark/removeBookmark`). **Not** a `/posts/{id}/…` route. `SaveResult`
  has no server `saved` flag; treat the toggle as authoritative.

All mutations above are non-idempotent POST/DELETE and therefore **excluded from AND-016 auto-retry**.
Transport (verified in `src/api/client.ts`): every request sends `credentials: include` (cookies),
`X-CSRF-Token` read from the `ui_csrf` cookie, **and** an `Authorization: Bearer <accessToken>`
header (the draft mentioned only cookies + CSRF — the Bearer token is additional). Error bodies
follow the FastAPI `detail` shape (string / `[{msg}]` / `{code}`) normalized by `normalizeErrorDetail`
(AND-015); validation failures are `422: HTTPValidationError`.

## 6. Data & State Management

- **Overlay store** (`MutableStateFlow<Map<String, PostOverlay>>`) is the only mutable state this
  ticket introduces; it lives for the ViewModel lifetime and is **not** persisted across process
  death (in-flight optimistic deltas are intentionally ephemeral — on restart the user sees server
  truth from the Room/SWR cache of AND-116).
- **Projection** merges overlay over the Paging-backed base snapshot at read time. The base list is
  never mutated, so a Paging refresh that delivers fresh server data automatically supersedes any
  stale overlay (overlay deltas should be cleared for a post once a fresh page contains its
  reconciled value; `combineOverlay` drops zero-effect overlays).
- **Counts** are stored as deltas, not absolutes, so they remain correct if the base count changes
  underneath (e.g. another like arrives via refresh). `baseLikeCount` on `PostUiModel` records the
  base used when the delta was taken, enabling exact reconciliation in `reconcile`.
- **One-shot events** (`InteractionError`) use a `SharedFlow` with buffer, consumed by the screen
  and not re-emitted on configuration change.

## 7. Error Handling & Resilience

- Any `ApiResult.Failure` → rollback of *only* the fields owned by the failed `InteractionType` →
  emit `InteractionError(postId, type, message)`. The message is derived from AND-015 mapping
  (string / `[{msg}]` / `{code}` → human string), defaulting to a generic localized string.
- **Timeouts** (~20s per project context) surface as `ApiResult.Failure(Timeout)` and roll back.
- **401**: the OkHttp authenticator (AND-013) performs the single `POST /ui/session/refresh` + retry
  beneath Retrofit; only if that still fails does the mutation reach this layer as a Failure → roll
  back. This layer does not itself retry.
- **Superseded mutations** (FR-6): a cancelled in-flight job throws `CancellationException`, which
  is swallowed (no rollback, no error) because a newer dispatch already owns the overlay.
- **Hide rollback** restores the post's `hidden=false`; because the base list is untouched, the post
  reappears at its original index on the next projection.
- No mutation is auto-retried (non-idempotent). The user re-triggers manually after a rollback.

## 8. Security & Privacy

- All mutations ride the cookie-based session + `X-CSRF-Token` header (project auth model);
  handled by `core-network` interceptors (AND-012/AND-013), not duplicated here.
- Tip amounts (`amountMinor`) and entitlement/unlock state are sensitive: never log amounts, post
  bodies, or comment text (see §10 redaction). Overlay state holds only ids, booleans, and integer
  deltas plus pending comment ids — no PII beyond what the post list already holds in memory.
- No new persistence; nothing sensitive is written to disk by this ticket.

## 9. Accessibility & i18n

- This is a ViewModel/state ticket; UI semantics live in AND-099/AND-100. However, all user-facing
  rollback strings produced here are externalized to `core-ui` string resources
  (`R.string.interaction_like_failed`, etc.) — no hardcoded English — to satisfy the i18n plumbing
  of AND-111/AND-112 and RTL readiness (AND-114).
- State changes (like count up/down, removal) must be announced by the consuming composable via
  `liveRegion`/`stateDescription`; this ticket guarantees the state transitions are observable as
  discrete StateFlow emissions so those announcements can fire.

## 10. Telemetry & Logging

- Emit a structured, **redacted** debug log per dispatch:
  `Timber.tag("Interaction").d("dispatch type=%s post=%s optimistic=%s", type, postId, applied)`
  and on terminal outcome `outcome=success|rollback`. **Never** log tip amounts, comment bodies, or
  cookies/CSRF (consistent with AND-052 redaction policy).
- Optional analytics hook (no-op stub here, wired by a later analytics ticket):
  `interaction_attempt` / `interaction_rollback` events with `{type, postId_hashed, latencyMs}`.

## 11. Testing Strategy

The acceptance bullet ("Optimistic/rollback unit-tested") is the core of this ticket. Tests use
JUnit4 + `kotlinx-coroutines-test` (`runTest`, `StandardTestDispatcher`), Turbine for Flow
assertions, and a fake `InteractionRepository` from `core-testing` whose results are scriptable
(success-with-value / failure / never-completes). No MockWebServer is required at this layer.

Required unit tests:
- **T1 optimistic apply** — `onLikeClicked` emits `liked=true, likeCount=base+1` *before* the fake
  repo completes (assert on the overlay emission while the mutate suspend is still pending).
- **T2 success reconciliation** — when the fake returns `LikeResult(liked=true, likeCount=99)`, the
  projected `likeCount` becomes 99 (server truth), not base+1.
- **T3 rollback on failure** — fake returns `ApiResult.Failure`; overlay reverts to pre-apply value
  and one `InteractionError` is emitted on `interactionErrors`.
- **T4 supersede/collapse** (FR-6) — two rapid `onLikeClicked` toggles; assert only the latest
  intent survives, the first job is cancelled, and no spurious error is emitted.
- **T5 hide remove + restore** — `onHideClicked` drops the post from projected list; on failure it
  reappears at original index.
- **T6 partial rollback isolation** — a failed like does not revert a concurrent successful
  bookmark on the same post.
- **T7 tip pending→confirmed and pending→failed** (non-toggle path).
- **T8 comment pending marker** added then reconciled/rolled back.
- **T9 `combineOverlay` pure-function table tests** over base × overlay combinations.

Coverage target: 100% of `OptimisticInteractionEngine` branches and `combineOverlay`.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-102 (Feed ViewModel + state) must exist; this ticket extends its
  `FeedViewModel`, `FeedUiState`/`PostUiModel`, and Paging flow.
- **Soft / consumer relationship:** AND-173, AND-174, AND-175, AND-176, AND-177, AND-178 each
  implement one `InteractionRepository` method and wire their screen affordance to the
  `onXxxClicked` entry points. They are listed in `blocks` because they need the primitive defined
  here; implement this ticket first, then they fill in concrete endpoints.
- Uses existing `ApiResult` (AND-018), error mapping (AND-015), and the SWR cache (AND-116) for base
  truth. No new third-party libraries.

## 13. Risks & Open Questions

- **R1 — Server count drift (CONFIRMED, not hypothetical).** Verified in §5: the post `like`/`unlike`
  response returns **no** count or liked flag (only the *video* like endpoint returns `LikeToggleOut`).
  Comment-add likewise returns no count. So delta-based reconciliation *cannot* read server truth for
  these. *Mitigation (now the required behavior):* keep the optimistic delta and clear it on the next
  page refresh (or re-fetch the post). Do **not** require a count in `LikeResult`/`CommentResult`.
- **R2 — Paging snapshot churn.** Overlays keyed by post id can momentarily double-count if a refresh
  delivers the reconciled value before the overlay is cleared. *Mitigation:* `combineOverlay` treats
  an overlay as superseded when the base already reflects it; add a clear-on-refresh hook.
- **R3 — Process death loses pending tips.** A tip submitted then process-killed shows no confirmation.
  *Open question:* should tips be queued durably (WorkManager)? Out of scope here; flagged for AND-178.
- **OQ1 (RESOLVED)** — Hide is server-persisted: `POST /feed/hide` records a preference, and there is
  an explicit `POST /feed/unhide` to reverse it (both `HidePostRequest`). Rollback after a *failed*
  hide is purely local (the overlay's `hidden` flag flips back); `/feed/unhide` is only needed to
  reverse a *successful* hide, which is a separate user action owned by AND-175.
- **OQ2** — Does comment add support optimistic body rendering, or only count? Resolve with AND-174.

## 14. Acceptance Criteria

AC-1 Triggering like/bookmark/hide/comment/unlock/tip updates the projected `PostUiModel` state
synchronously (before the network call resolves). *(unit-tested, T1)*

AC-2 On mutation success, the overlay is reconciled to the server-confirmed value, not the optimistic
guess. *(T2)*

AC-3 On mutation failure (error/timeout/post-refresh-401), the affected interaction's state rolls
back to its exact pre-apply value and exactly one `InteractionError` event is emitted. *(T3)*

AC-4 Rapid repeated toggles collapse to the user's last intent with no orphaned in-flight mutation
and no spurious rollback error. *(T4)*

AC-5 Hide optimistically removes the post; failure restores it at its original position. *(T5)*

AC-6 A failed interaction does not revert an unrelated concurrent successful interaction on the same
post. *(T6)*

AC-7 Tip and comment (non-toggle) follow pending→confirmed / pending→rolled-back. *(T7, T8)*

AC-8 All rollback strings are externalized resources; no amounts/bodies/cookies are logged. *(§8, §10)*

AC-9 `OptimisticInteractionEngine` and `combineOverlay` reach 100% branch coverage.

## 15. Definition of Done

- `OptimisticInteractionEngine`, `InteractionDelta`, `PostOverlay`, `combineOverlay`,
  `InteractionRepository` interface, and the `FeedViewModel` interaction entry points are implemented
  in `feature-feed` under `com.testlogon.android.feature.feed.interaction`.
- All unit tests T1–T9 pass on the CI unit-test job (AND-050); coverage gate met.
- `ktlint`/`detekt` (AND-005) and Hilt/KSP compile clean; no hardcoded user-facing strings.
- No new endpoints introduced; `InteractionRepository` contract reviewed by owners of AND-173..AND-178.
- Code merged to `android-port`; PR links AND-180 and references the six consumer tickets.
- Spec acceptance bullet satisfied: optimistic apply and rollback are unit-tested and green.

## 16. Citations & Assumption Audit

Each numbered item: the claim, a VERDICT, and an exact source pointer.

1. **Like uses `POST /posts/{id}/like` plus a separate `POST /posts/{id}/unlike` (no DELETE).**
   VERDICT: **Corrected** (draft claimed `POST` + `DELETE /posts/{id}/like`).
   SOURCE: OpenAPI `POST /posts/{post_id}/like` (op `like_post_posts__post_id__like_post`) and
   `POST /posts/{post_id}/unlike` (op `unlike_post_*`); `src/api/endpoints/newsfeed.ts: likePost`,
   `unlikePost`.
2. **Post like/unlike response carries no `liked`/`like_count`.** VERDICT: **Corrected** (draft
   claimed `{"liked":true,"like_count":42}`). SOURCE: OpenAPI `POST /posts/{post_id}/like`
   `resp=200:` (empty schema); `newsfeed.ts: likePost` typed `{ ok: boolean }`. The
   `{liked,like_count}` shape is `LikeToggleOut`, which belongs to OpenAPI
   `POST /ui/videos/{video_id}/like` (`toggle_like_endpoint_*`), a different (video) endpoint.
3. **Hide is `POST /feed/hide` with `{post_id}` → `{ok}` (not `POST /posts/{id}/hide`, not 204).**
   VERDICT: **Corrected**. SOURCE: OpenAPI `POST /feed/hide` (op `hide_post_feed_hide_post`,
   `req=HidePostRequest`, `resp=200:`); schema `HidePostRequest` (`post_id` required);
   `src/api/endpoints/newsfeed.ts: hidePost`, `src/api/endpoints/postHide.ts`.
4. **Restore-after-hide endpoint is `POST /feed/unhide`; "not interested" is
   `/feed/interesting` + `/feed/uninteresting`.** VERDICT: **Verified**. SOURCE: OpenAPI
   `POST /feed/unhide`, `POST /feed/interesting`, `POST /feed/uninteresting` (all `HidePostRequest`);
   `src/api/endpoints/postInteresting.ts`, `postHide.ts: unhide`.
5. **Comment add is `POST /posts/{id}/comments` body `CreateCommentRequest` (field `body`) →
   `CommentResponse`/`FeedComment`.** VERDICT: **Verified** (path/method/req/resp).
   SOURCE: OpenAPI `POST /posts/{post_id}/comments` (op `create_comment_*`, `req=CreateCommentRequest`,
   `resp=200:CommentResponse`); `src/api/endpoints/newsfeed.ts: createComment`.
6. **Comment-add response has NO `comment_count`.** VERDICT: **Corrected** (draft claimed
   `{"comment_id":…,"comment_count":13}`). SOURCE: schema `components.schemas.CommentResponse` —
   properties include `comment_id`, `post_id`, `author_id`, `created_at`, `body*`, `version`, etc., but
   no count field; `CommentResult.commentCount` is therefore client-derived (optimistic only).
7. **Post tip is `POST /posts/{id}/tip` body `PostTipRequest` (`amount_cents`) → `{ok, tip_total_cents}`.**
   VERDICT: **Corrected** (draft used `amount_minor` and a `{tipId, confirmed}` response).
   SOURCE: OpenAPI `POST /posts/{post_id}/tip` (op `tip_post_*`, `req=PostTipRequest`); schema
   `PostTipRequest` (`amount_cents` required, `currency` default `usd`, optional `payment_method_id`);
   `src/api/endpoints/newsfeed.ts: tipPostDirect` typed `{ ok: boolean; tip_total_cents: number }`.
8. **Unlock is `POST /posts/unlock` body `{post_id, payment_method_id?, idempotency_key?}` →
   `UnlockPostResponse{post_id, payment_intent}`.** VERDICT: **Corrected** (draft implied
   `POST /posts/{id}/unlock`). SOURCE: OpenAPI `POST /posts/unlock` (op `unlock_post_posts_unlock_post`,
   `req=UnlockPostRequest`, `resp=200:UnlockPostResponse`); schemas `UnlockPostRequest`/`UnlockPostResponse`;
   `src/api/endpoints/newsfeed.ts: unlockPost`.
9. **Bookmark/save is `POST /ui/bookmarks` + `DELETE /ui/bookmarks/{content_type}/{content_id}`
   (not a `/posts/{id}` route).** VERDICT: **Corrected** (draft assumed `/posts/...`).
   SOURCE: OpenAPI `POST /ui/bookmarks` (`req=CreateBookmarkRequest`) and
   `DELETE /ui/bookmarks/{content_type}/{content_id}`; schema `CreateBookmarkRequest`
   (`content_id` required, `content_type` default `post`, `collection_id?`);
   `src/api/endpoints/bookmarks.ts: createBookmark`, `removeBookmark`.
10. **CSRF: `X-CSRF-Token` header sourced from the `ui_csrf` cookie; requests send cookies.**
    VERDICT: **Verified**. SOURCE: `src/api/client.ts` — `getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`; all requests use `credentials: "include"`.
11. **Requests ALSO send `Authorization: Bearer <accessToken>`.** VERDICT: **Corrected/augmented**
    (draft said only cookies + CSRF). SOURCE: `src/api/client.ts` — `headers.set("Authorization",
    `Bearer ${accessToken}`)` from `useAuthStore`.
12. **401 triggers a single `POST /ui/session/refresh` then a retry; this layer does not itself retry.**
    VERDICT: **Verified**. SOURCE: OpenAPI `POST /ui/session/refresh` (op `ui_session_refresh_*`);
    `src/api/client.ts` `refreshSession()` + single-flight `refreshPromise` on `res.status === 401`.
13. **Error bodies follow FastAPI `detail` shape (string / `[{msg}]` / `{code}`); validation = 422
    `HTTPValidationError`.** VERDICT: **Verified**. SOURCE: `src/api/client.ts: normalizeErrorDetail`
    (handles string, array-of-`{msg}`, object-`{code}`); OpenAPI index shows `422:HTTPValidationError`
    on every interaction endpoint.
14. **Mutations are non-idempotent POST/DELETE and excluded from AND-016 auto-retry.**
    VERDICT: **Verified** (against the method column of each OpenAPI entry above) + design intent.
15. **Android stack/module layout (Kotlin 2.0.21, Coroutines/Flow, Hilt+KSP, Compose/M3, Paging 3,
    Turbine, `kotlinx-coroutines-test`).** VERDICT: **Unverified-assumption** (no Android sources in
    this repo to confirm versions). framework ref: Paging+ViewModel guidance
    https://developer.android.com/topic/libraries/architecture/paging/v3-paged-data ; coroutines test
    https://developer.android.com/kotlin/coroutines/test . Carried over from AND-102/project context.

### Corrections made
- Frontmatter: `status: draft → reviewed`, added `reviewed_on: 2026-06-06`.
- §2: web-reference filenames fixed — no `postLike.ts`; interaction calls live in `newsfeed.ts`
  (+ `postHide.ts`/`postInteresting.ts`/`bookmarks.ts`).
- §3 FR-4: noted that post like/comment/bookmark responses carry no value to reconcile to.
- §4.3: `onLikeClicked` reconcile lambda changed to a no-op (the like response has no count/flag) and
  annotated that it routes to `/like` or `/unlike`.
- §5: rewritten with verified endpoints/methods/request+response shapes for like, unlike, hide,
  unhide, comment, tip, unlock, bookmark; corrected Kotlin DTOs (`TipResult` now `tipTotalCents`);
  added the Bearer-token + CSRF + cookie transport detail; corrected `amount_cents` vs `amount_minor`.
- §13: R1 upgraded from hypothetical to confirmed; OQ1 resolved (hide is server-persisted with
  `/feed/unhide`).

### Open assumptions
- **A1 — `combineOverlay` clears a stale overlay once the base reflects it.** Since the like/comment
  responses return no count (items 2, 6), reconciliation depends on a *page refresh* delivering the
  server value. The exact "overlay superseded by base" detection (§6, R2) is a design assumption with
  no server signal to confirm timing; flagged for the consuming tickets.
- **A2 — Tip "confirmed" semantics.** The post-tip response is `{ok, tip_total_cents}` with no
  explicit confirmation/idempotency token (unlike unlock, which has `idempotency_key`). Whether a tip
  is durably confirmed vs. accepted-pending is unverifiable from the API surface (R3 / AND-178).
- **A3 — Android toolchain versions** (item 15) cannot be verified in this repo; inherited from
  project context, not from an authoritative Android source tree.
- **A4 — `InteractionRepository` Kotlin facade** is this ticket's own contract, not a server artifact;
  it is intentionally an assumption that the consuming tickets (AND-173..178) implement.

## 17. Test Plan

Test target legend (CI/dev): **JVM** = JVM/Robolectric unit (no device); **emu35** = headless AVD
`test35` (x86_64, Android 15 / API 35); **deviceA15** = physical Samsung Galaxy A15 5G (SM-A156U,
serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). This ticket is ViewModel/state logic, so most
cases are JVM unit; UI-projection and a11y observability cases run on emu35; a small set asserting
real-network/offline timeout behavior against the flaky dev host prefer **deviceA15**.

- **TC-AND-180-01 — Optimistic apply before network resolves.** Type: unit (JVM).
  Target: `FeedViewModel.onLikeClicked` + `OptimisticInteractionEngine.dispatch` + `combineOverlay`,
  fake `InteractionRepository` whose `setLiked` never completes. Preconditions: base post
  `liked=false, likeCount=10`. Steps: call `onLikeClicked(post)`; before completing the fake, collect
  the projected `PostUiModel` via Turbine. Expected: projected `liked=true, likeCount=11` emitted
  while `mutate` is still suspended; no error emitted. Traces: AC-1.
- **TC-AND-180-02 — Success keeps optimistic delta when response has no count (like).** Type:
  contract/MockWebServer (JVM). Target: `InteractionRepository.setLiked` → `POST /posts/{id}/like`
  wired to MockWebServer; reconcile no-op. Preconditions: MockWebServer returns `200 {"ok":true}`
  (verified empty/ok shape, §5 item 2). Steps: dispatch like; await success. Expected: request line is
  `POST /posts/{id}/like` with empty body and headers `X-CSRF-Token` + `Authorization: Bearer …`;
  projected `likeCount` stays at optimistic `11` (no server count to reconcile); overlay not cleared
  until refresh. Traces: AC-2 (caveat path).
- **TC-AND-180-03 — Success reconciles to server value when response carries one (tip).** Type:
  contract/MockWebServer (JVM). Target: `InteractionRepository.tip` → `POST /posts/{id}/tip`.
  Preconditions: MockWebServer returns `200 {"ok":true,"tip_total_cents":500}`. Steps: `onTipSubmitted`
  with `amountMinor=200`; await success. Expected: request body contains `amount_cents` (not
  `amount_minor`); overlay reconciles tip pending→confirmed using `tip_total_cents=500`. Traces: AC-2, AC-7.
- **TC-AND-180-04 — Rollback on failure emits exactly one error.** Type: unit (JVM). Target:
  `dispatch` rollback path. Preconditions: fake `setLiked` returns `ApiResult.Failure`. Steps: dispatch
  like from `liked=false`; await terminal. Expected: overlay reverts to exact pre-apply value
  (`liked=false, likeCount=10`); exactly one `InteractionError(postId, LIKE, …)` on
  `interactionErrors`. Traces: AC-3.
- **TC-AND-180-05 — Validation/error body (422) maps to a human message.** Type:
  contract/MockWebServer (JVM). Target: error mapping (AND-015) feeding `InteractionError.message`.
  Preconditions: MockWebServer returns `422 {"detail":[{"msg":"value is not a valid…","loc":[…]}]}`
  (real `HTTPValidationError` shape). Steps: dispatch a mutation; await failure. Expected: rollback
  occurs and `InteractionError.message` equals the extracted `msg` string (array-of-`{msg}` branch),
  not a stringified object. Traces: AC-3.
- **TC-AND-180-06 — Supersede/collapse of rapid toggles.** Type: unit (JVM). Target: `inFlight`
  cancel-and-replace (FR-6). Preconditions: fake delays each call. Steps: call `onLikeClicked` twice
  rapidly (false→true, then true→false). Expected: first job is cancelled (CancellationException
  swallowed — no error), only the latest intent (`liked=false`) survives, no spurious
  `InteractionError`. Traces: AC-4.
- **TC-AND-180-07 — Hide removes then restores on failure.** Type: unit (JVM). Target:
  `onHideClicked` + `combineOverlay` drop-hidden. Preconditions: post at index 2 of projected list;
  fake `hide` (→ `POST /feed/hide`) returns Failure. Steps: dispatch hide → assert post dropped from
  projection; let mutate fail. Expected: on failure `hidden` flips back and the post reappears at its
  original index 2 (base list untouched). Traces: AC-5.
- **TC-AND-180-08 — Hide contract: correct endpoint and body.** Type: contract/MockWebServer (JVM).
  Target: `InteractionRepository.hide`. Preconditions: MockWebServer returns `200 {"ok":true}`. Steps:
  dispatch hide. Expected: request is `POST /feed/hide` with JSON `{"post_id":"…"}` (NOT
  `POST /posts/{id}/hide`, NOT expecting 204). Traces: AC-5.
- **TC-AND-180-09 — Partial rollback isolation.** Type: unit (JVM). Target: per-type field ownership in
  rollback. Preconditions: same post; bookmark succeeds, like fails (concurrent). Steps: dispatch
  bookmark (success) and like (failure) together. Expected: like rolls back `likedOverride`/
  `likeCountDelta` only; `savedOverride` from the successful bookmark is untouched. Traces: AC-6.
- **TC-AND-180-10 — Comment pending marker added then reconciled/rolled back.** Type: unit (JVM).
  Target: `onCommentSubmitted` non-toggle path. Preconditions: fake `addComment` scriptable.
  Steps: submit comment → assert `pendingComments` contains marker and `commentCountDelta=+1` (no
  server count, per §5 item 6); then (a) success → pending promoted/cleared, count delta kept until
  refresh; (b) failure → pending marker removed and delta reverted with one error. Traces: AC-7, AC-3.
- **TC-AND-180-11 — `combineOverlay` pure-function table.** Type: unit (JVM). Target: `combineOverlay`.
  Preconditions: matrix of base × overlay (liked override, count delta, saved override, hidden,
  comment delta, unlocked override). Steps: run table. Expected: each projection equals the expected
  merged `PostUiModel`; `hidden=true` rows are absent; zero-effect overlays are dropped. Traces:
  AC-1, AC-9 (branch coverage).
- **TC-AND-180-12 — Flaky dev-host timeout / offline rolls back.** Type: integration (prefer
  **deviceA15**; the physical device exercises the real plaintext-HTTP dev host
  `http://18.222.237.167:8000` and real ~20s socket timeouts and airplane-mode network loss that the
  emulator's virtualized NAT does not faithfully reproduce). Target: real Retrofit/OkHttp →
  `InteractionRepository` against the dev host (or a delayed MockWebServer if the host is down).
  Preconditions: toggle airplane mode / point at an unresponsive host. Steps: trigger a like; wait past
  the timeout. Expected: `ApiResult.Failure(Timeout/Network)` → overlay rolls back and one
  `InteractionError` fires; no auto-retry occurs. Traces: AC-3.
- **TC-AND-180-13 — Security: no sensitive values logged; CSRF/cookies attached.** Type:
  contract/MockWebServer + log capture (JVM). Target: §8/§10 redaction + transport. Preconditions:
  capture Timber output and the recorded request. Steps: dispatch a tip (`amount_cents=1000`) and a
  comment with body text. Expected: logs contain `type/postId/outcome` only — no amount, comment body,
  cookie, or CSRF token value; the recorded request includes `X-CSRF-Token` and the session cookie,
  and `Authorization: Bearer`. Traces: AC-8.
- **TC-AND-180-14 — Accessibility: state transitions are observable for announcements.** Type:
  Compose-UI / instrumented (emu35). Target: the consuming composable reading this ViewModel's
  StateFlow (uses AND-099 affordance harness in `core-ui`); validates that like/unlike and removal
  produce discrete StateFlow emissions a `liveRegion`/`stateDescription` can announce, and that
  rollback strings resolve from `R.string.*` (no hardcoded English). Preconditions: TalkBack-style
  semantics assertions via `onNodeWithContentDescription`/`assertHasStateDescription`. Steps: toggle
  like, then force a rollback. Expected: state description updates on apply and again on rollback; the
  failure snackbar text comes from a string resource. Traces: AC-1, AC-8.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (synchronous optimistic apply) | TC-01, TC-11, TC-14 |
| AC-2 (reconcile to server value on success) | TC-02 (no-count caveat), TC-03 (count present) |
| AC-3 (rollback + exactly one error) | TC-04, TC-05, TC-10(b), TC-12 |
| AC-4 (collapse rapid toggles, no orphan/spurious error) | TC-06 |
| AC-5 (hide removes; failure restores at index) | TC-07, TC-08 |
| AC-6 (failed interaction doesn't revert unrelated success) | TC-09 |
| AC-7 (tip & comment pending→confirmed/rolled-back) | TC-03, TC-10 |
| AC-8 (externalized strings; no sensitive logging) | TC-13, TC-14 |
| AC-9 (100% branch coverage of engine + combineOverlay) | TC-11 (+ TC-01/04/06/07/09 exercise engine branches) |
