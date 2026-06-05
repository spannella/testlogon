---
id: AND-180
title: Interaction ViewModel updates
milestone: M4
epic: E24
priority: P0
size: M
status: draft
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
- Web reference: `frontend/src/api/endpoints/*.ts` (e.g. `postLike.ts`, `postHide.ts`,
  `postInteresting.ts`), shared types `frontend/src/api/types.ts`.

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
authoritative server value from the response (e.g. server-confirmed `likeCount`), not merely "kept."
This reconciles optimistic guesses (the +1 we assumed) with server truth.

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
        mutate = { interactions.setLiked(post.id, liked = !post.liked) },
        reconcile = { o, r -> o.copy(likedOverride = r.liked, likeCountDelta = r.likeCount - post.baseLikeCount) },
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
data class LikeResult(val liked: Boolean, val likeCount: Int)
data class SaveResult(val saved: Boolean)
data class CommentResult(val commentId: String, val commentCount: Int)
data class TipResult(val tipId: String, val confirmed: Boolean)
```

Assumed server contract (confirm against `/openapi.json` in the consuming tickets):
`POST /posts/{id}/like` and `DELETE /posts/{id}/like` → `{"liked": true, "like_count": 42}`;
`POST /posts/{id}/hide` → `204`; `POST /posts/{id}/comments` body `{"body":"..."}` →
`{"comment_id":"c_…","comment_count":13}`. All mutations are non-idempotent POST/DELETE and
therefore **excluded from AND-016 auto-retry**; they carry cookies + `X-CSRF-Token` per the
auth model. Error bodies follow the FastAPI `detail` shape mapped by AND-015.

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

- **R1 — Server count drift.** If the server returns no count on a like response, delta-based
  reconciliation can drift. *Mitigation:* require count in `LikeResult`; if absent, keep the
  optimistic delta and clear it on next page refresh. Confirm shape in AND-173 against `/openapi.json`.
- **R2 — Paging snapshot churn.** Overlays keyed by post id can momentarily double-count if a refresh
  delivers the reconciled value before the overlay is cleared. *Mitigation:* `combineOverlay` treats
  an overlay as superseded when the base already reflects it; add a clear-on-refresh hook.
- **R3 — Process death loses pending tips.** A tip submitted then process-killed shows no confirmation.
  *Open question:* should tips be queued durably (WorkManager)? Out of scope here; flagged for AND-178.
- **OQ1** — Is hide a server-persisted preference or session-local? AND-175 says "preference honored";
  confirm endpoint so rollback semantics (restore) match server.
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
