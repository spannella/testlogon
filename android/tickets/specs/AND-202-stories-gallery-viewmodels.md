---
id: AND-202
title: Stories/gallery ViewModels
milestone: M4
epic: E27
priority: P2
size: M
status: draft
depends_on: [AND-199, AND-201]
blocks: [AND-203]
---

# AND-202 — Stories/gallery ViewModels

## 1. Overview & Goal

This ticket delivers the presentation-layer state holders for the Stories and Gallery
features: `StoriesViewModel`, `StoryViewerViewModel`, and `GalleryViewModel`. These
ViewModels own all UI state, drive paging for the gallery grid, sequence story-ring
playback (auto-advance, tap-to-skip, hold-to-pause), and expose immutable
`StateFlow<UiState>` streams that the Compose UI from AND-199 (stories tray + viewer)
and AND-201 (gallery grid + lightbox) collect.

The goal is a fully unit-tested, lifecycle-safe state layer that:
- Loads the stories tray and per-user story reels, tracking seen/unseen and current
  segment.
- Pages the gallery via Paging 3 with a `RemoteMediator`-free network `PagingSource`
  (cursor-based), surfacing load/append/refresh states.
- Maps `ApiResult<T>` and FastAPI `detail` errors into discrete, testable UI states
  (Loading / Content / Empty / Error / Stale).
- Survives configuration changes and process death where feasible (saved state for
  selected indices), and tolerates the unreliable dev backend with timeouts and
  bounded retry for idempotent GETs.

The Compose screens, navigation wiring, and the actual story/lightbox rendering are
owned by AND-199 and AND-201; this ticket owns only the `feature-stories` and
`feature-gallery` ViewModels, their UI-state models, and supporting use cases /
mappers within those feature modules.

## 2. Context & References

- **Modules:** `feature-stories`, `feature-gallery` (Compose UI + ViewModels), built
  on `core-network`, `core-model`, `core-data`, `core-ui`, `core-testing`. Layering:
  `app -> feature-* -> core-*`. No feature depends on another feature.
- **Package roots:** `com.testlogon.android.feature.stories`,
  `com.testlogon.android.feature.gallery`, `com.testlogon.android.core.model`,
  `com.testlogon.android.core.network`.
- **Upstream tickets:**
  - **AND-199** — Stories tray + viewer; defines the `stories.ts`-equivalent Retrofit
    service and Compose tray/viewer. This ticket consumes that service and feeds those
    composables.
  - **AND-201** — Gallery browsing; defines the `gallery.ts`-equivalent service and the
    grid + lightbox composables. This ticket provides the paging stream and lightbox
    selection state.
- **Downstream:** **AND-203** — Stories/gallery UI smoke tests; depends on the public
  state contracts and intent functions defined here.
- **Web reference:** `frontend/src/api/endpoints/stories.ts`,
  `frontend/src/api/endpoints/gallery.ts`, shared types in
  `frontend/src/api/types.ts`. OpenAPI authority: `GET /openapi.json` on the dev
  backend `http://18.222.237.167:8000` (plaintext HTTP, unreliable; ~20s timeouts).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Paging 3, Room 2.6, DataStore. minSdk 24,
  compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

**Stories tray (`StoriesViewModel`):**
1. On init, load the tray (ordered list of reels grouped by author) and expose
   `StoriesUiState`.
2. Track seen/unseen per reel; the tray orders unseen first, then seen, preserving
   backend order within each group.
3. Expose `refresh()` (pull-to-refresh) and `onReelClicked(reelId)` intents.
4. Persist the last-opened reel id in `SavedStateHandle` so re-entry restores position.

**Story viewer (`StoryViewerViewModel`):**
5. Given an entry reel id, build an ordered playlist of reels (starting at the entry,
   continuing through subsequent unseen reels) and, within each reel, its ordered
   segments (image or video).
6. Auto-advance segments on a per-segment duration timer (default 5,000 ms for images;
   video duration for video segments, capped at 30,000 ms).
7. Support intents: `onTapNext()`, `onTapPrevious()`, `onHoldStart()` (pause timer),
   `onHoldEnd()` (resume), `onReelSwipe(direction)` (jump reel), `onClose()`.
8. Mark a segment seen once viewed past 50% of its duration; mark a reel seen when its
   last segment completes; emit a one-shot effect to POST the seen receipt.
9. When the playlist completes (last segment of last reel), emit a `Finished` effect so
   AND-199 can dismiss the viewer.

**Gallery (`GalleryViewModel`):**
10. Expose `pagingData: Flow<PagingData<GalleryItemUi>>` backed by a cursor-based
    `PagingSource`, cached in `viewModelScope` via `cachedIn`.
11. Support an optional `album`/`tag` filter argument; changing the filter restarts
    paging.
12. Maintain lightbox selection state (`selectedIndex`, open/closed) in a separate
    `StateFlow` so paging recomposition does not reset the lightbox.
13. Expose `onItemClicked(index)`, `onLightboxClosed()`, `onLightboxPage(index)`,
    and `retry()` intents.

**Cross-cutting:**
14. All ViewModels expose `StateFlow<UiState>` (never `LiveData`); one-shot events use a
    `Channel`-backed `Flow` of sealed effects, not state.
15. Distinguish Empty (200 with empty list) from Error and from Loading. Surface a
    `Stale` flag when content is served from Room cache after a failed refresh.

## 4. Technical Design

Each feature module contributes Hilt-injected ViewModels annotated
`@HiltViewModel`, constructor-injecting repository interfaces (provided by AND-199 /
AND-201) and a `SavedStateHandle`.

```kotlin
// com.testlogon.android.feature.stories.StoriesViewModel
@HiltViewModel
class StoriesViewModel @Inject constructor(
    private val storiesRepository: StoriesRepository, // from AND-199
    private val savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<StoriesUiState>
    fun refresh()
    fun onReelClicked(reelId: String)
}

sealed interface StoriesUiState {
    data object Loading : StoriesUiState
    data class Content(
        val reels: List<ReelSummaryUi>,
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
    ) : StoriesUiState
    data object Empty : StoriesUiState
    data class Error(val message: String, val retryable: Boolean) : StoriesUiState
}

data class ReelSummaryUi(
    val reelId: String,
    val authorName: String,
    val avatarUrl: String?,
    val seen: Boolean,
    val segmentCount: Int,
    val updatedAt: Instant,
)
```

```kotlin
// com.testlogon.android.feature.stories.StoryViewerViewModel
@HiltViewModel
class StoryViewerViewModel @Inject constructor(
    private val storiesRepository: StoriesRepository,
    private val savedState: SavedStateHandle, // "entryReelId" nav arg
    private val clock: TimeSource = TimeSource.Monotonic, // injectable for tests
) : ViewModel() {
    val uiState: StateFlow<StoryViewerUiState>
    val effects: Flow<StoryViewerEffect>
    fun onTapNext(); fun onTapPrevious()
    fun onHoldStart(); fun onHoldEnd()
    fun onReelSwipe(direction: SwipeDirection)
    fun onClose()
}

data class StoryViewerUiState(
    val reelIndex: Int = 0,
    val segmentIndex: Int = 0,
    val playlist: List<ReelPlaybackUi> = emptyList(),
    val isPaused: Boolean = false,
    val progress: Float = 0f, // 0..1 for current segment
    val loading: Boolean = true,
    val error: String? = null,
)

sealed interface StoryViewerEffect {
    data class MarkSeen(val reelId: String) : StoryViewerEffect
    data object Finished : StoryViewerEffect
}
```

The auto-advance timer is a `viewModelScope` coroutine driving `progress` from a
`flow { }` that ticks every 50 ms against the segment duration. `onHoldStart/End`
toggle a `MutableStateFlow<Boolean>` (`paused`) that the ticker `collect`s via
`transformLatest`, so resuming continues from the accrued elapsed time. `TimeSource` is
injected so virtual time can be used in unit tests.

```kotlin
// com.testlogon.android.feature.gallery.GalleryViewModel
@HiltViewModel
class GalleryViewModel @Inject constructor(
    private val galleryRepository: GalleryRepository, // from AND-201
    private val savedState: SavedStateHandle,
) : ViewModel() {
    private val filter = MutableStateFlow(savedState.get<String?>(KEY_ALBUM))
    val pagingData: Flow<PagingData<GalleryItemUi>> = filter
        .flatMapLatest { album -> galleryRepository.pager(album).flow }
        .cachedIn(viewModelScope)
    val lightbox: StateFlow<LightboxUiState>
    fun setFilter(album: String?)
    fun onItemClicked(index: Int)
    fun onLightboxPage(index: Int)
    fun onLightboxClosed()
}

data class LightboxUiState(
    val isOpen: Boolean = false,
    val selectedIndex: Int = 0,
)

data class GalleryItemUi(
    val id: String,
    val thumbUrl: String,
    val fullUrl: String,
    val width: Int,
    val height: Int,
    val isVideo: Boolean,
)
```

The gallery `PagingSource` (`GalleryPagingSource`, in `feature-gallery`, constructed by
`GalleryRepository.pager()`) is cursor-based: `LoadParams.key` is the opaque
`next_cursor` string; `load()` calls the AND-201 service and returns
`LoadResult.Page(data, prevKey = null, nextKey = response.nextCursor)`. `PagingConfig`
uses `pageSize = 30, prefetchDistance = 10, initialLoadSize = 30, enablePlaceholders =
false`. UI mapping (`GalleryItemDto -> GalleryItemUi`) lives in a `pure` mapper
function so it is unit-testable without Paging machinery.

## 5. API Contract

This ticket consumes services defined by AND-199 (stories) and AND-201 (gallery); it
defines no new endpoints. The contracts it depends on (verify against
`/openapi.json`):

**Stories tray** — `GET /ui/stories/tray`
```json
{
  "reels": [
    {
      "reel_id": "r_123",
      "author": { "name": "Ada", "avatar_url": "https://.../a.jpg" },
      "segment_count": 3,
      "seen": false,
      "updated_at": "2026-06-05T12:00:00Z"
    }
  ]
}
```

**Reel detail** — `GET /ui/stories/reels/{reel_id}`
```json
{
  "reel_id": "r_123",
  "segments": [
    { "segment_id": "s_1", "type": "image", "url": "https://.../1.jpg", "duration_ms": 5000 },
    { "segment_id": "s_2", "type": "video", "url": "https://.../2.m3u8", "duration_ms": 12000 }
  ]
}
```

**Mark reel seen** — `POST /ui/stories/reels/{reel_id}/seen` — body `{}`; returns `204`.
This is non-idempotent for retry purposes; it is fire-and-forget with at-most-one local
retry on transient network failure.

**Gallery page** — `GET /ui/gallery/items?album={album}&cursor={cursor}&limit=30`
```json
{
  "items": [
    { "id": "g_1", "thumb_url": "https://.../t1.jpg", "full_url": "https://.../f1.jpg",
      "width": 1080, "height": 1350, "is_video": false }
  ],
  "next_cursor": "eyJvIjoxMjB9"
}
```
`next_cursor` is `null` on the last page. All GETs ride the cookie session +
`X-CSRF-Token` header (echoed `ui_csrf` cookie) installed by the auth interceptor;
on `401` the OkHttp authenticator calls `POST /ui/session/refresh` once then retries
(owned by core-network).

Error bodies follow FastAPI `detail`: `string`, `[{ "msg": "..." }]`, or
`{ "code": "...", ... }`; mapping to user messages is delegated to the shared
`ApiResult`/`ErrorMapper` in `core-network`.

## 6. Data & State Management

- **Source of truth:** Repositories (AND-199/AND-201) return `ApiResult<T>` for tray
  and reel calls and a `Pager` for gallery. ViewModels never call Retrofit directly.
- **Caching:** Tray and reel responses are cached in Room (`core-data`) by the
  repositories; this ViewModel layer observes the cache as a `Flow` where available and
  reflects `isStale = true` when a refresh fails but cached content exists.
- **Saved state:** `StoriesViewModel` persists `lastOpenedReelId`; `StoryViewerViewModel`
  persists `entryReelId` (nav arg) plus `reelIndex`/`segmentIndex` for restoration;
  `GalleryViewModel` persists `album` filter and `lightbox.selectedIndex`. Paging
  position itself is not persisted across process death (Paging 3 reloads from refresh
  key = first visible item).
- **Immutability:** All UI-state classes are immutable `data class`/`data object`;
  updates use `MutableStateFlow.update { }`. Lists are read-only `List<>`.
- **Threading:** All repository calls run on `Dispatchers.IO` (injected
  `@IoDispatcher CoroutineDispatcher` from core); state assembly stays on the default
  collector. No work runs on the main thread beyond `StateFlow` emission.
- **stateIn:** Derived flows use
  `.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), initial)` so cache
  observation stops 5s after the UI detaches.

## 7. Error Handling & Resilience

- **Timeouts:** Inherit the core-network OkHttp config (~20s call timeout). On
  timeout/`IOException`, GET-backed states (tray, reel, gallery refresh/append) surface
  `Error(retryable = true)`.
- **Retry:** Idempotent GETs (tray, reel detail, gallery page) get bounded
  exponential backoff (max 2 retries, base 500 ms, jitter) inside the repository; the
  ViewModel additionally exposes `retry()` / `refresh()` for user-initiated retry.
  Paging append failures expose `LoadState.Error`; the UI calls `retry()` on the
  `LazyPagingItems`.
- **Non-idempotent calls:** `POST .../seen` is at-most-once with a single local retry;
  failure is swallowed (logged, not surfaced) since it is advisory.
- **Stale/offline:** When refresh fails but Room has data, emit `Content(isStale=true)`
  rather than `Error`, letting AND-199/AND-201 show a stale banner.
- **Empty vs error:** A `200` with empty `reels`/`items` yields `Empty`, never `Error`.
- **Timer safety:** The auto-advance ticker is cancelled in `onCleared()` and on
  `onClose()`; reel/segment index bounds are clamped so taps past the end emit
  `Finished` instead of throwing.

## 8. Security & Privacy

- No credentials, tokens, or PII are stored by these ViewModels. Session auth is
  cookie-based and handled entirely by the core-network cookie jar + CSRF interceptor;
  ViewModels never read or persist cookies.
- `SavedStateHandle` stores only non-sensitive ids (reel ids, album filter, indices).
- Media URLs are treated as opaque; they are passed to Coil/Media3 (AND-199/AND-201) and
  never logged at info level.
- The dev backend is plaintext HTTP; cleartext is permitted only for the dev flavor via
  the network-security-config owned by the build/config tickets, not here.

## 9. Accessibility & i18n

- This is a non-UI (state) ticket; it renders no composables. However, all
  user-facing strings produced by the ViewModels (error messages, empty-state copy)
  MUST be resolved from string resources via an injected resource provider
  (`StringProvider`) rather than hardcoded, so AND-199/AND-201 and translators can
  localize them. No string literals in state objects intended for display.
- Story segment durations and progress are exposed numerically so the UI can render
  accessible progress semantics and respect "reduce motion"; the ViewModel exposes a
  `prefersReducedMotion` hook (from DataStore) that, when true, disables auto-advance
  and requires explicit taps.
- Content descriptions and TalkBack semantics are the responsibility of the consuming UI
  tickets.

## 10. Telemetry & Logging

- Emit structured analytics events through the injected `Analytics` interface
  (core): `story_reel_opened` (reelId, position), `story_segment_viewed` (reelId,
  segmentId, completed: Boolean), `story_reel_completed`, `gallery_opened`,
  `gallery_page_loaded` (pageIndex, count), `gallery_lightbox_opened` (index).
- Log load failures at `WARN` with the mapped error code and HTTP status (no URLs with
  query secrets, no PII). Use the core `Logger`/Timber tree; no `println`.
- Paging `LoadState` transitions are logged at `DEBUG` only.

## 11. Testing Strategy

This ticket's acceptance is "unit-tested"; tests are JVM unit tests in
`feature-stories/src/test` and `feature-gallery/src/test` using JUnit4, kotlinx
`runTest`, `Turbine` for Flow assertions, `MockK` for repositories, and the
`MainDispatcherRule` + fake clock from `core-testing`.

- **StoriesViewModel:** loading -> content ordering (unseen before seen); empty list ->
  `Empty`; repository error -> `Error(retryable)`; refresh failure with cache ->
  `Content(isStale=true)`; `onReelClicked` persists `lastOpenedReelId`.
- **StoryViewerViewModel (virtual time):** builds correct playlist from entry reel;
  auto-advance moves segment after duration; `onHoldStart` pauses progress and
  `onHoldEnd` resumes from accrued time; `onTapNext/Previous` clamp at bounds;
  segment past 50% emits `MarkSeen`; last segment emits `Finished`; `onCleared`
  cancels the ticker (no leaked coroutine).
- **GalleryViewModel / GalleryPagingSource:** first page returns items + `nextKey`;
  `null` cursor terminates paging; mapper converts DTO -> `GalleryItemUi`;
  `setFilter` restarts paging (new `PagingData`); `onItemClicked` opens lightbox at
  index without resetting paging; `onLightboxClosed` resets `isOpen` only. Paging
  assertions use `AsyncPagingDataDiffer` or `PagingSource.load()` direct invocation.
- **Coverage target:** >= 85% line coverage for the three ViewModels and the paging
  source/mappers. No Android instrumentation required for this ticket; smoke/UI tests
  are AND-203.

## 12. Dependencies & Sequencing

- **Depends on AND-199** for `StoriesRepository`, the stories Retrofit service
  (`stories.ts` equivalent), and the tray/viewer composables that consume this state.
- **Depends on AND-201** for `GalleryRepository`, `Pager`/service (`gallery.ts`
  equivalent), and the grid/lightbox composables.
- **Depends transitively** on core-network (`ApiResult`, CSRF/refresh interceptor,
  cookie jar), core-data (Room cache), core-model (DTOs/domain), core-testing
  (`MainDispatcherRule`, fakes).
- **Blocks AND-203** (Stories/gallery UI smoke tests), which exercises these
  ViewModels through the composables.
- **Sequencing:** Land after AND-199 and AND-201 expose their repository interfaces.
  May proceed in parallel with their UI polish provided the repository contracts are
  frozen.

## 13. Risks & Open Questions

- **Repository contract drift:** If AND-199/AND-201 expose `Flow<ApiResult>` vs raw
  suspend functions differently than assumed, the ViewModel wiring changes. *Mitigation:*
  freeze repository interfaces before starting; depend on interfaces, not impls.
- **Paging + lightbox index stability:** Keeping lightbox selection valid as new pages
  load (and when items shift) needs item-id-based selection, not raw index.
  *Open question:* does AND-201's lightbox page by index or by item id? Prefer id;
  resolve with AND-201 owner.
- **Video segment duration:** Auto-advance for HLS/video segments depends on Media3
  reporting duration; if duration is unknown at start, fall back to the
  `duration_ms` from the reel-detail payload (capped 30s).
- **`seen` receipt semantics:** Backend may dedupe seen POSTs server-side; confirm via
  `/openapi.json` whether repeated POSTs are safe (affects retry policy).
- **Reduced-motion source:** Confirm the DataStore key for `prefersReducedMotion` is
  owned by a settings ticket; if absent, default to auto-advance enabled.

## 14. Acceptance Criteria

1. `StoriesViewModel`, `StoryViewerViewModel`, and `GalleryViewModel` exist in
   `feature-stories` / `feature-gallery` under `com.testlogon.android.feature.*`,
   each `@HiltViewModel`, each exposing `StateFlow<UiState>` (no `LiveData`).
2. Stories tray loads and orders unseen-before-seen; empty -> `Empty`; failure ->
   `Error`; failure-with-cache -> `Content(isStale=true)`.
3. Story viewer auto-advances by per-segment duration, supports tap-next/previous,
   hold-to-pause/resume, marks segments/reels seen past 50%, and emits `Finished` at
   the end of the playlist.
4. Gallery exposes a cursor-based Paging 3 `Flow<PagingData<GalleryItemUi>>` cached in
   `viewModelScope`; `null` cursor terminates paging; filter change restarts paging;
   lightbox open/close/page state is independent of paging recomposition.
5. All user-facing strings come from a resource provider, not literals; analytics
   events are emitted via the injected `Analytics` interface.
6. Unit tests pass with virtual-time coverage of the timer, paging-source load results,
   and all UI-state transitions; >= 85% line coverage on the three ViewModels and
   paging source/mappers.
7. No coroutine leaks: tickers and collectors are cancelled in `onCleared()`
   (verified by a leak test).

## 15. Definition of Done

- Code merged to `android-port` under `android/feature-stories` and
  `android/feature-gallery`; builds green with AGP 8.7.3 / Gradle 8.9 / JDK 17.
- All unit tests pass in CI (`./gradlew :feature-stories:testDebugUnitTest
  :feature-gallery:testDebugUnitTest`); coverage gate met.
- `ktlint`/`detekt` clean; no `LiveData`, no main-thread blocking, no hardcoded
  display strings.
- Public ViewModel/state contracts documented with KDoc and confirmed stable for
  AND-203.
- Open questions in section 13 resolved or explicitly tracked as follow-ups.
- Self-review against acceptance criteria complete; PR description links AND-199,
  AND-201 (deps) and AND-203 (blocked).
