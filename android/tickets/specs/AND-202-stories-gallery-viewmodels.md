---
id: AND-202
title: Stories/gallery ViewModels
milestone: M4
epic: E27
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference (verified):** `src/api/endpoints/stories.ts` (story-bar, per-user
  stories, view recording), `src/api/endpoints/gallery.ts` (video gallery browse),
  shared types in `src/api/types.ts`; screen behavior in `src/pages/feed/StoryViewer.tsx`,
  `src/pages/feed/StoryBar.tsx`, and `src/pages/gallery/GalleryPage.tsx`. Auth/CSRF
  transport in `src/api/client.ts`. OpenAPI authority: `GET /openapi.json` on the dev
  backend `http://18.222.237.167:8000` (plaintext HTTP, unreliable; ~20s timeouts).
  IMPORTANT: the backend stories domain is modelled as a **bar of user rings**, not
  "reels"/"segments"; throughout this spec "reel" denotes a single user's ordered story
  ring and "segment" denotes one `Story` within it (see §5 and §16).
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
   for video segments use `Story.duration_seconds * 1000`). NOTE: the backend field is
   `duration_seconds` (seconds), not `duration_ms`; the web client uses 5,000 ms for
   images and `duration_seconds * 1000` for video with **no upper cap**. The 30,000 ms
   cap below is an Android-side safety choice (see §13), not a backend-imposed limit.
7. Support intents: `onTapNext()`, `onTapPrevious()`, `onHoldStart()` (pause timer),
   `onHoldEnd()` (resume), `onReelSwipe(direction)` (jump reel), `onClose()`.
8. Mark a story (segment) seen and emit a one-shot effect to POST the view receipt
   (`POST /ui/stories/{story_id}/view`). NOTE: the web reference records the view
   **once, when the story first becomes visible** (deduped by a local per-story set),
   not at a 50% threshold. The Android port MAY adopt the same on-visible semantics
   (recommended, matching the web contract) or a >50%-viewed threshold as a deliberate
   product choice; whichever is chosen MUST be deduped per `story_id` and is safe to
   retry because the backend dedupes server-side (`already_viewed`). There is no
   separate "mark reel seen" endpoint; a user's ring is considered seen client-side once
   all its stories have been viewed (drives `has_unseen` re-fetch on next tray load).
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

// Mapped from StoryBarEntry { user_id, latest_story_id, latest_media_url,
// story_count, has_unseen, is_own }. The bar is keyed by USER, not "reel". The backend
// provides no author display name, avatar URL, or updatedAt on the bar entry — only
// latest_media_url (ring thumbnail) and story_count. seen = !has_unseen.
data class ReelSummaryUi(
    val userId: String,           // <- user_id (the "reel" is a user's story ring)
    val latestStoryId: String,    // <- latest_story_id
    val ringThumbUrl: String?,    // <- latest_media_url
    val seen: Boolean,            // <- !has_unseen
    val segmentCount: Int,        // <- story_count
    val isOwn: Boolean,           // <- is_own
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

// NOTE: the gallery endpoint returns video-centric items (GalleryVideoItem:
// video_id, title, thumbnail_url, duration_seconds, view_count, ...). It does NOT
// provide a distinct full-resolution URL, intrinsic width/height, or an is_video flag.
// The mapper derives the fields below: id = video_id, thumbUrl = thumbnail_url,
// title from title, durationSeconds from duration_seconds, isVideo = true (all gallery
// items are videos). width/height are NOT available from this endpoint and are dropped;
// the grid must size cells without intrinsic dimensions (or use a fixed aspect ratio).
data class GalleryItemUi(
    val id: String,            // <- video_id
    val thumbUrl: String?,     // <- thumbnail_url (optional in the DTO)
    val title: String,         // <- title
    val durationSeconds: Int?, // <- duration_seconds
    val isVideo: Boolean = true,
)
```

The gallery `PagingSource` (`GalleryPagingSource`, in `feature-gallery`, constructed by
`GalleryRepository.pager()`) is cursor-based: `LoadParams.key` is the opaque
`next_cursor` string; `load()` calls the AND-201 service and returns
`LoadResult.Page(data, prevKey = null, nextKey = response.cursor)` — the backend cursor
field is `cursor` (absent/`null` on the last page), NOT `next_cursor`. `PagingConfig`
uses `pageSize = 30, prefetchDistance = 10, initialLoadSize = 30, enablePlaceholders =
false`. UI mapping (`GalleryItemDto -> GalleryItemUi`) lives in a `pure` mapper
function so it is unit-testable without Paging machinery.

## 5. API Contract

This ticket consumes services defined by AND-199 (stories) and AND-201 (gallery); it
defines no new endpoints. The contracts below were **verified against the backend
OpenAPI spec and the frontend reference client** (`src/api/endpoints/stories.ts`,
`gallery.ts`, `types.ts`). NOTE: an earlier draft of this section invented a
"reels/segments/tray" model that does not exist in the backend; the real contract is a
**story-bar of users**, where each user has an ordered list of **Story** objects (the
"segments" of that user's ring). Corrections are summarized in §16.

**Story bar (tray)** — `GET /ui/stories/bar` (NOT `/ui/stories/tray`).
Response schema `StoryBarResp` = `{ "bar": StoryBarEntry[] }`:
```json
{
  "bar": [
    {
      "user_id": "u_123",
      "latest_story_id": "s_999",
      "latest_media_url": "https://.../a.jpg",
      "story_count": 3,
      "has_unseen": true,
      "is_own": false
    }
  ]
}
```
Unseen/seen is tracked per **user entry** via `has_unseen` (boolean), NOT a per-story
`seen` flag. There is no `author` object, `avatar_url`, `segment_count`, or `updated_at`
field; map `latest_media_url` for the ring thumbnail and `story_count` for the segment
count. `is_own` marks the current user's own ring.

**Per-user stories (reel detail)** — `GET /ui/stories/user/{user_id}` (NOT
`/ui/stories/reels/{reel_id}`). Response schema `UserStoriesResp` =
`{ "stories": Story[] }`:
```json
{
  "stories": [
    {
      "story_id": "s_1",
      "author_id": "u_123",
      "media_type": "image",
      "media_url": "https://.../1.jpg",
      "duration_seconds": 5,
      "created_at": "2026-06-05T12:00:00Z",
      "expires_at": 1749200000,
      "view_count": 12,
      "highlighted": false
    }
  ]
}
```
Fields are `media_type` (`"image" | "video"`), `media_url` (single URL, no separate
thumb/full), and `duration_seconds` (seconds, NOT `duration_ms`; absent for images).
There is no `segment_id`/`type`/`url`/`duration_ms`. A single story is also fetchable
via `GET /ui/stories/{story_id}` (schema `Story`).

**Record story view (mark seen)** — `POST /ui/stories/{story_id}/view` (NOT
`POST /ui/stories/reels/{reel_id}/seen`). Returns **`200`** with schema `StoryViewResp`
= `{ "ok": true, "already_viewed": false }` (NOT `204`, NOT an empty body). The backend
**dedupes server-side** (`already_viewed` reflects this), so the call is effectively
**idempotent** and safe to retry — resolving the §13 open question. The web client
records a view **once per story when that story first becomes visible** (deduped by a
local in-memory set), NOT at 50% and NOT only at end-of-reel.

**Gallery page** — `GET /ui/videos/gallery?category={category}&cursor={cursor}&limit={n}`
(NOT `/ui/gallery/items`; filter param is `category`, NOT `album`/`tag`). Response
schema `GalleryListOut` (frontend `GalleryListResponse`):
```json
{
  "videos": [
    {
      "video_id": "g_1",
      "title": "Clip",
      "thumbnail_url": "https://.../t1.jpg",
      "duration_seconds": 42,
      "category": "music",
      "tags": [],
      "view_count": 100,
      "like_count": 5,
      "owner_user_id": "u_9",
      "created_at": 1749100000
    }
  ],
  "categories": [{ "slug": "music", "label": "Music" }],
  "cursor": "eyJvIjoxMjB9"
}
```
The page list is under **`videos`** (NOT `items`); the cursor field is **`cursor`** (NOT
`next_cursor`) and is absent/`undefined` (`null`) on the last page. Items are
**video-centric** (`video_id`, `title`, `thumbnail_url`, `duration_seconds`,
`view_count`, `like_count`, `owner_user_id`): there is **no** `id`/`thumb_url`/`full_url`/
`width`/`height`/`is_video`. The Android `GalleryItemUi` mapper must derive its fields
from these (e.g. `id = video_id`, `thumbUrl = thumbnail_url`, treat all gallery items as
video; intrinsic width/height are NOT provided by this endpoint). Related browse
endpoints also exist if needed: `GET /ui/videos/gallery/categories`,
`GET /ui/videos/gallery/search?q=`, `GET /ui/videos/gallery/for-you`, and the
short-form `GET /ui/clips`.

All authenticated calls ride the cookie session + `X-CSRF-Token` request header whose
value is read from the `ui_csrf` cookie (verified in `src/api/client.ts`); on `401` the
client calls `POST /ui/session/refresh` once, then retries the original request (this is
owned by core-network in the Android port). Note the OpenAPI also lists header params
`X-SESSION-ID` / `X-IMPERSONATION-TOKEN` / `user_sub` on these routes; the web client
relies on the cookie session and CSRF header rather than those, and the Android port
should follow the web client's transport contract.

Error bodies follow FastAPI conventions: validation failures return **`422`** with
`HTTPValidationError` = `{ "detail": [{ "loc": [...], "msg": "...", "type": "..." }] }`
(verified: `components.schemas.HTTPValidationError` / `ValidationError`). Other errors
return `detail` as a string. Mapping to user messages is delegated to the shared
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
- **Video segment duration:** Auto-advance for video segments depends on Media3
  reporting duration; if duration is unknown at start, fall back to the
  `duration_seconds` from the per-user stories payload (`Story.duration_seconds`,
  multiplied by 1000). The 30s cap is an Android-side guard, not backend-imposed.
- **`seen` receipt semantics:** RESOLVED. `POST /ui/stories/{story_id}/view` returns
  `200 { ok, already_viewed }` and dedupes server-side, so repeated POSTs are safe and
  retry is harmless (idempotent in effect). Local per-`story_id` dedup still recommended
  to avoid redundant network calls.
- **Reduced-motion source:** Confirm the DataStore key for `prefersReducedMotion` is
  owned by a settings ticket; if absent, default to auto-advance enabled.

## 14. Acceptance Criteria

1. `StoriesViewModel`, `StoryViewerViewModel`, and `GalleryViewModel` exist in
   `feature-stories` / `feature-gallery` under `com.testlogon.android.feature.*`,
   each `@HiltViewModel`, each exposing `StateFlow<UiState>` (no `LiveData`).
2. Stories tray loads and orders unseen-before-seen; empty -> `Empty`; failure ->
   `Error`; failure-with-cache -> `Content(isStale=true)`.
3. Story viewer auto-advances by per-segment duration (5,000 ms images; video
   `duration_seconds * 1000`), supports tap-next/previous, hold-to-pause/resume, records
   each story view via `POST /ui/stories/{story_id}/view` (deduped per `story_id`), and
   emits `Finished` at the end of the playlist.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Story bar/tray endpoint is `GET /ui/stories/bar`.** VERDICT: Corrected (draft said
   `GET /ui/stories/tray`, which does not exist). SOURCE: OpenAPI `GET /ui/stories/bar`
   (op `get_story_bar_endpoint_...`); frontend `src/api/endpoints/stories.ts: getStoryBar`.
2. **Story-bar response shape is `{ bar: StoryBarEntry[] }` with fields `user_id`,
   `latest_story_id`, `latest_media_url`, `story_count`, `has_unseen`, `is_own`.**
   VERDICT: Corrected (draft invented `reels[].{reel_id, author{name,avatar_url},
   segment_count, seen, updated_at}`). SOURCE: `src/api/types.ts: StoryBarResp`,
   `StoryBarEntry`.
3. **Per-user stories (reel detail) endpoint is `GET /ui/stories/user/{user_id}` →
   `{ stories: Story[] }`.** VERDICT: Corrected (draft said
   `GET /ui/stories/reels/{reel_id}` with `segments[]`). SOURCE: OpenAPI
   `GET /ui/stories/user/{user_id}` (op `get_user_stories_endpoint_...`); frontend
   `src/api/endpoints/stories.ts: getUserStories`; `src/api/types.ts: UserStoriesResp`.
4. **`Story` fields are `media_type` (`image|video`), `media_url`, `duration_seconds`
   (seconds, optional), `story_id`, `author_id`, etc.** VERDICT: Corrected (draft used
   `segment_id`, `type`, `url`, `duration_ms`). SOURCE: `src/api/types.ts: Story`.
5. **A single story is fetchable via `GET /ui/stories/{story_id}` (schema `Story`).**
   VERDICT: Verified. SOURCE: OpenAPI `GET /ui/stories/{story_id}` (op
   `get_story_endpoint_...`); frontend `src/api/endpoints/stories.ts: getStory`.
6. **Mark-seen / view-record endpoint is `POST /ui/stories/{story_id}/view`, returns
   `200 { ok, already_viewed }`, server-side deduped (idempotent in effect).** VERDICT:
   Corrected (draft said `POST /ui/stories/reels/{reel_id}/seen`, body `{}`, `204`,
   non-idempotent). SOURCE: OpenAPI `POST /ui/stories/{story_id}/view` (op
   `record_view_endpoint_...`); `src/api/endpoints/stories.ts: recordStoryView`;
   `src/api/types.ts: StoryViewResp { ok, already_viewed }`.
7. **Web client records a view once per story when it becomes visible (deduped locally),
   not at 50% nor only at reel end.** VERDICT: Corrected the draft's "past 50%" /
   "last segment completes" claim (now noted as an optional Android product choice).
   SOURCE: `src/pages/feed/StoryViewer.tsx` (`viewedSetRef` + `recordStoryView` in the
   on-visible `useEffect`).
8. **Story auto-advance: images 5,000 ms; video `duration_seconds * 1000`; no backend
   cap.** VERDICT: Corrected (draft's `duration_ms` field and "capped at 30,000 ms" as
   if backend-imposed). The 30s cap is retained as an explicit Android-side guard.
   SOURCE: `src/pages/feed/StoryViewer.tsx` (`SLIDE_DURATION_MS = 5000`,
   `duration_seconds * 1000`).
9. **Gallery page endpoint is `GET /ui/videos/gallery?category=&cursor=&limit=`.**
   VERDICT: Corrected (draft said `GET /ui/gallery/items?album=&cursor=&limit=30`, which
   does not exist; filter param is `category`, not `album`/`tag`). SOURCE: OpenAPI
   `GET /ui/videos/gallery` (op `browse_gallery_endpoint_...`, params
   `category,limit,cursor`); frontend `src/api/endpoints/gallery.ts: browseGallery`.
10. **Gallery response shape: `{ videos: GalleryVideoItem[], categories, cursor? }`;
    page list under `videos`; pagination field `cursor` (absent on last page).** VERDICT:
    Corrected (draft used `items[]` and `next_cursor`). SOURCE:
    `src/api/endpoints/gallery.ts: GalleryListResponse`; OpenAPI resp `GalleryListOut`.
11. **`GalleryVideoItem` fields are video-centric (`video_id`, `title`, `thumbnail_url`,
    `duration_seconds`, `view_count`, `like_count`, `owner_user_id`, ...); no `id`,
    `thumb_url`, `full_url`, `width`, `height`, or `is_video`.** VERDICT: Corrected
    (draft's item shape). SOURCE: `src/api/endpoints/gallery.ts: GalleryVideoItem`.
12. **Auth transport: `X-CSRF-Token` request header sourced from the `ui_csrf` cookie;
    on `401`, `POST /ui/session/refresh` once then retry.** VERDICT: Verified. SOURCE:
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`;
    `refreshSession()` → `POST /ui/session/refresh` on `401` then retry).
13. **Validation errors return `422` with `HTTPValidationError`
    `{ detail: [{ loc, msg, type }] }`; other errors return `detail` as a string.**
    VERDICT: Corrected the draft's loose claim of an arbitrary `{ "code": ... }` body.
    SOURCE: OpenAPI `components.schemas.HTTPValidationError` and `ValidationError`;
    `src/api/client.ts: normalizeErrorDetail`.
14. **Web gallery uses `limit: 48`; Android spec uses `pageSize = 30`.** VERDICT:
    Unverified-assumption (Android paging choice; not dictated by backend). SOURCE:
    `src/pages/gallery/GalleryPage.tsx` (`browseGallery({ category, limit: 48 })`) vs
    spec §4 `PagingConfig`.
15. **Cursor is an opaque string passed back as `cursor`; web browse uses TanStack Query
    keyed by category rather than incremental cursor paging in the visible page code.**
    VERDICT: Verified (cursor opaque, supported by endpoint) / partially
    Unverified-assumption (the Paging-3 cursor loop is an Android design; the web page
    shown does not demonstrate multi-page cursor fetching). SOURCE:
    `src/api/endpoints/gallery.ts: browseGallery` (cursor param);
    `src/pages/gallery/GalleryPage.tsx`.
16. **Repository interfaces (`StoriesRepository`, `GalleryRepository`), `ApiResult<T>`,
    Room cache, `ErrorMapper`, CSRF/refresh interceptor are provided by
    AND-199/AND-201/core-network/core-data.** VERDICT: Unverified-assumption (upstream
    Android tickets not present in sources). SOURCE: n/a (cross-ticket dependency).
17. **Reduced-motion (`prefersReducedMotion`) DataStore key owned by a settings ticket.**
    VERDICT: Unverified-assumption (no such key in sources). SOURCE: n/a.
18. **Framework: Paging 3 cursor `PagingSource` with `LoadResult.Page(prevKey=null,
    nextKey=cursor)`; `cachedIn(viewModelScope)`; `SavedStateHandle`; `StateFlow` +
    `Channel`-backed effects.** VERDICT: Verified (framework ref). SOURCE: framework ref
    https://developer.android.com/topic/libraries/architecture/paging/v3-paged-data and
    https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate

### Corrections made

- §5 rewritten: stories endpoints `tray→bar`, `reels/{reel_id}→user/{user_id}`,
  `reels/{reel_id}/seen→{story_id}/view`; response shapes (`bar/StoryBarEntry`,
  `stories/Story`, `StoryViewResp`); gallery endpoint `/ui/gallery/items→/ui/videos/gallery`,
  param `album→category`, list `items→videos`, cursor `next_cursor→cursor`, item shape
  to `GalleryVideoItem`; view-record `204→200` and re-classified as idempotent; error
  body clarified to FastAPI `422 HTTPValidationError`.
- §2: web-reference bullet corrected to real file paths and the user-ring model note.
- §3 FR6/FR8: `duration_ms→duration_seconds`, removed false backend 30s cap, corrected
  seen semantics to on-visible per-story view recording.
- §4: `ReelSummaryUi` and `GalleryItemUi` data classes remapped to real backend fields;
  `GalleryPagingSource` nextKey `response.nextCursor→response.cursor`.
- §13: `seen` receipt open question marked RESOLVED (idempotent); video-duration
  fallback field corrected.
- §14 AC-3 reworded to accurate durations and view-recording.
- Frontmatter: `status: reviewed`, `reviewed_on: 2026-06-06`.

### Open assumptions

- Android `pageSize = 30` and the cursor Paging-3 loop are design choices; the web app
  shows `limit: 48` and query-key (not incremental-cursor) browsing — backend supports
  cursor but the multi-page loop is unverified against web behavior (claims 14, 15).
- Upstream Android contracts (`StoriesRepository`, `GalleryRepository`, `ApiResult`,
  Room cache, `ErrorMapper`, CSRF/refresh OkHttp interceptor) are assumed from
  AND-199/AND-201/core-* and cannot be verified from the provided sources (claim 16).
- `prefersReducedMotion` DataStore ownership is unverified; default to auto-advance
  enabled if absent (claim 17).
- Gallery item intrinsic `width`/`height` are not provided by the endpoint; grid sizing
  must use a fixed aspect ratio or Coil intrinsic measurement (derived from claim 11).
- The 30,000 ms video-duration cap is an Android safety guard with no backend basis.

## 17. Test Plan

JVM unit/Robolectric cases run on the local JVM (no device). UI/instrumented cases run
on the headless emulator AVD `test35` (x86_64, API 35) unless they exercise real
hardware/network behavior, in which case they run on the **physical Samsung Galaxy A15
5G (SM-A156U, API 34, arm64-v8a)** — noted per case. This ticket's core acceptance is
unit-tested ViewModels; instrumented/device cases are included for the resilience and
ABI/API-skew surfaces and are otherwise deferred to AND-203.

Test targets legend: JVM = JVM unit/Robolectric; EMU = emulator `test35`; DEV = physical
device SM-A156U.

- **TC-AND-202-01** — Type: contract/MockWebServer (JVM). Target: JVM (MockWebServer).
  Preconditions: MockWebServer enqueues `200` for `GET /ui/stories/bar` with a
  `StoryBarResp` of 2 unseen + 1 seen entries (mixed `has_unseen`). Steps: instantiate
  `StoriesViewModel`; collect `uiState` with Turbine. Expected: terminal state
  `Content` with reels ordered **unseen-before-seen**, each `ReelSummaryUi` mapped from
  `user_id`/`latest_story_id`/`latest_media_url`/`story_count`/`has_unseen`/`is_own`;
  request path is exactly `/ui/stories/bar` and carries the `X-CSRF-Token` header.
  Traces: AC-1, AC-2.
- **TC-AND-202-02** — Type: unit (JVM). Target: JVM. Preconditions: repository returns
  `Content` with an empty `bar`. Steps: init `StoriesViewModel`; collect `uiState`.
  Expected: state is `Empty` (NOT `Error`, NOT `Content` with empty list). Traces: AC-2.
- **TC-AND-202-03** — Type: unit (JVM). Target: JVM. Preconditions: repository returns
  `ApiResult` failure (IOException) and Room cache is empty. Steps: init; collect.
  Expected: `Error(retryable=true)`; calling `refresh()` re-issues the load. Traces: AC-2.
- **TC-AND-202-04** — Type: unit (JVM). Target: JVM. Preconditions: live `bar` request
  fails but Room has a cached bar. Steps: init; trigger `refresh()` that fails.
  Expected: `Content(isStale=true)` with cached reels (stale path, not `Error`).
  Traces: AC-2.
- **TC-AND-202-05** — Type: contract/MockWebServer (JVM). Target: JVM (MockWebServer).
  Preconditions: `GET /ui/stories/user/{user_id}` returns `UserStoriesResp` with 1 image
  (`duration_seconds` absent) + 1 video (`duration_seconds=12`). Steps: build
  `StoryViewerViewModel` with virtual `TimeSource`; let the image segment elapse.
  Expected: playlist built from `stories[]` in order; image auto-advances at 5,000 ms;
  video segment duration computed as `12 * 1000` ms; `progress` ticks 0→1. Traces:
  AC-3, AC-6.
- **TC-AND-202-06** — Type: unit, virtual time (JVM). Target: JVM. Preconditions:
  viewer with a 2-segment reel. Steps: call `onHoldStart()` mid-segment, advance virtual
  time, call `onHoldEnd()`, advance remaining time. Expected: progress freezes during
  hold and resumes from accrued elapsed (no skip/reset); `onTapNext`/`onTapPrevious`
  clamp at first/last index. Traces: AC-3.
- **TC-AND-202-07** — Type: contract/MockWebServer (JVM). Target: JVM (MockWebServer).
  Preconditions: `POST /ui/stories/{story_id}/view` enqueued `200 {ok:true,
  already_viewed:false}`. Steps: advance the viewer so a story becomes visible.
  Expected: exactly one POST to `/ui/stories/{story_id}/view` per `story_id` (deduped on
  revisit); a `MarkSeen`/view effect is emitted; the call body is empty/none. Negative:
  a second visit to the same story issues **no** additional POST. Traces: AC-3.
- **TC-AND-202-08** — Type: unit (JVM). Target: JVM. Preconditions: viewer at last
  segment of last reel. Steps: trigger advance past the end. Expected: a single
  `Finished` effect is emitted (one-shot, via `Channel` flow), and indices stay clamped
  (no `IndexOutOfBounds`). Traces: AC-3.
- **TC-AND-202-09** — Type: unit / leak test (JVM). Target: JVM. Preconditions: viewer
  with an active ticker. Steps: call `onClose()` / trigger `onCleared()`; advance virtual
  time. Expected: ticker coroutine and all collectors are cancelled; no further `progress`
  emissions; no leaked coroutine (assert via `TestScope`/`UncaughtException` or job
  state). Traces: AC-7.
- **TC-AND-202-10** — Type: contract/MockWebServer (JVM). Target: JVM (MockWebServer).
  Preconditions: `GET /ui/videos/gallery` page 1 returns `{videos:[...30], cursor:"c2"}`,
  page 2 returns `{videos:[...], cursor:null}`. Steps: drive `GalleryPagingSource.load()`
  directly (REFRESH then APPEND) or via `AsyncPagingDataDiffer`. Expected: page 1
  `LoadResult.Page(nextKey="c2")`; page 2 `nextKey=null` terminates paging; request path
  is `/ui/videos/gallery` with `limit` and `cursor` query params (NOT `/ui/gallery/items`,
  NOT `album`). Traces: AC-4.
- **TC-AND-202-11** — Type: unit, pure mapper (JVM). Target: JVM. Preconditions: a
  `GalleryVideoItem` DTO. Steps: call the DTO→`GalleryItemUi` mapper. Expected:
  `id=video_id`, `thumbUrl=thumbnail_url`, `title=title`, `durationSeconds=duration_seconds`,
  `isVideo=true`; mapper tolerates absent optional fields (`thumbnail_url`,
  `duration_seconds` null). Traces: AC-4, AC-6.
- **TC-AND-202-12** — Type: unit (JVM). Target: JVM. Preconditions: `GalleryViewModel`
  with `pagingData` collected. Steps: call `setFilter("music")` (category). Expected:
  paging restarts with a new `PagingData` whose requests carry `category=music`; then
  `onItemClicked(i)` opens the lightbox at index `i` **without** resetting `pagingData`;
  `onLightboxClosed()` sets `isOpen=false` only (selectedIndex unaffected); lightbox
  `StateFlow` is independent of paging recomposition. Traces: AC-4.
- **TC-AND-202-13** — Type: unit (JVM). Target: JVM. Preconditions: `MockK` `Analytics`
  and `StringProvider`. Steps: drive open/page/lightbox flows. Expected: analytics events
  (`gallery_opened`, `gallery_page_loaded`, `gallery_lightbox_opened`, `story_reel_opened`,
  `story_segment_viewed`) emitted via the injected interface; all user-facing error/empty
  strings resolved through `StringProvider`, with **no** hardcoded display literals in
  state objects. Traces: AC-5.
- **TC-AND-202-14** — Type: contract/MockWebServer, security (JVM). Target: JVM
  (MockWebServer). Preconditions: first `GET` returns `401`; refresh endpoint
  `POST /ui/session/refresh` returns `200`; retried `GET` returns `200`. Steps: issue a
  gallery/tray load. Expected: client sends `X-CSRF-Token` from the `ui_csrf` cookie,
  performs exactly **one** `/ui/session/refresh`, then retries once and succeeds;
  `SavedStateHandle` persists only non-sensitive ids (no cookies/tokens). Negative: an
  unauthenticated `401` (no prior session) surfaces `Error` without a refresh loop.
  Traces: AC-1, AC-2, AC-4.
- **TC-AND-202-15** — Type: instrumented/e2e, resilience (DEV — physical device).
  Target: DEV (SM-A156U, API 34, arm64-v8a). MUST run on the physical device to exercise
  real flaky-dev-host/offline behavior over the cellular/real-network stack and the
  arm64 ABI (the emulator's x86_64 + virtual network does not reproduce real timeout
  jitter). Preconditions: app pointed at the unreliable dev backend; toggle airplane
  mode / induce a slow link mid-load. Steps: open gallery then stories while the network
  drops. Expected: GET-backed loads surface `Error(retryable=true)` on timeout/IO,
  `retry()`/`refresh()` recover when connectivity returns, stale cache is shown with
  `isStale=true` rather than `Error`, and the view-record POST is at-most-once with the
  server dedupe preventing duplicates. Traces: AC-2, AC-3.
- **TC-AND-202-16** — Type: Compose-UI / accessibility (EMU). Target: EMU `test35`.
  Preconditions: AND-199/AND-201 composables wired to these ViewModels (smoke harness).
  Steps: render story viewer + gallery grid; run an accessibility/semantics check
  (TalkBack semantics, progress `stateDescription`, min touch-target sizes); toggle the
  `prefersReducedMotion` hook. Expected: progress is exposed numerically for accessible
  semantics; when reduced-motion is on, auto-advance is disabled and explicit taps are
  required; content descriptions are present on interactive elements. NOTE: this overlaps
  AND-203 and is included only to assert the ViewModel's a11y hooks
  (`prefersReducedMotion`, numeric progress) are consumable. Traces: AC-1, AC-3, AC-5.

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
| --- | --- |
| AC-1 (ViewModels exist, `@HiltViewModel`, `StateFlow`, no `LiveData`) | TC-01, TC-14, TC-16 |
| AC-2 (tray load/order, Empty/Error/stale) | TC-01, TC-02, TC-03, TC-04, TC-14, TC-15 |
| AC-3 (viewer auto-advance, hold/pause, view-record, Finished) | TC-05, TC-06, TC-07, TC-08, TC-15, TC-16 |
| AC-4 (cursor paging, null-terminate, filter restart, lightbox independence) | TC-10, TC-11, TC-12, TC-14 |
| AC-5 (resource-provided strings, analytics) | TC-13, TC-16 |
| AC-6 (unit tests: virtual-time timer, paging loads, transitions; coverage) | TC-05, TC-10, TC-11 (+ all unit TCs contribute to coverage) |
| AC-7 (no coroutine leaks; cancelled in `onCleared()`) | TC-09 |
