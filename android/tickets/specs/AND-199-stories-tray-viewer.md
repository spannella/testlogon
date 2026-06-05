---
id: AND-199
title: Stories tray + viewer
milestone: M4
epic: E27
priority: P1
size: L
status: draft
depends_on: [AND-168]
blocks: [AND-200]
---

# AND-199 — Stories tray + viewer

## 1. Overview & Goal

Deliver the Stories surface for the TestLogon native Android client: a horizontally
scrollable **tray** of per-author story rings rendered above the feed, and a
**full-screen viewer** that opens when a ring is tapped and auto-advances through an
author's story segments (image or video) and then on to the next author. This ticket
owns the data layer (`stories.ts`-equivalent Kotlin API + repository), the tray
composable, and the viewer shell with auto-advance and seen/unseen state. Manual
segment progress bars, tap-to-skip navigation gestures, and reactions/replies are
explicitly **out of scope** and owned by the downstream ticket **AND-200**.

The acceptance bar is concrete: tapping a tray ring opens the viewer, and segments
auto-advance on a timer (images) or on video completion (clips), rolling forward to
the next author and dismissing cleanly at the end of the tray. The viewer reuses the
shared player from **AND-168** for video segments rather than instantiating its own
ExoPlayer.

Module placement: a new `feature-stories` module under the established
`app -> feature-* -> core-*` layering, namespace
`com.testlogon.android.feature.stories`.

## 2. Context & References

- **Web reference:** `frontend/src/api/endpoints/stories.ts` (authoritative endpoint
  shapes and query params) and shared types in `frontend/src/api/types.ts`
  (`Story`, `StorySegment`, `StoryAuthor`). The native API surface mirrors these.
- **Backend:** FastAPI + DynamoDB; OpenAPI at `/openapi.json`. Dev host
  `http://18.222.237.167:8000` is plaintext HTTP and unreliable — see §7.
- **Upstream dependency AND-168 (Reusable player UI):** provides the shared
  `PlayerManager` wrapper and `VideoPlayerSurface` Composable with controls,
  buffering/error states, and lifecycle-aware release. Video story segments embed
  this surface in a chrome-suppressed mode (no scrubber/controls shown).
- **Transitive deps (already merged before this ticket):** AND-166 (Media3
  integration / `PlayerManager`), AND-167 (HLS playback), AND-009–AND-018
  (network stack: OkHttp timeouts, Retrofit/Moshi, cookie jar, CSRF interceptor,
  401 refresh authenticator, `ApiResult<T>`, retry/backoff), AND-019–AND-021
  (Material 3 theme, state composables), AND-022/AND-024 (nav host, authenticated
  graph).
- **Downstream AND-200 (Story progress + reactions):** consumes the viewer scaffold
  built here and adds segment progress bars, tap-zone navigation, and
  reactions/replies. Hooks for those are stubbed (§3, §6) but not implemented.

## 3. Functional Requirements

FR-1. **Tray fetch & display.** On entering the feed/home authenticated route, the
tray loads the current user's available stories via `GET /ui/stories`. Each entry is
one author with one or more segments. The tray renders a horizontally scrolling
`LazyRow` of circular avatars with a gradient ring.

FR-2. **Seen/unseen ordering & styling.** Authors with at least one unseen segment
sort before fully-seen authors; unseen authors render a vivid gradient ring, fully
seen authors render a muted gray ring. "Seen" is derived from the per-segment
`seen` flag returned by the API and the local viewed set (§6).

FR-3. **Open viewer.** Tapping a tray ring opens the full-screen viewer positioned at
that author and at the author's first unseen segment (or segment 0 if all seen).

FR-4. **Auto-advance within an author.** Image segments auto-advance after a fixed
display duration (default 5000 ms, overridable by `segment.durationMs`). Video
segments advance when playback completes (or after `durationMs` as a ceiling).

FR-5. **Auto-advance across authors.** After the last segment of the current author,
the viewer advances to the next author in tray order; after the last author it
dismisses and returns to the feed.

FR-6. **Mark seen.** When a segment becomes the active segment, fire
`POST /ui/stories/{storyId}/segments/{segmentId}/seen` (fire-and-forget, debounced)
and update the local viewed set so the tray ring restyles on return.

FR-7. **Pause on hold.** Press-and-hold anywhere on the viewer pauses the auto-advance
timer (and the video, via `PlayerManager.pause()`); release resumes. This is the
minimum gesture; richer tap-zone navigation is AND-200.

FR-8. **Dismiss.** A close affordance (top-right X) and the system back gesture both
dismiss the viewer and return to the prior route, releasing the player.

FR-9. **Empty/offline.** If the tray returns zero authors, the tray is hidden (height
0). If the fetch fails offline, show the last cached tray (stale) per §6/§7.

FR-10. **Loading.** While a segment's media buffers, show the shared buffering state
from AND-168 (video) or a Coil placeholder (image); the auto-advance timer for images
does not start until the bitmap is decoded.

Out of scope (AND-200): per-segment progress bars, tap-left/tap-right navigation,
reaction emoji bar, reply composer.

## 4. Technical Design

New module `feature-stories`:

```
feature-stories/
  api/StoriesApi.kt
  data/StoriesRepository.kt
  data/StoriesDtos.kt
  model/Story.kt  model/StorySegment.kt
  ui/tray/StoriesTray.kt        ui/tray/StoryRing.kt
  ui/viewer/StoryViewerScreen.kt ui/viewer/StoryViewerViewModel.kt
  ui/viewer/StorySegmentContent.kt
  di/StoriesModule.kt
```

**Models (`core-model`-style, immutable):**

```kotlin
data class StoryAuthor(
    val id: String, val username: String, val avatarUrl: String?,
)
data class StorySegment(
    val id: String,
    val storyId: String,
    val kind: SegmentKind,          // IMAGE | VIDEO
    val mediaUrl: String,           // image URL or HLS/MP4 URL
    val durationMs: Long,           // server hint; default 5000 for image
    val createdAt: Instant,
    val seen: Boolean,
)
enum class SegmentKind { IMAGE, VIDEO }
data class Story(
    val id: String,
    val author: StoryAuthor,
    val segments: List<StorySegment>,
) {
    val hasUnseen: Boolean get() = segments.any { !it.seen }
    val firstUnseenIndex: Int get() = segments.indexOfFirst { !it.seen }.coerceAtLeast(0)
}
```

**Repository:**

```kotlin
interface StoriesRepository {
    fun trayFlow(): Flow<ApiResult<List<Story>>>     // cached-then-network
    suspend fun refreshTray(): ApiResult<Unit>
    suspend fun markSeen(storyId: String, segmentId: String): ApiResult<Unit>
}
```

`StoriesRepositoryImpl` emits a Room-cached tray immediately (stale) then triggers a
network refresh on the `GET` path (idempotent → eligible for the AND-016 bounded
backoff retry). `markSeen` is a non-idempotent `POST` → **no** retry; failures are
logged and dropped (the local viewed set is the source of truth for UI).

**Viewer state machine (ViewModel):**

```kotlin
@HiltViewModel
class StoryViewerViewModel @Inject constructor(
    private val repo: StoriesRepository,
    val playerManager: PlayerManager,            // shared, AND-168
    savedStateHandle: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<StoryViewerUiState>
    fun onSegmentShown(s: StorySegment)          // marks seen, starts timer/player
    fun onSegmentComplete()                       // advance within/across author
    fun onPauseHold(paused: Boolean)
    fun onClose()
}

data class StoryViewerUiState(
    val authors: List<Story> = emptyList(),
    val authorIndex: Int = 0,
    val segmentIndex: Int = 0,
    val paused: Boolean = false,
    val phase: ViewerPhase = ViewerPhase.Loading, // Loading|Playing|Error|Done
)
```

Auto-advance for images uses a cancellable coroutine timer:

```kotlin
private fun startImageTimer(durationMs: Long) {
    timerJob?.cancel()
    timerJob = viewModelScope.launch {
        var remaining = durationMs
        while (remaining > 0) {
            if (!_uiState.value.paused) { delay(TICK); remaining -= TICK }
            else delay(TICK)
        }
        onSegmentComplete()
    }
}
```

Video segments call `playerManager.play(mediaUrl)` and observe its
`PlayerState.ended` to trigger `onSegmentComplete()`; the shared surface is rendered
with controls disabled.

**Composables:**

```kotlin
@Composable fun StoriesTray(
    state: ApiResult<List<Story>>,
    onRingClick: (storyId: String) -> Unit,
    modifier: Modifier = Modifier,
)
@Composable fun StoryRing(author: StoryAuthor, hasUnseen: Boolean, onClick: () -> Unit)
@Composable fun StoryViewerScreen(vm: StoryViewerViewModel, onDismiss: () -> Unit)
@Composable fun StorySegmentContent(segment: StorySegment, playerSurface: @Composable () -> Unit)
```

**Navigation (AND-022/024):** the viewer is a full-screen composable route on the
authenticated nav graph:

```kotlin
const val storyViewerRoute = "stories/viewer/{storyId}"
fun NavController.openStoryViewer(storyId: String) =
    navigate("stories/viewer/$storyId")
```

`storyId` is the entry author; the ViewModel resolves the tray list from the cached
repository flow so it can advance across authors.

## 5. API Contract

Base path `/ui/stories`. All calls carry session cookies + `X-CSRF-Token`
(echoed `ui_csrf` cookie) via existing interceptors (AND-011/012).

**GET `/ui/stories`** — fetch the tray (idempotent).
Response `200`:

```json
{
  "stories": [
    {
      "id": "stry_01H...",
      "author": { "id": "usr_42", "username": "ada", "avatarUrl": "https://.../a.jpg" },
      "segments": [
        { "id": "seg_1", "kind": "image", "mediaUrl": "https://.../1.jpg",
          "durationMs": 5000, "createdAt": "2026-06-05T12:00:00Z", "seen": false },
        { "id": "seg_2", "kind": "video", "mediaUrl": "https://.../2.m3u8",
          "durationMs": 12000, "createdAt": "2026-06-05T12:01:00Z", "seen": false }
      ]
    }
  ]
}
```

**POST `/ui/stories/{storyId}/segments/{segmentId}/seen`** — mark a segment viewed
(non-idempotent; no retry). Request body empty. Response `204` (no content). A `404`
(segment expired) is treated as success for UI purposes.

**DTOs & mapping (Moshi, AND-026 pattern):** `StoriesResponseDto`, `StoryDto`,
`StoryAuthorDto`, `StorySegmentDto`. `kind` is a lowercase string mapped to
`SegmentKind` via a custom adapter (unknown → `IMAGE` fallback, logged). Missing
`durationMs` defaults to `5000`. `createdAt` parsed as ISO-8601 `Instant`.

**Error envelope:** FastAPI `detail` mapped through the shared AND-015 mapper
(string | `[{msg}]` | `{code,...}`) into `ApiResult.Failure`. On `401` the AND-013
authenticator performs a single `POST /ui/session/refresh` then retries the GET.

If the live OpenAPI diverges (e.g., flattened `stories` array vs. envelope), the DTO
layer is the single point of adaptation; mappers must be tolerant of additional
unknown fields (`@JsonClass(generateAdapter = true)` ignores extras).

## 6. Data & State Management

- **Cache (Room 2.6, in `core-data` style):** `StoryEntity`, `StorySegmentEntity`
  with a `lastFetchedAt` column. `trayFlow()` is backed by `@Query` returning the
  cached authors/segments joined, exposed as a `Flow`, so the tray paints instantly
  on cold start (stale). Network refresh upserts and bumps `lastFetchedAt`.
- **Viewed set (DataStore prefs):** a `Set<String>` of seen `segmentId`s persisted so
  ring styling survives process death and reflects the optimistic mark before the
  `POST` lands. Merged with server `seen` flags (OR semantics).
- **StateFlow exposure:** ViewModel exposes `StateFlow<StoryViewerUiState>`; the tray
  consumer collects `repo.trayFlow()` mapped to `ApiResult<List<Story>>`.
- **Player ownership:** the shared `PlayerManager` (AND-168) is injected, not owned;
  the viewer calls `play/pause/stop` and releases on `onDispose`/back so it never
  leaks across navigation. Only one segment plays at a time (single-player reuse from
  AND-166).
- **Process-death restore:** `SavedStateHandle` persists `authorIndex`/`segmentIndex`
  so the viewer reopens on the same segment after recreation.
- **AND-200 hook:** the `StoryViewerUiState` already carries `segmentIndex` and a
  per-segment list so the downstream progress-bar/reactions ticket adds fields
  without reshaping the state class.

## 7. Error Handling & Resilience

- **Unreliable dev host:** OkHttp timeouts ~20s (AND-009). Tray `GET` uses bounded
  backoff retry for idempotent reads (AND-016); `markSeen` `POST` is **not** retried.
- **Offline tray:** if the network refresh fails and a cache exists, the tray renders
  stale cached rings (no error UI) and a subtle offline indicator from AND-021’s
  state composables. If no cache and offline → tray hidden (height 0), no blocking
  error since stories are non-critical.
- **Media load failure in viewer:** an image that fails to decode or a video that
  errors (via AND-168 error state) auto-advances after a 2s grace timer rather than
  blocking the whole story; the failed segment is skipped, logged, and the next
  segment loads.
- **401 mid-session:** AND-013 authenticator refreshes once and retries; if refresh
  fails, the viewer dismisses to the auth-gated route (AND-025).
- **markSeen failure:** swallowed; the DataStore viewed set keeps the UI correct, and
  a follow-up `GET` will reconcile `seen`.
- **Empty segments:** an author with an empty `segments` list is filtered out of the
  tray defensively.

## 8. Security & Privacy

- All requests ride the existing cookie session + CSRF header; no tokens are stored by
  this feature. The DataStore viewed set holds only opaque `segmentId`s — no PII.
- Media URLs are loaded over the session; Coil and Media3 use the shared OkHttp client
  so cookies/CSRF apply uniformly and cleartext is permitted only for the dev flavor’s
  base host via the existing network-security config (AND-006/014). No new cleartext
  exemptions are added.
- No story media is written to external/shared storage; Coil’s disk cache is the app’s
  private cache dir. Player buffers are in-memory/app-cache only.
- "Seen" telemetry is the user’s own viewing of stories shared with them; it is sent
  only to the authenticated backend, never third parties.

## 9. Accessibility & i18n

- Each `StoryRing` has a `contentDescription` such as
  `"Story from {username}, unseen"` / `"…, seen"`; the close button is labeled
  "Close stories". All strings live in `feature-stories/res/values/strings.xml` with
  placeholders for `username`.
- Auto-advance respects accessibility: when TalkBack is active or
  `Settings.Global.ANIMATOR_DURATION_SCALE`/reduce-motion is set, the per-image timer
  is extended (×2) and never advances while TalkBack is mid-utterance; users can still
  hold-to-pause.
- Touch targets (rings, close) are ≥48dp. The viewer supports the system back gesture.
- Color is not the sole seen/unseen signal — the `contentDescription` and ring stroke
  width both differ, satisfying non-color differentiation.
- All durations and counts are locale-formatted; layout is RTL-safe (`LazyRow` honors
  layout direction; close affordance mirrors).

## 10. Telemetry & Logging

- **Events (via the shared analytics interface, no PII):**
  `stories_tray_shown { authorCount }`,
  `story_viewer_opened { entryStoryId, source: "tray" }`,
  `story_segment_advance { kind, auto:true|false, index }`,
  `story_viewer_closed { authorsViewed, segmentsViewed, reason: "back"|"end"|"x" }`,
  `story_segment_error { kind, reason }`.
- **Logging:** repository logs network failures and DTO mapping fallbacks (unknown
  `kind`, missing `durationMs`) at `WARN`; `markSeen` drops at `DEBUG`. No media URLs
  or usernames are logged at INFO+.
- The player reuses AND-168’s existing playback telemetry; this ticket adds only the
  story-specific lifecycle events above.

## 11. Testing Strategy

- **Repository unit tests (MockWebServer, AND-046 harness):** GET parsing incl.
  envelope, image/video segment mapping, unknown `kind` fallback, missing
  `durationMs` default, error `detail` mapping to `ApiResult.Failure`, 401→refresh
  →retry, and stale-cache emission when offline. `markSeen` posts correct path and is
  not retried on failure.
- **ViewModel state-machine tests (coroutines `runTest`, virtual time):** image timer
  advances at `durationMs`; pause halts the timer and resumes; video `ended` triggers
  advance; cross-author rollover; dismissal after last author; failed segment
  auto-skip after grace; viewed set updated on `onSegmentShown`.
- **Compose UI tests (AND-046/048 pattern):** tray renders N rings with correct
  seen/unseen semantics and ordering; tapping a ring opens the viewer; viewer shows
  first unseen segment; close button dismisses; empty tray collapses to 0 height.
- **Auto-advance acceptance test:** an instrumented test opens the viewer on a
  two-segment fixture (image then video) and asserts auto-advance to segment 2 and
  then dismissal, satisfying the ticket acceptance ("Stories open + auto-advance").
- Player interactions are tested against a fake `PlayerManager` so tests don’t require
  real ExoPlayer/HLS.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-168 (Reusable player UI) must be merged — the viewer embeds
  its shared player surface for video segments. Transitively requires AND-166/167.
- **Network/UI baseline:** AND-009–018 (network stack, `ApiResult`, retry), AND-015
  (error mapping), AND-019–021 (theme/state composables), AND-022/024 (nav), AND-026
  (DTO/adapter pattern) are prerequisites already landed by M4.
- **Blocks:** AND-200 (Story progress + reactions) builds directly on the viewer
  scaffold, `StoryViewerUiState`, and the `markSeen` plumbing produced here.
- **Sequencing within ticket:** (1) models+DTOs+API, (2) repository+cache+viewed set,
  (3) tray composable, (4) viewer state machine + player wiring, (5) auto-advance &
  tests. Tray (3) can proceed in parallel with viewer (4) once (1)/(2) are stable.

## 13. Risks & Open Questions

- **OpenAPI shape unverified:** the dev host is unreliable; the `GET /ui/stories`
  envelope and the exact `seen`-marking path are inferred from `stories.ts`. Mitigated
  by isolating all shape assumptions in the DTO/mapper layer. **Open:** confirm path
  is `/segments/{id}/seen` vs. a batch `POST /ui/stories/seen {segmentIds:[]}`.
- **durationMs semantics:** unclear whether the server returns image display duration
  or only video length. Default 5000 ms for images is assumed; **open** for product
  confirmation.
- **Video as HLS vs. MP4:** segments may be either; the shared player (AND-167)
  handles both, but very short clips on HLS may buffer slowly on the dev host —
  grace-timer skip (§7) bounds the impact.
- **Reduce-motion timing:** the ×2 extension heuristic for auto-advance needs UX
  sign-off.
- **Reaction hooks:** confirm with AND-200 owner that `StoryViewerUiState` is the
  agreed extension point so no rework is needed.

## 14. Acceptance Criteria

1. Entering the authenticated feed shows a tray of story rings populated from
   `GET /ui/stories`; unseen authors sort first with a vivid ring, seen authors with a
   muted ring.
2. Tapping a ring opens the full-screen viewer at that author’s first unseen segment.
3. Image segments auto-advance after their duration; video segments auto-advance on
   completion — verified by an instrumented test.
4. After an author’s last segment the viewer advances to the next author; after the
   last author it dismisses to the feed.
5. The active segment is marked seen via `POST .../seen` and the tray ring restyles to
   "seen" on return (driven by the local viewed set even if the POST fails).
6. Press-and-hold pauses auto-advance (and video); release resumes.
7. Offline with a cached tray shows stale rings; offline with no cache hides the tray;
   a failed media segment auto-skips rather than blocking.
8. Close button and system back both dismiss the viewer and release the shared player
   (no player leak, verified by no lingering playback after dismiss).
9. Package/namespace is `com.testlogon.android.feature.stories`.

## 15. Definition of Done

- `feature-stories` module merged on `android-port` under `com.testlogon.android`,
  wired into the authenticated nav graph, building under Kotlin 2.0.21 / AGP 8.7.3 /
  Gradle 8.9 / JDK 17, minSdk 24 / target 35.
- All §11 unit, ViewModel, and Compose/instrumented tests pass in CI (AND-050 job);
  the auto-advance acceptance test is green.
- ktlint/detekt (AND-005) clean; no new cleartext exemptions; no new lint baseline
  suppressions added for this module.
- Strings externalized; accessibility labels present; reduce-motion handling in place.
- Telemetry events emitted as specified; no PII or media URLs logged at INFO+.
- Shared `PlayerManager` (AND-168) used for video — no second ExoPlayer instance;
  player released on dismiss.
- `StoryViewerUiState` documented as the AND-200 extension point; open questions in
  §13 either resolved or filed as follow-up issues.
