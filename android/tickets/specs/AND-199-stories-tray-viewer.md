---
id: AND-199
title: Stories tray + viewer
milestone: M4
epic: E27
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
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

> **Reviewer correction (data model):** Verified against the web reference and OpenAPI,
> the backend models a *Story* as a **single** media item (one image OR one video) — not
> an author with an embedded `segments[]` array. An author's "segments" are therefore the
> author's **list of `Story` objects**, fetched per-author via
> `GET /ui/stories/user/{user_id}`. The tray is fetched separately via `GET /ui/stories/bar`
> (one `StoryBarEntry` per author, with a server-provided `has_unseen` flag). Throughout
> this spec "segment" maps to one backend `Story`. See §5 and §16 for the corrected
> contract; the original single-`GET /ui/stories` envelope assumption was wrong.
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

- **Web reference:** `src/api/endpoints/stories.ts` (authoritative endpoint
  shapes and query params), shared types in `src/api/types.ts`
  (`Story`, `StoryBarEntry`, `StoryViewResp`, `UserStoriesResp`, `StoryBarResp`), and
  the screens `src/pages/feed/StoryBar.tsx` and `src/pages/feed/StoryViewer.tsx`.
  The native API surface mirrors these. **Correction:** the web types are `Story` (a
  single media item) and `StoryBarEntry`; there is **no** `StorySegment` or `StoryAuthor`
  type in `types.ts` — those names in the original draft were invented.
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
tray loads the story bar via **`GET /ui/stories/bar`** (response `StoryBarResp { bar:
StoryBarEntry[] }`). Each entry is one author (`user_id`, `latest_story_id`,
`latest_media_url`, `story_count`, `has_unseen`, `is_own`). The tray renders a
horizontally scrolling `LazyRow` of circular avatars with a gradient ring. *(Corrected:
the original `GET /ui/stories` endpoint does not exist; the web client uses
`getStoryBar()` → `/ui/stories/bar`.)* The web client also refetches the bar on a 60s
interval and invalidates it on viewer close; the native tray should likewise refresh on
viewer dismiss (and may poll while visible).

FR-2. **Seen/unseen styling.** Unseen authors (`has_unseen == true`) render a vivid
gradient ring; fully-seen authors render a muted gray ring. **"Unseen" is taken directly
from the server `has_unseen` flag on each `StoryBarEntry`**, OR-merged with the local
optimistic viewed set (§6) so a ring restyles immediately after viewing.
*(Corrected: there is no per-segment `seen` flag on the API; the original "derived from
per-segment `seen`" claim was wrong.)* **Unverified assumption:** unseen-first ordering —
the web client renders the bar **in server order and does not re-sort**; if product wants
unseen-first the native client must sort client-side. Marked open in §13/§16.

FR-3. **Open viewer.** Tapping a tray ring opens the full-screen viewer at that author.
The viewer then fetches that author's stories via **`GET /ui/stories/user/{user_id}`**
(`UserStoriesResp { stories: Story[] }`) and starts at index 0. *(Corrected: the web
viewer starts at index 0, not "first unseen segment" — there is no per-story seen flag to
compute a first-unseen index from `getUserStories`. Starting at first-unseen is an
optional native enhancement and is marked as an assumption in §16.)*

FR-4. **Auto-advance within an author.** Image segments auto-advance after a fixed
display duration (default **5000 ms**, the web `SLIDE_DURATION_MS`). Video segments
advance when playback completes; if the server supplies `duration_seconds`, that value
(× 1000) is used as the duration/ceiling. *(Corrected: the API field is
**`duration_seconds`** (seconds), not `durationMs`; the native DTO converts to ms.
Per the web client, `duration_seconds` is only applied to **video**; images always use
the 5000 ms default regardless of any duration field.)*

FR-5. **Auto-advance across authors.** After the last segment of the current author,
the viewer advances to the next author in tray order; after the last author it
dismisses and returns to the feed.

FR-6. **Mark seen.** When a segment (a `Story`) becomes active, fire
**`POST /ui/stories/{story_id}/view`** (no body; response `StoryViewResp { ok,
already_viewed }`) once per `story_id`, deduplicated via an in-memory viewed set (mirrors
the web `viewedSetRef`), and update the persisted local viewed set so the tray ring
restyles on return. *(Corrected: the per-segment `.../segments/{segmentId}/seen` path
does not exist; view tracking is story-level via `/view`. It is keyed and deduped by
`story_id`, not debounced by time.)*

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

**Models (`core-model`-style, immutable).** *Corrected to match the real API: a backend
`Story` is a single media item; the domain "segment" is one such `Story`, and an
"author" is a `StoryBarEntry`.*

```kotlin
// Tray entry — one per author (maps StoryBarEntry: user_id, latest_story_id,
// latest_media_url, story_count, has_unseen, is_own). NOTE: the API does NOT
// return a display name or avatar URL; the web client shows user_id[0] as a
// placeholder. avatar/username are therefore not available from /ui/stories/bar.
data class StoryBarItem(
    val userId: String,
    val latestStoryId: String,
    val latestMediaUrl: String?,   // a story media url, NOT an avatar
    val storyCount: Int,
    val hasUnseen: Boolean,
    val isOwn: Boolean,
)

// One segment == one backend Story (from GET /ui/stories/user/{user_id}).
enum class SegmentKind { IMAGE, VIDEO }   // maps media_type "image" | "video"
data class StorySegment(
    val storyId: String,            // story_id
    val authorId: String,           // author_id
    val kind: SegmentKind,          // media_type
    val mediaUrl: String,           // media_url (image URL or HLS/MP4 URL)
    val durationMs: Long,           // duration_seconds*1000 (video only); else default 5000
    val textOverlay: String?,       // text_overlay
    val linkUrl: String?,           // link_url
    val createdAt: Instant,         // created_at (ISO-8601)
    val expiresAt: Long,            // expires_at (epoch)
    val viewCount: Int,             // view_count
    val highlighted: Boolean,       // highlighted
)

// An author's playable set, assembled client-side (bar entry + fetched stories).
data class AuthorStories(
    val author: StoryBarItem,
    val segments: List<StorySegment>,
)
```

There is no server-side per-segment `seen` flag, so `firstUnseenIndex` cannot be computed
from `getUserStories`; the only unseen signal is `StoryBarItem.hasUnseen` (author-level)
plus the local viewed set. The viewer starts at index 0 (web parity).

**Repository:**

```kotlin
interface StoriesRepository {
    fun trayFlow(): Flow<ApiResult<List<StoryBarItem>>>   // cached-then-network (GET /ui/stories/bar)
    suspend fun refreshTray(): ApiResult<Unit>
    suspend fun loadAuthorStories(userId: String): ApiResult<List<StorySegment>>  // GET /ui/stories/user/{user_id}
    suspend fun recordView(storyId: String): ApiResult<Unit>                       // POST /ui/stories/{story_id}/view
}
```

*(Corrected signatures: the tray emits `StoryBarItem`s, the per-author segment list is a
separate `GET /ui/stories/user/{user_id}` call made lazily when the viewer opens that
author, and the seen call is `recordView(storyId)` → `/view`.)*

`StoriesRepositoryImpl` emits a Room-cached bar immediately (stale) then triggers a
network refresh on the `GET /ui/stories/bar` path (idempotent → eligible for the AND-016
bounded backoff retry). `recordView` is a `POST` → **no** retry; failures are logged and
dropped (the local viewed set is the source of truth for UI). It is deduped per
`story_id` so the same story is not re-posted within a viewing session.

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
    val authors: List<StoryBarItem> = emptyList(),     // tray order, for cross-author advance
    val authorIndex: Int = 0,
    val segments: List<StorySegment> = emptyList(),    // current author's stories, lazily loaded
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
    state: ApiResult<List<StoryBarItem>>,
    onRingClick: (userId: String) -> Unit,        // corrected: keyed by author user_id
    modifier: Modifier = Modifier,
)
@Composable fun StoryRing(entry: StoryBarItem, onClick: () -> Unit)  // hasUnseen read from entry
@Composable fun StoryViewerScreen(vm: StoryViewerViewModel, onDismiss: () -> Unit)
@Composable fun StorySegmentContent(segment: StorySegment, playerSurface: @Composable () -> Unit)
```

**Navigation (AND-022/024):** the viewer is a full-screen composable route on the
authenticated nav graph:

```kotlin
const val storyViewerRoute = "stories/viewer/{userId}"
fun NavController.openStoryViewer(userId: String) =
    navigate("stories/viewer/$userId")
```

*(Corrected: the viewer is keyed by **`userId`** (the author), matching the web client
where the tray passes `entry.user_id` into `StoryViewer`. The ViewModel resolves the tray
list from the cached repository flow so it can advance across authors, and fetches the
entry author's segments via `loadAuthorStories(userId)`.)*

## 5. API Contract

Base path `/ui/stories`. All calls carry session cookies + `X-CSRF-Token` (value read
from the `ui_csrf` cookie and echoed in the header — verified in
`src/api/client.ts`) via existing interceptors (AND-011/012). 401s are retried once after
a single `POST /ui/session/refresh` (verified in `client.ts`).

> **Reviewer note:** the entire original §5 endpoint set was inaccurate. Corrected below
> against `openapi.index.txt`, `openapi.pretty.json`, and `src/api/endpoints/stories.ts`.

**GET `/ui/stories/bar`** — fetch the tray/story-bar (idempotent). Verified:
`op=get_story_bar_endpoint_ui_stories_bar_get`, responses `200` / `422 HTTPValidationError`.
Frontend type `StoryBarResp`. Response `200`:

```json
{
  "bar": [
    {
      "user_id": "usr_42",
      "latest_story_id": "stry_01H...",
      "latest_media_url": "https://.../latest.jpg",
      "story_count": 3,
      "has_unseen": true,
      "is_own": false
    }
  ]
}
```

**GET `/ui/stories/user/{user_id}`** — fetch one author's stories, called when the viewer
opens that author (idempotent). Verified:
`op=get_user_stories_endpoint_ui_stories_user__user_id__get`, `200` / `422`. Frontend type
`UserStoriesResp`. Response `200`:

```json
{
  "stories": [
    { "story_id": "stry_1", "author_id": "usr_42", "media_type": "image",
      "media_url": "https://.../1.jpg", "text_overlay": "hi", "link_url": null,
      "duration_seconds": null, "created_at": "2026-06-05T12:00:00Z",
      "expires_at": 1749200000, "view_count": 10, "highlighted": false },
    { "story_id": "stry_2", "author_id": "usr_42", "media_type": "video",
      "media_url": "https://.../2.m3u8", "duration_seconds": 12,
      "created_at": "2026-06-05T12:01:00Z", "expires_at": 1749200060,
      "view_count": 4, "highlighted": false }
  ]
}
```

**POST `/ui/stories/{story_id}/view`** — record a view for a story (no retry; deduped per
`story_id`). Verified: `op=record_view_endpoint_ui_stories__story_id__view_post`,
**request body empty**, response **`200`** (`StoryViewResp { "ok": true,
"already_viewed": false }`) / `422`. *(Corrected: not `204`; not a per-segment path. No
`404` is documented — re-posting an already-viewed story returns `200` with
`already_viewed: true`, so the "treat 404 as success" rule is unnecessary; any non-2xx is
simply swallowed.)*

**DTOs & mapping (Moshi, AND-026 pattern):** `StoryBarResponseDto`/`StoryBarEntryDto`,
`UserStoriesResponseDto`/`StoryDto`, `StoryViewRespDto`. `media_type` is a lowercase
string mapped to `SegmentKind` via a custom adapter (unknown → `IMAGE` fallback, logged).
`duration_seconds` (seconds, nullable) is converted to ms; when null/absent, default
`5000` ms for images and treat video as "advance on playback complete." `created_at`
parsed as ISO-8601 `Instant`; `expires_at` is an epoch integer.

**Error envelope:** Verified — `422` returns `HTTPValidationError { detail:
ValidationError[] }` where each `ValidationError` is `{ loc, msg, type }`. The shared
AND-015 mapper handles `detail` as string | `[{msg,...}]` | `{code,...}` into
`ApiResult.Failure`; the `[{msg}]` array form is the one these endpoints actually return.
On `401` the AND-013 authenticator performs a single `POST /ui/session/refresh` then
retries the request (verified against `client.ts` 401 handling).

The DTO layer is the single point of adaptation; mappers must be tolerant of additional
unknown fields (`@JsonClass(generateAdapter = true)` ignores extras). Note the OpenAPI
declares an empty (`{}`) response schema for these endpoints, so the field shapes above
are taken from `src/api/types.ts` rather than the schema; mappers must stay defensive.

## 6. Data & State Management

- **Cache (Room 2.6, in `core-data` style):** `StoryBarEntity` (one row per author,
  keyed by `user_id`) with a `lastFetchedAt` column. `trayFlow()` is backed by `@Query`
  returning the cached bar entries, exposed as a `Flow`, so the tray paints instantly on
  cold start (stale). Network refresh upserts and bumps `lastFetchedAt`. *(Per-author
  story lists from `GET /ui/stories/user/{user_id}` are short-lived and fetched on viewer
  open; they need not be persisted — caching is optional.)*
- **Viewed set (DataStore prefs):** a `Set<String>` of viewed **`story_id`s** persisted so
  ring styling survives process death and reflects the optimistic mark before the `/view`
  `POST` lands. *(Corrected: keyed by `story_id`, not `segmentId`.)* Because the API has no
  per-story `seen` flag, ring styling is `StoryBarEntry.has_unseen` OR-merged with whether
  every story of that author is in the local viewed set.
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

- **Unreliable dev host:** OkHttp timeouts ~20s (AND-009). Tray `GET /ui/stories/bar` and
  per-author `GET /ui/stories/user/{user_id}` use bounded backoff retry for idempotent
  reads (AND-016); the `POST /ui/stories/{story_id}/view` call is **not** retried.
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
- **recordView failure:** swallowed; the DataStore viewed set keeps the UI correct, and
  a follow-up `GET /ui/stories/bar` will reconcile `has_unseen`.
- **Empty author:** if `GET /ui/stories/user/{user_id}` returns an empty `stories` list,
  the viewer skips that author and advances; bar entries with `story_count == 0` (should
  not occur) are filtered defensively.

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
  `"Story from {name}, unseen"` / `"…, seen"`; the close button is labeled
  "Close stories". All strings live in `feature-stories/res/values/strings.xml` with a
  placeholder for `{name}`. **Note:** the story-bar API returns no display name or avatar
  URL (`StoryBarEntry` has only `user_id`); like the web client (`user_id[0]` placeholder)
  the native client derives a label from `user_id` (e.g. the local-part before `@`) until
  a profile-name source is wired in. Flagged as an assumption in §16.
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

- **Repository unit tests (MockWebServer, AND-046 harness):** `GET /ui/stories/bar`
  parsing (`bar[]`), `GET /ui/stories/user/{id}` parsing (`stories[]`), image/video
  `media_type` mapping, unknown `media_type` fallback, missing `duration_seconds` default
  (seconds→ms), `422` `detail[]` mapping to `ApiResult.Failure`, 401→refresh→retry, and
  stale-cache emission when offline. `recordView` posts `POST /ui/stories/{story_id}/view`
  with the correct path/empty body, is deduped per `story_id`, and is not retried on
  failure.
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

- **OpenAPI shape — NOW VERIFIED (was a risk):** the tray is `GET /ui/stories/bar`
  (`StoryBarResp`), per-author stories are `GET /ui/stories/user/{user_id}`
  (`UserStoriesResp`), and view marking is `POST /ui/stories/{story_id}/view` (`200`,
  `StoryViewResp`). The original `GET /ui/stories` envelope and `/segments/{id}/seen` path
  did not exist and have been corrected (§5, §16). No batch seen endpoint exists.
- **duration semantics — RESOLVED:** the API field is `duration_seconds` (seconds,
  nullable). The web client applies it only to **video**; images always use the 5000 ms
  default. Native follows web parity (§4 FR-4).
- **Video as HLS vs. MP4:** segments may be either; the shared player (AND-167)
  handles both, but very short clips on HLS may buffer slowly on the dev host —
  grace-timer skip (§7) bounds the impact.
- **Reduce-motion timing:** the ×2 extension heuristic for auto-advance needs UX
  sign-off.
- **Reaction hooks:** confirm with AND-200 owner that `StoryViewerUiState` is the
  agreed extension point so no rework is needed.

## 14. Acceptance Criteria

1. Entering the authenticated feed shows a tray of story rings populated from
   `GET /ui/stories/bar`; unseen authors (`has_unseen`) render a vivid ring, seen authors
   a muted ring. (Unseen-first ordering is an optional client-side enhancement, not
   required — see §16 open assumptions.)
2. Tapping a ring opens the full-screen viewer for that author (fetched via
   `GET /ui/stories/user/{user_id}`), starting at the first segment (index 0).
3. Image segments auto-advance after 5000 ms; video segments auto-advance on completion
   (or after `duration_seconds`) — verified by an instrumented test.
4. After an author’s last segment the viewer advances to the next author; after the
   last author it dismisses to the feed.
5. The active segment (`story_id`) is marked viewed via `POST /ui/stories/{story_id}/view`
   and the tray ring restyles to "seen" on return (driven by the local viewed set even if
   the POST fails).
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source. Sources are
OpenAPI `METHOD /path` (from `reference/openapi.index.txt` /
`reference/openapi.pretty.json`), frontend paths under `reference/src/`, or framework
references.

1. **Tray is fetched from `GET /ui/stories`.** VERDICT: **Corrected** → the tray is
   `GET /ui/stories/bar`. SOURCE: OpenAPI `GET /ui/stories/bar`
   (`op=get_story_bar_endpoint_ui_stories_bar_get`); `src/api/endpoints/stories.ts:
   getStoryBar`. `GET /ui/stories` is not in the spec (only `POST /ui/stories` create).
2. **Tray response is `{ stories: [{ author, segments[] }] }`.** VERDICT: **Corrected** →
   `StoryBarResp { bar: StoryBarEntry[] }`, entry = `{ user_id, latest_story_id,
   latest_media_url, story_count, has_unseen, is_own }`. SOURCE: `src/api/types.ts:
   StoryBarResp`, `StoryBarEntry`.
3. **A Story is an author with an embedded `segments[]` array.** VERDICT: **Corrected** →
   a `Story` is a single media item (`story_id`, `author_id`, `media_type`, `media_url`,
   `duration_seconds`, `created_at`, `expires_at`, `view_count`, `highlighted`, …); an
   author's "segments" = their list of `Story` via `GET /ui/stories/user/{user_id}`.
   SOURCE: `src/api/types.ts: Story`, `UserStoriesResp`; OpenAPI
   `GET /ui/stories/user/{user_id}`; `src/pages/feed/StoryViewer.tsx` (iterates
   `data.stories`).
4. **Types `StorySegment`/`StoryAuthor` exist in the web types.** VERDICT: **Corrected** →
   no such types; the web types are `Story` and `StoryBarEntry`. SOURCE: `src/api/types.ts`
   (grep found no `StorySegment`/`StoryAuthor`).
5. **Seen marking is `POST /ui/stories/{storyId}/segments/{segmentId}/seen`, `204`, treat
   `404` as success.** VERDICT: **Corrected** → `POST /ui/stories/{story_id}/view`,
   returns **`200`** `StoryViewResp { ok, already_viewed }`, empty request body; no `404`
   documented. SOURCE: OpenAPI `POST /ui/stories/{story_id}/view`
   (`op=record_view_endpoint_...`, responses `200`/`422`); `src/api/endpoints/stories.ts:
   recordStoryView`; `src/api/types.ts: StoryViewResp`.
6. **View call is deduped per story (fire-and-forget).** VERDICT: **Verified** → web dedups
   via `viewedSetRef: Set<story_id>` and mutates once per `story_id`. SOURCE:
   `src/pages/feed/StoryViewer.tsx` (`viewedSetRef`, `viewMut.mutate`).
7. **Image display duration default 5000 ms.** VERDICT: **Verified** → `SLIDE_DURATION_MS
   = 5000`. SOURCE: `src/pages/feed/StoryViewer.tsx`.
8. **Per-segment `durationMs` overrides image duration.** VERDICT: **Corrected** → field is
   `duration_seconds` (seconds, nullable) and the web client applies it **only to video**;
   images always use 5000 ms. SOURCE: `src/api/types.ts: Story.duration_seconds`;
   `src/pages/feed/StoryViewer.tsx` (duration branch keyed on `media_type === "video"`).
9. **Video auto-advances on playback completion.** VERDICT: **Verified (web uses a timer,
   not the ended event)** → the web client uses a `duration_seconds`-based interval timer,
   not a real "ended" callback; native may legitimately use Media3 `STATE_ENDED` plus the
   `duration_seconds` ceiling. SOURCE: `src/pages/feed/StoryViewer.tsx` (setInterval). The
   native "advance on `PlayerState.ended`" is an acceptable improvement; noted as
   assumption.
10. **Cross-author advance after last segment; dismiss after last author.** VERDICT:
    **Verified** → `goNext` calls `onNextCreator`; parent advances `selectedIndex` or
    closes the viewer at the end. SOURCE: `src/pages/feed/StoryViewer.tsx` (`goNext`),
    `src/pages/feed/StoryBar.tsx` (`handleNextCreator`).
11. **Press-and-hold pauses auto-advance.** VERDICT: **Verified (web uses tap-to-toggle /
    spacebar, not hold)** → the web pauses via a center tap zone and the spacebar. The
    "press-and-hold" gesture is a reasonable native idiom but is NOT what the web does.
    SOURCE: `src/pages/feed/StoryViewer.tsx` (`setIsPaused`, key `" "`). Marked assumption.
12. **Unseen styling from `has_unseen`; ring gradient vs muted.** VERDICT: **Verified** →
    `entry.has_unseen ? gradient : muted`. SOURCE: `src/pages/feed/StoryBar.tsx`
    (`StoryBarAvatar.ringColor`).
13. **Unseen authors sort before seen authors.** VERDICT: **Unverified-assumption** → the
    web client renders the bar in server order with no client sort. SOURCE:
    `src/pages/feed/StoryBar.tsx` (`bar.map` over server array, no sort).
14. **Viewer opens at the author's first unseen segment.** VERDICT:
    **Unverified-assumption** → web opens at index 0; there is no per-story seen flag in
    `getUserStories` from which to derive first-unseen. SOURCE:
    `src/pages/feed/StoryViewer.tsx` (`setCurrentIndex(0)`).
15. **Tray rings show username + avatar.** VERDICT: **Unverified-assumption** →
    `StoryBarEntry` has no name/avatar field; web shows `user_id[0]` and `user_id.split("@")[0]`.
    SOURCE: `src/api/types.ts: StoryBarEntry`; `src/pages/feed/StoryBar.tsx`.
16. **Auth: session cookie + `X-CSRF-Token` from `ui_csrf` cookie.** VERDICT: **Verified**.
    SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", …)`).
17. **401 → single `POST /ui/session/refresh` then retry once.** VERDICT: **Verified**.
    SOURCE: `src/api/client.ts` (`refreshSession()` → `/ui/session/refresh`; single
    `refreshPromise`; one retry; re-throws 401 on failure).
18. **422 error envelope is `detail` (string | array of `{msg}` | object).** VERDICT:
    **Verified** → `HTTPValidationError { detail: ValidationError[] }`, each `{loc,msg,type}`;
    the array form is what these endpoints return. SOURCE: OpenAPI
    `components.schemas.HTTPValidationError` / `ValidationError`; `src/api/client.ts`
    (`normalizeErrorDetail`).
19. **Bar should refresh after viewing / periodically.** VERDICT: **Verified** → web
    refetches the bar every 60s and invalidates it on viewer close. SOURCE:
    `src/pages/feed/StoryBar.tsx` (`refetchInterval: 60_000`, `invalidateQueries` in
    `onClose`).
20. **Namespace `com.testlogon.android.feature.stories` / module layering.** VERDICT:
    **Unverified-assumption** (project convention; consistent with the stated
    `app → feature-* → core-*` layering, no authoritative source in the reference set).
21. **Shared `PlayerManager`/`VideoPlayerSurface` from AND-168, Media3 single-player.**
    VERDICT: **Unverified-assumption** (cross-ticket dependency, not in the backend/web
    reference; framework ref: Media3/ExoPlayer lifecycle —
    https://developer.android.com/media/media3/exoplayer). Verify against the AND-168
    deliverable at integration time.
22. **Reduce-motion: extend image timer; respect TalkBack.** VERDICT:
    **Unverified-assumption** (UX heuristic, no source). Framework ref:
    https://developer.android.com/guide/topics/ui/accessibility and
    `Settings.Global.ANIMATOR_DURATION_SCALE`.

### Corrections made

- §1/§2/§4/§5/§6/§13/§14: replaced the non-existent `GET /ui/stories` envelope model with
  the real two-call model — `GET /ui/stories/bar` (`StoryBarResp`) for the tray and
  `GET /ui/stories/user/{user_id}` (`UserStoriesResp`) per author (claims 1–3).
- §2/§4: removed invented web types `StorySegment`/`StoryAuthor`; introduced `StoryBarItem`
  (= `StoryBarEntry`) and `StorySegment` (= one backend `Story`) (claim 4).
- §4/§5/§6/§7/§11/§14: replaced `POST .../segments/{segmentId}/seen` (`204`, 404-as-success)
  with `POST /ui/stories/{story_id}/view` (`200`, `StoryViewResp`); renamed `markSeen` →
  `recordView`, keyed/deduped by `story_id` (claims 5–6).
- §4/§5: corrected field `durationMs` → `duration_seconds` (seconds → ms) and clarified it
  applies to video only (claim 8); listed the real `Story` fields.
- §4: viewer route re-keyed from `{storyId}` to `{userId}` (the author), matching the web
  client (claims 3, 10); fixed composable signatures (`onRingClick: (userId)`,
  `StoryRing(entry)`).
- §6: cache entity corrected to `StoryBarEntity` keyed by `user_id`; viewed set keyed by
  `story_id`; styling derived from `has_unseen` (claims 2, 5, 12).
- §3/§14: downgraded "first unseen segment" and "unseen-first ordering" from requirements
  to optional client-side enhancements (claims 13, 14).
- §9: noted the bar API returns no username/avatar; content description uses a `user_id`
  fallback (claim 15).
- §13: marked the previously "open" OpenAPI-shape and duration questions as resolved.

### Open assumptions

- **Unseen-first tray ordering** (claim 13): the web does not sort; native sorting needs
  product sign-off. Cannot verify a "correct" order from the sources.
- **Viewer starts at first-unseen segment** (claim 14): not derivable from the API (no
  per-story seen flag); web starts at index 0.
- **Press-and-hold to pause** (claim 11): native idiom; web uses tap/spacebar. Gesture
  choice unverifiable from sources.
- **Advancing video on `PlayerState.ended`** (claim 9): web uses a duration timer; native
  improvement pending AND-168 player capability.
- **Username/avatar in tray** (claim 15): no API field; placeholder until a profile source
  is wired.
- **Module namespace / AND-168 player contract / reduce-motion heuristic** (claims 20–22):
  project/cross-ticket conventions and UX heuristics with no authoritative reference here;
  verify at integration time.

## 17. Test Plan

Test target legend: **JVM** = local JVM/Robolectric unit (no device); **emu35** = headless
emulator AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G
(SM-A156U, serial `R5CX821TA9R`, API 34, arm64-v8a). Cases needing real media decode,
real-network HLS, or ABI/API-version behavior call out **A15 (required)**; pure-logic and
deterministic-UI cases run on JVM/emu35.

- **TC-AND-199-01 — Tray bar parse (happy path).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues a
  `200` `StoryBarResp` body with two entries (one `has_unseen:true`, one `false`).
  Steps: call `refreshTray()`/collect `trayFlow()`. Expected: two `StoryBarItem`s mapped
  with correct `userId`, `storyCount`, `hasUnseen`, `isOwn`; request path is
  `GET /ui/stories/bar` carrying session cookie + `X-CSRF-Token`. Traces: AC-1.

- **TC-AND-199-02 — Per-author stories parse + media_type/duration mapping.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `200` `UserStoriesResp`
  with an image story (no `duration_seconds`) and a video story (`duration_seconds:12`).
  Steps: `loadAuthorStories(userId)`. Expected: image → `IMAGE`, `durationMs==5000`; video
  → `VIDEO`, `durationMs==12000`; path `GET /ui/stories/user/{user_id}`. Traces: AC-2, AC-3.

- **TC-AND-199-03 — Unknown media_type + null duration fallback.**
  Type: unit. Target: JVM. Preconditions: a story with `media_type:"gif"` and absent
  `duration_seconds`. Steps: map DTO → domain. Expected: `kind==IMAGE` (logged WARN),
  `durationMs==5000`; no crash; extra unknown JSON fields ignored. Traces: AC-3.

- **TC-AND-199-04 — recordView posts correct path, deduped, not retried.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `200`
  `{ok:true,already_viewed:false}`. Steps: call `recordView("stry_1")` twice for the same
  id; then enqueue a `500` for a different id. Expected: exactly one
  `POST /ui/stories/stry_1/view` with empty body for the duped id; the `500` is not
  retried and is swallowed (`ApiResult.Failure`, no exception); viewed set still updated.
  Traces: AC-5.

- **TC-AND-199-05 — 401 → refresh → retry once.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: bar `GET` returns `401`, then
  `POST /ui/session/refresh` returns `200`, then the retried bar `GET` returns `200`.
  Steps: `refreshTray()`. Expected: exactly one refresh call, one retry, success result;
  a second consecutive `401` surfaces as auth failure (no infinite loop). Traces: AC-1, AC-7.

- **TC-AND-199-06 — 422 error envelope mapping.**
  Type: unit/contract. Target: JVM. Preconditions: bar `GET` returns `422`
  `{detail:[{loc:["query","x"],msg:"bad",type:"value_error"}]}`. Steps: `refreshTray()`.
  Expected: `ApiResult.Failure` carrying the `msg`/normalized detail via the AND-015
  mapper; no crash on the array shape. Traces: AC-7.

- **TC-AND-199-07 — Stale-cache emission when offline.**
  Type: unit. Target: JVM (Robolectric for Room). Preconditions: Room seeded with a
  cached bar; network refresh fails (IOException). Steps: collect `trayFlow()`. Expected:
  cached rings emitted immediately (stale), no blocking error UI; offline indicator state
  set. Traces: AC-7.

- **TC-AND-199-08 — ViewModel image timer auto-advance + cross-author rollover.**
  Type: unit (coroutines `runTest`, virtual time). Target: JVM. Preconditions: fake repo
  with author A (1 image) then author B (1 image); fake `PlayerManager`. Steps: open
  viewer at A, advance virtual time 5000 ms; then 5000 ms again. Expected: after first
  5000 ms `onSegmentComplete` advances to author B (loads B's stories); after B's segment
  the viewer reaches `phase==Done`/dismiss. `recordView` called once per story shown.
  Traces: AC-3, AC-4, AC-5.

- **TC-AND-199-09 — Pause halts and resumes the image timer.**
  Type: unit (`runTest`). Target: JVM. Preconditions: 1 image segment, duration 5000 ms.
  Steps: advance 2000 ms, `onPauseHold(true)`, advance 10000 ms, assert no advance,
  `onPauseHold(false)`, advance 3000 ms. Expected: segment advances only after the
  remaining ~3000 ms post-resume; `playerManager.pause()`/resume invoked for video case.
  Traces: AC-6.

- **TC-AND-199-10 — Failed media segment auto-skips after grace.**
  Type: unit (`runTest`). Target: JVM. Preconditions: video segment whose fake player
  emits an error state. Steps: open viewer, emit player error, advance the 2s grace timer.
  Expected: failed segment skipped, `story_segment_error` telemetry emitted, next segment
  loads; story not blocked. Traces: AC-7.

- **TC-AND-199-11 — Tray Compose rendering + ring semantics + tap opens viewer.**
  Type: Compose-UI. Target: emu35. Preconditions: `StoriesTray` fed an
  `ApiResult.Success` of 3 `StoryBarItem`s (mixed `hasUnseen`). Steps: assert 3 rings +
  the "Your story" affordance; assert unseen rings expose the unseen `contentDescription`
  and a distinct stroke (non-color cue); tap a ring. Expected: `onRingClick(userId)` fires
  with the correct `user_id`. Traces: AC-1, AC-2.

- **TC-AND-199-12 — Empty tray collapses; dismiss releases player.**
  Type: Compose-UI. Target: emu35. Preconditions: empty bar → tray height 0; then a viewer
  opened over a fake player. Steps: assert tray not shown when `bar` empty; open viewer,
  tap close (X) and separately use system back. Expected: both dismiss to prior route;
  `onDismiss` called; fake `PlayerManager.stop()/release` invoked (no lingering playback).
  Traces: AC-7, AC-8.

- **TC-AND-199-13 — Accessibility: TalkBack labels, touch targets, reduce-motion.**
  Type: instrumented (Espresso/AccessibilityChecks + UiAutomator). Target: A15 (required —
  real TalkBack + system animator-duration-scale behavior). Preconditions: TalkBack
  enabled; reduce-motion (`ANIMATOR_DURATION_SCALE=0`) set. Steps: traverse the tray and
  viewer; verify ring/close `contentDescription`s, ≥48dp targets, RTL mirroring under a
  pseudo-RTL locale; confirm per-image timer is extended and does not advance mid-utterance;
  hold-to-pause still works. Expected: all a11y checks pass; timing adjusts under
  reduce-motion. Traces: AC-2, AC-6.

- **TC-AND-199-14 — Auto-advance acceptance on real device (image → real video).**
  Type: instrumented/e2e. Target: A15 (required — real Media3 decode + real-network
  HLS/MP4, arm64 ABI on API 34). Preconditions: a two-segment author fixture (image then a
  real short HLS/MP4 clip) served to the app; AND-168 player wired. Steps: open the viewer
  from the tray; let it run unattended. Expected: image auto-advances at ~5000 ms; video
  plays and auto-advances on completion; after the last author the viewer dismisses to the
  feed; only one Media3 player instance is created and it is released on dismiss
  (satisfies "Stories open + auto-advance"). Traces: AC-3, AC-4, AC-8.

- **TC-AND-199-15 — Security: CSRF + cleartext + no PII logging.**
  Type: contract/instrumented. Target: JVM (request capture) + A15 (network-security
  config). Preconditions: MockWebServer with a `ui_csrf` cookie set. Steps: trigger bar
  `GET`, `user` `GET`, and `view` `POST`; inspect captured requests and logcat at INFO+.
  Expected: every request carries `X-CSRF-Token` matching the `ui_csrf` cookie and the
  session cookie; cleartext permitted only for the dev base host; no media URLs/usernames
  logged at INFO+; viewed set stores only `story_id`s. Traces: AC-5, AC-9.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (tray from `/ui/stories/bar`, ring styling) | TC-01, TC-05, TC-11 |
| AC-2 (tap ring → viewer for that author) | TC-02, TC-11, TC-13 |
| AC-3 (image timer / video completion auto-advance) | TC-02, TC-03, TC-08, TC-14 |
| AC-4 (cross-author advance, dismiss after last) | TC-08, TC-14 |
| AC-5 (mark viewed via `/view`, ring restyle) | TC-04, TC-08, TC-15 |
| AC-6 (press-and-hold pauses/resumes) | TC-09, TC-13 |
| AC-7 (offline cache / hide / failed-segment skip) | TC-05, TC-06, TC-07, TC-10, TC-12 |
| AC-8 (close + back dismiss, player released, no leak) | TC-12, TC-14 |
| AC-9 (namespace `com.testlogon.android.feature.stories`) | TC-15 (module/package assertion) |
