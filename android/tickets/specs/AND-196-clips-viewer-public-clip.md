---
id: AND-196
title: Clips viewer (+ public clip)
milestone: M4
epic: E26
priority: P1
size: L
status: draft
depends_on: [AND-168, AND-022]
blocks: []
---

# AND-196 — Clips viewer (+ public clip)

## 1. Overview & Goal

Deliver a full-screen, vertically swipeable short-form video experience ("Clips") for the
TestLogon Android app, plus an unauthenticated public deep link `/c/:clipId` that opens a single
clip directly. The viewer is the Android analogue of the web reference module backed by the
`clips.ts` API layer. A user can flick vertically through a paged feed of clips, each of which
auto-plays its HLS stream when it becomes the active page and pauses/releases when scrolled away.
Tapping a shared public URL (`https://testlogon.app/c/{clipId}`) launches the app — or the
relevant Activity if already running — directly onto that single clip, including for users who are
not logged in (public clips only).

The goal of this ticket is the **viewer surface and its data/playback plumbing**: paged retrieval,
per-page lifecycle-correct playback wired to the reusable player (AND-168), the public clip route
and Android App Link verification, and graceful offline/error/auth-gated states. Social actions
(like, comment, share, tip, bookmark) are surfaced as affordances but their behavior is delegated
to the feed-interaction tickets and is **out of scope** here except for navigation hand-off.

## 2. Context & References

- **Module:** new feature module `feature-clips` (`com.testlogon.android.feature.clips`), depending
  on `core-network`, `core-model`, `core-ui`, `core-data`, and the player module delivered by
  AND-168 (`feature-player` / `com.testlogon.android.feature.player`).
- **Depends on:**
  - **AND-168 — Reusable player UI:** provides `PlayerView`/`ClipPlayer` Compose surface, controls,
    buffering/error states, and PiP. Clips reuses this rather than instantiating ExoPlayer
    directly for chrome; it does manage `ExoPlayer` instances for paging (see §4).
  - **AND-022 — Navigation host & routes:** provides the single-Activity `NavHost` and typed route
    registry into which the `Clips` and `PublicClip` routes are added.
- **Related (not blocking, hand-off targets):** AND-166/167 (Media3/HLS foundation), AND-098/099
  (feed list & post item), AND-173–181 (feed interactions reused for clip actions), AND-016
  (retry/backoff), AND-021 (state composables), AND-045/116 (offline/SWR cache), AND-108 (deep-link
  routing from push taps).
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext, unreliable;
  ~20s timeouts, bounded backoff for idempotent GETs only). OpenAPI at `/openapi.json`. Web
  reference API layer is `frontend/src/api/endpoints/clips.ts`; shared types in
  `frontend/src/api/types.ts`. Endpoint paths in §5 follow those references; the implementer MUST
  reconcile against the live `/openapi.json` before merge and update DTOs accordingly.

## 3. Functional Requirements

1. **Paged clip feed.** Render a vertical, full-bleed pager (one clip per page) backed by Paging 3.
   Swiping up/down advances pages with snap behavior; only the active page plays audio + video.
2. **Auto-play on focus.** When a page becomes the settled/active page, its clip auto-plays from the
   start (or last position within the session) with sound on; when a page leaves focus it pauses and
   its player is released or recycled. At most one clip plays at a time.
3. **Prefetch.** The next clip's media is warmed (player prepared, manifest fetched) while the
   current clip plays, so swiping forward starts playback within ~300ms on a healthy network.
4. **Looping.** A clip loops on completion until the user swipes away.
5. **Overlay chrome.** Each clip overlays: author handle + avatar (tap → public profile AND-073),
   caption (expandable), and action rail (like/comment/share/bookmark) that delegates to the feed
   interaction tickets. Mute toggle and a tap-to-pause/resume gesture are local to this viewer.
6. **Public clip deep link.** An Android App Link on `https://testlogon.app/c/{clipId}` (and the
   `http` plus custom-scheme fallbacks) resolves to the `PublicClip` route showing exactly that
   clip. This MUST work for **unauthenticated** users for public clips.
7. **Auth-gated content.** If a deep-linked clip is private/entitlement-gated and the caller is
   unauthenticated or unentitled, show a sign-in/paywall prompt routed to the auth/paywall flows
   rather than the video; never leak the stream URL.
8. **Entry points.** Clips is reachable from the authenticated nav graph (a tab or More-hub entry,
   per AND-024/067) and from the public deep link. The public route, when the user is authenticated,
   offers "View more clips" to enter the full pager.
9. **States.** Loading (skeleton), empty ("No clips yet"), error (with retry), and offline/stale
   states reuse AND-021 composables. A single failed clip page must not break the pager.

## 4. Technical Design

### Module & key types

```kotlin
// feature-clips/src/main/kotlin/com/testlogon/android/feature/clips/

@Immutable
data class Clip(
    val id: String,
    val author: ClipAuthor,
    val caption: String?,
    val hlsUrl: String,            // master.m3u8; may be null until entitled
    val posterUrl: String?,
    val durationMs: Long?,
    val width: Int?,
    val height: Int?,
    val visibility: ClipVisibility, // PUBLIC, FOLLOWERS, PRIVATE, PAID
    val locked: Boolean,            // true when current viewer lacks entitlement
    val stats: ClipStats,
    val viewerState: ClipViewerState // liked/bookmarked flags (populated when authed)
)

enum class ClipVisibility { PUBLIC, FOLLOWERS, PRIVATE, PAID }

data class ClipsPage(val items: List<Clip>, val nextCursor: String?)
```

### Networking

```kotlin
interface ClipsApi {                       // Retrofit, core-network
    @GET("clips/feed")
    suspend fun getFeed(
        @Query("cursor") cursor: String?,
        @Query("limit") limit: Int = 10,
    ): Response<ClipsFeedResponseDto>

    @GET("clips/{clipId}")
    suspend fun getClip(@Path("clipId") clipId: String): Response<ClipDto>

    @GET("c/{clipId}")                      // public, cookie-optional
    suspend fun getPublicClip(@Path("clipId") clipId: String): Response<ClipDto>
}
```

`ClipsRepository` exposes a `Pager` and a single-clip fetcher. The feed is an idempotent GET, so it
uses the AND-016 bounded-backoff retry and AND-116 SWR cache; single public clip fetches use the
same retry policy. The repository maps `ClipDto → Clip` via Moshi adapters in `core-model`, and maps
FastAPI `detail` errors via AND-015's mapper into `ApiResult<T>`.

```kotlin
class ClipsRepository @Inject constructor(
    private val api: ClipsApi,
    private val authState: AuthStateStore,        // AND-029
) {
    fun feedPager(): Flow<PagingData<Clip>> =
        Pager(PagingConfig(pageSize = 10, prefetchDistance = 2)) { ClipsPagingSource(api) }.flow

    suspend fun publicClip(clipId: String): ApiResult<Clip>
}
```

### Playback & paging lifecycle

The viewer keeps a small `ExoPlayer` pool (3 instances: previous/current/next) created via the
AND-168/166 player factory, to avoid per-page allocation jank. A `ClipPlaybackController`
binds the active page to a player and drives prefetch:

```kotlin
class ClipPlaybackController(
    private val playerPool: ExoPlayerPool,   // from feature-player (AND-168)
) {
    fun bind(activePage: Int, clips: List<Clip>)  // play active, prepare next, release far pages
    fun setMuted(muted: Boolean)
    fun togglePlayPause()
    fun release()
}
```

Lifecycle: the controller observes the host `Lifecycle`; `onPause`/`onStop` pauses + saves position,
`onDestroy`/`onDispose` releases the pool. PiP transitions are handled by AND-168's player surface.

### Composables

```kotlin
@Composable fun ClipsScreen(viewModel: ClipsViewModel = hiltViewModel())   // pager entry
@Composable fun PublicClipScreen(viewModel: PublicClipViewModel = hiltViewModel())
@Composable fun ClipPage(clip: Clip, isActive: Boolean, controller: ClipPlaybackController)
@Composable fun ClipOverlay(clip: Clip, onAction: (ClipAction) -> Unit)
```

`ClipsScreen` uses `VerticalPager` (Compose Foundation) with `rememberPagerState`; a
`snapshotFlow { pagerState.settledPage }` drives `controller.bind(...)`.

### ViewModels

```kotlin
@HiltViewModel class ClipsViewModel @Inject constructor(repo: ClipsRepository) : ViewModel() {
    val pager: Flow<PagingData<Clip>> = repo.feedPager().cachedIn(viewModelScope)
    private val _ui = MutableStateFlow(ClipsUiState()); val ui: StateFlow<ClipsUiState> = _ui
}

@HiltViewModel class PublicClipViewModel @Inject constructor(
    private val repo: ClipsRepository,
    savedState: SavedStateHandle,
) : ViewModel() {
    private val clipId: String = checkNotNull(savedState["clipId"])
    val ui: StateFlow<UiState<Clip>>  // Loading/Content/Error/Locked/Offline
    fun retry()
}
```

### Navigation & deep links (AND-022)

```kotlin
sealed interface ClipsRoute {
    @Serializable data object Feed : ClipsRoute              // route: "clips"
    @Serializable data class Public(val clipId: String)      // route: "c/{clipId}"
}
```

Register both in the central `NavHost`. The `Public` destination declares
`deepLinks = listOf(navDeepLink { uriPattern = "https://testlogon.app/c/{clipId}" }, ...)`.

`AndroidManifest.xml` (single Activity) adds an App Links intent filter:

```xml
<intent-filter android:autoVerify="true">
  <action android:name="android.intent.action.VIEW"/>
  <category android:name="android.intent.category.DEFAULT"/>
  <category android:name="android.intent.category.BROWSABLE"/>
  <data android:scheme="https" android:host="testlogon.app" android:pathPrefix="/c/"/>
  <data android:scheme="http"  android:host="testlogon.app" android:pathPrefix="/c/"/>
</intent-filter>
```

App Links verification requires a `/.well-known/assetlinks.json` hosted on `testlogon.app` containing
this app's `applicationId` (`com.testlogon.android` + flavor suffix) and signing SHA-256 fingerprints.
Publishing assetlinks is a backend/web hosting task tracked as an open question (§13).

## 5. API Contract

All paths relative to the flavored base URL (`BuildConfig.API_BASE_URL`, AND-006). Cookie-based auth
+ `X-CSRF-Token` apply to authed calls; `GET /c/{clipId}` is cookie-optional.

**GET `/clips/feed?cursor=&limit=10`** → `200`
```json
{
  "items": [
    {
      "id": "clp_01H...",
      "author": { "id": "usr_…", "username": "alex", "displayName": "Alex", "avatarUrl": "https://…/a.jpg" },
      "caption": "behind the scenes",
      "hls_url": "https://cdn.testlogon.app/clips/clp_01H/master.m3u8",
      "poster_url": "https://cdn.testlogon.app/clips/clp_01H/poster.jpg",
      "duration_ms": 14200,
      "width": 1080, "height": 1920,
      "visibility": "public",
      "locked": false,
      "stats": { "likes": 102, "comments": 7, "views": 5400, "shares": 12 },
      "viewer_state": { "liked": false, "bookmarked": false }
    }
  ],
  "next_cursor": "eyJwayI6…"
}
```

**GET `/c/{clipId}`** (public) → `200` returns a single `ClipDto` (same shape as an `items[]` entry).
For a gated clip viewed without entitlement, returns the clip with `"locked": true` and a **null**
`hls_url` (stream URL never disclosed). For a non-public clip without auth → `403` or `404`:
```json
{ "detail": { "code": "clip_not_accessible", "message": "Sign in to view this clip." } }
```

**Errors** follow FastAPI `detail` union (string | `[{msg,…}]` | `{code,…}`) mapped by AND-015 to
`ApiError`. Relevant codes: `404 not_found` (deleted/unknown clip), `403 clip_not_accessible`,
`402 payment_required` (PAID/entitlement). View-count/heartbeat reporting is owned by playback
analytics (AND-171) and is **not** part of this ticket.

DTOs use Moshi `@Json(name=…)` for snake_case mapping; `Response<T>` is unwrapped to `ApiResult<T>`.

## 6. Data & State Management

- **Paging:** `ClipsPagingSource` keyed by opaque `next_cursor` (string). `PagingConfig(pageSize=10,
  prefetchDistance=2, enablePlaceholders=false)`. `PagingData<Clip>` is `cachedIn(viewModelScope)`.
- **UiState:**
  ```kotlin
  data class ClipsUiState(
      val muted: Boolean = false,
      val activePage: Int = 0,
      val refreshing: Boolean = false,
  )
  sealed interface UiState<out T> { object Loading; data class Content<T>(val data:T);
      data class Error(val error: ApiError, val stale: Boolean); object Locked; object Offline }
  ```
- **Caching (SWR, AND-116):** the first feed page and individual fetched clips are cached in Room
  (`ClipEntity`, `ClipFeedPageEntity`) with TTL (AND-118) so the viewer can render last-known clips
  while revalidating; offline shows stale + an offline banner (AND-042/045). Media segments are not
  persisted beyond ExoPlayer's default cache.
- **Player state:** mute preference persisted to DataStore (`clips_muted`); per-clip playback
  position kept in-memory for the session only.
- **Active-page source of truth:** `PagerState.settledPage` is authoritative; `ClipsUiState.activePage`
  mirrors it for the controller and telemetry.

## 7. Error Handling & Resilience

- **Timeouts/retry:** feed and public-clip GETs use the OkHttp 20s timeouts (AND-009) and AND-016
  bounded exponential backoff (idempotent GETs only). No retries on 4xx.
- **Auth refresh:** on `401`, the AND-013 authenticator performs a single `POST /ui/session/refresh`
  then retries; the public route tolerates the unauthenticated case (no refresh attempted when no
  session cookie exists).
- **Per-page failures:** a clip whose manifest/segment fails shows an inline retry overlay on that
  page only (reusing AND-168 player error state); paging continues unaffected.
- **Empty/end-of-feed:** when `next_cursor` is null and no items, show empty state; at feed end show
  a terminal "You're all caught up" page.
- **Offline:** if no network and cache exists → render stale with banner; if no cache → Offline
  state with retry wired to connectivity recovery (AND-017).
- **Deep-link miss:** unknown/deleted clip → friendly "This clip is unavailable" with a CTA to open
  the clips feed (authed) or sign in.

## 8. Security & Privacy

- **No URL leakage:** locked/gated clips must never expose `hls_url`; the client relies on the
  server returning null for unentitled viewers and must not synthesize stream URLs.
- **CSRF/cookies:** authed calls go through the persistent cookie jar (AND-011) and CSRF interceptor
  (AND-012); the public endpoint works without a session but still attaches CSRF/cookies if present.
- **Plaintext dev host:** the dev base URL is HTTP; production uses HTTPS. App Links require HTTPS.
  Network security config must permit cleartext only for the dev flavor host (AND-006/009).
- **Deep-link trust:** treat the incoming `clipId` as untrusted input — validate format, never
  interpolate into anything but the typed route arg; rely on server authorization for access control.
- **PII:** author handles/avatars are already public; no additional PII is collected. Watermark
  overlay hooks (AND-170) may apply for paid content but rendering is owned there.

## 9. Accessibility & i18n

- Each `ClipPage` exposes a content description (caption + author) and the action rail buttons have
  semantic labels (Like, Comment, Share, Bookmark, Mute) localized via AND-111/112 string resources.
- Tap-to-pause/resume has an equivalent visible control for switch/TalkBack users; auto-play respects
  the system "remove animations"/reduced-motion where feasible (still plays, but disables decorative
  transitions).
- Captions text is selectable/expandable and scales with system font size; overlay contrast meets
  WCAG AA over video (scrim behind text).
- Mute defaults respect the device and a persisted user preference; never force unmuted audio without
  a user-initiated focus.
- RTL: overlay/action-rail layout uses start/end (AND-114). All user-facing strings are externalized;
  no concatenation.

## 10. Telemetry & Logging

- Emit structured, redacted events (AND-052 conventions) through the app analytics facade:
  `clips_feed_opened`, `clip_impression {clipId, position}`, `clip_play_started {clipId}`,
  `clip_swiped {fromPos,toPos,direction}`, `clip_error {clipId, code}`,
  `public_clip_opened {clipId, authed:Boolean, source:"applink"}`.
- **Do not** log stream URLs, cookies, or CSRF tokens. Clip IDs are non-sensitive and may be logged.
- Playback heartbeat / watch-time analytics are explicitly **owned by AND-171**; this ticket only
  emits lifecycle/navigation events and forwards player events to that pipeline if available.

## 11. Testing Strategy

- **Unit (JVM):**
  - `ClipsPagingSource` cursor paging (load/append/end, error → `LoadResult.Error`).
  - `ClipsRepository` DTO→domain mapping incl. snake_case, locked/null `hls_url`, and `detail` error
    mapping (string/list/object) via MockWebServer (AND-046).
  - `PublicClipViewModel` state transitions: Loading→Content, →Locked (403), →Error, →Offline; retry.
- **Compose UI (instrumented):**
  - `ClipsScreen` renders pages; swiping to next page changes `settledPage` and triggers a single
    active player (assert only one playing via fake `ExoPlayerPool`).
  - Mute toggle persists and reflects in semantics.
  - State composables render for Loading/Empty/Error/Offline.
- **Deep link:** instrumented test launching the Activity with
  `Intent(ACTION_VIEW, Uri.parse("https://testlogon.app/c/clp_test"))` resolves to `PublicClipScreen`
  with the correct `clipId`; unauthenticated public clip renders; gated clip renders Locked.
- **Playback:** fake/idle ExoPlayer (Media3 test utils) verifies bind/prepare/release on page change
  and lifecycle pause/release.
- All run on CI unit (AND-050) and headless-emulator instrumented (AND-051) lanes. Acceptance:
  "Clips swipe + play" and "public clip opens" are covered by the swipe and deep-link tests above.

## 12. Dependencies & Sequencing

- **Hard deps:** AND-168 (player UI + pool/PiP) and AND-022 (NavHost/routes) must land first.
- **Strongly recommended before merge:** AND-166/167 (Media3/HLS), AND-098/099 (paging + item
  patterns to mirror), AND-021 (state composables), AND-015/016 (error map + retry), AND-116
  (SWR cache). AND-073 (public profile) for author tap; AND-177 (paywall) for PAID locked CTA.
- **Hand-offs (out of scope here):** AND-173–181 implement actual like/comment/share/bookmark/tip;
  AND-171 owns playback analytics/heartbeat; AND-170 owns watermark rendering; AND-108 reuses this
  route for push-tap deep linking.
- **Suggested order:** routes + manifest App Link → ClipsApi/DTOs/repo + paging → playback controller
  + pool binding → ClipsScreen pager → overlay/action hand-offs → PublicClip route → tests.

## 13. Risks & Open Questions

1. **Endpoint shape unverified.** Exact `/clips/feed`, `/clips/{id}`, `/c/{id}` paths and field names
   must be confirmed against `/openapi.json` and `frontend/src/api/endpoints/clips.ts`; treat §5 as
   provisional. *Owner action: reconcile before DTO freeze.*
2. **assetlinks.json hosting.** App Links auto-verification requires `/.well-known/assetlinks.json`
   on `testlogon.app` with the app's package + signing fingerprints. Not yet hosted — blocks verified
   deep links (falls back to disambiguation dialog until resolved). *Coordinate with web/infra.*
3. **Player pool jank.** Multiple ExoPlayer instances raise memory on low-end minSdk 24 devices;
   pool size (3) may need tuning or single-player reuse on constrained devices.
4. **Public unentitled stream:** relying on server to null `hls_url` for locked clips — must confirm
   the backend never returns playable URLs to unauthorized callers.
5. **Audio focus / autoplay-with-sound** policy vs. user expectation; default mute may be preferred.
   Open product decision.
6. **Looping vs. analytics view counting** interaction with AND-171 (does a loop re-count a view?).

## 14. Acceptance Criteria

1. The clips feed renders as a full-screen vertical pager; swiping up/down advances one clip per page
   with snap, and the newly settled clip auto-plays while the previous one pauses (only one clip plays
   at any time). *(Source: "Clips swipe + play")*
2. HLS playback starts on the active page and loops; forward swipes start playback within ~300ms on a
   healthy network via prefetch.
3. Opening `https://testlogon.app/c/{clipId}` (cold or warm app) routes directly to that single clip,
   including for an unauthenticated user when the clip is public. *(Source: "public clip opens")*
4. A gated/private deep-linked clip shows a sign-in/paywall prompt and never exposes the stream URL.
5. Mute toggle works and the preference persists across sessions; player state correctly pauses on
   app background and releases on destroy.
6. Loading, empty, error (with working retry), and offline/stale states render via AND-021; a single
   failed clip page does not break the pager.
7. Unknown/deleted clip deep links show an "unavailable" state with a sensible CTA.
8. Action-rail buttons navigate/hand off to the feed-interaction flows (no crash); their full behavior
   is validated in those tickets.

## 15. Definition of Done

- `feature-clips` module created under `com.testlogon.android.feature.clips`, layered app→feature→core,
  building on Kotlin 2.0.21 / compileSdk 35 / minSdk 24, with Hilt (KSP) wiring.
- `Clips` and `PublicClip` routes registered in the AND-022 NavHost; App Link intent filter added to
  the single Activity with `autoVerify="true"` and `https`/`http` `/c/` patterns.
- `ClipsApi`, DTOs/adapters, `ClipsRepository`, `ClipsPagingSource`, `ClipPlaybackController`,
  `ClipsViewModel`, `PublicClipViewModel`, and the `ClipsScreen`/`PublicClipScreen`/`ClipPage`/
  `ClipOverlay` composables implemented and reusing AND-168 player UI.
- All §11 unit and instrumented tests pass on CI (AND-050/051); lint/detekt/format (AND-005) clean.
- All §14 acceptance criteria demonstrably met, including the deep-link instrumented test and the
  single-active-player swipe test.
- Telemetry events from §10 emitted with redaction; no stream URLs/cookies/CSRF logged.
- Strings externalized (AND-111) and RTL/accessibility checks pass; mute preference persisted in
  DataStore.
- §13 open questions either resolved or filed as follow-up tickets (notably assetlinks.json hosting
  and OpenAPI reconciliation), with provisional endpoints flagged with TODOs referencing them.
- Code reviewed and merged to `android-port`; downstream owners (AND-171 analytics, AND-173–181
  interactions, AND-170 watermark, AND-108 push deep-link) notified of the integration points.
