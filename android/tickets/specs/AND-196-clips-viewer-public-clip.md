---
id: AND-196
title: Clips viewer (+ public clip)
milestone: M4
epic: E26
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
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
  `frontend/src/api/types.ts`. Endpoint paths in §5 have now been reconciled against the live
  `/openapi.json` and the frontend reference (see §16 audit). **Correction (2026-06-06 review):** the
  draft's `/clips/feed`, `/clips/{id}` and `/c/{id}` API paths were wrong. The real endpoints are
  `GET /ui/clips` (gallery feed), `GET /broadcast/clips/{clip_id}` (single authed clip), and
  `GET /broadcast/public/clips/{clip_id}` (public clip). `/c/{clipId}` is only the *web/deep-link URL*,
  not an API path. The DTO has **no `hls_url`/streaming field** — the clip references a `video_id` and a
  `thumbnail_url` only; the web reference renders a thumbnail + "Video player placeholder" and does not
  itself play HLS. There is also **no `visibility`/`locked`/entitlement** field in the backend schema.
  These are material to the design and are corrected throughout below.

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
7. **Auth-gated content.** *(Corrected: the backend `ClipOut`/`PublicClipOut` schema has no
   `visibility`/`locked`/entitlement field, and the public endpoint takes no auth — so server-side
   per-clip gating is **not** evidenced in the sources.)* If a clip fetch returns a 4xx (e.g. the
   public endpoint 404s on a non-shareable clip, or an authed endpoint 401/403s), show an
   "unavailable" / sign-in prompt rather than the video, and never synthesize a stream URL. Treat any
   future paywall/entitlement gating as an unverified assumption to confirm before building paywall UI.
8. **Entry points.** Clips is reachable from the authenticated nav graph (a tab or More-hub entry,
   per AND-024/067) and from the public deep link. The public route, when the user is authenticated,
   offers "View more clips" to enter the full pager.
9. **States.** Loading (skeleton), empty ("No clips yet"), error (with retry), and offline/stale
   states reuse AND-021 composables. A single failed clip page must not break the pager.

## 4. Technical Design

### Module & key types

> **Corrected (2026-06-06):** the original `Clip` shape below (author object, `hlsUrl`, `posterUrl`,
> `durationMs`, width/height, `visibility`, `locked`, `stats`, `viewerState`) does **not** match the
> backend. The authoritative DTOs are `ClipOut`/`PublicClipOut`/`ClipListOut` (OpenAPI) and
> `BroadcastClip`/`PublicBroadcastClip`/`ClipListResponse` (`src/api/types.ts`). The real fields are
> shown below; `ClipVisibility`/`locked`/entitlement do not exist server-side and are removed.

```kotlin
// feature-clips/src/main/kotlin/com/testlogon/android/feature/clips/

@Immutable
data class Clip(
    val clipId: String,             // @Json(name="clip_id")
    val sessionId: String,          // @Json(name="session_id") — source broadcast session
    val videoId: String,            // @Json(name="video_id") — source VOD; basis for stream URL (TODO §13)
    val creatorUserId: String,      // @Json(name="creator_user_id")
    val creatorDisplayName: String, // @Json(name="creator_display_name")
    val broadcasterUserId: String,  // @Json(name="broadcaster_user_id")
    val title: String,              // server field is `title` (NOT `caption`)
    val startSeconds: Double,       // @Json(name="start_seconds")
    val endSeconds: Double,         // @Json(name="end_seconds")
    val durationSeconds: Double,    // @Json(name="duration_seconds") — float seconds, NOT ms
    val status: ClipStatus,         // processing | ready | failed | deleted
    val viewCount: Int,             // @Json(name="view_count")
    val shareCount: Int,            // @Json(name="share_count")
    val thumbnailUrl: String,       // @Json(name="thumbnail_url") — NO hls_url field exists
    val createdAt: Long,            // @Json(name="created_at") — epoch seconds (Int in schema)
)

// PublicClip adds broadcaster attribution (PublicClipOut / PublicBroadcastClip):
//   broadcasterDisplayName: String (@Json "broadcaster_display_name"), profileId: String (@Json "profile_id")

enum class ClipStatus { PROCESSING, READY, FAILED, DELETED }

data class ClipsPage(val items: List<Clip>, val nextCursor: String?)  // @Json(name="next_cursor")
```

> **Playback URL is unresolved.** No backend field returns an HLS/stream URL for a clip. The web
> reference does not play the clip (it shows the thumbnail). Deriving a playable URL from `videoId`
> (e.g. via the videos/VOD streaming endpoints) is an **open dependency** — see §13. The HLS-pager
> design below is contingent on that being resolved; until then the viewer can only render
> thumbnails/posters like the web client.

### Networking

```kotlin
interface ClipsApi {                       // Retrofit, core-network — paths CORRECTED 2026-06-06
    // Gallery feed (was wrongly "clips/feed"). op=gallery_route_ui_clips_get → ClipListOut.
    @GET("ui/clips")
    suspend fun getFeed(
        @Query("sort") sort: String? = "recent",  // server supports "popular" | "recent"
        @Query("limit") limit: Int = 10,
        @Query("cursor") cursor: String?,
    ): Response<ClipListResponseDto>           // { clips: [ClipDto], next_cursor?: String }

    // Optional: own clips. op=my_clips_route_ui_clips_mine_get → ClipListOut (no paging params).
    @GET("ui/clips/mine")
    suspend fun getMyClips(): Response<ClipListResponseDto>

    // Single authed clip (was wrongly "clips/{clipId}"). op=get_clip_route_broadcast_clips__clip_id__get → ClipOut.
    @GET("broadcast/clips/{clipId}")
    suspend fun getClip(@Path("clipId") clipId: String): Response<ClipDto>

    // Public, no-auth (was wrongly "c/{clipId}"; that is only the web/deep-link URL).
    // op=public_clip_route_broadcast_public_clips__clip_id__get → PublicClipOut.
    @GET("broadcast/public/clips/{clipId}")
    suspend fun getPublicClip(@Path("clipId") clipId: String): Response<PublicClipDto>
}
```

> Note: the gallery feed (`/ui/clips`) returns `ClipListOut` which has a `next_cursor` so cursor paging
> is supported by the schema, but the web reference passes only `limit=50` (no infinite scroll). The
> Android pager (Paging 3) using `next_cursor` is a reasonable Android-side enhancement, flagged as an
> assumption in §16. The web app's gallery feed is a **grid of cards**, not a vertical swipe pager — the
> TikTok-style vertical viewer is an Android UX choice, not a mirror of web behavior.

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

All paths relative to the flavored base URL (`BuildConfig.API_BASE_URL`, AND-006). **Auth model
(corrected):** the web client sends `Authorization: Bearer <accessToken>` (from the auth store)
**plus** `X-CSRF-Token` (read from the `ui_csrf` cookie) **plus** cookies (`credentials: include`).
OpenAPI lists `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`, and `user_sub` params on authed clip endpoints.
So it is a Bearer-token + CSRF-cookie hybrid, not "cookie-only". The public endpoint
(`/broadcast/public/clips/{clip_id}`) takes **no auth params at all** (OpenAPI `params=clip_id` only),
so it is genuinely unauthenticated; the Android client may still attach CSRF/cookies harmlessly.

> The example bodies below are CORRECTED to the real `ClipOut`/`PublicClipOut` schemas. There is no
> `items[]`/`author`/`caption`/`hls_url`/`poster_url`/`duration_ms`/`width`/`height`/`visibility`/
> `locked`/`stats`/`viewer_state` — those were invented in the draft.

**GET `/ui/clips?sort=recent&limit=10&cursor=`** (authed gallery feed) → `200` `ClipListOut`
```json
{
  "clips": [
    {
      "clip_id": "clp_01H...",
      "session_id": "ses_01H...",
      "broadcaster_user_id": "usr_b...",
      "creator_user_id": "usr_c...",
      "creator_display_name": "Alex",
      "video_id": "vid_01H...",
      "title": "behind the scenes",
      "start_seconds": 12.0,
      "end_seconds": 26.2,
      "duration_seconds": 14.2,
      "status": "ready",
      "view_count": 5400,
      "share_count": 12,
      "thumbnail_url": "https://cdn.testlogon.app/clips/clp_01H/poster.jpg",
      "created_at": 1733443200
    }
  ],
  "next_cursor": "eyJwayI6…"
}
```

**GET `/broadcast/clips/{clipId}`** (authed single clip) → `200` `ClipOut` (one entry, same shape as a
`clips[]` element above).

**GET `/broadcast/public/clips/{clipId}`** (public, no auth) → `200` `PublicClipOut`: the same fields
as `ClipOut` **plus** `broadcaster_display_name` and `profile_id` for attribution. There is **no
entitlement/locked concept** and **no stream URL** in the response. (The web URL for sharing this is
`https://testlogon.app/c/{clipId}`, which the SPA maps to this API call — see App.tsx `"/c/:clipId"`.)

**Errors:** the only documented error response on these endpoints is `422 HTTPValidationError`
(FastAPI validation). Beyond that, FastAPI `detail` may be a string, a list of `{msg,…}`, or an object
`{code,…}` — the web client's `normalizeErrorDetail` handles all three (verified in `src/api/client.ts`),
and AND-015's mapper should mirror it. The draft's specific codes `clip_not_accessible`,
`payment_required (402)`, and `not_found` are **not** present in the spec/sources and are removed as
unverified; a missing/deleted clip is expected to surface as a 404 or 422 (treat 4xx → "unavailable").
View-count reporting (`POST /broadcast/clips/{id}/view`, `POST /broadcast/public/clips/{id}/view`) and
share (`…/share`) exist but heartbeat/watch-time analytics is owned by AND-171 and is out of scope here.

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

- **No URL leakage:** *(corrected)* the clip DTO contains **no `hls_url`** at all — the original
  "server returns null `hls_url` for unentitled viewers" claim is unsupported by the schema. Whatever
  mechanism ultimately yields a playable URL from `video_id` (see §13 open dependency) MUST itself be
  authorization-checked server-side; the client must never construct/guess stream URLs.
- **CSRF/cookies + Bearer:** *(corrected)* authed calls send `Authorization: Bearer <token>` (AND-013
  token store) AND `X-CSRF-Token` from the `ui_csrf` cookie (AND-012) AND the persistent cookie jar
  (AND-011) — verified in `src/api/client.ts`. The public endpoint works without a session and adds no
  auth headers; the Android client may still attach CSRF/cookies harmlessly.
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
  - `PublicClipViewModel` state transitions: Loading→Content, →Unavailable (4xx/404), →Error, →Offline;
    retry. *(Corrected: there is no server "Locked/403" entitlement state — see §5/§13; map 4xx to
    Unavailable.)*
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

1. **Endpoint shape — RECONCILED (2026-06-06).** The draft paths were wrong and are corrected:
   feed = `GET /ui/clips` (`ClipListOut`), single = `GET /broadcast/clips/{clip_id}` (`ClipOut`),
   public = `GET /broadcast/public/clips/{clip_id}` (`PublicClipOut`). `/c/{clipId}` is web URL only.
   Fields corrected to the real snake_case schema (no `hls_url`/`author`/`caption`/`visibility`/etc).
0. **NEW — Playback URL is unresolved (blocker for actual video).** No clip endpoint returns a
   stream/HLS URL; the clip only carries `video_id` + `thumbnail_url`, and the web reference does not
   play the clip (thumbnail + "Video player placeholder"). The HLS-pager/autoplay design (FR-2..4,
   AC-2) cannot be implemented until a way to obtain a playable URL from `video_id` (likely a
   videos/VOD streaming endpoint) is identified and confirmed. *Owner action: locate the VOD playback
   endpoint and add it to ClipsApi, or descope to thumbnail-only parity with web.*
2. **assetlinks.json hosting.** App Links auto-verification requires `/.well-known/assetlinks.json`
   on `testlogon.app` with the app's package + signing fingerprints. Not yet hosted — blocks verified
   deep links (falls back to disambiguation dialog until resolved). *Coordinate with web/infra.*
3. **Player pool jank.** Multiple ExoPlayer instances raise memory on low-end minSdk 24 devices;
   pool size (3) may need tuning or single-player reuse on constrained devices.
4. **Public/entitlement gating unverified:** the backend schema has **no** `locked`/`visibility`/
   entitlement field and the public endpoint is fully unauthenticated, so the draft's "null `hls_url`
   for locked clips" model does not exist as described. If product wants gated/paid clips, the gating
   + URL-authorization must be designed server-side first; until then, treat any clip the public
   endpoint returns as publicly viewable and rely on 4xx for "unavailable".
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer (OpenAPI `METHOD /path` / schema
name, or frontend path, or framework ref).

1. **Gallery feed endpoint is `GET /ui/clips` returning `ClipListOut` `{clips, next_cursor?}`** —
   **Corrected** (draft said `GET /clips/feed` → `ClipsFeedResponseDto` `{items, next_cursor}`).
   Source: OpenAPI `GET /ui/clips` (op `gallery_route_ui_clips_get`, `resp=200:ClipListOut`,
   `params=sort,limit,cursor,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`);
   `src/api/endpoints/clips.ts: listGallery`; `src/api/types.ts: ClipListResponse`;
   schema `components.schemas.ClipListOut`.
2. **Single authed clip is `GET /broadcast/clips/{clip_id}` → `ClipOut`** — **Corrected** (draft said
   `GET /clips/{clipId}`). Source: OpenAPI `GET /broadcast/clips/{clip_id}`
   (op `get_clip_route_broadcast_clips__clip_id__get`, `resp=200:ClipOut`);
   `src/api/endpoints/clips.ts: getClip`.
3. **Public clip is `GET /broadcast/public/clips/{clip_id}` → `PublicClipOut`, unauthenticated** —
   **Corrected** (draft said `GET /c/{clipId}`). Source: OpenAPI `GET /broadcast/public/clips/{clip_id}`
   (op `public_clip_route_broadcast_public_clips__clip_id__get`, `resp=200:PublicClipOut`,
   `params=clip_id` only → no auth); `src/api/endpoints/clips.ts: getPublicClip`;
   `src/api/types.ts: PublicBroadcastClip`.
4. **Web share/deep-link URL IS `/c/:clipId`** — **Verified** (the path is correct as a *web URL*, not
   an API path). Source: `src/App.tsx:283` `<Route path="/c/:clipId" element={<PublicClipPage />} />`.
5. **Clip DTO fields are flat snake_case: `clip_id, session_id, broadcaster_user_id, creator_user_id,
   creator_display_name, video_id, title, start_seconds, end_seconds, duration_seconds, status,
   view_count, share_count, thumbnail_url, created_at`** — **Corrected** (draft invented `id, author{},
   caption, hls_url, poster_url, duration_ms, width, height, visibility, locked, stats{}, viewer_state{}`).
   Source: schema `components.schemas.ClipOut`; `src/api/types.ts: BroadcastClip`.
6. **`PublicClipOut` adds `broadcaster_display_name` + `profile_id`** — **Verified.** Source: schema
   `components.schemas.PublicClipOut`; `src/api/types.ts: PublicBroadcastClip`.
7. **`duration_seconds` is a float (seconds), not `duration_ms`** — **Corrected.** Source:
   `ClipOut.duration_seconds: number`.
8. **`status` enum is `processing | ready | failed | deleted`** — **Verified** (new, not in draft).
   Source: `ClipOut.status` enum; `src/api/types.ts: BroadcastClip.status`.
9. **There is NO `hls_url`/stream URL field anywhere on the clip; web renders thumbnail +
   "Video player placeholder" and does not play HLS** — **Corrected** (draft's central HLS-autoplay
   assumption is unsupported). Source: `ClipOut`/`PublicClipOut` (no such field);
   `src/pages/clips/ClipPlayerPage.tsx:73-80` and `src/pages/clips/PublicClipPage.tsx:96-109`.
10. **There is NO `visibility`/`locked`/entitlement/paywall concept server-side** — **Corrected**
    (draft FR-7, §5 "locked:true / null hls_url", §8, AC-4). Source: `ClipOut`/`PublicClipOut` schemas;
    public endpoint takes no auth.
11. **Stats are flat `view_count` + `share_count` only; no likes/comments counts in the DTO** —
    **Corrected** (draft `stats{likes,comments,views,shares}`). Source: `ClipOut`; `BroadcastClip`.
12. **Gallery `sort` supports `popular | recent`** — **Verified** (draft omitted `sort`). Source:
    OpenAPI `GET /ui/clips params=sort,...`; `src/pages/clips/ClipGalleryPage.tsx:13,17`.
13. **`/ui/clips` schema carries `next_cursor`, so cursor paging is possible** — **Verified.** Source:
    `ClipListOut.next_cursor`. *(But web uses `limit=50` with no infinite scroll — see assumption A2.)*
14. **`GET /ui/clips/mine` (own clips) exists, no paging params** — **Verified** (not in draft;
    optional). Source: OpenAPI `GET /ui/clips/mine` (op `my_clips_route_ui_clips_mine_get`).
15. **Auth = `Authorization: Bearer <token>` + `X-CSRF-Token` (from `ui_csrf` cookie) + cookies** —
    **Corrected** (draft said "cookie-based auth + X-CSRF-Token"; missed the Bearer token). Source:
    `src/api/client.ts:157-171` (Authorization header from `useAuthStore`, CSRF from `ui_csrf` cookie,
    `credentials:"include"`); OpenAPI authed clip endpoints list `X-SESSION-ID,X-IMPERSONATION-TOKEN,user_sub`.
16. **On 401, the client refreshes once via `POST /ui/session/refresh` then retries** — **Verified.**
    Source: `src/api/client.ts:121-130, 194-237`.
17. **Public/unauth 401 does NOT trigger a refresh and propagates directly** — **Verified.** Source:
    `src/api/client.ts:196-203`.
18. **FastAPI `detail` may be string | `[{msg,…}]` | `{code,…}`; mapper handles all three** —
    **Verified.** Source: `src/api/client.ts: normalizeErrorDetail` (66-102).
19. **Documented error response on clip endpoints is `422 HTTPValidationError`; the codes
    `clip_not_accessible`, `402 payment_required`, `not_found` are not in the sources** — **Corrected**
    (draft invented those codes). Source: OpenAPI index lines for all clip endpoints (`resp=...;422:HTTPValidationError`).
20. **View/share recording endpoints exist (`POST /broadcast/clips/{id}/view|share`, public variants)
    but heartbeat/watch-time analytics is AND-171's; out of scope here** — **Verified.** Source:
    OpenAPI `POST /broadcast/clips/{clip_id}/view`, `/share`, `/broadcast/public/clips/{clip_id}/view`,
    `/share`; `src/api/endpoints/clips.ts: recordClipView/recordClipShare/recordPublicClip*`.
21. **`POST /ui/videos/{video_id}/clip` creates a clip from a VOD (`ClipVideoIn`→`ClipVideoOut`)** —
    **Verified** context only (clip *creation* is out of scope, but confirms `video_id` linkage to VOD).
    Source: OpenAPI `POST /ui/videos/{video_id}/clip`; `src/api/endpoints/clips.ts: createClip`.
22. **Vertical full-screen swipe pager via Compose `VerticalPager` + `rememberPagerState`,
    `settledPage`** — **Unverified-assumption** for product/UX (web uses a card grid + detail page, not
    a vertical feed); the API supports it but the UX is an Android choice. Framework ref:
    Jetpack Compose Foundation Pager — https://developer.android.com/develop/ui/compose/layouts/pager
23. **Android App Links via `<intent-filter autoVerify="true">` + hosted `/.well-known/assetlinks.json`**
    — **Verified (framework ref)**, hosting unverified (see assumption A3). Framework ref:
    https://developer.android.com/training/app-links/verify-android-applinks
24. **Multi-instance ExoPlayer pool (Media3) for paging** — **Unverified-assumption** (Android design;
    no source dictates it). Framework ref: AndroidX Media3 ExoPlayer —
    https://developer.android.com/media/media3/exoplayer

### Corrections made

- §2, §4, §5, §13: replaced the wrong API paths (`/clips/feed`, `/clips/{id}`, `/c/{id}`) with the real
  `GET /ui/clips`, `GET /broadcast/clips/{clip_id}`, `GET /broadcast/public/clips/{clip_id}`; clarified
  `/c/{clipId}` is a web/deep-link URL only.
- §4, §5: rewrote the `Clip` domain model and the example JSON to the real `ClipOut`/`PublicClipOut`
  fields; removed invented `author`, `caption`, `hls_url`, `poster_url`, `duration_ms`, width/height,
  `visibility`, `locked`, `stats{likes,comments}`, `viewer_state`. Fixed `duration_ms`→`duration_seconds`
  (float), `caption`→`title`, `poster_url`→`thumbnail_url`, and added `video_id`/`session_id`/status.
- §3.7, §8, §13.4, §11: removed the entitlement/`locked`/null-`hls_url`/paywall model (no backend
  support); reframed gating as 4xx → "unavailable" and flagged paywall as an unverified product idea.
- §2/§4/§13: flagged the **missing playback URL** — no stream URL is returned for a clip; the design's
  HLS autoplay is contingent on locating a VOD streaming endpoint from `video_id`.
- §5, §8: corrected the auth model to Bearer token + `X-CSRF-Token` (ui_csrf cookie) + cookies; added
  the `sort=popular|recent` param.
- §5: corrected error model to FastAPI `detail` union + `422 HTTPValidationError`; removed invented
  error codes (`clip_not_accessible`, `payment_required`, `not_found`).

### Open assumptions

- **A1 — Playback URL source (BLOCKER).** No clip endpoint returns a playable/HLS URL. Deriving one from
  `video_id` (presumably a VOD streaming endpoint) is unconfirmed; the videos endpoints were not audited
  for this ticket. Without it, only thumbnail rendering (web parity) is possible. *Why unverifiable:* the
  clip schema simply has no stream field, and the relevant VOD playback contract is outside the clips
  surface examined here.
- **A2 — Vertical TikTok-style pager + Paging 3 cursor paging.** The backend exposes `next_cursor`, but
  the web reference loads `limit=50` into a card grid (no infinite scroll, no vertical feed). The
  Android vertical pager and cursor-driven `Pager` are UX/perf choices, not mirrored web behavior.
- **A3 — `assetlinks.json` hosting on `testlogon.app`.** Required for App Links auto-verification;
  not present in any audited source. Until hosted, deep links fall back to the disambiguation dialog.
- **A4 — Entitlement/paywall/gated clips.** No server field supports it today; any such feature needs a
  backend contract first. The §6 `UiState.Locked` and AC-4 paywall remain Android placeholders only.
- **A5 — ExoPlayer pool size (3) / autoplay-with-sound default.** Performance and product decisions with
  no authoritative source; revisit on low-end minSdk-24 devices.

## 17. Test Plan

Test-target legend: **JVM** = local JVM/Robolectric (no device); **AVD test35** = headless x86_64
emulator, Android 15 / API 35 (CI instrumented); **A15** = physical Samsung Galaxy A15 5G (SM-A156U,
serial R5CX821TA9R), Android 14 / API 34, arm64-v8a (real hardware/network). Each case Traces to §14
Acceptance Criteria (AC-1..AC-8).

- **TC-AND-196-01** — Feed mapping & paging (happy path)
  - Type: contract/MockWebServer (+ unit). Target: JVM.
  - Preconditions: MockWebServer returns a valid `ClipListOut` (`/ui/clips?sort=recent&limit=10`) with
    2 pages (`next_cursor` set, then null).
  - Steps: collect `ClipsRepository.feedPager()`; load initial + append.
  - Expected: `ClipsPagingSource` maps `clips[]`→`Clip` with correct snake_case fields (`clip_id`,
    `creator_display_name`, `duration_seconds` as float, `thumbnail_url`); appends using `next_cursor`;
    terminates when `next_cursor` is null with `LoadResult.Page(nextKey=null)`.
  - Traces: AC-1, AC-6.
- **TC-AND-196-02** — Single public clip mapping (happy path)
  - Type: contract/MockWebServer. Target: JVM.
  - Preconditions: MockWebServer returns valid `PublicClipOut` for `GET /broadcast/public/clips/{id}`.
  - Steps: call `ClipsRepository.publicClip("clp_test")`.
  - Expected: `ApiResult.Success` with `Clip` incl. `broadcaster_display_name` + `profile_id`; no auth
    header required on the request (assert request has no `Authorization`); `thumbnail_url` populated,
    no stream URL synthesized.
  - Traces: AC-3.
- **TC-AND-196-03** — Error `detail` union mapping (validation/error responses)
  - Type: unit + contract/MockWebServer. Target: JVM.
  - Preconditions: MockWebServer returns, across sub-cases: `422` with `detail=[{msg,...}]`; `4xx` with
    `detail="string"`; `4xx` with `detail={code,...}`; and a `404`.
  - Steps: invoke `getClip`/`publicClip`; map via AND-015.
  - Expected: all three `detail` shapes normalize to a non-empty `ApiError` message; no retry on 4xx;
    404/4xx surfaces as the "unavailable" outcome (no crash, no invented `clip_not_accessible` code).
  - Traces: AC-6, AC-7.
- **TC-AND-196-04** — PublicClipViewModel state transitions
  - Type: unit. Target: JVM.
  - Preconditions: fake repo emitting success / 404 / network-error.
  - Steps: drive load; then `retry()` after error.
  - Expected: Loading→Content; Loading→Unavailable on 404; Loading→Offline on network error;
    `retry()` re-issues and reaches Content. (No "Locked/403" entitlement path — that state is a UI
    placeholder only, see §16 A4.)
  - Traces: AC-3, AC-6, AC-7.
- **TC-AND-196-05** — Single-active-player on swipe (core acceptance)
  - Type: Compose-UI instrumented. Target: AVD test35.
  - Preconditions: `ClipsScreen` with a fake `ExoPlayerPool`; ≥3 clips.
  - Steps: launch; swipe up to next page; assert `settledPage` advances.
  - Expected: exactly one player is in PLAYING state at any time; the previous page's player pauses;
    `controller.bind` invoked for the new settled page. (Asserts the "swipe + play" acceptance with a
    fake player; real HLS playback is gated on §16 A1.)
  - Traces: AC-1, AC-2.
- **TC-AND-196-06** — Playback lifecycle bind/prepare/release
  - Type: instrumented (Media3 test utils / idle ExoPlayer). Target: AVD test35.
  - Preconditions: fake/idle player pool; lifecycle owner controllable.
  - Steps: settle on a page (bind+prepare current, prepare next); move host to `onPause` then `onStop`,
    then `onDestroy`.
  - Expected: active player prepared, next prefetched, far pages released; `onPause/onStop` pauses +
    saves position; `onDestroy` releases the pool (no leaks).
  - Traces: AC-2, AC-5.
- **TC-AND-196-07** — Mute toggle persistence
  - Type: Compose-UI instrumented. Target: AVD test35.
  - Preconditions: DataStore key `clips_muted` cleared.
  - Steps: toggle mute in `ClipOverlay`; recreate the screen/process.
  - Expected: mute state reflected in semantics and applied to the player; persisted to DataStore and
    restored after recreation.
  - Traces: AC-5.
- **TC-AND-196-08** — Deep link to public clip, unauthenticated (core acceptance)
  - Type: instrumented/e2e. Target: AVD test35.
  - Preconditions: no session; MockWebServer (or staging) returns a valid `PublicClipOut`.
  - Steps: `Intent(ACTION_VIEW, Uri.parse("https://testlogon.app/c/clp_test"))` to launch the Activity
    cold; then repeat warm.
  - Expected: routes to `PublicClipScreen` with `clipId="clp_test"`; renders the clip without requiring
    login; request hits `GET /broadcast/public/clips/clp_test` with no `Authorization` header.
  - Traces: AC-3.
- **TC-AND-196-09** — Deep link to unknown/deleted clip
  - Type: instrumented. Target: AVD test35.
  - Preconditions: server returns 404 (or `status:"deleted"`) for the clip.
  - Steps: open `https://testlogon.app/c/clp_missing`.
  - Expected: "This clip is unavailable" state with a CTA (open feed if authed / sign in); no crash.
  - Traces: AC-7.
- **TC-AND-196-10** — Offline / flaky dev host resilience
  - Type: integration. Target: A15 (real network; toggle airplane mode) — must run on the physical
    device for real radio/connectivity transitions; AVD acceptable as a smoke check via network shaping.
  - Preconditions: one feed page previously cached (SWR, AND-116); then disable network.
  - Steps: open Clips offline; then attempt a public-clip fetch with no cache; restore connectivity.
  - Expected: cached clips render stale with an offline banner; uncached fetch shows Offline state with
    retry; on reconnect, retry succeeds (idempotent GET retried via AND-016 backoff; no 4xx retries).
  - Traces: AC-6.
- **TC-AND-196-11** — App Links auto-verification on device
  - Type: instrumented/e2e. Target: A15 (must be physical — verification uses the device's real
    `assetlinks.json` fetch + Play/verifier behavior; differs from emulator).
  - Preconditions: signed build installed; `assetlinks.json` hosted (or documented as pending → expect
    disambiguation fallback).
  - Steps: `adb shell am start -a android.intent.action.VIEW -d "https://testlogon.app/c/clp_test"`;
    inspect `adb shell pm get-app-links com.testlogon.android`.
  - Expected: when assetlinks is hosted, the link opens the app directly (verified domain). When not
    hosted, a disambiguation dialog appears — documented as the known §13/A3 gap, not a test failure.
  - Traces: AC-3.
- **TC-AND-196-12** — No stream-URL / secret leakage (security)
  - Type: unit + manual log inspection. Target: JVM (+ A15 spot-check of logcat).
  - Preconditions: telemetry/logging enabled; a clip loaded.
  - Steps: exercise feed + public clip; capture emitted analytics and logs.
  - Expected: no `Authorization`/cookies/`X-CSRF-Token` and no stream URLs are logged (clip DTO has no
    stream URL to begin with); only redacted events from §10 (clipId allowed). Client never constructs a
    stream URL from `video_id`.
  - Traces: AC-4 (security intent), AC-3.
- **TC-AND-196-13** — Per-page failure isolation
  - Type: Compose-UI instrumented. Target: AVD test35.
  - Preconditions: one clip in the page set whose media/thumbnail load fails.
  - Steps: swipe to the failing page, then continue swiping.
  - Expected: failing page shows an inline retry overlay; paging continues; other pages unaffected.
  - Traces: AC-6.
- **TC-AND-196-14** — Accessibility (TalkBack / semantics / contrast)
  - Type: Compose-UI instrumented (+ manual TalkBack pass on A15 for real screen-reader gestures).
    Target: AVD test35 for semantics assertions; A15 for the TalkBack manual pass.
  - Preconditions: a clip page rendered.
  - Steps: assert content descriptions (caption/title + author) and action-rail labels (Like, Comment,
    Share, Bookmark, Mute); verify a visible pause/resume control exists for the tap gesture; check
    text scales with system font size and scrim contrast meets WCAG AA.
  - Expected: all interactive elements have localized semantic labels; tap-to-pause has an accessible
    equivalent; no contrast or font-scaling failures.
  - Traces: AC-1, AC-5, AC-8.
- **TC-AND-196-15** — Action-rail hand-off (no crash)
  - Type: Compose-UI instrumented. Target: AVD test35.
  - Preconditions: feed-interaction targets stubbed.
  - Steps: tap Like / Comment / Share / Bookmark and the author handle.
  - Expected: each invokes the correct navigation/hand-off callback without crashing; author tap routes
    to the public profile (AND-073). Full interaction behavior is validated in AND-173–181.
  - Traces: AC-8.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (vertical pager, swipe, single active play) | TC-01, TC-05, TC-14 |
| AC-2 (HLS starts + loops, ~300ms prefetch) | TC-05, TC-06 — *real playback blocked by §16 A1* |
| AC-3 (public deep link opens, incl. unauth) | TC-02, TC-04, TC-08, TC-11, TC-12 |
| AC-4 (gated clip → prompt, no stream-URL leak) | TC-12 — *no server gating today (§16 A4)* |
| AC-5 (mute persists; pause on background, release on destroy) | TC-06, TC-07, TC-14 |
| AC-6 (Loading/Empty/Error+retry/Offline; failed page isolated) | TC-01, TC-03, TC-04, TC-10, TC-13 |
| AC-7 (unknown/deleted deep link → "unavailable" + CTA) | TC-03, TC-04, TC-09 |
| AC-8 (action-rail hand-off, no crash) | TC-14, TC-15 |
