---
id: AND-394
title: Public clip
milestone: M8
epic: E51
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-196]
blocks: []
---

# AND-394 — Public clip

## 1. Overview & Goal

This ticket delivers the standalone **public clip view** at the deep-link route `/c/:clipId`, the unauthenticated, shareable entry point into a single clip. Whereas AND-196 (Clips viewer) builds the authenticated vertical swipe feed and registers the `/c/:clipId` Android App Link, AND-394 hardens the *public* surface that opens when an anonymous user (no session cookies, app possibly cold-started from a browser or messaging app) follows a shared clip URL such as `https://testlogon.com/c/clp_8f2a91`.

The single, testable goal: **a public clip plays.** Concretely, tapping a shared `/c/:clipId` link launches (or resumes) the app, resolves the clip via the public (no-auth) API, renders it in the reusable player (AND-168) inside a dedicated `PublicClipScreen`, and begins HLS playback — without requiring login, and degrading gracefully when the clip is private, deleted, geo-blocked, or the unreliable dev backend times out.

This screen is intentionally minimal: a single full-bleed video, clip metadata (title, author handle, view count), a share affordance, and a contextual "Open in app / Sign in" call-to-action that bridges anonymous viewers into the authenticated experience. It is **not** the swipeable feed — there is no paging, no vertical pager, no autoplay-next.

## 2. Context & References

- **Backlog:** AND-394, Type Feature, Priority P2, Deps AND-196. Scope: `/c/:clipId` public clip view. Acceptance: "Public clip plays."
- **Direct dependency — AND-196 (Clips viewer + public clip), M4/E26:** owns `core-data`/`core-network` `clips.ts`-equivalent (`ClipsApi`, `ClipsRepository`), the `Clip` domain model, the vertical authenticated viewer, and registration of the `/c/:clipId` App Link `<intent-filter>` in the app manifest. AND-394 consumes those artifacts and adds the *public/anonymous* screen + ViewModel + the public API call. Where overlap is ambiguous, AND-394 owns everything keyed off the public entry point; AND-196 owns the authenticated feed.
- **Transitive — AND-168 (Reusable player UI), M4/E23:** the `VideoPlayer` Compose component (play/seek/scrub/volume/fullscreen, buffering/error states, PiP) built on Media3/ExoPlayer 1.4. AND-394 reuses it as-is for HLS playback. AND-168 → AND-166 supply the underlying ExoPlayer wiring.
- **Transitive — AND-022 (Navigation host & routes), M1/E03:** the single-Activity `NavHost` and typed route registry into which the `PublicClipRoute` is added.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (PLAINTEXT HTTP, unreliable). OpenAPI at `/openapi.json`. Public clip data is served by an unauthenticated GET (see §5). **CORRECTED:** the verified public endpoint is `GET /broadcast/public/clips/{clip_id}` returning `PublicClipOut` (verified in `openapi.index.txt` and `src/api/endpoints/clips.ts: getPublicClip`). **IMPORTANT GAP:** `PublicClipOut` contains **no HLS/playback-manifest URL** — only `thumbnail_url` and `video_id`. There is no `hls_url`/`m3u8` field in the verified schema, and the web reference renders only a thumbnail with a literal "Video player placeholder" (no actual player). The "HLS plays from `hls_url` in the payload" design below is therefore an **unverified assumption** pending a backend playback-URL field or a separate manifest-resolution endpoint (see OQ-1/OQ-4 and §16).
- **Web reference:** `src/api/endpoints/clips.ts` (`getPublicClip`, `recordPublicClipView`, `recordPublicClipShare`), shared types in `src/api/types.ts` (`PublicBroadcastClip extends BroadcastClip`), screen `src/pages/clips/PublicClipPage.tsx`, route registration `src/App.tsx` (`<Route path="/c/:clipId" element={<PublicClipPage />} />`), transport `src/api/client.ts`. These define the canonical request/response shapes corrected below.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Media3 1.4, Coil. Module layering `app → feature-clips → core-network/core-model/core-ui/core-data`. minSdk 24 / targetSdk 35, JDK 17, AGP 8.7.3.
- **Namespace:** `com.testlogon.android` everywhere.

## 3. Functional Requirements

FR-1. **Deep-link entry.** An Android App Link / web URL of form `https://testlogon.com/c/{clipId}` (and the `http`/custom-scheme fallbacks registered in AND-196) MUST route to `PublicClipScreen` with `clipId` extracted as a typed nav argument. The intent-filter (registered by AND-196) MUST cover both cold start and warm resume.

FR-2. **Anonymous resolution.** The screen MUST resolve the clip through the **public** endpoint `GET /broadcast/public/clips/{clip_id}` (§5; CORRECTED from `GET /clips/{clipId}/public` — verified against `openapi.index.txt` line 136 and `src/api/endpoints/clips.ts: getPublicClip`) using **no** auth/CSRF requirements. The endpoint's only parameter is `clip_id` (no `user_sub`/`X-SESSION-ID`/`X-IMPERSONATION-TOKEN`), confirming server-side anonymous access. A `401`/missing session MUST NOT block playback of a public clip.

FR-3. **Playback.** On successful resolution the clip's playback manifest URL MUST be handed to the AND-168 `VideoPlayer`, which begins buffering immediately and auto-plays once ready (muted-autostart is acceptable; see FR-7). The player surface is full-bleed with the AND-168 control overlay (play/pause, scrub, volume, fullscreen, PiP). **UNVERIFIED ASSUMPTION:** `PublicClipOut` exposes no playback-URL field (no `hls_url`/manifest); the verified web reference shows only `thumbnail_url` in a "Video player placeholder". A backend playback URL (or a manifest derived from `video_id`) is required before real HLS playback is possible — see OQ-4 and §16. If unresolved, the achievable MVP is poster/thumbnail rendering, not live HLS.

FR-4. **Metadata.** Title, broadcaster display name (`broadcaster_display_name`), creator display name (`creator_display_name`), formatted view count (`view_count`), and share count (`share_count`) MUST render as an overlay/caption. **CORRECTED:** the verified schema has **no nested `author` object**, **no `@handle`**, and **no `avatar_url`** — attribution is by display-name strings only (mirrors `PublicClipPage.tsx` "Clipped from {broadcaster_display_name} · Created by {creator_display_name}"). Thumbnail loaded via Coil from `thumbnail_url`. Missing optional fields degrade silently (no empty rows).

FR-5. **Visibility gates.** The screen MUST distinguish and surface, as distinct UI states. **CORRECTED / PARTIALLY UNVERIFIED:** the OpenAPI for `GET /broadcast/public/clips/{clip_id}` documents only `200:PublicClipOut` and `422:HTTPValidationError`; **no `403`/`404`/`410`/`451` responses are declared**, and `PublicClipOut` has **no `visibility` field**. Verified, source-backed states:
  - **Not found / unresolvable** — the web reference (`PublicClipPage.tsx`) treats any non-resolving response as a generic "Clip not found" (it sets `retry:false` and renders the not-found view when `!clip`). FastAPI default for a missing item is `404`, but this is **inferred, not declared** — map `404` → `NOT_FOUND` and keep a generic fallback for any other non-2xx.
  - **Removed/inactive** — driven by the verified `status` enum `"processing" | "ready" | "failed" | "deleted"`. Map `status == "deleted"` → `REMOVED`, `status == "failed"` → an unavailable/error state, and `status == "processing"` → a "still processing" state (web shows "Clip is processing..."). There is **no `status == "private"`** and no `visibility` gate in the schema.
  - **Validation error** — `422 HTTPValidationError` (e.g. malformed `clip_id`) → terminal `Unavailable(NOT_FOUND)` or a generic error.
  - **`403` PRIVATE / `410` REMOVED / `451` REGION_BLOCKED** are **UNVERIFIED assumptions** (not in this endpoint's OpenAPI). The web `client.ts` *does* contain generic `403` handling and a `geo_blocked` detail-code path (`detail.code === "geo_blocked"`) applied to all endpoints, so a `403`/geo-block *could* occur globally; keep defensive mapping but mark as unverified for this route. Each terminal state shows a message and an "Open TestLogon" CTA; none crash or hang.

FR-6. **Anonymous → app bridge.** A persistent CTA ("Sign in" / "Open in app") MUST navigate anonymous users to the auth flow (or the authenticated clips feed if a valid session already exists), passing the current `clipId` so the user lands back on the same clip in the AND-196 viewer.

FR-7. **Share.** A share button invokes the system share sheet (`ACTION_SEND`) with the canonical `https://testlogon.com/c/{clipId}` URL and clip title. **NOTE (verified, additive):** the backend also exposes `POST /broadcast/public/clips/{clip_id}/share` → `{ ok, share_count, share_url }` and `POST /broadcast/public/clips/{clip_id}/view` → `{ ok, view_count }` (verified `openapi.index.txt` lines 137–138; `src/api/endpoints/clips.ts: recordPublicClipShare`/`recordPublicClipView`). The web reference (a) fires `recordPublicClipView` on mount (fire-and-forget) and (b) on Share calls `recordPublicClipShare` and uses the returned `share_url` (prefixed with origin). AND-394 SHOULD mirror this: record a view on entry, and use the server `share_url` when present, falling back to the local canonical URL if the call fails/offline. This resolves OQ-3 (views ARE recorded, via a separate explicit POST — not server-side on the GET).

FR-8. **Lifecycle.** Playback pauses on `ON_PAUSE`, releases the player on `ON_STOP`/dispose, supports PiP via AND-168, and restores position on configuration change. Audio starts muted with an unmute toggle to satisfy autoplay-without-gesture constraints; user unmute is remembered for the session.

FR-9. **Refresh/retry.** On transient failure (timeout, 5xx, network) the screen shows a retryable error state with a single visible **Retry** action.

## 4. Technical Design

New feature module path: `feature-clips/src/main/kotlin/com/testlogon/android/feature/clips/public/`.

**Route (typed, Navigation-Compose 2.8 type-safe).**

```kotlin
@Serializable
data class PublicClipRoute(val clipId: String)

fun NavGraphBuilder.publicClipScreen(onOpenAuth: (clipId: String) -> Unit) {
    composable<PublicClipRoute> {
        PublicClipScreen(onOpenAuth = onOpenAuth)
    }
}

// Deep-link binding (manifest intent-filter from AND-196 maps the web URL;
// the route binds the path param):
composable<PublicClipRoute>(
    deepLinks = listOf(navDeepLink<PublicClipRoute>(basePath = "https://testlogon.com/c"))
)
```

**State.**

```kotlin
sealed interface PublicClipUiState {
    data object Loading : PublicClipUiState
    data class Ready(
        val clip: PublicClip,
        val isMuted: Boolean = true,
        val hasSession: Boolean = false,
    ) : PublicClipUiState
    data class Unavailable(val reason: ClipUnavailable) : PublicClipUiState   // see FR-5 (corrected)
    data class Error(val message: String, val retryable: Boolean) : PublicClipUiState
}

// CORRECTED: reasons are driven primarily by the verified `status` enum
// (processing|ready|failed|deleted) and HTTP outcome, NOT a `visibility` field.
// PRIVATE/REGION_BLOCKED are retained defensively but are unverified for this
// route (no 403/451 declared in OpenAPI for GET /broadcast/public/clips/{clip_id}).
enum class ClipUnavailable { NOT_FOUND, PROCESSING, REMOVED, FAILED, PRIVATE, REGION_BLOCKED }
```

**ViewModel.**

```kotlin
@HiltViewModel
class PublicClipViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repo: PublicClipRepository,
    private val session: SessionStateProvider,   // from core-data; readonly hasValidSession()
) : ViewModel() {
    private val clipId: String = savedStateHandle.toRoute<PublicClipRoute>().clipId

    private val _state = MutableStateFlow<PublicClipUiState>(PublicClipUiState.Loading)
    val state: StateFlow<PublicClipUiState> = _state.asStateFlow()

    init { load() }

    fun load() = viewModelScope.launch {
        _state.value = PublicClipUiState.Loading
        _state.value = repo.getPublicClip(clipId).toUiState(session.hasValidSession())
    }

    fun retry() = load()
    fun toggleMute() { _state.update { if (it is Ready) it.copy(isMuted = !it.isMuted) else it } }
}
```

**Repository (in `core-data`, backed by `ClipsApi` from AND-196 extended with the public route).**

```kotlin
interface PublicClipRepository {
    suspend fun getPublicClip(clipId: String): ApiResult<PublicClip>
}

class DefaultPublicClipRepository @Inject constructor(
    private val api: ClipsApi,
    private val errorMapper: ApiErrorMapper,        // FastAPI detail mapping
) : PublicClipRepository {
    override suspend fun getPublicClip(clipId: String): ApiResult<PublicClip> =
        runCatchingApi(errorMapper) { api.getPublicClip(clipId).toDomain() }
}
```

**Compose screen.** `PublicClipScreen` collects `state` via `collectAsStateWithLifecycle()` and renders: `Loading` → centered shimmer/progress; `Ready` → `VideoPlayer(mediaUri = clip.hlsUrl, muted = isMuted, autoPlay = true)` (AND-168) plus a metadata overlay (`ClipMetaOverlay`), `ShareButton`, and `OpenInAppCta(hasSession)`; `Unavailable` → `ClipUnavailableView(reason)`; `Error` → `RetryableErrorView(onRetry = vm::retry)`. The player is created/released through AND-168's lifecycle-aware wrapper.

**No autoplay-next / no pager.** This screen deliberately omits Paging 3 and the vertical pager — those belong to AND-196.

## 5. API Contract

**Resolve public clip. (CORRECTED — verified against OpenAPI + frontend.)**

```
GET /broadcast/public/clips/{clip_id}
Params: clip_id (path) only — no auth params (verified openapi.index.txt:136)
op = public_clip_route_broadcast_public_clips__clip_id__get
resp = 200:PublicClipOut ; 422:HTTPValidationError
```

Success `200` body is `PublicClipOut` (verified `components.schemas.PublicClipOut`). All listed fields are **required** in the schema; types as noted:

```json
{
  "clip_id": "clp_8f2a91",
  "session_id": "sess_123",
  "broadcaster_user_id": "usr_b",
  "broadcaster_display_name": "Nature Cam",
  "profile_id": "prof_1",
  "creator_user_id": "usr_c",
  "creator_display_name": "Clip Creator",
  "video_id": "vid_9",
  "title": "Sunset timelapse",
  "start_seconds": 12.0,
  "end_seconds": 30.4,
  "duration_seconds": 18.4,
  "status": "ready",
  "view_count": 10423,
  "share_count": 12,
  "thumbnail_url": "https://media.testlogon.com/clips/clp_8f2a91/thumb.jpg",
  "created_at": 1748689320
}
```

Note the corrected types/shape vs the prior draft: `created_at` is an **integer epoch-seconds** (not ISO string); `duration_seconds` is a **float number** in seconds (not `duration_ms`); `view_count`/`share_count` are integers; attribution is flat `*_display_name` strings (**no nested `author`, no `@handle`, no `avatar_url`**); the playback URL is **absent** (only `thumbnail_url` + `video_id`); there is **no `visibility`** field. `status` is the enum `processing | ready | failed | deleted`.

Error/edge mapping (corrected to the declared responses; speculative codes flagged):
- `422 HTTPValidationError` (malformed `clip_id`) → `Unavailable(NOT_FOUND)` (or generic terminal error). **Verified declared.**
- `404` (missing clip) → `Unavailable(NOT_FOUND)`. **Inferred** (FastAPI default; not declared for this op, but the web treats non-resolving as "Clip not found").
- `200` body with `status == "deleted"` → `Unavailable(REMOVED)`; `status == "failed"` → `Unavailable(FAILED)`; `status == "processing"` → `Unavailable(PROCESSING)` ("Clip is processing…", per web). **Verified via `status` enum.**
- `403` → `Unavailable(PRIVATE)` and `451` → `Unavailable(REGION_BLOCKED)` are **UNVERIFIED** for this route (no such responses declared). Keep defensive handling only because `client.ts` has a global `403`/`geo_blocked` path.
- `5xx` / timeout / IO → `Error(message, retryable = true)`.

**Retrofit/Moshi. (CORRECTED path + DTO.)**

```kotlin
interface ClipsApi {            // extends the AND-196 interface
    @GET("broadcast/public/clips/{clipId}")
    suspend fun getPublicClip(@Path("clipId") clipId: String): PublicClipDto

    // Additive, verified (lines 137–138). Mirror web view/share behavior.
    @POST("broadcast/public/clips/{clipId}/view")
    suspend fun recordPublicView(@Path("clipId") clipId: String): PublicClipCountDto

    @POST("broadcast/public/clips/{clipId}/share")
    suspend fun recordPublicShare(@Path("clipId") clipId: String): PublicClipShareDto
}

@JsonClass(generateAdapter = true)
data class PublicClipDto(
    @Json(name = "clip_id") val clipId: String,
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "broadcaster_user_id") val broadcasterUserId: String,
    @Json(name = "broadcaster_display_name") val broadcasterDisplayName: String,
    @Json(name = "profile_id") val profileId: String,
    @Json(name = "creator_user_id") val creatorUserId: String,
    @Json(name = "creator_display_name") val creatorDisplayName: String,
    @Json(name = "video_id") val videoId: String,
    val title: String,
    @Json(name = "start_seconds") val startSeconds: Double,
    @Json(name = "end_seconds") val endSeconds: Double,
    @Json(name = "duration_seconds") val durationSeconds: Double,
    val status: String,                                  // processing|ready|failed|deleted
    @Json(name = "view_count") val viewCount: Long,
    @Json(name = "share_count") val shareCount: Long,
    @Json(name = "thumbnail_url") val thumbnailUrl: String,
    @Json(name = "created_at") val createdAt: Long,      // epoch SECONDS
)

@JsonClass(generateAdapter = true)
data class PublicClipCountDto(val ok: Boolean, @Json(name = "view_count") val viewCount: Long)

@JsonClass(generateAdapter = true)
data class PublicClipShareDto(
    val ok: Boolean,
    @Json(name = "share_count") val shareCount: Long,
    @Json(name = "share_url") val shareUrl: String,
)
```

**OQ-4 (playback URL):** `PublicClipOut` exposes no manifest/HLS URL. Implementation MUST resolve how the AND-168 player obtains a stream — candidates: a yet-unconfirmed media-origin convention derived from `video_id`/`clip_id`, or a backend change adding `hls_url`. Until resolved, the player can only show `thumbnail_url`. Track as a hard prerequisite (see §13/§16).

## 6. Data & State Management

- **UiState:** single `StateFlow<PublicClipUiState>` exposed by the ViewModel; collected with `collectAsStateWithLifecycle`. `clipId` is read once from `SavedStateHandle.toRoute<PublicClipRoute>()`.
- **No Room persistence required.** Public clips are read-once on entry; caching them in Room offers little (cold deep-link, single item) and risks serving stale `visibility`. We rely on OkHttp's HTTP cache for the GET only (respecting `Cache-Control`). Decision: **no app-level Room cache for AND-394** (AND-196 may cache feed items independently).
- **Mute preference:** `isMuted` lives in UiState for the session only; not persisted to DataStore (a public viewer is largely ephemeral). A future enhancement could persist global mute via the existing player prefs DataStore from AND-168.
- **Playback position:** held by AND-168's player wrapper / `rememberSaveable` for config-change restore; not persisted across process death (acceptable for a single short clip).
- **Session awareness:** `SessionStateProvider.hasValidSession()` (read-only, from `core-data`) drives only the CTA label/target; it never gates playback.

## 7. Error Handling & Resilience

- **Unreliable dev host:** OkHttp call/connect/read timeouts ≈ **20s** (shared client config). The public GET is **idempotent**, so it is eligible for **bounded backoff retry** (max 2 retries, jittered, total budget ≤ ~45s) for `IOException`/timeout/`5xx`; `4xx` are **not** retried.
- **Terminal vs transient:** `403/404/410/451` and non-ready/non-public bodies are terminal `Unavailable` states (no retry button). Timeouts/network/`5xx` are `Error(retryable=true)` with a Retry button calling `vm.retry()`.
- **Player errors:** `PlaybackException` from Media3 (manifest 404, unsupported codec, network drop mid-stream) surfaces through AND-168's error overlay with its own retry that re-prepares the media source; we do not duplicate that logic.
- **Offline at entry:** if no connectivity, show `Error("You're offline", retryable=true)`; auto-retry once connectivity returns (observe `ConnectivityManager` if AND-196's connectivity observer is available, otherwise manual retry only).
- **CSRF/401 not applicable (native design choice — NOTE web differs):** the public GET requires no session server-side (verified: endpoint params are `clip_id` only). **CORRECTION of an implied claim:** the *web* `client.ts` does NOT special-case this route — it unconditionally attaches `X-CSRF-Token` (from the `ui_csrf` cookie, when present), `credentials: "include"`, and a `Bearer` token if logged in, to *all* requests, and runs the global `401 → POST /ui/session/refresh → retry` flow (verified `src/api/client.ts:140-237`). For the Android client we *choose* to exclude the public route from CSRF/auth injection and make the 401-refresh interceptor a no-op here (safe because the server does not require them); this is a deliberate native deviation from web, not a mirror of it.

## 8. Security & Privacy

- **Unauthenticated by design:** the screen MUST NOT attach `X-CSRF-Token` or require cookies for the public GET; it MUST NOT leak any session token into share URLs or logs. The shared URL is the bare canonical `https://testlogon.com/c/{clipId}`.
- **Transport:** dev backend is plaintext HTTP and is permitted only via the existing debug `network_security_config` cleartext allowlist for `18.222.237.167`. Production media/API hosts MUST be HTTPS; no new cleartext domains are added by this ticket.
- **Deep-link trust:** App Links use `autoVerify` (configured in AND-196) so only verified `testlogon.com` links open the app directly. `clipId` is treated as an opaque, server-validated token; the client performs basic format sanity (non-empty, length-bounded, `[A-Za-z0-9_-]`) before the network call to avoid malformed requests.
- **No PII collected** on this screen; view-count display is server-provided and non-identifying. Author handle/avatar are public profile data already exposed by the backend.

## 9. Accessibility & i18n

- All strings (title fallbacks, error/unavailable messages, CTA, share, mute toggle) in `strings.xml`; no hardcoded literals. Provide `contentDescription` for play/pause, mute/unmute, share, fullscreen, PiP, and author avatar.
- Video region has a descriptive label; control overlay targets ≥ 48dp touch targets and meets WCAG AA contrast against the dark scrim.
- Respect system font scaling (use `sp`); metadata overlay must not clip at 200% font scale (use scrollable/ellipsized text).
- Captions/subtitles: if the HLS manifest carries a subtitle track, AND-168's player exposes it; AND-394 surfaces the existing CC toggle when present.
- RTL-safe layout (start/end paddings). Auto-mute respects the accessibility expectation of no surprise audio; unmute is an explicit user action.

## 10. Telemetry & Logging

Emit via the shared analytics interface (consistent with other feature modules):
- `public_clip_open` { clipId, source = "deeplink"|"in_app", has_session }
- `public_clip_play_start` { clipId, time_to_first_frame_ms }
- `public_clip_unavailable` { clipId, reason } (NOT_FOUND/PRIVATE/REMOVED/REGION_BLOCKED)
- `public_clip_error` { clipId, kind = "timeout"|"network"|"5xx", retried }
- `public_clip_cta_tap` { clipId, target = "auth"|"feed" }
- `public_clip_share` { clipId }

Logging via Timber: no URLs containing tokens, no cookie values, no full response bodies in release builds. Player diagnostic logs (rebuffer count, bitrate) come from AND-168 and are out of scope here beyond `time_to_first_frame_ms`.

## 11. Testing Strategy

**Unit (core-testing, JUnit + Turbine + MockWebServer):**
- `PublicClipViewModel` emits `Loading → Ready` on `200`/ready/public.
- Maps `403→PRIVATE`, `404→NOT_FOUND`, `410→REMOVED`, `451→REGION_BLOCKED`.
- Coerces `200` with `status="processing"` and `visibility="private"` to the correct `Unavailable`.
- `timeout/5xx → Error(retryable=true)`; `retry()` re-issues the request.
- `toggleMute()` flips `isMuted` only in `Ready`.
- Repository: `ApiErrorMapper` correctly parses all three FastAPI `detail` shapes.
- MockWebServer verifies the request carries **no** `X-CSRF-Token` and **no** auth header.

**Compose UI (`createAndroidComposeRule`):**
- `Ready` shows the player + metadata + CTA; `Unavailable` shows terminal copy and no Retry; `Error` shows Retry which triggers `vm.retry()`.
- CTA shows "Sign in" when `hasSession=false`, "Open in app" when `true`.

**Instrumentation / E2E (the acceptance test — "Public clip plays"):**
- Launch via `adb shell am start -a android.intent.action.VIEW -d "https://testlogon.com/c/{seedClipId}"` against a seeded public clip on the dev backend; assert the player reaches `STATE_READY`/playing and first frame renders. Use an Espresso/UiAutomator idling resource around `play_start`.
- Deep-link routing test asserting cold-start and warm-resume both land on `PublicClipScreen` with the right `clipId`.

Player playback correctness itself (controls/PiP) is covered by AND-168's suite; AND-394 tests integration, not the player internals.

## 12. Dependencies & Sequencing

- **Hard dependency: AND-196** — provides `ClipsApi`/`ClipsRepository`, the `Clip`/author models, and the registered `/c/:clipId` App Link intent-filter. AND-394 extends `ClipsApi` with `getPublicClip` and adds the public screen. Must merge after AND-196.
- **Transitive: AND-168** (reusable `VideoPlayer`) and **AND-022** (NavHost/typed routes) must be in place.
- **Backend prerequisite:** the public/anonymous clip endpoint must exist and be reachable; confirm via `/openapi.json` (OQ-1). If absent, this ticket is blocked on backend work outside the Android repo.
- **Sequencing within AND-394:** (1) add `getPublicClip` to `ClipsApi` + DTO/mapping; (2) `PublicClipRepository` + error mapping + unit tests; (3) `PublicClipViewModel` + state; (4) `PublicClipScreen` Compose + route wiring; (5) deep-link/E2E acceptance test.
- **Blocks:** none currently listed in the backlog.

## 13. Risks & Open Questions

- **OQ-1 (path): RESOLVED.** The verified public endpoint is `GET /broadcast/public/clips/{clip_id}` → `PublicClipOut` (openapi.index.txt:136; `src/api/endpoints/clips.ts: getPublicClip`). The earlier `GET /clips/{clipId}/public` guess was wrong and is corrected throughout (§2/§5/FR-2).
- **OQ-4 (playback URL): OPEN / HIGH-RISK.** `PublicClipOut` carries **no HLS/manifest URL** (only `thumbnail_url`, `video_id`); the web reference renders a thumbnail placeholder, not a live player. The ticket's core "clip plays" goal cannot be met until a stream URL is available (backend field or a documented media-origin convention). This is a hard prerequisite, not a cosmetic swap.
- **OQ-2 (App Link ownership):** AND-196 registers the intent-filter; confirm it routes to the *public* screen for anonymous users rather than forcing the authenticated feed. If AND-196 routes everything to the feed, AND-394 must add a branch (anonymous → `PublicClipScreen`, session → AND-196 viewer).
- **R-1 (autoplay audio):** Starting muted is the safe default; product may want sound-on for deep-links — confirm desired default with product (FR-7/FR-8).
- **R-2 (dev host flakiness):** the unreliable backend may make the E2E acceptance test flaky; mitigate with the 20s timeout + bounded retry and a stable seeded clip; consider MockWebServer-backed variant for CI gating.
- **R-3 (HLS on minSdk 24):** verify Media3 1.4 HLS playback on API 24 emulator; AND-168 should already cover this.
- **OQ-3 (view-count freshness): RESOLVED.** Views are recorded by an explicit `POST /broadcast/public/clips/{clip_id}/view` (not server-side on the GET); the web fires it on mount (fire-and-forget). AND-394 mirrors this (see FR-7).

## 14. Acceptance Criteria

1. Following `https://testlogon.com/c/{clipId}` for a public, ready clip — from cold start and from a warm app — opens `PublicClipScreen` with the correct `clipId` and **the clip plays** (player reaches playing/first-frame), without any sign-in. (Maps directly to the backlog acceptance "Public clip plays.")
2. The public clip GET is issued with **no** session cookie requirement and **no** `X-CSRF-Token`; a `401` never blocks public playback.
3. Title, broadcaster/creator display names, view count, share count, and thumbnail render in `Ready` (CORRECTED — no `@handle`/avatar in the verified schema); missing optional fields degrade silently.
4. Status-driven and not-found bodies render the correct terminal `Unavailable` state — `status == "deleted"` → REMOVED, `"processing"` → PROCESSING, `"failed"` → FAILED, missing/`404`/`422` → NOT_FOUND — each with an "Open TestLogon" CTA and **no** Retry (CORRECTED from the unverified `403/404/410/451`+visibility model; PRIVATE/REGION_BLOCKED retained only defensively, unverified for this route).
5. Timeout/network/`5xx` render a retryable `Error`; **Retry** re-issues the request and can recover to `Ready`.
6. Share emits the canonical `https://testlogon.com/c/{clipId}` URL with title via the system share sheet.
7. CTA shows "Sign in" when anonymous and "Open in app"/feed when a valid session exists, passing `clipId` so the user returns to the same clip in the AND-196 viewer.
8. Playback auto-mutes on start with a working unmute toggle; pauses on background, releases on dispose, supports PiP via AND-168, restores position on rotation.
9. Unit, Compose, and the deep-link E2E "public clip plays" tests pass in CI.

## 15. Definition of Done

- `feature-clips` public screen, ViewModel, repository, route, and `ClipsApi.getPublicClip` implemented under `com.testlogon.android.feature.clips.public`, building on Kotlin 2.0.21 / AGP 8.7.3 / JDK 17 with KSP Hilt.
- All §14 acceptance criteria verified; the backlog acceptance "Public clip plays" demonstrated via the deep-link E2E test.
- Public GET excluded from CSRF/auth injection; verified by MockWebServer test.
- 20s timeouts + bounded idempotent-GET retry wired; terminal vs retryable error mapping complete; FastAPI `detail` shapes handled.
- All strings externalized; content descriptions, contrast, 48dp targets, font-scaling, and RTL verified.
- Telemetry events (§10) emitted; no tokens/cookies/URLs-with-secrets in release logs.
- Unit + Compose + instrumentation tests green in CI; lint/detekt clean; no new cleartext domains added to `network_security_config`.
- Merged to `android-port` after AND-196; OQ-1/OQ-2 resolved or explicitly tracked as follow-ups.

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT (Verified / Corrected / Unverified-assumption) and exact SOURCE.

1. **Public clip resolution endpoint is `GET /broadcast/public/clips/{clip_id}` → `PublicClipOut`.** VERDICT: Corrected (draft said `GET /clips/{clipId}/public`). SOURCE: OpenAPI `GET /broadcast/public/clips/{clip_id}` (openapi.index.txt:136, op `public_clip_route_broadcast_public_clips__clip_id__get`); `src/api/endpoints/clips.ts: getPublicClip`.
2. **The endpoint requires no auth params (anonymous).** VERDICT: Verified. SOURCE: openapi.index.txt:136 (`params=clip_id` only — no `user_sub`/`X-SESSION-ID`/`X-IMPERSONATION-TOKEN`), contrast authenticated `GET /broadcast/clips/{clip_id}` (line 130) which lists those params.
3. **`PublicClipOut` fields & types** (`clip_id, session_id, broadcaster_user_id, broadcaster_display_name, profile_id, creator_user_id, creator_display_name, video_id, title, start_seconds, end_seconds, duration_seconds, status, view_count, share_count, thumbnail_url, created_at` — all required; `created_at` integer epoch-seconds, `duration_seconds` float, counts integers). VERDICT: Corrected (draft invented `id, hls_url, poster_url, duration_ms, visibility, author{handle,display_name,avatar_url}`, ISO `created_at`). SOURCE: `components.schemas.PublicClipOut` (openapi.pretty.json:59937-60035); `src/api/types.ts: PublicBroadcastClip extends BroadcastClip` (lines 4927-4953).
4. **No HLS/playback-manifest URL in the payload; web renders only a thumbnail "Video player placeholder".** VERDICT: Verified (and corrects the draft's HLS-from-payload premise). SOURCE: `PublicClipOut` schema (no `hls_url`/`m3u8` field); `src/pages/clips/PublicClipPage.tsx:96-110` (thumbnail or "Video player placeholder"). The Android "HLS auto-plays from `hls_url`" design is therefore an Unverified-assumption (OQ-4).
5. **`status` enum is `processing | ready | failed | deleted`.** VERDICT: Verified. SOURCE: openapi.pretty.json:59987-59996; `src/api/types.ts:4938`.
6. **There is no `visibility` field; private/public gating by visibility is not in the schema.** VERDICT: Corrected. SOURCE: `PublicClipOut` schema (absent); `PublicBroadcastClip` (absent).
7. **Declared responses are only `200:PublicClipOut` and `422:HTTPValidationError`; `403/404/410/451` are not declared for this op.** VERDICT: Corrected/Unverified-assumption (draft asserted a `403/404/410/451` mapping). SOURCE: openapi.index.txt:136. `404` is inferred (FastAPI default; web treats non-resolving as "Clip not found", `PublicClipPage.tsx:66-72`).
8. **Web treats any non-resolving response as a generic "Clip not found" with `retry:false`.** VERDICT: Verified. SOURCE: `src/pages/clips/PublicClipPage.tsx:31-36, 66-72`.
9. **Views are recorded via `POST /broadcast/public/clips/{clip_id}/view` → `{ok, view_count}`; web fires it on mount.** VERDICT: Verified (resolves OQ-3). SOURCE: openapi.index.txt:138; `src/api/endpoints/clips.ts: recordPublicClipView`; `PublicClipPage.tsx:39-43`.
10. **Share uses `POST /broadcast/public/clips/{clip_id}/share` → `{ok, share_count, share_url}`; web copies `origin + share_url`.** VERDICT: Verified. SOURCE: openapi.index.txt:137; `src/api/endpoints/clips.ts: recordPublicClipShare`; `PublicClipPage.tsx:45-54`.
11. **Web route is `/c/:clipId` rendering `PublicClipPage`.** VERDICT: Verified. SOURCE: `src/App.tsx:283` (`<Route path="/c/:clipId" element={<PublicClipPage />} />`), import line 108.
12. **Web `client.ts` attaches `X-CSRF-Token` (from `ui_csrf` cookie), `credentials:"include"`, and `Authorization: Bearer` to ALL requests, with a global `401 → POST /ui/session/refresh → retry` flow — it does NOT exclude the public route.** VERDICT: Corrected (draft implied the public GET is excluded web-side; the exclusion is an Android-only design choice, safe because the server needs none of these). SOURCE: `src/api/client.ts:154-171, 180-237`; refresh path `client.ts:121-130, 204-221`.
13. **Web `client.ts` has a global `403` handler incl. a `detail.code === "geo_blocked"` branch.** VERDICT: Verified (basis for retaining defensive PRIVATE/REGION_BLOCKED handling, though unverified for this specific op). SOURCE: `src/api/client.ts:239-255`.
14. **Attribution is by display-name strings (`broadcaster_display_name`, `creator_display_name`), not handle/avatar.** VERDICT: Corrected. SOURCE: `PublicClipPage.tsx:118-141`; schema fields.
15. **Dev host `http://18.222.237.167:8000`, plaintext, unreliable.** VERDICT: Unverified-assumption from the spec/ticket context (not checkable from the provided reference files). SOURCE: spec §2 (carried over); no contradicting source found.
16. **Navigation-Compose 2.8 type-safe routes / `navDeepLink` / `toRoute` (framework APIs) and Media3 1.4 ExoPlayer HLS.** VERDICT: Unverified-assumption (framework ref — versions not checkable here). SOURCE (framework ref): developer.android.com/guide/navigation/design/type-safety and developer.android.com/media/media3/exoplayer/hls.

### Corrections made
- Endpoint path `GET /clips/{clipId}/public` → **`GET /broadcast/public/clips/{clip_id}`** (§2, FR-2, §5, Retrofit interface).
- Response schema replaced the fabricated body with the verified **`PublicClipOut`** shape & types; removed `hls_url`, `poster_url`, `duration_ms`, `visibility`, nested `author{handle,avatar_url}`, ISO `created_at`; added `session_id, broadcaster_*, profile_id, creator_*, video_id, start/end_seconds, duration_seconds (float), share_count, created_at (epoch int)` (§5, FR-4, AC-3, DTO).
- Error model: replaced the unverified `403/404/410/451 + visibility` mapping with the **status-enum-driven** model (`deleted/failed/processing`) plus inferred `404` and verified `422`; flagged `403/451` as unverified-defensive (§5, FR-5, AC-4, state enum).
- Metadata/attribution corrected to display-name strings (no `@handle`/avatar) (FR-4, AC-3).
- Added verified **view/share POST endpoints** and mirrored web behavior; resolved OQ-3 (FR-7, §5).
- CSRF claim corrected: web attaches CSRF/credentials/Bearer globally; Android exclusion is a deliberate native deviation, not a mirror of web (§7).
- Resolved OQ-1 (path) and added **OQ-4 (no playback URL)** as a hard open prerequisite (§13).
- Frontmatter `status: reviewed`, `reviewed_on: 2026-06-06`.

### Open assumptions
- **OQ-4 — playback/manifest URL:** Not present in any provided source. The verified `PublicClipOut` has no stream URL; how AND-168 obtains an HLS manifest (derive from `video_id`/`clip_id` vs a new backend field) is unverifiable here and blocks the literal "clip plays" goal. WHY unverifiable: no media-origin/CDN convention or playback endpoint appears in the OpenAPI index or frontend clips endpoints.
- **`403` PRIVATE / `451` REGION_BLOCKED for this route:** Not declared in OpenAPI for `GET /broadcast/public/clips/{clip_id}`; retained only because of `client.ts`'s global geo/403 handling. WHY unverifiable: endpoint declares only `200`/`422`.
- **`404` for missing clip:** Inferred FastAPI default + web "Clip not found"; not explicitly declared. WHY unverifiable: only `200`/`422` declared.
- **Dev host details, App Link `autoVerify`/intent-filter ownership (AND-196), AND-168 player API, AND-022 NavHost:** cross-ticket artifacts not in the provided reference; carried over as assumptions (OQ-2).
- **Framework versions** (Navigation-Compose 2.8, Media3 1.4, Kotlin/AGP/JDK): build-config claims not checkable from provided sources (framework refs).

## 17. Test Plan

IDs `TC-AND-394-NN`. "AC-#" traces to §14 acceptance criteria. Target legend per the CI/dev inventory: JVM/Robolectric (local), emulator AVD `test35` (API 35 x86_64), physical device Samsung Galaxy A15 5G `SM-A156U` serial `R5CX821TA9R` (API 34, arm64-v8a).

- **TC-AND-394-01 — Happy path: resolve + render Ready.** Type: unit (JVM + MockWebServer). Target: JVM/Robolectric (local). Preconditions: MockWebServer enqueues `200` with a valid `PublicClipOut` (`status:"ready"`). Steps: construct `PublicClipViewModel`; collect `state` via Turbine. Expected: emits `Loading → Ready(clip)`; `clip.title`, `broadcasterDisplayName`, `viewCount`, `shareCount`, `thumbnailUrl` mapped from snake_case; `createdAt` parsed as epoch-seconds Long; `durationSeconds` is Double. Traces: AC-1, AC-3.
- **TC-AND-394-02 — Contract: request shape & no auth/CSRF.** Type: contract/MockWebServer. Target: JVM/Robolectric (local). Preconditions: MockWebServer; cookie jar/session deliberately populated. Steps: call `getPublicClip("clp_x")`; inspect `RecordedRequest`. Expected: method `GET`, path `/broadcast/public/clips/clp_x`; **no** `X-CSRF-Token`, **no** `Authorization`, **no** `X-SESSION-ID` headers. Traces: AC-2.
- **TC-AND-394-03 — Status-driven Unavailable mapping.** Type: unit. Target: JVM/Robolectric (local). Preconditions: MockWebServer returns `200` bodies with `status` ∈ {`deleted`,`processing`,`failed`}. Steps: load for each. Expected: `Unavailable(REMOVED)`, `Unavailable(PROCESSING)`, `Unavailable(FAILED)` respectively; no Retry on terminal states. Traces: AC-4.
- **TC-AND-394-04 — Not-found / validation mapping.** Type: contract/MockWebServer. Target: JVM/Robolectric (local). Preconditions: enqueue `404` then `422 HTTPValidationError` (real FastAPI shape `{"detail":[{"loc":["path","clip_id"],"msg":"...","type":"..."}]}`). Steps: load for each. Expected: both → `Unavailable(NOT_FOUND)` (or generic terminal), no crash, no Retry; `ApiErrorMapper` parses the `detail` array shape. Traces: AC-4.
- **TC-AND-394-05 — Transient error is retryable and recovers.** Type: unit/contract. Target: JVM/Robolectric (local). Preconditions: MockWebServer enqueues `503`, then on retry a valid `200 ready`. Steps: load → assert `Error(retryable=true)`; call `vm.retry()`. Expected: re-issues GET, transitions to `Ready`. Traces: AC-5.
- **TC-AND-394-06 — Offline / flaky-dev-host at entry.** Type: integration. Target: physical device `R5CX821TA9R` (real radio toggle) — MUST run on device for genuine airplane-mode/connectivity-callback behavior; emulator network-off is an acceptable CI fallback. Preconditions: connectivity disabled, then re-enabled. Steps: open screen offline → assert `Error("You're offline", retryable=true)`; re-enable network; trigger retry (or auto-retry if connectivity observer present). Expected: recovers to `Ready` (or `Unavailable` per body); never hangs past the 20s timeout budget. Traces: AC-5.
- **TC-AND-394-07 — View recorded on entry; share uses server share_url.** Type: contract/MockWebServer. Target: JVM/Robolectric (local). Preconditions: enqueue `200 ready`, then `200` for `POST .../view` and `POST .../share` (`{ok,share_count,share_url}`). Steps: open screen; tap Share. Expected: a `POST /broadcast/public/clips/{id}/view` is issued on entry (fire-and-forget, failure ignored); Share issues `POST .../share` and the `ACTION_SEND` payload uses the canonical `https://testlogon.com/c/{id}` (preferring returned `share_url` when present) + title. Traces: AC-6.
- **TC-AND-394-08 — toggleMute only in Ready.** Type: unit. Target: JVM/Robolectric (local). Preconditions: VM in `Ready(isMuted=true)`; separately in `Loading`. Steps: call `toggleMute()` in each. Expected: flips `isMuted` only in `Ready`; no-op otherwise. Traces: AC-8.
- **TC-AND-394-09 — Compose: state rendering & Retry wiring.** Type: Compose-UI. Target: emulator AVD `test35`. Preconditions: fake VM exposing each state. Steps: render `Loading`/`Ready`/`Unavailable`/`Error`. Expected: `Ready` shows player/thumbnail + metadata (display names, counts) + CTA; `Unavailable` shows terminal copy + "Open TestLogon", **no** Retry; `Error` shows Retry that invokes `vm.retry()`. Traces: AC-3, AC-4, AC-5.
- **TC-AND-394-10 — Compose: CTA label/target by session.** Type: Compose-UI. Target: emulator AVD `test35`. Preconditions: `hasSession=false` then `true`. Steps: render Ready; tap CTA. Expected: label "Sign in" (anonymous) vs "Open in app" (session); tap invokes `onOpenAuth(clipId)` carrying the current `clipId`. Traces: AC-7.
- **TC-AND-394-11 — Accessibility checks.** Type: Compose-UI (+ instrumented a11y). Target: emulator AVD `test35`. Preconditions: Ready state; font scale 200%; enable accessibility checks (`AccessibilityChecks.enable()`). Steps: assert `contentDescription` on play/pause, mute/unmute, share, fullscreen/PiP, thumbnail; verify ≥48dp touch targets, AA contrast on scrim, no clipping at 200% scale; verify no externalized-string regressions. Expected: all assertions pass; no a11y violations. Traces: AC-3, AC-8.
- **TC-AND-394-12 — Deep-link routing: cold start & warm resume.** Type: instrumented/e2e. Target: emulator AVD `test35` (routing is ABI-agnostic). Preconditions: app installed; App Link intent-filter from AND-196 present. Steps: `adb shell am start -a android.intent.action.VIEW -d "https://testlogon.com/c/{seedId}"` with app (a) not running and (b) backgrounded. Expected: both land on `PublicClipScreen` with `clipId == seedId` (read via `toRoute<PublicClipRoute>()`). Traces: AC-1.
- **TC-AND-394-13 — E2E acceptance "Public clip plays" (real HLS).** Type: instrumented/e2e. Target: physical device `R5CX821TA9R` — MUST run on device (real-network HLS streaming, codec/ABI arm64-v8a, API-34 vs emulator API-35 behavior). Preconditions: a seeded **public, ready** clip on the dev backend **with a resolvable playback URL** (BLOCKED on OQ-4 until a stream URL exists; until then assert thumbnail render + non-crash). Steps: launch via the deep link; await `play_start` idling resource. Expected: player reaches `STATE_READY`/playing and first frame renders without sign-in. Traces: AC-1, AC-9.
- **TC-AND-394-14 — Lifecycle & PiP.** Type: instrumented. Target: physical device `R5CX821TA9R` (PiP/lifecycle fidelity preferred on real hardware; emulator acceptable for rotation-only). Preconditions: Ready + playing. Steps: rotate (config change); background (`ON_PAUSE`/`ON_STOP`); enter PiP; dispose. Expected: pauses on background, position restored on rotation, PiP via AND-168 works, player released on dispose (no leak). Traces: AC-8.

### Coverage matrix (§14 AC → TC)
- AC-1 (deep-link opens & plays, cold+warm, no sign-in): TC-01, TC-12, TC-13.
- AC-2 (no cookie/CSRF requirement; 401 never blocks): TC-02.
- AC-3 (metadata renders; optional degrade): TC-01, TC-09, TC-11.
- AC-4 (terminal Unavailable, no Retry): TC-03, TC-04, TC-09.
- AC-5 (retryable Error recovers): TC-05, TC-06, TC-09.
- AC-6 (share canonical URL + title): TC-07.
- AC-7 (CTA label/target by session, passes clipId): TC-10.
- AC-8 (auto-mute/unmute, lifecycle, PiP, rotation): TC-08, TC-11, TC-14.
- AC-9 (unit/Compose/E2E green in CI): TC-13 (E2E) + all unit/Compose cases TC-01..TC-11.
