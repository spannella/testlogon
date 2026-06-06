---
id: AND-394
title: Public clip
milestone: M8
epic: E51
priority: P2
size: M
status: draft
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
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (PLAINTEXT HTTP, unreliable). OpenAPI at `/openapi.json`. Public clip data is served by an unauthenticated GET (see §5); HLS variant playlists are served from the media/CDN origin referenced in the clip payload.
- **Web reference:** `frontend/src/api/endpoints/clips.ts` and shared types in `frontend/src/api/types.ts` (route `/c/:clipId`). These define the canonical request/response shapes mirrored below.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Media3 1.4, Coil. Module layering `app → feature-clips → core-network/core-model/core-ui/core-data`. minSdk 24 / targetSdk 35, JDK 17, AGP 8.7.3.
- **Namespace:** `com.testlogon.android` everywhere.

## 3. Functional Requirements

FR-1. **Deep-link entry.** An Android App Link / web URL of form `https://testlogon.com/c/{clipId}` (and the `http`/custom-scheme fallbacks registered in AND-196) MUST route to `PublicClipScreen` with `clipId` extracted as a typed nav argument. The intent-filter (registered by AND-196) MUST cover both cold start and warm resume.

FR-2. **Anonymous resolution.** The screen MUST resolve the clip through the **public** endpoint `GET /clips/{clipId}/public` (§5) using **no** auth/CSRF requirements. The persistent cookie jar MAY be present (returning user) but MUST NOT be required; a `401`/missing session MUST NOT block playback of a public clip.

FR-3. **Playback.** On successful resolution the clip's HLS manifest URL MUST be handed to the AND-168 `VideoPlayer`, which begins buffering immediately and auto-plays once ready (muted-autostart is acceptable; see FR-7). The player surface is full-bleed with the AND-168 control overlay (play/pause, scrub, volume, fullscreen, PiP).

FR-4. **Metadata.** Title, author handle (`@handle`), and formatted view count MUST render as an overlay/caption. Author avatar loaded via Coil. Missing optional fields degrade silently (no empty rows).

FR-5. **Visibility gates.** The screen MUST distinguish and surface, as distinct UI states: clip **not found** (`404`), clip **private/forbidden** (`403`), clip **removed/inactive** (`410`/`status != "ready"`), and **geo/region-blocked** (`451`). Each shows a terminal message and an "Open TestLogon" CTA; none crash or hang.

FR-6. **Anonymous → app bridge.** A persistent CTA ("Sign in" / "Open in app") MUST navigate anonymous users to the auth flow (or the authenticated clips feed if a valid session already exists), passing the current `clipId` so the user lands back on the same clip in the AND-196 viewer.

FR-7. **Share.** A share button invokes the system share sheet (`ACTION_SEND`) with the canonical `https://testlogon.com/c/{clipId}` URL and clip title.

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
    data class Unavailable(val reason: ClipUnavailable) : PublicClipUiState   // 403/404/410/451
    data class Error(val message: String, val retryable: Boolean) : PublicClipUiState
}

enum class ClipUnavailable { NOT_FOUND, PRIVATE, REMOVED, REGION_BLOCKED }
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

**Resolve public clip.**

```
GET /clips/{clipId}/public
Headers: (none required — no cookies, no X-CSRF-Token)
```

Success `200`:

```json
{
  "id": "clp_8f2a91",
  "title": "Sunset timelapse",
  "status": "ready",
  "visibility": "public",
  "hls_url": "https://media.testlogon.com/clips/clp_8f2a91/master.m3u8",
  "poster_url": "https://media.testlogon.com/clips/clp_8f2a91/poster.jpg",
  "duration_ms": 18400,
  "view_count": 10423,
  "author": { "handle": "naturecam", "display_name": "Nature Cam", "avatar_url": "https://.../a.jpg" },
  "created_at": "2026-05-31T11:02:00Z"
}
```

Error responses use FastAPI `detail` (string | `[{msg}]` | `{code,...}`), mapped by `ApiErrorMapper`:
- `403` → `Unavailable(PRIVATE)`  ·  `404` → `Unavailable(NOT_FOUND)`  ·  `410` → `Unavailable(REMOVED)`  ·  `451` → `Unavailable(REGION_BLOCKED)`.
- A `200` body with `status != "ready"` or `visibility != "public"` is also coerced to the matching `Unavailable`.
- `5xx` / timeout / IO → `Error(message, retryable = true)`.

**Retrofit/Moshi.**

```kotlin
interface ClipsApi {            // extends the AND-196 interface
    @GET("clips/{clipId}/public")
    suspend fun getPublicClip(@Path("clipId") clipId: String): PublicClipDto
}

@JsonClass(generateAdapter = true)
data class PublicClipDto(
    val id: String,
    val title: String?,
    val status: String,
    val visibility: String,
    @Json(name = "hls_url") val hlsUrl: String?,
    @Json(name = "poster_url") val posterUrl: String?,
    @Json(name = "duration_ms") val durationMs: Long?,
    @Json(name = "view_count") val viewCount: Long?,
    val author: AuthorDto?,
    @Json(name = "created_at") val createdAt: String?,
)
```

The exact public path MUST be confirmed against `/openapi.json` and `frontend/src/api/endpoints/clips.ts` during implementation; if the backend exposes the public clip via the same `GET /clips/{clipId}` with anonymous access rather than a `/public` suffix, the interface method swaps to that path with no other architectural change (open question OQ-1).

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
- **CSRF/401 not applicable:** the public GET carries no session; the global 401→`/ui/session/refresh`→retry interceptor MUST be a no-op here (the public route should be excluded from CSRF header injection).

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

- **OQ-1 (path):** Exact public endpoint shape — `GET /clips/{clipId}/public` vs anonymous `GET /clips/{clipId}` — pending `/openapi.json` and `frontend/.../clips.ts`. Low-risk swap; isolate behind `ClipsApi`.
- **OQ-2 (App Link ownership):** AND-196 registers the intent-filter; confirm it routes to the *public* screen for anonymous users rather than forcing the authenticated feed. If AND-196 routes everything to the feed, AND-394 must add a branch (anonymous → `PublicClipScreen`, session → AND-196 viewer).
- **R-1 (autoplay audio):** Starting muted is the safe default; product may want sound-on for deep-links — confirm desired default with product (FR-7/FR-8).
- **R-2 (dev host flakiness):** the unreliable backend may make the E2E acceptance test flaky; mitigate with the 20s timeout + bounded retry and a stable seeded clip; consider MockWebServer-backed variant for CI gating.
- **R-3 (HLS on minSdk 24):** verify Media3 1.4 HLS playback on API 24 emulator; AND-168 should already cover this.
- **OQ-3 (view-count freshness):** whether opening a public clip should increment views (a POST) is out of scope unless the backend does it server-side on the GET.

## 14. Acceptance Criteria

1. Following `https://testlogon.com/c/{clipId}` for a public, ready clip — from cold start and from a warm app — opens `PublicClipScreen` with the correct `clipId` and **the clip plays** (player reaches playing/first-frame), without any sign-in. (Maps directly to the backlog acceptance "Public clip plays.")
2. The public clip GET is issued with **no** session cookie requirement and **no** `X-CSRF-Token`; a `401` never blocks public playback.
3. Title, author handle, view count, and poster/avatar render in `Ready`; missing optional fields degrade silently.
4. `403/404/410/451` and non-ready/non-public bodies render the correct terminal `Unavailable` state (PRIVATE/NOT_FOUND/REMOVED/REGION_BLOCKED) with an "Open TestLogon" CTA and **no** Retry.
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
