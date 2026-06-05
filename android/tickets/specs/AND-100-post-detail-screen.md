---
id: AND-100
title: Post detail screen
milestone: M2
epic: E14
priority: P1
size: M
status: draft
depends_on: [AND-099]
blocks: []
---

# AND-100 — Post detail screen

## 1. Overview & Goal

Deliver a read-only, full-screen view of a single post identified by its `post_id`,
reachable both by in-app navigation (tapping a post in a feed/list) and by an external
deep link (`testlogon://post/{postId}` and `https://testlogon.app/post/{postId}`). The
screen fetches one post from the backend, renders its full content — author header,
body text, attached media (images and HLS video), and link previews — by reusing the
`PostItem` composable family delivered in AND-099, and exposes loading / error / empty /
offline-stale states.

This ticket explicitly scopes **viewing only**. No likes, reposts, comments, bookmarks,
share-to-network, or other write interactions are implemented here; the detail screen
must leave structural room (a stable bottom action bar slot and a top-app-bar overflow
slot) for the interaction ticket(s) that follow in epic E14, but those slots render
nothing actionable in this ticket beyond a system "Share link" affordance.

Goal is met when: a valid `post_id` opens and renders the post (text + media) from a
cold start via deep link, and from warm in-app navigation, with correct handling of
not-found (404), unauthorized (401 → refresh-once → retry), and offline conditions.

## 2. Context & References

- Module: new `feature-postdetail` module under `android/feature-postdetail`,
  namespace `com.testlogon.android.feature.postdetail`. Layering:
  `app → feature-postdetail → core-network, core-model, core-ui, core-data, core-testing`.
- Reuses `PostItem` and sub-composables from AND-099 (`feature-post` / `core-ui`):
  `AuthorHeader`, `PostBody`, `MediaGrid`, `LinkPreviewCard`, `RelativeTimestamp`.
- Web reference: `frontend/src/api/endpoints/posts.ts` (single-post fetch) and shared
  shapes in `frontend/src/api/types.ts` (`Post`, `Media`, `Author`, `LinkPreview`).
- Backend contract: `GET /ui/posts/{post_id}` on FastAPI dev host
  `http://18.222.237.167:8000`; OpenAPI at `/openapi.json`. Cookie-based session +
  `X-CSRF-Token` echo handled by the shared OkHttp stack (cookie jar, CSRF interceptor,
  401 refresh-once interceptor).
- Navigation: single-Activity Navigation-Compose graph owned by `app`. This ticket adds
  one destination and its deep-link `intent-filter` registration.
- Depends on AND-099 (Post item composable) for rendering primitives.

## 3. Functional Requirements

FR-1. A `PostDetailScreen` destination accepts a required `postId: String` argument.

FR-2. On entry the screen loads the post via `GET /ui/posts/{post_id}` and renders:
author header (avatar, display name, handle, absolute+relative timestamp), full body
text (no line-clamp; selectable text), media grid (1–N images and/or HLS videos),
and link previews. Body text is fully expanded — unlike the feed item, no "see more"
truncation is applied.

FR-3. Media rendering reuses AND-099 components. Images load via Coil; videos use a
Media3/ExoPlayer surface that is created lazily on first visibility and released on
`onStop`/dispose. Only one ExoPlayer instance is active at a time on the screen.

FR-4. Deep linking: tapping `testlogon://post/{postId}` or
`https://testlogon.app/post/{postId}` (and `http` variant) opens this screen directly,
creating a synthetic back stack so the system Back button returns to the app home/feed
rather than exiting the app.

FR-5. A top app bar shows a Back/Up affordance, a centered "Post" title, and an
overflow menu containing "Share link" (emits an `ACTION_SEND` chooser with the canonical
`https://testlogon.app/post/{postId}` URL) and "Open in browser". Other interaction
affordances are out of scope.

FR-6. States: `Loading` (skeleton matching post layout), `Content` (post rendered),
`Empty/NotFound` (404 → "This post is unavailable" with Back), `Error` (retryable with
a Retry button), and `Stale` (cached copy shown with an "Offline — showing saved copy"
banner when network is unavailable but a cached post exists).

FR-7. Pull-to-refresh re-fetches the post (idempotent GET, eligible for bounded retry).

FR-8. If the post arrives via navigation with a pre-supplied lightweight `Post` (from the
list), the screen may render it immediately as initial content and then refresh in the
background; otherwise it loads from scratch.

## 4. Technical Design

Module `feature-postdetail` (Compose + Hilt, KSP). Key types:

```kotlin
package com.testlogon.android.feature.postdetail

@Serializable
data class PostDetailArgs(val postId: String)

sealed interface PostDetailUiState {
    data object Loading : PostDetailUiState
    data class Content(
        val post: Post,
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
    ) : PostDetailUiState
    data object NotFound : PostDetailUiState
    data class Error(val message: String, val retryable: Boolean) : PostDetailUiState
}

@HiltViewModel
class PostDetailViewModel @Inject constructor(
    private val repo: PostDetailRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {
    private val args: PostDetailArgs = savedStateHandle.toRoute()
    val uiState: StateFlow<PostDetailUiState>          // started WhileSubscribed(5_000)
    fun load(force: Boolean = false)
    fun retry()
    fun refresh()                                       // sets isRefreshing then load(force=true)
}
```

Repository in `core-data`, depending on a Retrofit service in `core-network`:

```kotlin
interface PostDetailRepository {
    /** Emits cached post first (if any), then network result. */
    fun observePost(postId: String): Flow<ApiResult<Post>>
    suspend fun fetchPost(postId: String): ApiResult<Post>
}

interface PostApi {
    @GET("ui/posts/{post_id}")
    suspend fun getPost(@Path("post_id") postId: String): Response<PostDto>
}
```

Composables:

```kotlin
@Composable
fun PostDetailRoute(
    onBack: () -> Unit,
    viewModel: PostDetailViewModel = hiltViewModel(),
)

@Composable
fun PostDetailScreen(
    state: PostDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onShare: () -> Unit,
    onOpenInBrowser: () -> Unit,
)
```

`PostDetailScreen` uses `Scaffold` + `TopAppBar` (Material 3, `pinnedScrollBehavior`),
a `PullToRefreshBox`, and a single scrollable `Column` (not `LazyColumn` — a post is one
unit; long bodies still fit a verticalScroll). The `Content` state delegates body/media
rendering to AND-099's `PostItem(post, mode = PostRenderMode.Detail)`, where `Detail`
mode disables clamping and enables full-bleed media.

Navigation registration in `app`:

```kotlin
composable<PostDetailArgs>(
    deepLinks = listOf(
        navDeepLink<PostDetailArgs>(basePath = "testlogon://post"),
        navDeepLink<PostDetailArgs>(basePath = "https://testlogon.app/post"),
    ),
) { PostDetailRoute(onBack = navController::navigateUp) }
```

Manifest `intent-filter` (in `app`) declares the `https`/`http` and custom-scheme hosts
with `android:autoVerify="true"` for App Links; a paired `assetlinks.json` is tracked
separately (AND App-Links infra ticket; reference only, not blocking). When launched cold
via deep link, the graph sets the home/feed as the synthetic parent so Up/Back is sane.

ExoPlayer lifecycle is bound via `LocalLifecycleOwner`; the player is `remember`ed,
prepared on `ON_START`, paused on `ON_PAUSE`, released on `ON_DESTROY` / `onDispose`.

## 5. API Contract

`GET /ui/posts/{post_id}` (cookie-authenticated; idempotent; retry-eligible).

Request headers: session cookies (jar), `X-CSRF-Token: <ui_csrf cookie value>`.

Success `200`:

```json
{
  "id": "p_01HZX9",
  "author": {
    "id": "u_42",
    "display_name": "Ada L.",
    "handle": "ada",
    "avatar_url": "https://.../a.jpg"
  },
  "body": "full post text…",
  "created_at": "2026-05-30T18:04:11Z",
  "edited_at": null,
  "media": [
    { "type": "image", "url": "https://.../1.jpg", "width": 1080, "height": 1350, "alt": "…" },
    { "type": "video", "hls_url": "https://.../v.m3u8", "poster_url": "https://.../p.jpg", "duration_ms": 30200 }
  ],
  "link_previews": [
    { "url": "https://ex.com", "title": "…", "description": "…", "image_url": "https://.../og.jpg" }
  ],
  "counts": { "likes": 12, "comments": 3, "reposts": 1 }
}
```

`PostDto` is mapped to the `core-model` `Post` via a `toDomain()` mapper; unknown media
`type` values map to an `Unsupported` media variant that renders a placeholder. `counts`
is parsed and stored but not acted upon in this ticket.

Error mapping (FastAPI `detail` is `string | [{msg}] | {code,...}`):
- `404` → `PostDetailUiState.NotFound`.
- `401` → handled by the shared refresh-once interceptor: `POST /ui/session/refresh`
  then a single retry; persistent 401 → `Error("Session expired", retryable=false)`
  and a one-shot navigation event to re-authenticate (owned by the auth/session ticket).
- `4xx`/`5xx` other → `Error(detail-derived message, retryable=true)`.
- Timeout / IO (dev host ~20s timeout) → `Error("Couldn't reach the server", retryable=true)`
  or `Content(isStale=true)` if a cached copy exists.

No request body; no write endpoints used. Interaction endpoints (like/comment) are
deferred to the E14 interaction ticket and are out of scope.

## 6. Data & State Management

- `StateFlow<PostDetailUiState>` exposed by the ViewModel, collected with
  `collectAsStateWithLifecycle()`. `started = WhileSubscribed(5_000)` so config changes
  don't refetch.
- Room cache (`core-data`): a `PostEntity` keyed by `id` with a `cached_at` epoch.
  `observePost(postId)` reads cache first (emit if present), then performs the network
  fetch and upserts. This provides the `Stale` path and instant warm opens. TTL for
  "fresh vs stale" is 5 minutes; beyond TTL with no network the cached copy is shown with
  the offline banner.
- DataStore is not used here (no per-post prefs).
- `postId` survives process death via `SavedStateHandle.toRoute()`. Scroll position is
  preserved via `rememberScrollState` (Compose `saveable`).
- The optional list-supplied `Post` (FR-8) is passed as a navigation-time hint by id only
  (we re-fetch authoritative data); we do **not** serialize a full `Post` into the route,
  to keep deep links and route args small and URL-safe.

## 7. Error Handling & Resilience

- All network calls funnel through `ApiResult<T>` (`Success`, `Failure(code, message)`,
  `NetworkError`, `Unauthorized`). The dev host is unreliable: OkHttp call/connect/read
  timeouts set to ~20s; `GET /ui/posts/{id}` is idempotent and uses bounded exponential
  backoff (max 3 attempts, base 500ms, jitter, cap 4s) for `NetworkError` and `5xx` only.
- `401` triggers the shared refresh-once-then-retry interceptor; no infinite loops
  (refresh attempted at most once per originating request).
- Offline: if `ConnectivityManager` reports no validated network, skip the network attempt
  when a fresh cache exists; if cache is stale, attempt once then fall back to `Stale`.
- `NotFound` is terminal (no retry button; Back only).
- Media failures are isolated: a failed image/video does not fail the whole screen; Coil
  shows an error placeholder, ExoPlayer surfaces a retry chip on `PlaybackException`.

## 8. Security & Privacy

- Transport: the dev backend is plaintext HTTP, permitted only via a scoped
  `network_security_config` cleartext allowlist for `18.222.237.167`; production hosts
  remain HTTPS-only. No secrets logged.
- Auth rides on the persistent cookie jar; `X-CSRF-Token` is attached by the CSRF
  interceptor on every request. This ticket adds no new credential storage.
- Deep links: `postId` is validated (`^[A-Za-z0-9_\-]{1,64}$`) before use; malformed ids
  short-circuit to `NotFound` without a network call, preventing injection into the path.
- App Links use `autoVerify` so only verified domains open in-app; the custom scheme is
  treated as untrusted input and validated identically.
- Shared "Share link" emits only the canonical public post URL, never session tokens or
  cookies.

## 9. Accessibility & i18n

- All actionable elements (Back, overflow items, Retry, media) have
  `contentDescription` / `semantics`. Media `alt` text from the API populates image
  `contentDescription`; videos announce "Video, double-tap to play".
- Body text is `SelectionContainer`-wrapped and respects Dynamic Type / font scale; layout
  reflows up to 200% font scale without clipping (verified via `fontScale` previews).
- Touch targets ≥ 48dp; color contrast meets WCAG AA against Material 3 theme tokens.
- All user-facing strings (state messages, menu items, banner) live in
  `feature-postdetail` `strings.xml`; no hardcoded strings. Timestamps and relative time
  use `android.text.format` / locale-aware formatting from AND-099.
- TalkBack focus order: top bar → banner (if stale) → author header → body → media →
  link previews.

## 10. Telemetry & Logging

- Analytics events (via the app's analytics facade, no PII): `post_detail_opened`
  `{ post_id, source: "deeplink"|"navigation", warm_start: Bool }`,
  `post_detail_load_result` `{ post_id, result: "success"|"not_found"|"error"|"stale", latency_ms }`,
  `post_detail_media_play` `{ post_id, media_index }`, `post_detail_share`.
- Logging via Timber: tag `PostDetail`; log error codes and latency at `w`/`e`; never log
  cookie/CSRF values or full response bodies. Debug builds may log the resolved deep-link
  URI; release builds log only the validated `post_id`.

## 11. Testing Strategy

- Unit (JVM, `core-testing` + Turbine): `PostDetailViewModel` state transitions for
  success, 404→NotFound, 401→refresh→retry→success, 401-persistent→Error, network
  error→Error, cache-hit→Content then refresh, offline→Stale. Mapper test `PostDto.toDomain()`
  including unsupported media type.
- Repository tests against a MockWebServer with scripted 200/404/401/500/timeout and a
  Room in-memory DB to assert cache-first emission and upsert.
- Compose UI tests (`createAndroidComposeRule`): each `PostDetailUiState` renders expected
  nodes; Retry invokes `onRetry`; overflow → Share invokes `onShare`; skeleton shown in
  Loading; stale banner shown when `isStale`.
- Navigation/deep-link instrumented test: launch `Intent(ACTION_VIEW,
  Uri.parse("testlogon://post/p_01HZX9"))` and assert the destination resolves with the
  correct `postId` and a non-empty back stack returning to home.
- Acceptance verification: deep-link cold start renders text + media; in-app navigation
  renders the same post.

## 12. Dependencies & Sequencing

- **Depends on AND-099** (Post item composable) — required: detail rendering reuses its
  `PostItem`, `MediaGrid`, `AuthorHeader`, `LinkPreviewCard`. AND-099 in turn depends on
  AND-098 and AND-103 (transitive; not directly blocking this ticket's start once AND-099
  lands).
- Consumes the shared OkHttp/Retrofit/Moshi stack, cookie jar, CSRF + 401-refresh
  interceptors, and `ApiResult` (core-network, delivered earlier in M0/M1).
- Does **not** block on the App-Links `assetlinks.json` infra ticket (deep linking works
  via the custom scheme and unverified web links meanwhile).
- **Blocks**: the E14 post-interaction ticket(s) (like/comment/share-to-network), which
  attach to the action-bar/overflow slots reserved here.

## 13. Risks & Open Questions

- R1: Exact single-post payload shape must be confirmed against `/openapi.json`; field
  names above mirror the web `types.ts` but `counts`/`link_previews` nullability is
  assumed. Mapper is defensive (nullable + defaults).
- R2: Dev host instability may cause flaky media (HLS) playback; mitigated by isolated
  media error handling and Stale fallback.
- R3: App Links verification requires production domain + hosted `assetlinks.json`;
  until then `https`/`http` links may show the disambiguation chooser. Open question:
  final canonical domain (`testlogon.app` assumed).
- R4: Whether a list-supplied `Post` snapshot should render instantly (FR-8) depends on
  AND-099's exported model surface; decided to pass id-only and re-fetch (see §6).
- Open: is `GET /ui/posts/{id}` the correct path, or is it `/ui/post/{id}`? Verify in
  OpenAPI before implementation.

## 14. Acceptance Criteria

AC-1. Navigating to a valid `post_id` from a feed/list opens `PostDetailScreen` and
renders the full post: author header, full (un-clamped) body text, and all media.
AC-2. Launching `testlogon://post/{postId}` (and `https://testlogon.app/post/{postId}`)
from a cold start opens the post directly with a back stack that returns to home.
AC-3. Media renders: images via Coil; HLS video plays via ExoPlayer, with the player
released on dispose/stop.
AC-4. `404` shows the "unavailable" NotFound state; `401` performs refresh-once then
retry; network failure shows a retryable Error and, when cache exists, the Stale banner.
AC-5. Pull-to-refresh and Retry re-fetch the post.
AC-6. Overflow → "Share link" emits a chooser with the canonical post URL; no
write/interaction actions are present.
AC-7. Screen is TalkBack-navigable, respects font scaling to 200%, and uses externalized
strings.

## 15. Definition of Done

- `feature-postdetail` module created under `com.testlogon.android.feature.postdetail`
  with ViewModel, repository, Retrofit service, mapper, and composables as specified.
- Navigation destination + deep links registered in `app`; `intent-filter` (with
  `autoVerify`) and cleartext allowlist entry added.
- All acceptance criteria (§14) demonstrably pass.
- Unit, repository (MockWebServer + in-memory Room), Compose UI, and deep-link
  instrumented tests written and green in CI; new code coverage ≥ project threshold.
- No hardcoded user-facing strings; lint, ktlint/detekt, and `assembleDebug` clean.
- No secrets or PII in logs/telemetry; plaintext HTTP limited to the dev host.
- PR opened against `android-port` with screenshots of Loading/Content/NotFound/Error/
  Stale states and a deep-link demo; reviewed and approved.
