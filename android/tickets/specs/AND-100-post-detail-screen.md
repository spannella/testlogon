---
id: AND-100
title: Post detail screen
milestone: M2
epic: E14
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
not-found (404 at runtime), forbidden (403 → "subscription required"), unauthorized
(401 → refresh-once → retry), and offline conditions.

> Reviewer note (AND-100 review, 2026-06-06): the single-post endpoint is
> `GET /posts/{post_id}` (NOT `/ui/posts/{post_id}` as originally drafted), the response
> body matches the web `FeedPost` DTO (not the invented JSON in §5), and the web client
> authenticates with `Authorization: Bearer` **plus** cookies + `X-CSRF-Token`. See §16 for
> the full citation/correction audit.

## 2. Context & References

- Module: new `feature-postdetail` module under `android/feature-postdetail`,
  namespace `com.testlogon.android.feature.postdetail`. Layering:
  `app → feature-postdetail → core-network, core-model, core-ui, core-data, core-testing`.
- Reuses `PostItem` and sub-composables from AND-099 (`feature-post` / `core-ui`):
  `AuthorHeader`, `PostBody`, `MediaGrid`, `LinkPreviewCard`, `RelativeTimestamp`.
- Web reference: `src/api/endpoints/newsfeed.ts` (`getPost(postId)` → single-post fetch),
  the single-post page `src/pages/feed/PostDetailPage.tsx`, and shared shapes in
  `src/api/types.ts` (`FeedPost`, `LinkPreview`). NOTE (corrected in review): there is no
  `posts.ts` and no `Post`/`Media`/`Author` DTO; the web DTO is `FeedPost` and media is
  expressed as `image_urls: string[]` + a single `video` object, not a `media[]` array.
- Backend contract: `GET /posts/{post_id}` (corrected — NOT `/ui/posts/{post_id}`) on the
  FastAPI dev host `http://18.222.237.167:8000`; OpenAPI at `/openapi.json`
  (op=`get_post_posts__post_id__get`, tag `newsfeed`). The web client sends
  `Authorization: Bearer <accessToken>` **plus** session cookies and `X-CSRF-Token`
  (value of the `ui_csrf` cookie); the Android port mirrors this via the shared OkHttp
  stack (auth-token interceptor, cookie jar, CSRF interceptor, 401 refresh-once
  interceptor). HLS video additionally requires a per-post entitlement call
  (`POST /ui/posts/{post_id}/video/entitlement`) to obtain a playable manifest URL.
- Navigation: single-Activity Navigation-Compose graph owned by `app`. This ticket adds
  one destination and its deep-link `intent-filter` registration.
- Depends on AND-099 (Post item composable) for rendering primitives.

## 3. Functional Requirements

FR-1. A `PostDetailScreen` destination accepts a required `postId: String` argument.

FR-2. On entry the screen loads the post via `GET /posts/{post_id}` (corrected from
`/ui/posts/{post_id}`) and renders: author header (resolved from `author_id` — see note
below — display name, handle, avatar, absolute+relative timestamp), full body text
(no line-clamp; selectable text), media (0–N images from `image_urls`, plus an optional
single `video`), and any link preview. Body text is fully expanded — unlike the feed item,
no "see more" truncation is applied.

> Author note: `FeedPost` exposes only `author_id` (a string), not an embedded author
> object. The web `PostCard` resolves author display data separately. This Android ticket
> must either (a) reuse AND-099's author-resolution path or (b) accept author fields only
> if AND-099's model surface enriches them. This is an open dependency on AND-099 (see §16
> Open assumptions).

FR-3. Media rendering reuses AND-099 components. Images (`image_urls`) load via Coil;
the optional `video` uses a Media3/ExoPlayer surface created lazily on first visibility and
released on `onStop`/dispose. Only one ExoPlayer instance is active at a time. HLS playback
follows the web flow: call `POST /ui/posts/{post_id}/video/entitlement` to obtain a fresh
`hls_manifest_url` (and short-lived `playback_token`), falling back to
`video.hls_manifest_url` from the post payload if the entitlement call fails or is not
required. (The original FR omitted the entitlement step; corrected per
`src/pages/feed/VideoPostPlayer.tsx`.) Locked/paywalled videos (`lock_*`/`unlock_*` fields)
show the blurred `thumbnail_url` instead of playing — gating handled as in AND-099.

FR-4. Deep linking: tapping `testlogon://post/{postId}` or
`https://testlogon.app/post/{postId}` (and `http` variant) opens this screen directly,
creating a synthetic back stack so the system Back button returns to the app home/feed
rather than exiting the app.

FR-5. A top app bar shows a Back/Up affordance, a centered "Post" title, and an
overflow menu containing "Share link" (emits an `ACTION_SEND` chooser with the
`https://testlogon.app/post/{postId}` URL) and "Open in browser". Other interaction
affordances are out of scope.

> Assumption (unverified): the canonical public post-URL format and the `testlogon.app`
> domain are NOT defined in the backend OpenAPI or the web client. The web's
> `SharePostDialog.tsx` implements share-to-network (an internal repost-style action), not
> a "copy public link". This Android "Share link" affordance and its URL template are an
> Android-port assumption pending confirmation of the canonical domain (tracked in §16 and
> R3).

FR-6. States: `Loading` (skeleton matching post layout), `Content` (post rendered),
`Empty/NotFound` (404 → "This post is unavailable" with Back), `Forbidden` (403 →
"Subscription required to view this post" with Back — matches the web
`PostDetailPage.tsx` 403 branch), `Error` (retryable with a Retry button), and `Stale`
(cached copy shown with an "Offline — showing saved copy" banner when network is
unavailable but a cached post exists). Note: per OpenAPI only `200` and `422` are
documented for `GET /posts/{post_id}`; `404`/`403` are observed runtime behaviors
(confirmed in the web client), and `422` (validation) maps to the generic `Error` state.

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
    data object NotFound : PostDetailUiState          // HTTP 404 (runtime)
    data object Forbidden : PostDetailUiState          // HTTP 403 → "subscription required"
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
    // Corrected path: backend is GET /posts/{post_id} (op=get_post_posts__post_id__get),
    // NOT /ui/posts/{post_id}. Response maps to the web FeedPost DTO.
    @GET("posts/{post_id}")
    suspend fun getPost(@Path("post_id") postId: String): Response<PostDto>

    // HLS entitlement (only when post.video present). Web path is /ui/posts/{id}/...;
    // OpenAPI lists it as /posts/{id}/video/entitlement — prefer the web path, fall back.
    @POST("ui/posts/{post_id}/video/entitlement")
    suspend fun getVideoEntitlement(@Path("post_id") postId: String): Response<VideoEntitlementDto>
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

`GET /posts/{post_id}` (corrected path; idempotent; retry-eligible). Tag `newsfeed`,
op `get_post_posts__post_id__get`. Path param `post_id: string`. OpenAPI also exposes
optional `user_sub` (query) and `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` (headers) — these
are admin/impersonation affordances and are NOT used by the normal client.

Request headers (mirroring the web `api()` wrapper in `src/api/client.ts`):
`Authorization: Bearer <accessToken>`, session cookies (jar), and
`X-CSRF-Token: <ui_csrf cookie value>`. (The original draft omitted the Bearer token.)

Success `200`: the body is the web **`FeedPost`** DTO (`src/api/types.ts: FeedPost`). The
OpenAPI response schema is untyped (`{}`), so `FeedPost` is the authoritative shape.
Relevant fields for this read-only screen (all others ignored/passed through):

```jsonc
{
  "post_id": "p_01HZX9",          // NOT "id"
  "author_id": "u_42",            // a string id, NOT a nested author object
  "body": "full post text…",
  "body_format": "plain",         // "plain" | "markdown" | "rich" (+ body_markdown_html etc.)
  "created_at": "2026-05-30T18:04:11Z",
  "updated_at": "2026-05-30T18:10:00Z",  // NOT "edited_at"
  "image_urls": ["https://.../1.jpg"],   // string[]; NOT a media[] array
  "image_variants": [ { /* variant map per image */ } ],
  "video": {                              // single optional object; NOT in media[]
    "video_id": "v_1",
    "title": "…",
    "thumbnail_url": "https://.../p.jpg",
    "duration_seconds": 30,
    "hls_manifest_url": "https://.../v.m3u8",
    "playback_token": "…",
    "playback_expires_at": 1750000000
  },
  "like_count": 12,               // flat counts; NOT a counts{} object
  "comment_count": 3,
  "repost_count": 1,
  "tip_total_cents": 0,
  "lock_type": "fixed_price",     // lock_*/unlock_* gate paywalled media
  "unlock_price_cents": null,
  "unlocked": true
}
```

There is **no** `link_previews` array on `FeedPost` (the `LinkPreview` type exists in
`types.ts` but is used by messaging, not posts) and **no** nested `author`/`counts`
objects — these claims in the original draft were incorrect. `PostDto` is mapped to the
`core-model` `Post` via a `toDomain()` mapper; the mapper resolves author display from
`author_id` (via AND-099's author path), normalizes `image_urls` + `video` into the model's
media list, and is defensive about the many optional fields. Flat counts are parsed and
stored but not acted upon in this ticket.

Error mapping (FastAPI `detail` is `string | [{msg}] | {code,...}`; confirmed by
`normalizeErrorDetail` in `src/api/client.ts`, and the `422` body is
`HTTPValidationError` = `{ detail: ValidationError[] }`):
- `404` (runtime; not in OpenAPI) → `PostDetailUiState.NotFound` ("This post is unavailable").
- `403` → `PostDetailUiState.Forbidden` ("Subscription required to view this post").
  Geo-blocked 403s carry `detail.code == "geo_blocked"` with a `message` to surface.
- `401` → handled by the shared refresh-once interceptor: `POST /ui/session/refresh`
  (confirmed endpoint) then a single retry; persistent 401 → `Error("Session expired",
  retryable=false)` and a one-shot navigation event to re-authenticate (owned by the
  auth/session ticket).
- `422` (validation) → `Error(detail-derived message, retryable=false)`.
- other `4xx`/`5xx` → `Error(detail-derived message, retryable=true)`.
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
  timeouts set to ~20s; `GET /posts/{id}` (corrected path) is idempotent and uses bounded
  exponential backoff (max 3 attempts, base 500ms, jitter, cap 4s) for `NetworkError` and
  `5xx` only.
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

- R1: RESOLVED in review — payload shape confirmed as `FeedPost` (`src/api/types.ts`); the
  OpenAPI 200 schema is untyped (`{}`), so `FeedPost` is authoritative. Field names were
  corrected in §5 (`post_id`, `author_id`, `image_urls`, single `video`, flat counts; no
  `media[]`/`link_previews`/nested `author`/`counts`). Mapper remains defensive (the DTO has
  ~80 mostly-optional fields). Residual risk: backend may drift from web `FeedPost`.
- R2: Dev host instability may cause flaky media (HLS) playback; mitigated by isolated
  media error handling and Stale fallback.
- R3: App Links verification requires production domain + hosted `assetlinks.json`;
  until then `https`/`http` links may show the disambiguation chooser. Open question:
  final canonical domain (`testlogon.app` assumed).
- R4: Whether a list-supplied `Post` snapshot should render instantly (FR-8) depends on
  AND-099's exported model surface; decided to pass id-only and re-fetch (see §6).
- R5 (RESOLVED): the correct path is `GET /posts/{post_id}` (op=`get_post_posts__post_id__get`,
  tag `newsfeed`) — neither `/ui/posts/{id}` nor `/ui/post/{id}` exists. Verified against
  `openapi.index.txt` and `src/api/endpoints/newsfeed.ts: getPost`. Corrected throughout.
- Open: HLS video entitlement path mismatch — web uses
  `/ui/posts/{id}/video/entitlement`, OpenAPI lists `/posts/{id}/video/entitlement`. Prefer
  the web path with a fallback; confirm with backend before GA (see §16 Open assumptions).

## 14. Acceptance Criteria

AC-1. Navigating to a valid `post_id` from a feed/list opens `PostDetailScreen` and
renders the full post: author header, full (un-clamped) body text, and all media.
AC-2. Launching `testlogon://post/{postId}` (and `https://testlogon.app/post/{postId}`)
from a cold start opens the post directly with a back stack that returns to home.
AC-3. Media renders: images via Coil; HLS video plays via ExoPlayer, with the player
released on dispose/stop.
AC-4. `404` shows the "unavailable" NotFound state; `403` shows the "subscription
required" Forbidden state; `401` performs refresh-once then retry; network failure shows a
retryable Error and, when cache exists, the Stale banner.
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
- PR opened against `android-port` with screenshots of Loading/Content/NotFound/Forbidden/
  Error/Stale states and a deep-link demo; reviewed and approved.

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT and SOURCE. "Index" = `reference/openapi.index.txt`;
"OpenAPI" = `reference/openapi.pretty.json`; frontend paths are under `reference/src/`.

1. **Single-post endpoint is `GET /ui/posts/{post_id}`** — **Corrected** → real path is
   `GET /posts/{post_id}`. SOURCE: OpenAPI `GET /posts/{post_id}`
   (op=`get_post_posts__post_id__get`, tag `newsfeed`); `src/api/endpoints/newsfeed.ts: getPost`
   (`api.get<FeedPost>(\`/posts/${postId}\`)`). No `/ui/posts/{id}` path exists in the index.
2. **HTTP method GET** — **Verified**. SOURCE: Index line `GET /posts/{post_id}`;
   `src/api/endpoints/newsfeed.ts: getPost`.
3. **Response DTO is `Post` with nested `author{}`, `media[]`, `link_previews[]`, `counts{}`,
   `edited_at`** — **Corrected** → DTO is `FeedPost` with `post_id`, `author_id` (string),
   `image_urls: string[]`, single `video{}`, flat `like_count`/`comment_count`/`repost_count`/
   `tip_total_cents`, `updated_at`; no `media[]`, `link_previews`, nested `author`, or `counts`.
   SOURCE: `src/api/types.ts: FeedPost`; OpenAPI 200 schema for `GET /posts/{post_id}` is
   untyped (`{}`), so `FeedPost` is authoritative.
4. **Field `id`** — **Corrected** → `post_id`. SOURCE: `src/api/types.ts: FeedPost.post_id`.
5. **Field `edited_at`** — **Corrected** → `updated_at`. SOURCE: `src/api/types.ts: FeedPost.updated_at`.
6. **`link_previews[]` on a post** — **Corrected** → does not exist on `FeedPost`; the
   `LinkPreview` type is used by messaging (`SendTextMessageReq.preview`). SOURCE:
   `src/api/types.ts: FeedPost` (no link-preview field), `src/api/types.ts: LinkPreview` (line 1241).
7. **Media as a `media[]` array of image/video objects** — **Corrected** → `image_urls: string[]`
   + optional single `video{ video_id, title, thumbnail_url, duration_seconds, hls_manifest_url,
   playback_token, playback_expires_at }`. SOURCE: `src/api/types.ts: FeedPost`;
   `src/pages/feed/PostCard.tsx` (`post.image_urls`, `post.video → VideoPostPlayer`).
8. **HLS video plays directly from a payload URL** — **Corrected/augmented** → HLS requires a
   per-post entitlement (`POST /ui/posts/{post_id}/video/entitlement`) returning a fresh
   `hls_manifest_url`, with fallback to `video.hls_manifest_url`. SOURCE:
   `src/pages/feed/VideoPostPlayer.tsx` (entitlement query, manifest fallback line 64);
   `src/api/endpoints/newsfeed.ts` (`/ui/posts/${postId}/video/entitlement`). NOTE path
   mismatch: OpenAPI lists `POST /posts/{post_id}/video/entitlement` (op=
   `issue_video_post_entitlement...`) — see Open assumptions.
9. **Auth = cookie session + `X-CSRF-Token` only** — **Corrected** → also sends
   `Authorization: Bearer <accessToken>`. SOURCE: `src/api/client.ts` (sets `Authorization`
   from auth store + `X-CSRF-Token` from `ui_csrf` cookie + `credentials: "include"`).
10. **`X-CSRF-Token` = value of `ui_csrf` cookie** — **Verified**. SOURCE:
    `src/api/client.ts` (`getCookie("ui_csrf")` → `X-CSRF-Token`).
11. **401 → refresh-once via `POST /ui/session/refresh` then single retry** — **Verified**.
    SOURCE: `src/api/client.ts` (`refreshSession()` posts `/ui/session/refresh`, single retry);
    Index `POST /ui/session/refresh` (op=`ui_session_refresh...`, resp 200).
12. **FastAPI `detail` shape `string | [{msg}] | {code,...}`** — **Verified**. SOURCE:
    `src/api/client.ts: normalizeErrorDetail`; OpenAPI `HTTPValidationError` →
    `{ detail: ValidationError[] }`, `ValidationError = { loc, msg, type }`.
13. **404 → NotFound** — **Unverified-assumption (runtime)** → 404 is NOT in the OpenAPI
    responses (only 200/422), but the web treats `error.status === 404` as "Post not found".
    SOURCE: `src/pages/feed/PostDetailPage.tsx` (404 branch); OpenAPI (404 absent).
14. **403 → "subscription required"** — **Verified (added; was missing)**. SOURCE:
    `src/pages/feed/PostDetailPage.tsx` (403 → "Subscription required to view this post");
    geo-block 403 with `detail.code == "geo_blocked"` in `src/api/client.ts`.
15. **422 validation error possible** — **Verified (added)**. SOURCE: OpenAPI
    `GET /posts/{post_id}` resp `422: HTTPValidationError`.
16. **Web reference file `frontend/src/api/endpoints/posts.ts`** — **Corrected** → no such
    file; single-post fetch lives in `src/api/endpoints/newsfeed.ts`. Single-post page is
    `src/pages/feed/PostDetailPage.tsx`. SOURCE: directory listing of `src/api/endpoints/`,
    `src/pages/feed/`.
17. **"Share link" emits a canonical `https://testlogon.app/post/{postId}` URL** —
    **Unverified-assumption** → no canonical public-post-URL or domain is defined in OpenAPI
    or the web client; web `SharePostDialog.tsx` is internal share-to-network, not "copy link".
    SOURCE: `src/pages/feed/SharePostDialog.tsx` (mutation-based share, no URL); domain absent
    from sources.
18. **Deep-link schemes `testlogon://` / `https://testlogon.app`** — **Unverified-assumption**
    (Android-port choice; no web/OpenAPI basis). SOURCE: none in references; framework
    behavior per Navigation-Compose deep links — framework ref:
    https://developer.android.com/develop/ui/compose/navigation#deeplinks
19. **Cleartext HTTP to dev host `18.222.237.167` via `network_security_config`** —
    **Verified (framework)** as the correct mechanism. framework ref:
    https://developer.android.com/privacy-and-security/security-config
20. **Media3/ExoPlayer lifecycle (prepare on START, release on dispose)** — **Verified
    (framework)**. framework ref: https://developer.android.com/media/media3/exoplayer/hello-world
21. **Pull-to-refresh, Room offline cache / Stale banner, synthetic back stack, "warm
    instant render" (FR-8)** — **Unverified-assumption** (Android-port additions; the web
    `PostDetailPage.tsx` has none of these — no refresh, no cache, `navigate(-1)` back).
    SOURCE: `src/pages/feed/PostDetailPage.tsx`.

### Corrections made

- Endpoint path `/ui/posts/{post_id}` → `/posts/{post_id}` (§1, §2, §3 FR-2, §4 `PostApi`,
  §5, §7, §13). (citation 1)
- Response DTO corrected from invented `Post` JSON to the real `FeedPost` shape: `post_id`,
  `author_id`, `image_urls`, single `video`, flat counts; removed `media[]`, `link_previews`,
  nested `author`, `counts`, `edited_at`→`updated_at` (§2, §5, §13 R1). (citations 3–7)
- Auth: added `Authorization: Bearer` alongside cookies + CSRF (§2, §5). (citation 9)
- HLS: added the `video/entitlement` step for playable manifest (§2, §3 FR-3, §4). (citation 8)
- Errors: added `403` Forbidden state + `422` validation handling; flagged `404` as runtime
  (§1, §4 UiState, §5, §6, §14 AC-4). (citations 13–15)
- Reference file name corrected `posts.ts` → `newsfeed.ts`; noted web page
  `PostDetailPage.tsx` (§2). (citation 16)
- Marked the canonical share-URL and `testlogon.app` domain as unverified (§3 FR-5, R3).
  (citations 17–18)

### Open assumptions

- **Canonical public post URL & domain** (`testlogon.app`, `/post/{id}` path): no source;
  needed for FR-5 share + App Links. Why unverifiable: not present in OpenAPI or web client.
- **Deep-link schemes/hosts**: Android-port design choice; no backend/web basis.
- **Video entitlement path**: web `/ui/posts/{id}/video/entitlement` vs OpenAPI
  `/posts/{id}/video/entitlement` — confirm which the dev host honors. Why unverifiable now:
  the two authoritative sources disagree.
- **Author display fields**: `FeedPost` carries only `author_id`; resolving display name/
  handle/avatar depends on AND-099's model surface, which is not in these references.
- **Offline Room cache / Stale / pull-to-refresh / FR-8 instant render**: Android-only
  additions with no web equivalent; product-acceptable but not contract-derived.
- **404 on missing post**: runtime behavior assumed from the web client; not in OpenAPI.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (no device); **emu35** = headless emulator AVD
`test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34,
arm64-v8a, serial R5CX821TA9R). Hardware-dependent cases prefer **A15**.

- **TC-AND-100-01** — Type: contract/MockWebServer. Target: JVM. Precondition: MockWebServer
  scripted to return `200` with a `FeedPost` JSON body for `GET /posts/{id}`. Steps: call
  `PostApi.getPost("p_01HZX9")`; map via `toDomain()`. Expected: request path is
  `/posts/p_01HZX9` (NOT `/ui/posts/...`), method GET, headers include `Authorization: Bearer`,
  `X-CSRF-Token`; mapped model has body, `image_urls`, single `video`, flat counts; no crash on
  the ~80 optional fields. Traces: AC-1, AC-3.
- **TC-AND-100-02** — Type: unit. Target: JVM. Precondition: repo stubbed to return
  `ApiResult.Success(post)`. Steps: collect `PostDetailViewModel.uiState` (Turbine) through
  `load()`. Expected: `Loading → Content(post, isStale=false)`; `post_id`/`author_id` populated.
  Traces: AC-1.
- **TC-AND-100-03** — Type: unit (mapper). Target: JVM. Precondition: `FeedPost` JSON with an
  unknown/absent media combination (e.g. `image_urls` empty + `video=null`, and a future
  unknown field). Steps: run `PostDto.toDomain()`. Expected: maps to a content model with empty
  media, no exception; unknown fields ignored. Traces: AC-1, AC-3.
- **TC-AND-100-04** — Type: contract/MockWebServer. Target: JVM. Precondition: server returns
  `404` then (separately) `403` with `{"detail":"..."}`. Steps: fetch for each. Expected: `404`
  → `PostDetailUiState.NotFound`; `403` → `PostDetailUiState.Forbidden` ("subscription
  required"). Traces: AC-4.
- **TC-AND-100-05** — Type: contract/MockWebServer. Target: JVM. Precondition: first
  `GET /posts/{id}` → `401`; `POST /ui/session/refresh` → `200`; retried GET → `200`. Steps:
  fetch once. Expected: exactly one refresh call, one retry, final `Content`; no infinite loop.
  Traces: AC-4.
- **TC-AND-100-06** — Type: contract/MockWebServer. Target: JVM. Precondition: GET → `401`,
  refresh → `401` (persistent). Steps: fetch. Expected: `Error("Session expired",
  retryable=false)` + one-shot re-auth nav event; refresh attempted at most once. Traces: AC-4.
- **TC-AND-100-07** — Type: integration (MockWebServer + in-memory Room). Target: emu35.
  Precondition: Room seeded with a cached `PostEntity` (fresh, < 5 min); server set to a 20s
  no-response (simulated offline / `ConnectivityManager` no validated network). Steps:
  `observePost(id)`. Expected: emits cached `Content` immediately, then `Content(isStale=true)`
  with the "Offline — showing saved copy" banner; cache upsert skipped. Traces: AC-4.
- **TC-AND-100-08** — Type: integration (MockWebServer + Room). Target: JVM/Robolectric.
  Precondition: GET → `200`; Room empty. Steps: `observePost` then `refresh()`. Expected:
  cache-miss → network `Content`; Room upserted with `cached_at`; `refresh()` re-fetches
  (idempotent GET) and clears `isRefreshing`. Traces: AC-5.
- **TC-AND-100-09** — Type: contract/MockWebServer (flaky-host/retry). Target: JVM.
  Precondition: GET → `503` twice then `200` (and a separate run: read-timeout then `200`).
  Steps: fetch with the bounded-backoff policy (max 3, base 500ms, cap 4s). Expected: retries on
  `5xx`/`NetworkError` only, succeeds within 3 attempts; a `4xx` (e.g. 403) is NOT retried.
  Traces: AC-4, AC-5.
- **TC-AND-100-10** — Type: Compose-UI. Target: emu35. Precondition: `createAndroidComposeRule`
  with each `PostDetailUiState`. Steps: render Loading, Content, NotFound, Forbidden, Error,
  Stale. Expected: Loading shows skeleton; Content shows author/body/media nodes; NotFound shows
  "This post is unavailable" + Back; Forbidden shows "Subscription required…"; Error shows Retry
  (invokes `onRetry`); Stale shows offline banner; overflow → "Share link" invokes `onShare`.
  Traces: AC-1, AC-4, AC-5, AC-6.
- **TC-AND-100-11** — Type: Compose-UI (accessibility). Target: emu35. Precondition: Content
  state with images carrying `alt` and a video. Steps: assert semantics + run at `fontScale`
  2.0. Expected: Back/overflow/Retry/media have `contentDescription`; image `contentDescription`
  comes from `alt`; video announces "Video, double-tap to play"; layout reflows at 200% without
  clipping; touch targets ≥ 48dp; TalkBack focus order top bar → banner → author → body → media
  → link previews. Traces: AC-7.
- **TC-AND-100-12** — Type: instrumented/e2e (deep link). Target: emu35. Precondition: app
  installed; home/feed reachable. Steps: `adb shell am start -a android.intent.action.VIEW -d
  "testlogon://post/p_01HZX9"` from cold start; also test `https://testlogon.app/post/p_01HZX9`.
  Expected: `PostDetailScreen` resolves with `postId=p_01HZX9`; synthetic back stack returns to
  home (does not exit app). Traces: AC-2.
- **TC-AND-100-13** — Type: instrumented (security/validation). Target: emu35. Precondition:
  app installed. Steps: launch deep link with a malformed id (e.g. `testlogon://post/../../etc`
  or a 200-char id) violating `^[A-Za-z0-9_\-]{1,64}$`. Expected: short-circuits to NotFound
  with NO network call (no `/posts/...` request issued); no path injection. Also assert "Share
  link" payload contains only the public URL, never cookie/CSRF/Bearer values. Traces: AC-4, AC-6.
- **TC-AND-100-14** — Type: instrumented/e2e (real HLS playback). Target: **A15 (physical —
  required)**. Precondition: signed-in session on the dev host; a post with a `video`. Steps:
  open the post; allow the entitlement call `POST /ui/posts/{id}/video/entitlement`; let
  ExoPlayer prepare and play the HLS manifest; rotate / send app to background and back. Expected:
  entitlement fetched, video plays via Media3, single ExoPlayer instance, player released on stop
  and re-prepared on return; a media error shows a retry chip without failing the whole screen.
  MUST run on the physical device (real codec/network HLS + arm64 API-34 behavior, not the
  x86_64 API-35 emulator). Traces: AC-3, AC-4.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (open + render full post) | TC-01, TC-02, TC-03, TC-10 |
| AC-2 (deep-link cold start + back stack) | TC-12 |
| AC-3 (images Coil, HLS ExoPlayer, release) | TC-01, TC-03, TC-10, TC-14 |
| AC-4 (404/403/401/network + Stale) | TC-04, TC-05, TC-06, TC-07, TC-09, TC-10, TC-13, TC-14 |
| AC-5 (pull-to-refresh / Retry) | TC-08, TC-09, TC-10 |
| AC-6 (Share link; no write actions) | TC-10, TC-13 |
| AC-7 (TalkBack, 200% font, externalized strings) | TC-11 |
