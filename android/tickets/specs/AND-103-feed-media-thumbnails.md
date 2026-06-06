---
id: AND-103
title: Feed media thumbnails
milestone: M2
epic: E14
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-019]
blocks: [AND-099]
---

# AND-103 — Feed media thumbnails

## 1. Overview & Goal

This ticket delivers the reusable image-loading layer that renders media thumbnails in the
TestLogon feed. The deliverable is a small, self-contained Coil 2.x integration in `core-ui`
plus a set of Compose composables (`FeedThumbnail`, `MediaGrid`) that any feed surface can
consume. The focus is purely on **thumbnail rendering quality and resource discipline**: correct
placeholders while loading, graceful error fallbacks, sane aspect-ratio handling for mixed media
shapes, and a data-saver-aware loading policy. Video and HLS playback are explicitly out of scope
(owned by the Media3/ExoPlayer work, not this ticket); here a video media item shows a static
poster thumbnail with a play affordance overlay.

The two acceptance signals from the backlog are concrete and testable: (1) **images load with
placeholders** — a deterministic placeholder is visible before the bitmap resolves and an error
fallback is visible when it does not, and (2) **requests are cancelled on scroll** — when a feed
item leaves the viewport its in-flight Coil request is disposed so we never decode bitmaps for
rows the user has scrolled past. Achieving (2) is mostly a matter of using Coil's Compose
`AsyncImage` correctly inside a `LazyColumn`/`LazyVerticalGrid`, where disposal is automatic, and
proving it with an instrumented test plus a Coil event listener.

Goal: ship a single shared singleton `ImageLoader`, a typed thumbnail API, and the supporting
placeholder/aspect/data-saver behavior, so that AND-099 (Post item composable) can render media
grids without re-implementing image policy.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
  Code lands in `core-ui` (composables, `ImageLoader` provider) under namespace
  `com.testlogon.android.core.ui.media`. App wiring (Hilt entry point) lives in `app`.
- **Depends on AND-019 (Material 3 theme):** placeholders, error tints, and the play-overlay
  scrim must read from `MaterialTheme.colorScheme` / shapes so they track light/dark and dynamic
  color. This is the hard dependency.
- **Blocks AND-099 (Post item composable):** AND-099 composes `MediaGrid`/`FeedThumbnail` and
  must not know about Coil. The API in §4 is the contract AND-099 codes against.
- **Related, not blocking:**
  - AND-097 (Feed API + DTOs) supplies the `MediaItem` domain model (url, kind, dimensions). This
    ticket consumes that shape but does not require AND-097 to merge first; a minimal local
    `ThumbnailSpec` model decouples us (see §6).
  - AND-079 (Media preferences) owns `/ui/media/preferences`. **Correction (verified):** that
    endpoint (`MediaPreferencesOut`) covers audio/video defaults and `video_resolution` quality —
    it has **no** data-saver field. This ticket therefore sources `dataSaverEnabled` from the
    **system** signal (`ConnectivityManager.isActiveNetworkMetered` + restrict-background) and treats
    AND-079 only as a possible future in-app override behind `LocalDataSaver`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, OkHttp 4.12.
  Coil **2.7.0** (Compose artifact `io.coil-kt:coil-compose`). minSdk 24 / compileSdk 35, JDK 17.
- **Web reference:** `frontend/src/api/types.ts` (`FeedPost`, `ImageVariant`) and
  `frontend/src/api/endpoints/newsfeed.ts` (`getFeed`) for media URL fields. **Correction (verified):**
  there is **no** `media[]` array with per-item `kind`/`width`/`height` on `FeedPost`. The real shape
  exposes `image_urls?: string[]`, `image_variants?: Array<Record<string, ImageVariant>>` (each
  `ImageVariant = { url, width, height, size_bytes? }`), and a single `video?: { video_id, title,
  thumbnail_url?, duration_seconds?, hls_manifest_url?, ... }`. The feed call is `getFeed` hitting
  `GET /feed` and returning `{ items: FeedPost[]; next_cursor?: string }`. The `core-model` mapper
  (AND-097) must flatten these into `List<ThumbnailSpec>` — see §5 for the corrected mapping.

## 3. Functional Requirements

FR-1. Provide a singleton `coil.ImageLoader` configured with the app's authenticated OkHttp stack
so cookie-gated media URLs load (media on the dev backend rides the same session cookies).

FR-2. Provide `FeedThumbnail` composable that renders a single media thumbnail with: loading
placeholder, error fallback, content scaling, an optional play-button overlay for `VIDEO` kind,
and a content description for TalkBack.

FR-3. Provide `MediaGrid` composable that lays out 1–N thumbnails using the standard social grid
rules (1 = full bleed honoring aspect ratio; 2 = side-by-side halves; 3 = one large + two stacked;
4+ = 2×2 with a "+N" overflow badge on the last cell).

FR-4. **Aspect handling.** When the media item supplies intrinsic `width`/`height`, single-image
layout uses that ratio, clamped to `[0.5625, 1.91]` (9:16 portrait … 1.91:1 landscape) to avoid
extreme layouts. Grid cells use a fixed `1:1` (4-up) or `4:3` (1–3 up) cell ratio with
`ContentScale.Crop`. Missing dimensions fall back to `4:5`.

FR-5. **Placeholders.** Before load, show a neutral shimmer/solid placeholder sized to the final
slot (no layout jump). On failure, show an error placeholder (broken-image icon on
`surfaceVariant`). Both are theme-driven.

FR-6. **Cancellation on scroll.** Thumbnails MUST be rendered with Coil's `AsyncImage` (or
`rememberAsyncImagePainter`) so that when the composable leaves composition (row recycled by the
lazy list) the underlying request is disposed and the bitmap decode is cancelled.

FR-7. **Data-saver respect.** When data saver is on, do not load full thumbnails eagerly over a
metered connection: load a low-quality variant if the URL supports a size query, otherwise show
the placeholder with a tap-to-load affordance. The policy is centralized so it is testable.

FR-8. **Memory & disk caching.** Configure bounded memory (25% of app heap) and disk (96 MB)
caches keyed on the resolved URL so re-scrolling does not re-download.

## 4. Technical Design

All code is in `core-ui` (`com.testlogon.android.core.ui.media`) except the Hilt module that
supplies OkHttp, which may live in `app` and be provided to the loader.

**ImageLoader provisioning** (Hilt):

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object CoilModule {
    @Provides @Singleton
    fun provideImageLoader(
        @ApplicationContext context: Context,
        @ImageOkHttp client: dagger.Lazy<OkHttpClient>, // reuses cookie jar + CSRF stack
    ): ImageLoader = ImageLoader.Builder(context)
        .okHttpClient { client.get() }
        .memoryCache {
            MemoryCache.Builder(context).maxSizePercent(0.25).build()
        }
        .diskCache {
            DiskCache.Builder()
                .directory(context.cacheDir.resolve("image_cache"))
                .maxSizeBytes(96L * 1024 * 1024)
                .build()
        }
        .crossfade(true)
        .respectCacheHeaders(false) // dev host headers unreliable; we own TTL via cache size
        .build()
}
```

The `@ImageOkHttp` client is a thin clone of the core-network client (same cookie jar / CSRF
interceptor from AND-011/AND-012) but without the 401-refresh authenticator and with a shorter
20s call timeout; media 401s should fail to placeholder, not trigger a session refresh storm.

**Public API consumed by AND-099:**

```kotlin
enum class MediaKind { IMAGE, VIDEO, GIF, UNKNOWN }

@Immutable
data class ThumbnailSpec(
    val url: String,
    val kind: MediaKind = MediaKind.IMAGE,
    val width: Int? = null,
    val height: Int? = null,
    val blurHash: String? = null,
    val contentDescription: String? = null,
)

@Composable
fun FeedThumbnail(
    spec: ThumbnailSpec,
    modifier: Modifier = Modifier,
    contentScale: ContentScale = ContentScale.Crop,
    cornerRadius: Dp = 12.dp,
    onClick: (() -> Unit)? = null,
)

@Composable
fun MediaGrid(
    items: List<ThumbnailSpec>,
    modifier: Modifier = Modifier,
    maxVisible: Int = 4,
    onItemClick: ((index: Int) -> Unit)? = null,
)
```

**Loading policy** is isolated so it can be unit-tested without Compose:

```kotlin
interface ThumbnailPolicy {
    /** Returns the URL to request and whether to load eagerly. */
    fun resolve(spec: ThumbnailSpec, targetPx: Int, dataSaver: Boolean): LoadDecision
}
data class LoadDecision(val url: String, val eager: Boolean)
```

`DefaultThumbnailPolicy` appends a `?w={targetPx}` (or `&w=`) sizing hint when the host supports
it (allow-list of known image CDN paths), halves `targetPx` when `dataSaver` is true, and returns
`eager = false` when data saver is on AND the connection is metered (caller then renders the
tap-to-load state).

`FeedThumbnail` builds the request via Coil's Compose API and lets disposal handle cancellation:

```kotlin
val req = ImageRequest.Builder(LocalContext.current)
    .data(decision.url)
    .size(Size(targetPx, targetPx)) // downsample to the slot
    .memoryCacheKey(spec.url)
    .placeholderMemoryCacheKey(spec.url)
    .listener(thumbnailEventListener) // telemetry, §10
    .build()
AsyncImage(
    model = req,
    imageLoader = LocalImageLoader.current,
    contentDescription = spec.effectiveContentDescription(),
    contentScale = contentScale,
    placeholder = rememberThumbnailPlaceholder(spec),
    error = rememberThumbnailError(),
    modifier = modifier.clip(RoundedCornerShape(cornerRadius)),
)
```

`LocalImageLoader` is a `staticCompositionLocalOf` provided once near the Compose root from the
Hilt singleton, so previews/tests can override it. Video kind wraps the `AsyncImage` in a `Box`
with a centered play icon on a 40% scrim.

## 5. API Contract

This ticket defines **no new network endpoints**; it consumes media URLs already present on feed
post DTOs. The endpoint that returns those URLs is `GET /feed` (op `view_feed_feed_get`, response
`{ items: FeedPost[]; next_cursor?: string }`), owned by **AND-097 (Feed API + DTOs)**. Verified
against the OpenAPI index (`GET /feed`) and the web client (`src/api/endpoints/newsfeed.ts: getFeed`).
Note the web app also filters media posts with the `has_media` query param on `/feed`.

**Correction (verified).** The earlier draft of this section described a `media[]` array with
per-item `url` / `thumbnail_url` / `kind` / `width` / `height` / `blurhash`. **No such array exists
on `FeedPost`.** The actual DTO (`src/api/types.ts: FeedPost`) carries media across three separate
fields:

```ts
// src/api/types.ts (verified)
interface ImageVariant { url: string; width: number; height: number; size_bytes?: number; }

interface FeedPost {
  post_id: string;
  image_urls?: string[];
  image_variants?: Array<Record<string, ImageVariant>>; // e.g. {"thumb": {...}, "large": {...}}
  video?: {
    video_id: string;
    title: string;
    thumbnail_url?: string | null;
    duration_seconds?: number | null;
    hls_manifest_url?: string | null;
    // ...playback_token, playback_expires_at
  } | null;
  // ...many non-media fields
}
```

Corrected mapping rule (`MediaItemDto` → `ThumbnailSpec`, performed by the AND-097 mapper at the
call site):

- **Images:** for each entry in `image_variants`, prefer a small/thumb variant key when present,
  else fall back to the matching `image_urls[i]`. Each variant supplies real intrinsic `width`/
  `height` — feed those into `ThumbnailSpec.width/height` (this is the *only* verified source of
  dimensions; the draft's top-level `width`/`height` do not exist). `kind = IMAGE`.
- **Video:** map `video.thumbnail_url` (the poster) to `ThumbnailSpec.url`, `kind = VIDEO`. HLS
  playback (`hls_manifest_url`) is out of scope (Media3 ticket); we only render the poster.
- There is **no `blurhash` field** on `FeedPost` (unverified across the frontend source). The
  `ThumbnailSpec.blurHash` field is therefore an Android-side forward-looking option that will be
  `null` until/unless AND-097 adds it; see R4 and §16 Open assumptions.

**Data Saver source — corrected.** `GET /ui/media/preferences` does **NOT** return a
`data_saver: boolean`. Verified against schema `MediaPreferencesOut`
(`components.schemas.MediaPreferencesOut`): its fields are `user_sub` (required),
`default_audio_muted`, `default_video_off`, `video_resolution` ("360"|"480"|"720"|"1080"),
`preferred_audio_input_id` / `preferred_audio_output_id` / `preferred_video_input_id`, plus several
ad-fill fields (`affiliate_link_id`, `campaign_id`, `click_url`, `impression_url`, `skip_url`,
`skip_after_seconds`, `is_house_ad`, `fill_reason`, `promo_code_id`, `updated_at`). No data-saver /
metered / bandwidth flag exists on this endpoint (nor anywhere in the frontend source — a search for
`data_saver`/`dataSaver` returns zero matches). **Therefore this ticket derives data-saver state
solely from the Android system signal:** `ConnectivityManager.isActiveNetworkMetered` +
`getRestrictBackgroundStatus()`. AND-079 is downgraded from a data source to a future override; if it
later adds an in-app toggle, `LocalDataSaver` already abstracts the source. No request bodies are
issued by this ticket.

## 6. Data & State Management

There is no ViewModel and no `StateFlow<UiState>` in this ticket — thumbnails are stateless
leaf composables driven entirely by their `ThumbnailSpec` props plus two ambient inputs:

1. **`dataSaverEnabled: Boolean`** — read via a `CompositionLocal` (`LocalDataSaver`) populated
   by the host screen from the system metered/restrict-background signal
   (`ConnectivityManager`). (AND-079 has no data-saver field — see §5 correction — so it is only a
   potential future override of this local.) Default `false`.
2. **`LocalImageLoader`** — the singleton Coil loader.

Per-item transient UI state (for the data-saver tap-to-load case) is local
`rememberSaveable { mutableStateOf(false) }` so a "tap to load" choice survives recomposition and
config change but is not persisted across process death.

`ThumbnailSpec` is an `@Immutable` value type, decoupling `core-ui` from `core-model`; the feed
repository's mapper (AND-097 territory) converts `MediaItemDto` → `ThumbnailSpec` at the call
site. Caching state lives entirely inside Coil's memory/disk caches (§4); we do not maintain a
parallel cache. Memory-cache keys are pinned to the canonical `spec.url` (not the size-decorated
URL) so the same image shared across grid sizes reuses one cache entry.

## 7. Error Handling & Resilience

- **Load failure** (timeout, 4xx/5xx, decode error): `AsyncImage` `error` slot renders the broken-
  image fallback; no crash, no rethrow. The dev host is unreliable, so a failed thumbnail is an
  expected, silent, theme-styled fallback — never a blocking error.
- **Timeouts:** the `@ImageOkHttp` client uses 20s call/connect/read timeouts consistent with the
  project-wide dev-host policy. Coil does not retry image GETs here (a single attempt keeps the
  scroll responsive); the user re-triggers by scrolling the item back into view, which re-issues
  the request.
- **OOM / large bitmaps:** every request sets an explicit `.size(targetPx)` so Coil downsamples at
  decode time; we never decode source-resolution bitmaps into a thumbnail slot.
- **Cancellation:** guaranteed by `AsyncImage` disposal when the lazy item leaves composition.
  A Coil `EventListener` asserts (in tests) that `onCancel` fires for off-screen requests.
- **Null/blank URL:** `FeedThumbnail` short-circuits to the error placeholder without issuing a
  request.
- **Mixed/partial dimensions:** missing or zero width/height falls back to the `4:5` default ratio
  (FR-4) rather than collapsing to zero height.

## 8. Security & Privacy

- Media URLs on the dev backend are **plaintext HTTP**. **Verified auth model (web client,
  `src/api/client.ts`):** the primary credential is `Authorization: Bearer <accessToken>` from the
  auth store, sent alongside `credentials: "include"` (session cookies) and an `X-CSRF-Token` header
  copied from the `ui_csrf` cookie; CSRF applies to mutations, not to image GETs. The `@ImageOkHttp`
  client must therefore carry **both** the Bearer token and the persistent cookie jar so authenticated
  media resolves (the draft's "cookie-gated" framing was incomplete — Bearer is the primary auth).
  Cleartext is already permitted for the dev host via the existing `network_security_config`; no new
  cleartext exemption is introduced. (The specific Android tickets AND-011/AND-012/AND-013 named below
  are unverified against these sources — see §16.)
- The media client deliberately **omits the 401-refresh authenticator** (AND-013) to avoid a burst
  of refresh calls when many thumbnails 401 simultaneously; a 401 degrades to the error placeholder.
- No image bytes or URLs are logged at INFO; URLs may contain signed tokens, so telemetry (§10)
  logs only a stable hash of the URL plus outcome, never the raw query string.
- Disk cache lives in app-internal `cacheDir` (not world-readable, cleared by the OS under
  pressure). No media is written to external/shared storage.
- BlurHash, if present, is decoded locally for the placeholder and is non-sensitive.

## 9. Accessibility & i18n

- Every `FeedThumbnail` exposes a `contentDescription`. When the post supplies alt text it is used
  verbatim; otherwise a localized generic ("Post image", "Post video") from `strings.xml`.
- Decorative-only thumbnails inside a larger described post may pass `contentDescription = null`,
  marking the node as not important for accessibility, to avoid TalkBack double-reads — AND-099
  decides this per layout.
- Grid overflow "+N" badge sets a localized content description ("N more photos", plurals).
- Tap-to-load (data saver) affordance is a real focusable button with role `Button` and a
  localized label; minimum 48dp touch target.
- Placeholders/error tints derive from `MaterialTheme.colorScheme` (AND-019) so they meet contrast
  in light and dark. Play-overlay icon uses `onScrim`-equivalent contrast.
- All user-facing strings are in `core-ui/res/values/strings.xml`; no concatenation; plurals via
  `<plurals>`.

## 10. Telemetry & Logging

A Coil `EventListener` (`ThumbnailEventListener`) emits structured, redacted events through the
project logging facade (Timber-style), gated behind `BuildConfig.DEBUG` for verbose levels:

- `thumb_load_start` { keyHash, kind }
- `thumb_load_success` { keyHash, kind, ms, fromCache: MEMORY|DISK|NETWORK }
- `thumb_load_error` { keyHash, kind, ms, reason }
- `thumb_load_cancel` { keyHash } — used by the cancellation test to assert disposal on scroll.

`keyHash` is `sha256(url).take(12)`; raw URLs are never logged. Aggregate cache-hit ratio and p50/p90
load latency are exposed via a lightweight in-memory counter readable in debug for QA, with no PII.
No analytics SDK is added in this ticket.

## 11. Testing Strategy

**Unit (JVM, `core-ui` / `core-testing`):**
- `DefaultThumbnailPolicyTest` — size hint appended/halved under data saver; `eager=false` only
  when data saver + metered; CDN allow-list respected; non-CDN URLs passed through unchanged.
- `MediaKind.from()` mapping table (image/video/hls/gif/unknown, case-insensitive).
- `MediaGrid` layout selection logic (1/2/3/4/4+ → expected cell specs) tested as a pure function
  `gridLayoutFor(count): List<CellSpec>`.

**Instrumented / Compose UI (`androidTest`, with a fake `ImageLoader`):**
- Inject a test `ImageLoader` via `LocalImageLoader` backed by a `FakeImageLoaderEngine` (Coil
  test artifact) so loads are deterministic.
- `placeholder_shown_before_resolve` — assert placeholder node exists, then advance to success and
  assert the image node. Satisfies acceptance "images load with placeholders".
- `error_fallback_shown_on_failure` — engine returns error → error node visible, no crash.
- `request_cancelled_on_scroll` — render a `LazyColumn` of thumbnails, scroll the first item far
  off-screen, assert `ThumbnailEventListener` recorded `onCancel` for that item's keyHash and no
  `success`. Satisfies acceptance "cancelled on scroll".
- `data_saver_tap_to_load` — with `LocalDataSaver = true` + metered, assert tap-to-load button is
  shown and tapping it issues the load.
- `content_description_present` — TalkBack semantics assertions for image/video/overflow.
- Compose previews for light/dark, 1–5 item grids, video kind, error state.

CI: unit tests run on the build server (AND-050); the instrumented suite runs on the headless
emulator job (AND-051).

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-019 (Material 3 theme) — required for theme-driven placeholders/overlays.
- **Soft / data dependencies (not blocking merge):**
  - AND-097 (Feed API + DTOs) — supplies the real `FeedPost` shape (`image_urls`,
    `image_variants`, `video`); until merged, `ThumbnailSpec` is populated from fixtures. (Verified:
    there is no `media[]` DTO — see §5.)
  - AND-079 (Media preferences) — does **not** supply a data-saver flag (verified, §5); data saver is
    derived from system metered/restrict-background signals behind `LocalDataSaver`. AND-079 is only a
    potential future override and is not required for this ticket.
- **This blocks:** AND-099 (Post item composable), which composes `MediaGrid`/`FeedThumbnail`.
  AND-098 (Feed list paging) indirectly depends through AND-099.
- **Sequencing:** add Coil deps + `CoilModule` + `LocalImageLoader` first, then `FeedThumbnail`,
  then `MediaGrid`, then data-saver policy, then tests. Coordinate the `@ImageOkHttp` client with
  the core-network owner so the media client cloning is reviewed alongside AND-009/AND-011/AND-012.

## 13. Risks & Open Questions

- **R1 — Cleartext media URLs:** dev media is HTTP; if the backend ever returns mixed http/https
  URLs the network-security-config exemption must cover both. Mitigation: route all media through
  the host-selection base URL where possible.
- **R2 — Cancellation guarantee:** disposal-based cancellation depends on the lazy list actually
  recomposing items out. Risk if AND-099 wraps thumbnails in a `key {}` that keeps them composed
  while off-screen. Mitigation: document that grid items must be inside the lazy item scope.
- **R3 — Size-hint URL contract:** appending `?w=` assumes the CDN honors it; this is **unverified**
  for the dev host (no media-serving route with a width param is documented in the OpenAPI index).
  However, the verified DTO already exposes **discrete pre-sized variants** via
  `FeedPost.image_variants` (a map of named `ImageVariant` entries, each with `url`/`width`/`height`).
  Decision: the policy should **prefer selecting the smallest adequate discrete variant** and let Coil
  downsample, rather than rely on a `?w=` query param. The `?w=` allow-list path in
  `DefaultThumbnailPolicy` becomes an optional best-effort optimization only for URLs lacking a variant
  set; it must never be assumed to work.
- **R4 — BlurHash dependency:** including a BlurHash decoder adds a small library; open question
  whether to ship it now or use a solid placeholder. Default: solid placeholder, BlurHash optional
  follow-up.
- **R5 — Data Saver source of truth:** the system metered/restrict-background signal is the *only*
  verified source — `/ui/media/preferences` has no data-saver field (§5). If product wants an explicit
  in-app data-saver toggle it must be a new backend field (out of scope here); `LocalDataSaver` already
  abstracts the source so adding it later is non-breaking.

## 14. Acceptance Criteria

AC-1. A loading placeholder, sized to the final slot (no layout shift), is visible for every
thumbnail before the bitmap resolves (verified by `placeholder_shown_before_resolve`).

AC-2. A theme-styled error fallback renders on load failure with no crash (verified by
`error_fallback_shown_on_failure`).

AC-3. Scrolling a feed item off-screen cancels its in-flight image request; `ThumbnailEventListener`
records `onCancel` and no `success` for that item (verified by `request_cancelled_on_scroll`).

AC-4. Single images honor intrinsic aspect ratio clamped to 9:16…1.91:1; grids select the correct
layout for 1/2/3/4/4+ items with a "+N" overflow badge (verified by layout unit tests + previews).

AC-5. With data saver enabled on a metered connection, full thumbnails are not loaded eagerly; a
tap-to-load affordance loads on demand; size hints are halved (verified by policy unit test +
`data_saver_tap_to_load`).

AC-6. Re-scrolling previously seen thumbnails serves from cache (no new network request) per the
event listener's `fromCache` field.

AC-7. Placeholders, error tints, and overlays render correctly in light and dark themes (preview +
existing theme UI test from AND-019).

AC-8. Every thumbnail exposes an appropriate, localized content description (verified by
`content_description_present`).

## 15. Definition of Done

- `CoilModule`, `LocalImageLoader`, `FeedThumbnail`, `MediaGrid`, `ThumbnailSpec`,
  `ThumbnailPolicy`/`DefaultThumbnailPolicy`, and `ThumbnailEventListener` implemented in `core-ui`
  under `com.testlogon.android.core.ui.media`.
- Coil 2.7.0 (`coil-compose`, plus test artifact) added to the version catalog; `@ImageOkHttp`
  client reuses the persistent cookie jar and omits the 401 authenticator.
- All unit and instrumented tests in §11 pass on CI (AND-050 build-server unit job, AND-051
  emulator job); coverage includes AC-1 through AC-8.
- No raw media URLs logged; telemetry emits only hashed keys and outcomes.
- Compose previews exist for light/dark, 1–5 item grids, video kind, error, and data-saver states.
- Public API reviewed and confirmed sufficient by the AND-099 owner; AND-099 can compose
  `MediaGrid`/`FeedThumbnail` with zero Coil references.
- Lint/detekt/ktlint clean (AND-005); strings externalized and pluralized; merged to
  `android-port` behind no feature flag (leaf composables, safe to land).

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Feed endpoint is `GET /feed` returning `{ items: FeedPost[]; next_cursor?: string }`.**
   VERDICT: Verified. SOURCE: OpenAPI `GET /feed` (op `view_feed_feed_get`); frontend
   `src/api/endpoints/newsfeed.ts: getFeed` (`api.get<{ items: FeedPost[]; next_cursor?: string }>("/feed", ...)`).

2. **The feed exposes media via a `media[]` array with per-item `url`/`thumbnail_url`/`kind`/`width`/`height`/`blurhash`.**
   VERDICT: Corrected. The real `FeedPost` has `image_urls?: string[]`,
   `image_variants?: Array<Record<string, ImageVariant>>`, and a single `video?: {...}`; there is no
   `media[]`, no per-item `kind`, no top-level `width`/`height`, and no `blurhash`. SOURCE:
   `src/api/types.ts: FeedPost` (lines ~2181–2250) and `src/api/types.ts: ImageVariant`
   (`{ url, width, height, size_bytes? }`).

3. **Per-image intrinsic dimensions are available.**
   VERDICT: Verified (relocated). They come from `ImageVariant.width/height` inside `image_variants`,
   not from a top-level media item. SOURCE: `src/api/types.ts: ImageVariant`.

4. **Video items carry a poster thumbnail.**
   VERDICT: Verified. `FeedPost.video.thumbnail_url` (plus `hls_manifest_url` for the out-of-scope
   player). SOURCE: `src/api/types.ts: FeedPost.video`.

5. **`GET /ui/media/preferences` returns a `data_saver: boolean` flag (owned by AND-079).**
   VERDICT: Corrected. The endpoint exists (`GET /ui/media/preferences`, op
   `ui_get_media_preferences_ui_media_preferences_get`, resp `MediaPreferencesOut`) but
   `MediaPreferencesOut` has NO data-saver field — its fields are `user_sub`, `default_audio_muted`,
   `default_video_off`, `video_resolution`, `preferred_audio_input_id`/`_output_id`/`preferred_video_input_id`,
   and ad-fill fields (`affiliate_link_id`, `campaign_id`, `click_url`, `impression_url`, `skip_url`,
   `skip_after_seconds`, `is_house_ad`, `fill_reason`, `promo_code_id`, `updated_at`). A repo-wide search
   for `data_saver`/`dataSaver` in the frontend returns zero matches. SOURCE: OpenAPI
   `components.schemas.MediaPreferencesOut` (and `MediaPreferencesIn`); grep of `src/`.

6. **Data saver is therefore derived from the Android system signal.**
   VERDICT: Verified-as-corrected design (framework ref). SOURCE: framework ref —
   ConnectivityManager.isActiveNetworkMetered / getRestrictBackgroundStatus
   (https://developer.android.com/reference/android/net/ConnectivityManager#isActiveNetworkMetered()).

7. **Web auth model: media rides session cookies.**
   VERDICT: Corrected/clarified. The web client sends `Authorization: Bearer <accessToken>` as the
   PRIMARY credential, plus `credentials: "include"` (cookies) and `X-CSRF-Token` from the `ui_csrf`
   cookie. The `@ImageOkHttp` client must carry both Bearer and the cookie jar. SOURCE:
   `src/api/client.ts` (lines ~157–183: Authorization header, `getCookie("ui_csrf")` →
   `X-CSRF-Token`, `credentials: "include"`).

8. **CSRF is via `X-CSRF-Token` header sourced from the `ui_csrf` cookie.**
   VERDICT: Verified. CSRF guards mutations; image GETs do not require it. SOURCE:
   `src/api/client.ts: getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`.

9. **401 triggers a session refresh.**
   VERDICT: Verified (web). The web client refreshes once via `POST /ui/session/refresh` on 401. This
   ticket deliberately OMITS that refresh on the media client to avoid refresh storms when many
   thumbnails 401. SOURCE: `src/api/client.ts: refreshSession()` (`POST /ui/session/refresh`).

10. **`has_media` query param exists on the feed.**
    VERDICT: Verified. SOURCE: OpenAPI `GET /feed` params include `has_media`; frontend
    `FeedQueryParams.has_media` in `src/api/endpoints/newsfeed.ts`.

11. **Feed errors surface as `422 HTTPValidationError` for bad params.**
    VERDICT: Verified. SOURCE: OpenAPI `GET /feed` resp `422:HTTPValidationError`.

12. **Coil 2.7.0 (`io.coil-kt:coil-compose`), `AsyncImage` disposal cancels off-screen requests,
    Compose `LazyColumn`/`LazyVerticalGrid`, `staticCompositionLocalOf`.**
    VERDICT: Unverified-assumption (framework ref). Not derivable from backend/frontend sources; these
    are Android framework/library choices. SOURCE: framework ref — Coil docs
    (https://coil-kt.github.io/coil/compose/) and Compose lazy layouts
    (https://developer.android.com/jetpack/compose/lists).

13. **Android-side ticket internals: AND-011 cookie jar, AND-012 CSRF interceptor, AND-013
    401-refresh authenticator, AND-019 theme, AND-097 mapper, AND-099 consumer.**
    VERDICT: Unverified-assumption. These are sibling Android tickets not present in the provided
    backend/frontend sources; cited as planning assumptions only.

14. **`blurHash` on `ThumbnailSpec`.**
    VERDICT: Unverified-assumption. No `blurhash` field exists on `FeedPost` or anywhere in the
    frontend source; the field is a forward-looking Android option, null until a backend field exists.
    SOURCE: absence in `src/api/types.ts: FeedPost`.

15. **`?w=` width query param honored by the media route.**
    VERDICT: Unverified-assumption. No width-parameterized media route is documented in the OpenAPI
    index; prefer discrete `image_variants` instead. SOURCE: absence in OpenAPI index;
    `src/api/types.ts: ImageVariant`.

### Corrections made
- **§2 / §5 (DTO shape):** removed the fictional `media[]` array; replaced with the verified
  `FeedPost` fields (`image_urls`, `image_variants` of `ImageVariant`, single `video`) and a corrected
  mapper rule. Dimensions now sourced from `ImageVariant.width/height`.
- **§2 / §5 / §6 / §12 / §13-R5 (data saver):** removed the false `data_saver: boolean` field on
  `/ui/media/preferences`; data saver now derives from the Android system metered/restrict-background
  signal, with AND-079 demoted to a future optional override.
- **§5 (endpoint):** named the concrete feed endpoint `GET /feed` and its `{ items, next_cursor }`
  envelope; noted `has_media`.
- **§8 (auth):** clarified that primary auth is `Authorization: Bearer` (not merely cookies); the
  media client must carry Bearer + cookie jar; CSRF via `X-CSRF-Token`/`ui_csrf`.
- **§13-R3 (size hints):** changed the recommended strategy from `?w=` query hints to selecting
  discrete `image_variants`, since `?w=` support is unverified.

### Open assumptions
- All Coil/Compose/OkHttp framework behaviors (disposal-based cancellation, `staticCompositionLocalOf`,
  memory/disk cache config) are framework references, not verifiable from the project sources.
- Sibling Android tickets (AND-011/012/013/019/079/097/099) and their internal APIs are assumed; only
  their backend/frontend contracts (where they touch `/feed` and `/ui/media/preferences`) were checked.
- `blurHash` and `?w=` resizing have no backing in the sources and are explicitly optional/forward-looking.
- Whether dev media URLs are truly cookie+Bearer gated at the bytes level (vs. public/signed) could not
  be confirmed from the OpenAPI index, which does not document the static media-serving route; the
  client is built to send credentials defensively.

## 17. Test Plan

Test-target legend: **JVM** = local JVM/Robolectric (no device); **emu35** = headless emulator AVD
`test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a,
serial R5CX821TA9R). Coil loads are made deterministic with `FakeImageLoaderEngine` (Coil test
artifact) injected via `LocalImageLoader` unless a case explicitly exercises the real network.

**TC-AND-103-01 — Placeholder shown before resolve (happy path).**
Type: Compose-UI. Target: emu35. Preconditions: fake engine set to a controllable/suspended result
for a valid `ThumbnailSpec`. Steps: render `FeedThumbnail`; assert the placeholder node before
completing the load; release the result; assert the image node appears with no layout shift (same
measured bounds). Expected: placeholder visible pre-resolve, image visible post-resolve, slot size
unchanged. Traces: AC-1.

**TC-AND-103-02 — Error fallback on load failure.**
Type: Compose-UI. Target: emu35. Preconditions: fake engine returns an error for the spec. Steps:
render `FeedThumbnail`; let the load fail. Expected: theme-styled broken-image error node renders;
no crash/rethrow; node remains sized to the slot. Traces: AC-2.

**TC-AND-103-03 — Request cancelled on scroll.**
Type: instrumented/e2e. Target: emu35. Preconditions: `LazyColumn` of N thumbnails with a
`ThumbnailEventListener` recording events; fake engine with a small delay. Steps: scroll the first
item far off-screen before its load completes. Expected: listener records `onCancel`
(`thumb_load_cancel`) for that item's `keyHash` and NO `thumb_load_success` for it. Traces: AC-3.

**TC-AND-103-04 — Grid layout selection (pure logic).**
Type: unit (JVM). Target: JVM. Preconditions: none. Steps: call `gridLayoutFor(count)` for
count = 1,2,3,4,5,9. Expected: 1 = full-bleed honoring aspect; 2 = side-by-side halves; 3 = one
large + two stacked; 4 = 2×2; 5/9 = 2×2 with "+N" badge on the last cell (N = count-4). Traces: AC-4.

**TC-AND-103-05 — Aspect-ratio clamping.**
Type: unit (JVM). Target: JVM. Preconditions: none. Steps: compute single-image ratio from
`ImageVariant`-derived width/height for an ultra-wide (e.g. 3000×500), ultra-tall (500×3000),
in-range (1600×1200), and missing-dims spec. Expected: ratio clamped to [0.5625, 1.91]; missing
dims fall back to 4:5. Traces: AC-4.

**TC-AND-103-06 — Data-saver policy resolution.**
Type: unit (JVM). Target: JVM. Preconditions: `DefaultThumbnailPolicy`. Steps: call `resolve` for
(a) dataSaver=false → eager=true, full size; (b) dataSaver=true + metered → eager=false (tap-to-load),
target halved; (c) dataSaver=true + non-metered → eager=true, target halved; (d) verify a discrete
small `image_variant` is preferred over a `?w=` hint, and a non-CDN URL is passed through unchanged.
Expected: as stated; the `?w=` hint is only appended for allow-listed URLs lacking variants. Traces:
AC-5.

**TC-AND-103-07 — Data-saver tap-to-load (UI).**
Type: Compose-UI. Target: emu35. Preconditions: `LocalDataSaver=true`, simulated metered network,
fake engine. Steps: render `FeedThumbnail`; assert tap-to-load button (role Button, ≥48dp); tap it.
Expected: no eager load before tap; tapping issues the load and resolves to the image; choice
survives recomposition (`rememberSaveable`). Traces: AC-5, AC-8.

**TC-AND-103-08 — Cache hit on re-scroll (contract/MockWebServer).**
Type: contract/MockWebServer. Target: emu35 (real Coil `ImageLoader` against MockWebServer). Steps:
load a thumbnail (records 1 network GET, `fromCache=NETWORK`); scroll away and back. Expected: the
second display reports `fromCache=MEMORY` (or DISK) and MockWebServer records exactly one request for
that URL; memory-cache key is the canonical `spec.url`, so a different grid size of the same image
also hits cache. Traces: AC-6.

**TC-AND-103-09 — Flaky dev-host / offline fallback (real network).**
Type: integration. Target: A15 (physical; real radio for true metered + offline transitions). MUST
run on the physical device because it toggles real Wi-Fi/cellular and airplane mode; the headless
emulator cannot reproduce real metered/offline radio behavior. Preconditions: app pointed at the
dev host; a feed item with media on screen. Steps: (1) put the device offline (airplane mode) and
render the item; (2) restore connectivity and scroll it back into view. Expected: offline → error/
placeholder fallback, no crash, no session-refresh storm (media client omits the 401 authenticator);
on reconnect + re-scroll the request re-issues and resolves. Traces: AC-2, AC-3, AC-6.

**TC-AND-103-10 — No raw URL logged / 401 degrades silently (security).**
Type: contract/MockWebServer. Target: emu35. Preconditions: MockWebServer returns 401 for a media
URL containing a query token; logging facade captured. Steps: load the thumbnail. Expected: error
placeholder shown; NO session-refresh call is issued (no `POST /ui/session/refresh`); telemetry emits
only `keyHash = sha256(url).take(12)` and an outcome — the raw URL/query string never appears in any
log line. Traces: AC-2.

**TC-AND-103-11 — Auth headers attached to media requests (contract).**
Type: contract/MockWebServer. Target: emu35. Preconditions: `@ImageOkHttp` client configured with a
Bearer token + cookie jar. Steps: trigger a thumbnail load against MockWebServer. Expected: the
recorded request carries `Authorization: Bearer <token>` and the session cookie; it does NOT need an
`X-CSRF-Token` (GET). Verifies the §8 corrected auth model. Traces: AC-2, AC-6.

**TC-AND-103-12 — Accessibility semantics.**
Type: Compose-UI. Target: emu35. Preconditions: specs for image (with alt text), image (no alt →
localized "Post image"), video (localized "Post video"), and a 5-item grid. Steps: assert Compose
semantics. Expected: each thumbnail has an appropriate non-empty `contentDescription` (or is marked
not-important when decorative); the "+N" overflow badge has a localized plural description; tap-to-
load is a focusable `Button`. Traces: AC-8.

**TC-AND-103-13 — Light/dark theme rendering (UI snapshot).**
Type: Compose-UI. Target: emu35. Preconditions: AND-019 theme; previews for 1–5 grids, video kind,
error, placeholder, data-saver states. Steps: render in light and dark. Expected: placeholders,
error tints, and play-overlay scrim read from `MaterialTheme.colorScheme` and meet contrast in both
themes; no hard-coded colors. Traces: AC-7.

**TC-AND-103-14 — MediaKind mapping + DTO flattening (unit).**
Type: unit (JVM). Target: JVM. Preconditions: fixtures of the real `FeedPost` shape. Steps: map a
post with `image_variants` (multiple keys), a post with only `image_urls`, and a post with a `video`
into `List<ThumbnailSpec>`; map `kind` strings case-insensitively (image→IMAGE, video/hls→VIDEO,
gif→GIF, else UNKNOWN). Expected: images → IMAGE with variant width/height; video → VIDEO using
`video.thumbnail_url`; missing dims → null (→ 4:5 default downstream). Traces: AC-4.

### Coverage matrix

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (placeholder before resolve) | TC-AND-103-01 |
| AC-2 (error fallback, no crash) | TC-AND-103-02, -09, -10, -11 |
| AC-3 (cancel on scroll) | TC-AND-103-03, -09 |
| AC-4 (aspect clamp + grid layout) | TC-AND-103-04, -05, -14 |
| AC-5 (data-saver policy + tap-to-load) | TC-AND-103-06, -07 |
| AC-6 (cache hit on re-scroll) | TC-AND-103-08, -09, -11 |
| AC-7 (light/dark theming) | TC-AND-103-13 |
| AC-8 (content descriptions) | TC-AND-103-07, -12 |
