---
id: AND-103
title: Feed media thumbnails
milestone: M2
epic: E14
priority: P1
size: M
status: draft
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
  - AND-079 (Media preferences) owns the `/ui/media/preferences` source of truth (autoplay, data
    saver, quality). This ticket reads a `dataSaverEnabled` flag and degrades gracefully when that
    feature is absent, defaulting to the system Data Saver signal.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, OkHttp 4.12.
  Coil **2.7.0** (Compose artifact `io.coil-kt:coil-compose`). minSdk 24 / compileSdk 35, JDK 17.
- **Web reference:** `frontend/src/api/types.ts` media shapes and `frontend/src/api/endpoints/newsfeed.ts`
  for thumbnail URL fields; mirror their `media[].thumbnail_url` / `media[].kind` semantics.

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
post DTOs. The endpoint that returns those URLs is owned by **AND-097 (Feed API + DTOs)**.

Relevant consumed shape (from the FastAPI feed response, mirrored in `core-model`):

```json
{
  "id": "post_123",
  "media": [
    {
      "url": "http://18.222.237.167:8000/media/abc.jpg",
      "thumbnail_url": "http://18.222.237.167:8000/media/abc_thumb.jpg",
      "kind": "image",
      "width": 1600,
      "height": 1200,
      "blurhash": "LKO2?U%2Tw=w]~RBVZRi};RPxuwH"
    }
  ]
}
```

Mapping rule: prefer `thumbnail_url`; fall back to `url`. `kind` strings map case-insensitively to
`MediaKind` (`image`→IMAGE, `video`/`hls`→VIDEO, `gif`→GIF, else UNKNOWN). The optional Data
Saver flag comes from `GET /ui/media/preferences` (`data_saver: boolean`), owned by **AND-079**;
when that call is unavailable this ticket falls back to `ConnectivityManager.isActiveNetworkMetered`
+ `restrictBackgroundStatus`. No request bodies are issued by this ticket.

## 6. Data & State Management

There is no ViewModel and no `StateFlow<UiState>` in this ticket — thumbnails are stateless
leaf composables driven entirely by their `ThumbnailSpec` props plus two ambient inputs:

1. **`dataSaverEnabled: Boolean`** — read via a `CompositionLocal` (`LocalDataSaver`) populated
   by the host screen from `MediaPreferences` (AND-079) or the system metered/restrict-background
   signal. Default `false`.
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

- Media URLs on the dev backend are **plaintext HTTP** and cookie-gated. The `@ImageOkHttp` client
  reuses the persistent cookie jar (AND-011) so authenticated media resolves; cleartext is already
  permitted for the dev host via the existing `network_security_config`. No new cleartext exemption
  is introduced.
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
  - AND-097 (Feed API + DTOs) — supplies real `MediaItemDto`; until merged, `ThumbnailSpec` is
    populated from fixtures.
  - AND-079 (Media preferences) — supplies the `data_saver` flag; until merged, fall back to system
    metered/restrict-background signals behind `LocalDataSaver`.
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
- **R3 — Size-hint URL contract:** appending `?w=` assumes the CDN honors it; unknown for the dev
  host. Open question: does the FastAPI media route accept a width param, or is there a discrete
  `thumbnail_url`? If only discrete variants exist, the policy degrades to thumbnail_url + Coil
  downsample (still correct, just less bandwidth-optimal under data saver).
- **R4 — BlurHash dependency:** including a BlurHash decoder adds a small library; open question
  whether to ship it now or use a solid placeholder. Default: solid placeholder, BlurHash optional
  follow-up.
- **R5 — Data Saver source of truth:** until AND-079 lands, the system signal is a coarse proxy and
  may differ from the user's in-app preference.

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
