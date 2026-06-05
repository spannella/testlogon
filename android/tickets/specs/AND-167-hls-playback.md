---
id: AND-167
title: HLS playback
milestone: M4
epic: E23
priority: P0
size: M
status: draft
depends_on: [AND-166]
blocks: [AND-168, AND-169]
---

# AND-167 — HLS playback

## 1. Overview & Goal

Add HTTP Live Streaming (HLS) source support to the native Android player so that both **live** and **VOD** `.m3u8` manifests play with **adaptive bitrate (ABR)** switching driven by Media3/ExoPlayer's built-in `HlsMediaSource`. This is the direct replacement for the web reference app's `hls.js`-based playback (`frontend/`), where browser-native HLS is unavailable and a JS shim is required. On Android, ExoPlayer parses and demuxes HLS natively, so this ticket is primarily about **wiring the HLS module + source factory into the existing `PlayerManager`** (delivered by AND-166), distinguishing live vs VOD behavior, and proving adaptive track selection works end-to-end.

This ticket does **not** build player chrome/controls (AND-168) or user-facing quality selection / data-saver caps (AND-169). It delivers the source layer those tickets build on. The single acceptance gate is: *an HLS stream plays with adaptive switching.*

Scope boundary: source resolution, `HlsMediaSource.Factory` configuration, live/VOD detection, `TrackSelectionParameters` defaults enabling ABR, and an instrumented test proving variant switching. All UI, controls, and metered-network policy are downstream.

## 2. Context & References

- **Depends on AND-166 (Media3/ExoPlayer integration):** provides the `PlayerManager` wrapper (lifecycle-aware `ExoPlayer` create/release, single-player reuse) and the `core-media` module. This ticket extends `PlayerManager.setMediaItem(...)` / source resolution rather than introducing a new player.
- **Blocks AND-168 (Reusable player UI):** consumes the playing source to render controls, buffering/error states, fullscreen, PiP.
- **Blocks AND-169 (Adaptive quality / data-saver):** layers explicit quality caps and metered-network policy onto the `TrackSelector` defaults established here.
- **Web reference:** `frontend/` uses `hls.js` attached to a `<video>` element. The manifest URLs and any signed query params come from feed/post media payloads (`frontend/src/api/types.ts`, media DTOs from feed work AND-097+). Mirror the URL/header handling, not the JS player internals.
- **Stack:** Kotlin 2.0.21, Media3/ExoPlayer 1.4 (`androidx.media3:media3-exoplayer-hls`), Compose + Material 3, Hilt (KSP), Coroutines/Flow, OkHttp 4.12. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3.
- **Module:** `core-media` (created in AND-166). Namespace `com.testlogon.android.core.media`.
- **Networking:** Media segment fetches must reuse the app's configured OkHttp stack (timeouts ~20s, cookie jar, host-selection) so playback works against the unreliable plaintext dev backend `http://18.222.237.167:8000` and any CDN it points to. ExoPlayer must use an `OkHttpDataSource.Factory`, not the default `DefaultHttpDataSource`.

## 3. Functional Requirements

FR1. **HLS dependency.** Add `androidx.media3:media3-exoplayer-hls:1.4.x` to `core-media` (version aligned to the Media3 BOM/version catalog entry set in AND-166).

FR2. **Source resolution by type.** `PlayerManager` (or a new `MediaSourceFactoryProvider`) must build an `HlsMediaSource` when the media URL is an HLS manifest, and continue using progressive/`DefaultMediaSourceFactory` for MP4 (AND-166 behavior preserved). Detection is by explicit `MediaType` flag from the caller first, falling back to URI heuristic (`.m3u8` path or `application/vnd.apple.mpegurl` / `application/x-mpegURL` MIME).

FR3. **Live vs VOD.** Both live and VOD manifests must play. For **live**, the player must target the live edge using the manifest's `#EXT-X-... ` server-control / hold-back when present, with app defaults for `targetOffsetMs`. For **VOD**, normal seekable timeline behavior applies. Live-ness is detected from the loaded `Timeline` / `MediaItem.liveConfiguration`, not guessed up front.

FR4. **Adaptive switching enabled by default.** The `TrackSelector` must be configured so that, given a multi-variant master playlist, ExoPlayer's `AdaptiveTrackSelection` automatically switches video variants up/down with available bandwidth. No fixed video track may be pinned in this ticket (that is AND-169).

FR5. **OkHttp-backed segment/manifest loading.** Manifest and segment requests go through the shared `OkHttpClient` (so cookies, CSRF where applicable, host selection, and timeouts apply).

FR6. **Headers / auth pass-through.** Support optional per-source request headers (e.g. signed-URL cases already carry auth in the query string; cookie-based playlists rely on the shared cookie jar). Provide a hook to attach headers without leaking app session headers to arbitrary CDNs.

FR7. **State exposure.** HLS playback must surface the same `PlayerManager` state (`StateFlow<PlaybackUiState>` from AND-166) including a derived `isLive: Boolean` and current selected video height/bitrate (for downstream UI/telemetry). No new screen is added.

FR8. **Lifecycle correctness.** HLS sources must honor AND-166 lifecycle-aware release; switching between an MP4 and an HLS item must reuse the single `ExoPlayer` instance (no leak, no second player).

## 4. Technical Design

Module: `core-media`. New/changed types under `com.testlogon.android.core.media`.

```kotlin
// Caller-facing media descriptor (extends AND-166's media model)
enum class MediaType { PROGRESSIVE, HLS, AUTO }

data class MediaSourceSpec(
    val uri: String,
    val type: MediaType = MediaType.AUTO,
    val headers: Map<String, String> = emptyMap(),
    val title: String? = null,
)
```

```kotlin
// Resolves a MediaSource.Factory per spec. Hilt-provided singleton.
class MediaSourceFactoryProvider @Inject constructor(
    private val okHttpClient: OkHttpClient,   // shared app client (AND-009)
) {
    private val dataSourceFactory: DataSource.Factory =
        DefaultDataSource.Factory(
            /* context */ context,
            OkHttpDataSource.Factory(okHttpClient),
        )

    fun create(spec: MediaSourceSpec): MediaSource {
        val item = MediaItem.Builder()
            .setUri(spec.uri)
            .apply { spec.title?.let { setMediaMetadata(MediaMetadata.Builder().setTitle(it).build()) } }
            .build()
        return when (resolveType(spec)) {
            MediaType.HLS -> HlsMediaSource.Factory(headeredFactory(spec.headers))
                .setAllowChunklessPreparation(true)
                .createMediaSource(item)
            else -> DefaultMediaSourceFactory(headeredFactory(spec.headers))
                .createMediaSource(item)
        }
    }

    private fun resolveType(spec: MediaSourceSpec): MediaType =
        when (spec.type) {
            MediaType.AUTO -> if (isHlsUri(spec.uri)) MediaType.HLS else MediaType.PROGRESSIVE
            else -> spec.type
        }

    private fun isHlsUri(uri: String): Boolean =
        uri.substringBefore('?').endsWith(".m3u8", ignoreCase = true)
}
```

`headeredFactory(headers)` wraps the base `dataSourceFactory` with `setDefaultRequestProperties(headers)` so per-source headers are applied without mutating the shared client. `setAllowChunklessPreparation(true)` lets ExoPlayer build the period from the master playlist without first downloading each variant's media playlist — faster start and correct multi-variant track exposure for ABR.

`PlayerManager` (AND-166) gains:

```kotlin
fun setMedia(spec: MediaSourceSpec, autoPlay: Boolean = true)
```

which calls `exoPlayer.setMediaSource(factoryProvider.create(spec))`, `prepare()`, and sets `playWhenReady`. The existing simple `setMediaItem(uri)` path delegates to `setMedia(MediaSourceSpec(uri))`.

**Track selector / ABR.** In the `ExoPlayer.Builder` (AND-166) install a `DefaultTrackSelector` and set ABR-friendly defaults:

```kotlin
val trackSelector = DefaultTrackSelector(context).apply {
    setParameters(
        buildUponParameters()
            .setForceHighestSupportedBitrate(false)   // allow ABR to choose
            .setMaxVideoSizeSd(false /* no SD cap here; AND-169 owns caps */)
            .setAllowVideoMixedMimeTypeAdaptiveness(true)
            .build()
    )
}
```

The default `AdaptiveTrackSelection.Factory` (used automatically by `DefaultTrackSelector`) drives variant switching from `BandwidthMeter` estimates. No explicit min/max bitrate is pinned here.

**Live edge.** Provide app default live config applied only when the loaded item is live:

```kotlin
val liveConfig = MediaItem.LiveConfiguration.Builder()
    .setTargetOffsetMs(DEFAULT_LIVE_TARGET_OFFSET_MS) // e.g. 8_000; manifest hold-back overrides
    .build()
```

Set via `MediaItem.Builder().setLiveConfiguration(liveConfig)` when `type == HLS`. ExoPlayer prefers the manifest's `#EXT-X-SERVER-CONTROL` hold-back when present, falling back to the configured offset.

**Derived live flag.** `PlayerManager` observes `Player.Listener.onTimelineChanged` and reads `player.isCurrentMediaItemLive` to update `PlaybackUiState.isLive`; on `onTracksChanged` it records the selected video `Format.height`/`bitrate`.

## 5. API Contract

No new TestLogon backend endpoints are introduced by this ticket. HLS manifests and segments are fetched directly by ExoPlayer over HTTP(S) from URLs supplied in media payloads (owned by feed/post DTO tickets, AND-097+). The relevant "contract" is the HLS wire format, served behind the app's configured HTTP stack:

- **Master playlist** (`GET <uri>.m3u8`, `Content-Type: application/vnd.apple.mpegurl`): contains multiple `#EXT-X-STREAM-INF` variants (different `BANDWIDTH`/`RESOLUTION`) — required for FR4 adaptive switching.
- **Media playlist** (per-variant `.m3u8`): VOD ends with `#EXT-X-ENDLIST`; live omits it and may include `#EXT-X-SERVER-CONTROL:CAN-BLOCK-RELOAD=YES,HOLD-BACK=...` and `#EXT-X-PART-INF` (LL-HLS).
- **Segments** (`.ts` / fMP4 `.m4s`): fetched via the OkHttp data source; cookies from the persistent jar (AND-011) and the ~20s read timeout (AND-009) apply.

Request handling rules:
- Manifest/segment GETs are idempotent; ExoPlayer's own loader handles retries — do not add the app-level GET retry interceptor (AND-016) to media loads to avoid double-retry. Use the shared client but verify the retry interceptor is scoped to API calls only (open question OQ3).
- Per-source `headers` map (FR6) is applied via `setDefaultRequestProperties`; do not attach `X-CSRF-Token` unless the manifest host equals the API host.

## 6. Data & State Management

No persistence (Room/DataStore) is added by this ticket. State is in-memory in `PlayerManager` and exposed as Flow.

Extend AND-166's `PlaybackUiState`:

```kotlin
data class PlaybackUiState(
    val playbackState: Int = Player.STATE_IDLE,   // IDLE/BUFFERING/READY/ENDED
    val isPlaying: Boolean = false,
    val isLive: Boolean = false,                  // NEW
    val durationMs: Long = C.TIME_UNSET,
    val positionMs: Long = 0L,
    val selectedVideoHeight: Int = Format.NO_VALUE, // NEW (for AND-169/telemetry)
    val selectedVideoBitrate: Int = Format.NO_VALUE,// NEW
    val error: PlaybackError? = null,
)
```

- `isLive` derived from `player.isCurrentMediaItemLive` on `onTimelineChanged`.
- `selectedVideoHeight`/`selectedVideoBitrate` updated on `onTracksChanged` from the currently selected video `Format`; these reflect ABR's current choice and will change during a session as variants switch — that change is the observable proof of adaptive behavior.
- For live, `durationMs` stays `C.TIME_UNSET` and position is reported relative to the live window; downstream UI (AND-168) handles live indicator rendering.
- Single-player reuse (AND-166) means switching specs replaces the source on the same instance; state resets to `IDLE`/`BUFFERING` on each `setMedia`.

## 7. Error Handling & Resilience

Map ExoPlayer errors to AND-166's `PlaybackError` model via `Player.Listener.onPlayerError(PlaybackException)`:

| Condition | `PlaybackException.errorCode` | UI mapping (AND-168) |
|---|---|---|
| Manifest 4xx/5xx / unparseable | `ERROR_CODE_IO_BAD_HTTP_STATUS`, `ERROR_CODE_PARSING_MANIFEST_MALFORMED` | "Can't load video" + retry |
| Network timeout / no connectivity | `ERROR_CODE_IO_NETWORK_CONNECTION_FAILED`, `_TIMEOUT` | offline/stale state |
| No supported variant / decoder | `ERROR_CODE_DECODING_FAILED`, `ERROR_CODE_DECODER_INIT_FAILED` | "Unsupported format" |
| Live window drift / behind | `ERROR_CODE_BEHIND_LIVE_WINDOW` | auto-recover (see below) |

Resilience requirements:
- **Behind-live-window:** on `ERROR_CODE_BEHIND_LIVE_WINDOW`, automatically `seekToDefaultPosition()` and `prepare()` to rejoin the live edge instead of surfacing an error (common on the flaky dev host / slow networks).
- **Bounded recovery:** transient IO errors during prepare may be retried once via `prepare()` with a small backoff before reporting `PlaybackError`; cap at 1 app-level retry to avoid fighting ExoPlayer's internal loader retries.
- **Unreliable dev backend:** rely on the shared OkHttp ~20s timeout; do not block the UI thread. Buffering beyond a threshold surfaces a buffering state (rendered by AND-168), not an error.
- ExoPlayer's `LoadErrorHandlingPolicy` defaults are acceptable for v1; tuning is an open question (OQ2).

## 8. Security & Privacy

- **Cleartext:** the dev backend and possibly its segment CDN are plaintext HTTP. The existing network security config (set in app/networking tickets) must permit cleartext only for the dev host(s); production manifest hosts must remain HTTPS. Do not add a blanket `usesCleartextTraffic=true`.
- **Header scoping:** never send the app session cookie / `X-CSRF-Token` to a manifest or segment host that differs from the API host. The `MediaSourceFactoryProvider` must guard `setDefaultRequestProperties` so app-auth headers are only attached when the URI host matches the configured API host; third-party CDN URLs that carry their own signed query params get no app headers.
- **No new secrets / no persistence** of media URLs (which may be signed/expiring) beyond the in-memory player session.
- Logs must not print full signed manifest URLs at non-debug levels (could contain tokens) — redact query strings (see §10).

## 9. Accessibility & i18n

No new user-facing UI in this ticket; player chrome, captions toggle, and content descriptions are AND-168. However:
- **Captions/subtitles plumbing:** HLS `#EXT-X-MEDIA:TYPE=SUBTITLES` / `CLOSED-CAPTIONS` tracks are exposed by `HlsMediaSource` automatically; do not strip them. Wiring a captions UI and honoring the system caption style is AND-168.
- Any developer-facing or fallback strings introduced (e.g. a generic playback error) go through `core-ui` string resources, not hardcoded literals, for future i18n.

## 10. Telemetry & Logging

- Add Media3 `AnalyticsListener` to `PlayerManager` emitting (debug builds verbose, release minimal) to the app's redacting logger (AND-052 conventions):
  - `hls_prepare` (uri host only, type=HLS, isLive)
  - `hls_variant_switch` (fromHeight→toHeight, fromBitrate→toBitrate) — fires on `onVideoSizeChanged` / track-selection change; this is the key signal for verifying ABR.
  - `hls_error` (errorCode name, host)
  - `hls_first_frame` (startup latency ms, from `setMedia` to `STATE_READY`/first render)
- **Redaction:** log URI **host + path** only; strip query strings (signed tokens). No cookies/headers in logs.
- Counters/timings are emitted via the existing logging facade; no analytics backend integration in this ticket.

## 11. Testing Strategy

Unit (JVM, `core-media`):
- `MediaSourceFactoryProviderTest`: `resolveType` for `.m3u8` (with/without query string), MP4, explicit `MediaType.HLS`/`PROGRESSIVE`; asserts `HlsMediaSource` vs progressive source produced.
- Header-scoping test: app-auth headers attached only when host == API host; dropped for foreign CDN host.

Instrumented (androidTest, headless emulator — AND-051 CI lane):
- **`HlsPlaybackTest` (acceptance):** load a bundled/served **multi-variant master playlist** (VOD) via a local `MockWebServer` serving canned `.m3u8` + small segment fixtures (reuse AND-046 harness pattern). Assert: player reaches `STATE_READY`, `isPlaying` becomes true, and — by throttling the `MockWebServer`/dispatcher bandwidth — assert `selectedVideoHeight`/`selectedVideoBitrate` changes between two variants (proves **adaptive switching**).
- **Live manifest test:** serve a manifest without `#EXT-X-ENDLIST`; assert `PlaybackUiState.isLive == true` and `durationMs == C.TIME_UNSET`.
- **Behind-live-window recovery test:** simulate the exception path; assert auto `seekToDefaultPosition` + recovery without terminal error.
- **Reuse test (regression on AND-166):** play MP4 then HLS on the same `PlayerManager`; assert single `ExoPlayer` instance and no leak after lifecycle stop.

Fixtures: a tiny pre-encoded 2-variant HLS test asset (e.g. 240p + 480p, a few seconds) checked into `core-media/src/androidTest/assets/hls/`. Network-dependent tests use `MockWebServer`, not the live dev backend, so CI is deterministic.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-166 (Media3/ExoPlayer integration) — `PlayerManager`, `core-media`, OkHttp data source wiring, `PlaybackUiState`, lifecycle release. Cannot start until AND-166's progressive MP4 acceptance passes.
- **Upstream (transitive):** AND-003 (core module structure), AND-009 (OkHttp client), AND-011 (cookie jar), AND-051 (instrumented CI lane), AND-046 (MockWebServer harness).
- **Blocks:** AND-168 (Reusable player UI) and AND-169 (Adaptive quality / data-saver). AND-169 specifically builds quality caps / metered policy on the `TrackSelector` defaults and `selectedVideoHeight`/`isLive` state introduced here.
- **Sequencing:** AND-166 → **AND-167** → AND-168 → AND-169. AND-167 and AND-168 can partially overlap once AND-167's `setMedia`/state surface is stable, but the ABR acceptance test must land in AND-167.

## 13. Risks & Open Questions

- **R1 — Dev backend / CDN reliability:** plaintext, unreliable host may produce flaky live tests. Mitigation: all automated tests use `MockWebServer`; manual smoke against the dev host only.
- **R2 — Double retry:** combining ExoPlayer's loader retries with the app's GET backoff interceptor (AND-016) could amplify load on a flaky host. **OQ3:** confirm AND-016's interceptor is scoped to API (Retrofit) calls only and excluded from media data-source requests; if not, scope it.
- **R3 — Cleartext segment hosts:** if segments are served from a different cleartext host than the manifest, network-security-config domain list must include it. **OQ1:** enumerate actual manifest/segment hosts used by the dev backend.
- **OQ2 — LoadErrorHandlingPolicy tuning:** are default retry counts/backoff acceptable for the dev host, or do we need a custom policy? Defer tuning unless smoke testing shows excessive stalls.
- **OQ4 — LL-HLS:** does the backend emit Low-Latency HLS (`#EXT-X-PART`)? ExoPlayer 1.4 supports it; no extra work expected, but confirm target offset behavior if so.
- **OQ5 — DRM:** assumed none (no `#EXT-X-KEY` / Widevine) for v1. If encrypted HLS appears, a follow-up ticket is required.

## 14. Acceptance Criteria

AC1. `androidx.media3:media3-exoplayer-hls` is added to `core-media` at the Media3 1.4 version pinned in the catalog; project builds (AGP 8.7.3, JDK 17).
AC2. Given a **multi-variant VOD `.m3u8`**, calling `PlayerManager.setMedia(MediaSourceSpec(uri))` (AUTO type) builds an `HlsMediaSource`, reaches `STATE_READY`, and plays in the existing Compose surface from AND-166.
AC3. **Adaptive switching:** under varying bandwidth (throttled `MockWebServer` in test; real network in smoke), the selected video variant changes, observable as a change in `PlaybackUiState.selectedVideoHeight`/`selectedVideoBitrate`. No fixed track is pinned.
AC4. A **live** manifest (no `#EXT-X-ENDLIST`) plays; `PlaybackUiState.isLive == true`, targets the live edge, and `ERROR_CODE_BEHIND_LIVE_WINDOW` auto-recovers to the live edge.
AC5. HLS manifest/segment requests go through the shared `OkHttpClient` (cookies + ~20s timeout apply); app-auth headers are sent only when the URI host equals the API host.
AC6. MP4 progressive playback (AND-166) still works, on the **same single** `ExoPlayer` instance, including MP4→HLS switching with no leak after lifecycle stop.
AC7. Telemetry emits `hls_prepare`, `hls_variant_switch`, and `hls_error` with query strings redacted.
AC8. Unit + instrumented tests in §11 pass on the headless-emulator CI lane (AND-051).

## 15. Definition of Done

- Code merged to `android-port` under `android/core-media`, namespace `com.testlogon.android.core.media`.
- All AC1–AC8 met; the §11 instrumented acceptance test (multi-variant ABR + live) is green in CI.
- `MediaSourceFactoryProvider` Hilt-provided; `PlayerManager.setMedia(MediaSourceSpec)` public API documented with KDoc.
- No regression to AND-166 MP4 acceptance; lint/Detekt/ktlint (AND-005) clean.
- Header-scoping and cleartext config reviewed (§8); no signed URLs logged in plaintext (§10).
- Open questions OQ1/OQ3 resolved or explicitly deferred with owners noted; OQ5 (DRM) confirmed out of scope.
- Downstream tickets AND-168 and AND-169 unblocked: `PlaybackUiState.isLive`, `selectedVideoHeight`, and the `TrackSelector` hook are available and documented.
