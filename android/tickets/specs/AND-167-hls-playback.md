---
id: AND-167
title: HLS playback
milestone: M4
epic: E23
priority: P0
size: M
depends_on: [AND-166]
blocks: [AND-168, AND-169]
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference (verified):** the reference app's shared player is `src/components/shared/MediaPlayer.tsx` (MEDIA-001), which uses `hls.js` (`import Hls from "hls.js"`) attached to a `<video>` element, with `startLevel: -1` (auto/ABR), a Safari native-HLS fallback, and per-mode tuning (`lowLatencyMode`, `maxBufferLength` 6/30) for `mode: "live" | "vod"`. The manifest URL comes from the `hls_manifest_url` field on the video DTO, and **playback is authenticated by a `?token=<playback_token>` query parameter appended to the manifest URL** (verified in `src/pages/videos/VideoPlayerPage.tsx`: `` `${video.hls_manifest_url}?token=${video.playback_token}` `` and `src/pages/messages/VideoShareCard.tsx`). The token + URL are minted by the backend (`hls_manifest_url`, `playback_token`, `playback_expires_at` on `VideoDetailOut`, and via the entitlement endpoint for feed/post embeds). Mirror this URL/query-token handling, not the JS player internals. NOTE: `MediaPlayer.tsx` also accepts a `drmKeyUrl` for **AES-128 HLS encryption** — see §13 OQ5 correction.
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

No new TestLogon backend endpoints are introduced by this ticket. HLS manifests and segments are fetched directly by ExoPlayer over HTTP(S) from URLs supplied in media payloads. **Verified source of the manifest URL:** the `hls_manifest_url` (nullable string) and accompanying `playback_token` (nullable string) + `playback_expires_at` (nullable epoch int) fields on `VideoDetailOut` (OpenAPI `GET /ui/videos/{video_id}` → resp `200:VideoDetailOut`), and the per-post entitlement call `POST /ui/posts/{postId}/video/entitlement` (frontend `src/api/endpoints/newsfeed.ts: issueVideoPostEntitlement`, returning `{ video_id, hls_manifest_url, playback_token, playback_expires_at }`). Live broadcasts mint a separate URL via `POST /broadcast/sessions/{session_id}/playback-url` → `BroadcastPlaybackUrlOut { session_id, playback_url, expires_at }`, verifiable with `GET /broadcast/playback/verify` → `BroadcastPlaybackTokenVerifyOut { valid }`. **The web client authenticates HLS playback by appending `?token=<playback_token>` to the manifest URL** (verified `src/pages/videos/VideoPlayerPage.tsx`), not by session cookies. The Android caller is expected to construct the tokenized URL the same way; consuming these DTOs is owned upstream (feed/post/video tickets), and this ticket only plays whatever tokenized URL it is handed. The relevant "contract" for this ticket is therefore the HLS wire format, served behind the app's configured HTTP stack:

- **Master playlist** (`GET <uri>.m3u8`, `Content-Type: application/vnd.apple.mpegurl`): contains multiple `#EXT-X-STREAM-INF` variants (different `BANDWIDTH`/`RESOLUTION`) — required for FR4 adaptive switching.
- **Media playlist** (per-variant `.m3u8`): VOD ends with `#EXT-X-ENDLIST`; live omits it and may include `#EXT-X-SERVER-CONTROL:CAN-BLOCK-RELOAD=YES,HOLD-BACK=...` and `#EXT-X-PART-INF` (LL-HLS).
- **Segments** (`.ts` / fMP4 `.m4s`): fetched via the OkHttp data source with the ~20s read timeout (AND-009). NOTE: per the verified web behavior, manifest/segment **authorization is carried in the `?token=` query string, not in cookies**; the persistent cookie jar (AND-011) will still be attached by the shared client when the host matches, but it is not the auth mechanism the backend relies on for media. Do not assume cookie-gated segments.

Request handling rules:
- Manifest/segment GETs are idempotent; ExoPlayer's own loader handles retries — do not add the app-level GET retry interceptor (AND-016) to media loads to avoid double-retry. Use the shared client but verify the retry interceptor is scoped to API calls only (open question OQ3).
- Per-source `headers` map (FR6) is applied via `setDefaultRequestProperties`. The web client's API transport (verified `src/api/client.ts`) attaches `Authorization: Bearer <accessToken>`, `X-CSRF-Token` (from the `ui_csrf` cookie), and `X-IMPERSONATION-TOKEN`, plus `credentials: include`. None of these are required for HLS media loads (auth is the `?token=` query param). Do not attach `Authorization`, `X-CSRF-Token`, or session cookies to a manifest/segment request unless the manifest host equals the configured API host (see §8 header-scoping).

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
- **Header scoping:** never send the app's auth headers — `Authorization: Bearer <token>`, `X-CSRF-Token`, `X-IMPERSONATION-TOKEN`, or the session cookie (the full set the web client sends, verified in `src/api/client.ts`) — to a manifest or segment host that differs from the API host. The `MediaSourceFactoryProvider` must guard `setDefaultRequestProperties` so app-auth headers are only attached when the URI host matches the configured API host; third-party CDN URLs (which carry their own `?token=` signed query param) get no app headers.
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
- **OQ4 — LL-HLS:** does the backend emit Low-Latency HLS (`#EXT-X-PART`)? The web client opts into low-latency for live (`lowLatencyMode: mode === "live"`, with `maxBufferLength` 6 / `maxMaxBufferLength` 12 for live vs 30/60 for VOD — verified `src/components/shared/MediaPlayer.tsx`), which strongly suggests live streams MAY be LL-HLS. ExoPlayer 1.4 supports LL-HLS; no extra work expected, but confirm the `targetOffsetMs` / live-edge behavior against an actual live manifest, since web tunes buffer length per mode.
- **OQ5 — DRM / encryption (CORRECTED):** the original assumption of "no encryption for v1" is too strong. The web reference player **does** support encrypted HLS via a `drmKeyUrl` prop for **AES-128 (`#EXT-X-KEY METHOD=AES-128`)** key delivery (verified `src/components/shared/MediaPlayer.tsx`: prop `drmKeyUrl` "Key server URL for AES-128 HLS encryption", `hlsConfig.emeEnabled = true` when set). AES-128 sample/segment encryption is handled natively by ExoPlayer's `HlsMediaSource` (the key URI is read from the playlist and fetched through the data source) and requires **no extra Android work for v1** as long as the key request goes through the same OkHttp data source — so basic AES-128 streams should play out of the box. What remains genuinely deferred is **Widevine/PlayReady (EME/CDM) DRM**, for which no `#EXT-X-KEY METHOD=SAMPLE-AES`/Widevine PSSH usage is evidenced in the reference; if Widevine-protected HLS appears, a follow-up ticket is required. Action: add an instrumented smoke for an AES-128 playlist if a fixture is available; otherwise track as a known gap.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. "OpenAPI" = `reference/openapi.index.txt` / `reference/openapi.pretty.json`; frontend paths are under `reference/src/`.

1. **Manifest URL is delivered as `hls_manifest_url` on the video DTO.** — VERIFIED. OpenAPI `GET /ui/videos/{video_id}` → `200:VideoDetailOut`; schema `VideoDetailOut.hls_manifest_url` (nullable string). Frontend `src/api/endpoints/videos.ts: VideoDetail.hls_manifest_url`, `src/api/types.ts` (multiple), `src/pages/feed/VideoPostPlayer.tsx`.
2. **HLS playback is authenticated by a `?token=<playback_token>` query parameter appended to the manifest URL — not by session cookies.** — CORRECTED (spec originally implied cookie-jar-gated playlists). Source: frontend `src/pages/videos/VideoPlayerPage.tsx` (`` `${video.hls_manifest_url}?token=${video.playback_token}` ``) and `src/pages/messages/VideoShareCard.tsx`. Backing fields `playback_token` / `playback_expires_at` confirmed on `VideoDetailOut` (OpenAPI schema `VideoDetailOut`).
3. **Per-post/feed video playback URL + token come from an entitlement endpoint.** — VERIFIED. Frontend `src/api/endpoints/newsfeed.ts: issueVideoPostEntitlement` → `POST /ui/posts/{postId}/video/entitlement` returning `{ video_id, hls_manifest_url, playback_token, playback_expires_at }`; consumed in `src/pages/feed/VideoPostPlayer.tsx`.
4. **Live broadcasts mint a separate playback URL.** — VERIFIED. OpenAPI `POST /broadcast/sessions/{session_id}/playback-url` → `BroadcastPlaybackUrlOut { session_id, playback_url, expires_at }`; token verification `GET /broadcast/playback/verify` → `BroadcastPlaybackTokenVerifyOut { valid }`.
5. **Web reference uses `hls.js` with auto/ABR start level and a Safari native-HLS fallback.** — VERIFIED. `src/components/shared/MediaPlayer.tsx`: `import Hls from "hls.js"`, `startLevel: -1`, `if (!Hls.isSupported()) { ... native fallback ... }`. (Spec's framing that ExoPlayer replaces the `hls.js` shim is sound.)
6. **Web live mode enables low-latency HLS and uses shorter buffers (live 6/12 vs VOD 30/60).** — VERIFIED. `src/components/shared/MediaPlayer.tsx`: `lowLatencyMode: mode === "live"`, `maxBufferLength: mode === "live" ? 6 : 30`, `maxMaxBufferLength: mode === "live" ? 12 : 60`. Informs §3 FR3 / §13 OQ4.
7. **Encrypted HLS via AES-128 is a real product capability (not "no DRM").** — CORRECTED. `src/components/shared/MediaPlayer.tsx`: prop `drmKeyUrl` documented "Key server URL for AES-128 HLS encryption"; sets `hlsConfig.emeEnabled = true`. ExoPlayer handles AES-128 HLS natively. Widevine/PlayReady remains unevidenced and deferred. See §13 OQ5.
8. **App API transport sends `Authorization: Bearer`, `X-CSRF-Token` (from `ui_csrf` cookie), `X-IMPERSONATION-TOKEN`, and `credentials: include`.** — VERIFIED / CLARIFIED. `src/api/client.ts` lines ~157–183. Spec previously cited only "cookie / X-CSRF-Token"; corrected to the full header set for §8 scoping.
9. **No new TestLogon backend endpoints are introduced by this ticket; HLS is the wire contract.** — VERIFIED (negative). No `m3u8`/`hls`/`playlist` HLS-serving endpoint exists in `reference/openapi.index.txt` (grep returned no matches); manifests/segments are static media URLs, not API operations.
10. **Web player surfaces variant list and current level on manifest-parse / level-switch (analogue of Android ABR observation).** — VERIFIED. `src/components/shared/MediaPlayer.tsx`: `Hls.Events.MANIFEST_PARSED` builds `QualityLevel[]` (height/bitrate); `Hls.Events.LEVEL_SWITCHED` updates current level. Supports §6 claim that selected height/bitrate is the observable ABR signal.
11. **Web treats manifest load failure / token expiry as a distinct user-facing error ("Stream unavailable … or the URL has expired").** — VERIFIED. `src/components/shared/MediaPlayer.tsx` `Hls.Events.ERROR` NETWORK_ERROR branch; `playback_expires_at` field corroborates token expiry. Supports §7 error mapping and TC-AND-167-04.
12. **Media3/ExoPlayer 1.4 `HlsMediaSource`, `setAllowChunklessPreparation`, `DefaultTrackSelector` ABR, `MediaItem.LiveConfiguration`, `ERROR_CODE_BEHIND_LIVE_WINDOW`, `isCurrentMediaItemLive`.** — UNVERIFIED-ASSUMPTION (framework ref). These are Media3 framework APIs not present in the provided sources; rely on Media3 1.4 docs (framework ref: https://developer.android.com/media/media3/exoplayer/hls and https://developer.android.com/reference/androidx/media3/exoplayer/hls/HlsMediaSource). API names are accurate to Media3 1.x as of the knowledge cutoff but should be pinned against the catalog version in AND-166.
13. **`OkHttpDataSource.Factory` (media3-datasource-okhttp) is the data source.** — UNVERIFIED-ASSUMPTION (framework ref). Reasonable Media3 wiring; not in provided sources. Framework ref: https://developer.android.com/reference/androidx/media3/datasource/okhttp/OkHttpDataSource.
14. **Cleartext dev backend host `http://18.222.237.167:8000`.** — UNVERIFIED-ASSUMPTION. Stated in spec/AND-166 context; not confirmable from OpenAPI/frontend sources here. Actual manifest/segment hosts (OQ1) remain unenumerated.
15. **AND-016 GET-retry interceptor is scoped to API/Retrofit calls only (OQ3).** — UNVERIFIED-ASSUMPTION. AND-016 source not in provided references; must be confirmed in the Android codebase.

### Corrections made
- **§2 / §5 / §6:** Replaced the vague "signed query params / cookie-based playlists" framing with the verified mechanism — manifest URL = `hls_manifest_url`, auth = `?token=<playback_token>` query param (and the broadcast `playback-url` path for live). Cited exact DTO fields and frontend files.
- **§5 / §7 / §8:** Corrected the auth-header set the web client actually sends (added `Authorization: Bearer` and `X-IMPERSONATION-TOKEN` alongside `X-CSRF-Token`/cookie) and clarified that none of these are the media auth mechanism; header-scoping guard now names the full set.
- **§5 segments bullet:** Removed the implication that segments are cookie-gated; auth is the query token.
- **§13 OQ4:** Strengthened with verified web evidence of low-latency live mode and per-mode buffer tuning.
- **§13 OQ5:** Corrected the blanket "assume no DRM" to "AES-128 HLS is supported by the product and handled natively by ExoPlayer; only Widevine/PlayReady is deferred."

### Open assumptions
- Media3/ExoPlayer API surface (claims 12–13) is framework knowledge, not derivable from the provided TestLogon sources — pin to the AND-166 version catalog.
- Actual manifest/segment CDN hostnames and whether segments share the manifest host (OQ1/R3) cannot be enumerated from the supplied OpenAPI/frontend (manifest URLs are opaque runtime values).
- AND-016 interceptor scoping (OQ3/R2), AND-009 timeout value (~20s), AND-011 cookie jar, and the cleartext dev host are taken from sibling-ticket context not included here; verify in-repo.
- Whether live broadcast manifests are LL-HLS (`#EXT-X-PART`) is inferred from the web `lowLatencyMode` flag, not confirmed against a real manifest.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** = headless emulator AVD `test35` (x86_64, Android 15 / API 35, KVM, CI lane AND-051); **device** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). All network-dependent automated cases use `MockWebServer` (AND-046) for determinism; the physical device is used where real-hardware decode / ABI differences matter.

- **TC-AND-167-01 — Source resolution: AUTO `.m3u8` builds `HlsMediaSource`.**
  - Type: unit (JVM). Target: JVM. Preconditions: `MediaSourceFactoryProvider` constructed with a stub `OkHttpClient`.
  - Steps: call `create(MediaSourceSpec("https://h/x.m3u8"))`; also `"...x.m3u8?token=abc"`, `"...x.mp4"`, explicit `MediaType.HLS` on a non-`.m3u8` URI, explicit `MediaType.PROGRESSIVE` on a `.m3u8` URI.
  - Expected: `.m3u8` (with/without query) and explicit HLS → `HlsMediaSource`; `.mp4` and explicit PROGRESSIVE → progressive/`DefaultMediaSourceFactory` source. `resolveType` strips query before suffix check.
  - Traces: AC2 (partial), AC6 (progressive branch).

- **TC-AND-167-02 — Header scoping: app-auth headers attached only when host == API host.**
  - Type: unit (JVM). Target: JVM. Preconditions: configured API host known; provider with header hook.
  - Steps: build sources for an API-host URL with headers (`Authorization`, `X-CSRF-Token`) and for a foreign CDN-host URL with the same headers; inspect the data-source `defaultRequestProperties` applied.
  - Expected: app-auth headers present for API-host source; absent for foreign-host source. Foreign host gets no `Authorization`/`X-CSRF-Token`/cookie.
  - Traces: AC5.

- **TC-AND-167-03 — Happy path: multi-variant VOD reaches READY and plays + ABR switch (acceptance).**
  - Type: contract/MockWebServer + instrumented. Target: emu35 (CI acceptance); confirm once on device for real arm64 decode.
  - Preconditions: `MockWebServer` serves a 2-variant master playlist (240p + 480p) + small segment fixtures (`core-media/src/androidTest/assets/hls/`); dispatcher can throttle bandwidth.
  - Steps: `PlayerManager.setMedia(MediaSourceSpec(uri))` (AUTO); await `STATE_READY` + `isPlaying==true`; throttle bandwidth low then high (or vice versa); observe `PlaybackUiState.selectedVideoHeight`/`selectedVideoBitrate`.
  - Expected: reaches `STATE_READY`, `isPlaying` true, no pinned track, and selected height/bitrate changes between the two variants (proves adaptive switching).
  - Traces: AC2, AC3, AC8.

- **TC-AND-167-04 — Manifest error: 4xx / unparseable manifest maps to PlaybackError.**
  - Type: contract/MockWebServer + instrumented. Target: emu35.
  - Preconditions: `MockWebServer` returns 404 for the manifest, and a separate run returns malformed `.m3u8` body.
  - Steps: `setMedia(...)`; observe `onPlayerError` / `PlaybackUiState.error`.
  - Expected: 404 → `ERROR_CODE_IO_BAD_HTTP_STATUS`; malformed → `ERROR_CODE_PARSING_MANIFEST_MALFORMED`; mapped to the "Can't load video" `PlaybackError`; bounded single app-level retry not exceeded. Mirrors web "Stream unavailable / URL expired" handling.
  - Traces: AC2 (negative), AC8.

- **TC-AND-167-05 — Expired playback token: 401/403 on tokenized manifest.**
  - Type: contract/MockWebServer + instrumented. Target: emu35.
  - Preconditions: `MockWebServer` returns 403 when `?token=` is missing/expired.
  - Steps: `setMedia(MediaSourceSpec("…/x.m3u8?token=expired"))`; observe error state.
  - Expected: surfaces an IO/bad-HTTP-status `PlaybackError` (not a crash); query string redacted in any log. Confirms the token is the auth path (claim 2/11).
  - Traces: AC5, AC7.

- **TC-AND-167-06 — Live manifest: isLive true and unbounded duration.**
  - Type: contract/MockWebServer + instrumented. Target: emu35.
  - Preconditions: `MockWebServer` serves a media playlist WITHOUT `#EXT-X-ENDLIST` (optionally `#EXT-X-SERVER-CONTROL`).
  - Steps: `setMedia(...)`; await ready; read `PlaybackUiState`.
  - Expected: `isLive == true`, `durationMs == C.TIME_UNSET`, player targets the live edge using manifest hold-back when present else `DEFAULT_LIVE_TARGET_OFFSET_MS`.
  - Traces: AC4 (partial), AC8.

- **TC-AND-167-07 — Behind-live-window auto-recovery.**
  - Type: integration/instrumented. Target: emu35.
  - Preconditions: live source; simulate `ERROR_CODE_BEHIND_LIVE_WINDOW` (e.g. force the player behind the window via a sliding `MockWebServer` window or injected exception).
  - Steps: trigger the behind-live error; observe recovery.
  - Expected: `PlayerManager` calls `seekToDefaultPosition()` + `prepare()`, rejoins live edge, no terminal `PlaybackError` surfaced.
  - Traces: AC4.

- **TC-AND-167-08 — Single-player reuse: MP4 → HLS on the same ExoPlayer, no leak.**
  - Type: integration/instrumented. Target: emu35.
  - Preconditions: `PlayerManager` from AND-166; MP4 fixture + HLS fixture.
  - Steps: play MP4, assert ready; `setMedia` HLS spec on the same manager; assert ready; capture the underlying `ExoPlayer` reference across both; drive lifecycle stop.
  - Expected: same single `ExoPlayer` instance reused (no second player), state resets to IDLE/BUFFERING on switch, instance released after lifecycle stop (no leak).
  - Traces: AC6.

- **TC-AND-167-09 — OkHttp data source is used (not DefaultHttpDataSource); ~20s timeout applies.**
  - Type: contract/MockWebServer + instrumented. Target: emu35.
  - Preconditions: `MockWebServer` records request headers and can delay responses.
  - Steps: `setMedia(...)`; inspect that requests carry the shared client's fingerprint (e.g. User-Agent / interceptor marker); add a delay beyond the read timeout for one case.
  - Expected: manifest/segment requests go through the shared `OkHttpClient`; a response slower than ~20s yields a timeout/network error (`ERROR_CODE_IO_NETWORK_CONNECTION_FAILED`/`_TIMEOUT`) not a UI hang.
  - Traces: AC5, AC8.

- **TC-AND-167-10 — Telemetry: hls_prepare / hls_variant_switch / hls_error with redacted query strings.**
  - Type: unit + instrumented. Target: JVM (redaction logic) + emu35 (AnalyticsListener firing during ABR).
  - Preconditions: capturing logger; tokenized signed URL with `?token=secret`.
  - Steps: run the ABR happy path (TC-03) and an error case (TC-04) with the capturing logger; inspect emitted events.
  - Expected: `hls_prepare` (host+path only, type=HLS, isLive), `hls_variant_switch` (from→to height/bitrate), `hls_error` (errorCode name, host) emitted; NO query string / token / cookie / header value appears in any log line.
  - Traces: AC7.

- **TC-AND-167-11 — Cleartext policy: cleartext dev host allowed, arbitrary HTTPS-only enforced.**
  - Type: instrumented (security). Target: emu35.
  - Preconditions: network-security-config permitting cleartext only for the dev host(s).
  - Steps: attempt a cleartext `http://` manifest load against the permitted dev host (succeeds path) and against a non-allowlisted cleartext host (blocked path).
  - Expected: permitted dev host loads; non-allowlisted cleartext host is blocked by the platform (no blanket `usesCleartextTraffic`). 
  - Traces: AC5 (security boundary), §8.

- **TC-AND-167-12 — AES-128 encrypted HLS plays natively (OQ5 follow-up smoke).**
  - Type: instrumented/e2e. Target: **device (MUST run on physical device)** — real arm64-v8a hardware decode of decrypted segments; emulator x86 decode is not representative for the encrypted/decoder path.
  - Preconditions: a 2-variant AES-128 (`#EXT-X-KEY METHOD=AES-128`) HLS fixture with a key URI served by `MockWebServer`; if no fixture, mark skipped/known-gap.
  - Steps: `setMedia` the AES-128 manifest; await ready; verify playback + ABR; confirm key request goes through the OkHttp data source.
  - Expected: stream decrypts and plays; key fetched via shared data source; if Widevine/SAMPLE-AES encountered instead, fail fast with a clear unsupported error (deferred to follow-up).
  - Traces: AC2 (encrypted variant), §13 OQ5.

- **TC-AND-167-13 — Offline / flaky-dev-host smoke (manual).**
  - Type: manual. Target: **device** (real cellular/Wi-Fi toggling against dev host `http://18.222.237.167:8000`).
  - Preconditions: app pointed at dev backend; a real video with `hls_manifest_url` + `playback_token`.
  - Steps: start playback; toggle airplane mode mid-stream; restore connectivity; for a live stream, leave the device backgrounded long enough to fall behind the live window.
  - Expected: buffering state (not error) during brief drops; graceful network-error state on sustained loss; live auto-recovers to the edge on reconnect; no crash, no leaked player after backgrounding.
  - Traces: AC4, AC6, §7 resilience, R1.

- **TC-AND-167-14 — Captions/subtitles tracks are exposed, not stripped (accessibility plumbing).**
  - Type: instrumented. Target: emu35.
  - Preconditions: HLS fixture with `#EXT-X-MEDIA:TYPE=SUBTITLES`/`CLOSED-CAPTIONS`.
  - Steps: `setMedia`; inspect the player `Tracks` after `onTracksChanged`.
  - Expected: text/subtitle tracks present and selectable (UI/styling deferred to AND-168); HLS source does not drop them.
  - Traces: §9, AC8 (test-suite green).

### Coverage matrix

| AC (§14) | Covered by |
|---|---|
| AC1 (dependency added, builds) | Covered by CI build gate; no dedicated TC (build/catalog assertion). Implicitly required by all instrumented TCs (TC-03..14). |
| AC2 (VOD AUTO → HlsMediaSource, READY, plays) | TC-AND-167-01, TC-AND-167-03, TC-AND-167-04, TC-AND-167-12 |
| AC3 (adaptive switching, no pinned track) | TC-AND-167-03 |
| AC4 (live plays, isLive, live edge, behind-live recovery) | TC-AND-167-06, TC-AND-167-07, TC-AND-167-13 |
| AC5 (shared OkHttp; app headers only when host==API) | TC-AND-167-02, TC-AND-167-05, TC-AND-167-09, TC-AND-167-11 |
| AC6 (MP4 still works, single instance, MP4→HLS, no leak) | TC-AND-167-01 (progressive branch), TC-AND-167-08, TC-AND-167-13 |
| AC7 (telemetry events, query strings redacted) | TC-AND-167-05, TC-AND-167-10 |
| AC8 (unit + instrumented suites green on CI lane) | TC-AND-167-03, TC-AND-167-04, TC-AND-167-06, TC-AND-167-09, TC-AND-167-14 (suite); JVM TC-AND-167-01/02/10 |
