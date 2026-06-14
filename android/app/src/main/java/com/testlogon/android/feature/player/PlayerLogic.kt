package com.testlogon.android.feature.player

import java.util.Locale

/**
 * AND-166 / AND-167 / AND-168 — PURE, JVM-unit-testable player logic.
 *
 * Everything in this file is framework-free: no android.util, no android.text.format, no java.time
 * (API26), no ExoPlayer / Player / Uri types. Time formatting works on Long ms with Locale.ROOT;
 * player-state mapping, error retryability, HLS detection, header scoping, and quality labels are
 * plain functions over Int / String. ExoPlayer-touching runtime code lives in the controller and the
 * Compose surface, never here, so these helpers are covered by the JVM unit suite.
 */

/**
 * AND-166 — UI-facing playback phase, decoupled from Media3 Player.STATE_* ints so unit tests and
 * Compose code never import androidx.media3.common.Player. Mapped from the runtime listener via
 * [PlayerStateMapper.toPhase].
 */
enum class PlaybackPhase { IDLE, BUFFERING, READY, ENDED }

/**
 * AND-166 / AND-167 — caller-supplied media kind. AUTO resolves HLS vs progressive from the URI;
 * an explicit value forces the source factory branch (mirrors AND-167 MediaType in the spec).
 */
enum class PlayerMediaType { AUTO, HLS, PROGRESSIVE }

/**
 * AND-166 — a mapped playback error. [code] is the Media3 PlaybackException.errorCode (surfaced for
 * telemetry only, never shown raw); [codeName] is the symbolic name; [isRetryable] drives the UI
 * Retry affordance. This type holds no Android/Media3 references so it is JVM-testable.
 */
data class PlayerError(
    val code: Int,
    val codeName: String,
    val isRetryable: Boolean,
)

/**
 * AND-166 / AND-167 — the observable player UI state. Pure data; no Media3 types. Position/duration
 * are sampled ms; [isLive] and [selectedVideoHeight]/[selectedVideoBitrate] surface HLS/ABR info for
 * AND-168/AND-169. [durationMs] is [DURATION_UNSET] when unknown (live or not yet known).
 */
data class PlayerUiState(
    val phase: PlaybackPhase = PlaybackPhase.IDLE,
    val isPlaying: Boolean = false,
    val isLive: Boolean = false,
    val positionMs: Long = 0L,
    val bufferedPositionMs: Long = 0L,
    val durationMs: Long = DURATION_UNSET,
    val volume: Float = 1f,
    val selectedVideoHeight: Int = VALUE_UNSET,
    val selectedVideoBitrate: Int = VALUE_UNSET,
    val error: PlayerError? = null,
) {
    /** Whether the scrubber/seek UI is meaningful (VOD with a known, positive duration). */
    val isSeekable: Boolean get() = !isLive && durationMs > 0L

    /** 0f..1f progress for the scrubber; 0 when duration is unknown so the bar never jumps. */
    val progressFraction: Float
        get() = if (durationMs <= 0L) 0f else (positionMs.toFloat() / durationMs).coerceIn(0f, 1f)

    companion object {
        /** Mirrors Media3 C.TIME_UNSET; kept local so this type stays framework-free. */
        const val DURATION_UNSET: Long = Long.MIN_VALUE + 1L
        /** Mirrors Media3 Format.NO_VALUE (-1) for an unknown height/bitrate. */
        const val VALUE_UNSET: Int = -1
    }
}

/**
 * AND-166 — maps Media3 Player.STATE_* ints (passed as plain Int by the runtime listener) onto the
 * pure [PlaybackPhase], and classifies PlaybackException error codes for retryability. The runtime
 * controller passes raw ints/codes here so the mapping stays unit-testable without Media3 on the
 * classpath.
 */
object PlayerStateMapper {

    // Media3 Player.STATE_* values (stable framework constants), redeclared so this object is pure.
    const val STATE_IDLE = 1
    const val STATE_BUFFERING = 2
    const val STATE_READY = 3
    const val STATE_ENDED = 4

    fun toPhase(playbackState: Int): PlaybackPhase = when (playbackState) {
        STATE_BUFFERING -> PlaybackPhase.BUFFERING
        STATE_READY -> PlaybackPhase.READY
        STATE_ENDED -> PlaybackPhase.ENDED
        else -> PlaybackPhase.IDLE
    }

    // Media3 PlaybackException.ERROR_CODE_* values treated as transient (worth a Retry).
    private val RETRYABLE_CODES = setOf(
        2001, // ERROR_CODE_IO_NETWORK_CONNECTION_FAILED
        2002, // ERROR_CODE_IO_NETWORK_CONNECTION_TIMEOUT
        2003, // ERROR_CODE_IO_INVALID_HTTP_CONTENT_TYPE
        2004, // ERROR_CODE_IO_BAD_HTTP_STATUS
        1002, // ERROR_CODE_BEHIND_LIVE_WINDOW
    )

    /** True for transient IO / behind-live errors; false for decode/parse/source errors. */
    fun isRetryable(errorCode: Int): Boolean = errorCode in RETRYABLE_CODES

    /** Builds a pure [PlayerError] from a Media3 error code + symbolic name. */
    fun toError(errorCode: Int, codeName: String): PlayerError =
        PlayerError(code = errorCode, codeName = codeName, isRetryable = isRetryable(errorCode))
}

/**
 * AND-168 — pure ms -> mm:ss / h:mm:ss formatting for the scrubber's elapsed/duration labels.
 * Uses Locale.ROOT (digit-stable, no android.text.format / DateUtils) so it is JVM-unit-tested.
 */
object PlayerTimeFormat {

    /** Formats a non-negative ms value as "m:ss" (or "h:mm:ss" past an hour). Negatives -> 0:00. */
    fun format(ms: Long): String {
        val totalSeconds = (ms.coerceAtLeast(0L)) / 1000L
        val seconds = totalSeconds % 60L
        val minutes = (totalSeconds / 60L) % 60L
        val hours = totalSeconds / 3600L
        return if (hours > 0L) {
            String.format(Locale.ROOT, "%d:%02d:%02d", hours, minutes, seconds)
        } else {
            String.format(Locale.ROOT, "%d:%02d", minutes, seconds)
        }
    }

    /** "elapsed / total" label; an unknown/unset duration renders only the elapsed time. */
    fun positionLabel(positionMs: Long, durationMs: Long): String =
        if (durationMs <= 0L || durationMs == PlayerUiState.DURATION_UNSET) {
            format(positionMs)
        } else {
            "${format(positionMs)} / ${format(durationMs)}"
        }
}

/**
 * AND-167 — pure source-resolution + auth helpers. No Media3 / OkHttp / Uri types; the runtime
 * [MediaSourceFactoryProvider] consumes these decisions to build the actual MediaSource.
 */
object MediaSourceResolver {

    /** True when the URI (query stripped) ends in .m3u8 — the HLS manifest heuristic for AUTO. */
    fun isHlsUri(uri: String): Boolean =
        uri.substringBefore('?').endsWith(".m3u8", ignoreCase = true)

    /** Resolves the effective media type for a spec; AUTO falls back to the URI heuristic. */
    fun resolveType(uri: String, declared: PlayerMediaType): PlayerMediaType = when (declared) {
        PlayerMediaType.AUTO -> if (isHlsUri(uri)) PlayerMediaType.HLS else PlayerMediaType.PROGRESSIVE
        else -> declared
    }

    /**
     * AND-167 §8 header scoping — app-auth headers (Authorization, X-CSRF-Token, cookies, the
     * impersonation token) may only ride a request whose host equals the configured API host;
     * foreign CDN hosts (which carry their own ?token= signed query) get NO app headers. Returns the
     * headers to attach: the full map for an API-host URI, empty otherwise.
     */
    fun scopedHeaders(
        uri: String,
        apiHost: String?,
        headers: Map<String, String>,
    ): Map<String, String> {
        if (headers.isEmpty()) return emptyMap()
        val host = hostOf(uri) ?: return emptyMap()
        return if (apiHost != null && host.equals(apiHost, ignoreCase = true)) headers else emptyMap()
    }

    /** Extracts the lowercased host from an http(s) URI without android.net.Uri. Null if unparseable. */
    fun hostOf(uri: String): String? {
        val schemeSep = uri.indexOf("://")
        if (schemeSep < 0) return null
        val afterScheme = uri.substring(schemeSep + 3)
        val authority = afterScheme.substringBefore('/').substringBefore('?')
        // Strip any userinfo@ and :port.
        val hostPort = authority.substringAfterLast('@')
        val host = hostPort.substringBefore(':')
        return host.lowercase(Locale.ROOT).takeIf { it.isNotEmpty() }
    }

    /**
     * AND-167 §10 — redacts a media URI to host + path (drops the query string that may carry the
     * signed ?token=) for safe logging/telemetry.
     */
    fun redactForLog(uri: String): String = uri.substringBefore('?')

    /**
     * AND-131 / AND-167 — appends the short-lived playback token to an HLS manifest URL exactly like
     * the web client ("`${url}?token=${token}`", "&" when a query already exists). Mirrors the
     * verified web behavior (VideoPlayerPage.tsx / VideoShareCard.tsx). Null url -> null; null/blank
     * token -> the base url unchanged.
     */
    fun tokenizedManifestUrl(manifestUrl: String?, playbackToken: String?): String? {
        val base = manifestUrl ?: return null
        val token = playbackToken?.takeIf { it.isNotBlank() } ?: return base
        val sep = if (base.contains('?')) "&" else "?"
        return "$base${sep}token=$token"
    }
}

/**
 * AND-167 / AND-169 — pure quality-label helpers over the ABR-selected video Format height/bitrate.
 * AND-169 owns the quality MENU; this only provides the display strings AND-168's UI shows.
 */
object PlayerQuality {

    /** A human label for a selected variant height: 1080 -> "1080p"; unknown -> "Auto". */
    fun heightLabel(height: Int): String =
        if (height <= 0 || height == PlayerUiState.VALUE_UNSET) "Auto" else "${height}p"

    /** Bitrate (bps) as an approximate Mbps label for telemetry/overlay; unknown -> "". */
    fun bitrateLabel(bitrateBps: Int): String {
        if (bitrateBps <= 0 || bitrateBps == PlayerUiState.VALUE_UNSET) return ""
        val mbps = bitrateBps / 1_000_000.0
        return String.format(Locale.ROOT, "%.1f Mbps", mbps)
    }
}

/**
 * AND-167 §3 FR3 — default live-edge target offset (ms) applied to HLS items when the manifest does
 * not specify a server-control hold-back. Mirrors the web client's short live buffer intent.
 */
const val DEFAULT_LIVE_TARGET_OFFSET_MS: Long = 8_000L
