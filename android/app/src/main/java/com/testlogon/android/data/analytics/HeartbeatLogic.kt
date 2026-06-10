package com.testlogon.android.data.analytics

/**
 * AND-171 — PURE, JVM-unit-testable playback-analytics logic.
 *
 * Framework-free (no Media3, no Retrofit, no android.*): the target model, phase enum, the internal
 * snapshot, the playing-edge derivation, the interval/cadence, the watched-time clamp, and the
 * phase->server-call mapping are plain data + functions. The runtime [DefaultPlaybackReporter]
 * (Player.Listener + lifecycle) and the [CoroutineHeartbeatSink] (network) consume these decisions.
 *
 * REAL-CONTRACT (verified, AND-171 §5): there is NO unified `/ui/playback/heartbeat` endpoint and no
 * JSON telemetry body. VOD -> one-shot `POST /ui/videos/{id}/view` (ViewRecordOut). Live broadcast ->
 * `viewers/join` -> `viewers/heartbeat?viewer_id=` -> `viewers/leave?viewer_id=`
 * (ViewerJoinOut/ViewerHeartbeatOut). The rich snapshot below is INTERNAL telemetry only (local debug
 * logs/counters) — it is never sent as a body. No server cadence override, no server stop directive.
 */

/** AND-171 §4.1 — what is being watched; selects the server call family. */
sealed interface PlaybackTarget {
    val kind: String
    val id: String

    data class Content(override val id: String) : PlaybackTarget {
        override val kind: String get() = KIND
        companion object { const val KIND = "content" }
    }

    data class Broadcast(override val id: String) : PlaybackTarget {
        override val kind: String get() = KIND
        companion object { const val KIND = "broadcast" }
    }
}

/** AND-171 §4.1 — the lifecycle phase of a reporting event. */
enum class HeartbeatPhase { START, HEARTBEAT, STOP }

/**
 * AND-171 §4.1 — internal-only snapshot (NOT a server body). Feeds local debug logs / drop counters.
 */
data class PlaybackSnapshot(
    val sessionId: String,
    val target: PlaybackTarget,
    val phase: HeartbeatPhase,
    val positionMs: Long,
    val durationMs: Long?,
    val watchedMsDelta: Long,
    val isLive: Boolean,
    val playbackSpeed: Float,
    val clientEventId: String,
    val occurredAtEpochMs: Long,
)

/** AND-171 §6 — in-memory session accounting (mutable; main-thread guarded by the reporter). */
data class SessionState(
    val sessionId: String,
    val target: PlaybackTarget,
    var startSent: Boolean = false,
    var lastReportPositionMs: Long = 0L,
    var lastReportWallMs: Long = 0L,
    /** Broadcast-only: viewer_id obtained from `viewers/join`, reused for heartbeat/leave. */
    var viewerId: String? = null,
)

/**
 * AND-171 — the pure scheduling / accounting decisions, JVM-tested with no Player on the classpath.
 */
object HeartbeatLogic {

    const val DEFAULT_INTERVAL_MS = 10_000L
    const val MIN_INTERVAL_MS = 5_000L
    const val MAX_INTERVAL_MS = 60_000L

    /** Media3 Player.STATE_READY (redeclared so this object stays pure). */
    const val STATE_READY = 3

    /**
     * AND-171 FR-1/§4.2 — the single "actually playing" boolean from the raw player state. Heartbeats
     * fire only on its rising edge (true) and stop on its falling edge. Buffering / paused / ended are
     * all not-playing.
     */
    fun isPlaying(playbackState: Int, playWhenReady: Boolean): Boolean =
        playbackState == STATE_READY && playWhenReady

    /** Clamps a configured interval into the supported bounds (§6). */
    fun clampInterval(intervalMs: Long): Long =
        intervalMs.coerceIn(MIN_INTERVAL_MS, MAX_INTERVAL_MS)

    /**
     * AND-171 FR-6 — watched wall-clock time during the interval, clamped so seeks/scrubs cannot
     * inflate watch time. The reported delta is at most the wall-clock elapsed scaled by playback
     * speed, and additionally clamped to the (non-negative) position delta when the stream is NOT live
     * (live has no meaningful position delta). Negative position deltas (backward seek) contribute 0.
     */
    fun watchedMsDelta(
        wallElapsedMs: Long,
        intervalMs: Long,
        positionDeltaMs: Long,
        isLive: Boolean,
        speed: Float,
    ): Long {
        val byWall = minOf(wallElapsedMs.coerceAtLeast(0L), (intervalMs * speed).toLong().coerceAtLeast(0L))
        if (isLive) return byWall
        val byPosition = positionDeltaMs.coerceAtLeast(0L)
        return minOf(byWall, byPosition)
    }

    /**
     * AND-171 §5.1 — whether a START phase performs a server call for this target. Content -> a single
     * one-shot view record; Broadcast -> the join (which mints the viewer_id).
     */
    fun startCallsServer(target: PlaybackTarget): Boolean = when (target) {
        is PlaybackTarget.Content -> true // record view once
        is PlaybackTarget.Broadcast -> true // join
    }

    /**
     * AND-171 §5.1 — whether a HEARTBEAT phase performs a server call. Only broadcast has a periodic
     * server call (`viewers/heartbeat`); VOD has NO periodic server call (one-shot view at START).
     */
    fun heartbeatCallsServer(target: PlaybackTarget): Boolean = when (target) {
        is PlaybackTarget.Content -> false
        is PlaybackTarget.Broadcast -> true
    }

    /**
     * AND-171 §5.1 — whether a STOP phase performs a server call. Broadcast -> `viewers/leave`;
     * VOD -> no-op (the view was already recorded at START).
     */
    fun stopCallsServer(target: PlaybackTarget): Boolean = when (target) {
        is PlaybackTarget.Content -> false
        is PlaybackTarget.Broadcast -> true
    }
}
