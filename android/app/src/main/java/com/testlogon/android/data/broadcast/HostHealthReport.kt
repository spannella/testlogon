package com.testlogon.android.data.broadcast

import java.time.Instant

/**
 * AND-309 — canonical (DTO-free) host health snapshot for a LIVE broadcast session.
 *
 * Built from [BroadcastHealthDto] by [toDomain]. [level] is CLIENT-DERIVED from [connectionQuality]
 * (the wire carries no numeric/enum level). [rttMs] / [ingestConnected] stay null: those would come from
 * real WebRTC RTCStats, and host media is FLAGGED (the
 * [com.testlogon.android.data.webrtc.BroadcastPublisher] seam never opens a peer), so there is no client-
 * derived RTT or ingest-connected signal to surface.
 *
 * [updatedAt] is the server sample time (epoch SECONDS -> [Instant]); UI formats it locale-aware.
 */
data class HostHealthReport(
    val sessionId: String,
    val connectionQuality: String,
    val level: HealthLevel,
    val ingestBitrateKbps: Int,
    val ingestFramerate: Double,
    val droppedFrames: Int,
    val droppedFramesPct: Double,
    val outputErrors: Int,
    val inputLossSeconds: Double,
    val viewerCount: Int,
    val updatedAt: Instant,
    val rttMs: Int? = null,
    val ingestConnected: Boolean? = null,
)

/**
 * AND-309 — client-derived coarse health band, mapped from the server's free `connection_quality` string.
 * Unknown / absent strings map to [UNKNOWN] (the mapper never throws).
 */
enum class HealthLevel {
    HEALTHY, DEGRADED, UNHEALTHY, UNKNOWN
}

/** Maps the wire `connection_quality` string to a [HealthLevel] band (client-derived). */
internal fun String?.toHealthLevel(): HealthLevel = when (this?.lowercase()) {
    "healthy" -> HealthLevel.HEALTHY
    "degraded" -> HealthLevel.DEGRADED
    "unhealthy", "critical" -> HealthLevel.UNHEALTHY
    else -> HealthLevel.UNKNOWN
}

/**
 * AND-309 — pure DTO -> domain mapper. Side-effect-free; never throws. [level] is derived from
 * `connection_quality`; [updatedAt] is `updated_at` epoch SECONDS -> [Instant]; rttMs / ingestConnected
 * stay null (media FLAGGED).
 */
fun BroadcastHealthDto.toDomain(): HostHealthReport = HostHealthReport(
    sessionId = sessionId,
    connectionQuality = connectionQuality,
    level = connectionQuality.toHealthLevel(),
    ingestBitrateKbps = ingestBitrateKbps,
    ingestFramerate = ingestFramerate,
    droppedFrames = droppedFrames,
    droppedFramesPct = droppedFramesPct,
    outputErrors = outputErrors,
    inputLossSeconds = inputLossSeconds,
    viewerCount = viewerCount,
    updatedAt = Instant.ofEpochSecond(updatedAt),
    rttMs = null,
    ingestConnected = null,
)
