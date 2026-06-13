package com.testlogon.android.data.broadcast

/**
 * AND-316 — DTO-free domain models for the host AD-BREAK / AD-CONFIG surface.
 *
 * SCOPE: HOST control-plane only (config edit + ad-break trigger/end). Viewer ad RENDERING is OUT OF SCOPE.
 * Timestamps are kept as epoch-SECOND [Long]s (matching how the host code already carries the active-break
 * started_at on the wire — no Instant conversion is needed for the simple countdown maths). The mappers are
 * pure and never throw on shape variance.
 */

/**
 * The host ad configuration plus the current ad-break state. [adBreakStartedAt] is an epoch-SECOND Long, null
 * when no break is active. [midRollDurationSeconds] / [skipAfterSeconds] are the persisted server values.
 */
data class AdConfig(
    val sessionId: String,
    val preRollEnabled: Boolean,
    val midRollDurationSeconds: Int,
    val skipAfterSeconds: Int,
    val adBreakActive: Boolean,
    val adBreakStartedAt: Long?,
    val totalAdBreaks: Int,
)

/**
 * A just-started ad break (from the trigger response). [startedAt] is an epoch-SECOND Long; the countdown is
 * derived as startedAt + durationSeconds - now.
 */
data class AdBreak(
    val durationSeconds: Int,
    val startedAt: Long,
    val skipAfterSeconds: Int,
)

// ---- mappers (pure; never throw) ----

internal fun BroadcastAdConfigOutDto.toDomain(): AdConfig = AdConfig(
    sessionId = sessionId,
    preRollEnabled = preRollEnabled,
    midRollDurationSeconds = midRollAdBreakDurationSeconds,
    skipAfterSeconds = midRollSkipAfterSeconds,
    adBreakActive = adBreakActive,
    adBreakStartedAt = adBreakStartedAt,
    totalAdBreaks = totalAdBreaks,
)

internal fun AdBreakOutDto.toDomain(): AdBreak = AdBreak(
    durationSeconds = durationSeconds,
    startedAt = startedAt,
    skipAfterSeconds = skipAfterSeconds,
)
