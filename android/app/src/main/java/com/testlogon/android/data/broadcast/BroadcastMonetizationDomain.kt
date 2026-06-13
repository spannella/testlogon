package com.testlogon.android.data.broadcast

import java.time.Instant

/**
 * AND-315 — DTO-free domain models for the host monetization surface (tip-config + private-show lifecycle).
 *
 * SCOPE: [TipConfig] is the SMALL backed model — exactly {tipsEnabled, minCents, maxCents}. It is NOT the
 * rich aspirational tip-menu/currency/goal-linkage model (no backend). All status / behavior / ended_by
 * strings are kept as raw strings or coerced to safe defaults; the mappers NEVER throw on shape variance.
 */

/**
 * The host's tip configuration. [minCents] / [maxCents] are null when the server has not set bounds (the
 * editor then seeds empty fields). Backed by {tip_enabled, tip_min_cents, tip_max_cents} on the session.
 */
data class TipConfig(
    val tipsEnabled: Boolean,
    val minCents: Long?,
    val maxCents: Long?,
)

/**
 * A pending (or in-progress) private-show request. Viewer identity is flat. [ratePerMinuteCents] is set by
 * the VIEWER (read-only to the host). [requestedAt] is parsed from an epoch-second int.
 */
data class PrivateShowRequest(
    val requestId: String,
    val privateSessionId: String?,
    val sessionId: String,
    val viewerId: String,
    val viewerDisplayName: String?,
    val ratePerMinuteCents: Long,
    val status: String,
    val maxDurationMinutes: Int?,
    val requestedAt: Instant?,
    val startedAt: Instant?,
)

/** An accepted / active private show (from the accept response). */
data class PrivateShowSession(
    val privateSessionId: String,
    val sessionId: String,
    val status: String,
    val behavior: String?,
    val callId: String?,
    val ratePerMinuteCents: Long,
    val startedAt: Instant?,
)

/** The authoritative end summary (server billing wins over the client estimate). */
data class PrivateShowSummary(
    val privateSessionId: String,
    val sessionId: String,
    val status: String,
    val durationSeconds: Int,
    val totalBilledCents: Long,
    val endedBy: String?,
)

/**
 * The host's current private-show status, used to rehydrate on screen start + fold into the poll loop.
 * Optional fields are absent when idle. [status] is the raw wire string (coerced into a [PrivateShowState]
 * by the ViewModel).
 */
data class PrivateStatus(
    val status: String,
    val requestId: String?,
    val privateSessionId: String?,
    val sessionId: String?,
    val viewerId: String?,
    val viewerDisplayName: String?,
    val ratePerMinuteCents: Long?,
    val behavior: String?,
    val callId: String?,
    val startedAt: Instant?,
)

// ---- mappers (pure; epoch-second -> Instant; never throw) ----

/** Extracts the SMALL tip-config from a full session (tipEnabled defaults to false when absent). */
internal fun BroadcastSession.toTipConfig(): TipConfig = TipConfig(
    tipsEnabled = tipEnabled ?: false,
    minCents = tipMinCents,
    maxCents = tipMaxCents,
)

internal fun PrivateRequestDto.toDomain(): PrivateShowRequest = PrivateShowRequest(
    requestId = requestId,
    privateSessionId = privateSessionId,
    sessionId = sessionId,
    viewerId = viewerId,
    viewerDisplayName = viewerDisplayName,
    ratePerMinuteCents = ratePerMinuteCents,
    status = status,
    maxDurationMinutes = maxDurationMinutes,
    requestedAt = requestedAt.epochSecondToInstant(),
    startedAt = startedAt.epochSecondToInstant(),
)

internal fun PrivateStatusDto.toDomain(): PrivateStatus = PrivateStatus(
    status = status,
    requestId = requestId,
    privateSessionId = privateSessionId,
    sessionId = sessionId,
    viewerId = viewerId,
    viewerDisplayName = viewerDisplayName,
    ratePerMinuteCents = ratePerMinuteCents,
    behavior = behavior,
    callId = callId,
    startedAt = startedAt.epochSecondToInstant(),
)

internal fun PrivateAcceptDto.toDomain(): PrivateShowSession = PrivateShowSession(
    privateSessionId = privateSessionId,
    sessionId = sessionId,
    status = status,
    behavior = behavior,
    callId = callId,
    ratePerMinuteCents = ratePerMinuteCents,
    startedAt = startedAt.epochSecondToInstant(),
)

internal fun PrivateSessionEndDto.toDomain(): PrivateShowSummary = PrivateShowSummary(
    privateSessionId = privateSessionId,
    sessionId = sessionId,
    status = status,
    durationSeconds = durationSeconds,
    totalBilledCents = totalBilledCents,
    endedBy = endedBy,
)
