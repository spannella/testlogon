package com.testlogon.android.data.broadcast.tips

/**
 * AND-282 — broadcast tips + goals domain models (DTO-free). All amounts are integer cents; timestamps
 * are epoch SECONDS (Long). Goal progress math is pure/JVM-testable here. The server `reached` flag is
 * authoritative; the local current>=target comparison is only a fallback when the flag is absent.
 */
data class TipsSummary(
    val sessionId: String,
    val totalCents: Long,
    val tipCount: Int,
    val currency: String = "USD",
)

data class Goal(
    val goalId: String,
    val sessionId: String,
    val label: String,
    val currentCents: Long,
    val targetCents: Long,
    val reached: Boolean,
    val reachedAt: Long?,
    val sortOrder: Int,
) {
    /** Determinate progress fraction in [0f, 1f]; 0 for a non-positive target. */
    val fraction: Float
        get() = if (targetCents <= 0L) {
            0f
        } else {
            (currentCents.toFloat() / targetCents.toFloat()).coerceIn(0f, 1f)
        }

    /** Integer percentage 0..100 for display + a11y. */
    val percent: Int get() = (fraction * 100f).toInt().coerceIn(0, 100)

    /** Prefer the server flag; fall back to a local comparison only when the flag is false. */
    val isReached: Boolean get() = reached || (targetCents > 0L && currentCents >= targetCents)
}

/**
 * A submitted/echoed tip rendered as a chat message (BroadcastChatMessageOut). Not a dedicated Tip
 * object on the wire. `tipTotalCents` is the running session total at the time of the tip.
 */
data class TipMessage(
    val messageId: String,
    val tipAmountCents: Long?,
    val tipCurrency: String?,
    val tipTotalCents: Long?,
    val text: String?,
    val createdAtEpochSeconds: Long,
)

// ---- Mappers (DTO -> domain) ----

internal fun TipSummaryDto.toDomain(): TipsSummary = TipsSummary(
    sessionId = sessionId,
    totalCents = totalCents,
    tipCount = tipCount,
    currency = currency.ifBlank { "USD" },
)

internal fun TipGoalDto.toDomain(): Goal = Goal(
    goalId = goalId,
    sessionId = sessionId,
    label = label,
    currentCents = currentCents,
    targetCents = targetCents,
    reached = reached,
    reachedAt = reachedAt,
    sortOrder = sortOrder,
)

/** Maps + orders goals by sort_order, then created_at as a stable tiebreaker (FR-5 / R5). */
internal fun TipGoalsListDto.toDomain(): List<Goal> =
    goals.sortedWith(compareBy({ it.sortOrder }, { it.createdAt })).map { it.toDomain() }

internal fun TipMessageDto.toDomain(): TipMessage = TipMessage(
    messageId = messageId,
    tipAmountCents = tipAmountCents,
    tipCurrency = tipCurrency,
    tipTotalCents = tipTotalCents,
    text = text,
    createdAtEpochSeconds = createdAt,
)
