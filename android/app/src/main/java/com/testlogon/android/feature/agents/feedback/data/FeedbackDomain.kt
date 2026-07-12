package com.testlogon.android.feature.agents.feedback.data

/**
 * AGENTS-BASICS (web-parity) - framework-free domain models for the FEEDBACK surface. Kept in feature/data (NOT
 * core-model, which cannot depend on core-network). Times are EPOCH SECONDS (0 -> null via the mapper).
 */

/** A feedback-request lifecycle status. UNKNOWN preserves an unrecognised server string for forward-compat. */
enum class FeedbackStatus(val wire: String) {
    PENDING("pending"),
    RESPONDED("responded"),
    SKIPPED("skipped"),
    TIMED_OUT("timed_out"),
    UNKNOWN("");

    companion object {
        fun from(wire: String): FeedbackStatus = entries.firstOrNull { it.wire == wire } ?: UNKNOWN
    }
}

/** One feedback request raised by a worker awaiting an operator response. */
data class FeedbackRequest(
    val requestId: String,
    val workerId: String,
    val ticketId: String,
    val status: FeedbackStatus,
    val statusWire: String,
    val question: String,
    val terminalContext: String,
    val detectedPattern: String,
    val responseText: String,
    val respondedAt: Long?,
    val timeoutAt: Long?,
    val timeoutAction: String,
    val createdAt: Long?,
) {
    /** Only a pending request can be responded to or skipped. */
    val isPending: Boolean get() = status == FeedbackStatus.PENDING
}
