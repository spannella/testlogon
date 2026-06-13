package com.testlogon.android.core.model.ads

/**
 * AND-364 - domain model + status enum for the CONTENT BOOST surface (paid post promotion).
 *
 * core-model has NO Moshi dependency: these are plain domain types. The wire DTO (core-network
 * ContentBoostOut) carries `status` as a raw String; [BoostStatus.from] parses that token into the typed
 * enum with an [BoostStatus.UNKNOWN] fallback so an unrecognized server status NEVER crashes the UI. The
 * raw status String is ALSO retained on [ContentBoost.status] (display / debugging) - we keep both.
 *
 * MONEY: every monetary field is a flat *_cents [Long] (overflow-proof). Currency is implicitly USD.
 * TIME: [endsAt] is an EPOCH-seconds [Long] (NOT an ISO string).
 */

/**
 * Typed lifecycle status of a boost, parsed from the free-form wire string. UNKNOWN is the forward-compat
 * fallback for any token the client does not recognize (it NEVER throws). Only [ACTIVE] is exercised by
 * the web client today (Cancel + refund are offered only while active).
 */
enum class BoostStatus {
    ACTIVE,
    PENDING,
    UNDER_REVIEW,
    REJECTED,
    COMPLETED,
    CANCELLED,
    UNKNOWN,
    ;

    /** True only for the running state in which spend accrues and Cancel/refund is offered. */
    val isActive: Boolean get() = this == ACTIVE

    companion object {
        /** Parses a wire token into a [BoostStatus]; null / unrecognized -> [UNKNOWN] (never throws). */
        fun from(wire: String?): BoostStatus = when (wire?.trim()?.lowercase()) {
            "active" -> ACTIVE
            "pending" -> PENDING
            "under_review", "under review", "in_review", "reviewing" -> UNDER_REVIEW
            "rejected" -> REJECTED
            "completed", "complete", "finished" -> COMPLETED
            "cancelled", "canceled" -> CANCELLED
            else -> UNKNOWN
        }
    }
}

/**
 * A content boost the caller created. Identity is [boostId]. [status] is the RAW wire string (kept for
 * display); [statusEnum] is the typed parse (UNKNOWN fallback). All money is *_cents [Long]; [endsAt] is
 * epoch seconds.
 */
data class ContentBoost(
    val boostId: String,
    val status: String,
    val statusEnum: BoostStatus,
    val budgetCents: Long,
    val spentCents: Long? = null,
    val remainingCents: Long? = null,
    val durationSeconds: Long? = null,
    val endsAt: Long? = null,
)

/** A lightweight spend snapshot for a boost (both fields optional flat *_cents Longs). */
data class BoostSpend(
    val spentCents: Long? = null,
    val remainingCents: Long? = null,
)

/** The outcome of cancelling an active boost. [refundedCents] is the amount returned to the wallet. */
data class BoostCancelResult(
    val boostId: String? = null,
    val status: String? = null,
    val refundedCents: Long? = null,
)
