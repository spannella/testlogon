package com.testlogon.android.core.model.collaborations

/**
 * FIN-011 (Android) - PURE, framework-free logic for the collaboration revenue-splitting + dispute surface.
 *
 * This object mirrors the invariants the backend (app/services/collaboration_revenue.py) enforces server-side,
 * so the client can validate BEFORE a round-trip and gate which dispute affordances render. It has NO Android /
 * Moshi / Retrofit dependency - it is a plain JVM object with a companion JVM test.
 *
 * Two concerns:
 *  1. SPLIT-PERCENT VALIDATION. A collaboration `split` (and any proposed dispute split) is a userId -> integer
 *     PERCENT map. The percents MUST sum to exactly [FULL_SHARE_PERCENT] (100), each party MUST be in
 *     1..99 (a 0% or >=100% party is invalid), and there must be at least two parties. [validateSplit] returns
 *     a typed [SplitValidation] result (never throws) so the UI can show a precise reason.
 *
 *  2. DISPUTE-STATE GATING. A split record carries an optional `dispute_status` and each dispute carries a
 *     `status` string (free on the wire). [DisputeState.from] parses the token (UNKNOWN fallback, never
 *     throws); the gating helpers ([canFileDispute], [canResolveDispute]) decide which action is valid for a
 *     given viewer so the disputes panel never offers an illegal action.
 */
object CollaborationMath {

    /** The percent representing a full 100% share (a valid split sums to this). */
    const val FULL_SHARE_PERCENT = 100

    /** A single party's percent must be within these inclusive bounds (0 and >=100 are rejected). */
    const val MIN_PARTY_PCT = 1
    const val MAX_PARTY_PCT = 99

    /** The minimum number of parties in a valid two-party (or larger) split. */
    const val MIN_PARTIES = 2

    /**
     * Validates a userId -> integer PERCENT split map. Order of checks is deterministic (the FIRST failing rule
     * wins) so the surfaced reason is stable. Never throws.
     */
    fun validateSplit(split: Map<String, Int>): SplitValidation {
        if (split.size < MIN_PARTIES) return SplitValidation.TooFewParties(split.size)
        val offender = split.entries.firstOrNull { it.value < MIN_PARTY_PCT || it.value > MAX_PARTY_PCT }
        if (offender != null) return SplitValidation.PartyOutOfRange(offender.key, offender.value)
        val total = split.values.sum()
        if (total != FULL_SHARE_PERCENT) return SplitValidation.WrongTotal(total)
        return SplitValidation.Valid
    }

    /** Convenience: true only when [validateSplit] is [SplitValidation.Valid]. */
    fun isSplitValid(split: Map<String, Int>): Boolean = validateSplit(split) is SplitValidation.Valid

    /** The sum of all party percents (0 for an empty map). */
    fun splitTotal(split: Map<String, Int>): Int = split.values.sum()

    /**
     * The signed distance from a full 100% share (positive = over-allocated, negative = under-allocated,
     * 0 = exactly balanced). Useful for a "-15%" style UI hint next to an invalid split.
     */
    fun remainderToFull(split: Map<String, Int>): Int = splitTotal(split) - FULL_SHARE_PERCENT

    // ---- dispute-state gating ---------------------------------------------------------------------------

    /**
     * True when a NEW dispute may be filed on a split record. A dispute can be filed only when the viewer is a
     * participant AND the split is not already under an OPEN dispute. A record with no dispute (null / blank /
     * "none") is disputable; a [DisputeState.OPEN] record is NOT (one open dispute per split); a
     * [DisputeState.RESOLVED] record is NOT re-disputable.
     */
    fun canFileDispute(splitDisputeStatus: String?, isParticipant: Boolean): Boolean {
        if (!isParticipant) return false
        return when (DisputeState.from(splitDisputeStatus)) {
            DisputeState.NONE, DisputeState.UNKNOWN -> true
            DisputeState.OPEN, DisputeState.RESOLVED -> false
        }
    }

    /**
     * True when [viewerId] may RESOLVE the given dispute. Only an OPEN dispute is resolvable; an admin may
     * always arbitrate an open dispute; a participant may resolve an open dispute they did NOT file (the
     * counter-party accepts/rejects the proposed re-split). The filer can never self-resolve.
     */
    fun canResolveDispute(
        disputeStatus: String?,
        filedBy: String?,
        viewerId: String?,
        isAdmin: Boolean,
        isParticipant: Boolean,
    ): Boolean {
        if (DisputeState.from(disputeStatus) != DisputeState.OPEN) return false
        if (isAdmin) return true
        if (!isParticipant || viewerId.isNullOrBlank()) return false
        return viewerId != filedBy
    }
}

/**
 * The typed result of [CollaborationMath.validateSplit]. Sealed so the UI renders a mutually-exclusive reason.
 */
sealed interface SplitValidation {
    /** The split is well-formed: >=2 parties, each 1..99, summing to exactly 100. */
    data object Valid : SplitValidation

    /** Fewer than [CollaborationMath.MIN_PARTIES] parties. [count] is how many were supplied. */
    data class TooFewParties(val count: Int) : SplitValidation

    /** A party's percent is outside 1..99. [userId] / [percent] identify the offender. */
    data class PartyOutOfRange(val userId: String, val percent: Int) : SplitValidation

    /** The percents summed to [total] instead of 100. */
    data class WrongTotal(val total: Int) : SplitValidation

    /** True only for [Valid]. */
    val isValid: Boolean get() = this is Valid
}

/**
 * The parsed dispute state. The wire ships a FREE string, so any unrecognized token maps to [UNKNOWN] (never
 * throws). [from] tolerates null / blank (-> [NONE]) so a split record with no dispute is handled cleanly.
 */
enum class DisputeState {
    /** No dispute on the record (null / blank / "none"). */
    NONE,

    /** A dispute has been filed and is awaiting resolution ("open" / "disputed" / "pending"). */
    OPEN,

    /** The dispute has been resolved ("resolved" / "accepted" / "rejected" / "closed"). */
    RESOLVED,

    /** An unrecognized token (kept typed so the UI can still show the raw string). */
    UNKNOWN,
    ;

    /** True when the state represents an actively-open dispute. */
    val isOpen: Boolean get() = this == OPEN

    companion object {
        /** Parses a wire token; null / blank -> [NONE]; unrecognized -> [UNKNOWN]. Never throws. */
        fun from(wire: String?): DisputeState = when (wire?.trim()?.lowercase()) {
            null, "", "none" -> NONE
            "open", "disputed", "pending" -> OPEN
            "resolved", "accepted", "rejected", "closed" -> RESOLVED
            else -> UNKNOWN
        }
    }
}
