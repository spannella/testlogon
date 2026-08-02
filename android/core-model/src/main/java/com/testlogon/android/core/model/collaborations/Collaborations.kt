package com.testlogon.android.core.model.collaborations

/**
 * AND-358 / PAR-04 - domain model + status enum for the collaborations surface (a two-party revenue-sharing
 * agreement).
 *
 * core-model has NO Moshi dependency: these are plain domain types. The wire DTOs (core-network
 * CollaborationDtos) carry `status` as a raw String; [CollabStatus.from] parses that token into the typed enum
 * with a [CollabStatus.UNKNOWN] fallback so an unrecognized status NEVER crashes the UI (mirrors AND-356
 * SplitMode). Because the wire status set is NOT pinned, the RAW status String is ALSO kept on the domain.
 *
 * SPLIT: `split` is a userId -> integer PERCENT map (0-100, NOT basis points). [Collaboration.splitTotalsOk]
 * is true when the percents sum to exactly 100; a non-100 total drives a NON-blocking warning at the UI (it
 * does NOT fail the screen). The viewer's own share is [Collaboration.shareFor] (split[viewerId]).
 *
 * PAR-04 (deal actions): the negotiation gating helpers ([Collaboration.awaitingResponse], [isPendingProposal],
 * [isActiveAgreement], [isInitiator]) mirror the iOS CollaborationDetailScreen actionsCard. The state-only
 * mutations (accept / reject / counter / cancel / terminate) are NOT money-bearing.
 *
 * MONEY: the optional split-history distributions carry *_cents (Int) amounts; format with
 * [com.testlogon.android.core.model.syndicates.formatCents] (REUSED from AND-356).
 *
 * ROOM: persistence across process death is DEFERRED - the list is a network Paging-3 source and the detail
 * keeps an in-memory last-good snapshot with an isStale flag. No Room cache / migration this wave.
 */

/**
 * The collaboration status. The wire ships a FREE string, so any unrecognized token maps to [UNKNOWN] (never
 * throws). The known tokens here are best-effort; the RAW status String is preserved on [Collaboration] so the
 * UI can still surface an unknown value verbatim.
 */
enum class CollabStatus {
    PROPOSED,
    NEGOTIATING,
    ACTIVE,
    COMPLETED,
    CANCELLED,
    DECLINED,
    UNKNOWN,
    ;

    companion object {
        /** Parses a wire token into a [CollabStatus]; null / unknown -> [UNKNOWN] (never throws). */
        fun from(wire: String?): CollabStatus = when (wire?.trim()?.lowercase()) {
            "proposed", "pending" -> PROPOSED
            "negotiating", "counter", "countered" -> NEGOTIATING
            "active", "accepted" -> ACTIVE
            "completed", "complete" -> COMPLETED
            "cancelled", "canceled" -> CANCELLED
            "declined", "rejected" -> DECLINED
            else -> UNKNOWN
        }
    }
}

/**
 * One collaboration (a two-party agreement between [initiatorId] and [recipientId]).
 *
 * [status] is the RAW wire string (may be blank); [statusEnum] is the typed parse (UNKNOWN fallback).
 * [split] is a userId -> integer PERCENT (0-100) map. [createdAt] / [updatedAt] stay Long epoch-seconds
 * (relative-time at the UI). [splitTotalsOk] is true ONLY when the percents sum to exactly [FULL_SHARE_PERCENT]
 * (100); a non-100 total drives a non-blocking UI warning (it never fails the screen).
 *
 * [lastProposedBy] is the party who last proposed / countered (drives the awaiting-response gate); when absent
 * the FIRST proposal convention applies (the recipient responds). Mirrors the iOS Collaboration DTO.
 */
data class Collaboration(
    val id: String,
    val title: String,
    val description: String? = null,
    val status: String,
    val statusEnum: CollabStatus,
    val initiatorId: String? = null,
    val recipientId: String? = null,
    val split: Map<String, Int> = emptyMap(),
    val lastProposedBy: String? = null,
    val createdAt: Long? = null,
    val updatedAt: Long? = null,
) {
    /** The sum of all party percents (0 when there are no split rows). */
    val splitTotalPercent: Int get() = split.values.sum()

    /** True when the split percents sum to EXACTLY 100. A false value is a NON-blocking warning at the UI. */
    val splitTotalsOk: Boolean get() = splitTotalPercent == FULL_SHARE_PERCENT

    /** The split rows as ordered [SplitShare]s (one per party in the `split` map). */
    val shares: List<SplitShare> get() = split.entries.map { SplitShare(it.key, it.value) }

    /** The viewer's own percent share when present in the split map, else null. */
    fun shareFor(viewerId: String?): Int? = viewerId?.let { split[it] }

    /** True when the agreement is still a live proposal awaiting a first response (status proposed/pending). */
    val isPendingProposal: Boolean get() = statusEnum == CollabStatus.PROPOSED

    /** True when the agreement is being negotiated (a counter-offer is on the table). */
    val isNegotiating: Boolean get() = statusEnum == CollabStatus.NEGOTIATING

    /** True when the agreement is live (accepted / active). Only an active agreement can be terminated. */
    val isActiveAgreement: Boolean get() = statusEnum == CollabStatus.ACTIVE

    /** True when [viewerId] is the agreement initiator (the only party who can cancel a pending request). */
    fun isInitiator(viewerId: String?): Boolean = viewerId != null && viewerId == initiatorId

    /**
     * True when [viewerId] is the participant who must respond to the current proposal (accept / reject /
     * counter). Only meaningful while proposed or negotiating: the party who did NOT last propose responds;
     * on the FIRST proposal (no [lastProposedBy]) the recipient responds. Mirrors iOS awaitingResponse(from:).
     */
    fun awaitingResponse(viewerId: String?): Boolean {
        if (viewerId == null || !(isPendingProposal || isNegotiating)) return false
        val lastBy = lastProposedBy?.takeIf { it.isNotBlank() }
        return if (lastBy != null) lastBy != viewerId else recipientId == viewerId
    }

    companion object {
        /** The percent representing a full 100% share (the split rows should sum to this). */
        const val FULL_SHARE_PERCENT = 100
    }
}

/** One party's revenue share: [userId] -> [percent] (integer 0-100). */
data class SplitShare(
    val userId: String,
    val percent: Int,
)

/**
 * One per-party distribution from the optional split history. [percent] is the party's integer percent;
 * [amountCents] is the disbursed amount in minor units (Int, formatted with formatCents when present).
 */
data class SplitDistribution(
    val userId: String? = null,
    val percent: Int = 0,
    val amountCents: Int? = null,
)

/**
 * PAR-04 - one prior negotiation revision (GET ui/collaborations/{id}/revisions). Each revision records the
 * proposed [split] at that step, who proposed it ([proposedBy]) and when ([proposedAt], epoch-seconds), plus
 * the revision's [status] (typically "superseded" for historical rows). [terms] is an optional free note.
 */
data class CollabRevision(
    val revision: Int,
    val split: Map<String, Int> = emptyMap(),
    val terms: String? = null,
    val proposedBy: String? = null,
    val proposedAt: Long? = null,
    val status: String? = null,
) {
    /** The revision's split rows as ordered [SplitShare]s. */
    val shares: List<SplitShare> get() = split.entries.map { SplitShare(it.key, it.value) }
}
