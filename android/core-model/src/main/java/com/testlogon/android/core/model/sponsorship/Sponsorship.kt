package com.testlogon.android.core.model.sponsorship

/**
 * AND-365 - domain model + status enum for the READ-ONLY sponsorship inbox (inbound brand deals).
 *
 * core-model has NO Moshi dependency: these are plain domain types. The wire DTO (core-network
 * SponsorshipDealDto) carries `status` as a raw String; [SponsorshipDealStatus.from] parses that token into
 * the typed enum with a [SponsorshipDealStatus.UNKNOWN] fallback so an unrecognized server status NEVER
 * crashes the UI (mirrors AND-364 BoostStatus). The RAW status String is ALSO retained on
 * [SponsorshipDeal.status] for display / debugging - we keep both.
 *
 * MONEY: [compensationCents] is a flat *_cents [Long] (overflow-proof). Currency is implicitly USD (no
 * currency field on the wire); format with
 * [com.testlogon.android.core.model.syndicates.formatCents] (REUSED).
 * TIME: [createdAt] is an EPOCH-seconds [Long] (relative-time at the UI). [deadline] is an ISO date STRING on
 * the wire (the web type ships `deadline: string`), kept verbatim here.
 *
 * The advertiser is the opaque [advertiserSub] subject id (rendered "From <sub>", no display-name lookup,
 * no avatar - neither is on the wire). READ-ONLY: there is NO read_at / unread state.
 */

/**
 * The lifecycle status of a sponsorship deal. The verified wire set is fixed
 * (proposed / negotiating / accepted / content_submitted / completed / rejected / cancelled); any
 * unrecognized token maps to [UNKNOWN] (never throws). The RAW status String is preserved on
 * [SponsorshipDeal] so the UI can still surface an unknown value verbatim.
 *
 * [group] buckets each status into the four client-side filter groups the web client uses:
 * Pending (proposed + negotiating), Active (accepted + content_submitted), Completed (completed) and
 * Cancelled (rejected + cancelled). UNKNOWN falls into [SponsorshipDealGroup.PENDING] so a forward-compat
 * status still surfaces in the default-visible bucket rather than vanishing.
 */
enum class SponsorshipDealStatus {
    PROPOSED,
    NEGOTIATING,
    ACCEPTED,
    CONTENT_SUBMITTED,
    COMPLETED,
    REJECTED,
    CANCELLED,
    UNKNOWN,
    ;

    /** The client-side filter bucket this status belongs to (UNKNOWN -> PENDING, never hidden). */
    val group: SponsorshipDealGroup
        get() = when (this) {
            PROPOSED, NEGOTIATING, UNKNOWN -> SponsorshipDealGroup.PENDING
            ACCEPTED, CONTENT_SUBMITTED -> SponsorshipDealGroup.ACTIVE
            COMPLETED -> SponsorshipDealGroup.COMPLETED
            REJECTED, CANCELLED -> SponsorshipDealGroup.CANCELLED
        }

    companion object {
        /** Parses a wire token into a [SponsorshipDealStatus]; null / unrecognized -> [UNKNOWN]. */
        fun from(wire: String?): SponsorshipDealStatus = when (wire?.trim()?.lowercase()) {
            "proposed" -> PROPOSED
            "negotiating" -> NEGOTIATING
            "accepted" -> ACCEPTED
            "content_submitted" -> CONTENT_SUBMITTED
            "completed" -> COMPLETED
            "rejected" -> REJECTED
            "cancelled", "canceled" -> CANCELLED
            else -> UNKNOWN
        }
    }
}

/**
 * The four client-side filter buckets (plus an implicit "all" handled at the feature layer). The web client
 * groups the seven statuses this way; the inbox filter chips map to these groups, applied CLIENT-SIDE over
 * the in-memory list.
 */
enum class SponsorshipDealGroup {
    PENDING,
    ACTIVE,
    COMPLETED,
    CANCELLED,
}

/**
 * One inbound sponsorship deal. Identity is [dealId]. [status] is the RAW wire string (kept for display);
 * [statusEnum] is the typed parse (UNKNOWN fallback). [compensationCents] is a flat *_cents [Long] (implicit
 * USD); [deadline] is the ISO date string from the wire; [createdAt] is epoch seconds.
 */
data class SponsorshipDeal(
    val dealId: String,
    val advertiserSub: String? = null,
    val brief: String? = null,
    val status: String,
    val statusEnum: SponsorshipDealStatus,
    val compensationCents: Long? = null,
    val deadline: String? = null,
    val createdAt: Long? = null,
)
