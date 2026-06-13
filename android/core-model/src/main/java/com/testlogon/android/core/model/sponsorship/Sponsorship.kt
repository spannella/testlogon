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

    /**
     * AND-366 - true for a TERMINAL status (the deal-detail screen is then READ-ONLY: a status banner, NO
     * actions). The actionable statuses are exactly proposed / negotiating; everything else (including UNKNOWN,
     * which never offers actions) is treated as terminal for the read-only banner.
     */
    val isTerminal: Boolean
        get() = this != PROPOSED && this != NEGOTIATING

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

/**
 * AND-366 - the FULL sponsorship deal (the detail screen's subject). A SUPERSET of the inbox row
 * [SponsorshipDeal] (it adds [creatorSub], [deliverables], [cpmBonusCents], [platformCommissionBps],
 * [contentId] and a [hasPaymentDetails] presence flag) - kept SEPARATE so the lean inbox row stays untouched.
 *
 * Identity is [dealId]. [status] is the RAW wire string (kept for display); [statusEnum] is the typed parse
 * (UNKNOWN fallback). [compensationCents] + [cpmBonusCents] are flat *_cents [Long] (implicit USD, format with
 * [com.testlogon.android.core.model.syndicates.formatCents]); [platformCommissionBps] is basis points;
 * [deadline] is the ISO date STRING from the wire (NOT epoch). The deal does NOT embed offers[] - the
 * negotiation history is the separate [SponsorshipDealEvent] list.
 */
data class SponsorshipDealDetail(
    val dealId: String,
    val advertiserSub: String? = null,
    val creatorSub: String? = null,
    val brief: String? = null,
    val status: String,
    val statusEnum: SponsorshipDealStatus,
    val compensationCents: Long? = null,
    val deliverables: List<String> = emptyList(),
    val deadline: String? = null,
    val cpmBonusCents: Long? = null,
    val platformCommissionBps: Int? = null,
    val contentId: String? = null,
    val hasPaymentDetails: Boolean = false,
)

/**
 * AND-366 - one negotiation / lifecycle event from the deal history. Identity is [eventId]. [eventType] is the
 * raw wire kind (e.g. "countered" / "accepted"); [actorSub] is who acted; [detailsText] is the OPAQUE payload
 * flattened to a single display string (the wire ships either an object map OR a plain string - both are
 * stringified by the mapper, never schema-parsed); [createdAt] is an EPOCH [Long].
 */
data class SponsorshipDealEvent(
    val eventId: String,
    val eventType: String? = null,
    val actorSub: String? = null,
    val detailsText: String? = null,
    val createdAt: Long? = null,
)

/**
 * AND-366 - the viewer's role on a deal, derived CLIENT-SIDE by comparing the current user's sub to the deal's
 * advertiser_sub vs creator_sub (there is NO viewerRole field on the wire). [OBSERVER] covers a blank current
 * sub or a sub that matches neither party. This gating is UX-only; the server is authoritative on every
 * mutation.
 */
enum class ViewerRole {
    ADVERTISER,
    CREATOR,
    OBSERVER,
    ;

    companion object {
        /** Derives the role from [currentSub] vs the deal's [advertiserSub] / [creatorSub]. */
        fun derive(
            currentSub: String?,
            advertiserSub: String?,
            creatorSub: String?,
        ): ViewerRole {
            val sub = currentSub?.trim().orEmpty()
            if (sub.isEmpty()) return OBSERVER
            return when (sub) {
                advertiserSub?.trim() -> ADVERTISER
                creatorSub?.trim() -> CREATOR
                else -> OBSERVER
            }
        }
    }
}

/**
 * AND-366 - a management action on a deal. ACCEPT and NEGOTIATE (counter-offer) plus REJECT (the backlog's
 * "decline" - the wire verb is reject, NOT decline).
 */
enum class DealAction {
    ACCEPT,
    REJECT,
    NEGOTIATE,
}

/**
 * AND-366 - the set of management actions available CLIENT-SIDE for a deal. Pure (no I/O). Actions are offered
 * ONLY in the actionable statuses {proposed, negotiating}; every terminal state
 * (accepted / content_submitted / completed / rejected / cancelled) and UNKNOWN yields the EMPTY set (a
 * read-only status banner, NO actions). The full {ACCEPT, REJECT, NEGOTIATE} set is offered to BOTH parties
 * in an actionable status (either party may accept the current terms, walk away, or counter); an OBSERVER gets
 * nothing. The server remains authoritative - this only drives which affordances render.
 */
fun availableActions(status: SponsorshipDealStatus, role: ViewerRole): Set<DealAction> {
    if (role == ViewerRole.OBSERVER) return emptySet()
    return when (status) {
        SponsorshipDealStatus.PROPOSED,
        SponsorshipDealStatus.NEGOTIATING,
        -> setOf(DealAction.ACCEPT, DealAction.REJECT, DealAction.NEGOTIATE)

        SponsorshipDealStatus.ACCEPTED,
        SponsorshipDealStatus.CONTENT_SUBMITTED,
        SponsorshipDealStatus.COMPLETED,
        SponsorshipDealStatus.REJECTED,
        SponsorshipDealStatus.CANCELLED,
        SponsorshipDealStatus.UNKNOWN,
        -> emptySet()
    }
}
