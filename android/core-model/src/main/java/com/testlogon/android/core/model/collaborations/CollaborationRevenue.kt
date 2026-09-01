package com.testlogon.android.core.model.collaborations

/**
 * FIN-011 (Android) - domain types for the collaboration REVENUE-SPLITTING + DISPUTE surface (the read/write
 * layer on top of the AND-358 two-party agreement). Framework-free (no Moshi / Android): the wire DTOs live in
 * core-network (CollaborationDtos) and the feature maps DTO -> these.
 *
 * These mirror the backend models (app/models.py CollabContentItem / CollabSplitRecord / CollabDisputeOut /
 * CollaborationSettingsOut) and the web types (frontend/src/api/types.ts). *_cents amounts are minor units
 * (Int), formatted with [com.testlogon.android.core.model.syndicates.formatCents]. Epoch fields are Long
 * epoch-seconds.
 */

/**
 * One piece of content assigned to a collaboration (auto-splits its revenue events per the agreement).
 * [totalRevenueCents] is the running gross this content has generated inside the collaboration.
 */
data class CollabContent(
    val contentId: String,
    val contentType: String,
    val title: String = "",
    val assignedBy: String? = null,
    val assignedAt: Long? = null,
    val totalRevenueCents: Int = 0,
    val splitCount: Int = 0,
)

/**
 * One executed split record (a revenue event that was split across the parties). [distributions] is the
 * per-party breakdown; [disputeStatus] (free wire string) drives the disputes gating via
 * [CollaborationMath.canFileDispute] / [DisputeState.from].
 */
data class CollabSplitRecordModel(
    val splitId: String,
    val contentId: String? = null,
    val contentType: String? = null,
    val grossAmountCents: Int = 0,
    val source: String? = null,
    val distributions: List<SplitDistribution> = emptyList(),
    val createdAt: Long? = null,
    val disputeStatus: String? = null,
) {
    /** The parsed dispute state (NONE / OPEN / RESOLVED / UNKNOWN) for gating. */
    val disputeState: DisputeState get() = DisputeState.from(disputeStatus)

    /** True when this split is currently under an open dispute. */
    val isDisputed: Boolean get() = disputeState.isOpen
}

/**
 * One dispute filed against a split record. [proposedSplit] is the re-split the filer proposes (optional);
 * [status] (free wire string) is parsed via [DisputeState.from]. The resolution fields are populated once the
 * counter-party or an admin resolves it.
 */
data class CollabDispute(
    val disputeId: String,
    val splitId: String,
    val collaborationId: String? = null,
    val filedBy: String? = null,
    val reason: String = "",
    val proposedSplit: Map<String, Int>? = null,
    val status: String = "",
    val resolution: String = "",
    val resolvedBy: String = "",
    val resolvedAt: Long? = null,
    val createdAt: Long? = null,
) {
    /** The parsed dispute state for gating / labelling. */
    val state: DisputeState get() = DisputeState.from(status)

    /** True while the dispute is still open (awaiting resolution). */
    val isOpen: Boolean get() = state.isOpen
}

/**
 * The viewer's collaboration inbound-request settings (GET/PUT ui/collaborations/settings). All fields have
 * safe defaults so a degraded (404 / empty) read renders a sensible form. [minSplitPct] is the smallest split
 * the viewer will accept from an inbound proposal (1..99); [autoExpireDays] auto-declines stale requests.
 */
data class CollaborationSettings(
    val acceptingRequests: Boolean = true,
    val minSplitPct: Int = 1,
    val allowedContentTypes: List<String> = listOf("broadcast", "post", "vod"),
    val autoExpireDays: Int = 7,
    val updatedAt: Long? = null,
)
