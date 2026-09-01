package com.testlogon.android.feature.collaborations.data

import com.testlogon.android.core.model.collaborations.CollabContent
import com.testlogon.android.core.model.collaborations.CollabDispute
import com.testlogon.android.core.model.collaborations.CollabRevision
import com.testlogon.android.core.model.collaborations.CollabSplitRecordModel
import com.testlogon.android.core.model.collaborations.CollabStatus
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.model.collaborations.CollaborationSettings
import com.testlogon.android.core.model.collaborations.SplitDistribution
import com.testlogon.android.core.network.collaborations.CollabContentItem
import com.testlogon.android.core.network.collaborations.CollabContentListOut
import com.testlogon.android.core.network.collaborations.CollabDisputeListOut
import com.testlogon.android.core.network.collaborations.CollabDisputeOut
import com.testlogon.android.core.network.collaborations.CollabSplitDistribution
import com.testlogon.android.core.network.collaborations.CollabSplitHistoryOut
import com.testlogon.android.core.network.collaborations.CollabSplitRecord
import com.testlogon.android.core.network.collaborations.CollaborationListOut
import com.testlogon.android.core.network.collaborations.CollaborationOut
import com.testlogon.android.core.network.collaborations.CollaborationRevisionOut
import com.testlogon.android.core.network.collaborations.CollaborationSettingsOut

/**
 * AND-358 / PAR-04 / FIN-011 - DTO -> domain mappers for the collaborations surface.
 *
 * PLACEMENT: core-model has no dependency on core-network's DTOs (and core-network has no domain dep), so the
 * bridging mappers live here in the feature, which depends on BOTH (mirrors AND-356 SyndicateMappers).
 *
 * Key transforms: the id coalesces `collab_id` then `id`; `status` is kept RAW on the domain AND parsed via
 * [CollabStatus.from] (UNKNOWN fallback); `split` is a userId -> integer PERCENT (0-100) map kept verbatim
 * ([Collaboration.splitTotalsOk] is computed in-domain); created_at / updated_at stay Long epoch-seconds.
 * PAR-04 adds `last_proposed_by` + the revision-history mapper. FIN-011 adds the split-record / content /
 * dispute / settings mappers.
 */

/** The list envelope coalesces to `items` then `collaborations`; the cursor is normalized (blank -> null). */
fun CollaborationListOut.itemsOrEmpty(): List<CollaborationOut> = items ?: collaborations ?: emptyList()

/** The opaque next-page cursor; a blank cursor terminates pagination. */
fun CollaborationListOut.normalizedCursor(): String? = nextCursor?.takeIf { it.isNotBlank() }

/**
 * Maps a collaboration DTO to the domain [Collaboration]. The id coalesces `collaboration_id` -> `collab_id`
 * -> `id` -> "" (a row with none is degenerate but never crashes). status is kept RAW and parsed to the enum;
 * split percents are kept verbatim; `last_proposed_by` (may be null) drives the negotiation action gate.
 */
fun CollaborationOut.toDomain(): Collaboration {
    val rawStatus = status.orEmpty()
    return Collaboration(
        id = (collaborationId ?: collabId ?: id).orEmpty(),
        title = title.orEmpty(),
        description = description,
        status = rawStatus,
        statusEnum = CollabStatus.from(rawStatus),
        initiatorId = initiatorId,
        recipientId = recipientId,
        split = split.orEmpty(),
        lastProposedBy = lastProposedBy,
        createdAt = createdAt,
        updatedAt = updatedAt,
    )
}

/** The split-history records coalesce `items` (real backend) then `records` (legacy). */
fun CollabSplitHistoryOut.recordsOrEmpty(): List<CollabSplitRecord> = items ?: records ?: emptyList()

/**
 * Flattens the split history into a single list of [SplitDistribution]s (across all records). A null
 * percentage folds to 0; amount_cents stays nullable (rendered only when present).
 */
fun CollabSplitHistoryOut.toDistributions(): List<SplitDistribution> =
    recordsOrEmpty().flatMap { record -> record.distributions.orEmpty().map { it.toDomain() } }

/** Maps the split history to the richer per-record domain model (FIN-011 revenue view). */
fun CollabSplitHistoryOut.toRecords(): List<CollabSplitRecordModel> = recordsOrEmpty().map { it.toDomain() }

/** Maps one split-record DTO to the domain model. The id coalesces `split_id` -> `record_id` -> "". */
fun CollabSplitRecord.toDomain(): CollabSplitRecordModel = CollabSplitRecordModel(
    splitId = (splitId ?: recordId).orEmpty(),
    contentId = contentId,
    contentType = contentType,
    grossAmountCents = grossAmountCents ?: 0,
    source = source,
    distributions = distributions.orEmpty().map { it.toDomain() },
    createdAt = createdAt,
    disputeStatus = disputeStatus,
)

/** Maps one split-distribution DTO to the domain [SplitDistribution]; a null percentage folds to 0. */
fun CollabSplitDistribution.toDomain(): SplitDistribution = SplitDistribution(
    userId = userId,
    percent = percentage ?: 0,
    amountCents = amountCents,
)

/**
 * PAR-04 - maps the revision-history ARRAY to the domain. A null `revision` folds to 0; the split map is kept
 * verbatim; `proposed_at` stays Long epoch-seconds. Newest-first is left to the server order.
 */
fun List<CollaborationRevisionOut>.toRevisions(): List<CollabRevision> = map { it.toDomain() }

/** Maps one revision DTO to the domain [CollabRevision]; a null revision number folds to 0. */
fun CollaborationRevisionOut.toDomain(): CollabRevision = CollabRevision(
    revision = revision ?: 0,
    split = split.orEmpty(),
    terms = termsText,
    proposedBy = proposedBy,
    proposedAt = proposedAt,
    status = status,
)

// ---- FIN-011: content / dispute / settings mappers --------------------------------------------------------

/** Maps the assigned-content envelope to the domain list. */
fun CollabContentListOut.toContent(): List<CollabContent> = items.orEmpty().map { it.toDomain() }

/** Maps one content DTO to the domain [CollabContent]; the id coalesces to "" when absent. */
fun CollabContentItem.toDomain(): CollabContent = CollabContent(
    contentId = contentId.orEmpty(),
    contentType = contentType.orEmpty(),
    title = title.orEmpty(),
    assignedBy = assignedBy,
    assignedAt = assignedAt,
    totalRevenueCents = totalRevenueCents ?: 0,
    splitCount = splitCount ?: 0,
)

/** Maps the disputes envelope to the domain list. */
fun CollabDisputeListOut.toDisputes(): List<CollabDispute> = items.orEmpty().map { it.toDomain() }

/** Maps one dispute DTO to the domain [CollabDispute]; ids / strings coalesce to "" when absent. */
fun CollabDisputeOut.toDomain(): CollabDispute = CollabDispute(
    disputeId = disputeId.orEmpty(),
    splitId = splitId.orEmpty(),
    collaborationId = collaborationId,
    filedBy = filedBy,
    reason = reason.orEmpty(),
    proposedSplit = proposedSplit,
    status = status.orEmpty(),
    resolution = resolution.orEmpty(),
    resolvedBy = resolvedBy.orEmpty(),
    resolvedAt = resolvedAt,
    createdAt = createdAt,
)

/**
 * Maps the settings DTO to the domain [CollaborationSettings]. A degraded (404 / empty) read leaves null
 * fields, which fold to the domain defaults so the form always renders.
 */
fun CollaborationSettingsOut.toDomain(): CollaborationSettings {
    val defaults = CollaborationSettings()
    return CollaborationSettings(
        acceptingRequests = acceptingRequests ?: defaults.acceptingRequests,
        minSplitPct = minSplitPct ?: defaults.minSplitPct,
        allowedContentTypes = allowedContentTypes ?: defaults.allowedContentTypes,
        autoExpireDays = autoExpireDays ?: defaults.autoExpireDays,
        updatedAt = updatedAt,
    )
}
