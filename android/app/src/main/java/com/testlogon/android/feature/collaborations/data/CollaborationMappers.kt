package com.testlogon.android.feature.collaborations.data

import com.testlogon.android.core.model.collaborations.CollabRevision
import com.testlogon.android.core.model.collaborations.CollabStatus
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.model.collaborations.SplitDistribution
import com.testlogon.android.core.network.collaborations.CollabSplitDistribution
import com.testlogon.android.core.network.collaborations.CollabSplitHistoryOut
import com.testlogon.android.core.network.collaborations.CollaborationListOut
import com.testlogon.android.core.network.collaborations.CollaborationOut
import com.testlogon.android.core.network.collaborations.CollaborationRevisionOut

/**
 * AND-358 / PAR-04 - DTO -> domain mappers for the collaborations surface.
 *
 * PLACEMENT: core-model has no dependency on core-network's DTOs (and core-network has no domain dep), so the
 * bridging mappers live here in the feature, which depends on BOTH (mirrors AND-356 SyndicateMappers).
 *
 * Key transforms: the id coalesces `collab_id` then `id`; `status` is kept RAW on the domain AND parsed via
 * [CollabStatus.from] (UNKNOWN fallback); `split` is a userId -> integer PERCENT (0-100) map kept verbatim
 * ([Collaboration.splitTotalsOk] is computed in-domain); created_at / updated_at stay Long epoch-seconds.
 * PAR-04 adds `last_proposed_by` (drives the awaiting-response action gate) + the revision-history mapper.
 */

/** The list envelope coalesces to `items` then `collaborations`; the cursor is normalized (blank -> null). */
fun CollaborationListOut.itemsOrEmpty(): List<CollaborationOut> = items ?: collaborations ?: emptyList()

/** The opaque next-page cursor; a blank cursor terminates pagination. */
fun CollaborationListOut.normalizedCursor(): String? = nextCursor?.takeIf { it.isNotBlank() }

/**
 * Maps a collaboration DTO to the domain [Collaboration]. The id coalesces `collab_id` -> `id` -> "" (a row
 * with neither is degenerate but never crashes). status is kept RAW and parsed to the enum; split percents are
 * kept verbatim; `last_proposed_by` (may be null) drives the negotiation action gate.
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

/**
 * Flattens the optional split history into a single list of [SplitDistribution]s (across all records). A null
 * percentage folds to 0; amount_cents stays nullable (rendered only when present).
 */
fun CollabSplitHistoryOut.toDistributions(): List<SplitDistribution> =
    records.orEmpty().flatMap { record -> record.distributions.orEmpty().map { it.toDomain() } }

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
