package com.testlogon.android.feature.collaborations.data

import com.testlogon.android.core.model.collaborations.CollabStatus
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.model.collaborations.SplitDistribution
import com.testlogon.android.core.network.collaborations.CollabSplitDistribution
import com.testlogon.android.core.network.collaborations.CollabSplitHistoryOut
import com.testlogon.android.core.network.collaborations.CollaborationListOut
import com.testlogon.android.core.network.collaborations.CollaborationOut

/**
 * AND-358 - DTO -> domain mappers for the collaborations surface.
 *
 * PLACEMENT: core-model has no dependency on core-network's DTOs (and core-network has no domain dep), so the
 * bridging mappers live here in the feature, which depends on BOTH (mirrors AND-356 SyndicateMappers).
 *
 * Key transforms: the id coalesces `collab_id` then `id`; `status` is kept RAW on the domain AND parsed via
 * [CollabStatus.from] (UNKNOWN fallback); `split` is a userId -> integer PERCENT (0-100) map kept verbatim
 * ([Collaboration.splitTotalsOk] is computed in-domain); created_at / updated_at stay Long epoch-seconds.
 */

/** The list envelope coalesces to `items` then `collaborations`; the cursor is normalized (blank -> null). */
fun CollaborationListOut.itemsOrEmpty(): List<CollaborationOut> = items ?: collaborations ?: emptyList()

/** The opaque next-page cursor; a blank cursor terminates pagination. */
fun CollaborationListOut.normalizedCursor(): String? = nextCursor?.takeIf { it.isNotBlank() }

/**
 * Maps a collaboration DTO to the domain [Collaboration]. The id coalesces `collab_id` -> `id` -> "" (a row
 * with neither is degenerate but never crashes). status is kept RAW and parsed to the enum; split percents are
 * kept verbatim.
 */
fun CollaborationOut.toDomain(): Collaboration {
    val rawStatus = status.orEmpty()
    return Collaboration(
        id = (collabId ?: id).orEmpty(),
        title = title.orEmpty(),
        description = description,
        status = rawStatus,
        statusEnum = CollabStatus.from(rawStatus),
        initiatorId = initiatorId,
        recipientId = recipientId,
        split = split.orEmpty(),
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
