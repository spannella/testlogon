package com.testlogon.android.feature.syndicates.data

import com.testlogon.android.core.model.syndicates.LicensingContentType
import com.testlogon.android.core.model.syndicates.OpenLicensingContent
import com.testlogon.android.core.model.syndicates.RegistrationResult
import com.testlogon.android.core.model.syndicates.RevenueSplitPolicy
import com.testlogon.android.core.model.syndicates.SplitMode
import com.testlogon.android.core.model.syndicates.SyndicateFeedItem
import com.testlogon.android.core.model.syndicates.SyndicateMember
import com.testlogon.android.core.model.syndicates.SyndicateListItem
import com.testlogon.android.core.model.syndicates.SyndicateOverview
import com.testlogon.android.core.model.syndicates.TreasuryEntry
import com.testlogon.android.core.model.syndicates.TreasurySummary
import com.testlogon.android.core.network.syndicates.SplitConfigOut
import com.testlogon.android.core.network.syndicates.SyndicateOpenLicensingContentOut
import com.testlogon.android.core.network.syndicates.SyndicateOpenLicensingRegistrationOut
import com.testlogon.android.core.network.syndicates.SyndicateMemberDto
import com.testlogon.android.core.network.syndicates.SyndicatePostOut
import com.testlogon.android.core.network.syndicates.SyndicateCreateOut
import com.testlogon.android.core.network.syndicates.SyndicateListItemDto
import com.testlogon.android.core.network.syndicates.SyndicateProfileOut
import com.testlogon.android.core.network.syndicates.SyndicateTreasuryLedgerEntryOut
import com.testlogon.android.core.network.syndicates.SyndicateTreasuryOut
import java.util.Locale

/**
 * AND-356 - DTO -> domain mappers for the syndicate-overview surface.
 *
 * PLACEMENT: core-model has no dependency on core-network's DTOs (and core-network has no domain dep), so
 * the bridging mappers live here in the feature, which depends on BOTH (mirrors AND-355 GroupMappers).
 *
 * Key transforms: `currency` is UPPER-cased (the wire ships lowercase ISO; NumberFormat wants the ISO-4217
 * upper form); `mode` is parsed via [SplitMode.from] (UNKNOWN fallback); created_at / ts stay Long epoch;
 * the role badge is DERIVED here from `admin_user_id` == the supplied current userId (there is NO
 * viewer_role field on the wire).
 */

private const val FALLBACK_CURRENCY = "USD"

/** Batch-7 - maps a syndicate list-row DTO to the domain [SyndicateListItem] (id = syndicate_id). */
fun SyndicateListItemDto.toDomain(): SyndicateListItem = SyndicateListItem(
    id = syndicateId,
    name = syndicateName.orEmpty(),
    role = role,
    joinedAt = joinedAt,
)

/** Batch-7 - maps a create receipt to a [SyndicateListItem] (creator is admin) for immediate nav. */
fun SyndicateCreateOut.toListItem(): SyndicateListItem = SyndicateListItem(
    id = syndicateId,
    name = name.orEmpty(),
    role = "admin",
)

/**
 * Maps the profile DTO to the domain [SyndicateOverview]. [currentUserId] is the viewer's own user id, used
 * to derive the admin role badge (admin when admin_user_id == currentUserId). A blank/absent currency falls
 * back to USD so the money formatter always has a code; is_member defaults to true when the wire omits it.
 */
fun SyndicateProfileOut.toDomain(currentUserId: String?): SyndicateOverview = SyndicateOverview(
    id = id,
    name = name,
    memberCount = memberCount,
    isAdmin = adminUserId != null && currentUserId != null && adminUserId == currentUserId,
    isMember = isMember ?: true,
    currency = (currency?.takeIf { it.isNotBlank() } ?: FALLBACK_CURRENCY).uppercase(Locale.ROOT),
)

/** Maps a feed-post DTO to the domain [SyndicateFeedItem]; created_at stays a Long epoch. */
fun SyndicatePostOut.toDomain(): SyndicateFeedItem = SyndicateFeedItem(
    postId = postId,
    authorName = authorName,
    authorAvatarUrl = authorAvatarUrl,
    createdAt = createdAt,
    text = text,
    imageUrl = imageUrl,
    reactionCount = reactionCount,
    commentCount = commentCount,
    tipCount = tipCount,
)

/** Maps the treasury DTO's summary fields to the domain [TreasurySummary] (currency upper-cased). */
fun SyndicateTreasuryOut.toSummary(): TreasurySummary = TreasurySummary(
    balanceCents = balanceCents,
    depositedCents = totalDepositedCents,
    disbursedCents = totalDisbursedCents,
    currency = (currency?.takeIf { it.isNotBlank() } ?: FALLBACK_CURRENCY).uppercase(Locale.ROOT),
)

/** Maps a ledger-entry DTO to the domain [TreasuryEntry]; direction kept raw, ts stays a Long epoch. */
fun SyndicateTreasuryLedgerEntryOut.toDomain(): TreasuryEntry = TreasuryEntry(
    entryId = entryId,
    direction = direction.orEmpty(),
    amountCents = amountCents,
    reason = reason,
    ts = ts,
    counterpartyUserId = counterpartyUserId,
)

/**
 * Maps the split-config DTO to the domain [RevenueSplitPolicy]; `mode` via [SplitMode.from] (UNKNOWN
 * fallback). [RevenueSplitPolicy.weightSumOk] is computed in the domain type (weighted-only check).
 */
fun SplitConfigOut.toDomain(): RevenueSplitPolicy = RevenueSplitPolicy(
    mode = SplitMode.from(mode),
    platformFeeBps = platformFeeBps,
    performanceMetric = performanceMetric,
    performanceWindowDays = performanceWindowDays,
    updatedAt = updatedAt,
    updatedBy = updatedBy,
    weightsBps = weightsBps.orEmpty(),
)

// ---- AND-357: open-licensing mappers ----

/**
 * AND-357 - maps an open-licensing content-row DTO to the domain [OpenLicensingContent]. content_type via
 * [LicensingContentType.from] (UNKNOWN fallback); exempt defaults false; registered_at stays a Long epoch.
 */
fun SyndicateOpenLicensingContentOut.toDomain(): OpenLicensingContent = OpenLicensingContent(
    contentId = contentId,
    contentType = LicensingContentType.from(contentType),
    creatorId = creatorId,
    exempt = exempt ?: false,
    registeredAt = registeredAt,
)

/**
 * AND-357 - maps the register-content receipt DTO to the domain [RegistrationResult]; a null
 * licenses_created folds to 0.
 */
fun SyndicateOpenLicensingRegistrationOut.toDomain(): RegistrationResult = RegistrationResult(
    contentId = contentId,
    licensesCreated = licensesCreated ?: 0,
)

/** Batch-9 (#12) - maps a [SyndicateMemberDto] to the domain [SyndicateMember]. */
fun SyndicateMemberDto.toDomain(): SyndicateMember = SyndicateMember(
    userId = userId,
    displayName = displayName?.takeIf { it.isNotBlank() } ?: userId,
    role = role?.takeIf { it.isNotBlank() } ?: "member",
    joinedAt = joinedAt ?: 0,
)
