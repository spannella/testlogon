package com.testlogon.android.feature.syndicates.management

import com.testlogon.android.core.model.syndicates.SyndicateMath
import com.testlogon.android.core.network.syndicates.ArchiveBundlePlanOut
import com.testlogon.android.core.network.syndicates.BundlePlanOut
import com.testlogon.android.core.network.syndicates.BundleSubscriptionOut
import com.testlogon.android.core.network.syndicates.SyndicateAuditOut
import com.testlogon.android.core.network.syndicates.SyndicateInviteOut
import com.testlogon.android.core.network.syndicates.SyndicateRequestOut

/** DTO -> domain mappers for the syndicate MANAGEMENT surface (in :app; core-model has no core-network dep). */

fun SyndicateInviteOut.toDomain(): SyndicateInvite = SyndicateInvite(
    syndicateId = syndicateId,
    syndicateName = syndicateName?.takeIf { it.isNotBlank() } ?: syndicateId,
    userId = userId.orEmpty(),
    invitedBy = invitedBy.orEmpty(),
    invitedAt = invitedAt ?: 0L,
    status = SyndicateMath.membershipStatus(status),
)

fun SyndicateRequestOut.toDomain(): JoinRequest = JoinRequest(
    syndicateId = syndicateId,
    userId = userId.orEmpty(),
    displayName = displayName?.takeIf { it.isNotBlank() } ?: userId.orEmpty(),
    requestedAt = requestedAt ?: 0L,
    message = message.orEmpty(),
    status = SyndicateMath.membershipStatus(status),
)

fun BundlePlanOut.toDomain(): BundlePlan = BundlePlan(
    planId = planId,
    syndicateId = syndicateId.orEmpty(),
    name = name?.takeIf { it.isNotBlank() } ?: planId,
    description = description.orEmpty(),
    priceCents = priceCents,
    interval = interval?.takeIf { it.isNotBlank() } ?: "month",
    status = status?.takeIf { it.isNotBlank() } ?: "active",
    includedCreatorIds = includedCreatorIds ?: emptyList(),
    createdAt = createdAt ?: 0L,
)

fun SyndicateAuditOut.toDomain(): SyndicateAuditEntry = SyndicateAuditEntry(
    eventId = eventId.orEmpty(),
    actorId = actorId.orEmpty(),
    action = action.orEmpty(),
    targetId = targetId.orEmpty(),
    ts = ts ?: 0L,
)

fun BundleSubscriptionOut.toSubscribeResult(): SubscribeResult = SubscribeResult(
    subscriptionId = subscriptionId,
    planId = planId.orEmpty(),
    status = status?.takeIf { it.isNotBlank() } ?: "active",
)

fun ArchiveBundlePlanOut.toStatus(): String = status?.takeIf { it.isNotBlank() } ?: "archived"
