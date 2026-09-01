package com.testlogon.android.feature.syndicates.management

import com.testlogon.android.core.model.syndicates.MembershipStatus

/**
 * Framework-free domain models for the syndicate MANAGEMENT surface (invites / join-requests / bundle
 * plans / audit). Kept in the feature (NOT core-model) because core-model cannot depend on core-network.
 * Times are EPOCH SECONDS (Long); money is *_cents (Int).
 */

/** One pending/answered invite the caller has received, or that the admin has sent. */
data class SyndicateInvite(
    val syndicateId: String,
    val syndicateName: String,
    val userId: String,
    val invitedBy: String,
    val invitedAt: Long,
    val status: MembershipStatus,
)

/** One join-request awaiting an admin decision. */
data class JoinRequest(
    val syndicateId: String,
    val userId: String,
    val displayName: String,
    val requestedAt: Long,
    val message: String,
    val status: MembershipStatus,
)

/** One bundle plan authored by a syndicate admin. */
data class BundlePlan(
    val planId: String,
    val syndicateId: String,
    val name: String,
    val description: String,
    val priceCents: Int,
    val interval: String,
    val status: String,
    val includedCreatorIds: List<String>,
    val createdAt: Long,
) {
    val isActive: Boolean get() = status.equals("active", ignoreCase = true)
}

/** One audit-log entry. */
data class SyndicateAuditEntry(
    val eventId: String,
    val actorId: String,
    val action: String,
    val targetId: String,
    val ts: Long,
)

/** A minimal view of a subscription result (used to confirm a successful subscribe). */
data class SubscribeResult(
    val subscriptionId: String,
    val planId: String,
    val status: String,
)
