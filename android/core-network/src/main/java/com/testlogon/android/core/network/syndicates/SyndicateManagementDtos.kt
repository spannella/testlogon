package com.testlogon.android.core.network.syndicates

import com.squareup.moshi.Json

/**
 * Transport DTOs for the syndicate MANAGEMENT surface (invites / join-requests / bundle plans / subscribe /
 * transfer-admin / audit). Mirrors app/routers/syndicates.py + app/models.py and the web contract in
 * frontend/src/api/endpoints/syndicates.ts.
 *
 * CODEGEN NOTE (identical to SyndicateDtos): core-network uses the reflective KotlinJsonAdapterFactory, so
 * every wire key is pinned with an explicit @Json(name = ...); @JsonClass(generateAdapter=true) is OMITTED.
 * Optional wire fields are nullable with null defaults; required fields have NO default. Extra keys are
 * tolerated.
 *
 * TIME: *_at / requested_at / ts are INTEGER epoch (Long). MONEY: price_cents is an Int.
 */

// ---- Invites ----

/** Body for POST ui/syndicates/{id}/invite (SyndicateInviteIn). */
data class SyndicateInviteIn(
    @Json(name = "user_id") val userId: String,
)

/** Body for POST ui/syndicates/{id}/invite/respond (SyndicateInviteRespondIn). */
data class SyndicateInviteRespondIn(
    @Json(name = "accept") val accept: Boolean,
)

/** One pending/answered invite row (SyndicateInviteOut). Bare array on GET ui/syndicates/invites. */
data class SyndicateInviteOut(
    @Json(name = "syndicate_id") val syndicateId: String,
    @Json(name = "syndicate_name") val syndicateName: String? = null,
    @Json(name = "user_id") val userId: String? = null,
    @Json(name = "invited_by") val invitedBy: String? = null,
    @Json(name = "invited_at") val invitedAt: Long? = 0,
    @Json(name = "status") val status: String? = null,
)

/** Response of POST ui/syndicates/{id}/invite/respond: {ok, status}. */
data class SyndicateInviteRespondOut(
    @Json(name = "ok") val ok: Boolean? = null,
    @Json(name = "status") val status: String? = null,
)

// ---- Join requests ----

/** Body for POST ui/syndicates/{id}/request (SyndicateJoinRequestIn). message defaults to "". */
data class SyndicateJoinRequestIn(
    @Json(name = "message") val message: String = "",
)

/** One join-request row (SyndicateRequestOut). Bare array on GET ui/syndicates/{id}/requests. */
data class SyndicateRequestOut(
    @Json(name = "syndicate_id") val syndicateId: String,
    @Json(name = "user_id") val userId: String? = null,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "requested_at") val requestedAt: Long? = 0,
    @Json(name = "message") val message: String? = null,
    @Json(name = "status") val status: String? = null,
)

/** Response of approve / reject / remove: {ok}. */
data class SyndicateOkOut(
    @Json(name = "ok") val ok: Boolean? = null,
)

// ---- Admin transfer ----

/** Body for POST ui/syndicates/{id}/transfer-admin (SyndicateTransferAdminIn). */
data class SyndicateTransferAdminIn(
    @Json(name = "new_admin_user_id") val newAdminUserId: String,
)

/** Response of transfer-admin (the SyndicateOut meta shape). */
data class SyndicateMetaOut(
    @Json(name = "syndicate_id") val syndicateId: String,
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "admin_user_id") val adminUserId: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "member_count") val memberCount: Int? = null,
    @Json(name = "created_at") val createdAt: Long? = 0,
    @Json(name = "updated_at") val updatedAt: Long? = 0,
)

// ---- Audit ----

/** One audit-log row (SyndicateAuditOut). Bare array on GET ui/syndicates/{id}/audit. */
data class SyndicateAuditOut(
    @Json(name = "event_id") val eventId: String? = null,
    @Json(name = "actor_id") val actorId: String? = null,
    @Json(name = "action") val action: String? = null,
    @Json(name = "target_id") val targetId: String? = null,
    @Json(name = "details") val details: Map<String, Any?>? = null,
    @Json(name = "ts") val ts: Long? = 0,
)

// ---- Bundle plans (SYND-002) ----

/** Body for POST ui/syndicates/{id}/plans (BundlePlanCreateIn). */
data class BundlePlanCreateIn(
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "price_cents") val priceCents: Int,
    @Json(name = "interval") val interval: String = "month",
)

/** Body for PUT ui/syndicates/{id}/plans/{planId} (BundlePlanUpdateIn). At least one field must be set. */
data class BundlePlanUpdateIn(
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "price_cents") val priceCents: Int? = null,
)

/** One bundle plan (BundlePlanOut). Bare array on GET ui/syndicates/{id}/plans. */
data class BundlePlanOut(
    @Json(name = "plan_id") val planId: String,
    @Json(name = "plan_type") val planType: String? = null,
    @Json(name = "syndicate_id") val syndicateId: String? = null,
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "price_cents") val priceCents: Int = 0,
    @Json(name = "interval") val interval: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "included_creator_ids") val includedCreatorIds: List<String>? = null,
    @Json(name = "current_members") val currentMembers: List<SyndicateMemberDto>? = null,
    @Json(name = "created_at") val createdAt: Long? = 0,
)

/** Response of DELETE ui/syndicates/{id}/plans/{planId}: {ok, plan_id, status}. */
data class ArchiveBundlePlanOut(
    @Json(name = "ok") val ok: Boolean? = null,
    @Json(name = "plan_id") val planId: String? = null,
    @Json(name = "status") val status: String? = null,
)

/** Body for POST ui/syndicates/{id}/plans/{planId}/subscribe (BundleSubscribeIn). */
data class BundleSubscribeIn(
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
)
