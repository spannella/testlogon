package com.testlogon.android.core.network.delegates

import com.squareup.moshi.Json

/**
 * AND-359 - transport DTOs for the delegate / delegation surface (manage-as-creator mode).
 *
 * CODEGEN NOTE (identical to AND-353 OrgDtos): core-network does NOT apply the Moshi KSP codegen plugin,
 * so these DTOs decode via the reflective KotlinJsonAdapterFactory registered on the shared Moshi in
 * NetworkModule.provideMoshi. The reflective factory maps Kotlin property names to JSON keys VERBATIM
 * (Moshi does NOT auto snake_case), so every wire key is pinned with an explicit @Json(name = ...).
 * @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * Optional fields are nullable with null defaults; the list field defaults to empty so a missing key does
 * not crash. Extra / unknown wire keys are tolerated leniently by the reflective adapter.
 *
 * WIRE CONTRACT (verified corrections - obey):
 *   GET ui/delegates/managed -> BARE ARRAY of ManagedCreatorOut (creators the current principal MAY
 *   manage). There is NO display_name / username / avatar_url on the row - the only human field is `label`.
 *
 * SCOPE NOTE: the fuller delegate-management surface (GET or POST ui/delegates, invites, settings,
 * presets, audit, the {delegate_id} sub-resources) is OPTIONAL / downstream. For AND-359 the REQUIRED
 * call is listManagedCreators; the optional invite DTOs below are modeled minimally for an invites
 * list-or-respond helper (kept off the critical path).
 */

/**
 * One creator the current principal MAY manage as a delegate. `creator_id` is required; `permissions` is
 * the list of granted permission tokens (defaults to empty). The remaining fields are optional metadata.
 * The ONLY human-readable field is `label` (there is intentionally NO display_name / username /
 * avatar_url on this row).
 */
data class ManagedCreatorOut(
    @Json(name = "creator_id") val creatorId: String,
    @Json(name = "permissions") val permissions: List<String> = emptyList(),
    @Json(name = "preset") val preset: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "label") val label: String? = null,
    @Json(name = "accepted_at") val acceptedAt: String? = null,
)

/**
 * AND-359 (OPTIONAL / downstream) - one pending delegate invite addressed to the current principal.
 * Modeled minimally so an invites list-or-respond helper can exist; it is NOT on the critical path (the
 * only REQUIRED call is listManagedCreators). `invite_id` and `creator_id` are required; the rest is
 * optional metadata.
 */
data class DelegateInviteOut(
    @Json(name = "invite_id") val inviteId: String,
    @Json(name = "creator_id") val creatorId: String,
    @Json(name = "permissions") val permissions: List<String> = emptyList(),
    @Json(name = "preset") val preset: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "label") val label: String? = null,
    @Json(name = "invited_by") val invitedBy: String? = null,
    @Json(name = "created_at") val createdAt: String? = null,
    @Json(name = "expires_at") val expiresAt: String? = null,
)

/**
 * AND-359 (OPTIONAL / downstream) - body for responding to a delegate invite. `accept` is required; the
 * server stays authoritative. Kept minimal and off the critical path.
 */
data class DelegateInviteRespondReq(
    @Json(name = "accept") val accept: Boolean,
)
