package com.testlogon.android.core.network.orgs

import com.squareup.moshi.Json

/**
 * AND-353 - transport DTOs for the organizations members/roles surface.
 *
 * CODEGEN NOTE (identical to AND-339 SigningDtos): core-network does NOT apply the Moshi KSP codegen
 * plugin, so these DTOs decode via the reflective KotlinJsonAdapterFactory registered on the shared
 * Moshi in NetworkModule.provideMoshi. The reflective factory maps Kotlin property names to JSON keys
 * VERBATIM (Moshi does NOT auto snake_case), so every wire key is pinned with an explicit
 * @Json(name = ...). @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * Optional fields are nullable with null defaults; required wire fields have NO default so a missing key
 * surfaces as a JsonDataException. Extra/unknown wire keys are tolerated leniently by the reflective
 * adapter.
 *
 * WIRE CONTRACT (OpenAPI-verified):
 *   GET    ui/orgs                              -> BARE ARRAY of OrgOut (NOT an {orgs:[]} envelope)
 *   GET    ui/orgs/{orgId}/members              -> BARE ARRAY of OrgMemberOut
 *   GET    ui/orgs/invites/pending              -> BARE ARRAY of OrgInviteOut
 *   POST   ui/orgs/{orgId}/members/invite       body OrgMemberInviteReq  -> 201 OrgInviteOut
 *   PATCH  ui/orgs/{orgId}/members/{memberSub}/role  body OrgMemberRoleUpdateReq -> 200
 *   DELETE ui/orgs/{orgId}/members/{memberSub}  -> 204 empty
 *   POST   ui/orgs/{orgId}/transfer-ownership   body TransferOwnershipReq -> 200/204
 *
 * IDENTITY NOTE: a member's identity on the wire is `user_sub`; there is NO display_name / email / id on
 * the member row (rows render user_sub - see the OrgMembersScreen open assumption).
 */

/**
 * One organization the caller belongs to. `org_id` is required; `org_role` is the CALLER's role in this
 * org (used for permission gating).
 */
data class OrgOut(
    @Json(name = "org_id") val orgId: String,
    @Json(name = "org_name") val orgName: String? = null,
    @Json(name = "org_role") val orgRole: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "created_at") val createdAt: String? = null,
)

/**
 * One member of an org. Identity is `user_sub` (there is NO display_name / email / id on this row).
 * `status` is kept as a raw String (the contract does not pin a confirmed enum of status values).
 */
data class OrgMemberOut(
    @Json(name = "user_sub") val userSub: String,
    @Json(name = "org_role") val orgRole: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "joined_at") val joinedAt: String? = null,
    @Json(name = "storage_used_bytes") val storageUsedBytes: Long? = null,
    @Json(name = "last_active_at") val lastActiveAt: String? = null,
)

/**
 * One PENDING invite (a separate resource from members). Returned both by the pending-invites list and
 * as the 201 body of the invite POST.
 */
data class OrgInviteOut(
    @Json(name = "invite_id") val inviteId: String,
    @Json(name = "org_id") val orgId: String? = null,
    @Json(name = "org_name") val orgName: String? = null,
    @Json(name = "email") val email: String,
    @Json(name = "org_role") val orgRole: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "invited_by") val invitedBy: String? = null,
    @Json(name = "created_at") val createdAt: String? = null,
    @Json(name = "expires_at") val expiresAt: String? = null,
    @Json(name = "token") val token: String? = null,
)

/**
 * Body for POST ui/orgs/{orgId}/members/invite. `email` is required (len 3..254). `org_role` is optional
 * (server default "member"); OWNER CANNOT be invited (server regex ^(admin|member|viewer)$).
 */
data class OrgMemberInviteReq(
    @Json(name = "email") val email: String,
    @Json(name = "org_role") val orgRole: String? = null,
)

/**
 * Body for PATCH ui/orgs/{orgId}/members/{memberSub}/role. `org_role` is required; promotion to OWNER is
 * NOT permitted here (server regex ^(admin|member|viewer)$). Ownership transfer is a separate endpoint.
 */
data class OrgMemberRoleUpdateReq(
    @Json(name = "org_role") val orgRole: String,
)

/** Body for POST ui/orgs/{orgId}/transfer-ownership. Modeled per the OpenAPI; no dedicated UI here. */
data class TransferOwnershipReq(
    @Json(name = "new_owner_user_sub") val newOwnerUserSub: String,
)
