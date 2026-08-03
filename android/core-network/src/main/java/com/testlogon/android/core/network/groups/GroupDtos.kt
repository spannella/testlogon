package com.testlogon.android.core.network.groups

import com.squareup.moshi.Json

/**
 * AND-355 - transport DTOs for the SOCIAL GROUPS surface (distinct from messaging group chats).
 *
 * CODEGEN NOTE (identical to AND-353 OrgDtos): core-network does NOT apply the Moshi KSP codegen plugin,
 * so these DTOs decode via the reflective KotlinJsonAdapterFactory registered on the shared Moshi in
 * NetworkModule.provideMoshi. The reflective factory maps Kotlin property names to JSON keys VERBATIM
 * (Moshi does NOT auto snake_case), so every wire key is pinned with an explicit @Json(name = ...).
 * @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * Optional fields are nullable with null defaults; required wire fields have NO default so a missing key
 * surfaces as a JsonDataException. Extra/unknown wire keys are tolerated leniently by the reflective
 * adapter.
 *
 * WIRE CONTRACT (OpenAPI / frontend-verified - ENVELOPE responses, NOT bare arrays):
 *   GET    ui/groups                                   -> ENVELOPE {groups: UserGroupDto[]}
 *   GET    ui/groups/{groupId}                         -> a UserGroupDto detail object
 *   GET    ui/groups/{groupId}/members                 -> ENVELOPE {members: GroupMemberDto[], count: int}
 *   POST   ui/groups/{groupId}/invite        body GroupInviteIn     -> invitee becomes status="invited"
 *   PATCH  ui/groups/{groupId}/members/{userId}/role  body GroupUpdateRoleIn (moderator|member) -> 200
 *   DELETE ui/groups/{groupId}/members/{userId}        -> 200
 *   POST   ui/groups/{groupId}/leave                   (NO body) -> 200
 *
 * ROLE NOTE: my_role is admin|moderator|member on the wire - there is NO owner role; the owner is
 * identified by admin_user_id. The typed GroupRole enum + UNKNOWN fallback lives in core-model.
 *
 * IDENTITY NOTE: a member's identity is `user_id`; the row carries display_name (NO username, NO
 * avatar_url). `status` is kept raw (a member with status=="invited" is a PENDING entry).
 */

/**
 * One social group. `group_id` + `name` are required; `my_role` is the CALLER's role in this group
 * (admin|moderator|member). The owner is NOT a role - it is identified by `admin_user_id`.
 */
data class UserGroupDto(
    @Json(name = "group_id") val groupId: String,
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "member_count") val memberCount: Int? = null,
    @Json(name = "my_role") val myRole: String? = null,
    @Json(name = "admin_user_id") val adminUserId: String? = null,
    @Json(name = "cover_image_url") val coverImageUrl: String? = null,
    @Json(name = "topic") val topic: String? = null,
    @Json(name = "visibility") val visibility: String? = null,
    @Json(name = "status") val status: String? = null,
)

/**
 * Body for POST ui/groups (create a social group). `name` is required (3..100 chars server-side);
 * description/visibility/topic are optional. `visibility` is "public" or "private" (defaults public
 * server-side). Nulls are omitted by the shared Moshi (serializeNulls off on the production client).
 */
data class GroupCreateIn(
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "visibility") val visibility: String? = null,
    @Json(name = "topic") val topic: String? = null,
)

/** ENVELOPE for GET ui/groups (NOT a bare array). */
data class GroupListResponse(
    @Json(name = "groups") val groups: List<UserGroupDto> = emptyList(),
)

/**
 * One member of a group. Identity is `user_id`; the row carries `display_name` (NO username, NO
 * avatar_url). `status` is kept raw (status=="invited" is a PENDING entry, not active).
 */
data class GroupMemberDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "role") val role: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "joined_at") val joinedAt: String? = null,
    @Json(name = "promoted_at") val promotedAt: String? = null,
)

/** ENVELOPE for GET ui/groups/{groupId}/members (NOT paginated - no cursor/limit). */
data class GroupMembersResponse(
    @Json(name = "members") val members: List<GroupMemberDto> = emptyList(),
    @Json(name = "count") val count: Int? = null,
)

/** Body for POST ui/groups/{groupId}/invite. The invitee becomes status="invited" (a PENDING entry). */
data class GroupInviteIn(
    @Json(name = "user_id") val userId: String,
)

/**
 * Body for PATCH ui/groups/{groupId}/members/{userId}/role. `role` is "moderator" or "member" ONLY -
 * you CANNOT PATCH to admin (admin is the owner, identified by admin_user_id, not assignable here).
 */
data class GroupUpdateRoleIn(
    @Json(name = "role") val role: String,
)

/**
 * PAR-10 - ENVELOPE for GET ui/groups/discover (public group discovery). The backend returns
 * {groups, cursor, has_more}; only the `groups` list is consumed here (the feature loads a single bounded
 * page - cursor/has_more are tolerated but unused). Each row is a [UserGroupDto] whose `my_role` is null for
 * a group the caller has not joined (used to derive the join affordance).
 */
data class GroupDiscoverResponse(
    @Json(name = "groups") val groups: List<UserGroupDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
    @Json(name = "has_more") val hasMore: Boolean? = null,
)
