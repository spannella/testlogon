package com.testlogon.android.core.network.groups

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-355 - Retrofit interface for the SOCIAL GROUPS surface. Transport only; the repository
 * (GroupsRepository) wraps these RAW DTO returns in ApiResult.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the
 * codebase). All calls are suspend. The shared authenticated client attaches the session cookie and the
 * X-CSRF-Token on mutating verbs via the global interceptors - there is NO cookieless client here.
 *
 * RETURN SHAPES (OpenAPI / frontend-verified):
 *  - listMyGroups returns an ENVELOPE {groups:[]} (NOT a bare array).
 *  - getGroup returns a single UserGroupDto detail object.
 *  - listMembers returns an ENVELOPE {members:[], count} (NOT paginated).
 *  - invite / changeRole / removeMember / leave return Response<Unit> (200, possibly EMPTY body), so the
 *    repository treats success as Response.isSuccessful and yields ApiResult.Success(Unit).
 *
 * @Path tokens are EXACTLY {groupId} and {userId}.
 */
interface GroupsApi {

    /** GET the groups the caller belongs to. ENVELOPE {groups:[]}. my_role is the caller's role. */
    @GET("ui/groups")
    suspend fun listMyGroups(): GroupListResponse

    /** GET one group's detail (same UserGroupDto shape as a list row). */
    @GET("ui/groups/{groupId}")
    suspend fun getGroup(@Path("groupId") groupId: String): UserGroupDto

    /** GET the member roster for one group. ENVELOPE {members:[], count}. NOT paginated. */
    @GET("ui/groups/{groupId}/members")
    suspend fun listMembers(@Path("groupId") groupId: String): GroupMembersResponse

    /**
     * POST an invite (the invitee becomes status="invited" - a PENDING entry, not an active member).
     * Typed as Response<Unit> so the repo succeeds by isSuccessful regardless of body.
     */
    @Headers("Content-Type: application/json")
    @POST("ui/groups/{groupId}/invite")
    suspend fun invite(
        @Path("groupId") groupId: String,
        @Body body: GroupInviteIn,
    ): Response<Unit>

    /**
     * PATCH a member's role (200, body may be empty). role is moderator|member ONLY (you CANNOT PATCH to
     * admin). Typed as Response<Unit> so the repo succeeds by isSuccessful regardless of body.
     */
    @Headers("Content-Type: application/json")
    @PATCH("ui/groups/{groupId}/members/{userId}/role")
    suspend fun changeRole(
        @Path("groupId") groupId: String,
        @Path("userId") userId: String,
        @Body body: GroupUpdateRoleIn,
    ): Response<Unit>

    /** DELETE a member (200). Success-by-isSuccessful via Response<Unit>. */
    @DELETE("ui/groups/{groupId}/members/{userId}")
    suspend fun removeMember(
        @Path("groupId") groupId: String,
        @Path("userId") userId: String,
    ): Response<Unit>

    /** POST leave (200, NO request body). Success-by-isSuccessful via Response<Unit>. */
    @POST("ui/groups/{groupId}/leave")
    suspend fun leave(
        @Path("groupId") groupId: String,
    ): Response<Unit>
}
