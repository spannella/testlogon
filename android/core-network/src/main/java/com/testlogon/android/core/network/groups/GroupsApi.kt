package com.testlogon.android.core.network.groups

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

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

    /**
     * POST a new social group. Returns the created group as a UserGroupDto detail object
     * (group_id + my_role="admin" for the creator). 201 on success; a 422 carries field detail.
     */
    @Headers("Content-Type: application/json")
    @POST("ui/groups")
    suspend fun createGroup(@Body body: GroupCreateIn): UserGroupDto

    /** GET one group's detail (same UserGroupDto shape as a list row). */
    @GET("ui/groups/{groupId}")
    suspend fun getGroup(@Path("groupId") groupId: String): UserGroupDto

    /** GET the member roster for one group. ENVELOPE {members:[], count}. NOT paginated. */
    @GET("ui/groups/{groupId}/members")
    suspend fun listMembers(@Path("groupId") groupId: String): GroupMembersResponse

    // ---- Batch-8 (#11): group feed (GROUP-002) ----

    /**
     * POST a new group feed post. 201 -> the created GroupFeedPostDto. The shared authenticated client
     * attaches the session cookie + X-CSRF-Token.
     */
    @Headers("Content-Type: application/json")
    @POST("ui/groups/{groupId}/posts")
    suspend fun createGroupPost(
        @Path("groupId") groupId: String,
        @Body body: GroupPostCreateIn,
    ): GroupFeedPostDto

    /** GET one reverse-chronological page of the group feed. ENVELOPE {posts, cursor, has_more}. */
    @GET("ui/groups/{groupId}/feed")
    suspend fun getGroupFeed(
        @Path("groupId") groupId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): GroupFeedResponse

    // ---- Batch-9 (#11): group post comments (B-GRPFULL #11) ----

    /** POST a comment (text and/or image, optional threaded reply) to a group post. 201 -> GroupCommentDto. */
    @Headers("Content-Type: application/json")
    @POST("ui/groups/{groupId}/posts/{postId}/comments")
    suspend fun addGroupComment(
        @Path("groupId") groupId: String,
        @Path("postId") postId: String,
        @Body body: GroupCommentCreateIn,
    ): GroupCommentDto

    /** GET one oldest-first page of a group post's comments. ENVELOPE {comments, next_cursor}. */
    @GET("ui/groups/{groupId}/posts/{postId}/comments")
    suspend fun getGroupComments(
        @Path("groupId") groupId: String,
        @Path("postId") postId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): GroupCommentListResponse

    /** DELETE a group post comment (author or admin/mod). 200 -> success-by-isSuccessful. */
    @DELETE("ui/groups/{groupId}/posts/{postId}/comments/{commentId}")
    suspend fun deleteGroupComment(
        @Path("groupId") groupId: String,
        @Path("postId") postId: String,
        @Path("commentId") commentId: String,
    ): Response<Unit>

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
    // ---- Sub-pages: treasury / fundraising / campaigns / settings (AND-355 sub-pages) ----

    /** GET the group treasury balance (membership-gated read). */
    @GET("ui/groups/{groupId}/treasury")
    suspend fun getTreasuryBalance(@Path("groupId") groupId: String): TreasuryBalanceDto

    /** GET the treasury ledger (ENVELOPE {entries, cursor?, has_more}). Membership-gated read. */
    @GET("ui/groups/{groupId}/treasury/ledger")
    suspend fun getTreasuryLedger(
        @Path("groupId") groupId: String,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): TreasuryLedgerResponse

    /** GET the treasury contributors (ENVELOPE {contributors, count}). Membership-gated read. */
    @GET("ui/groups/{groupId}/treasury/contributors")
    suspend fun getTreasuryContributors(@Path("groupId") groupId: String): ContributorListResponse

    /** GET the group fundraisers (ENVELOPE {fundraisers}). Membership-gated read. */
    @GET("ui/groups/fundraising/{groupId}/fundraisers")
    suspend fun listFundraisers(@Path("groupId") groupId: String): GroupFundraiserListResponse

    /** POST a new fundraiser (admin-gated at the service layer -> 403 for non-admins). */
    @Headers("Content-Type: application/json")
    @POST("ui/groups/fundraising/{groupId}/fundraisers")
    suspend fun createFundraiser(
        @Path("groupId") groupId: String,
        @Body body: GroupCreateFundraiserIn,
    ): GroupFundraiserDto

    /** GET the group advertising campaigns (ENVELOPE {campaigns}). Membership-gated read. */
    @GET("ui/groups/fundraising/{groupId}/campaigns")
    suspend fun listCampaigns(@Path("groupId") groupId: String): GroupCampaignListResponse

    /** GET per-campaign stats. Membership-gated read. */
    @GET("ui/groups/fundraising/{groupId}/campaigns/{campaignId}/stats")
    suspend fun getCampaignStats(
        @Path("groupId") groupId: String,
        @Path("campaignId") campaignId: String,
    ): GroupCampaignStatsDto

    /** POST a new campaign (admin-gated at the service layer -> 403 for non-admins). */
    @Headers("Content-Type: application/json")
    @POST("ui/groups/fundraising/{groupId}/campaigns")
    suspend fun createCampaign(
        @Path("groupId") groupId: String,
        @Body body: GroupCreateCampaignIn,
    ): GroupCampaignDto

    /** PATCH the group settings (admin-gated at the service layer -> 403 for non-admins). */
    @Headers("Content-Type: application/json")
    @PATCH("ui/groups/{groupId}")
    suspend fun updateGroup(
        @Path("groupId") groupId: String,
        @Body body: GroupUpdateIn,
    ): UserGroupDto
}
