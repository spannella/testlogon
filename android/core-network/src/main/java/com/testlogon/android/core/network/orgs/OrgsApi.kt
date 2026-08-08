package com.testlogon.android.core.network.orgs

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-353 - Retrofit interface for the organizations members/roles surface. Transport only; the
 * repository (OrgsRepository) wraps these RAW DTO returns in ApiResult.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the
 * codebase). All calls are suspend. The shared authenticated client attaches the session cookie and the
 * X-CSRF-Token on mutating verbs via the global interceptors - there is NO cookieless client here.
 *
 * RETURN SHAPES (OpenAPI-verified):
 *  - The three GETs return BARE JSON ARRAYS (List<...>), NOT {orgs:[]} / {members:[]} envelopes.
 *  - invite returns a 201 OrgInviteOut (a PENDING INVITE, not a member).
 *  - changeRole / removeMember / transferOwnership return Response<Unit> (200/204, possibly EMPTY body),
 *    so the repository treats success as Response.isSuccessful and yields ApiResult.Success(Unit).
 *
 * @Path tokens are EXACTLY {orgId} and {memberSub}.
 */
interface OrgsApi {

    /** GET all orgs the caller belongs to (BARE ARRAY). org_role is the caller's role per org. */
    @GET("ui/orgs")
    suspend fun listOrgs(): List<OrgOut>

    /** GET the member roster for one org (BARE ARRAY). Member identity is user_sub. */
    @GET("ui/orgs/{orgId}/members")
    suspend fun listMembers(@Path("orgId") orgId: String): List<OrgMemberOut>

    /** GET the caller's pending invites (BARE ARRAY) - a SEPARATE resource from members. */
    @GET("ui/orgs/invites/pending")
    suspend fun listPendingInvites(): List<OrgInviteOut>

    /** POST an invite (201 -> the created PENDING invite, NOT a member). owner is NOT invitable. */
    @Headers("Content-Type: application/json")
    @POST("ui/orgs/{orgId}/members/invite")
    suspend fun inviteMember(
        @Path("orgId") orgId: String,
        @Body body: OrgMemberInviteReq,
    ): OrgInviteOut

    /**
     * PATCH a member's role (200, body may be empty). org_role is admin|member|viewer (owner is NOT
     * assignable here). Typed as Response<Unit> so the repo succeeds by isSuccessful regardless of body.
     */
    @Headers("Content-Type: application/json")
    @PATCH("ui/orgs/{orgId}/members/{memberSub}/role")
    suspend fun changeRole(
        @Path("orgId") orgId: String,
        @Path("memberSub") memberSub: String,
        @Body body: OrgMemberRoleUpdateReq,
    ): Response<Unit>

    /** DELETE a member (204 EMPTY body). Success-by-isSuccessful via Response<Unit>. */
    @DELETE("ui/orgs/{orgId}/members/{memberSub}")
    suspend fun removeMember(
        @Path("orgId") orgId: String,
        @Path("memberSub") memberSub: String,
    ): Response<Unit>

    /**
     * PAR-35(b) - the CURRENT USER leaves the org (204 EMPTY body, NO request body). Success-by-isSuccessful
     * via Response<Unit>. The backend rejects a SOLE-OWNER leave with 409 ("Transfer ownership first."),
     * which surfaces as Failure(status=409). Confirmed live in cpp h_org_leave. @Path token is EXACTLY {orgId}.
     */
    @POST("ui/orgs/{orgId}/leave")
    suspend fun leaveOrg(
        @Path("orgId") orgId: String,
    ): Response<Unit>

    /**
     * POST ownership transfer (the SEPARATE owner-assignment endpoint). Modeled per OpenAPI; the
     * role-change UI does NOT offer this. Success-by-isSuccessful via Response<Unit>.
     */
    @Headers("Content-Type: application/json")
    @POST("ui/orgs/{orgId}/transfer-ownership")
    suspend fun transferOwnership(
        @Path("orgId") orgId: String,
        @Body body: TransferOwnershipReq,
    ): Response<Unit>

    /**
     * AND-354 - the CURRENT USER accepts one of their OWN pending invites (from
     * GET ui/orgs/invites/pending). Body carries the invite [OrgInviteAcceptReq.token]; the response body
     * (if any) is ignored, so this is typed as Response<Unit> and folded by isSuccessful. @Path token is
     * EXACTLY {inviteId}. There is NO inviter-side revoke endpoint - do NOT add one (flagged unverified).
     */
    @Headers("Content-Type: application/json")
    @POST("ui/orgs/invites/{inviteId}/accept")
    suspend fun acceptInvite(
        @Path("inviteId") inviteId: String,
        @Body body: OrgInviteAcceptReq,
    ): Response<Unit>

    /**
     * AND-354 - the CURRENT USER declines one of their OWN pending invites (204 EMPTY body, NO request
     * body). Success-by-isSuccessful via Response<Unit>. @Path token is EXACTLY {inviteId}.
     */
    @POST("ui/orgs/invites/{inviteId}/decline")
    suspend fun declineInvite(
        @Path("inviteId") inviteId: String,
    ): Response<Unit>
}
