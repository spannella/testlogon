package com.testlogon.android.core.network.syndicates

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface for the syndicate MANAGEMENT surface: invites (send/list/respond), join-requests
 * (create/list/approve/reject), bundle plans (CRUD + subscribe), admin-transfer, remove-member and the
 * audit log. Transport ONLY; the :app repository folds these RAW DTO returns into ApiResult.
 *
 * Kept SEPARATE from the large read-only SyndicateApi (additive; mirrors how SyndicateBundleApi was split
 * out). Paths have NO leading slash (relative to the shared Retrofit base URL). All calls are suspend. The
 * shared authenticated client attaches the session cookie, the X-CSRF-Token and the Bearer token globally.
 *
 * Contract source: app/routers/syndicates.py (prefix ui/syndicates) + web frontend/src/api/endpoints/
 * syndicates.ts. GET reads return BARE ARRAYS (not envelopes) unless noted.
 */
interface SyndicateManagementApi {

    // ---- Invites ----

    /** GET the caller's pending invites (bare array of SyndicateInviteOut). Idempotent. */
    @GET("ui/syndicates/invites")
    suspend fun listMyInvites(): List<SyndicateInviteOut>

    /** POST an invite for [body].userId to a syndicate (admin-only server-side). 201 -> SyndicateInviteOut. */
    @Headers("Content-Type: application/json")
    @POST("ui/syndicates/{syndicateId}/invite")
    suspend fun invite(
        @Path("syndicateId") syndicateId: String,
        @Body body: SyndicateInviteIn,
    ): SyndicateInviteOut

    /** POST the caller's accept/decline of an invite. Returns {ok, status}. */
    @Headers("Content-Type: application/json")
    @POST("ui/syndicates/{syndicateId}/invite/respond")
    suspend fun respondToInvite(
        @Path("syndicateId") syndicateId: String,
        @Body body: SyndicateInviteRespondIn,
    ): SyndicateInviteRespondOut

    // ---- Join requests ----

    /** POST a request to join [syndicateId] (the caller). 201 -> SyndicateRequestOut. */
    @Headers("Content-Type: application/json")
    @POST("ui/syndicates/{syndicateId}/request")
    suspend fun requestToJoin(
        @Path("syndicateId") syndicateId: String,
        @Body body: SyndicateJoinRequestIn,
    ): SyndicateRequestOut

    /** GET the pending join-requests for [syndicateId] (admin-only server-side; bare array). Idempotent. */
    @GET("ui/syndicates/{syndicateId}/requests")
    suspend fun listRequests(
        @Path("syndicateId") syndicateId: String,
    ): List<SyndicateRequestOut>

    /** POST approve a join-request for [userId] (admin-only). Returns {ok}. */
    @POST("ui/syndicates/{syndicateId}/request/{userId}/approve")
    suspend fun approveRequest(
        @Path("syndicateId") syndicateId: String,
        @Path("userId") userId: String,
    ): SyndicateOkOut

    /** POST reject a join-request for [userId] (admin-only). Returns {ok}. */
    @POST("ui/syndicates/{syndicateId}/request/{userId}/reject")
    suspend fun rejectRequest(
        @Path("syndicateId") syndicateId: String,
        @Path("userId") userId: String,
    ): SyndicateOkOut

    // ---- Admin transfer / remove ----

    /** POST transfer admin to [body].newAdminUserId (current-admin-only). Returns the SyndicateOut meta. */
    @Headers("Content-Type: application/json")
    @POST("ui/syndicates/{syndicateId}/transfer-admin")
    suspend fun transferAdmin(
        @Path("syndicateId") syndicateId: String,
        @Body body: SyndicateTransferAdminIn,
    ): SyndicateMetaOut

    /** POST remove [userId] from the syndicate (admin-only). Returns {ok}. */
    @POST("ui/syndicates/{syndicateId}/remove/{userId}")
    suspend fun removeMember(
        @Path("syndicateId") syndicateId: String,
        @Path("userId") userId: String,
    ): SyndicateOkOut

    // ---- Audit ----

    /** GET the audit log (bare array of SyndicateAuditOut). [limit] clamped 1..200 server-side. Idempotent. */
    @GET("ui/syndicates/{syndicateId}/audit")
    suspend fun getAudit(
        @Path("syndicateId") syndicateId: String,
        @Query("limit") limit: Int = 50,
    ): List<SyndicateAuditOut>

    // ---- Bundle plans (SYND-002) ----

    /** GET the syndicate's bundle plans (bare array of BundlePlanOut). Idempotent. */
    @GET("ui/syndicates/{syndicateId}/plans")
    suspend fun listPlans(
        @Path("syndicateId") syndicateId: String,
    ): List<BundlePlanOut>

    /** GET one plan's detail. */
    @GET("ui/syndicates/{syndicateId}/plans/{planId}")
    suspend fun getPlan(
        @Path("syndicateId") syndicateId: String,
        @Path("planId") planId: String,
    ): BundlePlanOut

    /** POST create a bundle plan (admin-only). 201 -> BundlePlanOut. */
    @Headers("Content-Type: application/json")
    @POST("ui/syndicates/{syndicateId}/plans")
    suspend fun createPlan(
        @Path("syndicateId") syndicateId: String,
        @Body body: BundlePlanCreateIn,
    ): BundlePlanOut

    /** PUT update a bundle plan (admin-only; at least one field). Returns the updated BundlePlanOut. */
    @Headers("Content-Type: application/json")
    @PUT("ui/syndicates/{syndicateId}/plans/{planId}")
    suspend fun updatePlan(
        @Path("syndicateId") syndicateId: String,
        @Path("planId") planId: String,
        @Body body: BundlePlanUpdateIn,
    ): BundlePlanOut

    /** DELETE (archive) a bundle plan (admin-only). Returns {ok, plan_id, status}. */
    @DELETE("ui/syndicates/{syndicateId}/plans/{planId}")
    suspend fun archivePlan(
        @Path("syndicateId") syndicateId: String,
        @Path("planId") planId: String,
    ): ArchiveBundlePlanOut

    /** POST subscribe the caller to a bundle plan. Returns the BundleSubscriptionOut (existing DTO). */
    @Headers("Content-Type: application/json")
    @POST("ui/syndicates/{syndicateId}/plans/{planId}/subscribe")
    suspend fun subscribeToPlan(
        @Path("syndicateId") syndicateId: String,
        @Path("planId") planId: String,
        @Body body: BundleSubscribeIn,
    ): BundleSubscriptionOut
}
