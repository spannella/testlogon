package com.testlogon.android.core.network.collaborations

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-358 / PAR-04 - Retrofit interface for the collaborations surface. Transport only; the repository
 * (CollaborationsRepository) wraps these RAW DTO returns in ApiResult and exposes the list as a Paging-3
 * flow. Mirrors the AND-356 SyndicateApi convention.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the codebase).
 * All calls are suspend. The shared authenticated client attaches the session cookie, the X-CSRF-Token and
 * the Bearer token via the global interceptors.
 *
 * AND-358 added the READ surface (list / detail / splits). PAR-04 adds the STATE-only DEAL ACTIONS
 * (accept / reject / counter / cancel / terminate) + the negotiation revision history. These mutations are
 * NOT money-bearing (agreement state only) so they are NOT routed through BillingAuthorizer.
 *
 * @Path token is EXACTLY {collabId}. The list is cursor-paged via the optional `cursor` query.
 */
interface CollaborationsApi {

    /**
     * GET one page of the viewer's collaborations. `cursor` is the opaque next-page token (null for the first
     * page). Returns the {items/collaborations, next_cursor} envelope.
     */
    @GET("ui/collaborations")
    suspend fun listCollaborations(
        @Query("cursor") cursor: String? = null,
    ): CollaborationListOut

    /** GET a single collaboration by id (same shape as a list row). */
    @GET("ui/collaborations/{collabId}")
    suspend fun getCollaboration(@Path("collabId") collabId: String): CollaborationOut

    /**
     * GET the OPTIONAL split history (per-distribution amounts) for a collaboration. The detail screen
     * tolerates this call failing (it falls back to an empty distributions list).
     */
    @GET("ui/collaborations/{collabId}/splits")
    suspend fun getSplits(@Path("collabId") collabId: String): CollabSplitHistoryOut

    /**
     * GET the negotiation revision history (a BARE JSON ARRAY of prior proposed splits). The detail screen
     * tolerates this call failing (it falls back to an empty revisions list).
     */
    @GET("ui/collaborations/{collabId}/revisions")
    suspend fun getRevisions(@Path("collabId") collabId: String): List<CollaborationRevisionOut>

    /** POST accept the current proposal (body-less). Returns the updated collaboration. State-only. */
    @POST("ui/collaborations/{collabId}/accept")
    suspend fun acceptCollaboration(@Path("collabId") collabId: String): CollaborationOut

    /** POST reject the current proposal (body-less). Returns the updated collaboration. State-only. */
    @POST("ui/collaborations/{collabId}/reject")
    suspend fun rejectCollaboration(@Path("collabId") collabId: String): CollaborationOut

    /** POST a counter-offer (new initiator split percent). Returns the updated collaboration. State-only. */
    @POST("ui/collaborations/{collabId}/counter")
    suspend fun counterCollaboration(
        @Path("collabId") collabId: String,
        @Body body: CollaborationCounterIn,
    ): CollaborationOut

    /** POST cancel the pending request (initiator only, body-less). Returns the updated collaboration. */
    @POST("ui/collaborations/{collabId}/cancel")
    suspend fun cancelCollaboration(@Path("collabId") collabId: String): CollaborationOut

    /** POST terminate the active agreement (optional reason). Returns the updated collaboration. State-only. */
    @POST("ui/collaborations/{collabId}/terminate")
    suspend fun terminateCollaboration(
        @Path("collabId") collabId: String,
        @Body body: CollaborationTerminateIn,
    ): CollaborationOut
}
