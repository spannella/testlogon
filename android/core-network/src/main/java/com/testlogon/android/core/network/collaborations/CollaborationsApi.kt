package com.testlogon.android.core.network.collaborations

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-358 / PAR-04 / FIN-011 - Retrofit interface for the collaborations surface. Transport only; the
 * repository (CollaborationsRepository) wraps these RAW DTO returns in ApiResult and exposes the list as a
 * Paging-3 flow. Mirrors the AND-356 SyndicateApi convention.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the codebase).
 * All calls are suspend. The shared authenticated client attaches the session cookie, the X-CSRF-Token and
 * the Bearer token via the global interceptors.
 *
 * AND-358 added the READ surface (list / detail / splits). PAR-04 adds the STATE-only DEAL ACTIONS
 * (accept / reject / counter / cancel / terminate) + the negotiation revision history. FIN-011 adds the
 * REVENUE-SPLITTING + DISPUTE + inbound-request SETTINGS surface (assign/list/unassign content, trigger a
 * revenue event, list/file/resolve disputes, get/put settings). The deal actions + disputes are agreement /
 * state only (money movement happens server-side in the revenue-event path) so they are NOT routed through
 * BillingAuthorizer.
 *
 * @Path token is EXACTLY {collabId} (and {contentId} / {splitId} / {disputeId}). The list is cursor-paged via
 * the optional `cursor` query.
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
     * GET the split history (per-record per-party amounts) for a collaboration. The detail screen tolerates
     * this call failing (falls back to an empty list).
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

    // ---- FIN-011: inbound-request settings ----------------------------------------------------------------

    /** GET the viewer's inbound-collaboration settings. */
    @GET("ui/collaborations/settings")
    suspend fun getSettings(): CollaborationSettingsOut

    /** PUT a partial update of the viewer's inbound-collaboration settings. Returns the merged settings. */
    @PUT("ui/collaborations/settings")
    suspend fun updateSettings(@Body body: CollaborationSettingsIn): CollaborationSettingsOut

    // ---- FIN-011: content assignment + auto-split revenue events -----------------------------------------

    /** GET the content assigned to a collaboration (each auto-splits its revenue events per the agreement). */
    @GET("ui/collaborations/{collabId}/content")
    suspend fun listContent(@Path("collabId") collabId: String): CollabContentListOut

    /** POST assign a piece of owned content to the collaboration. Returns an ok ack. */
    @POST("ui/collaborations/{collabId}/content")
    suspend fun assignContent(
        @Path("collabId") collabId: String,
        @Body body: CollabContentAssignIn,
    ): CollabOkOut

    /** DELETE unassign a piece of content from the collaboration. Returns an ok ack. */
    @DELETE("ui/collaborations/{collabId}/content/{contentId}")
    suspend fun unassignContent(
        @Path("collabId") collabId: String,
        @Path("contentId") contentId: String,
    ): CollabOkOut

    /** POST deterministically trigger an auto-split for a revenue event on assigned content. */
    @POST("ui/collaborations/{collabId}/content/{contentId}/revenue-event")
    suspend fun recordRevenueEvent(
        @Path("collabId") collabId: String,
        @Path("contentId") contentId: String,
        @Body body: CollabContentSplitTriggerIn,
    ): CollabOkOut

    // ---- FIN-011: disputes ------------------------------------------------------------------------------

    /** GET the disputes for a collaboration (optionally filtered by `status`). */
    @GET("ui/collaborations/{collabId}/disputes")
    suspend fun listDisputes(
        @Path("collabId") collabId: String,
        @Query("status") status: String? = null,
    ): CollabDisputeListOut

    /** POST file a dispute on a split record (required reason + optional proposed re-split). Returns an ack. */
    @POST("ui/collaborations/{collabId}/splits/{splitId}/dispute")
    suspend fun fileDispute(
        @Path("collabId") collabId: String,
        @Path("splitId") splitId: String,
        @Body body: CollabDisputeIn,
    ): CollabOkOut

    /** POST resolve an open dispute (accept/reject the proposed re-split). Returns an ack with the new status. */
    @POST("ui/collaborations/{collabId}/disputes/{disputeId}/resolve")
    suspend fun resolveDispute(
        @Path("collabId") collabId: String,
        @Path("disputeId") disputeId: String,
        @Body body: CollabDisputeResolveIn,
    ): CollabOkOut
}
