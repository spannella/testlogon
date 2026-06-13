package com.testlogon.android.core.network.collaborations

import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-358 - Retrofit interface for the READ-ONLY collaborations surface. Transport only; the repository
 * (CollaborationsRepository) wraps these RAW DTO returns in ApiResult and exposes the list as a Paging-3
 * flow. Mirrors the AND-356 SyndicateApi convention.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the codebase).
 * All calls are suspend. The shared authenticated client attaches the session cookie, the X-CSRF-Token and
 * the Bearer token via the global interceptors.
 *
 * READ-ONLY: there is NO create / edit / propose / payout endpoint here - those are OUT OF SCOPE for AND-358.
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
}
