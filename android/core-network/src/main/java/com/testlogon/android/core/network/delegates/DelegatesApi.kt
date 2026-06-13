package com.testlogon.android.core.network.delegates

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-359 - Retrofit interface for the delegate / delegation surface (manage-as-creator mode). Transport
 * only; the repository (DelegationRepository) wraps these RAW DTO returns in ApiResult.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the
 * codebase). All calls are suspend. The shared authenticated client attaches the session cookie and the
 * X-CSRF-Token on mutating verbs via the global interceptors.
 *
 * CRITICAL (verified corrections - obey): the ONLY REQUIRED network call here is [listManagedCreators]
 * (GET ui/delegates/managed). Entering / exiting delegate mode is a PURE LOCAL state mutation of the
 * observable managingCreator flag (mirrors the web authStore.setManagingCreator) - there is NO
 * POST ui/delegates/enter, NO /exit, NO GET /current, and NO X-Manage-As header. Path-scoping for
 * downstream features is the activeCreatorId seam on the repository, NOT a header on this API.
 *
 * RETURN SHAPE: GET ui/delegates/managed returns a BARE JSON ARRAY (List<ManagedCreatorOut>), NOT an
 * envelope. The optional invite calls below are OPTIONAL / downstream and kept off the critical path.
 */
interface DelegatesApi {

    /**
     * GET the creators the current principal MAY manage as a delegate (BARE ARRAY). This is the ONLY
     * REQUIRED network call for AND-359.
     */
    @GET("ui/delegates/managed")
    suspend fun listManagedCreators(): List<ManagedCreatorOut>

    /**
     * AND-359 (OPTIONAL / downstream) - GET the current principal's pending delegate invites (BARE ARRAY).
     * Kept minimal; not on the critical path.
     */
    @GET("ui/delegates/invites")
    suspend fun listInvites(): List<DelegateInviteOut>

    /**
     * AND-359 (OPTIONAL / downstream) - respond to one pending delegate invite (accept / decline). The
     * response body (if any) is ignored, so this is typed as Response<Unit> and folded by isSuccessful.
     * @Path token is EXACTLY {inviteId}. Kept minimal; not on the critical path.
     */
    @Headers("Content-Type: application/json")
    @POST("ui/delegates/invites/{inviteId}/respond")
    suspend fun respondInvite(
        @Path("inviteId") inviteId: String,
        @Body body: DelegateInviteRespondReq,
    ): Response<Unit>
}
