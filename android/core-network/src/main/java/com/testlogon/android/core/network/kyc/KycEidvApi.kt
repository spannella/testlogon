package com.testlogon.android.core.network.kyc

import com.testlogon.android.core.model.kyc.EidSchemesListOutDto
import com.testlogon.android.core.model.kyc.EidStatusOutDto
import com.testlogon.android.core.model.kyc.StartEidVerificationInDto
import com.testlogon.android.core.model.kyc.StartEidVerificationOutDto
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-325 - Retrofit interface for the KYC electronic ID verification (eIDV) endpoint surface.
 *
 * Like AND-319's [KycApi], these endpoints live under the `v1/` prefix; paths have NO leading slash
 * (relative to the shared Retrofit base URL). Session cookies, Authorization Bearer and X-CSRF-Token are
 * attached by the core-network interceptors.
 *
 * This is a FULLY REAL REST eIDV control plane using a REDIRECT-based government eID scheme flow: the app
 * lists schemes, ensures a draft KYC case (via AND-319's KycApi.createCase), starts a session for the
 * chosen scheme (NO PII - only {scheme}), opens the returned redirect_url EXTERNALLY (ACTION_VIEW), then
 * polls status until an eid_verification assertion appears or the session expires. There is NO vendor / ML
 * / CameraX SDK and NO flagged seam.
 *
 * IDEMPOTENCY: [startEid] is a NON-IDEMPOTENT mutating POST (a retry of a succeeded start opens a second
 * provider session) so it is NOT auto-retried and the caller (EidvViewModel) debounces it. [listSchemes]
 * and [eidStatus] are idempotent GETs.
 */
interface KycEidvApi {

    @GET("v1/kyc/eid/schemes")
    suspend fun listSchemes(@Query("country") country: String?): EidSchemesListOutDto

    @Headers("Content-Type: application/json")
    @POST("v1/kyc/cases/{case_id}/eid/start")
    suspend fun startEid(
        @Path("case_id") caseId: String,
        @Body body: StartEidVerificationInDto,
    ): StartEidVerificationOutDto

    @GET("v1/kyc/cases/{case_id}/eid/status")
    suspend fun eidStatus(@Path("case_id") caseId: String): EidStatusOutDto
}
