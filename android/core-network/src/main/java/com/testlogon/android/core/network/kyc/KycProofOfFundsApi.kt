package com.testlogon.android.core.network.kyc

import com.testlogon.android.core.model.kyc.ProofOfFundsSubmissionListDto
import com.testlogon.android.core.model.kyc.ProofOfFundsSubmissionOutDto
import com.testlogon.android.core.model.kyc.ProofOfFundsSubmitRequestDto
import com.testlogon.android.core.model.kyc.ProofOfFundsSummaryDto
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-327 - Retrofit interface for the KYC proof-of-funds surface.
 *
 * The endpoints live under the `ui/` prefix (mirroring AND-321's KycDocumentsApi / AND-326's residency
 * document surface). Paths have NO leading slash (relative to the shared Retrofit base URL). Session
 * cookies, Authorization Bearer and X-CSRF-Token are attached by the core-network interceptors (the
 * mutating POST gets the CSRF header).
 *
 * FULLY REAL REST. The optional supporting document is uploaded SEPARATELY via the AND-129 presign->PUT
 * pipeline (reused by the repository); only the returned `key` rides this surface as document_s3_key.
 * NO vendor / ML / CameraX SDK, NO flagged seam.
 *
 * IDEMPOTENCY: [summary], [listSubmissions] and [getSubmission] are idempotent GETs; [submit] is a
 * NON-IDEMPOTENT POST (a retry opens a second submission) so it is NOT auto-retried and the caller
 * (ProofOfFundsViewModel) debounces it. Success is 200 (NOT 201).
 */
interface KycProofOfFundsApi {

    @GET("ui/kyc/proof-of-funds/summary")
    suspend fun summary(): ProofOfFundsSummaryDto

    @GET("ui/kyc/proof-of-funds/submissions")
    suspend fun listSubmissions(): ProofOfFundsSubmissionListDto

    @GET("ui/kyc/proof-of-funds/submissions/{submission_id}")
    suspend fun getSubmission(
        @Path("submission_id") submissionId: String,
    ): ProofOfFundsSubmissionOutDto

    @Headers("Content-Type: application/json")
    @POST("ui/kyc/proof-of-funds/submissions")
    suspend fun submit(@Body body: ProofOfFundsSubmitRequestDto): ProofOfFundsSubmissionOutDto
}
