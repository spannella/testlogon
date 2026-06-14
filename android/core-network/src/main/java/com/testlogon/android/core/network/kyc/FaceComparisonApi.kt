package com.testlogon.android.core.network.kyc

import com.testlogon.android.core.model.kyc.FaceComparisonListDto
import com.testlogon.android.core.model.kyc.FaceComparisonResultDto
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-323 - Retrofit interface for the KYC facial-comparison control plane (comparison runs
 * SERVER-SIDE; the client only triggers it and reads history).
 *
 * Like AND-319's [KycApi], these endpoints live under `v1/kyc`; paths have NO leading slash (relative
 * to the shared Retrofit base URL). compare-face is a suspend mutating POST with an EMPTY body (no
 * @Body), so no Content-Type header is declared. Session cookies, Authorization Bearer and
 * X-CSRF-Token are attached by the core-network interceptors.
 *
 * The selfie upload (presign -> bare cookieless PUT) and the attach (KycApi.attachFile, file_type
 * "selfie") happen BEFORE compare-face; this api covers only the compare + history calls.
 *
 * compare-face is NON-IDEMPOTENT (each call is a new attempt counted against max_attempts), so the
 * caller (FaceComparisonRepository / FaceComparisonViewModel) guards against re-submitting.
 */
interface FaceComparisonApi {

    @POST("v1/kyc/cases/{caseId}/compare-face")
    suspend fun compareFace(@Path("caseId") caseId: String): FaceComparisonResultDto

    @GET("v1/kyc/cases/{caseId}/face-comparisons")
    suspend fun listComparisons(@Path("caseId") caseId: String): FaceComparisonListDto
}
