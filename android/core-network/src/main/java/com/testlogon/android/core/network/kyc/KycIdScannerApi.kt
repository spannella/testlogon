package com.testlogon.android.core.network.kyc

import com.testlogon.android.core.model.kyc.KycIdScannerScanOutDto
import com.testlogon.android.core.model.kyc.KycIdScannerScanRequestDto
import com.testlogon.android.core.model.kyc.KycIdScannerValidateRequestDto
import com.testlogon.android.core.model.kyc.KycIdScannerValidationOutDto
import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-322 - Retrofit interface for the KYC ID-scanner control plane.
 *
 * Like AND-321's [KycDocumentsApi], these endpoints live under the `ui/` prefix (NOT `v1/`); paths have NO
 * leading slash (relative to the shared Retrofit base URL). Both calls are suspend mutating POSTs and carry
 * an explicit JSON Content-Type; session cookies, Authorization Bearer and X-CSRF-Token are attached by the
 * core-network interceptors. The base64 image upload is a SEPARATE call to AND-321's KycDocumentsApi.
 *
 * scan-document is NON-IDEMPOTENT: a retry of a succeeded scan creates a duplicate scan, so the caller
 * (IdScannerViewModel) guards against re-scanning an already-succeeded side.
 */
interface KycIdScannerApi {

    @Headers("Content-Type: application/json")
    @POST("ui/kyc/id-scanner/cases/{caseId}/validate-document")
    suspend fun validateDocument(
        @Path("caseId") caseId: String,
        @Body body: KycIdScannerValidateRequestDto,
    ): KycIdScannerValidationOutDto

    @Headers("Content-Type: application/json")
    @POST("ui/kyc/id-scanner/cases/{caseId}/scan-document")
    suspend fun scanDocument(
        @Path("caseId") caseId: String,
        @Body body: KycIdScannerScanRequestDto,
    ): KycIdScannerScanOutDto
}
