package com.testlogon.android.core.network.kyc

import com.testlogon.android.core.model.kyc.KycDocumentOutDto
import com.testlogon.android.core.model.kyc.KycDocumentUploadRequestDto
import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST

/**
 * AND-321 - Retrofit interface for the KYC identity-document upload endpoint.
 *
 * This is a SEPARATE api from AND-319's [KycApi] because the documents endpoint lives under the `ui/`
 * prefix (NOT `v1/`) and AND-319 deliberately scoped KycApi to `v1/kyc`. The path has NO leading slash
 * (relative to the shared Retrofit base URL, matching the rest of the codebase). The call is suspend and
 * carries an explicit JSON Content-Type. Session cookies, Authorization Bearer and X-CSRF-Token are
 * attached by the core-network interceptors (the POST is a mutating request and gets the CSRF header).
 *
 * The endpoint is NON-IDEMPOTENT: a retry of a succeeded upload duplicates the document, so the caller
 * (DocumentCaptureViewModel) guards against re-POSTing an already-succeeded image.
 */
interface KycDocumentsApi {

    @Headers("Content-Type: application/json")
    @POST("ui/kyc/documents")
    suspend fun uploadDocument(@Body body: KycDocumentUploadRequestDto): KycDocumentOutDto
}
