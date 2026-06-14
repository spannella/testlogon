package com.testlogon.android.core.network.kyc

import com.testlogon.android.core.model.kyc.AddressInputDto
import com.testlogon.android.core.model.kyc.AddressVerificationOutDto
import com.testlogon.android.core.model.kyc.KycResidencyDocumentOutDto
import com.testlogon.android.core.model.kyc.KycResidencyListResponseDto
import com.testlogon.android.core.model.kyc.KycResidencyUploadRequestDto
import com.testlogon.android.core.model.kyc.PostalCodeValidationDto
import com.testlogon.android.core.model.kyc.PostalCodeValidationRequestDto
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-326 - Retrofit interface for the two KYC residency / address-verification surfaces.
 *
 * The proof-of-residency DOCUMENT endpoints live under the `ui/` prefix (NOT `v1/`, mirroring AND-321's
 * KycDocumentsApi); the structured ADDRESS-verification endpoints live under the `v1/` prefix (mirroring
 * AND-319's KycApi / AND-325's KycEidvApi). Paths have NO leading slash (relative to the shared Retrofit
 * base URL). Session cookies, Authorization Bearer and X-CSRF-Token are attached by the core-network
 * interceptors (the mutating POSTs get the CSRF header).
 *
 * Both surfaces are FULLY REAL REST: the proof image/PDF is uploaded as inline base64 (NO vendor / ML /
 * CameraX SDK, NO flagged seam); the address is verified server-side against a structured input.
 *
 * IDEMPOTENCY: [uploadResidency], [extractResidency], [verifyAddress] and [validatePostalCode] are
 * NON-IDEMPOTENT mutating POSTs (a retry of a succeeded upload duplicates the document; a re-verify opens a
 * second verification), so they are NOT auto-retried and the caller (ResidencyViewModel) debounces them.
 * [listResidency] and [getAddressVerification] are idempotent GETs.
 */
interface KycResidencyApi {

    @GET("ui/kyc/residency")
    suspend fun listResidency(): KycResidencyListResponseDto

    @Headers("Content-Type: application/json")
    @POST("ui/kyc/residency")
    suspend fun uploadResidency(@Body body: KycResidencyUploadRequestDto): KycResidencyDocumentOutDto

    @POST("ui/kyc/residency/{document_id}/extract")
    suspend fun extractResidency(@Path("document_id") documentId: String): KycResidencyDocumentOutDto

    @Headers("Content-Type: application/json")
    @POST("v1/kyc/address-verification/cases/{case_id}/verify")
    suspend fun verifyAddress(
        @Path("case_id") caseId: String,
        @Body body: AddressInputDto,
    ): AddressVerificationOutDto

    @GET("v1/kyc/address-verification/cases/{case_id}")
    suspend fun getAddressVerification(@Path("case_id") caseId: String): AddressVerificationOutDto

    @Headers("Content-Type: application/json")
    @POST("v1/kyc/address-verification/validate-postal-code")
    suspend fun validatePostalCode(@Body body: PostalCodeValidationRequestDto): PostalCodeValidationDto
}
