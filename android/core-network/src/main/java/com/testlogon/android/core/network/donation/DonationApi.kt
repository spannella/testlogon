package com.testlogon.android.core.network.donation

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-393 - Retrofit interface for the PUBLIC fundraiser-donation surface (session-free).
 *
 * CRUCIAL: these endpoints MUST be callable by an anonymous (signed-out) donor, so this interface is
 * provided on a SEPARATE, COOKIELESS Retrofit (see DonationNetworkModule.provideDonationApi) built on a
 * plain OkHttpClient with NO cookie jar, NO CsrfInterceptor and NO SessionAuthenticator - mirroring the
 * AND-335 PublicShareApi pattern. Only the HostSelectionInterceptor (host targeting), RetryInterceptor
 * and debug logging are shared. The authed interceptors are NOT modified. A truly anonymous caller
 * therefore sends NO Cookie / X-CSRF-Token / Authorization headers, and GET /ui/me is never on this path.
 *
 * Paths have NO leading slash (relative to the cookieless Retrofit base URL). @Path tokens match the
 * {token} exactly. Transport returns RAW DTOs (the donate POST returns a 201 body, modelled as a
 * Response<DonationDto> so the repository can read the body on isSuccessful); the repository wraps each
 * call in ApiResult via the established call{} pattern.
 *
 * ERROR CONTRACT (§5/§16): only 200/201 + 422 HTTPValidationError are documented; a missing/closed
 * fundraiser is INFERRED from the GET result (`status != "active"` or an absent body), not from a 404
 * body. The repository maps 422 per-field via ApiErrorParser.fieldErrorForLocTail.
 */
interface DonationApi {

    /** GET the public fundraiser summary (session-free). 200 -> GroupPublicFundraiserOut. */
    @GET("public/fundraisers/{fundraiserId}")
    suspend fun getFundraiser(
        @Path("fundraiserId") fundraiserId: String,
    ): Response<PublicFundraiserDto>

    /** POST a donation (session-free). 201 -> GroupDonationOut. NOT idempotent server-side (§5). */
    @Headers("Content-Type: application/json")
    @POST("public/fundraisers/{fundraiserId}/donate")
    suspend fun donate(
        @Path("fundraiserId") fundraiserId: String,
        @Body body: DonateRequestDto,
    ): Response<DonationDto>

    /** GET the donation receipt as a SECOND call after donate (session-free). 200 -> GroupDonationReceiptOut. */
    @GET("public/fundraisers/{fundraiserId}/donations/{donationId}/receipt")
    suspend fun getReceipt(
        @Path("fundraiserId") fundraiserId: String,
        @Path("donationId") donationId: String,
    ): Response<DonationReceiptDto>
}
