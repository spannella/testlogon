package com.testlogon.android.data.payouts

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST

/**
 * PAY-22 — Retrofit interface + Moshi DTOs for the payouts W-9 tax-info surface (PAY-21 backend).
 *
 * Backend (app/routers/creator_payouts.py, prefix `/ui/payouts`):
 *  - GET  ui/payouts/tax-info   -> PayoutTaxInfoOut (on_file + masked view; NEVER the raw TIN)
 *  - POST ui/payouts/tax-info   -> PayoutTaxInfoOut (201; body W9SubmitIn — raw TIN sent over TLS only,
 *                                  KMS-tokenized + masked to last-4 server-side, never stored/echoed raw)
 *
 * Paths have NO leading slash (relative to the shared authenticated Retrofit base URL). Session cookie,
 * Authorization Bearer and X-CSRF-Token are attached by core-network interceptors.
 */
interface TaxInfoApi {

    /** W-9 status for the pre-withdrawal gate. Masked (tin_last4 only). Idempotent GET. */
    @GET("ui/payouts/tax-info")
    suspend fun getTaxInfo(): PayoutTaxInfoDto

    /** Submit the W-9. The raw TIN is tokenized+masked server-side. Mutation (CSRF); not retried. */
    @Headers("Content-Type: application/json")
    @POST("ui/payouts/tax-info")
    suspend fun submitTaxInfo(@Body body: W9SubmitDto): PayoutTaxInfoDto
}

/**
 * PayoutTaxInfoOut — the safe (masked) W-9 view. `on_file` tells the app whether a W-9 was collected;
 * the TIN is ALWAYS masked to [tinLast4] (the raw SSN/EIN is never included). The backend gate needs a
 * CERTIFIED W-9, so [certified] matters for the gate decision.
 */
@JsonClass(generateAdapter = true)
data class PayoutTaxInfoDto(
    @Json(name = "on_file") val onFile: Boolean = false,
    @Json(name = "legal_name") val legalName: String = "",
    @Json(name = "tin_last4") val tinLast4: String = "",
    @Json(name = "tin_type") val tinType: String = "",
    @Json(name = "address_line1") val addressLine1: String = "",
    @Json(name = "city") val city: String = "",
    @Json(name = "state") val state: String = "",
    @Json(name = "zip_code") val zipCode: String = "",
    @Json(name = "certified") val certified: Boolean = false,
    @Json(name = "certified_at") val certifiedAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

/**
 * W9SubmitIn — the collection body. The raw [tin] is WRITE-ONLY: it is sent once over TLS and tokenized
 * server-side (KMS), never returned. The app never persists it (it lives only in the transient form).
 */
@JsonClass(generateAdapter = true)
data class W9SubmitDto(
    @Json(name = "legal_name") val legalName: String,
    @Json(name = "tin") val tin: String,
    @Json(name = "tin_type") val tinType: String,
    @Json(name = "address_line1") val addressLine1: String,
    @Json(name = "city") val city: String,
    @Json(name = "state") val state: String,
    @Json(name = "zip_code") val zipCode: String,
    @Json(name = "certified") val certified: Boolean,
)
