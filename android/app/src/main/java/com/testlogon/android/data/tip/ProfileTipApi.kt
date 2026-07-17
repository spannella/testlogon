package com.testlogon.android.data.tip

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * TIPX-C2 - Retrofit interface + DTOs for a standalone DIRECT tip to a creator from their profile
 * (no specific content open). Wire contract: POST /ui/profile/{identifier}/tip (backend
 * app/routers/profile.py: tip_creator_profile, schema ProfileTipRequest).
 *
 *  - request ProfileTipRequest { amount_cents (int, min 1), currency? (default "usd"),
 *    payment_method_id?, client_request_id? }. The client_request_id is the STABLE idempotency key so a
 *    double-tap / retry replays the receipt (charged once).
 *  - response { ok, tip_payment_id, charged_cents, net_cents, recipient_id, tip_total_cents,
 *    idempotent_replay } (all optional/nullable client-side).
 *
 * The base URL does NOT include /ui, so the path carries it (matching data/profile/ProfileApi.kt).
 * Cookies / Authorization: Bearer / X-CSRF-Token are attached by the core-network interceptor chain.
 */
interface ProfileTipApi {

    @Headers("Content-Type: application/json")
    @POST("ui/profile/{identifier}/tip")
    suspend fun tipCreator(
        @Path("identifier") identifier: String,
        @Body body: ProfileTipRequestDto,
    ): ProfileTipResultDto
}

@JsonClass(generateAdapter = true)
data class ProfileTipRequestDto(
    @Json(name = "amount_cents") val amountCents: Int,
    @Json(name = "currency") val currency: String? = "usd",
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
    @Json(name = "client_request_id") val clientRequestId: String? = null,
)

@JsonClass(generateAdapter = true)
data class ProfileTipResultDto(
    @Json(name = "ok") val ok: Boolean? = null,
    @Json(name = "tip_payment_id") val tipPaymentId: String? = null,
    @Json(name = "charged_cents") val chargedCents: Int? = null,
    @Json(name = "net_cents") val netCents: Int? = null,
    @Json(name = "recipient_id") val recipientId: String? = null,
    @Json(name = "tip_total_cents") val tipTotalCents: Int? = null,
    @Json(name = "idempotent_replay") val idempotentReplay: Boolean? = null,
)
