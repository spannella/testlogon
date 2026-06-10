package com.testlogon.android.data.tip

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-178 — Retrofit interface + DTOs for tipping a post.
 *
 * Verified contract (OpenAPI POST /posts/{post_id}/tip, op tip_post_posts__post_id__tip_post; schema
 * PostTipRequest; reference src/api/endpoints/newsfeed.ts: tipPostDirect, types.ts: TipReq):
 *  - path is /posts/{post_id}/tip (NO /ui prefix).
 *  - request PostTipRequest { amount_cents (int, min 1), currency? (default "usd"), payment_method_id? }.
 *    There is NO message field in the backend schema (OQ-5) — message is never sent.
 *  - response: OpenAPI documents an empty body {}; the web client types it { ok, tip_total_cents };
 *    both fields are therefore optional/nullable. No tip_id / created_at / per-tip amount is returned.
 *  - Idempotency-Key is NOT in the OpenAPI contract (OQ-3); the firm double-submit guard is the
 *    client-side submit lock. We do not send a speculative header.
 *
 * Mutating POST: cookies, Authorization: Bearer and X-CSRF-Token are attached by the core-network
 * interceptor chain; non-2xx surfaces as retrofit2.HttpException.
 */
interface TipApi {

    @Headers("Content-Type: application/json")
    @POST("posts/{post_id}/tip")
    suspend fun tipPost(
        @Path("post_id") postId: String,
        @Body body: TipRequestDto,
    ): TipResultDto
}

@JsonClass(generateAdapter = true)
data class TipRequestDto(
    @Json(name = "amount_cents") val amountCents: Int,
    @Json(name = "currency") val currency: String? = "usd",
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
)

@JsonClass(generateAdapter = true)
data class TipResultDto(
    @Json(name = "ok") val ok: Boolean? = null,
    @Json(name = "tip_total_cents") val tipTotalCents: Int? = null,
)
