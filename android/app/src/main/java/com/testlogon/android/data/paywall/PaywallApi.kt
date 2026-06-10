package com.testlogon.android.data.paywall

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST

/**
 * AND-177 — Retrofit interface + DTOs for unlocking a fixed-price locked post.
 *
 * Verified contract (OpenAPI POST /posts/unlock, op unlock_post_posts_unlock_post; schemas
 * UnlockPostRequest / UnlockPostResponse; reference src/api/endpoints/newsfeed.ts: unlockPost):
 *  - request UnlockPostRequest { post_id (required), payment_method_id (string|null),
 *    idempotency_key (string|null, ^[A-Za-z0-9:_.-]+$, 1..128) }.
 *  - response 200 UnlockPostResponse { post_id (required), payment_intent (object, opaque,
 *    additionalProperties:true, required) }.
 *  - the web client sends only post_id (+ optional payment_method_id) and ignores payment_intent;
 *    OpenAPI is authoritative here so we model the full response. idempotency_key is schema-legal
 *    (server honoring unverified) — we send it for safe-retry intent.
 *
 * Mutating POST: cookies, Authorization: Bearer and X-CSRF-Token are attached by the core-network
 * interceptor chain; non-2xx surfaces as retrofit2.HttpException.
 */
interface PaywallApi {

    @Headers("Content-Type: application/json")
    @POST("posts/unlock")
    suspend fun unlock(@Body body: UnlockPostRequestDto): UnlockPostResponseDto
}

@JsonClass(generateAdapter = true)
data class UnlockPostRequestDto(
    @Json(name = "post_id") val postId: String,
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
    @Json(name = "idempotency_key") val idempotencyKey: String? = null,
)

@JsonClass(generateAdapter = true)
data class UnlockPostResponseDto(
    @Json(name = "post_id") val postId: String,
    // payment_intent is opaque (additionalProperties: true); we only inspect "status".
    @Json(name = "payment_intent") val paymentIntent: Map<String, Any?>? = null,
)
