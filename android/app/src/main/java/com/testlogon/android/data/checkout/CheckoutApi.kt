package com.testlogon.android.data.checkout

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.Header
import retrofit2.http.POST

/**
 * AND-213 — Retrofit interface + DTOs for the checkout-session step.
 *
 * Verified contract (reference/openapi.index.txt line 1327; components.schemas.UnifiedCheckoutSessionIn /
 * UnifiedCheckoutSessionOut):
 *  - POST ui/checkout/session  req=UnifiedCheckoutSessionIn  resp=UnifiedCheckoutSessionOut
 *
 * Notes / gaps (see spec AND-213 section 16):
 *  - `source` is REQUIRED on the request ("cart" | "direct" | "subscription_action"); we send "cart".
 *  - The response id field is `checkout_session_id` (plus `order_id`); there is NO top-level
 *    subtotal/tax/shipping/total/currency and `line_items` are free-form objects
 *    (additionalProperties: true) -- we model them as a map and project SKU/quantity defensively.
 *  - The endpoint declares NO idempotency parameter; we send X-Idempotency-Key best-effort (the cart
 *    purchase endpoint uses this header). Re-entry safety is anchored on reusing the in-flight session.
 *  - Session cookies, Authorization: Bearer and X-CSRF-Token are attached by core-network interceptors.
 *    This non-idempotent POST is never auto-retried.
 */
interface CheckoutApi {

    @POST("ui/checkout/session")
    suspend fun createSession(
        @Header("X-Idempotency-Key") idempotencyKey: String,
        @Body body: UnifiedCheckoutSessionInDto,
    ): UnifiedCheckoutSessionOutDto
}

/** Request body (schema UnifiedCheckoutSessionIn). required: source. */
@JsonClass(generateAdapter = true)
data class UnifiedCheckoutSessionInDto(
    @Json(name = "source") val source: String,
    @Json(name = "cart_id") val cartId: String? = null,
)

/** Response body (schema UnifiedCheckoutSessionOut). required: order_id, checkout_session_id, source. */
@JsonClass(generateAdapter = true)
data class UnifiedCheckoutSessionOutDto(
    @Json(name = "checkout_session_id") val checkoutSessionId: String,
    @Json(name = "order_id") val orderId: String,
    @Json(name = "source") val source: String,
    @Json(name = "status") val status: String? = null,
    // additionalProperties: true elements; no documented element schema. Projected defensively.
    @Json(name = "line_items") val lineItems: List<Map<String, Any?>>? = null,
)
