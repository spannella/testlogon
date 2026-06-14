package com.testlogon.android.core.network.ads

import com.squareup.moshi.Json

/**
 * AND-364 - transport DTOs for the platform CONTENT BOOST surface (ui/ads/boost). A boost is a paid
 * promotion of a single post: the user picks a total budget + duration, the server charges the wallet
 * UP-FRONT (no payment-method / ads-account selection on the client - corrected contract), creates the
 * boost, and the client then watches its status (with cancel/refund while active).
 *
 * CODEGEN NOTE (identical to AND-363 AdsDtos): core-network does NOT apply the Moshi KSP codegen plugin,
 * so these DTOs decode via the reflective KotlinJsonAdapterFactory registered on the shared Moshi in
 * NetworkModule.provideMoshi. The reflective factory maps Kotlin property names to JSON keys VERBATIM
 * (Moshi does NOT auto snake_case), so every wire key is pinned with an explicit @Json(name = ...).
 * @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * MONEY / TIME (wire contract): every monetary amount is a FLAT *_cents integer typed as Long (avoid Int
 * overflow; NO float, NO nested money object, NO currency / display string - currency is implicitly USD).
 * ends_at / created_at are EPOCH integers typed as Long (NOT ISO strings).
 *
 * STATUS: a boost's `status` is a FREE-FORM String here (NOT a network enum). The domain layer
 * (core-model BoostStatus) maps it to a typed enum with an UNKNOWN fallback; only "active" is exercised by
 * the web client (with Cancel + refund). Keeping the wire field a raw String makes it forward-compatible.
 *
 * WIRE CONTRACT (OpenAPI / frontend-corrected; endpoints under ui/ads/boost NOT ui/content/boost):
 *   POST ui/ads/boost                       body ContentBoostCreateIn -> ContentBoostOut
 *   GET  ui/ads/boost/{boostId}             -> ContentBoostOut
 *   GET  ui/ads/boost/{boostId}/spend       -> ContentBoostSpendOut
 *   POST ui/ads/boost/{boostId}/cancel      -> ContentBoostCancelOut (only while status == "active")
 *   GET  ui/ads/boost                       -> ContentBoostListResponse (optional convenience)
 */

/**
 * Create-boost request body. EXACTLY four fields - there is NO ads_account / payment_method / currency /
 * daily_budget (the server charges the wallet up-front; currency is implicitly USD integer cents). Both
 * `budget_cents` and `duration_seconds` are required and must be at least 1 (gated client-side too).
 */
data class ContentBoostCreateIn(
    @Json(name = "content_type") val contentType: String,
    @Json(name = "content_id") val contentId: String,
    @Json(name = "budget_cents") val budgetCents: Long,
    @Json(name = "duration_seconds") val durationSeconds: Long,
)

/**
 * One boost as returned by create / get. `boost_id` and `status` are the required structural keys; the
 * total `budget_cents` is required, while spent / remaining / duration / timestamps are optional (the
 * server may omit them depending on lifecycle). status is a FREE String (mapped to BoostStatus downstream).
 */
data class ContentBoostOut(
    @Json(name = "boost_id") val boostId: String,
    @Json(name = "status") val status: String,
    @Json(name = "content_type") val contentType: String? = null,
    @Json(name = "content_id") val contentId: String? = null,
    @Json(name = "budget_cents") val budgetCents: Long,
    @Json(name = "spent_cents") val spentCents: Long? = null,
    @Json(name = "remaining_cents") val remainingCents: Long? = null,
    @Json(name = "duration_seconds") val durationSeconds: Long? = null,
    @Json(name = "ends_at") val endsAt: Long? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)

/**
 * Lightweight spend snapshot returned by the spend endpoint. Both fields are optional flat *_cents Longs;
 * the boost id is echoed back when present.
 */
data class ContentBoostSpendOut(
    @Json(name = "boost_id") val boostId: String? = null,
    @Json(name = "spent_cents") val spentCents: Long? = null,
    @Json(name = "remaining_cents") val remainingCents: Long? = null,
)

/**
 * Cancel result. `refunded_cents` is the amount returned to the wallet on a cancel of an active boost; all
 * fields are optional since the server response shape is lenient.
 */
data class ContentBoostCancelOut(
    @Json(name = "boost_id") val boostId: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "refunded_cents") val refundedCents: Long? = null,
)

/**
 * Optional convenience list response. The server may envelope the boosts under either `items` or `boosts`;
 * both are tolerated (whichever is non-null wins). Included only because it is trivial - the list screen
 * is NOT part of AND-364's exercised flow.
 */
data class ContentBoostListResponse(
    @Json(name = "items") val items: List<ContentBoostOut>? = null,
    @Json(name = "boosts") val boosts: List<ContentBoostOut>? = null,
) {
    /** The boosts under whichever envelope key the server used (empty when neither is present). */
    val all: List<ContentBoostOut> get() = items ?: boosts ?: emptyList()
}
