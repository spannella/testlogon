package com.testlogon.android.data.entitlements

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.Query

/**
 * ECOMX-43 (B5) — the buyer's own entitlements (digital library). GET /v1/entitlements returns the
 * caller's granted products (product_type / sku / status / scope / order_id). The library surface + the
 * per-order "digital items" card filter this list client-side (the endpoint has no order_id filter).
 * Session cookie + Bearer + CSRF are attached by the core-network interceptor chain.
 */
interface OrderEntitlementsApi {

    @GET("v1/entitlements")
    suspend fun listEntitlements(
        @Query("status") status: String? = null,
        @Query("product_type") productType: String? = null,
    ): List<EntitlementDto>
}

@JsonClass(generateAdapter = true)
data class EntitlementDto(
    @Json(name = "entitlement_id") val entitlementId: String? = null,
    @Json(name = "sku") val sku: String? = null,
    @Json(name = "product_type") val productType: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "order_id") val orderId: String? = null,
    @Json(name = "starts_at") val startsAt: String? = null,
    @Json(name = "ends_at") val endsAt: String? = null,
    @Json(name = "scope") val scope: Map<String, Any?>? = null,
)
