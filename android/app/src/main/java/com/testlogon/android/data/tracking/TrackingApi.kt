package com.testlogon.android.data.tracking

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.Path

/**
 * AND-215 — Retrofit interface + DTOs for carrier tracking.
 *
 * Verified contract (reference/openapi.index.txt line 1772; reference/src/api/endpoints/carrierTracking.ts
 * getCarrierTracking; reference/src/api/types.ts CarrierTrackingView / CarrierEvent):
 *  - GET ui/purchase-history/transactions/{txn_id}/tracking -> CarrierTrackingView
 *
 * The OpenAPI 200 body is declared empty/untyped, so the AUTHORITATIVE shape is the frontend
 * `CarrierTrackingView` type. Notes vs the original draft:
 *  - The body is FLAT / single-shipment: top-level `txn_id`, a single `carrier` string code, events
 *    under `carrier_events` (no `shipments` array, no per-event `status`).
 *  - `delivered_at` and `last_carrier_check` are epoch SECONDS (numbers); `estimated_delivery` is an
 *    ISO string. We model the epoch-seconds fields as Long and parse the ISO field defensively.
 *  - A not-yet-shipped transaction returns null/absent carrier + tracking_number -> NotShipped.
 *
 * Read-only (no poll / mutations in this ticket; the web "refresh" POST poll is out of scope). The GET
 * is idempotent; session cookies + Authorization + X-CSRF-Token are attached by core-network.
 */
interface TrackingApi {

    @GET("ui/purchase-history/transactions/{txnId}/tracking")
    suspend fun getTracking(@Path("txnId") txnId: String): CarrierTrackingViewDto
}

/** Response body (schema CarrierTrackingView, frontend type — OpenAPI body is untyped). */
@JsonClass(generateAdapter = true)
data class CarrierTrackingViewDto(
    @Json(name = "txn_id") val txnId: String,
    @Json(name = "carrier") val carrier: String? = null,
    @Json(name = "tracking_number") val trackingNumber: String? = null,
    @Json(name = "tracking_url") val trackingUrl: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "status_description") val statusDescription: String? = null,
    // ISO-8601 string.
    @Json(name = "estimated_delivery") val estimatedDelivery: String? = null,
    // epoch SECONDS (number) or null.
    @Json(name = "delivered_at") val deliveredAt: Long? = null,
    @Json(name = "carrier_events") val carrierEvents: List<CarrierEventDto>? = null,
    // epoch SECONDS (number) or null.
    @Json(name = "last_carrier_check") val lastCarrierCheck: Long? = null,
)

/** One carrier event (schema CarrierEvent). NOTE: there is no per-event `status` field in the contract. */
@JsonClass(generateAdapter = true)
data class CarrierEventDto(
    // ISO-8601 string; nullable per contract.
    @Json(name = "timestamp") val timestamp: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "location") val location: String? = null,
)
