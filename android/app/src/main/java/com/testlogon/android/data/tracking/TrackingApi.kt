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

/**
 * One carrier event (schema CarrierEvent).
 *
 * ECOMX selldash-E3: the E1/ECOMX-E3 tracking endpoint aggregates SHIP-GROUP events, emitted as
 * `{description, source, ts (epoch SECONDS), status}` — NOT the legacy `{timestamp (ISO), location}`
 * shape. Both are accepted here (all optional) so the timeline renders regardless of source; the domain
 * mapper prefers `ts` when present and falls back to the ISO `timestamp`.
 */
@JsonClass(generateAdapter = true)
data class CarrierEventDto(
    // ISO-8601 string; nullable per contract (legacy carrier-poll events).
    @Json(name = "timestamp") val timestamp: String? = null,
    // epoch SECONDS; ship-group events (seller_ship / runner progression) use this.
    @Json(name = "ts") val ts: Long? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "location") val location: String? = null,
    // Present on ship-group events (label_created / in_transit / ...); absent on legacy carrier events.
    @Json(name = "status") val status: String? = null,
)
