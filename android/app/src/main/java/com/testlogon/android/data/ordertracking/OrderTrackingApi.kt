package com.testlogon.android.data.ordertracking

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.data.tracking.Carrier
import com.testlogon.android.data.tracking.CarrierTracking
import com.testlogon.android.data.tracking.Shipment
import com.testlogon.android.data.tracking.ShipmentStatus
import com.testlogon.android.data.tracking.TrackingEvent
import retrofit2.http.GET
import retrofit2.http.Path

/**
 * D4 - BUYER order shipment-tracking, keyed by ship-group id.
 *
 * Backend (LIVE hotfix, ecom-ship D4): GET ui/orders/tracking/{ship_group_id} -> TrackingOut
 * (buyer-scoped; 404 when the caller is not the buyer). Shape:
 *   { ship_group_id, order_id, carrier, tracking_number, tracking_url, status,
 *     events:[{ ts(epoch s), status, location, description, source }], created_at, updated_at }
 *
 * We map into the SHARED [CarrierTracking]/[Shipment] domain so the proven tracking UI is reused.
 * The buyer alert deep-links here via action_url /orders?order=..&ship_group=..&track=1.
 */
interface OrderTrackingApi {
    @GET("ui/orders/tracking/{shipGroupId}")
    suspend fun getOrderTracking(@Path("shipGroupId") shipGroupId: String): OrderTrackingDto
}

@JsonClass(generateAdapter = true)
data class OrderTrackingDto(
    @Json(name = "ship_group_id") val shipGroupId: String = "",
    @Json(name = "order_id") val orderId: String = "",
    @Json(name = "carrier") val carrier: String = "",
    @Json(name = "tracking_number") val trackingNumber: String = "",
    @Json(name = "tracking_url") val trackingUrl: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "events") val events: List<OrderTrackingEventDto> = emptyList(),
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class OrderTrackingEventDto(
    // epoch SECONDS.
    @Json(name = "ts") val ts: Long = 0,
    @Json(name = "status") val status: String = "",
    @Json(name = "location") val location: String = "",
    @Json(name = "description") val description: String = "",
    @Json(name = "source") val source: String = "",
)

/** Human label fallback for an event with no description (mirrors the status vocabulary). */
private fun statusHumanLabel(status: String): String = when (status.lowercase().trim()) {
    "label_created" -> "Shipping label created"
    "in_transit" -> "In transit"
    "out_for_delivery" -> "Out for delivery"
    "delivered" -> "Delivered"
    "exception" -> "Delivery exception"
    else -> status
}

internal fun OrderTrackingDto.toDomain(): CarrierTracking {
    val hasShipment = carrier.isNotBlank() || trackingNumber.isNotBlank()
    if (!hasShipment) return CarrierTracking(txnId = shipGroupId, shipment = null)
    val domainStatus = ShipmentStatus.from(status)
    val events = events
        .map { e ->
            TrackingEvent(
                timestampEpochMs = if (e.ts > 0) e.ts * 1000L else 0L,
                description = e.description.ifBlank { statusHumanLabel(e.status.ifBlank { status }) },
                location = e.location.takeIf { it.isNotBlank() },
            )
        }
        .sortedByDescending { it.timestampEpochMs }
    val deliveredMs = if (domainStatus == ShipmentStatus.DELIVERED) {
        events.firstOrNull()?.timestampEpochMs?.takeIf { it > 0 }
    } else {
        null
    }
    return CarrierTracking(
        txnId = shipGroupId,
        shipment = Shipment(
            carrier = Carrier(code = carrier, displayName = carrier.ifBlank { "Carrier" }.uppercase()),
            trackingNumber = trackingNumber.takeIf { it.isNotBlank() },
            trackingUrl = trackingUrl.takeIf { it.isNotBlank() },
            status = domainStatus,
            statusDescription = null,
            estimatedDeliveryEpochMs = null,
            deliveredAtEpochMs = deliveredMs,
            events = events,
        ),
    )
}
