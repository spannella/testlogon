package com.testlogon.android.data.tracking

/**
 * AND-215 — framework-free domain models for carrier tracking. DTO -> domain mapping lives here so the
 * repository never leaks raw DTOs.
 *
 * Timestamps stay Long epoch MILLIS (JVM-safe; no java.time on the unit-tested path). Epoch-seconds
 * wire fields (`delivered_at`, `last_carrier_check`) are converted to millis; the ISO `estimated_delivery`
 * is parsed defensively to millis (null on failure). The contract is flat/single-shipment, so we expose
 * a single optional [Shipment].
 */

enum class ShipmentStatus {
    PRE_TRANSIT, LABEL_CREATED, IN_TRANSIT, OUT_FOR_DELIVERY,
    DELIVERED, EXCEPTION, RETURNED, UNKNOWN,
    ;

    companion object {
        /** Case-insensitive lookup; unrecognized -> [UNKNOWN] so dev-host drift never crashes the UI. */
        fun from(raw: String?): ShipmentStatus = when (raw?.lowercase()?.trim()) {
            "pre_transit", "pretransit" -> PRE_TRANSIT
            "label_created", "labelcreated" -> LABEL_CREATED
            "in_transit", "intransit" -> IN_TRANSIT
            "out_for_delivery", "outfordelivery" -> OUT_FOR_DELIVERY
            "delivered" -> DELIVERED
            "exception" -> EXCEPTION
            "returned" -> RETURNED
            else -> UNKNOWN
        }
    }
}

/** A carrier code + display name. */
data class Carrier(
    val code: String,
    val displayName: String,
)

/** One tracking event. Timestamp is epoch millis (0 when the wire value was missing/unparseable). */
data class TrackingEvent(
    val timestampEpochMs: Long,
    val description: String,
    val location: String?,
)

/** A single shipment's tracking state. */
data class Shipment(
    val carrier: Carrier,
    val trackingNumber: String?,
    val trackingUrl: String?,
    val status: ShipmentStatus,
    val statusDescription: String?,
    val estimatedDeliveryEpochMs: Long?,
    val deliveredAtEpochMs: Long?,
    val events: List<TrackingEvent>,
)

/** Per-transaction tracking. [shipment] is null when the transaction has not shipped. */
data class CarrierTracking(
    val txnId: String,
    val shipment: Shipment?,
)

// ---- Mappers ----

private fun carrierDisplayName(code: String?): String =
    code?.takeIf { it.isNotBlank() }?.uppercase() ?: "Carrier"

/**
 * Parses an ISO-8601 instant string to epoch millis without java.time (JVM-unit-test safe). Accepts the
 * common `...Z` UTC form the backend emits; returns null on any parse failure.
 */
internal fun parseIsoToEpochMs(iso: String?): Long? {
    if (iso.isNullOrBlank()) return null
    return try {
        // SimpleDateFormat is JVM-available and avoids the API-26 java.time gate.
        val fmt = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", java.util.Locale.US)
        fmt.timeZone = java.util.TimeZone.getTimeZone("UTC")
        // Strip trailing Z / fractional seconds / offset; keep seconds precision.
        val trimmed = iso.substringBefore('.').removeSuffix("Z").substringBefore('+')
        fmt.parse(trimmed)?.time
    } catch (_: Exception) {
        null
    }
}

internal fun CarrierEventDto.toDomain(): TrackingEvent = TrackingEvent(
    // ECOMX selldash-E3: ship-group events carry `ts` (epoch SECONDS); legacy carrier events carry the
    // ISO `timestamp`. Prefer ts (-> millis) and fall back to the parsed ISO string; 0 when neither.
    timestampEpochMs = ts?.let { it * 1000L } ?: parseIsoToEpochMs(timestamp) ?: 0L,
    description = description?.takeIf { it.isNotBlank() } ?: "",
    location = location?.takeIf { it.isNotBlank() },
)

/**
 * Maps the flat view into a [CarrierTracking]. When neither carrier nor tracking number is present, the
 * transaction has not shipped -> [CarrierTracking.shipment] is null. Events are sorted newest-first.
 */
internal fun CarrierTrackingViewDto.toDomain(): CarrierTracking {
    val hasShipment = !carrier.isNullOrBlank() || !trackingNumber.isNullOrBlank()
    if (!hasShipment) return CarrierTracking(txnId = txnId, shipment = null)

    val events = carrierEvents.orEmpty()
        .map { it.toDomain() }
        .sortedByDescending { it.timestampEpochMs }

    return CarrierTracking(
        txnId = txnId,
        shipment = Shipment(
            carrier = Carrier(code = carrier.orEmpty(), displayName = carrierDisplayName(carrier)),
            trackingNumber = trackingNumber?.takeIf { it.isNotBlank() },
            trackingUrl = trackingUrl?.takeIf { it.isNotBlank() },
            status = ShipmentStatus.from(status),
            statusDescription = statusDescription?.takeIf { it.isNotBlank() },
            estimatedDeliveryEpochMs = parseIsoToEpochMs(estimatedDelivery),
            // delivered_at / last_carrier_check are epoch SECONDS -> millis.
            deliveredAtEpochMs = deliveredAt?.let { it * 1000L },
            events = events,
        ),
    )
}
