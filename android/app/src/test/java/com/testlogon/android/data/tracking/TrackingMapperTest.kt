package com.testlogon.android.data.tracking

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-215 / AND-217 — mapper + enum coverage for [CarrierTrackingViewDto.toDomain] and
 * [ShipmentStatus.from]: happy path, epoch-seconds conversion, unknown status, not-shipped, carrier
 * display fallback, and newest-first event ordering.
 */
class TrackingMapperTest {

    @Test
    fun happyPath_mapsCarrierStatusEventsSortedNewestFirst() {
        val dto = CarrierTrackingViewDto(
            txnId = "txn_1",
            carrier = "ups",
            trackingNumber = "1Z999",
            trackingUrl = "https://ups.com/track",
            status = "in_transit",
            statusDescription = "Departed facility",
            estimatedDelivery = "2026-06-09T00:00:00Z",
            deliveredAt = null,
            carrierEvents = listOf(
                CarrierEventDto("2026-06-06T14:22:00Z", "Departed facility", "Columbus, OH, US"),
                CarrierEventDto("2026-06-07T08:00:00Z", "Arrived hub", "Dayton, OH, US"),
            ),
            lastCarrierCheck = 1749218400,
        )
        val tracking = dto.toDomain()
        val shipment = requireNotNull(tracking.shipment)
        assertEquals("ups", shipment.carrier.code)
        assertEquals("UPS", shipment.carrier.displayName)
        assertEquals(ShipmentStatus.IN_TRANSIT, shipment.status)
        assertEquals("1Z999", shipment.trackingNumber)
        // Newest first: the 06-07 event precedes the 06-06 event.
        assertEquals("Arrived hub", shipment.events[0].description)
        assertEquals("Departed facility", shipment.events[1].description)
        assertNull(shipment.deliveredAtEpochMs)
    }

    @Test
    fun epochSeconds_deliveredAt_convertsToMillis_andUnknownStatus() {
        val dto = CarrierTrackingViewDto(
            txnId = "txn_2",
            carrier = "fedex",
            status = "warp_speed", // unrecognized
            deliveredAt = 1749218400, // epoch seconds
            estimatedDelivery = "not-a-date",
        )
        val shipment = requireNotNull(dto.toDomain().shipment)
        assertEquals(ShipmentStatus.UNKNOWN, shipment.status)
        assertEquals(1749218400L * 1000L, shipment.deliveredAtEpochMs)
        assertNull(shipment.estimatedDeliveryEpochMs) // unparseable -> null, no crash
    }

    @Test
    fun notShipped_whenCarrierAndTrackingNull_yieldsNullShipment() {
        val dto = CarrierTrackingViewDto(txnId = "txn_3", carrier = null, trackingNumber = null)
        val tracking = dto.toDomain()
        assertNull(tracking.shipment)
        assertEquals("txn_3", tracking.txnId)
    }

    @Test
    fun statusDescriptionPreferred_andCarrierFallback() {
        // carrier present but blank-ish handling: a blank carrier with a tracking number still shows.
        val dto = CarrierTrackingViewDto(
            txnId = "txn_4",
            carrier = "",
            trackingNumber = "TN-1",
            status = "delivered",
            statusDescription = "Delivered to porch",
        )
        val shipment = requireNotNull(dto.toDomain().shipment)
        assertEquals("Carrier", shipment.carrier.displayName) // blank code -> fallback
        assertEquals("Delivered to porch", shipment.statusDescription)
        assertEquals(ShipmentStatus.DELIVERED, shipment.status)
    }

    @Test
    fun statusFrom_isCaseInsensitive() {
        assertEquals(ShipmentStatus.OUT_FOR_DELIVERY, ShipmentStatus.from("OUT_FOR_DELIVERY"))
        assertEquals(ShipmentStatus.LABEL_CREATED, ShipmentStatus.from("label_created"))
        assertEquals(ShipmentStatus.UNKNOWN, ShipmentStatus.from(null))
    }

    @Test
    fun isoParse_handlesZSuffix() {
        val ms = parseIsoToEpochMs("2026-06-09T00:00:00Z")
        assertTrue(ms != null && ms > 0L)
    }
}
