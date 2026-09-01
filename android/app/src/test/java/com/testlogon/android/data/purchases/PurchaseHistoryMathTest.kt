package com.testlogon.android.data.purchases

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-218-extras — JVM unit tests for the pure purchase-history extras logic (event labels/timeline,
 * receipt openability, tracking step/label/progress formatting). No Android types; degrade-on-empty and
 * degrade-on-bad-input are asserted so the UI never crashes on dev-host drift / 404.
 */
class PurchaseHistoryMathTest {

    // ---- event labels ----

    @Test
    fun eventLabel_knownNames_mapToCuratedLabels() {
        assertEquals("Order created", purchaseEventLabel("created"))
        assertEquals("Payment completed", purchaseEventLabel("completed"))
        assertEquals("Refunded", purchaseEventLabel("reverted"))
        assertEquals("Cancellation requested", purchaseEventLabel("cancel_requested"))
        assertEquals("Shipping updated", purchaseEventLabel("shipping_updated"))
    }

    @Test
    fun eventLabel_isCaseInsensitive_andTrims() {
        assertEquals("Payment completed", purchaseEventLabel("  COMPLETED "))
    }

    @Test
    fun eventLabel_unknownName_titleCasesFromSnake() {
        assertEquals("Weird custom event", purchaseEventLabel("weird_custom_event"))
    }

    @Test
    fun eventLabel_nullOrBlank_fallsBackToUpdate() {
        assertEquals("Update", purchaseEventLabel(null))
        assertEquals("Update", purchaseEventLabel("   "))
    }

    // ---- payload detail extraction ----

    @Test
    fun eventDetail_prefersNoteThenReason_ignoresNonStrings() {
        assertEquals("hello", eventDetailFromPayload(mapOf("note" to "hello", "reason" to "x")))
        assertEquals("because", eventDetailFromPayload(mapOf("reason" to "because")))
        // non-string values are skipped, not rendered
        assertNull(eventDetailFromPayload(mapOf("note" to 42, "amount" to 5.0)))
        assertNull(eventDetailFromPayload(null))
        assertNull(eventDetailFromPayload(emptyMap()))
    }

    // ---- timeline mapping / sorting ----

    @Test
    fun timeline_mapsSortsNewestFirst_andPreservesDetail() {
        val dto = PurchaseEventsResponseDto(
            txnId = "txn_1",
            events = listOf(
                PurchaseEventDto(eventName = "created", createdAt = 100L, payload = null),
                PurchaseEventDto(eventName = "completed", createdAt = 300L, payload = mapOf("note" to "done")),
                PurchaseEventDto(eventName = "shipped", createdAt = 200L, payload = null),
            ),
        )
        val timeline = dto.toTimeline()
        assertEquals(3, timeline.size)
        assertEquals("Payment completed", timeline[0].label)
        assertEquals(300L, timeline[0].atEpochSec)
        assertEquals("done", timeline[0].detail)
        assertEquals("Shipped", timeline[1].label)
        assertEquals("Order created", timeline[2].label)
    }

    @Test
    fun timeline_nullOrEmptyEvents_degradesToEmptyList() {
        assertTrue(PurchaseEventsResponseDto(txnId = "t", events = null).toTimeline().isEmpty())
        assertTrue(PurchaseEventsResponseDto(txnId = "t", events = emptyList()).toTimeline().isEmpty())
    }

    @Test
    fun timeline_zeroTimestamp_isTreatedAsNull_andSortsLast() {
        val dto = PurchaseEventsResponseDto(
            events = listOf(
                PurchaseEventDto(eventName = "created", createdAt = 0L),
                PurchaseEventDto(eventName = "completed", createdAt = 500L),
            ),
        )
        val timeline = dto.toTimeline()
        assertNull(timeline.last().atEpochSec)
        assertEquals("Payment completed", timeline.first().label)
    }

    // ---- receipt ----

    @Test
    fun receipt_absoluteHttpsUrl_isOpenable() {
        val r = PurchaseReceiptDto(
            receiptUrl = "https://host/v1/fs/download?path=x",
            generatedAt = 1748451851L,
        ).toReceiptOrNull()
        assertTrue(r != null && r.isOpenable)
        assertEquals(1748451851L, r!!.generatedAtEpochSec)
    }

    @Test
    fun receipt_relativeOrBlankUrl_isNotOpenable() {
        val rel = PurchaseReceiptDto(receiptUrl = "/v1/fs/download?path=x", generatedAt = 10L).toReceiptOrNull()
        assertTrue(rel != null && !rel.isOpenable)
        val blank = PurchaseReceiptDto(receiptUrl = "   ", generatedAt = 10L).toReceiptOrNull()
        // blank url collapses to null url but the timestamp keeps the receipt present + not openable
        assertTrue(blank != null && !blank.isOpenable)
    }

    @Test
    fun receipt_emptyDto_degradesToNull() {
        assertNull(PurchaseReceiptDto().toReceiptOrNull())
        assertNull(PurchaseReceiptDto(receiptUrl = "  ", generatedAt = 0L).toReceiptOrNull())
    }

    @Test
    fun isOpenableUrl_acceptsHttpAndHttps_rejectsOthers() {
        assertTrue(isOpenableUrl("http://x"))
        assertTrue(isOpenableUrl("HTTPS://X"))
        assertFalse(isOpenableUrl("ftp://x"))
        assertFalse(isOpenableUrl("testlogon://library/1"))
        assertFalse(isOpenableUrl(null))
    }

    // ---- tracking step / progress ----

    @Test
    fun trackingStep_fromStatus_isCaseInsensitive_unknownFallback() {
        assertEquals(TrackingStep.IN_TRANSIT, trackingStepFromStatus("In_Transit"))
        assertEquals(TrackingStep.DELIVERED, trackingStepFromStatus("delivered"))
        assertEquals(TrackingStep.UNKNOWN, trackingStepFromStatus("banana"))
        assertEquals(TrackingStep.UNKNOWN, trackingStepFromStatus(null))
    }

    @Test
    fun trackingStepLabel_coversAllSteps() {
        assertEquals("In transit", trackingStepLabel(TrackingStep.IN_TRANSIT))
        assertEquals("Out for delivery", trackingStepLabel(TrackingStep.OUT_FOR_DELIVERY))
        assertEquals("Delivered", trackingStepLabel(TrackingStep.DELIVERED))
        assertEquals("Exception", trackingStepLabel(TrackingStep.EXCEPTION))
    }

    @Test
    fun trackingProgressFraction_happyPath_andOffPath() {
        assertEquals(0f, trackingProgressFraction("pre_transit"), 0.0001f)
        assertEquals(0.5f, trackingProgressFraction("in_transit"), 0.0001f)
        assertEquals(1f, trackingProgressFraction("delivered"), 0.0001f)
        // off-path / unknown -> 0
        assertEquals(0f, trackingProgressFraction("exception"), 0.0001f)
        assertEquals(0f, trackingProgressFraction("banana"), 0.0001f)
    }

    @Test
    fun trackingStep_stepIndex_matchesOrdering() {
        assertEquals(0, TrackingStep.PRE_TRANSIT.stepIndex)
        assertEquals(4, TrackingStep.DELIVERED.stepIndex)
        assertEquals(-1, TrackingStep.UNKNOWN.stepIndex)
        assertEquals(TRACKING_STEP_COUNT, 5)
    }
}
