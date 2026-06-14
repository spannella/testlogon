package com.testlogon.android.data.admin

import com.testlogon.android.core.model.admin.DashboardChannel
import com.testlogon.android.core.model.admin.DeliveryStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-404 - mapper unit tests (TC-06/TC-07): DTO -> domain including rate-as-percentage formatting, SMS having
 * NO bounced card, null/absent numeric defaults, recipient MASKING (email/phone), the EPOCH-SECONDS timestamp
 * (NOT ISO parse), the derived stable row key (no `id` on the wire), the open-status UNKNOWN fallback, and the
 * derived emptiness. Pure JVM (no Android, no network).
 */
class MessagingDashboardMappersTest {

    // ---- status mapping (open string -> UNKNOWN fallback, never throws) ----

    @Test
    fun statusMapping_knownAndUnknown() {
        assertEquals(DeliveryStatus.DELIVERED, mapDeliveryStatus("delivered"))
        assertEquals(DeliveryStatus.DELIVERED, mapDeliveryStatus("DELIVERED"))
        assertEquals(DeliveryStatus.BOUNCED, mapDeliveryStatus("bounced"))
        assertEquals(DeliveryStatus.FAILED, mapDeliveryStatus("undelivered"))
        assertEquals(DeliveryStatus.PENDING, mapDeliveryStatus("queued"))
        assertEquals(DeliveryStatus.UNKNOWN, mapDeliveryStatus(null))
        assertEquals(DeliveryStatus.UNKNOWN, mapDeliveryStatus("totally_new_state"))
    }

    // ---- masking ----

    @Test
    fun maskEmail_masksLocalAndDomainKeepsTld() {
        assertEquals("j***@e***.com", maskEmail("jane@example.com"))
        // "sub.co.uk" -> host "sub.co", tld ".uk" (lastIndexOf('.')); first char of host is 's'.
        assertEquals("b***@s***.uk", maskEmail("bob@sub.co.uk"))
    }

    @Test
    fun maskEmail_malformedYieldsPlaceholder_noLeak() {
        assertFalse(maskEmail("not-an-email").contains("not-an-email"))
        assertFalse(maskEmail(null).contains("@"))
        assertFalse(maskEmail("").contains("@"))
    }

    @Test
    fun maskPhone_revealsOnlyLast4() {
        val masked = maskPhone("+15551234821")
        assertTrue(masked.endsWith("4821"))
        assertFalse(masked.contains("5551"))
    }

    @Test
    fun maskPhone_tooShortYieldsPlaceholder() {
        assertFalse(maskPhone("12").contains("12"))
        assertFalse(maskPhone(null).contains("0"))
    }

    // ---- delivery item -> activity (epoch seconds, stable key, channel-specific recipient/detail) ----

    @Test
    fun toDeliveryActivity_email_usesEpochSecondsAndSubjectDetail() {
        val item = DeliveryItemDto(
            toEmail = "jane@example.com",
            subject = "Welcome",
            status = "delivered",
            createdAt = 1_749_132_131L,
        )
        val row = toDeliveryActivity(item, DashboardChannel.EMAIL, index = 0)
        assertEquals("j***@e***.com", row.maskedRecipient)
        assertEquals(DeliveryStatus.DELIVERED, row.status)
        assertEquals("Welcome", row.detail)
        // EPOCH SECONDS retained verbatim (the UI multiplies by 1000 for DateUtils, no ISO parse here).
        assertEquals(1_749_132_131L, row.createdAtEpochSeconds)
        // Stable key derived from masked recipient + createdAt (the wire item has no id).
        assertEquals("j***@e***.com@1749132131", row.key)
    }

    @Test
    fun toDeliveryActivity_sms_masksPhone_usesErrorDetail() {
        val item = DeliveryItemDto(phone = "+15551234821", status = "failed", error = "carrier rejected")
        val row = toDeliveryActivity(item, DashboardChannel.SMS, index = 3)
        assertTrue(row.maskedRecipient.endsWith("4821"))
        assertEquals(DeliveryStatus.FAILED, row.status)
        assertEquals("carrier rejected", row.detail)
    }

    @Test
    fun toDeliveryActivity_nullRecipient_safePlaceholder_indexKey() {
        val item = DeliveryItemDto(status = "sent", createdAt = null)
        val row = toDeliveryActivity(item, DashboardChannel.EMAIL, index = 7)
        assertFalse(row.maskedRecipient.contains("@example"))
        // No createdAt -> key falls back to the index.
        assertTrue(row.key.endsWith("#7"))
    }

    // ---- dashboard build (percentages, SMS no-bounced, defaults, emptiness) ----

    @Test
    fun toEmailDashboard_ratesAsPercent_andHasBounced() {
        val stats = EmailStatsDto(sent = 12840, delivered = 12111, bounced = 412, failed = 96, deliveryRate = 94.3)
        val dashboard = toEmailDashboard(stats, DeliveryListDto())
        val rate = dashboard.metrics.first { it.key == METRIC_MSG_DELIVERY_RATE }
        // Treated as a percentage (94.3%), NOT 9430%.
        assertTrue(rate.value.contains("94.3"))
        assertTrue(rate.value.endsWith("%"))
        assertTrue(dashboard.metrics.any { it.key == METRIC_MSG_BOUNCED })
        assertEquals(94.3, dashboard.deliveryRatePct!!, 0.001)
        assertFalse(dashboard.isEmpty)
    }

    @Test
    fun toSmsDashboard_noBouncedCard_hasSegments() {
        val stats = SmsStatsDto(sent = 4210, delivered = 4001, failed = 209, totalSegments = 5120, deliveryRate = 95.0)
        val dashboard = toSmsDashboard(stats, DeliveryListDto())
        assertFalse(dashboard.metrics.any { it.key == METRIC_MSG_BOUNCED })
        assertTrue(dashboard.metrics.any { it.key == METRIC_MSG_SEGMENTS })
        assertFalse(dashboard.isEmpty)
    }

    @Test
    fun toEmailDashboard_nullDefaults_allZero_isEmpty() {
        val dashboard = toEmailDashboard(EmailStatsDto(), DeliveryListDto())
        // Absent numeric fields default to 0.
        assertEquals("0", dashboard.metrics.first { it.key == METRIC_MSG_SENT }.value)
        assertTrue(dashboard.allZeroStats)
        assertTrue(dashboard.isEmpty)
        assertNull(dashboard.activity.firstOrNull())
    }
}
