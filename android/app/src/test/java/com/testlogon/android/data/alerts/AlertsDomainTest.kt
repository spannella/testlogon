package com.testlogon.android.data.alerts

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure DTO -> domain mapper tests for the alerts inbox. No ViewModel, no dispatcher rule.
 */
class AlertsDomainTest {

    @Test
    fun alertDto_withNullTsEventTitle_mapsWithoutThrowing_usingDefaults() {
        val dto = AlertDto(
            alertId = "a1",
            event = null,
            title = null,
            read = false,
            readAt = null,
            ts = null,
            priority = null,
            actionUrl = null,
            category = null,
        )

        val alert = dto.toDomain()

        assertEquals("a1", alert.id)
        assertEquals(0L, alert.timestampSeconds)
        assertEquals("", alert.event)
        assertEquals("", alert.title)
        assertEquals("", alert.category)
    }

    @Test
    fun alertDto_readFalse_mapsToUnread() {
        val dto = AlertDto(alertId = "a1", read = false, readAt = null)
        assertTrue(dto.toDomain().isUnread)
        assertNull(dto.toDomain().readAt)
    }

    @Test
    fun alertDto_readTrue_withReadAt_mapsToRead() {
        val dto = AlertDto(alertId = "a1", read = true, readAt = 1_700_000_000L)
        val alert = dto.toDomain()
        assertFalse(alert.isUnread)
        assertEquals(1_700_000_000L, alert.readAt)
    }

    @Test
    fun alertDto_priorityStrings_mapToPriorityEnum() {
        assertEquals(
            AlertPriority.URGENT,
            AlertDto(alertId = "a", priority = "urgent").toDomain().priority,
        )
        assertEquals(
            AlertPriority.LOW,
            AlertDto(alertId = "a", priority = "low").toDomain().priority,
        )
        assertEquals(
            AlertPriority.NORMAL,
            AlertDto(alertId = "a", priority = "normal").toDomain().priority,
        )
        assertEquals(
            AlertPriority.NORMAL,
            AlertDto(alertId = "a", priority = null).toDomain().priority,
        )
    }

    @Test
    fun alertsRespDto_filtersOutUnreadCountSentinelRow() {
        val resp = AlertsRespDto(
            alerts = listOf(
                AlertDto(alertId = "UNREAD_COUNT"),
                AlertDto(alertId = "real_1"),
                AlertDto(alertId = "real_2"),
            ),
            nextCursor = null,
        )

        val pageAlerts = resp.toDomain().alerts

        assertEquals(2, pageAlerts.size)
        assertEquals(listOf("real_1", "real_2"), pageAlerts.map { it.id })
        assertTrue(pageAlerts.none { it.id == "UNREAD_COUNT" })
    }

    @Test
    fun alertsRespDto_nextCursor_passesThrough() {
        val resp = AlertsRespDto(
            alerts = listOf(AlertDto(alertId = "real_1")),
            nextCursor = "cursor_abc",
        )
        assertEquals("cursor_abc", resp.toDomain().nextCursor)
    }
}
