package com.testlogon.android.data.contentcalendar

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.time.Instant

/** AND-274 — pure mapper tests (epoch-seconds conversion + enum tolerance). */
class ContentCalendarMapperTest {

    @Test
    fun mapsEpochSecondsAndKnownEnums() {
        val dto = ContentCalendarItemDto(
            id = "cnt_1",
            type = "post",
            title = "Newsletter",
            scheduledAt = 1781445600L,
            timezone = "America/New_York",
            localTime = "10:00 AM",
            status = "scheduled",
            color = "#3b82f6",
            icon = "calendar",
        )
        val domain = dto.toDomain()
        assertEquals(Instant.ofEpochSecond(1781445600L), domain.scheduledAt)
        assertEquals(ContentItemType.POST, domain.type)
        assertEquals(ScheduledStatus.SCHEDULED, domain.status)
        assertEquals("10:00 AM", domain.localTime)
    }

    @Test
    fun tolerantEnums_unknownMapsToUnknown_noThrow() {
        assertEquals(ContentItemType.UNKNOWN, "reel".toContentItemType())
        assertEquals(ContentItemType.VOD, "vod".toContentItemType())
        assertEquals(ContentItemType.BROADCAST, "broadcast".toContentItemType())
        assertEquals(ScheduledStatus.UNKNOWN, (null as String?).toScheduledStatus())
        assertEquals(ScheduledStatus.OVERDUE, "overdue".toScheduledStatus())
        assertEquals(ScheduledStatus.CANCELLED, "canceled".toScheduledStatus())
    }

    @Test
    fun nullableOptionals_mapThrough() {
        val dto = ContentCalendarItemDto(
            id = "cnt_2",
            type = "broadcast",
            title = "Teaser",
            scheduledAt = 1781618400L,
            timezone = null,
            localTime = null,
            status = "overdue",
            description = "Go-live teaser",
        )
        val domain = dto.toDomain()
        assertNull(domain.timezone)
        assertNull(domain.localTime)
        assertEquals("Go-live teaser", domain.description)
        assertEquals(ScheduledStatus.OVERDUE, domain.status)
    }
}
