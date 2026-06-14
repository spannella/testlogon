package com.testlogon.android.data.calendar.ics

import com.testlogon.android.feature.calendar.CalendarMath
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

/**
 * AND-276 — pure RFC 5545 serializer tests (JVM). Golden VEVENT structure, CRLF, UTC `Z` timestamps,
 * TEXT escaping, 75-octet UTF-8-aware folding, all-day VALUE=DATE (no off-by-one), RRULE/EXDATE, status
 * normalization, missing-optional omission, and builder validation. No java.time in the serializer path.
 */
class Rfc5545IcsSerializerTest {

    private val serializer = Rfc5545IcsSerializer()

    private fun millis(iso: String): Long = Instant.parse(iso).toEpochMilli()

    private val timed = IcsEvent(
        uid = "evt_8f12@testlogon.android",
        summary = "Q3 Content Review",
        description = "Agenda, notes",
        url = "http://18.222.237.167:8000/event/cal_1/evt_8f12",
        startEpochMillis = millis("2026-06-10T15:00:00Z"),
        endEpochMillis = millis("2026-06-10T16:00:00Z"),
        status = IcsStatus.CONFIRMED,
    )

    @Test
    fun timedEvent_goldenStructure_crlf_utc() {
        val out = serializer.serialize(listOf(timed))
        // CRLF line endings throughout.
        assertTrue(out.contains("\r\n"))
        assertFalse("must not contain a bare LF without CR", out.replace("\r\n", "").contains("\n"))

        val lines = out.split("\r\n")
        assertEquals("BEGIN:VCALENDAR", lines[0])
        assertEquals("VERSION:2.0", lines[1])
        assertEquals("PRODID:-//com.testlogon.android//TestLogon//EN", lines[2])
        assertEquals("CALSCALE:GREGORIAN", lines[3])
        assertTrue(out.contains("BEGIN:VEVENT\r\n"))
        assertTrue(out.contains("UID:evt_8f12@testlogon.android\r\n"))
        assertTrue(out.contains("DTSTART:20260610T150000Z\r\n"))
        assertTrue(out.contains("DTEND:20260610T160000Z\r\n"))
        assertTrue(out.contains("SUMMARY:Q3 Content Review\r\n"))
        assertTrue(out.contains("URL:http://18.222.237.167:8000/event/cal_1/evt_8f12\r\n"))
        assertTrue(out.contains("STATUS:CONFIRMED\r\n"))
        assertTrue(out.contains("END:VEVENT\r\n"))
        assertTrue(out.endsWith("END:VCALENDAR\r\n"))
        // No LOCATION line is ever emitted (no location in the verified DTOs).
        assertFalse(out.contains("LOCATION"))
    }

    @Test
    fun escaping_backslashSemicolonCommaNewline() {
        val ev = timed.copy(description = "back\\slash; semi, comma\nnewline")
        val out = serializer.serialize(listOf(ev))
        // Backslash escaped first, then ; , and \n.
        assertTrue(out.contains("DESCRIPTION:back\\\\slash\\; semi\\, comma\\nnewline"))
    }

    @Test
    fun folding_at75Octets_doesNotSplitMultibyte() {
        // A description with a long run of a 2-byte UTF-8 char (é = 0xC3 0xA9) forcing several folds.
        val longText = "é".repeat(120)
        val ev = timed.copy(description = longText)
        val out = serializer.serialize(listOf(ev))
        val allLines = out.split("\r\n")
        val descIndex = allLines.indexOfFirst { it.startsWith("DESCRIPTION:") }
        assertTrue(descIndex >= 0)
        // Collect the DESCRIPTION line plus its folded continuation lines (leading space).
        val folded = ArrayList<String>()
        folded += allLines[descIndex]
        var i = descIndex + 1
        while (i < allLines.size && allLines[i].startsWith(" ")) {
            folded += allLines[i]
            i++
        }
        assertTrue("expected multiple folded lines", folded.size > 1)
        // Every physical line is <= 75 octets.
        for (line in folded) {
            assertTrue("line over 75 octets: $line", line.toByteArray(Charsets.UTF_8).size <= 75)
        }
        // Unfold (RFC 5545: strip CRLF + the single leading continuation space) and round-trip.
        val rejoined = folded.first().removePrefix("DESCRIPTION:") +
            folded.drop(1).joinToString("") { it.removePrefix(" ") }
        assertEquals(longText, rejoined)
    }

    @Test
    fun allDay_valueDate_nextDayDtend_noOffByOne() {
        val day = CalendarMath.toEpochDay(2026, 7, 3)
        val ev = IcsEvent(
            uid = "evt_ad@testlogon.android",
            summary = "Company holiday",
            allDay = true,
            allDayEpochDay = day,
        )
        val out = serializer.serialize(listOf(ev))
        assertTrue(out.contains("DTSTART;VALUE=DATE:20260703\r\n"))
        // DTEND is the EXCLUSIVE next day.
        assertTrue(out.contains("DTEND;VALUE=DATE:20260704\r\n"))
        assertFalse(out.contains("DTSTART:2026")) // no timed DTSTART
        // No timed DTSTART/DTEND for an all-day event (DTSTAMP legitimately carries a UTC time).
        assertFalse(out.contains("DTSTART:"))
        assertFalse(out.contains("DTEND:"))
    }

    @Test
    fun recurrence_rrule_and_exdate() {
        val ev = timed.copy(
            rrule = "FREQ=WEEKLY;BYDAY=MO;COUNT=8",
            exDatesEpochMillis = listOf(millis("2026-06-15T15:00:00Z"), millis("2026-06-22T15:00:00Z")),
        )
        val out = serializer.serialize(listOf(ev))
        assertTrue(out.contains("RRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=8\r\n"))
        assertTrue(out.contains("EXDATE:20260615T150000Z,20260622T150000Z\r\n"))
    }

    @Test
    fun status_emittedFromEnum_andDescriptionOmittedWhenNull() {
        val ev = IcsEvent(
            uid = "evt_c@testlogon.android",
            summary = "Cancelled meeting",
            startEpochMillis = millis("2026-06-10T15:00:00Z"),
            description = null,
            status = IcsStatus.CANCELLED,
        )
        val out = serializer.serialize(listOf(ev))
        assertTrue(out.contains("STATUS:CANCELLED\r\n"))
        // A null description never emits an empty DESCRIPTION line.
        assertFalse(out.contains("DESCRIPTION:"))
        // A missing end omits DTEND.
        assertFalse(out.contains("DTEND"))
    }

    @Test
    fun blankUid_throwsGuardedError_notCrashElsewhere() {
        val ev = timed.copy(uid = "")
        assertThrows(IllegalArgumentException::class.java) { serializer.serialize(listOf(ev)) }
    }

    @Test
    fun formatUtc_isTimezoneIndependent() {
        // Pure arithmetic: the same epoch always yields the same Z string regardless of host TZ.
        assertEquals("20260610T150000Z", serializer.formatUtc(millis("2026-06-10T15:00:00Z")))
        assertEquals("19700101T000000Z", serializer.formatUtc(0L))
    }
}
