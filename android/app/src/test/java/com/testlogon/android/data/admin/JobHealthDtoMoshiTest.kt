package com.testlogon.android.data.admin

import com.testlogon.android.testutil.testMoshi
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Contract lock (2026-07-21): JobHealthEntryDto was changed from a `data class` to a plain `class`
 * to eliminate a Kotlin 2.0.21 K2 JVM-backend codegen OOM on its generated 12-property equals()
 * (which was intermittently reddening the money-unit CI gate). This test proves that change did NOT
 * alter the Moshi wire contract: every @Json field name still round-trips, and absent optional keys
 * still fall back to their defaults. Uses the codegen adapter (@JsonClass) via the reflective
 * fallback factory so the test is self-contained.
 */
class JobHealthDtoMoshiTest {

    private val moshi = testMoshi()

    @Test
    fun jobHealthEntry_deserializesEveryWireKey() {
        val json = """
            {
              "name": "reconcile_ledger",
              "label": "Ledger reconcile",
              "description": "Nightly ledger reconcile",
              "health": "degraded",
              "last_status": "partial",
              "last_run_at": 1721500000,
              "last_finished_at": 1721500123,
              "last_error": "3 rows skipped",
              "last_items_processed": 998,
              "last_items_failed": 2,
              "next_run_at": 1721586400
            }
        """.trimIndent()

        val dto = moshi.adapter(JobHealthEntryDto::class.java).fromJson(json)!!
        assertEquals("reconcile_ledger", dto.name)
        assertEquals("Ledger reconcile", dto.label)
        assertEquals("Nightly ledger reconcile", dto.description)
        assertEquals("degraded", dto.health)
        assertEquals("partial", dto.lastStatus)
        assertEquals(1721500000L, dto.lastRunAt)
        assertEquals(1721500123L, dto.lastFinishedAt)
        assertEquals("3 rows skipped", dto.lastError)
        assertEquals(998L, dto.lastItemsProcessed)
        assertEquals(2L, dto.lastItemsFailed)
        assertEquals(1721586400L, dto.nextRunAt)
    }

    @Test
    fun jobHealthEntry_minimalBody_appliesDefaults() {
        // Only the single required wire key `name` is present; every other field must default.
        val dto = moshi.adapter(JobHealthEntryDto::class.java)
            .fromJson("""{ "name": "solo" }""")!!
        assertEquals("solo", dto.name)
        assertEquals("", dto.label)
        assertEquals("", dto.description)
        assertEquals("unknown", dto.health)
        assertNull(dto.lastStatus)
        assertNull(dto.lastRunAt)
        assertNull(dto.lastFinishedAt)
        assertNull(dto.lastError)
        assertEquals(0L, dto.lastItemsProcessed)
        assertEquals(0L, dto.lastItemsFailed)
        assertNull(dto.nextRunAt)
    }

    @Test
    fun jobHealthEnvelope_roundTripsJobsAndTimestamp() {
        val json = """
            {
              "jobs": [
                { "name": "a", "health": "healthy" },
                { "name": "b", "health": "failed", "last_error": "boom" }
              ],
              "timestamp": 1721599999
            }
        """.trimIndent()
        val dto = moshi.adapter(JobHealthDto::class.java).fromJson(json)!!
        assertEquals(2, dto.jobs.size)
        assertEquals("a", dto.jobs[0].name)
        assertEquals("boom", dto.jobs[1].lastError)
        assertEquals(1721599999L, dto.timestamp)
    }
}
