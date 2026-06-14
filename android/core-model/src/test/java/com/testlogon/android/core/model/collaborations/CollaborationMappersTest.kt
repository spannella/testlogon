package com.testlogon.android.core.model.collaborations

import com.testlogon.android.core.model.syndicates.formatCents
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale

/**
 * AND-358 - unit tests for the core-model collaboration domain types: [CollabStatus.from] (UNKNOWN fallback),
 * [Collaboration.splitTotalsOk] (100 ok; 99 not ok), the viewer-share helper, and the REUSED [formatCents]
 * money helper (for the optional distribution amount_cents). Pure JVM; no Android, no Moshi.
 */
class CollaborationMappersTest {

    private fun collab(split: Map<String, Int>, status: String = "active") = Collaboration(
        id = "c1",
        title = "Track",
        status = status,
        statusEnum = CollabStatus.from(status),
        initiatorId = "usr_a",
        recipientId = "usr_b",
        split = split,
    )

    // ---- CollabStatus.from ----

    @Test
    fun status_parsesKnownTokens_caseAndWhitespaceInsensitive() {
        assertEquals(CollabStatus.ACTIVE, CollabStatus.from("active"))
        assertEquals(CollabStatus.PROPOSED, CollabStatus.from(" PROPOSED "))
        assertEquals(CollabStatus.COMPLETED, CollabStatus.from("Completed"))
    }

    @Test
    fun status_unknownOrNull_isUnknown_neverThrows() {
        assertEquals(CollabStatus.UNKNOWN, CollabStatus.from(null))
        assertEquals(CollabStatus.UNKNOWN, CollabStatus.from(""))
        // a free-string status the app does not know about -> UNKNOWN (the raw string is kept on the domain)
        assertEquals(CollabStatus.UNKNOWN, CollabStatus.from("some_custom_status"))
    }

    @Test
    fun unknownStatus_keepsRawStringOnDomain() {
        val c = collab(split = mapOf("usr_a" to 100), status = "some_custom_status")
        assertEquals(CollabStatus.UNKNOWN, c.statusEnum)
        assertEquals("some_custom_status", c.status)
    }

    // ---- splitTotalsOk ----

    @Test
    fun splitTotalsOk_sumsTo100_isOk() {
        val c = collab(split = mapOf("usr_a" to 60, "usr_b" to 40))
        assertEquals(100, c.splitTotalPercent)
        assertTrue(c.splitTotalsOk)
    }

    @Test
    fun splitTotalsOk_sumsTo99_isNotOk() {
        val c = collab(split = mapOf("usr_a" to 60, "usr_b" to 39))
        assertEquals(99, c.splitTotalPercent)
        assertFalse(c.splitTotalsOk)
    }

    @Test
    fun splitTotalsOk_emptySplit_isNotOk() {
        val c = collab(split = emptyMap())
        assertEquals(0, c.splitTotalPercent)
        assertFalse(c.splitTotalsOk)
    }

    // ---- viewer share ----

    @Test
    fun shareFor_returnsViewerPercent_whenPresent() {
        val c = collab(split = mapOf("usr_a" to 60, "usr_b" to 40))
        assertEquals(60, c.shareFor("usr_a"))
        assertEquals(40, c.shareFor("usr_b"))
    }

    @Test
    fun shareFor_returnsNull_whenViewerAbsentOrNull() {
        val c = collab(split = mapOf("usr_a" to 60, "usr_b" to 40))
        assertNull(c.shareFor("usr_x"))
        assertNull(c.shareFor(null))
    }

    @Test
    fun shares_oneRowPerSplitParty() {
        val c = collab(split = mapOf("usr_a" to 60, "usr_b" to 40))
        assertEquals(setOf("usr_a", "usr_b"), c.shares.map { it.userId }.toSet())
    }

    // ---- formatCents (REUSED from AND-356) for distribution amount_cents ----

    @Test
    fun formatCents_usd_enUs_formatsAmount() {
        assertEquals("$60.00", formatCents(6000, "USD", Locale.US))
    }
}
