package com.testlogon.android.data.crm

import com.testlogon.android.data.crm.CrmSalesMath.LeadScoreBand
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * CRM-AND-LED — JVM unit tests for the pure lead-hygiene logic (email normalisation, duplicate
 * detection, merge-conflict resolution, score bucketing). No Android types; degrade-on-bad-input is
 * asserted so the UI never crashes on a 404 (module disabled) or dev-host drift.
 */
class LeadHygieneMathTest {

    private data class L(val id: String, val email: String?)

    // ── normalizeEmail / sameEmail ───────────────────────────────────────────

    @Test
    fun normalizeEmail_trimsAndLowercases() {
        assertEquals("a@b.com", LeadHygieneMath.normalizeEmail("  A@B.CoM "))
        assertEquals("", LeadHygieneMath.normalizeEmail(null))
        assertEquals("", LeadHygieneMath.normalizeEmail("   "))
    }

    @Test
    fun sameEmail_matchesIgnoringCaseAndSpace_butNotBlanks() {
        assertTrue(LeadHygieneMath.sameEmail("Foo@X.com", " foo@x.com "))
        assertFalse(LeadHygieneMath.sameEmail("a@x.com", "b@x.com"))
        assertFalse(LeadHygieneMath.sameEmail(null, null))
        assertFalse(LeadHygieneMath.sameEmail("", ""))
    }

    // ── duplicatesByEmail ────────────────────────────────────────────────────

    @Test
    fun duplicatesByEmail_returnsSameEmailExcludingSelf() {
        val primary = L("1", "Dup@x.com")
        val candidates = listOf(
            L("1", "dup@x.com"),   // self -> excluded
            L("2", "DUP@x.com"),   // match
            L("3", "other@x.com"), // no match
            L("4", "dup@x.com"),   // match
        )
        val dupes = LeadHygieneMath.duplicatesByEmail(primary, candidates, { it.id }, { it.email })
        assertEquals(listOf("2", "4"), dupes.map { it.id })
    }

    @Test
    fun duplicatesByEmail_blankPrimaryEmail_returnsEmpty() {
        val primary = L("1", "  ")
        val candidates = listOf(L("2", "x@y.com"))
        assertTrue(LeadHygieneMath.duplicatesByEmail(primary, candidates, { it.id }, { it.email }).isEmpty())
    }

    // ── resolveField ─────────────────────────────────────────────────────────

    @Test
    fun resolveField_primaryWinsWhenPresent() {
        assertEquals("Acme", LeadHygieneMath.resolveField("Acme", "Globex"))
        assertEquals("Acme", LeadHygieneMath.resolveField("  Acme ", "Globex"))
    }

    @Test
    fun resolveField_secondaryBackfillsBlankPrimary() {
        assertEquals("Globex", LeadHygieneMath.resolveField(null, "Globex"))
        assertEquals("Globex", LeadHygieneMath.resolveField("   ", "Globex"))
    }

    @Test
    fun resolveField_bothBlank_isNull() {
        assertNull(LeadHygieneMath.resolveField(null, null))
        assertNull(LeadHygieneMath.resolveField(" ", ""))
    }

    // ── mergeWouldChange ─────────────────────────────────────────────────────

    @Test
    fun mergeWouldChange_trueWhenSecondaryBackfillsBlank() {
        val primary = listOf("Ann", null, "")
        val secondary = listOf("X", "555-1212", "Acme")
        assertTrue(LeadHygieneMath.mergeWouldChange(primary, secondary))
    }

    @Test
    fun mergeWouldChange_falseWhenPrimaryComplete() {
        val primary = listOf("Ann", "555", "Acme")
        val secondary = listOf("X", "999", "Globex")
        assertFalse(LeadHygieneMath.mergeWouldChange(primary, secondary))
    }

    @Test
    fun mergeWouldChange_falseWhenSecondaryAlsoBlank() {
        assertFalse(LeadHygieneMath.mergeWouldChange(listOf(""), listOf("  ")))
    }

    // ── scoreBucket / maxAchievablePoints ────────────────────────────────────

    @Test
    fun scoreBucket_agreesWithSalesMathBands() {
        assertEquals(LeadScoreBand.COLD, LeadHygieneMath.scoreBucket(10, 100))
        assertEquals(LeadScoreBand.WARM, LeadHygieneMath.scoreBucket(50, 100))
        assertEquals(LeadScoreBand.HOT, LeadHygieneMath.scoreBucket(90, 100))
    }

    @Test
    fun scoreBucket_nonPositiveCapDegradesToDefault() {
        // maxScore <= 0 falls back to DEFAULT_MAX_SCORE (100): 90/100 -> HOT
        assertEquals(LeadScoreBand.HOT, LeadHygieneMath.scoreBucket(90, 0))
        assertEquals(LeadScoreBand.HOT, LeadHygieneMath.scoreBucket(90, -5))
    }

    @Test
    fun scoreBucket_respectsCustomCap() {
        // cap 20: score 18 -> 90% -> HOT
        assertEquals(LeadScoreBand.HOT, LeadHygieneMath.scoreBucket(18, 20))
    }

    @Test
    fun maxAchievablePoints_sumsPositivesClampedToCap() {
        assertEquals(45, LeadHygieneMath.maxAchievablePoints(listOf(10, 20, 15, -5), 100))
        assertEquals(20, LeadHygieneMath.maxAchievablePoints(listOf(10, 20, 15), 20)) // capped
        assertEquals(0, LeadHygieneMath.maxAchievablePoints(emptyList(), 100))
        assertEquals(0, LeadHygieneMath.maxAchievablePoints(listOf(-3, -1), 100))
    }
}
