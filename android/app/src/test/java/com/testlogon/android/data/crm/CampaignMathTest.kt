package com.testlogon.android.data.crm

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * CMP — JVM unit tests for the pure Campaign logic (send eligibility, A/B split, merge-var
 * validation, budget parsing). No Android types; degrade-on-bad-input is asserted so the UI never
 * crashes on a 404 (module disabled) or dev-host drift.
 */
class CampaignMathTest {

    // ── Send eligibility ──────────────────────────────────────────────────────

    @Test
    fun hasAudience_countsListsAndSegmentsIgnoringBlanks() {
        assertFalse(CampaignMath.hasAudience(null, null))
        assertFalse(CampaignMath.hasAudience(emptyList(), emptyList()))
        assertFalse(CampaignMath.hasAudience(listOf("", "  "), listOf("")))
        assertTrue(CampaignMath.hasAudience(listOf("l1"), null))
        assertTrue(CampaignMath.hasAudience(null, listOf("s1")))
        assertEquals(3, CampaignMath.audienceSourceCount(listOf("l1", "l2"), listOf("s1")))
    }

    @Test
    fun canSend_requiresAudienceAndNonTerminalStatus() {
        assertTrue(CampaignMath.canSend("draft", listOf("l1"), null))
        assertTrue(CampaignMath.canSend(null, listOf("l1"), null))
        assertTrue(CampaignMath.canSend("", null, listOf("s1")))
        // no audience blocks
        assertFalse(CampaignMath.canSend("draft", null, null))
        // terminal status blocks
        assertFalse(CampaignMath.canSend("sent", listOf("l1"), null))
        assertFalse(CampaignMath.canSend("COMPLETED", listOf("l1"), null))
        assertFalse(CampaignMath.canSend("cancelled", listOf("l1"), null))
    }

    @Test
    fun sendBlockedReason_explainsWhy() {
        assertEquals(
            "Add a contact list or segment before sending.",
            CampaignMath.sendBlockedReason("draft", null, null),
        )
        assertEquals(
            "This campaign has already been sent.",
            CampaignMath.sendBlockedReason("sent", listOf("l1"), null),
        )
        assertNull(CampaignMath.sendBlockedReason("draft", listOf("l1"), null))
    }

    // ── A/B split ─────────────────────────────────────────────────────────────

    @Test
    fun abSplit_evenlyApportionsAndSumsBack() {
        assertEquals(listOf(50, 50), CampaignMath.abSplit(100, 2))
        // remainder goes to earliest variants
        assertEquals(listOf(4, 3, 3), CampaignMath.abSplit(10, 3))
        val split = CampaignMath.abSplit(101, 3)
        assertEquals(101, split.sum())
        assertEquals(listOf(34, 34, 33), split)
    }

    @Test
    fun abSplit_degradesOnBadInput() {
        assertEquals(emptyList<Int>(), CampaignMath.abSplit(100, 0))
        assertEquals(emptyList<Int>(), CampaignMath.abSplit(100, -1))
        assertEquals(listOf(0, 0), CampaignMath.abSplit(0, 2))
        assertEquals(listOf(0, 0, 0), CampaignMath.abSplit(-5, 3))
    }

    @Test
    fun abSplitPercents_evenShares() {
        assertEquals(listOf(50.0, 50.0), CampaignMath.abSplitPercents(2))
        assertEquals(listOf(33.3, 33.3, 33.3), CampaignMath.abSplitPercents(3))
        assertEquals(emptyList<Double>(), CampaignMath.abSplitPercents(0))
    }

    @Test
    fun isAbTest_needsTwoLabeledVariants() {
        assertFalse(CampaignMath.isAbTest(null))
        assertFalse(CampaignMath.isAbTest(listOf("A")))
        assertFalse(CampaignMath.isAbTest(listOf("A", "  ")))
        assertTrue(CampaignMath.isAbTest(listOf("A", "B")))
    }

    @Test
    fun pickWinner_byOpenThenClickRate() {
        assertNull(CampaignMath.pickWinner(emptyList()))
        // no signal
        assertNull(
            CampaignMath.pickWinner(
                listOf(Triple("a", 0.0, 0.0), Triple("b", 0.0, 0.0)),
            ),
        )
        assertEquals(
            "b",
            CampaignMath.pickWinner(
                listOf(Triple("a", 0.2, 0.9), Triple("b", 0.4, 0.1)),
            ),
        )
        // tie on opens -> higher clicks wins
        assertEquals(
            "b",
            CampaignMath.pickWinner(
                listOf(Triple("a", 0.3, 0.1), Triple("b", 0.3, 0.2)),
            ),
        )
    }

    // ── Merge-var extraction / validation ─────────────────────────────────────

    @Test
    fun extractTemplateVars_distinctSortedFromSubjectAndBody() {
        assertEquals(
            listOf("first_name", "offer"),
            CampaignMath.extractTemplateVars("Hi {{ first_name }}", "Enjoy {{offer}}, {{ first_name }}!"),
        )
        assertEquals(emptyList<String>(), CampaignMath.extractTemplateVars(null, null))
        assertEquals(emptyList<String>(), CampaignMath.extractTemplateVars("no vars here", ""))
    }

    @Test
    fun missingTemplateVars_reportsUnfilled() {
        val missing = CampaignMath.missingTemplateVars(
            "Hi {{ first_name }}",
            "Code {{ code }}",
            mapOf("first_name" to "Sam", "code" to ""),
        )
        assertEquals(listOf("code"), missing)
        assertTrue(
            CampaignMath.isTemplateComplete(
                "Hi {{ first_name }}",
                "Code {{ code }}",
                mapOf("first_name" to "Sam", "code" to "X1"),
            ),
        )
    }

    @Test
    fun validateTemplateInput_enforcesFieldRules() {
        assertEquals("A template name is required.", CampaignMath.validateTemplateInput("  ", "s", "b"))
        assertEquals("A subject line is required.", CampaignMath.validateTemplateInput("n", "", "b"))
        assertEquals("The email body cannot be empty.", CampaignMath.validateTemplateInput("n", "s", "   "))
        assertNull(CampaignMath.validateTemplateInput("Welcome", "Hi {{name}}", "<p>Hello</p>"))
        assertEquals(
            "The template name is too long (max 120).",
            CampaignMath.validateTemplateInput("x".repeat(121), "s", "b"),
        )
    }

    @Test
    fun validateCampaignInput_enforcesFieldRules() {
        assertEquals("A campaign name is required.", CampaignMath.validateCampaignInput("", null, 0))
        assertEquals("The budget cannot be negative.", CampaignMath.validateCampaignInput("n", null, -1))
        assertNull(CampaignMath.validateCampaignInput("Spring Blast", "Awareness", 5000))
        assertEquals(
            "The campaign name is too long (max 200).",
            CampaignMath.validateCampaignInput("x".repeat(201), null, 0),
        )
    }

    // ── Budget parsing ────────────────────────────────────────────────────────

    @Test
    fun parseBudgetToCents_toleratesFormatting() {
        assertEquals(0L, CampaignMath.parseBudgetToCents(""))
        assertEquals(0L, CampaignMath.parseBudgetToCents(null))
        assertEquals(1200L, CampaignMath.parseBudgetToCents("$12"))
        assertEquals(123450L, CampaignMath.parseBudgetToCents("1,234.50"))
        assertNull(CampaignMath.parseBudgetToCents("abc"))
        assertNull(CampaignMath.parseBudgetToCents("-5"))
    }

    @Test
    fun campaignTypes_coverAllServerVariants() {
        assertEquals(listOf("email", "phone", "mail", "fax", "sms"), CampaignMath.CAMPAIGN_TYPES)
    }
}
