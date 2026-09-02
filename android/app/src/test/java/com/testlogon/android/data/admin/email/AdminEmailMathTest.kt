package com.testlogon.android.data.admin.email

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** JVM unit tests for [AdminEmailMath] (pure helpers: rate/count formatting + merge-field/template validation). */
class AdminEmailMathTest {

    // ---- formatRate ----

    @Test
    fun formatRate_dropsTrailingZero() {
        assertEquals("100%", AdminEmailMath.formatRate(100.0))
        assertEquals("0%", AdminEmailMath.formatRate(0.0))
    }

    @Test
    fun formatRate_keepsOneDecimal() {
        assertEquals("98.7%", AdminEmailMath.formatRate(98.72))
    }

    @Test
    fun formatRate_clampsOutOfRange() {
        assertEquals("100%", AdminEmailMath.formatRate(150.0))
        assertEquals("0%", AdminEmailMath.formatRate(-5.0))
    }

    @Test
    fun formatRate_handlesNaN() {
        assertEquals("0%", AdminEmailMath.formatRate(Double.NaN))
        assertEquals("0%", AdminEmailMath.formatRate(Double.POSITIVE_INFINITY))
    }

    // ---- formatCount ----

    @Test
    fun formatCount_smallAndCompact() {
        assertEquals("0", AdminEmailMath.formatCount(0))
        assertEquals("0", AdminEmailMath.formatCount(-3))
        assertEquals("42", AdminEmailMath.formatCount(42))
        assertEquals("1.5K", AdminEmailMath.formatCount(1_500))
        assertEquals("2M", AdminEmailMath.formatCount(2_000_000))
    }

    // ---- summaryLine ----

    @Test
    fun summaryLine_groupsThousandsAndRate() {
        assertEquals("1,240 sent · 98.7% delivered", AdminEmailMath.summaryLine(1240, 98.7))
        assertEquals("0 sent · 0% delivered", AdminEmailMath.summaryLine(0, 0.0))
    }

    // ---- merge field validation ----

    @Test
    fun mergeField_validAndInvalid() {
        assertTrue(AdminEmailMath.isValidMergeField("first_name"))
        assertTrue(AdminEmailMath.isValidMergeField("A1_b2"))
        assertFalse(AdminEmailMath.isValidMergeField("first name"))
        assertFalse(AdminEmailMath.isValidMergeField("bad-field"))
        assertFalse(AdminEmailMath.isValidMergeField(""))
    }

    @Test
    fun mergeField_rejectsTooLong() {
        assertTrue(AdminEmailMath.isValidMergeField("a".repeat(64)))
        assertFalse(AdminEmailMath.isValidMergeField("a".repeat(65)))
    }

    @Test
    fun parseMergeFields_blankIsEmpty() {
        assertEquals(emptyList<String>(), AdminEmailMath.parseMergeFields("   "))
        assertEquals(emptyList<String>(), AdminEmailMath.parseMergeFields(""))
    }

    @Test
    fun parseMergeFields_splitsDedupesAndKeepsOrder() {
        assertEquals(
            listOf("first_name", "last_name", "plan"),
            AdminEmailMath.parseMergeFields("first_name, last_name first_name plan"),
        )
    }

    @Test
    fun parseMergeFields_returnsNullOnInvalidToken() {
        assertNull(AdminEmailMath.parseMergeFields("ok, bad-field"))
    }

    // ---- template form validation ----

    @Test
    fun templateForm_validPasses() {
        assertTrue(AdminEmailMath.canSubmitTemplate("Welcome", "Hi", "Body", "first_name"))
        assertTrue(AdminEmailMath.templateFormErrors("Welcome", "Hi", "Body", "").isEmpty())
    }

    @Test
    fun templateForm_reportsMissingFields() {
        val errors = AdminEmailMath.templateFormErrors("", "", "", "")
        assertTrue(errors.any { it.contains("Name") })
        assertTrue(errors.any { it.contains("Subject") })
        assertTrue(errors.any { it.contains("Body") })
        assertFalse(AdminEmailMath.canSubmitTemplate("", "s", "b", ""))
    }

    @Test
    fun templateForm_reportsInvalidMergeField() {
        val errors = AdminEmailMath.templateFormErrors("N", "S", "B", "bad-field")
        assertTrue(errors.any { it.contains("merge field", ignoreCase = true) })
    }

    @Test
    fun templateForm_reportsTooLong() {
        val longName = "a".repeat(AdminEmailMath.NAME_MAX + 1)
        assertTrue(AdminEmailMath.templateFormErrors(longName, "S", "B", "").any { it.contains("Name too long") })
    }
}
