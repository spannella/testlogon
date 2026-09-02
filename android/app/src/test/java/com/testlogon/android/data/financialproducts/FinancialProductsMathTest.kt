package com.testlogon.android.data.financialproducts

import com.testlogon.android.data.financialproducts.FinancialProductsMath.AttributeType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** JVM unit tests for [FinancialProductsMath] (product-code + typed-attribute validation, family label). */
class FinancialProductsMathTest {

    // ---- product code ----

    @Test
    fun productCode_validAndInvalid() {
        assertTrue(FinancialProductsMath.isValidProductCode("SAV_01"))
        assertTrue(FinancialProductsMath.isValidProductCode("chk-account"))
        assertFalse(FinancialProductsMath.isValidProductCode("has space"))
        assertFalse(FinancialProductsMath.isValidProductCode("bad/slash"))
        assertFalse(FinancialProductsMath.isValidProductCode(""))
    }

    @Test
    fun productCode_lengthCap() {
        assertTrue(FinancialProductsMath.isValidProductCode("a".repeat(64)))
        assertFalse(FinancialProductsMath.isValidProductCode("a".repeat(65)))
    }

    // ---- attribute type parsing ----

    @Test
    fun attributeType_fromWire() {
        assertEquals(AttributeType.STRING, AttributeType.from("STRING"))
        assertEquals(AttributeType.DATE_WITH_DAY, AttributeType.from("date_with_day"))
        assertNull(AttributeType.from("BOGUS"))
        assertNull(AttributeType.from(null))
    }

    // ---- typed value validation ----

    @Test
    fun attributeValue_string() {
        assertTrue(FinancialProductsMath.isValidAttributeValue(AttributeType.STRING, "anything"))
        assertFalse(FinancialProductsMath.isValidAttributeValue(AttributeType.STRING, "   "))
    }

    @Test
    fun attributeValue_integer() {
        assertTrue(FinancialProductsMath.isValidAttributeValue(AttributeType.INTEGER, "-42"))
        assertFalse(FinancialProductsMath.isValidAttributeValue(AttributeType.INTEGER, "4.2"))
        assertFalse(FinancialProductsMath.isValidAttributeValue(AttributeType.INTEGER, "abc"))
    }

    @Test
    fun attributeValue_double() {
        assertTrue(FinancialProductsMath.isValidAttributeValue(AttributeType.DOUBLE, "3.14"))
        assertTrue(FinancialProductsMath.isValidAttributeValue(AttributeType.DOUBLE, "5"))
        assertFalse(FinancialProductsMath.isValidAttributeValue(AttributeType.DOUBLE, "NaN"))
        assertFalse(FinancialProductsMath.isValidAttributeValue(AttributeType.DOUBLE, "x"))
    }

    @Test
    fun attributeValue_date() {
        assertTrue(FinancialProductsMath.isValidAttributeValue(AttributeType.DATE_WITH_DAY, "2026-01-31"))
        assertFalse(FinancialProductsMath.isValidAttributeValue(AttributeType.DATE_WITH_DAY, "2026-13-01"))
        assertFalse(FinancialProductsMath.isValidAttributeValue(AttributeType.DATE_WITH_DAY, "01-01-2026"))
    }

    @Test
    fun attributeValue_lengthCap() {
        val huge = "a".repeat(FinancialProductsMath.ATTRIBUTE_VALUE_MAX + 1)
        assertFalse(FinancialProductsMath.isValidAttributeValue(AttributeType.STRING, huge))
    }

    // ---- form validation ----

    @Test
    fun productForm_errors() {
        assertTrue(FinancialProductsMath.canSubmitProduct("SAV_01", "Savings"))
        assertFalse(FinancialProductsMath.canSubmitProduct("", "Savings"))
        val errors = FinancialProductsMath.productFormErrors("bad code", "")
        assertTrue(errors.any { it.contains("product code", ignoreCase = true) })
        assertTrue(errors.any { it.contains("Name") })
    }

    @Test
    fun collectionForm_errors() {
        assertTrue(FinancialProductsMath.canSubmitCollection("CORE", "Core products"))
        assertFalse(FinancialProductsMath.canSubmitCollection("bad code", "x"))
        assertFalse(FinancialProductsMath.canSubmitCollection("CORE", ""))
    }

    @Test
    fun attributeForm_errors() {
        assertTrue(FinancialProductsMath.canSubmitAttribute("rate", AttributeType.DOUBLE, "1.5"))
        assertFalse(FinancialProductsMath.canSubmitAttribute("", AttributeType.DOUBLE, "1.5"))
        assertFalse(FinancialProductsMath.canSubmitAttribute("rate", AttributeType.INTEGER, "1.5"))
    }

    // ---- family label ----

    @Test
    fun familyLabel_composesAndFallsBack() {
        // order is superFamily › family › category
        assertEquals(
            "Deposits › Savings › Basic",
            FinancialProductsMath.familyLabel(category = "Basic", family = "Savings", superFamily = "Deposits"),
        )
        assertEquals("—", FinancialProductsMath.familyLabel(null, null, null))
        assertEquals("Deposits", FinancialProductsMath.familyLabel(null, null, "Deposits"))
        assertEquals("Savings", FinancialProductsMath.familyLabel(null, "Savings", "  "))
    }
}
