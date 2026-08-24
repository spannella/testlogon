package com.testlogon.android.feature.adminrewards

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CatalogAdminValidationTest {

    @Test
    fun validPerk_ok_noErrors() {
        val r = validateCatalogItem(name = "Free sticker", costPoints = 500, valueCents = 0, kind = "perk")
        assertTrue(r.ok)
        assertTrue(r.errors.isEmpty())
    }

    @Test
    fun validCash_withValue_ok() {
        val r = validateCatalogItem(name = "\$5 credit", costPoints = 5000, valueCents = 500, kind = "cash")
        assertTrue(r.ok)
    }

    @Test
    fun blankName_isError() {
        val r = validateCatalogItem(name = "   ", costPoints = 500, valueCents = 0, kind = "perk")
        assertFalse(r.ok)
        assertNotNullError(r, "name")
    }

    @Test
    fun zeroCost_isError() {
        val r = validateCatalogItem(name = "Perk", costPoints = 0, valueCents = 0, kind = "perk")
        assertFalse(r.ok)
        assertNotNullError(r, "costPoints")
    }

    @Test
    fun negativeCost_isError() {
        val r = validateCatalogItem(name = "Perk", costPoints = -1, valueCents = 0, kind = "perk")
        assertFalse(r.ok)
        assertNotNullError(r, "costPoints")
    }

    @Test
    fun negativeValue_isError() {
        val r = validateCatalogItem(name = "Perk", costPoints = 100, valueCents = -1, kind = "perk")
        assertFalse(r.ok)
        assertNotNullError(r, "valueCents")
    }

    @Test
    fun unknownKind_isError() {
        val r = validateCatalogItem(name = "Perk", costPoints = 100, valueCents = 0, kind = "swag")
        assertFalse(r.ok)
        assertNotNullError(r, "kind")
    }

    @Test
    fun cashWithoutValue_isError() {
        val r = validateCatalogItem(name = "Cash", costPoints = 100, valueCents = 0, kind = "cash")
        assertFalse(r.ok)
        assertNotNullError(r, "valueCents")
    }

    @Test
    fun kindIsCaseInsensitiveAndTrimmed() {
        val r = validateCatalogItem(name = "Perk", costPoints = 100, valueCents = 0, kind = "  PERK ")
        assertTrue(r.ok)
    }

    @Test
    fun emptyDraft_defaultsAreSaneButInvalidCost() {
        val d = emptyDraft()
        assertEquals("perk", d.kind)
        assertTrue(d.active)
        // cost defaults to 0 -> not yet submittable, which is the intended "fill me in" state.
        val r = validateCatalogItem(d)
        assertFalse(r.ok)
        assertNotNullError(r, "costPoints")
    }

    @Test
    fun draftOverload_matchesPrimitiveOverload() {
        val d = CatalogDraft(name = "X", costPoints = 10, valueCents = 0, kind = "perk", active = true)
        assertTrue(validateCatalogItem(d).ok)
    }

    @Test
    fun stockLimit_absentIsUnlimited_ok() {
        val r = validateCatalogItem(name = "Perk", costPoints = 100, valueCents = 0, kind = "perk", stockLimit = null)
        assertTrue(r.ok)
        assertNull(r.errorFor("stockLimit"))
    }

    @Test
    fun stockLimit_zeroIsValid() {
        // Zero is a valid (currently out-of-stock) cap, not an error.
        val r = validateCatalogItem(name = "Perk", costPoints = 100, valueCents = 0, kind = "perk", stockLimit = 0)
        assertTrue(r.ok)
    }

    @Test
    fun stockLimit_positiveIsValid() {
        val r = validateCatalogItem(name = "Perk", costPoints = 100, valueCents = 0, kind = "perk", stockLimit = 25)
        assertTrue(r.ok)
    }

    @Test
    fun stockLimit_negativeIsError() {
        val r = validateCatalogItem(name = "Perk", costPoints = 100, valueCents = 0, kind = "perk", stockLimit = -1)
        assertFalse(r.ok)
        assertNotNullError(r, "stockLimit")
    }

    @Test
    fun emptyDraft_stockLimitIsUnlimited() {
        assertNull(emptyDraft().stockLimit)
    }

    @Test
    fun draftOverload_carriesStockLimit() {
        val d = CatalogDraft(name = "X", costPoints = 10, valueCents = 0, kind = "perk", active = true, stockLimit = -5)
        val r = validateCatalogItem(d)
        assertFalse(r.ok)
        assertNotNullError(r, "stockLimit")
    }

    private fun assertNotNullError(r: CatalogValidationResult, field: String) {
        assertTrue("expected error for \$field", r.errorFor(field) != null)
    }

    @Test
    fun okDraft_hasNoFieldErrors() {
        val r = validateCatalogItem(name = "Perk", costPoints = 100, valueCents = 0, kind = "perk")
        assertNull(r.errorFor("name"))
        assertNull(r.errorFor("costPoints"))
        assertNull(r.errorFor("kind"))
    }
}
