package com.testlogon.android.feature.call.group

import org.junit.Assert.assertEquals
import org.junit.Test

/** AND-299 — pure unit tests for [GridLayoutPolicy]. */
class GridLayoutPolicyTest {

    private fun portrait(count: Int) = GridLayoutPolicy.spec(count, GridOrientation.Portrait)
    private fun landscape(count: Int) = GridLayoutPolicy.spec(count, GridOrientation.Landscape)

    @Test
    fun zeroOrNegative_fallsBackTo1x1() {
        assertEquals(GridSpec(1, 1, scrollable = false), portrait(0))
        assertEquals(GridSpec(1, 1, scrollable = false), landscape(-3))
    }

    @Test
    fun portrait_breakpoints() {
        assertEquals(GridSpec(1, 1, scrollable = false), portrait(1))
        assertEquals(GridSpec(1, 2, scrollable = false), portrait(2))
        assertEquals(GridSpec(2, 2, scrollable = false), portrait(3))
        assertEquals(GridSpec(2, 2, scrollable = false), portrait(4))
        assertEquals(GridSpec(2, 3, scrollable = false), portrait(5))
        assertEquals(GridSpec(2, 3, scrollable = false), portrait(6))
        assertEquals(GridSpec(3, 3, scrollable = false), portrait(7))
        assertEquals(GridSpec(3, 3, scrollable = false), portrait(9))
        // 10+ -> 3 columns, scrollable.
        val ten = portrait(10)
        assertEquals(3, ten.columns)
        assertEquals(true, ten.scrollable)
        assertEquals(4, ten.rows)
    }

    @Test
    fun landscape_transposes() {
        assertEquals(GridSpec(1, 1, scrollable = false), landscape(1))
        assertEquals(GridSpec(2, 1, scrollable = false), landscape(2))
        assertEquals(GridSpec(2, 2, scrollable = false), landscape(3))
        assertEquals(GridSpec(2, 2, scrollable = false), landscape(4))
        assertEquals(GridSpec(3, 2, scrollable = false), landscape(5))
        assertEquals(GridSpec(3, 2, scrollable = false), landscape(6))
        assertEquals(GridSpec(3, 3, scrollable = false), landscape(7))
        assertEquals(GridSpec(3, 3, scrollable = false), landscape(9))
        val ten = landscape(10)
        assertEquals(true, ten.scrollable)
    }
}
