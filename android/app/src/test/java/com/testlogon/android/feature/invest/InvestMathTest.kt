package com.testlogon.android.feature.invest

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure unit tests for [InvestMath] — no Android, no repositories. */
class InvestMathTest {

    private fun item(
        id: String,
        title: String,
        subtitle: String = "",
        kind: InvestKind = InvestKind.MARKET,
        sortKey: Double = 0.0,
        searchText: String = "",
    ) = InvestItem(kind = kind, id = id, title = title, subtitle = subtitle, sortKey = sortKey, searchText = searchText)

    @Test
    fun normalizeQuery_trimsAndLowercases() {
        assertEquals("btc", InvestMath.normalizeQuery("  BTC  "))
        assertEquals("", InvestMath.normalizeQuery("   "))
    }

    @Test
    fun matches_blankQueryMatchesEverything() {
        assertTrue(InvestMath.matches(item("1", "BTCUSDC"), ""))
        assertTrue(InvestMath.matches(item("1", "BTCUSDC"), "   "))
    }

    @Test
    fun matches_byTitleCaseInsensitive() {
        val it = item("1", "BTCUSDC", subtitle = "Bitcoin")
        assertTrue(InvestMath.matches(it, "btc"))
        assertTrue(InvestMath.matches(it, "USDC"))
    }

    @Test
    fun matches_bySubtitleAndId() {
        val it = item("tok_42", "MOON", subtitle = "Creator revenue token")
        assertTrue(InvestMath.matches(it, "revenue"))
        assertTrue(InvestMath.matches(it, "tok_42"))
    }

    @Test
    fun matches_byExtraSearchText() {
        // searchText is expected lowercase (chain/asset/ticker folded in by the ViewModel).
        val it = item("p1", "Lido", kind = InvestKind.STAKING, searchText = "ethereum steth")
        assertTrue(InvestMath.matches(it, "ethereum"))
        assertTrue(InvestMath.matches(it, "STETH"))
    }

    @Test
    fun matches_negativeWhenNoField() {
        val it = item("1", "BTCUSDC", subtitle = "Bitcoin", searchText = "spot")
        assertFalse(InvestMath.matches(it, "solana"))
    }

    @Test
    fun filter_preservesOrderAndDropsNonMatches() {
        val items = listOf(
            item("1", "BTCUSDC"),
            item("2", "ETHUSDC"),
            item("3", "SOLUSDC"),
        )
        val out = InvestMath.filter(items, "eth")
        assertEquals(1, out.size)
        assertEquals("2", out.single().id)
    }

    @Test
    fun rankBySortKey_descWithStableTieBreak() {
        val items = listOf(
            item("a", "Alpha", sortKey = 1.0),
            item("c", "Charlie", sortKey = 3.0),
            item("b", "Bravo", sortKey = 3.0),
        )
        val ranked = InvestMath.rankBySortKey(items)
        // 3.0s first, tie broken by title (Bravo < Charlie), then the 1.0.
        assertEquals(listOf("b", "c", "a"), ranked.map { it.id })
    }

    @Test
    fun topN_takesHighestAndClampsAtZero() {
        val items = listOf(
            item("a", "A", sortKey = 1.0),
            item("b", "B", sortKey = 5.0),
            item("c", "C", sortKey = 3.0),
        )
        assertEquals(listOf("b", "c"), InvestMath.topN(items, 2).map { it.id })
        assertTrue(InvestMath.topN(items, 0).isEmpty())
        assertTrue(InvestMath.topN(items, -1).isEmpty())
    }

    @Test
    fun moverKey_isAbsoluteAndNullSafe() {
        assertEquals(5.0, InvestMath.moverKey(-5.0), 0.0)
        assertEquals(2.5, InvestMath.moverKey(2.5), 0.0)
        assertEquals(0.0, InvestMath.moverKey(null), 0.0)
    }

    @Test
    fun returnKey_andAumKey_nullSafe() {
        assertEquals(1200.0, InvestMath.returnKey(1200), 0.0)
        assertEquals(-300.0, InvestMath.returnKey(-300), 0.0)
        assertEquals(0.0, InvestMath.returnKey(null), 0.0)
        assertEquals(999.0, InvestMath.aumKey(999L), 0.0)
        assertEquals(0.0, InvestMath.aumKey(null), 0.0)
    }

    @Test
    fun capacityRemainingFraction_bounds() {
        // Half full -> 0.5 remaining.
        assertEquals(0.5, InvestMath.capacityRemainingFraction(1000L, 500L)!!, 1e-9)
        // Fully used -> 0.0 (clamped, never negative even if over-subscribed).
        assertEquals(0.0, InvestMath.capacityRemainingFraction(1000L, 1500L)!!, 1e-9)
        // Empty fund -> 1.0 remaining (null AUM treated as 0).
        assertEquals(1.0, InvestMath.capacityRemainingFraction(1000L, null)!!, 1e-9)
        // No cap -> null (uncapped is distinct from full).
        assertNull(InvestMath.capacityRemainingFraction(0L, 100L))
    }

    @Test
    fun totalCount_sumsSections() {
        val sections = listOf(
            listOf(item("1", "A"), item("2", "B")),
            emptyList(),
            listOf(item("3", "C")),
        )
        assertEquals(3, InvestMath.totalCount(sections))
        assertEquals(0, InvestMath.totalCount(emptyList()))
    }
}
