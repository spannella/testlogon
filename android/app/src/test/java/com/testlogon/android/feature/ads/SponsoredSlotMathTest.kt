package com.testlogon.android.feature.ads

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** FE-161 — pure-math unit tests for [interleaveSponsored] / [sponsoredSlotCount] / [isValidServe]. */
class SponsoredSlotMathTest {

    private fun organic(entry: SlotEntry<Int, String>): Int? =
        (entry as? SlotEntry.Organic<Int>)?.item

    private fun ad(entry: SlotEntry<Int, String>): String? =
        (entry as? SlotEntry.Sponsored<String>)?.ad

    private fun organicItems(list: List<SlotEntry<Int, String>>): List<Int> =
        list.mapNotNull { organic(it) }

    private fun sponsoredCount(list: List<SlotEntry<Int, String>>): Int =
        list.count { it is SlotEntry.Sponsored<*> }

    @Test
    fun `no sponsored returns organic list verbatim`() {
        val items = (1..7).toList()
        val out = interleaveSponsored(items, emptyList<String>(), everyN = 3)
        assertEquals(items, organicItems(out))
        assertEquals(0, sponsoredCount(out))
        assertEquals(items.size, out.size)
    }

    @Test
    fun `empty items returns empty`() {
        val out = interleaveSponsored(emptyList<Int>(), listOf("a"), everyN = 3)
        assertTrue(out.isEmpty())
    }

    @Test
    fun `inserts one slot every N after the boundary`() {
        val items = (1..10).toList()
        val out = interleaveSponsored(items, listOf("a", "b", "c"), everyN = 5, startAt = 5, max = 3)
        // Organic order preserved.
        assertEquals(items, organicItems(out))
        // With 10 items and everyN=5: a slot after item#5 only (after #10 is the last -> suppressed).
        assertEquals(1, sponsoredCount(out))
        // Slot sits right after the 5th organic item.
        val idx = out.indexOfFirst { it is SlotEntry.Sponsored<*> }
        assertEquals(5, out.take(idx).count { it is SlotEntry.Organic<*> })
    }

    @Test
    fun `never places two sponsored slots adjacent`() {
        val items = (1..30).toList()
        val out = interleaveSponsored(items, List(10) { "ad$it" }, everyN = 5, startAt = 5, max = 10)
        for (i in 0 until out.size - 1) {
            val bothSponsored = out[i] is SlotEntry.Sponsored<*> && out[i + 1] is SlotEntry.Sponsored<*>
            assertFalse("adjacent sponsored at $i", bothSponsored)
        }
    }

    @Test
    fun `never ends with a sponsored slot (never past end)`() {
        val items = (1..10).toList()
        val out = interleaveSponsored(items, List(5) { "ad$it" }, everyN = 2, startAt = 2, max = 5)
        assertTrue(out.last() is SlotEntry.Organic<*>)
    }

    @Test
    fun `respects max cap`() {
        val items = (1..100).toList()
        val out = interleaveSponsored(items, List(20) { "ad$it" }, everyN = 5, startAt = 5, max = 2)
        assertEquals(2, sponsoredCount(out))
    }

    @Test
    fun `respects available served count`() {
        val items = (1..100).toList()
        val out = interleaveSponsored(items, listOf("a"), everyN = 5, startAt = 5, max = 10)
        assertEquals(1, sponsoredCount(out))
        assertEquals("a", ad(out.first { it is SlotEntry.Sponsored<*> }))
    }

    @Test
    fun `ads consumed in order`() {
        val items = (1..30).toList()
        val out = interleaveSponsored(items, listOf("x", "y", "z"), everyN = 5, startAt = 5, max = 3)
        val ads = out.mapNotNull { ad(it) }
        assertEquals(listOf("x", "y", "z"), ads)
    }

    @Test
    fun `keys are applied from the key function`() {
        val items = (1..20).toList()
        val out = interleaveSponsored(
            items, listOf("a", "b"), everyN = 5, startAt = 5, max = 2,
            key = { i, adv -> "k_${adv}_$i" },
        )
        val keys = out.filterIsInstance<SlotEntry.Sponsored<String>>().map { it.key }
        assertEquals(listOf("k_a_0", "k_b_1"), keys)
    }

    @Test
    fun `startAt shifts the first slot`() {
        val items = (1..20).toList()
        val out = interleaveSponsored(items, listOf("a"), everyN = 5, startAt = 3, max = 1)
        val idx = out.indexOfFirst { it is SlotEntry.Sponsored<*> }
        // First slot after the 3rd organic item.
        assertEquals(3, out.take(idx).count { it is SlotEntry.Organic<*> })
    }

    @Test
    fun `everyN zero degrades to organic`() {
        val items = (1..5).toList()
        val out = interleaveSponsored(items, listOf("a"), everyN = 0, max = 3)
        assertEquals(items, organicItems(out))
        assertEquals(0, sponsoredCount(out))
    }

    @Test
    fun `all organic items preserved regardless of injection`() {
        val items = (1..23).toList()
        val out = interleaveSponsored(items, List(5) { "ad$it" }, everyN = 4, startAt = 4, max = 5)
        assertEquals(items, organicItems(out))
    }

    @Test
    fun `sponsoredSlotCount matches interleave placement`() {
        val items = (1..17).toList()
        val everyN = 5
        val max = 10
        val count = sponsoredSlotCount(items.size, everyN, max)
        val out = interleaveSponsored(items, List(max) { "ad$it" }, everyN = everyN, startAt = everyN, max = max)
        assertEquals(count, sponsoredCount(out))
    }

    @Test
    fun `sponsoredSlotCount guards`() {
        assertEquals(0, sponsoredSlotCount(0, 5, 3))
        assertEquals(0, sponsoredSlotCount(10, 0, 3))
        assertEquals(0, sponsoredSlotCount(10, 5, 0))
        assertEquals(1, sponsoredSlotCount(10, 5, 3))
        assertEquals(3, sponsoredSlotCount(100, 5, 3))
    }

    @Test
    fun `isValidServe requires filled and creative id`() {
        assertTrue(isValidServe(true, "cr_1"))
        assertFalse(isValidServe(false, "cr_1"))
        assertFalse(isValidServe(true, ""))
        assertFalse(isValidServe(true, null))
        assertFalse(isValidServe(false, null))
    }
}
