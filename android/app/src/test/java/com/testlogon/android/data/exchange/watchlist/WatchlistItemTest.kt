package com.testlogon.android.data.exchange.watchlist

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure JVM tests for the framework-free unified-watchlist helpers. */
class WatchlistItemTest {

    @Test
    fun watchKey_encodesKindAndId() {
        assertEquals("SYMBOL:1", watchKey(WatchKind.SYMBOL, "1"))
        assertEquals("TOKEN:abc", watchKey(WatchKind.TOKEN, "abc"))
        assertEquals("STRATEGY:xyz", watchKey(WatchKind.STRATEGY, "xyz"))
    }

    @Test
    fun symbolWatch_buildsSymbolItem() {
        val w = symbolWatch(7)
        assertEquals(WatchKind.SYMBOL, w.kind)
        assertEquals("7", w.id)
        assertEquals("SYMBOL:7", w.key)
    }

    @Test
    fun parseWatchKey_prefixedRoundTrips() {
        assertEquals(WatchItem(WatchKind.TOKEN, "abc"), parseWatchKey("TOKEN:abc"))
        assertEquals(WatchItem(WatchKind.STRATEGY, "s-1"), parseWatchKey("STRATEGY:s-1"))
        // Token ids may themselves contain colons; only the first delimiter splits.
        assertEquals(WatchItem(WatchKind.TOKEN, "a:b:c"), parseWatchKey("TOKEN:a:b:c"))
    }

    @Test
    fun parseWatchKey_legacyBareIdIsSymbol() {
        assertEquals(WatchItem(WatchKind.SYMBOL, "3"), parseWatchKey("3"))
        assertEquals(WatchItem(WatchKind.SYMBOL, "42"), parseWatchKey(" 42 "))
    }

    @Test
    fun parseWatchKey_blankIsNull() {
        assertNull(parseWatchKey(""))
        assertNull(parseWatchKey("   "))
    }

    @Test
    fun migrateLegacy_mixedSetFoldsCorrectly() {
        val raw = setOf("1", "2", "TOKEN:t1", "STRATEGY:s1", "", "  ")
        val migrated = migrateLegacy(raw)
        assertEquals(
            setOf(
                symbolWatch(1),
                symbolWatch(2),
                WatchItem(WatchKind.TOKEN, "t1"),
                WatchItem(WatchKind.STRATEGY, "s1"),
            ),
            migrated,
        )
    }

    @Test
    fun migrateLegacy_isIdempotent() {
        val once = migrateLegacy(setOf("1", "TOKEN:t1"))
        val twice = migrateLegacy(serialize(once))
        assertEquals(once, twice)
    }

    @Test
    fun isWatched_matchesByKindAndId() {
        val items = setOf(symbolWatch(1), WatchItem(WatchKind.TOKEN, "1"))
        assertTrue(isWatched(items, WatchKind.SYMBOL, "1"))
        assertTrue(isWatched(items, WatchKind.TOKEN, "1"))
        // Same id, different kind is NOT the same item.
        assertFalse(isWatched(items, WatchKind.STRATEGY, "1"))
        assertFalse(isWatched(items, WatchKind.SYMBOL, "2"))
    }

    @Test
    fun toggleWatch_addsThenRemoves_withoutMutatingInput() {
        val start = emptySet<WatchItem>()
        val added = toggleWatch(start, WatchKind.TOKEN, "t1")
        assertTrue(isWatched(added, WatchKind.TOKEN, "t1"))
        assertTrue(start.isEmpty()) // input untouched
        val removed = toggleWatch(added, WatchKind.TOKEN, "t1")
        assertFalse(isWatched(removed, WatchKind.TOKEN, "t1"))
    }

    @Test
    fun toggleWatch_kindIsolated() {
        var items = setOf(symbolWatch(1))
        items = toggleWatch(items, WatchKind.STRATEGY, "1")
        assertEquals(2, items.size)
        assertTrue(isWatched(items, WatchKind.SYMBOL, "1"))
        assertTrue(isWatched(items, WatchKind.STRATEGY, "1"))
    }

    @Test
    fun symbolIds_extractsOnlyNumericSymbols() {
        val items = setOf(
            symbolWatch(1),
            symbolWatch(5),
            WatchItem(WatchKind.TOKEN, "9"),
            WatchItem(WatchKind.STRATEGY, "3"),
        )
        assertEquals(setOf(1, 5), symbolIds(items))
    }

    @Test
    fun serialize_roundTripsThroughMigrate() {
        val items = setOf(symbolWatch(2), WatchItem(WatchKind.TOKEN, "abc"))
        assertEquals(items, migrateLegacy(serialize(items)))
    }

    @Test
    fun sortForDisplay_groupsByKindThenId() {
        val items = listOf(
            WatchItem(WatchKind.STRATEGY, "s1"),
            symbolWatch(2),
            WatchItem(WatchKind.TOKEN, "t1"),
            symbolWatch(1),
        )
        val sorted = sortForDisplay(items)
        assertEquals(
            listOf(
                symbolWatch(1),
                symbolWatch(2),
                WatchItem(WatchKind.TOKEN, "t1"),
                WatchItem(WatchKind.STRATEGY, "s1"),
            ),
            sorted,
        )
    }

    @Test
    fun kindLabel_isHumanReadable() {
        assertEquals("Symbol", kindLabel(WatchKind.SYMBOL))
        assertEquals("Token", kindLabel(WatchKind.TOKEN))
        assertEquals("Strategy", kindLabel(WatchKind.STRATEGY))
    }
}
