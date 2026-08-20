package com.testlogon.android.feature.search

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [SearchMatching] — the pure filter + ranking behind the global search list.
 * No Android, no coroutines: exercises substring matching, the fuzzy score tiers, deterministic
 * ordering, and the kind grouping.
 */
class SearchMatchingTest {

    private fun symbol(id: Int, sym: String, vararg kw: String) =
        SearchItem("symbol:$id", SearchResultKind.SYMBOL, sym, keywords = kw.toList(), symbolId = id)

    private fun dest(title: String, subtitle: String? = null, vararg kw: String) =
        SearchItem("dest:$title", SearchResultKind.DESTINATION, title, subtitle, kw.toList())

    private fun action(id: SearchActionId, title: String) =
        SearchItem("action:${id.name}", SearchResultKind.ACTION, title, actionId = id)

    private val catalogue = listOf(
        symbol(1, "BTCUSDC", "btc", "usdc"),
        symbol(2, "ETHUSDC", "eth", "usdc"),
        symbol(3, "SOLUSDC", "sol", "usdc"),
        dest("Markets", "Instruments & live quotes", "instruments", "watchlist"),
        dest("Portfolio", "Cross-venue balances", "holdings"),
        dest("Price alerts", "Your price alerts", "notify"),
        action(SearchActionId.DEPOSIT, "Deposit"),
        action(SearchActionId.NEW_PRICE_ALERT, "New price alert"),
    )

    // ---- blank query ----

    @Test fun blankQuery_matchesNothing() {
        assertTrue(SearchMatching.rank(catalogue, "").isEmpty())
        assertTrue(SearchMatching.rank(catalogue, "   ").isEmpty())
        assertTrue(SearchMatching.filterGrouped(catalogue, "").isEmpty())
    }

    // ---- substring / case-insensitive ----

    @Test fun matchesCaseInsensitiveSubstring() {
        val titles = SearchMatching.rank(catalogue, "btc").map { it.title }
        assertEquals(listOf("BTCUSDC"), titles)
    }

    @Test fun matchesKeywordAlias() {
        // "usdc" is a keyword on all three symbols; none has it in the title as a prefix.
        val ids = SearchMatching.rank(catalogue, "usdc").map { it.symbolId }.toSet()
        assertEquals(setOf(1, 2, 3), ids)
    }

    @Test fun matchesSubtitle() {
        val titles = SearchMatching.rank(catalogue, "balances").map { it.title }
        assertEquals(listOf("Portfolio"), titles)
    }

    @Test fun noMatch_returnsEmpty() {
        assertTrue(SearchMatching.rank(catalogue, "zzznope").isEmpty())
    }

    // ---- scoring tiers ----

    @Test fun exactTitle_scoresZero() {
        assertEquals(0, SearchMatching.score(dest("Deposit"), "deposit"))
    }

    @Test fun titlePrefix_beatsWordPrefix_beatsContains() {
        val prefix = SearchMatching.score(dest("Markets"), "mark")!!
        val wordPrefix = SearchMatching.score(dest("Price alerts"), "alert")!!
        val contains = SearchMatching.score(dest("Portfolio"), "folio")!!
        assertTrue(prefix < wordPrefix)
        assertTrue(wordPrefix < contains)
    }

    @Test fun keywordOnly_scoresWorstTier() {
        assertEquals(4, SearchMatching.score(dest("Markets", "x", "watchlist"), "watchlist"))
    }

    @Test fun score_nullWhenNoMatch() {
        assertNull(SearchMatching.score(dest("Markets"), "zzz"))
    }

    // ---- ranking / determinism ----

    @Test fun prefixMatchRanksAboveKeywordMatch() {
        val items = listOf(
            dest("Alpha", "x", "target"),   // keyword-only match on "target"
            dest("Target", "y"),            // title-prefix match on "target"
        )
        val ranked = SearchMatching.rank(items, "target")
        assertEquals(listOf("Target", "Alpha"), ranked.map { it.title })
    }

    @Test fun ties_breakByKindThenTitle() {
        // Both are exact-title (score 0) for "x"; kind order = SYMBOL before DESTINATION.
        val items = listOf(
            dest("x"),
            symbol(9, "x"),
        )
        val ranked = SearchMatching.rank(items, "x")
        assertEquals(SearchResultKind.SYMBOL, ranked.first().kind)
    }

    // ---- grouping ----

    @Test fun filterGrouped_groupsByKindInKindOrder() {
        val groups = SearchMatching.filterGrouped(catalogue, "usdc")
        // "usdc" only hits symbols here.
        assertEquals(listOf(SearchResultKind.SYMBOL), groups.map { it.kind })
    }

    @Test fun filterGrouped_multipleKindsOrdered() {
        // "price" hits the "Price alerts" destination + the "New price alert" action.
        val groups = SearchMatching.filterGrouped(catalogue, "price")
        val kinds = groups.map { it.kind }
        assertEquals(listOf(SearchResultKind.DESTINATION, SearchResultKind.ACTION), kinds)
    }
}
