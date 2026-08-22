package com.testlogon.android.feature.invest

import kotlin.math.abs

/**
 * PURE, dependency-free logic for the unified INVEST hub. Everything here is deterministic over plain
 * inputs (no Android, no coroutines, no repositories) so it is exhaustively unit-testable (see
 * InvestMathTest). The ViewModel maps its heterogeneous repository domain models down to the
 * normalized [InvestItem] shape, then leans on these functions for search + ranking.
 *
 * The hub aggregates five investable/tradeable product classes that each already live in their own
 * screen: exchange markets, creator revenue-share tokens, strategy funds, staking, and open
 * opportunities (IPO token auctions / bailout rescue auctions / peer stake+auction discovery). By
 * collapsing them all to [InvestItem] the UI renders one uniform card and one search box filters
 * across every section at once.
 */

/** The product class an [InvestItem] belongs to — drives its section + which detail route it opens. */
enum class InvestKind {
    MARKET,
    TOKEN,
    STRATEGY,
    STAKING,
    OPPORTUNITY,
}

/**
 * A normalized, render-ready row for ANY investable product. Kept intentionally flat so a single card
 * composable can present a market, a token, a strategy fund, a staking provider, or an opportunity
 * without branching.
 *
 * @property kind which product class this is (also selects the section).
 * @property id the stable per-kind identifier (symbolId as string, tokenId, strategyId, provider id, ...).
 * @property title the primary label (ticker / name).
 * @property subtitle the secondary label (full name / descriptor); may be blank.
 * @property metric a short headline metric string already formatted for display (may be blank).
 * @property route the in-app navigation route this item opens (blank = not navigable on its own).
 * @property sortKey a numeric key the ranking helpers sort DESC by (e.g. |change|, return bps, AUM,
 *   capacity-remaining fraction scaled). Higher = more prominent. Defaults to 0.
 * @property searchText extra lowercase text folded into search matching beyond title/subtitle (e.g. a
 *   ticker distinct from the title, a chain/asset name). Kept lowercase to avoid per-query work.
 */
data class InvestItem(
    val kind: InvestKind,
    val id: String,
    val title: String,
    val subtitle: String = "",
    val metric: String = "",
    val route: String = "",
    val sortKey: Double = 0.0,
    val searchText: String = "",
)

object InvestMath {

    /** Normalize a query for matching: trimmed + lowercased. */
    fun normalizeQuery(query: String): String = query.trim().lowercase()

    /**
     * Whether [item] matches [query] (heterogeneous search across symbol/token/strategy/etc). A blank
     * query matches everything. Matching is a case-insensitive substring test over the title, subtitle,
     * id, and the item's extra [InvestItem.searchText] (ticker/name/chain/asset). This is the single
     * definition of "matches" the ViewModel uses so every section filters consistently.
     */
    fun matches(item: InvestItem, query: String): Boolean {
        val q = normalizeQuery(query)
        if (q.isEmpty()) return true
        val hay = buildString {
            append(item.title.lowercase()); append(' ')
            append(item.subtitle.lowercase()); append(' ')
            append(item.id.lowercase()); append(' ')
            append(item.searchText)
        }
        return hay.contains(q)
    }

    /** Filter a list to the items matching [query] (order preserved). */
    fun filter(items: List<InvestItem>, query: String): List<InvestItem> =
        items.filter { matches(it, query) }

    /**
     * Rank DESC by [InvestItem.sortKey] (highest first), tie-broken by title then id for a STABLE,
     * deterministic order. Used to surface top movers / best-returning strategies / largest funds /
     * most-open-capacity first within a section.
     */
    fun rankBySortKey(items: List<InvestItem>): List<InvestItem> =
        items.sortedWith(
            compareByDescending<InvestItem> { it.sortKey }
                .thenBy { it.title.lowercase() }
                .thenBy { it.id },
        )

    /** Take the top [n] after ranking DESC by sort key (n <= 0 -> empty). */
    fun topN(items: List<InvestItem>, n: Int): List<InvestItem> =
        if (n <= 0) emptyList() else rankBySortKey(items).take(n)

    // ---- Numeric sort-key helpers (one definition per ranking dimension) ----

    /** Top-movers key: absolute value of a percent change (null change -> 0, never negative). */
    fun moverKey(changePct: Double?): Double = abs(changePct ?: 0.0)

    /** Strategy-by-return key: inception return in bps as a Double (null -> 0; negatives allowed). */
    fun returnKey(inceptionReturnBps: Int?): Double = (inceptionReturnBps ?: 0).toDouble()

    /** Size key: AUM in cents as a Double (null -> 0). Larger funds rank first. */
    fun aumKey(aumCents: Long?): Double = (aumCents ?: 0L).toDouble()

    /**
     * Capacity-remaining FRACTION of a capped fund: remaining / max, clamped to [0,1]. Returns null
     * when there is no cap (maxAumCents <= 0) so the caller can treat "uncapped" distinctly from
     * "full". A higher fraction = more room to invest.
     */
    fun capacityRemainingFraction(maxAumCents: Long, aumCents: Long?): Double? {
        if (maxAumCents <= 0L) return null
        val used = (aumCents ?: 0L).coerceAtLeast(0L)
        val remaining = (maxAumCents - used).coerceAtLeast(0L)
        return (remaining.toDouble() / maxAumCents.toDouble()).coerceIn(0.0, 1.0)
    }

    /**
     * The grand-total count across a set of section item-lists — powers the hub header ("N products")
     * and the honest "nothing matches your search" empty state.
     */
    fun totalCount(sections: List<List<InvestItem>>): Int = sections.sumOf { it.size }
}
