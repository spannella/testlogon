package com.testlogon.android.feature.ads

/**
 * FE-161 (EPIC G, <- BE-161/BE-162) — PURE, framework-free math for interleaving served SPONSORED
 * units into an organic list (market / token-discovery, catalog & search). No Android/Compose deps so
 * it is fully JVM-unit-testable.
 *
 * A rendered list is an ordered sequence of [SlotEntry]: [SlotEntry.Organic] wraps a real list item,
 * [SlotEntry.Sponsored] wraps a served ad with a stable de-dupe [SlotEntry.Sponsored.key]. Sponsored
 * slots are inserted deterministically every N organic items, never adjacent to each other, never
 * past the end of the organic list, capped at both the available served count and [max]. When no ads
 * fill, the output is exactly the organic list (identity) — the organic rendering is unchanged.
 */
sealed interface SlotEntry<out T, out A> {
    data class Organic<out T>(val item: T) : SlotEntry<T, Nothing>
    data class Sponsored<out A>(val ad: A, val key: String) : SlotEntry<Nothing, A>
}

/**
 * How many sponsored slots a list of [itemCount] organic items can hold at a cadence of one slot per
 * [everyN] items, capped at [max]. A slot is placed AFTER each run of [everyN] organic items, and
 * never after the final item (a slot must be followed by at least one organic item — "never past
 * end"), so the count is `floor((itemCount) / everyN)` clamped so the last placement still has a
 * trailing organic item, then capped at [max].
 */
fun sponsoredSlotCount(itemCount: Int, everyN: Int, max: Int): Int {
    if (itemCount <= 0 || everyN <= 0 || max <= 0) return 0
    // Slots go after positions everyN, 2*everyN, ... but the position must be strictly before the
    // last item so a sponsored entry is never the terminal row and never sits past the end.
    var slots = 0
    var pos = everyN
    while (pos < itemCount && slots < max) {
        slots++
        pos += everyN
    }
    return slots
}

/**
 * Interleave [sponsored] ads into [items] every [everyN] organic items, beginning the cadence at
 * [startAt] organic items in, capped at [max] and at the available [sponsored] count.
 *
 * Guarantees:
 *  - deterministic ordering (organic order preserved; ads consumed in order);
 *  - a sponsored slot is only ever placed AFTER an organic item and BEFORE another organic item, so
 *    two sponsored slots are never adjacent and none is the last entry ("never past end");
 *  - respects the available served count (stops when [sponsored] is exhausted) and [max];
 *  - identity when [sponsored] is empty (returns exactly the organic list) — organic rendering is
 *    unchanged when no ads fill.
 *
 * @param key stable per-ad key (used for de-dupe / LazyColumn keys). Defaults to the ad index.
 */
fun <T, A> interleaveSponsored(
    items: List<T>,
    sponsored: List<A>,
    everyN: Int,
    startAt: Int = everyN,
    max: Int = Int.MAX_VALUE,
    key: (index: Int, ad: A) -> String = { i, _ -> "sponsored_$i" },
): List<SlotEntry<T, A>> {
    val out = ArrayList<SlotEntry<T, A>>(items.size + minOf(sponsored.size, if (max > 0) max else 0))
    // Degrade / guard: nothing to inject -> return the organic list verbatim.
    if (sponsored.isEmpty() || everyN <= 0 || max <= 0 || items.isEmpty()) {
        items.forEach { out.add(SlotEntry.Organic(it)) }
        return out
    }
    val effectiveStart = if (startAt <= 0) everyN else startAt
    var placed = 0
    var adIndex = 0
    for ((i, item) in items.withIndex()) {
        out.add(SlotEntry.Organic(item))
        val organicSoFar = i + 1
        val isLast = organicSoFar == items.size
        // Place a slot after this organic item when we've hit a cadence boundary, there is at least
        // one more organic item to follow (never last / never past end), an ad is available, and we're
        // under the cap.
        val atBoundary = organicSoFar >= effectiveStart &&
            (organicSoFar - effectiveStart) % everyN == 0
        if (atBoundary && !isLast && adIndex < sponsored.size && placed < max) {
            val ad = sponsored[adIndex]
            out.add(SlotEntry.Sponsored(ad, key(adIndex, ad)))
            adIndex++
            placed++
        }
    }
    return out
}

/**
 * FE-161 — a served /ui/ads (shop) unit is a valid, renderable sponsored slot only when the serve was
 * FILLED and carries a non-blank creative id (the money-path track call requires it). Degrade-on-404 /
 * unfilled -> false -> no slot rendered.
 */
fun isValidServe(filled: Boolean, creativeId: String?): Boolean =
    filled && !creativeId.isNullOrBlank()
