package com.testlogon.android.data.exchange.watchlist

/**
 * UNIFIED cross-instrument watchlist model + FRAMEWORK-FREE pure helpers.
 *
 * The watchlist historically held only exchange symbols (a set of numeric symbolIds persisted under the
 * legacy [WatchKind.SYMBOL] contract). It now holds three kinds of watchable thing — exchange SYMBOLs,
 * creator TOKENs, and STRATEGY funds — under one set. Each entry is identified by a stable per-kind id
 * ([WatchItem.id]): the symbolId string for a symbol, the tokenId for a token, the strategyId for a
 * strategy. Serialisation is a single flat string "KIND:id" ([watchKey]); legacy bare-integer entries
 * (no "KIND:" prefix) migrate transparently to [WatchKind.SYMBOL] via [migrateLegacy].
 *
 * Everything here is pure (no Android / coroutine dependency) so it is unit-testable on the JVM.
 */
enum class WatchKind { SYMBOL, TOKEN, STRATEGY }

/** One watched item: its [kind] and the per-kind stable [id]. */
data class WatchItem(val kind: WatchKind, val id: String) {
    /** The flat serialised key for this item. */
    val key: String get() = watchKey(kind, id)
}

/** Convenience: a symbol watch item from the numeric symbolId. */
fun symbolWatch(symbolId: Int): WatchItem = WatchItem(WatchKind.SYMBOL, symbolId.toString())

/** The flat serialised key for a (kind, id) pair — "SYMBOL:1", "TOKEN:abc", "STRATEGY:xyz". */
fun watchKey(kind: WatchKind, id: String): String = "${kind.name}:$id"

/**
 * Parse one persisted key back into a [WatchItem]. A key WITHOUT a recognised "KIND:" prefix is a
 * LEGACY symbol entry (the pre-unification format was a bare symbolId) and maps to [WatchKind.SYMBOL].
 * Returns null only for a blank token.
 */
fun parseWatchKey(raw: String): WatchItem? {
    val s = raw.trim()
    if (s.isEmpty()) return null
    val idx = s.indexOf(':')
    if (idx > 0) {
        val kindStr = s.substring(0, idx)
        val id = s.substring(idx + 1)
        val kind = WatchKind.entries.firstOrNull { it.name == kindStr }
        if (kind != null && id.isNotEmpty()) return WatchItem(kind, id)
    }
    // Legacy bare-id (symbol) entry.
    return WatchItem(WatchKind.SYMBOL, s)
}

/**
 * Migrate a raw persisted set of keys (possibly a mix of legacy bare symbolIds and new "KIND:id"
 * keys) into the canonical [WatchItem] set. Blank/garbage tokens are dropped. Idempotent: running it on
 * an already-migrated set yields the same set.
 */
fun migrateLegacy(raw: Set<String>): Set<WatchItem> =
    raw.mapNotNull { parseWatchKey(it) }.toSet()

/** True when [items] contains an entry matching [kind] + [id]. */
fun isWatched(items: Set<WatchItem>, kind: WatchKind, id: String): Boolean =
    items.any { it.kind == kind && it.id == id }

/**
 * Toggle (kind, id) in [items]: remove it when present, add it otherwise. Returns a NEW set (never
 * mutates the input) so it composes cleanly with immutable state.
 */
fun toggleWatch(items: Set<WatchItem>, kind: WatchKind, id: String): Set<WatchItem> {
    val existing = items.firstOrNull { it.kind == kind && it.id == id }
    return if (existing != null) items - existing else items + WatchItem(kind, id)
}

/** Only the SYMBOL entries, as the numeric symbolId set (the shape the markets filter consumes). */
fun symbolIds(items: Set<WatchItem>): Set<Int> =
    items.filter { it.kind == WatchKind.SYMBOL }.mapNotNull { it.id.toIntOrNull() }.toSet()

/** Serialise a set to the flat persisted key set. */
fun serialize(items: Set<WatchItem>): Set<String> = items.map { it.key }.toSet()

/** A stable display order: group by kind (SYMBOL, TOKEN, STRATEGY) then by id within each kind. */
fun sortForDisplay(items: Collection<WatchItem>): List<WatchItem> =
    items.sortedWith(compareBy({ it.kind.ordinal }, { it.id }))

/** Short human label for a kind badge. */
fun kindLabel(kind: WatchKind): String = when (kind) {
    WatchKind.SYMBOL -> "Symbol"
    WatchKind.TOKEN -> "Token"
    WatchKind.STRATEGY -> "Strategy"
}
