package com.testlogon.android.data.exchange.watchlist

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Device-local UNIFIED watchlist store: the single source of truth for the starred set across
 * exchange SYMBOLs, creator TOKENs, and STRATEGY funds.
 *
 * Persistence lives in the SAME [PREFS] file the symbol watchlist has always used ("markets_prefs")
 * so nothing else has to move. The new canonical value is a serialised [WatchItem] set under
 * [KEY_ITEMS]; the ORIGINAL symbol-only set under [KEY_FAV] (bare symbolId strings) is kept in sync on
 * every write so the existing Markets Watchlist filter (which reads that key) keeps working unchanged.
 *
 * Migration is transparent: on first construction any legacy entries (bare symbolIds under [KEY_FAV],
 * or un-prefixed keys) are folded into the unified set via [migrateLegacy] and written back.
 */
@Singleton
class WatchlistStore @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private val _items = MutableStateFlow(loadAndMigrate())

    /** The full unified watchlist, live. */
    val items: StateFlow<Set<WatchItem>> = _items.asStateFlow()

    /** Snapshot read of the current unified set. */
    fun current(): Set<WatchItem> = _items.value

    /** True when (kind, id) is currently watched. */
    fun isWatched(kind: WatchKind, id: String): Boolean = isWatched(_items.value, kind, id)

    /** Toggle (kind, id) in the watchlist, persisting the result. Returns the new watched-state. */
    fun toggle(kind: WatchKind, id: String): Boolean {
        val next = toggleWatch(_items.value, kind, id)
        persist(next)
        return isWatched(next, kind, id)
    }

    /** Remove (kind, id) if present. */
    fun remove(kind: WatchKind, id: String) {
        val existing = _items.value.firstOrNull { it.kind == kind && it.id == id } ?: return
        persist(_items.value - existing)
    }

    /** Convenience: the SYMBOL entries as a numeric id set (the markets filter shape). */
    fun symbolIds(): Set<Int> = symbolIds(_items.value)

    private fun persist(next: Set<WatchItem>) {
        prefs.edit()
            .putStringSet(KEY_ITEMS, serialize(next))
            // Keep the legacy symbol-only key in lock-step for the existing Markets filter / any reader.
            .putStringSet(KEY_FAV, symbolIds(next).map { it.toString() }.toSet())
            .apply()
        _items.value = next
    }

    /**
     * Load the canonical items, folding in any legacy symbol-only entries. If a migration actually
     * changed the persisted shape (first run after upgrade), write the canonical form back so both keys
     * are consistent going forward.
     */
    private fun loadAndMigrate(): Set<WatchItem> {
        val itemKeys = prefs.getStringSet(KEY_ITEMS, null)
        val legacyFav = prefs.getStringSet(KEY_FAV, emptySet()).orEmpty()
        val fromItems = migrateLegacy(itemKeys.orEmpty())
        val fromLegacy = migrateLegacy(legacyFav)
        val merged = fromItems + fromLegacy
        val needsWriteBack = itemKeys == null || serialize(merged) != itemKeys ||
            legacyFav != symbolIds(merged).map { it.toString() }.toSet()
        if (needsWriteBack) {
            prefs.edit()
                .putStringSet(KEY_ITEMS, serialize(merged))
                .putStringSet(KEY_FAV, symbolIds(merged).map { it.toString() }.toSet())
                .apply()
        }
        return merged
    }

    companion object {
        // Same file + legacy key the symbol watchlist has always used (see MarketsViewModel).
        const val PREFS = "markets_prefs"
        const val KEY_FAV = "favorites"
        const val KEY_ITEMS = "watch_items"
    }
}
