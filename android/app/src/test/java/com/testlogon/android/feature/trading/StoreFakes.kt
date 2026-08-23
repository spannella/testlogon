package com.testlogon.android.feature.trading

import com.testlogon.android.data.activity.ActivityLastSeenStore
import com.testlogon.android.data.exchange.watchlist.WatchItem
import com.testlogon.android.data.exchange.watchlist.WatchKind
import com.testlogon.android.data.exchange.watchlist.WatchlistStore
import com.testlogon.android.data.exchange.watchlist.isWatched
import com.testlogon.android.data.exchange.watchlist.symbolIds
import com.testlogon.android.data.exchange.watchlist.toggleWatch
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * In-memory [WatchlistStore] fake for ViewModel tests. Reuses the pure watchlist helpers so the toggle
 * / remove / symbolIds semantics match the real store exactly, without SharedPreferences/Context.
 * [toggleCalls] records the (kind, id) toggles so a test can assert the star affordance calls through.
 */
class FakeWatchlistStore(initial: Set<WatchItem> = emptySet()) : WatchlistStore {
    private val _items = MutableStateFlow(initial)
    override val items: StateFlow<Set<WatchItem>> = _items.asStateFlow()

    val toggleCalls = mutableListOf<Pair<WatchKind, String>>()
    val removeCalls = mutableListOf<Pair<WatchKind, String>>()

    override fun current(): Set<WatchItem> = _items.value
    override fun isWatched(kind: WatchKind, id: String): Boolean = isWatched(_items.value, kind, id)
    override fun toggle(kind: WatchKind, id: String): Boolean {
        toggleCalls.add(kind to id)
        _items.value = toggleWatch(_items.value, kind, id)
        return isWatched(_items.value, kind, id)
    }
    override fun remove(kind: WatchKind, id: String) {
        removeCalls.add(kind to id)
        _items.value = _items.value.filterNot { it.kind == kind && it.id == id }.toSet()
    }
    override fun symbolIds(): Set<Int> = symbolIds(_items.value)
}

/** In-memory [ActivityLastSeenStore] fake: a monotonic last-seen mark, no DataStore. */
class FakeActivityLastSeenStore(initial: Long = 0L) : ActivityLastSeenStore {
    private val _lastSeen = MutableStateFlow(initial)
    override val lastSeen: Flow<Long> = _lastSeen.asStateFlow()
    var setCalls = 0
        private set
    override suspend fun setLastSeen(ts: Long) {
        setCalls++
        if (ts > _lastSeen.value) _lastSeen.value = ts
    }
}
