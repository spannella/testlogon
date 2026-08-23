package com.testlogon.android.feature.watchlist

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.data.exchange.watchlist.WatchItem
import com.testlogon.android.data.exchange.watchlist.WatchKind
import com.testlogon.android.feature.trading.FakeExchangeRepository
import com.testlogon.android.feature.trading.FakeStrategiesRepository
import com.testlogon.android.feature.trading.FakeTokensRepository
import com.testlogon.android.feature.trading.FakeWatchlistStore
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * ViewModel-level coverage for [WatchlistViewModel] using the new [com.testlogon.android.data.exchange.watchlist.WatchlistStore]
 * interface seam. Empty store -> Empty phase; a populated store enriches rows (degrading per-item to
 * skeleton labels when the enrichment repos return empty); remove() calls through to the store.
 */
class WatchlistViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun vm(store: FakeWatchlistStore, symbols: List<Instrument> = emptyList()) = WatchlistViewModel(
        watchlist = store,
        exchange = FakeExchangeRepository(symbolsResult = ApiResult.Success(symbols)),
        tokens = FakeTokensRepository(),
        strategies = FakeStrategiesRepository(),
    )

    @Test
    fun empty_store_toEmptyPhase() = runTest(mainRule.dispatcher) {
        val vm = vm(FakeWatchlistStore())
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(WatchlistUiState.Phase.Empty, s.phase)
        assertTrue(s.rows.isEmpty())
    }

    @Test
    fun happy_populated_rendersRows() = runTest(mainRule.dispatcher) {
        val store = FakeWatchlistStore(
            setOf(
                WatchItem(WatchKind.SYMBOL, "1"),
                WatchItem(WatchKind.TOKEN, "tok-a"),
                WatchItem(WatchKind.STRATEGY, "strat-a"),
            ),
        )
        val vm = vm(
            store,
            symbols = listOf(Instrument(symbol = "BTC-USD", symbolId = 1, priceScaler = 1, lotSize = 1, referencePrice = 100, isPerpetual = false)),
        )
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(WatchlistUiState.Phase.Content, s.phase)
        assertEquals(3, s.rows.size)
        // The symbol row picked up its instrument label from the exchange fake.
        assertTrue(s.rows.any { it.title == "BTC-USD" })
    }

    @Test
    fun remove_callsStore_andReRenders() = runTest(mainRule.dispatcher) {
        val item = WatchItem(WatchKind.TOKEN, "tok-a")
        val store = FakeWatchlistStore(setOf(item))
        val vm = vm(store)
        advanceUntilIdle()
        vm.remove(item)
        advanceUntilIdle()
        assertEquals(1, store.removeCalls.size)
        assertEquals(WatchKind.TOKEN to "tok-a", store.removeCalls.first())
        assertEquals(WatchlistUiState.Phase.Empty, vm.uiState.value.phase)
    }
}
