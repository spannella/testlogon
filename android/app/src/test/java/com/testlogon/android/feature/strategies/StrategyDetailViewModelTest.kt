package com.testlogon.android.feature.strategies

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.watchlist.WatchKind
import com.testlogon.android.feature.trading.FakeStrategiesRepository
import com.testlogon.android.feature.trading.FakeWatchlistStore
import com.testlogon.android.feature.trading.sampleStrategyFake
import com.testlogon.android.navigation.StrategyDetailDest
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * ViewModel coverage for [StrategyDetailViewModel] via the [com.testlogon.android.data.exchange.watchlist.WatchlistStore]
 * seam: degrade-to-empty Content (strategy read folds 404 to Success(null)), a happy path with a
 * strategy, a transport failure -> retryable Error, and the watch-star toggle calling the fake store.
 */
class StrategyDetailViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun handle(id: String) = SavedStateHandle(mapOf(StrategyDetailDest.ARG_STRATEGY_ID to id))

    @Test
    fun degrade_nullStrategy_toContent() = runTest(mainRule.dispatcher) {
        val vm = StrategyDetailViewModel(FakeStrategiesRepository(), FakeWatchlistStore(), handle("s-1"))
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(StrategyDetailUiState.Phase.Content, s.phase)
        assertNull(s.strategy)
    }

    @Test
    fun happy_strategySurfaced() = runTest(mainRule.dispatcher) {
        val repo = FakeStrategiesRepository(strategyResult = ApiResult.Success(sampleStrategyFake("s-1", "Alpha")))
        val vm = StrategyDetailViewModel(repo, FakeWatchlistStore(), handle("s-1"))
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(StrategyDetailUiState.Phase.Content, s.phase)
        assertEquals("Alpha", s.strategy?.name)
    }

    @Test
    fun transportFailure_toRetryableError() = runTest(mainRule.dispatcher) {
        val repo = FakeStrategiesRepository(strategyResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false))
        val vm = StrategyDetailViewModel(repo, FakeWatchlistStore(), handle("s-1"))
        advanceUntilIdle()
        assertEquals(StrategyDetailUiState.Phase.Error, vm.uiState.value.phase)
        assertTrue(vm.uiState.value.errorMessage != null)
    }

    @Test
    fun toggleWatch_callsStore() = runTest(mainRule.dispatcher) {
        val store = FakeWatchlistStore()
        val vm = StrategyDetailViewModel(FakeStrategiesRepository(), store, handle("s-1"))
        advanceUntilIdle()
        assertFalse(vm.isWatched.value)
        vm.toggleWatch()
        advanceUntilIdle()
        assertEquals(WatchKind.STRATEGY to "s-1", store.toggleCalls.single())
        assertTrue(store.isWatched(WatchKind.STRATEGY, "s-1"))
    }
}
