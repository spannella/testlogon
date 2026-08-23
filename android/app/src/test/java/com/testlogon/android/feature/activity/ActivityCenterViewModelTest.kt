package com.testlogon.android.feature.activity

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.FillFee
import com.testlogon.android.data.exchange.FillsFees
import com.testlogon.android.data.exchange.Liquidity
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.feature.trading.FakeActivityLastSeenStore
import com.testlogon.android.feature.trading.FakeTradingRepository
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * ViewModel coverage for [ActivityCenterViewModel] using the [com.testlogon.android.data.activity.ActivityLastSeenStore]
 * interface seam: a degrade case where every feed fails (empty timeline + degraded-source banner) and a
 * happy path where the fills feed produces events, plus markAllRead() advancing the fake store.
 */
class ActivityCenterViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun sampleFill(ts: Long) = FillFee(
        symbolId = 1,
        price = 100,
        qty = 5,
        side = OrderSide.BUY,
        liquidity = Liquidity.TAKER,
        fee = 1,
        feeAsset = 0,
        tsNs = ts,
    )

    @Test
    fun degrade_allFeedsFail_toEmptyWithDegradedSources() = runTest(mainRule.dispatcher) {
        val trading = FakeTradingRepository().apply {
            val net = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
            fillsFeesResult = net
            fundingPaymentsResult = net
            liquidationsResult = net
            marginAccountResult = net
            pmResolutionsResult = net
        }
        val vm = ActivityCenterViewModel(trading, FakeActivityLastSeenStore())
        backgroundScope.launch { vm.state.collect {} }
        advanceUntilIdle()
        val s = vm.state.value
        assertFalse(s.loading)
        assertTrue(s.days.isEmpty())
        assertEquals(0, s.total)
        // Trades / Funding / Liquidations / System all reported as degraded (margin 403 is not a source).
        assertTrue(s.degradedSources.containsAll(listOf("Trades", "Funding", "Liquidations", "System")))
    }

    @Test
    fun happy_fillsProduceEventsAndUnread() = runTest(mainRule.dispatcher) {
        val trading = FakeTradingRepository().apply {
            fillsFeesResult = ApiResult.Success(FillsFees(listOf(sampleFill(2_000_000L), sampleFill(3_000_000L)), 2))
        }
        val vm = ActivityCenterViewModel(trading, FakeActivityLastSeenStore())
        backgroundScope.launch { vm.state.collect {} }
        backgroundScope.launch { vm.unreadCount.collect {} }
        advanceUntilIdle()
        val s = vm.state.value
        assertEquals(2, s.total)
        assertTrue(s.days.isNotEmpty())
        assertEquals(2, vm.unreadCount.value)
    }

    @Test
    fun markAllRead_advancesStore_clearsUnread() = runTest(mainRule.dispatcher) {
        val store = FakeActivityLastSeenStore()
        val trading = FakeTradingRepository().apply {
            fillsFeesResult = ApiResult.Success(FillsFees(listOf(sampleFill(2_000_000L)), 1))
        }
        val vm = ActivityCenterViewModel(trading, store)
        backgroundScope.launch { vm.unreadCount.collect {} }
        advanceUntilIdle()
        assertEquals(1, vm.unreadCount.value)
        vm.markAllRead()
        advanceUntilIdle()
        assertTrue(store.setCalls >= 1)
        assertEquals(0, vm.unreadCount.value)
    }
}
