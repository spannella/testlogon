package com.testlogon.android.feature.portfolioanalytics

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.custody.CustodyAssets
import com.testlogon.android.data.custody.CustodyBalances
import com.testlogon.android.data.exchange.PriceMap
import com.testlogon.android.feature.trading.FakeCustodyReader
import com.testlogon.android.feature.trading.FakeExchangeRepository
import com.testlogon.android.feature.trading.FakeStrategiesRepository
import com.testlogon.android.feature.trading.FakeTokensRepository
import com.testlogon.android.feature.trading.FakeTradingRepository
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * ViewModel coverage for [PortfolioAnalyticsViewModel] via the new [com.testlogon.android.data.custody.CustodyReader]
 * seam: an all-degraded case (every source empty -> allEmpty, no crash) and a happy path where a funded
 * custody balance + a price map produce a valued position.
 */
class PortfolioAnalyticsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun vm(
        custody: FakeCustodyReader = FakeCustodyReader(),
        trading: FakeTradingRepository = FakeTradingRepository(),
    ) = PortfolioAnalyticsViewModel(
        custody = custody,
        trading = trading,
        exchange = FakeExchangeRepository(),
        tokens = FakeTokensRepository(),
        strategies = FakeStrategiesRepository(),
    )

    @Test
    fun degrade_allEmpty_noCrash() = runTest(mainRule.dispatcher) {
        val vm = vm()
        advanceUntilIdle()
        val s = vm.uiState.value
        assertFalse(s.loading)
        assertTrue(s.allEmpty)
        assertTrue(s.positions.isEmpty())
        assertEquals(0L, s.totalValueCents)
    }

    @Test
    fun happy_fundedCustodyValued() = runTest(mainRule.dispatcher) {
        val custody = FakeCustodyReader(
            balanceResult = ApiResult.Success(
                CustodyBalances(vault = "v", tier = "T1", rows = CustodyAssets.mergeBalances(mapOf("ETH" to 2.0))),
            ),
        )
        val trading = FakeTradingRepository().apply {
            pricesResult = ApiResult.Success(
                PriceMap(prices = mapOf("ETH" to 1_000.0), quote = "USD", source = "test", stub = false, note = null),
            )
        }
        val vm = vm(custody, trading)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertFalse(s.allEmpty)
        assertTrue(s.positions.any { it.key == "ETH" })
        // 2 ETH * $1000 = $2000 = 200_000 cents.
        assertEquals(200_000L, s.totalValueCents)
    }
}
