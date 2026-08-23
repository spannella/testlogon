package com.testlogon.android.feature.invest

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.feature.trading.FakeBailoutRepository
import com.testlogon.android.feature.trading.FakeCustodyReader
import com.testlogon.android.feature.trading.FakeExchangeRepository
import com.testlogon.android.feature.trading.FakeStrategiesRepository
import com.testlogon.android.feature.trading.FakeTokensRepository
import com.testlogon.android.feature.trading.FakeTradingRepository
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * ViewModel coverage for [InvestViewModel] via the [com.testlogon.android.data.custody.CustodyReader]
 * seam: an all-degraded case (every section pending, Content phase), a happy path where the markets
 * section is populated from the exchange fake, and a transport failure -> retryable Error.
 */
class InvestViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun vm(exchange: FakeExchangeRepository = FakeExchangeRepository()) = InvestViewModel(
        exchange = exchange,
        tokens = FakeTokensRepository(),
        strategies = FakeStrategiesRepository(),
        custody = FakeCustodyReader(),
        bailout = FakeBailoutRepository(),
        trading = FakeTradingRepository(),
    )

    @Test
    fun degrade_allEmpty_toContentAllPending() = runTest(mainRule.dispatcher) {
        val vm = vm()
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(InvestUiState.Phase.Content, s.phase)
        assertTrue(s.markets.pending)
        assertTrue(s.tokens.pending)
        assertTrue(s.strategies.pending)
        assertTrue(s.staking.pending)
        assertTrue(s.opportunities.pending)
        assertEquals(0, s.totalCount)
    }

    @Test
    fun happy_marketsPopulated() = runTest(mainRule.dispatcher) {
        val exchange = FakeExchangeRepository(
            symbolsResult = ApiResult.Success(
                listOf(
                    Instrument(symbol = "BTC-USD", symbolId = 1, priceScaler = 1, lotSize = 1, referencePrice = 100, isPerpetual = false),
                    Instrument(symbol = "ETH-PERP", symbolId = 2, priceScaler = 1, lotSize = 1, referencePrice = 50, isPerpetual = true),
                ),
            ),
        )
        val vm = vm(exchange)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(InvestUiState.Phase.Content, s.phase)
        assertEquals(2, s.markets.items.size)
        assertTrue(s.totalCount >= 2)
    }

    @Test
    fun transportFailure_toRetryableError() = runTest(mainRule.dispatcher) {
        val exchange = FakeExchangeRepository(symbolsResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false))
        val vm = vm(exchange)
        advanceUntilIdle()
        assertEquals(InvestUiState.Phase.Error, vm.uiState.value.phase)
        assertTrue(vm.uiState.value.errorMessage != null)
    }
}
