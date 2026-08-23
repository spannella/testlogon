package com.testlogon.android.feature.strategies

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.strategies.InvestorPosition
import com.testlogon.android.data.strategies.Strategy
import com.testlogon.android.data.strategies.StrategiesRepository
import com.testlogon.android.data.strategies.StrategyAck
import com.testlogon.android.data.strategies.StrategyFees
import com.testlogon.android.data.strategies.StrategyHolding
import com.testlogon.android.data.strategies.StrategyNav
import com.testlogon.android.data.strategies.UpsertStrategyRequestDto
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

private fun sampleStrategy(id: String, name: String) = Strategy(strategyId = id, name = name)

private class FakeStrategiesRepo(
    var marketResult: ApiResult<List<Strategy>> = ApiResult.Success(emptyList()),
    var mineResult: ApiResult<List<Strategy>> = ApiResult.Success(emptyList()),
) : StrategiesRepository {
    override suspend fun mine(): ApiResult<List<Strategy>> = mineResult
    override suspend fun market(): ApiResult<List<Strategy>> = marketResult
    override suspend fun strategy(id: String): ApiResult<Strategy?> = ApiResult.Success(null)
    override suspend fun nav(id: String): ApiResult<StrategyNav?> = ApiResult.Success(null)
    override suspend fun holdings(id: String): ApiResult<List<StrategyHolding>> = ApiResult.Success(emptyList())
    override suspend fun position(id: String): ApiResult<InvestorPosition?> = ApiResult.Success(null)
    override suspend fun fees(id: String): ApiResult<StrategyFees> = ApiResult.Success(StrategyFees(id, 0, 0, 0, emptyList()))
    override suspend fun create(body: UpsertStrategyRequestDto) = ApiResult.Success(sampleStrategy("x", "x"))
    override suspend fun update(id: String, body: UpsertStrategyRequestDto) = ApiResult.Success(sampleStrategy(id, "x"))
    override suspend fun publish(id: String) = ApiResult.Success(sampleStrategy(id, "x"))
    override suspend fun invest(id: String, amountCents: Long) = ApiResult.Success(StrategyAck(true))
    override suspend fun redeem(id: String, units: Long) = ApiResult.Success(StrategyAck(true))
}

/**
 * ViewModel-level coverage for [StrategyMarketViewModel]: degrade-on-404 -> empty Content, happy path
 * with a fake repo returning marketplace + authored strategies, and transport failure -> retryable
 * Error. Complements the pure StrategyMath tests.
 */
class StrategyMarketViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    @Test
    fun degrade_bothEmpty_toEmptyContent() = runTest(mainRule.dispatcher) {
        val vm = StrategyMarketViewModel(FakeStrategiesRepo())
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(StrategyMarketUiState.Phase.Content, s.phase)
        assertTrue(s.market.isEmpty())
        assertTrue(s.mine.isEmpty())
        assertNull(s.errorMessage)
    }

    @Test
    fun happy_marketAndMine_populated() = runTest(mainRule.dispatcher) {
        val repo = FakeStrategiesRepo(
            marketResult = ApiResult.Success(listOf(sampleStrategy("s1", "Alpha"), sampleStrategy("s2", "Beta"))),
            mineResult = ApiResult.Success(listOf(sampleStrategy("s3", "Mine"))),
        )
        val vm = StrategyMarketViewModel(repo)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(StrategyMarketUiState.Phase.Content, s.phase)
        assertEquals(2, s.market.size)
        assertEquals(1, s.mine.size)
        assertEquals(2, s.rows.size)
        vm.selectTab(StrategyListTab.MINE)
        assertEquals(1, vm.uiState.value.rows.size)
    }

    @Test
    fun transportFailure_toRetryableError() = runTest(mainRule.dispatcher) {
        val repo = FakeStrategiesRepo(mineResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false))
        val vm = StrategyMarketViewModel(repo)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(StrategyMarketUiState.Phase.Error, s.phase)
        assertTrue(s.errorMessage != null)
    }
}
