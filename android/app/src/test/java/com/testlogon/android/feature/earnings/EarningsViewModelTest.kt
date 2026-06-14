package com.testlogon.android.feature.earnings

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.earnings.EarningsBreakdown
import com.testlogon.android.data.earnings.EarningsDashboard
import com.testlogon.android.data.earnings.EarningsMoney
import com.testlogon.android.data.earnings.EarningsPrefs
import com.testlogon.android.data.earnings.EarningsQuickStats
import com.testlogon.android.data.earnings.EarningsRange
import com.testlogon.android.data.earnings.EarningsRepository
import com.testlogon.android.data.earnings.EarningsSummary
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class EarningsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun money(c: Long) = EarningsMoney(c, "USD")

    private fun sampleDashboard(
        range: EarningsRange = EarningsRange.D30,
        empty: Boolean = false,
    ) = EarningsDashboard(
        range = range,
        quickStats = EarningsQuickStats(money(1), money(2), money(3), money(4), money(5)),
        summary = EarningsSummary(
            total = money(if (empty) 0 else 1000),
            transactionCount = 0,
            breakdown = EarningsBreakdown(0, 0, 0, 0, 0, "USD"),
            series = emptyList(),
        ),
        currency = "USD",
        fetchedAtEpochMs = 0L,
    )

    private class FakeRepo : EarningsRepository {
        var result: ApiResult<EarningsDashboard>? = null
        var cacheValue: EarningsDashboard? = null
        val loadedRanges = mutableListOf<EarningsRange>()
        override suspend fun loadDashboard(range: EarningsRange, granularity: String): ApiResult<EarningsDashboard> {
            loadedRanges += range
            // Mirror the real backend: the dashboard returned for a range is stamped with that range.
            return when (val r = result) {
                is ApiResult.Success -> ApiResult.Success(r.data.copy(range = range))
                null -> ApiResult.Failure(ApiError(status = 500, message = "x"))
                else -> r
            }
        }
        override fun cached(range: EarningsRange): EarningsDashboard? = cacheValue
        override fun clear() {}
    }

    private class FakePrefs(var range: EarningsRange = EarningsRange.D30) : EarningsPrefs {
        var saved: EarningsRange? = null
        override suspend fun selectedRange(): EarningsRange = range
        override suspend fun setSelectedRange(range: EarningsRange) { saved = range }
    }

    private fun vm(repo: FakeRepo, prefs: FakePrefs, deepLink: String? = null): EarningsViewModel {
        val handle = SavedStateHandle().apply { if (deepLink != null) set(EarningsViewModel.ARG_RANGE, deepLink) }
        return EarningsViewModel(repo, prefs, handle)
    }

    @Test
    fun init_loadsPrefRange_thenContent() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(sampleDashboard()) }
        val prefs = FakePrefs(range = EarningsRange.D90)
        val sut = vm(repo, prefs)
        advanceUntilIdle()
        assertEquals(EarningsRange.D90, sut.uiState.value.range)
        assertEquals(EarningsUiState.Phase.Content, sut.uiState.value.phase)
        assertTrue(repo.loadedRanges.contains(EarningsRange.D90))
    }

    @Test
    fun init_deepLinkOverridesPref() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(sampleDashboard(range = EarningsRange.D7)) }
        val prefs = FakePrefs(range = EarningsRange.D90)
        val sut = vm(repo, prefs, deepLink = "7d")
        advanceUntilIdle()
        assertEquals(EarningsRange.D7, sut.uiState.value.range)
    }

    @Test
    fun emptyData_yieldsEmptyPhase() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(sampleDashboard(empty = true)) }
        val sut = vm(repo, FakePrefs())
        advanceUntilIdle()
        assertEquals(EarningsUiState.Phase.Empty, sut.uiState.value.phase)
    }

    @Test
    fun failureNoCache_yieldsError() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Failure(ApiError(status = 500, message = "boom")) }
        val sut = vm(repo, FakePrefs())
        advanceUntilIdle()
        assertEquals(EarningsUiState.Phase.Error, sut.uiState.value.phase)
        assertEquals("boom", sut.uiState.value.errorMessage)
    }

    @Test
    fun networkErrorNoCache_yieldsOffline() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.NetworkError(java.io.IOException("net")) }
        val sut = vm(repo, FakePrefs())
        advanceUntilIdle()
        assertEquals(EarningsUiState.Phase.Offline, sut.uiState.value.phase)
    }

    @Test
    fun failureWithCache_yieldsStaleContent() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply {
            result = ApiResult.NetworkError(java.io.IOException("net"))
            cacheValue = sampleDashboard()
        }
        val sut = vm(repo, FakePrefs())
        advanceUntilIdle()
        assertEquals(EarningsUiState.Phase.Content, sut.uiState.value.phase)
        assertTrue(sut.uiState.value.isStale)
        assertTrue(sut.uiState.value.dashboard?.isStale == true)
    }

    @Test
    fun onRangeSelected_reloadsAndPersists() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(sampleDashboard()) }
        val prefs = FakePrefs()
        val sut = vm(repo, prefs)
        advanceUntilIdle()
        repo.result = ApiResult.Success(sampleDashboard(range = EarningsRange.D7))
        sut.onRangeSelected(EarningsRange.D7)
        advanceUntilIdle()
        assertEquals(EarningsRange.D7, sut.uiState.value.range)
        assertEquals(EarningsRange.D7, prefs.saved)
        assertTrue(repo.loadedRanges.contains(EarningsRange.D7))
    }

    @Test
    fun success_exposesLastUpdated_andIsEmptyFlag() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply {
            result = ApiResult.Success(sampleDashboard().copy(fetchedAtEpochMs = 1_700_000_000_000L))
        }
        val sut = vm(repo, FakePrefs())
        advanceUntilIdle()
        // AND-256: lastUpdated (client fetch time) and the derived isEmpty flag are exposed.
        assertEquals(1_700_000_000_000L, sut.uiState.value.lastUpdated)
        assertEquals(false, sut.uiState.value.isEmpty)
    }

    @Test
    fun emptyData_isEmptyFlagTrue() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(sampleDashboard(empty = true)) }
        val sut = vm(repo, FakePrefs())
        advanceUntilIdle()
        assertTrue(sut.uiState.value.isEmpty)
    }

    @Test
    fun refresh_withContent_keepsContentVisible() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(sampleDashboard()) }
        val sut = vm(repo, FakePrefs())
        advanceUntilIdle()
        sut.onRefresh()
        // After settling, content is retained (refresh of the same range), refreshing cleared.
        advanceUntilIdle()
        assertEquals(EarningsUiState.Phase.Content, sut.uiState.value.phase)
        assertEquals(false, sut.uiState.value.isRefreshing)
        assertNull(sut.uiState.value.errorMessage)
    }

    @Test
    fun onChartTypeToggled_flipsAndResetsSelection() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(sampleDashboard()) }
        val sut = vm(repo, FakePrefs())
        advanceUntilIdle()
        sut.onPointSelected(2)
        assertEquals(2, sut.uiState.value.selectedPoint)
        sut.onChartTypeToggled()
        assertEquals(ChartType.BAR, sut.uiState.value.chartType)
        assertNull(sut.uiState.value.selectedPoint)
    }
}
