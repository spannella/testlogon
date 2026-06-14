package com.testlogon.android.feature.analytics.engagement

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.analytics.Engagement
import com.testlogon.android.data.analytics.EngagementRateDto
import com.testlogon.android.data.analytics.EngagementRepository
import com.testlogon.android.data.analytics.EngagementTrendPoint
import com.testlogon.android.data.analytics.toMetrics
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-256 / AND-257 — JVM tests for [EngagementViewModel]: initial load, period selection + reset,
 * empty/error/offline reduction, chart toggle, and last-write-wins on rapid period switches.
 */
class EngagementViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun engagement(rate: Double = 9.83, followers: Int = 18450, total: Int = 1626) = Engagement(
        metrics = EngagementRateDto(
            engagementRate = rate, followerCount = followers, totalInteractions = total,
        ).toMetrics(),
        trend = listOf(
            EngagementTrendPoint("2026-05-01", 20574L, rate, (rate * 100).toInt(), total, 3),
        ),
    )

    private class FakeRepo : EngagementRepository {
        var result: ApiResult<Engagement>? = null
        val loadedPeriods = mutableListOf<Int>()
        // Optional gate to delay a specific period's result (for last-write-wins).
        var gate: CompletableDeferred<ApiResult<Engagement>>? = null
        var gatePeriod: Int? = null

        override suspend fun load(periodDays: Int): ApiResult<Engagement> {
            loadedPeriods += periodDays
            if (periodDays == gatePeriod) return gate!!.await()
            return result ?: ApiResult.Failure(ApiError(status = 500, message = "x"))
        }
    }

    private fun vm(repo: FakeRepo, deepLink: String? = null): EngagementViewModel {
        val handle = SavedStateHandle().apply { if (deepLink != null) set(EngagementViewModel.ARG_PERIOD, deepLink) }
        return EngagementViewModel(repo, handle)
    }

    @Test
    fun init_loadsDefault_thenContent() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(engagement()) }
        val sut = vm(repo)
        advanceUntilIdle()
        assertEquals(EngagementPeriod.D30, sut.uiState.value.period)
        assertEquals(EngagementUiState.Phase.Content, sut.uiState.value.phase)
        assertTrue(repo.loadedPeriods.contains(30))
    }

    @Test
    fun init_deepLinkPeriod_isUsed() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(engagement()) }
        val sut = vm(repo, deepLink = "7")
        advanceUntilIdle()
        assertEquals(EngagementPeriod.D7, sut.uiState.value.period)
        assertTrue(repo.loadedPeriods.contains(7))
    }

    @Test
    fun emptyEngagement_yieldsEmptyPhase() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(engagement(followers = 0, total = 0)) }
        val sut = vm(repo)
        advanceUntilIdle()
        assertEquals(EngagementUiState.Phase.Empty, sut.uiState.value.phase)
        assertNull(sut.uiState.value.engagement)
    }

    @Test
    fun failure_yieldsError_withMessage() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Failure(ApiError(status = 500, message = "boom")) }
        val sut = vm(repo)
        advanceUntilIdle()
        assertEquals(EngagementUiState.Phase.Error, sut.uiState.value.phase)
        assertEquals("boom", sut.uiState.value.errorMessage)
    }

    @Test
    fun networkError_yieldsOffline() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.NetworkError(java.io.IOException("net")) }
        val sut = vm(repo)
        advanceUntilIdle()
        assertEquals(EngagementUiState.Phase.Offline, sut.uiState.value.phase)
    }

    @Test
    fun onPeriodSelected_reloads_andResetsSelection() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(engagement()) }
        val sut = vm(repo)
        advanceUntilIdle()
        sut.onPointSelected(2)
        sut.onPeriodSelected(EngagementPeriod.D90)
        advanceUntilIdle()
        assertEquals(EngagementPeriod.D90, sut.uiState.value.period)
        assertNull(sut.uiState.value.selectedPoint)
        assertTrue(repo.loadedPeriods.contains(90))
    }

    @Test
    fun onPeriodSelected_sameHealthyPeriod_isNoOp() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(engagement()) }
        val sut = vm(repo)
        advanceUntilIdle()
        val before = repo.loadedPeriods.size
        sut.onPeriodSelected(EngagementPeriod.D30)
        advanceUntilIdle()
        assertEquals(before, repo.loadedPeriods.size)
    }

    @Test
    fun onChartTypeToggled_flipsAndResetsSelection() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(engagement()) }
        val sut = vm(repo)
        advanceUntilIdle()
        sut.onPointSelected(1)
        sut.onChartTypeToggled()
        assertEquals(EngagementChartType.BAR, sut.uiState.value.chartType)
        assertNull(sut.uiState.value.selectedPoint)
    }

    @Test
    fun rapidPeriodSwitch_dropsStaleResult_lastWriteWins() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply {
            result = ApiResult.Success(engagement())
            gate = CompletableDeferred()
            gatePeriod = 7 // the D7 load blocks until released
        }
        val sut = vm(repo)
        advanceUntilIdle() // initial D30 content settles

        sut.onPeriodSelected(EngagementPeriod.D7) // blocks on the gate
        advanceUntilIdle()
        sut.onPeriodSelected(EngagementPeriod.D90) // supersedes; resolves immediately
        advanceUntilIdle()

        // Now release the stale D7 result — it must be discarded by the gen guard.
        repo.gate!!.complete(ApiResult.Success(engagement(rate = 1.0)))
        advanceUntilIdle()

        assertEquals(EngagementPeriod.D90, sut.uiState.value.period)
        assertEquals(EngagementUiState.Phase.Content, sut.uiState.value.phase)
        assertEquals(9.83, sut.uiState.value.engagement!!.metrics.engagementRate!!, 1e-9)
    }
}
