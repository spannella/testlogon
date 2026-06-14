package com.testlogon.android.feature.analytics.dashboards

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.analytics.AnalyticsDashboard
import com.testlogon.android.data.analytics.AnalyticsDashboardRange
import com.testlogon.android.data.analytics.AnalyticsDashboardRepository
import com.testlogon.android.data.analytics.AnalyticsOverview
import com.testlogon.android.data.analytics.AnalyticsRangePrefs
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-399 — JVM tests for [AnalyticsDashboardViewModel]: default range (LAST_30), deep-link + persisted
 * range resolution, range-change persistence + re-query, empty/error/offline reduction, refresh toggle,
 * and the stale-cache fallback on a failed refresh.
 */
class AnalyticsDashboardViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun dashboard(views: Long = 184320L) = AnalyticsDashboard.EMPTY.copy(
        overview = AnalyticsOverview(
            periodViews = views,
            periodRevenueCents = 942180L,
            periodNewSubscribers = 1372L,
            totalSubscribers = 51240L,
            currency = "USD",
        ),
    )

    private class FakeRepo : AnalyticsDashboardRepository {
        var result: ApiResult<AnalyticsDashboard> = ApiResult.Success(AnalyticsDashboard.EMPTY)
        var refreshResult: ApiResult<AnalyticsDashboard>? = null
        val loadedRanges = mutableListOf<AnalyticsDashboardRange>()
        val refreshedRanges = mutableListOf<AnalyticsDashboardRange>()
        var cachedValue: AnalyticsDashboard? = null

        override suspend fun loadDashboard(range: AnalyticsDashboardRange): ApiResult<AnalyticsDashboard> {
            loadedRanges += range
            return result
        }

        override suspend fun refresh(range: AnalyticsDashboardRange): ApiResult<AnalyticsDashboard> {
            refreshedRanges += range
            return refreshResult ?: result
        }

        override fun cached(range: AnalyticsDashboardRange): AnalyticsDashboard? = cachedValue
        override fun clear() {}
    }

    private class FakePrefs(private var range: AnalyticsDashboardRange = AnalyticsDashboardRange.LAST_30) :
        AnalyticsRangePrefs {
        val saved = mutableListOf<AnalyticsDashboardRange>()
        override suspend fun selectedRange(): AnalyticsDashboardRange = range
        override suspend fun setSelectedRange(range: AnalyticsDashboardRange) {
            this.range = range
            saved += range
        }
    }

    private fun vm(
        repo: FakeRepo,
        prefs: FakePrefs = FakePrefs(),
        deepLink: String? = null,
    ): AnalyticsDashboardViewModel {
        val handle = SavedStateHandle().apply {
            if (deepLink != null) set(AnalyticsDashboardViewModel.ARG_RANGE, deepLink)
        }
        return AnalyticsDashboardViewModel(repo, prefs, handle)
    }

    @Test
    fun init_loadsDefaultRange_thenContent() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(dashboard()) }
        val sut = vm(repo)
        advanceUntilIdle()
        assertEquals(DashboardRangeOption.LAST_30, sut.uiState.value.range)
        assertEquals(AnalyticsDashboardUiState.Phase.Content, sut.uiState.value.phase)
        assertTrue(repo.loadedRanges.contains(AnalyticsDashboardRange.LAST_30))
    }

    @Test
    fun init_usesPersistedRange() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(dashboard()) }
        val sut = vm(repo, prefs = FakePrefs(AnalyticsDashboardRange.LAST_90))
        advanceUntilIdle()
        assertEquals(DashboardRangeOption.LAST_90, sut.uiState.value.range)
        assertTrue(repo.loadedRanges.contains(AnalyticsDashboardRange.LAST_90))
    }

    @Test
    fun init_deepLinkRange_overridesPersisted() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(dashboard()) }
        val sut = vm(repo, prefs = FakePrefs(AnalyticsDashboardRange.LAST_90), deepLink = "7")
        advanceUntilIdle()
        assertEquals(DashboardRangeOption.LAST_7, sut.uiState.value.range)
        assertTrue(repo.loadedRanges.contains(AnalyticsDashboardRange.LAST_7))
    }

    @Test
    fun onRangeSelected_persists_andReQueries() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(dashboard()) }
        val prefs = FakePrefs()
        val sut = vm(repo, prefs)
        advanceUntilIdle()
        sut.onRangeSelected(DashboardRangeOption.LAST_90)
        advanceUntilIdle()
        assertEquals(DashboardRangeOption.LAST_90, sut.uiState.value.range)
        assertTrue(repo.loadedRanges.contains(AnalyticsDashboardRange.LAST_90))
        assertTrue(prefs.saved.contains(AnalyticsDashboardRange.LAST_90))
    }

    @Test
    fun emptyDashboard_yieldsEmptyPhase() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(AnalyticsDashboard.EMPTY) }
        val sut = vm(repo)
        advanceUntilIdle()
        assertEquals(AnalyticsDashboardUiState.Phase.Empty, sut.uiState.value.phase)
        assertNull(sut.uiState.value.dashboard)
    }

    @Test
    fun failure_yieldsError_withMessage() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Failure(ApiError(status = 422, message = "bad date")) }
        val sut = vm(repo)
        advanceUntilIdle()
        assertEquals(AnalyticsDashboardUiState.Phase.Error, sut.uiState.value.phase)
        assertEquals("bad date", sut.uiState.value.errorMessage)
    }

    @Test
    fun networkError_yieldsOffline() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.NetworkError(java.io.IOException("net")) }
        val sut = vm(repo)
        advanceUntilIdle()
        assertEquals(AnalyticsDashboardUiState.Phase.Offline, sut.uiState.value.phase)
    }

    @Test
    fun failureWithCache_servesStaleContent() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply {
            result = ApiResult.NetworkError(java.io.IOException("net"))
            cachedValue = dashboard()
        }
        val sut = vm(repo)
        advanceUntilIdle()
        assertEquals(AnalyticsDashboardUiState.Phase.Content, sut.uiState.value.phase)
        assertTrue(sut.uiState.value.isStale)
        assertEquals(184320L, sut.uiState.value.dashboard!!.overview!!.periodViews)
    }

    @Test
    fun onRefresh_togglesRefreshing_andHitsRefresh() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(dashboard()) }
        val sut = vm(repo)
        advanceUntilIdle()
        sut.onRefresh()
        advanceUntilIdle()
        assertFalse(sut.uiState.value.isRefreshing)
        assertTrue(repo.refreshedRanges.contains(AnalyticsDashboardRange.LAST_30))
    }
}
