package com.testlogon.android.feature.dashboard

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.Dashboard
import com.testlogon.android.core.model.EarningsBreakdown
import com.testlogon.android.data.dashboard.DashboardRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class DashboardViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun sampleDashboard(empty: Boolean = false) = Dashboard(
        todayEarningsCents = if (empty) 0 else 100,
        earningsBreakdown = EarningsBreakdown(0, 0, 0, 0, 0),
        periodViews = 0,
        periodRevenueCents = 0,
        totalSubscribers = 0,
        topContent = emptyList(),
        activeBroadcasts = emptyList(),
        recentMilestones = emptyList(),
        currency = "USD",
        generatedAtMillis = null,
        warnings = emptyList(),
    )

    /** P2 — profile repo the dashboard VM gained (used only for the header display name/photo). */
    private class FakeProfileRepo : com.testlogon.android.data.profile.ProfileRepository {
        override suspend fun getOwnProfile(forceRefresh: Boolean) =
            ApiResult.Failure(ApiError(status = 0, message = "stub"))
        override fun cachedOwnProfile(): com.testlogon.android.core.model.profile.Profile? = null
        override suspend fun getPublicProfile(identifier: String) =
            com.testlogon.android.data.profile.ProfileResult.NotFound
        override suspend fun updateProfile(patch: com.testlogon.android.core.model.profile.ProfilePatch) =
            ApiResult.Failure(ApiError(status = 0, message = "stub"))
        override suspend fun uploadPhoto(
            kind: com.testlogon.android.data.profile.MediaKind,
            upload: com.testlogon.android.data.profile.ProfileMediaUploader.PreparedUpload,
        ) = ApiResult.Failure(ApiError(status = 0, message = "stub"))
    }

    private fun DashboardViewModel(repo: DashboardRepository) =
        com.testlogon.android.feature.dashboard.DashboardViewModel(repo, FakeProfileRepo())

    private class FakeRepo : DashboardRepository {
        var result: ApiResult<Dashboard> = ApiResult.Success(
            Dashboard(1, EarningsBreakdown(0, 0, 0, 0, 0), 0, 0, 0, emptyList(), emptyList(), emptyList(), "USD", null, emptyList()),
        )
        var cache: Dashboard? = null
        var calls = 0
        override suspend fun getDashboard(forceRefresh: Boolean): ApiResult<Dashboard> {
            calls++
            return result
        }
        override fun dashboard(): Flow<ApiResult<Dashboard>> = flowOf(result)
        override fun cachedDashboard(): Dashboard? = cache
    }

    @Test
    fun init_loadingThenContent() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(sampleDashboard()) }
        val vm = DashboardViewModel(repo)
        assertEquals(DashboardUiState.Phase.Loading, vm.uiState.value.phase)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(DashboardUiState.Phase.Content, s.phase)
        assertTrue(s.dashboard != null)
        assertFalse(s.isStale)
        assertNull(s.errorMessage)
    }

    @Test
    fun init_emptyPayload_toEmpty() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(sampleDashboard(empty = true)) }
        val vm = DashboardViewModel(repo)
        advanceUntilIdle()
        assertEquals(DashboardUiState.Phase.Empty, vm.uiState.value.phase)
        assertTrue(vm.uiState.value.canRetry)
    }

    @Test
    fun init_errorNoCache_toError() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Failure(ApiError(500, "boom")) }
        val vm = DashboardViewModel(repo)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(DashboardUiState.Phase.Error, s.phase)
        assertEquals("boom", s.errorMessage)
        assertNull(s.dashboard)
    }

    @Test
    fun init_networkError_withCache_toStaleContent_andEffect() = runTest(mainRule.dispatcher) {
        val cached = sampleDashboard()
        val repo = FakeRepo().apply {
            result = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
            cache = cached
        }
        val effects = mutableListOf<DashboardEffect>()
        val vm = DashboardViewModel(repo)
        val job = launch { vm.effects.toList(effects) }
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(DashboardUiState.Phase.Content, s.phase)
        assertTrue(s.isStale)
        assertTrue(s.isOffline)
        assertEquals(1, effects.size)
        job.cancel()
    }

    @Test
    fun refresh_overContent_clearsStaleOnSuccess() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(sampleDashboard()) }
        val vm = DashboardViewModel(repo)
        advanceUntilIdle()
        repo.result = ApiResult.Success(sampleDashboard())
        vm.onRefresh()
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(DashboardUiState.Phase.Content, s.phase)
        assertFalse(s.isStale)
        assertFalse(s.isRefreshing)
    }

    @Test
    fun refresh_failureWithCache_keepsContentSetsStale() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Success(sampleDashboard()) }
        val vm = DashboardViewModel(repo)
        advanceUntilIdle()
        repo.cache = sampleDashboard()
        repo.result = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
        vm.onRefresh()
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(DashboardUiState.Phase.Content, s.phase)
        assertTrue(s.isStale)
        assertTrue(s.dashboard != null)
    }

    @Test
    fun onRetry_fromError_reloadsToContent() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo().apply { result = ApiResult.Failure(ApiError(500, "boom")) }
        val vm = DashboardViewModel(repo)
        advanceUntilIdle()
        assertEquals(DashboardUiState.Phase.Error, vm.uiState.value.phase)
        repo.result = ApiResult.Success(sampleDashboard())
        vm.onRetry()
        advanceUntilIdle()
        assertEquals(DashboardUiState.Phase.Content, vm.uiState.value.phase)
        assertNull(vm.uiState.value.errorMessage)
    }

    @Test
    fun reducers_arePure() {
        val base = DashboardUiState()
        assertEquals(DashboardUiState.Phase.Loading, base.startLoad(fromUser = false).phase)
        assertEquals(DashboardUiState.Phase.Content, base.toContentOrEmpty(sampleDashboard()).phase)
        assertEquals(DashboardUiState.Phase.Empty, base.toContentOrEmpty(sampleDashboard(empty = true)).phase)
        assertEquals(DashboardUiState.Phase.Error, base.toError("x").phase)
        assertTrue(base.toStaleContent(sampleDashboard()).isStale)
    }
}
