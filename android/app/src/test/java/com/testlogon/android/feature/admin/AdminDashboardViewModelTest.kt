package com.testlogon.android.feature.admin

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.admin.AdminAlert
import com.testlogon.android.core.model.admin.AdminDashboard
import com.testlogon.android.core.model.admin.AdminMetric
import com.testlogon.android.core.model.admin.AlertSeverity
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.admin.AdminRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-403 - [AdminDashboardViewModel] state transitions (TC-01/03/04/05/06/07/08/09):
 * admin Loading->Content; non-admin -> Forbidden with ZERO repo loadDashboard calls; backend 403 -> Forbidden;
 * empty dashboard -> Empty; present metrics + empty alerts -> Content; 5xx/network first load -> Error;
 * persistent 401 -> Error(AUTH); refresh failure over Content retains stale data + transient error.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class AdminDashboardViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private class FakeRepo(
        var result: ApiResult<AdminDashboard>,
        var admin: Boolean = true,
    ) : AdminRepository {
        var loadCalls = 0
            private set

        override suspend fun loadDashboard(): ApiResult<AdminDashboard> {
            loadCalls++
            return result
        }

        override fun isAdmin(): Boolean = admin
    }

    private fun dashboard(
        alerts: List<AdminAlert> = listOf(
            AdminAlert("a1", AlertSeverity.CRITICAL, "Boom", source = "jobs", createdAtEpochSeconds = 10),
        ),
        metrics: List<AdminMetric> = listOf(AdminMetric("m1", "Jobs", "3")),
    ) = AdminDashboard(alerts = alerts, metrics = metrics)

    private fun vmWith(repo: FakeRepo): AdminDashboardViewModel {
        return AdminDashboardViewModel(repo)
    }

    @Test
    fun admin_success_emitsContent() = runTest {
        val repo = FakeRepo(ApiResult.Success(dashboard()))
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        assertTrue(vm.state.value is AdminDashboardUiState.Content)
        job.cancel()
    }

    @Test
    fun nonAdmin_emitsForbidden_withNoLoadCall() = runTest {
        val repo = FakeRepo(ApiResult.Success(dashboard()), admin = false)
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        assertTrue(vm.state.value is AdminDashboardUiState.Forbidden)
        assertEquals(0, repo.loadCalls)
        job.cancel()
    }

    @Test
    fun backend403_mapsForbidden() = runTest {
        val repo = FakeRepo(ApiResult.Failure(ApiError(status = 403, message = "Admin access required")))
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        assertTrue(vm.state.value is AdminDashboardUiState.Forbidden)
        job.cancel()
    }

    @Test
    fun emptyDashboard_emitsEmpty() = runTest {
        val repo = FakeRepo(ApiResult.Success(AdminDashboard(alerts = emptyList(), metrics = emptyList())))
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        assertTrue(vm.state.value is AdminDashboardUiState.Empty)
        job.cancel()
    }

    @Test
    fun emptyAlerts_presentMetrics_emitsContentNotEmpty() = runTest {
        val repo = FakeRepo(ApiResult.Success(dashboard(alerts = emptyList())))
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        val content = vm.state.value as AdminDashboardUiState.Content
        assertTrue(content.dashboard.alerts.isEmpty())
        assertTrue(content.dashboard.metrics.isNotEmpty())
        job.cancel()
    }

    @Test
    fun serverError_firstLoad_emitsError() = runTest {
        val repo = FakeRepo(ApiResult.Failure(ApiError(status = 500, message = "boom")))
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        val error = vm.state.value as AdminDashboardUiState.Error
        assertEquals(AdminErrorType.SERVER, error.error.type)
        job.cancel()
    }

    @Test
    fun networkError_firstLoad_emitsError() = runTest {
        val repo = FakeRepo(ApiResult.NetworkError(java.io.IOException("offline")))
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        val error = vm.state.value as AdminDashboardUiState.Error
        assertEquals(AdminErrorType.NETWORK, error.error.type)
        job.cancel()
    }

    @Test
    fun persistent401_emitsAuthError() = runTest {
        val repo = FakeRepo(ApiResult.Failure(ApiError(status = 401, message = "expired")))
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        val error = vm.state.value as AdminDashboardUiState.Error
        assertEquals(AdminErrorType.AUTH, error.error.type)
        job.cancel()
    }

    @Test
    fun refreshFailure_overContent_retainsStaleData() = runTest {
        val repo = FakeRepo(ApiResult.Success(dashboard()))
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        assertTrue(vm.state.value is AdminDashboardUiState.Content)

        repo.result = ApiResult.NetworkError(java.io.IOException("offline"))
        vm.refresh()
        advanceUntilIdle()

        val content = vm.state.value as AdminDashboardUiState.Content
        assertTrue(content.isStale)
        assertFalse(content.isRefreshing)
        assertEquals(AdminErrorType.NETWORK, content.error?.type)
        // Last-good data still present.
        assertTrue(content.dashboard.alerts.isNotEmpty())
        job.cancel()
    }

    @Test
    fun retry_reInvokesRepository() = runTest {
        val repo = FakeRepo(ApiResult.Failure(ApiError(status = 500, message = "boom")))
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        val callsAfterInit = repo.loadCalls

        repo.result = ApiResult.Success(dashboard())
        vm.retry()
        advanceUntilIdle()

        assertTrue(repo.loadCalls > callsAfterInit)
        assertTrue(vm.state.value is AdminDashboardUiState.Content)
        job.cancel()
    }

    @Test
    fun dismissTransientError_clearsErrorOnContent() = runTest {
        val repo = FakeRepo(ApiResult.Success(dashboard()))
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()

        repo.result = ApiResult.NetworkError(java.io.IOException("offline"))
        vm.refresh()
        advanceUntilIdle()
        assertEquals(AdminErrorType.NETWORK, (vm.state.value as AdminDashboardUiState.Content).error?.type)

        vm.dismissTransientError()
        assertEquals(null, (vm.state.value as AdminDashboardUiState.Content).error)
        job.cancel()
    }
}
