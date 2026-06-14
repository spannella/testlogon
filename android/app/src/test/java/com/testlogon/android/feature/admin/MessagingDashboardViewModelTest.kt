package com.testlogon.android.feature.admin

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.admin.DashboardChannel
import com.testlogon.android.core.model.admin.DashboardMetricCard
import com.testlogon.android.core.model.admin.DeliveryActivity
import com.testlogon.android.core.model.admin.DeliveryStatus
import com.testlogon.android.core.model.admin.MessagingDashboard
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.admin.MessagingDashboardRepository
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
 * AND-404 - [MessagingDashboardViewModel] state transitions (TC-01..05): admin Loading->Content; all-zero+empty
 * -> Empty; failure-no-cache -> Error; offline-over-content -> stale Content; refresh toggles + re-fetches;
 * non-admin -> Forbidden with ZERO repo calls; backend 403 -> Forbidden; persistent 401 -> Error(AUTH); the
 * channel nav arg selects EMAIL vs SMS.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class MessagingDashboardViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private class FakeRepo(
        var result: ApiResult<MessagingDashboard>,
        var admin: Boolean = true,
    ) : MessagingDashboardRepository {
        var loadCalls = 0
            private set
        var lastChannel: DashboardChannel? = null
            private set

        override suspend fun dashboard(channel: DashboardChannel): ApiResult<MessagingDashboard> {
            loadCalls++
            lastChannel = channel
            return result
        }

        override fun isAdmin(): Boolean = admin
    }

    private fun emailDashboard(
        activity: List<DeliveryActivity> = listOf(
            DeliveryActivity("k1", "j***@e***.com", DeliveryStatus.DELIVERED, "Welcome", 1_749_132_131L),
        ),
        allZero: Boolean = false,
        activityFailed: Boolean = false,
    ) = MessagingDashboard(
        channel = DashboardChannel.EMAIL,
        metrics = listOf(DashboardMetricCard("msg_sent", "Sent", "12,840")),
        deliveryRatePct = 94.3,
        activity = activity,
        allZeroStats = allZero,
        activityFailed = activityFailed,
    )

    private fun vmWith(repo: FakeRepo, channel: String = "email"): MessagingDashboardViewModel =
        MessagingDashboardViewModel(repo, SavedStateHandle(mapOf(ARG_DASHBOARD_CHANNEL to channel)))

    @Test
    fun admin_success_emitsContent() = runTest {
        val repo = FakeRepo(ApiResult.Success(emailDashboard()))
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        val content = vm.state.value as MessagingDashboardUiState.Content
        assertTrue(content.dashboard.metrics.isNotEmpty())
        assertTrue(content.dashboard.activity.isNotEmpty())
        assertFalse(content.isRefreshing)
        assertEquals(DashboardChannel.EMAIL, repo.lastChannel)
        job.cancel()
    }

    @Test
    fun allZeroAndEmptyActivity_emitsEmpty() = runTest {
        val repo = FakeRepo(ApiResult.Success(emailDashboard(activity = emptyList(), allZero = true)))
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        assertTrue(vm.state.value is MessagingDashboardUiState.Empty)
        job.cancel()
    }

    @Test
    fun failureNoCache_emitsError() = runTest {
        val repo = FakeRepo(ApiResult.Failure(ApiError(status = 500, message = "boom")))
        val vm = vmWith(repo, channel = "sms")
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        val error = vm.state.value as MessagingDashboardUiState.Error
        assertEquals(AdminErrorType.SERVER, error.error.type)
        assertEquals(DashboardChannel.SMS, repo.lastChannel)
        job.cancel()
    }

    @Test
    fun offlineOverContent_retainsStaleData() = runTest {
        val repo = FakeRepo(ApiResult.Success(emailDashboard()))
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        assertTrue(vm.state.value is MessagingDashboardUiState.Content)

        repo.result = ApiResult.NetworkError(java.io.IOException("offline"))
        vm.refresh()
        advanceUntilIdle()

        val content = vm.state.value as MessagingDashboardUiState.Content
        assertTrue(content.isStale)
        assertFalse(content.isRefreshing)
        assertEquals(AdminErrorType.NETWORK, content.error?.type)
        assertTrue(content.dashboard.activity.isNotEmpty())
        job.cancel()
    }

    @Test
    fun refresh_reFetches() = runTest {
        val repo = FakeRepo(ApiResult.Success(emailDashboard()))
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        val before = repo.loadCalls

        vm.refresh()
        advanceUntilIdle()
        assertTrue(repo.loadCalls > before)
        assertTrue(vm.state.value is MessagingDashboardUiState.Content)
        job.cancel()
    }

    @Test
    fun nonAdmin_emitsForbidden_withNoLoadCall() = runTest {
        val repo = FakeRepo(ApiResult.Success(emailDashboard()), admin = false)
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        assertTrue(vm.state.value is MessagingDashboardUiState.Forbidden)
        assertEquals(0, repo.loadCalls)
        job.cancel()
    }

    @Test
    fun backend403_mapsForbidden() = runTest {
        val repo = FakeRepo(ApiResult.Failure(ApiError(status = 403, message = "Admin access required")))
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        assertTrue(vm.state.value is MessagingDashboardUiState.Forbidden)
        job.cancel()
    }

    @Test
    fun persistent401_emitsAuthError() = runTest {
        val repo = FakeRepo(ApiResult.Failure(ApiError(status = 401, message = "expired")))
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        val error = vm.state.value as MessagingDashboardUiState.Error
        assertEquals(AdminErrorType.AUTH, error.error.type)
        job.cancel()
    }

    @Test
    fun activityFailed_butStatsOk_emitsContentNotEmpty() = runTest {
        val repo = FakeRepo(
            ApiResult.Success(emailDashboard(activity = emptyList(), allZero = false, activityFailed = true)),
        )
        val vm = vmWith(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        val content = vm.state.value as MessagingDashboardUiState.Content
        assertTrue(content.dashboard.activityFailed)
        assertTrue(content.dashboard.activity.isEmpty())
        job.cancel()
    }
}
