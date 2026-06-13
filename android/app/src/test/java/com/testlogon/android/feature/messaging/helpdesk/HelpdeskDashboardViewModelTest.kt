package com.testlogon.android.feature.messaging.helpdesk

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.helpdesk.HelpdeskMetrics
import com.testlogon.android.data.messaging.helpdesk.CachedMetrics
import com.testlogon.android.data.messaging.helpdesk.ClaimState
import com.testlogon.android.data.messaging.helpdesk.HelpdeskDashboardData
import com.testlogon.android.data.messaging.helpdesk.HelpdeskQueueItem
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRoutingState
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.IOException

/** AND-377 — unit tests for the helpdesk dashboard ViewModel (TC-01,02,06,07,14). */
class HelpdeskDashboardViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeHelpdeskMetricsRepository()

    private fun metrics(
        open: Int = 5,
        unassigned: Int = 2,
        assignedToMe: Int = 1,
        sla: Int = 1,
    ) = HelpdeskMetrics(
        openCount = open,
        unassignedCount = unassigned,
        assignedToMeCount = assignedToMe,
        slaAtRiskCount = sla,
        generatedAtEpochSeconds = 1000L,
    )

    private fun previewItem(id: String) = HelpdeskQueueItem(
        conversationId = id, title = "T", preview = "p",
        routingState = HelpdeskRoutingState.AWAITING_AGENT, claimState = ClaimState.UNASSIGNED,
        activeAgentUserId = null, unreadCount = 0, lastMessageAtEpochSeconds = 1,
    )

    @Test
    fun agentHappyPath_rendersContentWithPreview() = runTest {
        repo.refreshResult = ApiResult.Success(
            HelpdeskDashboardData(metrics = metrics(), queuePreview = listOf(previewItem("c1"))),
        )
        val vm = HelpdeskDashboardViewModel(repo)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertTrue(s is HelpdeskDashboardUiState.Content)
        assertFalse((s as HelpdeskDashboardUiState.Content).isStale)
        assertEquals(5, s.metrics.openCount)
        assertEquals(1, vm.queuePreview.value.size)
    }

    @Test
    fun nonAgent403_rendersAccessDenied_noFurtherFetch() = runTest {
        repo.refreshResult = ApiResult.Failure(ApiError(status = 403, message = "forbidden"))
        val vm = HelpdeskDashboardViewModel(repo)
        advanceUntilIdle()
        assertEquals(HelpdeskDashboardUiState.AccessDenied, vm.uiState.value)
        assertEquals(1, repo.refreshCalls)
    }

    @Test
    fun emptyPayload_rendersEmpty() = runTest {
        repo.refreshResult = ApiResult.Success(
            HelpdeskDashboardData(
                metrics = metrics(open = 0, unassigned = 0, assignedToMe = 0, sla = 0),
                queuePreview = emptyList(),
            ),
        )
        val vm = HelpdeskDashboardViewModel(repo)
        advanceUntilIdle()
        assertEquals(HelpdeskDashboardUiState.Empty, vm.uiState.value)
    }

    @Test
    fun networkFailWithCache_rendersStaleContent() = runTest {
        repo.cache.value = CachedMetrics(
            data = HelpdeskDashboardData(metrics = metrics(open = 9), queuePreview = listOf(previewItem("c1"))),
            cachedAtEpochSeconds = 500L,
        )
        repo.refreshResult = ApiResult.NetworkError(IOException("offline"))
        val vm = HelpdeskDashboardViewModel(repo)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertTrue(s is HelpdeskDashboardUiState.Content)
        assertTrue((s as HelpdeskDashboardUiState.Content).isStale)
        assertEquals(9, s.metrics.openCount)
        assertEquals(500L, s.cachedAtEpochSeconds)
    }

    @Test
    fun networkFailNoCache_rendersRetryableError_thenRetryRecovers() = runTest {
        repo.refreshResult = ApiResult.NetworkError(IOException("offline"))
        val vm = HelpdeskDashboardViewModel(repo)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertTrue(s is HelpdeskDashboardUiState.Error)
        assertTrue((s as HelpdeskDashboardUiState.Error).retryable)

        repo.refreshResult = ApiResult.Success(
            HelpdeskDashboardData(metrics = metrics(), queuePreview = emptyList()),
        )
        vm.retry()
        advanceUntilIdle()
        assertTrue(vm.uiState.value is HelpdeskDashboardUiState.Content)
    }

    @Test
    fun refresh_togglesIsRefreshing_andReissuesFetch() = runTest {
        repo.refreshResult = ApiResult.Success(
            HelpdeskDashboardData(metrics = metrics(), queuePreview = emptyList()),
        )
        val vm = HelpdeskDashboardViewModel(repo)
        advanceUntilIdle()
        assertEquals(1, repo.refreshCalls)
        assertFalse(vm.isRefreshing.value)

        vm.refresh()
        advanceUntilIdle()
        assertEquals(2, repo.refreshCalls)
        assertFalse(vm.isRefreshing.value)
    }
}
