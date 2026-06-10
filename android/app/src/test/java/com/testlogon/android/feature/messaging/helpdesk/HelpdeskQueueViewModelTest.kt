package com.testlogon.android.feature.messaging.helpdesk

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.helpdesk.ClaimState
import com.testlogon.android.data.messaging.helpdesk.HelpdeskQueueItem
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRoutingState
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class HelpdeskQueueViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeHelpdeskRepository()

    private fun item(id: String) = HelpdeskQueueItem(
        conversationId = id, title = "T", preview = "p",
        routingState = HelpdeskRoutingState.AWAITING_AGENT, claimState = ClaimState.UNASSIGNED,
        activeAgentUserId = null, unreadCount = 0, lastMessageAtEpochSeconds = 1,
    )

    @Test
    fun load_success_rendersReady() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1"), item("c2")))
        val vm = HelpdeskQueueViewModel(repo)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertTrue(s is HelpdeskQueueUiState.Ready)
        assertEquals(2, (s as HelpdeskQueueUiState.Ready).items.size)
    }

    @Test
    fun load_emptyArray_rendersReadyEmpty() = runTest {
        repo.queueResult = ApiResult.Success(emptyList())
        val vm = HelpdeskQueueViewModel(repo)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertTrue(s is HelpdeskQueueUiState.Ready)
        assertTrue((s as HelpdeskQueueUiState.Ready).items.isEmpty())
    }

    @Test
    fun load_403_rendersNotAuthorized() = runTest {
        repo.queueResult = ApiResult.Failure(ApiError(status = 403, message = "forbidden"))
        val vm = HelpdeskQueueViewModel(repo)
        advanceUntilIdle()
        assertEquals(HelpdeskQueueUiState.NotAuthorized, vm.uiState.value)
    }

    @Test
    fun load_otherError_rendersError() = runTest {
        repo.queueResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val vm = HelpdeskQueueViewModel(repo)
        advanceUntilIdle()
        assertTrue(vm.uiState.value is HelpdeskQueueUiState.Error)
    }

    @Test
    fun refresh_reissuesFetch() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1")))
        val vm = HelpdeskQueueViewModel(repo)
        advanceUntilIdle()
        assertEquals(1, repo.loadQueueCalls)
        vm.refresh()
        advanceUntilIdle()
        assertEquals(2, repo.loadQueueCalls)
    }
}
