package com.testlogon.android.feature.webhooks

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.webhooks.testing.FakeWebhooksRepo
import com.testlogon.android.feature.webhooks.testing.FakeWebhooksRepo.Companion.webhook
import com.testlogon.android.feature.webhooks.ui.WebhooksEffect
import com.testlogon.android.feature.webhooks.ui.WebhooksListUiState
import com.testlogon.android.feature.webhooks.ui.WebhooksListViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-398 - tests for [WebhooksListViewModel]: a load resolves to Content (AC-1), an empty list -> Empty (AC-2),
 * a failure -> Error, a refresh failure keeps the last-good list with isStale=true (AC-6), concurrent refresh
 * collapses to one read, and a TERMINAL 401 emits the one-shot NavigateToLogin (AC-5).
 *
 * runCurrent (NOT advanceUntilIdle) drains the init load(); the effect channel is collected on
 * backgroundScope.launch so the test never blocks on it.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class WebhooksListViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeWebhooksRepo()

    private fun vm() = WebhooksListViewModel(repo)

    @Test
    fun load_success_isContent() = runTest {
        repo.listResult = ApiResult.Success(listOf(webhook("wh_1"), webhook("wh_2")))
        val vm = vm()
        runCurrent()

        val state = vm.uiState.value
        assertTrue(state is WebhooksListUiState.Content)
        assertEquals(listOf("wh_1", "wh_2"), (state as WebhooksListUiState.Content).items.map { it.id })
        assertFalse(state.isStale)
    }

    @Test
    fun load_emptyList_isEmpty() = runTest {
        repo.listResult = ApiResult.Success(emptyList())
        val vm = vm()
        runCurrent()
        assertEquals(WebhooksListUiState.Empty, vm.uiState.value)
    }

    @Test
    fun load_failure_isError() = runTest {
        repo.listResult = FakeWebhooksRepo.webhooksFailure(500)
        val vm = vm()
        runCurrent()
        val state = vm.uiState.value
        assertTrue(state is WebhooksListUiState.Error)
        assertTrue((state as WebhooksListUiState.Error).retryable)
    }

    @Test
    fun refreshFailure_keepsLastGood_andFlagsStale() = runTest {
        repo.listResult = ApiResult.Success(listOf(webhook("wh_1")))
        val vm = vm()
        runCurrent()
        assertTrue(vm.uiState.value is WebhooksListUiState.Content)

        repo.listResult = FakeWebhooksRepo.webhooksFailure(503)
        vm.refresh()
        runCurrent()

        val state = vm.uiState.value
        assertTrue(state is WebhooksListUiState.Content)
        state as WebhooksListUiState.Content
        assertEquals(listOf("wh_1"), state.items.map { it.id })
        assertTrue(state.isStale)
        assertFalse(state.isRefreshing)
    }

    @Test
    fun concurrentRefresh_collapsesToOneRepositoryCall() = runTest {
        repo.listResult = ApiResult.Success(listOf(webhook("wh_1")))
        val vm = vm()
        runCurrent() // drains the init load() (call #1)
        assertEquals(1, repo.listCallCount)

        vm.refresh() // call #2 launches
        vm.refresh() // collapses onto the in-flight #2 (no new call)
        runCurrent()

        assertEquals(2, repo.listCallCount)
    }

    @Test
    fun load_401_emitsNavigateToLogin() = runTest {
        repo.listResult = FakeWebhooksRepo.webhooksFailure(401)
        val received = mutableListOf<WebhooksEffect>()
        val vm = vm()
        backgroundScope.launch { vm.effects.collect { received += it } }
        runCurrent()

        assertEquals(listOf(WebhooksEffect.NavigateToLogin), received)
    }
}
