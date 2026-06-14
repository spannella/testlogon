package com.testlogon.android.feature.webhooks

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.webhooks.testing.FakeWebhooksRepo
import com.testlogon.android.feature.webhooks.testing.FakeWebhooksRepo.Companion.webhook
import com.testlogon.android.feature.webhooks.ui.WebhookDetailUiState
import com.testlogon.android.feature.webhooks.ui.WebhookDetailViewModel
import com.testlogon.android.feature.webhooks.ui.WebhooksEffect
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-398 - tests for [WebhookDetailViewModel] (AC-3): a successful get -> Content; a 404 -> NotFound (handled
 * defensively even though undeclared in the OpenAPI); a 401 -> NavigateToLogin; the {webhookId} nav arg is read
 * from SavedStateHandle and passed to the repository.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class WebhookDetailViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeWebhooksRepo()

    private fun vm(id: String = "wh_1") = WebhookDetailViewModel(
        repo = repo,
        savedState = SavedStateHandle(mapOf(WebhookDetailViewModel.ARG_WEBHOOK_ID to id)),
    )

    @Test
    fun load_success_isContent_andReadsNavArg() = runTest {
        repo.getResult = ApiResult.Success(webhook("wh_1", url = "https://a.test/h"))
        val vm = vm("wh_1")
        runCurrent()

        assertEquals("wh_1", vm.webhookId)
        val state = vm.uiState.value
        assertTrue(state is WebhookDetailUiState.Content)
        assertEquals("https://a.test/h", (state as WebhookDetailUiState.Content).webhook.url)
        assertTrue(repo.getCallCount >= 1)
    }

    @Test
    fun load_404_isNotFound() = runTest {
        repo.getResult = FakeWebhooksRepo.webhooksFailure(404)
        val vm = vm()
        runCurrent()
        assertEquals(WebhookDetailUiState.NotFound, vm.uiState.value)
    }

    @Test
    fun load_500_isError() = runTest {
        repo.getResult = FakeWebhooksRepo.webhooksFailure(500)
        val vm = vm()
        runCurrent()
        assertTrue(vm.uiState.value is WebhookDetailUiState.Error)
    }

    @Test
    fun load_401_emitsNavigateToLogin() = runTest {
        repo.getResult = FakeWebhooksRepo.webhooksFailure(401)
        val received = mutableListOf<WebhooksEffect>()
        val vm = vm()
        backgroundScope.launch { vm.effects.collect { received += it } }
        runCurrent()
        assertEquals(listOf(WebhooksEffect.NavigateToLogin), received)
    }
}
