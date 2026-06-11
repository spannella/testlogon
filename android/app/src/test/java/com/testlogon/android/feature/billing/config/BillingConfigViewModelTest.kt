package com.testlogon.android.feature.billing.config

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.billing.AdminBillingConfig
import com.testlogon.android.data.billing.AdminBillingConfigRepository
import com.testlogon.android.data.billing.PayoutSchedule
import com.testlogon.android.feature.billing.error.BillingErrorMapper
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
 * AND-248/250 — [BillingConfigViewModel] reducer transitions: Success -> Content; 403 -> Error(no retry);
 * 404 -> Empty; 5xx -> Error(retryable); a failed refresh over existing Content keeps the last-good config
 * (isStale); retry re-invokes the repository.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class BillingConfigViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val mapper = BillingErrorMapper()

    private class FakeRepo(var result: ApiResult<AdminBillingConfig>) : AdminBillingConfigRepository {
        var calls = 0
            private set
        override suspend fun getBillingConfig(): ApiResult<AdminBillingConfig> {
            calls++
            return result
        }
    }

    private fun sampleBillingConfig() = AdminBillingConfig(
        feeTipsBps = 250, feeUnlocksBps = 250, feeSubscriptionsBps = 1500, feeCatalogBps = 1000,
        feeAdRevenueBps = 3000, minPayoutCents = 5000, payoutFeeCents = 25,
        payoutSchedule = PayoutSchedule.Weekly, autoPayoutEnabled = true,
        minDepositCents = 500, maxDepositCents = 1_000_000, depositFeeBps = 290,
        defaultCurrency = "USD", supportedCurrencies = listOf("USD", "EUR"),
        taxEnabled = false, defaultTaxRateBps = 0,
        updatedAtEpochSeconds = 1_717_200_000L, updatedBy = "root|abc123",
    )

    @Test
    fun success_emitsContent() = runTest {
        val repo = FakeRepo(ApiResult.Success(sampleBillingConfig()))
        val vm = BillingConfigViewModel(repo, mapper)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        val content = vm.state.value as BillingConfigUiState.Content
        assertEquals(PayoutSchedule.Weekly, content.config.payoutSchedule)
        assertFalse(content.isStale)
        job.cancel()
    }

    @Test
    fun forbidden_403_emitsErrorNonRetryable() = runTest {
        val repo = FakeRepo(ApiResult.Failure(ApiError(status = 403, message = "Permission denied")))
        val vm = BillingConfigViewModel(repo, mapper)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        val error = vm.state.value as BillingConfigUiState.Error
        assertFalse(error.canRetry)
        job.cancel()
    }

    @Test
    fun notFound_404_emitsEmpty() = runTest {
        val repo = FakeRepo(ApiResult.Failure(ApiError(status = 404, message = "no config")))
        val vm = BillingConfigViewModel(repo, mapper)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        assertTrue(vm.state.value is BillingConfigUiState.Empty)
        job.cancel()
    }

    @Test
    fun serverError_emitsRetryableError() = runTest {
        val repo = FakeRepo(ApiResult.Failure(ApiError(status = 500, message = "boom")))
        val vm = BillingConfigViewModel(repo, mapper)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        val error = vm.state.value as BillingConfigUiState.Error
        assertTrue(error.canRetry)
        job.cancel()
    }

    @Test
    fun refreshFailure_overContent_keepsLastGood_stale() = runTest {
        val repo = FakeRepo(ApiResult.Success(sampleBillingConfig()))
        val vm = BillingConfigViewModel(repo, mapper)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        assertTrue(vm.state.value is BillingConfigUiState.Content)

        repo.result = ApiResult.NetworkError(java.io.IOException("offline"))
        vm.refresh()
        advanceUntilIdle()

        val content = vm.state.value as BillingConfigUiState.Content
        assertTrue(content.isStale)
        assertFalse(content.isRefreshing)
        // Last-good config still present.
        assertEquals(PayoutSchedule.Weekly, content.config.payoutSchedule)
        job.cancel()
    }

    @Test
    fun retry_reInvokesRepository() = runTest {
        val repo = FakeRepo(ApiResult.Failure(ApiError(status = 500, message = "boom")))
        val vm = BillingConfigViewModel(repo, mapper)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        val callsAfterInit = repo.calls

        repo.result = ApiResult.Success(sampleBillingConfig())
        vm.retry()
        advanceUntilIdle()

        assertTrue(repo.calls > callsAfterInit)
        assertTrue(vm.state.value is BillingConfigUiState.Content)
        job.cancel()
    }
}
