package com.testlogon.android.feature.refunds

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-244 — list/submit/detail ViewModel transitions: list load + stale-on-failure-with-cache, submit
 * validation matrix + double-submit guard + success/failure events, detail content/error/404.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class RefundViewModelsTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val mapper = BillingErrorMapper()

    // ---- List ----

    @Test
    fun list_load_success_populatesRows() = runTest {
        val repo = FakeRefundsRepository().apply { listResult = ApiResult.Success(listOf(sampleRefund())) }
        val vm = RefundListViewModel(repo, mapper)
        val job = launch { vm.uiState.collect {} }
        advanceUntilIdle()
        assertEquals(1, vm.uiState.value.refunds.size)
        assertFalse(vm.uiState.value.isLoading)
        job.cancel()
    }

    @Test
    fun list_refreshFailure_withCache_setsStale_keepsRows() = runTest {
        val repo = FakeRefundsRepository().apply { listResult = ApiResult.Success(listOf(sampleRefund())) }
        val vm = RefundListViewModel(repo, mapper)
        val job = launch { vm.uiState.collect {} }
        advanceUntilIdle()

        repo.listResult = failure(503)
        vm.refresh()
        advanceUntilIdle()

        assertEquals(1, vm.uiState.value.refunds.size) // cached rows retained
        assertTrue(vm.uiState.value.isStale)
        job.cancel()
    }

    @Test
    fun list_loadFailure_noCache_surfacesError() = runTest {
        val repo = FakeRefundsRepository().apply { listResult = failure(500) }
        val vm = RefundListViewModel(repo, mapper)
        val job = launch { vm.uiState.collect {} }
        advanceUntilIdle()
        assertTrue(vm.uiState.value.error != null)
        assertTrue(vm.uiState.value.refunds.isEmpty())
        job.cancel()
    }

    // ---- Submit ----

    private fun submitVm(repo: FakeRefundsRepository) = RefundSubmitViewModel(
        repository = repo,
        errorMapper = mapper,
        savedStateHandle = SavedStateHandle(
            mapOf(RefundSubmitViewModel.ARG_TRANSACTION_ENTRY_ID to "entry_1"),
        ),
    )

    @Test
    fun submit_validation_disablesUntilValid() = runTest {
        val vm = submitVm(FakeRefundsRepository())
        val job = launch { vm.uiState.collect {} }

        vm.onReasonChange("short") // 5 chars
        advanceUntilIdle()
        assertFalse(vm.uiState.value.submitEnabled)
        assertTrue(vm.uiState.value.reasonError != null)

        vm.onReasonChange("a valid reason here") // >= 10
        advanceUntilIdle()
        assertTrue(vm.uiState.value.submitEnabled)

        vm.onAmountChange("0") // not >= 1
        advanceUntilIdle()
        assertFalse(vm.uiState.value.submitEnabled)
        assertTrue(vm.uiState.value.amountError != null)

        vm.onAmountChange("100")
        advanceUntilIdle()
        assertTrue(vm.uiState.value.submitEnabled)
        job.cancel()
    }

    @Test
    fun submit_doubleTap_inFlight_callsRepoOnce() = runTest {
        val gate = CompletableDeferred<Unit>()
        val repo = FakeRefundsRepository().apply {
            submitGate = gate
            submitResult = ApiResult.Success(sampleRefund())
        }
        val vm = submitVm(repo)
        val job = launch { vm.uiState.collect {} }
        vm.onReasonChange("a valid reason here")
        advanceUntilIdle()

        vm.submit()
        vm.submit() // swallowed by the in-flight guard
        advanceUntilIdle()
        assertEquals(1, repo.submitCalls)
        gate.complete(Unit)
        advanceUntilIdle()
        job.cancel()
    }

    @Test
    fun submit_success_emitsSuccessEvent() = runTest {
        val repo = FakeRefundsRepository().apply { submitResult = ApiResult.Success(sampleRefund("rfnd_x")) }
        val vm = submitVm(repo)
        val events = mutableListOf<RefundSubmitEvent>()
        val ejob = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch { vm.events.toList(events) }
        vm.onReasonChange("a valid reason here")
        advanceUntilIdle()

        vm.submit()
        advanceUntilIdle()
        assertTrue(events.single() is RefundSubmitEvent.Success)
        assertEquals("rfnd_x", (events.single() as RefundSubmitEvent.Success).refundId)
        ejob.cancel()
    }

    @Test
    fun submit_failure_emitsFailureEvent() = runTest {
        val repo = FakeRefundsRepository().apply { submitResult = failure(422) }
        val vm = submitVm(repo)
        val events = mutableListOf<RefundSubmitEvent>()
        val ejob = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch { vm.events.toList(events) }
        vm.onReasonChange("a valid reason here")
        advanceUntilIdle()

        vm.submit()
        advanceUntilIdle()
        assertTrue(events.single() is RefundSubmitEvent.Failure)
        ejob.cancel()
    }

    // ---- Detail ----

    private fun detailVm(repo: FakeRefundsRepository) = RefundDetailViewModel(
        repository = repo,
        errorMapper = mapper,
        savedStateHandle = SavedStateHandle(mapOf(RefundDetailViewModel.ARG_REFUND_ID to "rfnd_1")),
    )

    @Test
    fun detail_success_emitsContent() = runTest {
        val repo = FakeRefundsRepository().apply { detailResult = ApiResult.Success(sampleRefund()) }
        val vm = detailVm(repo)
        val job = launch { vm.uiState.collect {} }
        advanceUntilIdle()
        assertTrue(vm.uiState.value is RefundDetailUiState.Content)
        job.cancel()
    }

    @Test
    fun detail_404_isNonRetryable() = runTest {
        val repo = FakeRefundsRepository().apply { detailResult = failure(404) }
        val vm = detailVm(repo)
        val job = launch { vm.uiState.collect {} }
        advanceUntilIdle()
        val state = vm.uiState.value as RefundDetailUiState.Error
        assertFalse(state.retryable)
        job.cancel()
    }
}
