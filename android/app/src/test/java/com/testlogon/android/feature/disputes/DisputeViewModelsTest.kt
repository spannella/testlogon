package com.testlogon.android.feature.disputes

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

/** AND-245 — list (content/empty/failure), detail (content/notfound/failure), file (validation + guard). */
@OptIn(ExperimentalCoroutinesApi::class)
class DisputeViewModelsTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val mapper = BillingErrorMapper()

    // ---- List ----

    @Test
    fun list_success_nonEmpty_isContent() = runTest {
        val repo = FakeDisputesRepository().apply { listResult = ApiResult.Success(listOf(sampleDispute())) }
        val vm = DisputesListViewModel(repo, mapper)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        assertTrue(vm.state.value is DisputesListUiState.Content)
        job.cancel()
    }

    @Test
    fun list_success_empty_isEmpty() = runTest {
        val repo = FakeDisputesRepository().apply { listResult = ApiResult.Success(emptyList()) }
        val vm = DisputesListViewModel(repo, mapper)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        assertEquals(DisputesListUiState.Empty, vm.state.value)
        job.cancel()
    }

    @Test
    fun list_error_isFailure() = runTest {
        val repo = FakeDisputesRepository().apply { listResult = disputeFailure(500) }
        val vm = DisputesListViewModel(repo, mapper)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        assertTrue(vm.state.value is DisputesListUiState.Failure)
        job.cancel()
    }

    // ---- Detail ----

    private fun detailVm(repo: FakeDisputesRepository) = DisputeDetailViewModel(
        repository = repo,
        errorMapper = mapper,
        savedStateHandle = SavedStateHandle(mapOf(DisputeDetailViewModel.ARG_DISPUTE_ID to "dp_1")),
    )

    @Test
    fun detail_success_isContent() = runTest {
        val repo = FakeDisputesRepository().apply { detailResult = ApiResult.Success(sampleDispute()) }
        val vm = detailVm(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        assertTrue(vm.state.value is DisputeDetailUiState.Content)
        job.cancel()
    }

    @Test
    fun detail_404_isNotFound() = runTest {
        val repo = FakeDisputesRepository().apply { detailResult = disputeFailure(404) }
        val vm = detailVm(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        assertEquals(DisputeDetailUiState.NotFound, vm.state.value)
        job.cancel()
    }

    @Test
    fun detail_otherError_isFailure() = runTest {
        val repo = FakeDisputesRepository().apply { detailResult = disputeFailure(422) }
        val vm = detailVm(repo)
        val job = launch { vm.state.collect {} }
        advanceUntilIdle()
        assertTrue(vm.state.value is DisputeDetailUiState.Failure)
        job.cancel()
    }

    // ---- File ----

    private fun fileVm(repo: FakeDisputesRepository) = DisputeFileViewModel(
        repository = repo,
        errorMapper = mapper,
        savedStateHandle = SavedStateHandle(
            mapOf(DisputeFileViewModel.ARG_TRANSACTION_ENTRY_ID to "le_1"),
        ),
    )

    @Test
    fun file_validation_requiresReasonAndAmount() = runTest {
        val vm = fileVm(FakeDisputesRepository())
        val job = launch { vm.uiState.collect {} }

        vm.onReasonChange("valid reason here")
        advanceUntilIdle()
        assertFalse(vm.uiState.value.submitEnabled) // no amount yet

        vm.onAmountChange("4900")
        advanceUntilIdle()
        assertTrue(vm.uiState.value.submitEnabled)

        vm.onAmountChange("0")
        advanceUntilIdle()
        assertFalse(vm.uiState.value.submitEnabled)
        job.cancel()
    }

    @Test
    fun file_doubleTap_inFlight_callsRepoOnce() = runTest {
        val gate = CompletableDeferred<Unit>()
        val repo = FakeDisputesRepository().apply {
            fileGate = gate
            fileResult = ApiResult.Success(sampleDispute())
        }
        val vm = fileVm(repo)
        val job = launch { vm.uiState.collect {} }
        vm.onReasonChange("valid reason here")
        vm.onAmountChange("4900")
        advanceUntilIdle()

        vm.submit()
        vm.submit()
        advanceUntilIdle()
        assertEquals(1, repo.fileCalls)
        gate.complete(Unit)
        advanceUntilIdle()
        job.cancel()
    }

    @Test
    fun file_success_emitsSuccessEvent() = runTest {
        val repo = FakeDisputesRepository().apply { fileResult = ApiResult.Success(sampleDispute("dp_x")) }
        val vm = fileVm(repo)
        val events = mutableListOf<DisputeFileEvent>()
        val ejob = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch { vm.events.toList(events) }
        vm.onReasonChange("valid reason here")
        vm.onAmountChange("4900")
        advanceUntilIdle()

        vm.submit()
        advanceUntilIdle()
        assertTrue(events.single() is DisputeFileEvent.Success)
        ejob.cancel()
    }
}
