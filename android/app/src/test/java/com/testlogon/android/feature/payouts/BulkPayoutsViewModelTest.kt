package com.testlogon.android.feature.payouts

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-261/262/263 — [BulkPayoutsListViewModel] + [BulkPayoutDetailViewModel] transitions: load ->
 * Content/Empty/Error, the offline/stale retention path (FR-6), retry, and the SavedStateHandle-keyed
 * detail load (header + embedded items in one call). Read-only — no mutating intents exist.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class BulkPayoutsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun listVm(repo: FakeBulkPayoutsRepository) =
        BulkPayoutsListViewModel(repo, BillingErrorMapper())

    private fun detailVm(repo: FakeBulkPayoutsRepository, batchId: String = "bat_1") =
        BulkPayoutDetailViewModel(
            repo,
            BillingErrorMapper(),
            SavedStateHandle(mapOf(BulkPayoutDetailViewModel.ARG_BATCH_ID to batchId)),
        )

    // ---- list ----

    @Test
    fun list_load_success_rendersContent() = runTest {
        val repo = FakeBulkPayoutsRepository().apply {
            batchesResult = ApiResult.Success(listOf(sampleBatch("bat_a"), sampleBatch("bat_b")))
        }
        val vm = listVm(repo)
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is BulkListUiState.Content)
        assertEquals(listOf("bat_a", "bat_b"), (state as BulkListUiState.Content).batches.map { it.id })
    }

    @Test
    fun list_load_emptyArray_rendersEmpty() = runTest {
        val repo = FakeBulkPayoutsRepository().apply { batchesResult = ApiResult.Success(emptyList()) }
        val vm = listVm(repo)
        advanceUntilIdle()
        assertEquals(BulkListUiState.Empty, vm.state.value)
    }

    @Test
    fun list_load_failure_noPrior_rendersError() = runTest {
        val repo = FakeBulkPayoutsRepository().apply {
            batchesResult = ApiResult.Failure(ApiError(status = 500, message = "down"))
        }
        val vm = listVm(repo)
        advanceUntilIdle()
        assertTrue(vm.state.value is BulkListUiState.Error)
    }

    @Test
    fun list_refreshFailure_withPrior_retainsContentAsStale() = runTest {
        val repo = FakeBulkPayoutsRepository().apply {
            batchesResult = ApiResult.Success(listOf(sampleBatch("bat_a")))
        }
        val vm = listVm(repo)
        advanceUntilIdle()
        assertTrue(vm.state.value is BulkListUiState.Content)

        // Subsequent refresh fails -> retain rows + stale flag (FR-6).
        repo.batchesResult = ApiResult.NetworkError(java.io.IOException("offline"))
        vm.retry()
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is BulkListUiState.Content)
        assertTrue((state as BulkListUiState.Content).stale)
        assertEquals(listOf("bat_a"), state.batches.map { it.id })
    }

    @Test
    fun list_retry_afterError_recovers() = runTest {
        val repo = FakeBulkPayoutsRepository().apply {
            batchesResult = ApiResult.Failure(ApiError(status = 500, message = "down"))
        }
        val vm = listVm(repo)
        advanceUntilIdle()
        assertTrue(vm.state.value is BulkListUiState.Error)

        repo.batchesResult = ApiResult.Success(listOf(sampleBatch("bat_a")))
        vm.retry()
        advanceUntilIdle()
        assertTrue(vm.state.value is BulkListUiState.Content)
    }

    // ---- detail ----

    @Test
    fun detail_load_success_rendersContent_readsBatchIdFromSavedState() = runTest {
        val repo = FakeBulkPayoutsRepository().apply {
            batchResult = ApiResult.Success(sampleBatch("bat_77"))
        }
        val vm = detailVm(repo, batchId = "bat_77")
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is BulkBatchDetailUiState.Content)
        assertEquals("bat_77", (state as BulkBatchDetailUiState.Content).batch.id)
        assertEquals("bat_77", repo.lastBatchId)
        assertEquals(1, state.batch.items.size) // embedded items present from one call
    }

    @Test
    fun detail_load_failure_rendersError() = runTest {
        val repo = FakeBulkPayoutsRepository().apply {
            batchResult = ApiResult.Failure(ApiError(status = 422, message = "bad"))
        }
        val vm = detailVm(repo)
        advanceUntilIdle()
        assertTrue(vm.state.value is BulkBatchDetailUiState.Error)
    }

    @Test
    fun detail_retry_afterError_recovers() = runTest {
        val repo = FakeBulkPayoutsRepository().apply {
            batchResult = ApiResult.Failure(ApiError(status = 500, message = "down"))
        }
        val vm = detailVm(repo)
        advanceUntilIdle()
        assertTrue(vm.state.value is BulkBatchDetailUiState.Error)

        repo.batchResult = ApiResult.Success(sampleBatch())
        vm.retry()
        advanceUntilIdle()
        assertTrue(vm.state.value is BulkBatchDetailUiState.Content)
    }
}
