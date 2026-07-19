package com.testlogon.android.feature.payouts

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-260 / PAY-51 — [PayoutDetailViewModel]. The former in-memory [PayoutCache] hydration was replaced
 * by a user-scoped backend fetch (GET payout detail): Success -> Content(detail), 404/403 -> NotFound
 * (reopen-from-history), and network/5xx -> Error.
 */
class PayoutDetailViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun vm(repo: FakePayoutsRepository, id: String = "po_x") = PayoutDetailViewModel(
        repo,
        BillingErrorMapper(),
        SavedStateHandle(mapOf(PayoutDetailViewModel.ARG_PAYOUT_ID to id)),
    )

    @Test
    fun detailSuccess_rendersContent() = runTest {
        val repo = FakePayoutsRepository().apply {
            payoutDetailResult = ApiResult.Success(samplePayoutDetail("po_x"))
        }
        val vm = vm(repo)
        advanceUntilIdle()
        val state = vm.uiState.value
        assertTrue(state is PayoutDetailUiState.Content)
        assertEquals("po_x", (state as PayoutDetailUiState.Content).detail.payoutId)
    }

    @Test
    fun notOwnedOrUnknown_404_rendersNotFound() = runTest {
        val repo = FakePayoutsRepository().apply {
            payoutDetailResult = ApiResult.Failure(ApiError(status = 404, message = "unknown"))
        }
        val vm = vm(repo)
        advanceUntilIdle()
        assertEquals(PayoutDetailUiState.NotFound, vm.uiState.value)
    }

    @Test
    fun notOwner_403_rendersNotFound() = runTest {
        val repo = FakePayoutsRepository().apply {
            payoutDetailResult = ApiResult.Failure(ApiError(status = 403, message = "forbidden"))
        }
        val vm = vm(repo)
        advanceUntilIdle()
        assertEquals(PayoutDetailUiState.NotFound, vm.uiState.value)
    }

    @Test
    fun serverError_500_rendersError() = runTest {
        val repo = FakePayoutsRepository().apply {
            payoutDetailResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val vm = vm(repo)
        advanceUntilIdle()
        assertTrue(vm.uiState.value is PayoutDetailUiState.Error)
    }
}
