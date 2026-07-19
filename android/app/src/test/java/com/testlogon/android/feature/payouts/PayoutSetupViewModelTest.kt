package com.testlogon.android.feature.payouts

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.payouts.PayoutGate
import com.testlogon.android.data.payouts.PayoutRequestOutcome
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-259 — [PayoutSetupViewModel] transitions: load -> gate derivation, below-tier submit no-op,
 * local validation, the STOP-AND-FLAG NotConfigured outcome surfacing "payouts unavailable" (no payout
 * created), fail-closed gate, and the KYC-return evaluate path.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PayoutSetupViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun vm(repo: FakePayoutSetupRepository) = PayoutSetupViewModel(repo, BillingErrorMapper())

    @Test
    fun load_allowed_derivesAllowedGate_andBalance() = runTest {
        val repo = FakePayoutSetupRepository().apply {
            setupResult = ApiResult.Success(
                com.testlogon.android.data.payouts.PayoutSetupData(
                    balance = sampleBalance(), recentPayouts = emptyList(), tierStatus = sampleTierStatus(eligible = true),
                ),
            )
        }
        val viewModel = vm(repo)
        advanceUntilIdle()
        val state = viewModel.state.value
        assertFalse(state.isLoading)
        assertEquals(PayoutGate.Allowed, state.gate)
        assertEquals(50000L, state.balance?.availableCents)
    }

    @Test
    fun load_belowTier_blocked_submitIsNoOp() = runTest {
        val repo = FakePayoutSetupRepository().apply {
            setupResult = ApiResult.Success(
                com.testlogon.android.data.payouts.PayoutSetupData(
                    balance = sampleBalance(),
                    recentPayouts = emptyList(),
                    tierStatus = sampleTierStatus(current = 0, required = 1, eligible = false, unmet = listOf("gov_id")),
                ),
            )
        }
        val viewModel = vm(repo)
        advanceUntilIdle()
        assertTrue(viewModel.state.value.gate is PayoutGate.Blocked)
        viewModel.submit()
        advanceUntilIdle()
        // Defensive guard: blocked gate => no backend request.
        assertEquals(0, repo.requestPayoutCalls)
    }

    @Test
    fun load_kycUnavailable_gateUnknown_failClosed() = runTest {
        val repo = FakePayoutSetupRepository().apply {
            setupResult = ApiResult.Success(
                com.testlogon.android.data.payouts.PayoutSetupData(
                    balance = sampleBalance(), recentPayouts = emptyList(), tierStatus = null,
                ),
            )
        }
        val viewModel = vm(repo)
        advanceUntilIdle()
        assertEquals(PayoutGate.Unknown, viewModel.state.value.gate)
    }

    @Test
    fun validation_blocksSubmit_belowMin_aboveAvailable_andEnablesInRange() = runTest {
        val repo = FakePayoutSetupRepository().apply {
            setupResult = ApiResult.Success(
                com.testlogon.android.data.payouts.PayoutSetupData(
                    balance = sampleBalance(available = 50000, min = 1000),
                    recentPayouts = emptyList(),
                    tierStatus = sampleTierStatus(eligible = true),
                ),
            )
        }
        val viewModel = vm(repo)
        advanceUntilIdle()

        viewModel.onAmountChanged("5") // $5 = 500 cents < min 1000
        assertFalse(viewModel.state.value.form.canSubmit)
        assertTrue(viewModel.state.value.form.amountError != null)

        viewModel.onAmountChanged("9999") // 999900 cents > available 50000
        assertFalse(viewModel.state.value.form.canSubmit)

        viewModel.onAmountChanged("100") // $100 = 10000 cents, in [1000, 50000]
        assertTrue(viewModel.state.value.form.canSubmit)
        assertNull(viewModel.state.value.form.amountError)
    }

    @Test
    fun submit_backendGateRejects_surfacesError_noPayoutCreated() = runTest {
        // PAY-52: the client short-circuit is gone; a payout that the server gate rejects comes back as
        // PayoutRequestOutcome.Error and the VM must surface it WITHOUT a created id.
        val repo = FakePayoutSetupRepository().apply {
            setupResult = ApiResult.Success(
                com.testlogon.android.data.payouts.PayoutSetupData(
                    balance = sampleBalance(), recentPayouts = emptyList(), tierStatus = sampleTierStatus(eligible = true),
                ),
            )
            requestOutcome = PayoutRequestOutcome.Error(
                ApiResult.Failure(com.testlogon.android.core.model.ApiError(status = 403, message = "kyc_required")),
            )
        }
        val viewModel = vm(repo)
        advanceUntilIdle()
        viewModel.onAmountChanged("100")
        viewModel.submit()
        advanceUntilIdle()
        val state = viewModel.state.value
        assertNull("no payout was created", state.lastCreatedPayoutId)
        assertTrue("an error message is surfaced", state.error != null)
        assertFalse(state.isSubmitting)
        assertEquals(1, repo.requestPayoutCalls)
    }

    @Test
    fun submit_created_setsConfirmation() = runTest {
        val repo = FakePayoutSetupRepository().apply {
            setupResult = ApiResult.Success(
                com.testlogon.android.data.payouts.PayoutSetupData(
                    balance = sampleBalance(), recentPayouts = emptyList(), tierStatus = sampleTierStatus(eligible = true),
                ),
            )
            requestOutcome = PayoutRequestOutcome.Created(
                com.testlogon.android.data.payouts.PayoutCreateResult(
                    ok = true,
                    payoutId = "po_42",
                    amount = com.testlogon.android.data.payouts.PayoutMoney(10000, "USD"),
                    status = com.testlogon.android.data.payouts.PayoutStatus.REQUESTED,
                ),
            )
        }
        val viewModel = vm(repo)
        advanceUntilIdle()
        viewModel.onAmountChanged("100")
        viewModel.submit()
        advanceUntilIdle()
        assertEquals("po_42", viewModel.state.value.lastCreatedPayoutId)
    }

    @Test
    fun onReturnedFromKyc_evaluates_unlocksWhenTierRises() = runTest {
        val repo = FakePayoutSetupRepository().apply {
            setupResult = ApiResult.Success(
                com.testlogon.android.data.payouts.PayoutSetupData(
                    balance = sampleBalance(),
                    recentPayouts = emptyList(),
                    tierStatus = sampleTierStatus(current = 0, required = 1, eligible = false, unmet = listOf("gov_id")),
                ),
            )
            refreshResult = ApiResult.Success(sampleTierStatus(current = 1, required = 1, eligible = true))
        }
        val viewModel = vm(repo)
        advanceUntilIdle()
        assertTrue(viewModel.state.value.gate is PayoutGate.Blocked)
        viewModel.onReturnedFromKyc()
        advanceUntilIdle()
        assertEquals(PayoutGate.Allowed, viewModel.state.value.gate)
        assertFalse(viewModel.state.value.evaluating)
    }

    @Test
    fun onVerifyIdentity_emitsNavigateToKycEffect() = runTest {
        val repo = FakePayoutSetupRepository()
        val viewModel = vm(repo)
        advanceUntilIdle()
        var received: PayoutSetupViewModel.Effect? = null
        val job = launch { viewModel.effects.collect { received = it } }
        viewModel.onVerifyIdentity()
        advanceUntilIdle()
        assertEquals(PayoutSetupViewModel.Effect.NavigateToKyc, received)
        job.cancel()
    }

    @Test
    fun load_failure_setsLoadFailed() = runTest {
        val repo = FakePayoutSetupRepository().apply {
            setupResult = ApiResult.Failure(ApiError(status = 500, message = "down"))
        }
        val viewModel = vm(repo)
        advanceUntilIdle()
        assertTrue(viewModel.state.value.loadFailed)
    }
}
