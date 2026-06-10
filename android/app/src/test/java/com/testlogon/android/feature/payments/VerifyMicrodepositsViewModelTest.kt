package com.testlogon.android.feature.payments

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.payments.PayPalCaptureDto
import com.testlogon.android.data.payments.PaymentRedirectRepository
import com.testlogon.android.data.payments.RedirectProvider
import com.testlogon.android.data.payments.RedirectSessionResult
import com.testlogon.android.data.payments.UsBankVerificationResult
import com.testlogon.android.data.payments.UsBankVerificationState
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

/** AND-230 — VerifyMicrodepositsViewModel: input gating, success event, error keeps form usable. */
@OptIn(ExperimentalCoroutinesApi::class)
class VerifyMicrodepositsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun vm(repo: PaymentRedirectRepository) = VerifyMicrodepositsViewModel(
        repository = repo,
        savedState = SavedStateHandle(mapOf(VerifyMicrodepositsViewModel.ARG_SETUP_INTENT_ID to "seti_1")),
    )

    @Test
    fun inputGating_onlyValidCentsEnableSubmit() {
        val model = vm(FakeVerifyRepo())
        assertFalse(model.uiState.value.canSubmit)
        model.onFirstChange("0"); model.onSecondChange("45")
        assertFalse(model.uiState.value.canSubmit) // 0 invalid (range 1..99)
        model.onFirstChange("32")
        assertTrue(model.uiState.value.canSubmit)
        model.onFirstChange("1a9") // digit-only, max 2 -> "19"
        assertEquals("19", model.uiState.value.firstCents)
    }

    @Test
    fun submit_success_emitsVerified_andSetsVerifiedState() = runTest {
        val model = vm(FakeVerifyRepo(ApiResult.Success(UsBankVerificationResult("seti_1", UsBankVerificationState.VERIFIED))))
        val events = mutableListOf<VerifyMicrodepositsEvent>()
        val job = launch { model.events.collect { events += it } }
        advanceUntilIdle()

        model.onFirstChange("32"); model.onSecondChange("45")
        model.submit()
        advanceUntilIdle()

        assertTrue(model.uiState.value.verified)
        assertFalse(model.uiState.value.isSubmitting)
        assertEquals("seti_1", (events.single() as VerifyMicrodepositsEvent.Verified).setupIntentId)
        job.cancel()
    }

    @Test
    fun submit_failure_keepsFormUsable_showsError() = runTest {
        val model = vm(FakeVerifyRepo(ApiResult.Failure(ApiError(422, "field required"))))
        val job = launch { model.events.collect { } }
        advanceUntilIdle()
        model.onFirstChange("11"); model.onSecondChange("22")
        model.submit()
        advanceUntilIdle()

        assertEquals("field required", model.uiState.value.error)
        assertFalse(model.uiState.value.isSubmitting)
        assertFalse(model.uiState.value.verified) // form still usable
        job.cancel()
    }

    @Test
    fun submit_networkError_showsRetryableMessage_resetsSubmitting() = runTest {
        val model = vm(FakeVerifyRepo(ApiResult.NetworkError(java.io.IOException(), isTimeout = true)))
        val job = launch { model.events.collect { } }
        advanceUntilIdle()
        model.onFirstChange("32"); model.onSecondChange("45")
        model.submit()
        advanceUntilIdle()

        assertFalse(model.uiState.value.isSubmitting)
        assertTrue(model.uiState.value.error != null)
        job.cancel()
    }

    @Test
    fun submit_whenInvalid_isNoOp() = runTest {
        val repo = FakeVerifyRepo()
        val model = vm(repo)
        model.submit() // blank -> no call
        advanceUntilIdle()
        assertEquals(0, repo.verifyCalls)
        assertNull(model.uiState.value.error)
    }
}

private class FakeVerifyRepo(
    private val result: ApiResult<UsBankVerificationResult> =
        ApiResult.Success(UsBankVerificationResult("seti_1", UsBankVerificationState.VERIFIED)),
) : PaymentRedirectRepository {
    var verifyCalls = 0

    override suspend fun createRedirectSession(
        provider: RedirectProvider,
        amountCents: Long,
        currency: String,
        description: String?,
        ccbillFlowType: String?,
        ccbillCheckoutSessionId: String?,
        ccbillReturnUrl: String?,
        ccbillState: String?,
    ): RedirectSessionResult = RedirectSessionResult.NotConfigured

    override suspend fun capturePayPalOrder(orderId: String, idempotencyKey: String) =
        ApiResult.Success(PayPalCaptureDto(null, null, "COMPLETED"))

    override suspend fun verifyMicrodeposits(setupIntentId: String, amounts: List<Int>): ApiResult<UsBankVerificationResult> {
        verifyCalls++
        return result
    }
}
