package com.testlogon.android.feature.payments

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.payments.InFlightPayment
import com.testlogon.android.data.payments.PaymentClock
import com.testlogon.android.data.payments.PaymentIntentStore
import com.testlogon.android.data.payments.PaymentOutcome
import com.testlogon.android.data.payments.PaymentRedirectRepository
import com.testlogon.android.data.payments.PaymentReturn
import com.testlogon.android.data.payments.PaymentReturnDispatcher
import com.testlogon.android.data.payments.PayPalCaptureDto
import com.testlogon.android.data.payments.RedirectProvider
import com.testlogon.android.data.payments.RedirectSession
import com.testlogon.android.data.payments.RedirectSessionResult
import com.testlogon.android.data.payments.UsBankVerificationResult
import com.testlogon.android.data.payments.UsBankVerificationState
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-227/228/229/231 — RedirectCheckoutViewModel state-machine tests.
 *
 * Headline (PAYMENTS FLAG / AND-031): with a NotConfigured session result, pay() lands on
 * PaymentsUnavailable, emits NO open-tab effect, and persists NO in-flight intent (no live session).
 * The authorized path drives CreatingSession -> AwaitingReturn (open-tab) -> Confirming -> Succeeded
 * via a simulated SUCCESS return.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class RedirectCheckoutViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun savedState() = SavedStateHandle(
        mapOf(
            RedirectCheckoutViewModel.ARG_AMOUNT_CENTS to 500L,
            RedirectCheckoutViewModel.ARG_CURRENCY to "USD",
        ),
    )

    private fun vm(
        repo: PaymentRedirectRepository,
        store: PaymentIntentStore = FakeStore(),
        dispatcher: PaymentReturnDispatcher = PaymentReturnDispatcher(),
    ) = RedirectCheckoutViewModel(
        repository = repo,
        intentStore = store,
        clock = PaymentClock { 1_000L },
        dispatcher = dispatcher,
        savedState = savedState(),
    )

    @Test
    fun pay_notConfigured_surfacesUnavailable_noTab_noInFlight() = runTest {
        val store = FakeStore()
        val model = vm(FakeRepo(sessionResult = RedirectSessionResult.NotConfigured), store)
        val effects = mutableListOf<RedirectCheckoutEffect>()
        val job = launch { model.effects.collect { effects += it } }
        advanceUntilIdle()

        model.pay(PaymentMethodOption.PAYPAL)
        advanceUntilIdle()

        assertEquals(RedirectCheckoutUiState.PaymentsUnavailable, model.uiState.value)
        assertTrue(effects.isEmpty()) // no Custom Tab opened
        assertTrue(store.puts.isEmpty()) // no live session persisted
        job.cancel()
    }

    @Test
    fun pay_authorized_opensTab_thenSuccessReturn_confirms() = runTest {
        val session = RedirectSession(RedirectProvider.PAYPAL, "cs_1", "https://approve.example/cs_1")
        val model = vm(
            FakeRepo(
                sessionResult = RedirectSessionResult.Created(session),
                capture = ApiResult.Success(PayPalCaptureDto("cs_1", "PP-CAP", "COMPLETED")),
            ),
        )
        val effects = mutableListOf<RedirectCheckoutEffect>()
        val job = launch { model.effects.collect { effects += it } }
        advanceUntilIdle()

        model.pay(PaymentMethodOption.PAYPAL)
        advanceUntilIdle()
        assertTrue(model.uiState.value is RedirectCheckoutUiState.AwaitingReturn)
        assertEquals(1, effects.count { it is RedirectCheckoutEffect.OpenCustomTab })

        model.onReturn(successReturn("cs_1"))
        advanceUntilIdle()
        assertTrue(model.uiState.value is RedirectCheckoutUiState.Succeeded)
        job.cancel()
    }

    @Test
    fun onReturn_cancel_movesToCancelled() = runTest {
        val session = RedirectSession(RedirectProvider.PAYPAL, "cs_1", "u")
        val model = vm(FakeRepo(sessionResult = RedirectSessionResult.Created(session)))
        val job = launch { model.effects.collect { } }
        advanceUntilIdle()
        model.pay(PaymentMethodOption.PAYPAL)
        advanceUntilIdle()

        model.onReturn(successReturn("cs_1").copy(outcome = PaymentOutcome.CANCEL))
        advanceUntilIdle()
        assertTrue(model.uiState.value is RedirectCheckoutUiState.Cancelled)
        job.cancel()
    }

    @Test
    fun pay_doubleTapWhileInFlight_isNoOp() = runTest {
        val session = RedirectSession(RedirectProvider.PAYPAL, "cs_1", "u")
        val repo = FakeRepo(sessionResult = RedirectSessionResult.Created(session))
        val model = vm(repo)
        val job = launch { model.effects.collect { } }
        advanceUntilIdle()

        model.pay(PaymentMethodOption.PAYPAL)
        advanceUntilIdle()
        model.pay(PaymentMethodOption.PAYPAL) // ignored while AwaitingReturn
        advanceUntilIdle()
        assertEquals(1, repo.createCalls)
        job.cancel()
    }

    @Test
    fun pay_failure_surfacesRetryableFailed() = runTest {
        val model = vm(FakeRepo(sessionResult = RedirectSessionResult.Failed("boom", retryable = true)))
        val job = launch { model.effects.collect { } }
        advanceUntilIdle()
        model.pay(PaymentMethodOption.HOSTED_CHECKOUT)
        advanceUntilIdle()
        val state = model.uiState.value
        assertTrue(state is RedirectCheckoutUiState.Failed)
        assertEquals("boom", (state as RedirectCheckoutUiState.Failed).message)
        job.cancel()
    }

    @Test
    fun confirm_paypalCaptureFails_isRecoverableNotSilentFailure() = runTest {
        val session = RedirectSession(RedirectProvider.PAYPAL, "cs_1", "u")
        val model = vm(
            FakeRepo(
                sessionResult = RedirectSessionResult.Created(session),
                capture = ApiResult.Failure(ApiError(500, "server")),
            ),
        )
        val job = launch { model.effects.collect { } }
        advanceUntilIdle()
        model.pay(PaymentMethodOption.PAYPAL)
        advanceUntilIdle()
        model.onReturn(successReturn("cs_1"))
        advanceUntilIdle()
        val state = model.uiState.value
        assertTrue(state is RedirectCheckoutUiState.Failed)
        assertTrue((state as RedirectCheckoutUiState.Failed).retryable)
        job.cancel()
    }

    private fun successReturn(intentId: String) = PaymentReturn(
        provider = "paypal",
        outcome = PaymentOutcome.SUCCESS,
        intentId = intentId,
        state = null,
        providerRef = "PP-ORDER",
        errorCode = null,
        errorMessage = null,
        rawUri = "testlogon://payments/return?provider=paypal&intent=$intentId&status=success",
    )
}

private class FakeRepo(
    private val sessionResult: RedirectSessionResult,
    private val capture: ApiResult<PayPalCaptureDto> = ApiResult.Success(PayPalCaptureDto(null, null, "COMPLETED")),
) : PaymentRedirectRepository {
    var createCalls = 0

    override suspend fun createRedirectSession(
        provider: RedirectProvider,
        amountCents: Long,
        currency: String,
        description: String?,
        ccbillFlowType: String?,
        ccbillCheckoutSessionId: String?,
        ccbillReturnUrl: String?,
        ccbillState: String?,
    ): RedirectSessionResult {
        createCalls++
        return sessionResult
    }

    override suspend fun capturePayPalOrder(orderId: String, idempotencyKey: String) = capture

    override suspend fun verifyMicrodeposits(setupIntentId: String, amounts: List<Int>) =
        ApiResult.Success(UsBankVerificationResult(setupIntentId, UsBankVerificationState.VERIFIED))
}

private class FakeStore : PaymentIntentStore {
    val puts = mutableListOf<InFlightPayment>()
    private var current: InFlightPayment? = null
    private val consumed = mutableSetOf<String>()
    override suspend fun put(payment: InFlightPayment) { puts += payment; current = payment }
    override suspend fun get(): InFlightPayment? = current
    override suspend fun clear() { current = null }
    override suspend fun markConsumed(intentId: String): Boolean = consumed.add(intentId)
}
