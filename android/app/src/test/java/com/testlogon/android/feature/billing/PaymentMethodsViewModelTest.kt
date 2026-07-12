package com.testlogon.android.feature.billing

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import com.testlogon.android.feature.billing.error.Recoverability
import com.testlogon.android.data.billing.BillingBalance
import com.testlogon.android.data.billing.BillingConfig
import com.testlogon.android.data.billing.BillingRepository
import com.testlogon.android.data.billing.BillingSettings
import com.testlogon.android.data.billing.CardBrand
import com.testlogon.android.data.billing.LedgerPage
import com.testlogon.android.data.billing.PaymentMethod
import com.testlogon.android.data.billing.Subscription
import com.testlogon.android.data.billing.WalletBalance
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.IOException

/**
 * AND-224 — [PaymentMethodsViewModel] transitions: load -> Loaded / Empty / Error; set-default and
 * remove lock only their row, reconcile to the re-fetched list, and emit one-shot events; mutation
 * failure leaves the row and emits Failure; in-flight guard prevents duplicate calls.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PaymentMethodsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun card(id: String, default: Boolean = false, priority: Int = 0) = PaymentMethod(
        id = id,
        methodType = "card",
        brand = CardBrand.VISA,
        rawBrand = "visa",
        last4 = "4242",
        expMonth = 12,
        expYear = 2030,
        label = null,
        priority = priority,
        provider = "stripe",
        isDefault = default,
    )

    private fun vm(repo: FakeBillingRepository) = PaymentMethodsViewModel(repo, BillingErrorMapper())

    @Test
    fun load_success_populatesMethods() = runTest {
        val repo = FakeBillingRepository().apply {
            methods = ApiResult.Success(listOf(card("pm_1", default = true), card("pm_2")))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertTrue(model.uiState.value.load is PaymentMethodsLoadState.Loaded)
        assertEquals(2, model.uiState.value.methods.size)
        assertFalse(model.uiState.value.isEmpty)
        job.cancel()
    }

    @Test
    fun load_empty_isEmptyState() = runTest {
        val repo = FakeBillingRepository().apply { methods = ApiResult.Success(emptyList()) }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertTrue(model.uiState.value.isEmpty)
        job.cancel()
    }

    @Test
    fun load_networkError_isRetryableError() = runTest {
        val repo = FakeBillingRepository().apply { methods = ApiResult.NetworkError(IOException("x")) }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        val load = model.uiState.value.load
        assertTrue(load is PaymentMethodsLoadState.Error)
        assertTrue((load as PaymentMethodsLoadState.Error).retryable)
        job.cancel()
    }

    @Test
    fun setDefault_reconcilesAndEmitsDefaultSet() = runTest {
        val repo = FakeBillingRepository().apply {
            methods = ApiResult.Success(listOf(card("pm_1", default = true), card("pm_2")))
            setDefaultResult = ApiResult.Success(listOf(card("pm_2", default = true), card("pm_1")))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        val events = mutableListOf<PaymentMethodsEvent>()
        val ejob = launch { model.events.collect { events += it } }
        advanceUntilIdle()

        model.setDefault("pm_2")
        advanceUntilIdle()

        assertEquals("pm_2", model.uiState.value.methods.first().id)
        assertTrue(model.uiState.value.methods.first().isDefault)
        assertTrue(model.uiState.value.rowInFlight.isEmpty())
        assertTrue(events.single() is PaymentMethodsEvent.DefaultSet)
        assertEquals(1, repo.setDefaultCalls)
        job.cancel(); ejob.cancel()
    }

    @Test
    fun remove_reconcilesAndEmitsRemoved() = runTest {
        val repo = FakeBillingRepository().apply {
            methods = ApiResult.Success(listOf(card("pm_1", default = true), card("pm_2")))
            removeResult = ApiResult.Success(listOf(card("pm_1", default = true)))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        val events = mutableListOf<PaymentMethodsEvent>()
        val ejob = launch { model.events.collect { events += it } }
        advanceUntilIdle()

        model.remove("pm_2")
        advanceUntilIdle()

        assertEquals(listOf("pm_1"), model.uiState.value.methods.map { it.id })
        assertTrue(events.single() is PaymentMethodsEvent.Removed)
        assertEquals(1, repo.removeCalls)
        job.cancel(); ejob.cancel()
    }

    @Test
    fun remove_failure_dropsRowLocally_noErrorState() = runTest {
        // #15 — a post-delete re-fetch failure (masks delete success) must NOT leave a stale row or a
        // permanent Error screen: the deleted row is pruned locally and the list stays Loaded.
        val repo = FakeBillingRepository().apply {
            methods = ApiResult.Success(listOf(card("pm_1", default = true), card("pm_2")))
            removeResult = ApiResult.NetworkError(IOException("boom"))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        val events = mutableListOf<PaymentMethodsEvent>()
        val ejob = launch { model.events.collect { events += it } }
        advanceUntilIdle()

        model.remove("pm_2")
        advanceUntilIdle()

        // Loaded (NOT Error); pm_2 pruned; row cleared; one Failure event surfaced.
        assertTrue(model.uiState.value.load is PaymentMethodsLoadState.Loaded)
        assertEquals(listOf("pm_1"), model.uiState.value.methods.map { it.id })
        assertTrue(model.uiState.value.rowInFlight.isEmpty())
        assertTrue(events.single() is PaymentMethodsEvent.Failure)
        job.cancel(); ejob.cancel()
    }

    @Test
    fun mutationFailure_leavesRow_andEmitsFailure_noListChange() = runTest {
        val repo = FakeBillingRepository().apply {
            methods = ApiResult.Success(listOf(card("pm_1", default = true), card("pm_2")))
            // A validation error (422) -> FATAL, server-normalized message passed through (Raw).
            setDefaultResult = ApiResult.Failure(ApiError(status = 422, message = "Card on file is invalid"))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        val events = mutableListOf<PaymentMethodsEvent>()
        val ejob = launch { model.events.collect { events += it } }
        advanceUntilIdle()

        model.setDefault("pm_2")
        advanceUntilIdle()

        // List unchanged; row cleared; Failure event with a mapped BillingError.
        assertEquals(listOf("pm_1", "pm_2"), model.uiState.value.methods.map { it.id })
        assertTrue(model.uiState.value.rowInFlight.isEmpty())
        val failure = events.single() as PaymentMethodsEvent.Failure
        assertEquals(Recoverability.FATAL, failure.error.recoverability)
        assertEquals(UiText.Raw("Card on file is invalid"), failure.error.message)
        job.cancel(); ejob.cancel()
    }

    @Test
    fun setDefault_whileRowInFlight_isNoOp() = runTest {
        val repo = FakeBillingRepository().apply {
            methods = ApiResult.Success(listOf(card("pm_1", default = true), card("pm_2")))
            // Block the first call so the row stays in flight.
            setDefaultResult = ApiResult.Success(listOf(card("pm_2", default = true), card("pm_1")))
            blockSetDefault = true
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()

        model.setDefault("pm_2")
        model.setDefault("pm_2") // second tap while in-flight
        advanceUntilIdle()
        // Still blocked -> exactly one call recorded.
        assertEquals(1, repo.setDefaultCalls)
        assertTrue("pm_2" in model.uiState.value.rowInFlight)
        repo.release()
        advanceUntilIdle()
        assertTrue(model.uiState.value.rowInFlight.isEmpty())
        job.cancel()
    }
}

/** Test double for the billing repository (payment-method ops are the ones exercised). */
class FakeBillingRepository : BillingRepository {
    var methods: ApiResult<List<PaymentMethod>> = ApiResult.Success(emptyList())
    var setDefaultResult: ApiResult<List<PaymentMethod>> = ApiResult.Success(emptyList())
    var removeResult: ApiResult<List<PaymentMethod>> = ApiResult.Success(emptyList())
    var setDefaultCalls = 0
    var removeCalls = 0

    var blockSetDefault = false
    private val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
    fun release() = gate.complete(Unit)

    override suspend fun getPaymentMethods(): ApiResult<List<PaymentMethod>> = methods

    override suspend fun setDefaultPaymentMethod(id: String): ApiResult<List<PaymentMethod>> {
        setDefaultCalls++
        if (blockSetDefault) gate.await()
        return setDefaultResult
    }

    override suspend fun removePaymentMethod(id: String): ApiResult<List<PaymentMethod>> {
        removeCalls++
        return removeResult
    }

    var addCardResult: ApiResult<List<PaymentMethod>> = ApiResult.Success(emptyList())
    var addBankResult: ApiResult<List<PaymentMethod>> = ApiResult.Success(emptyList())
    var addCardCalls = 0
    var addBankCalls = 0

    override suspend fun addCard(
        req: com.testlogon.android.data.billing.AddCardReqDto,
    ): ApiResult<List<PaymentMethod>> {
        addCardCalls++
        return addCardResult
    }

    override suspend fun addBank(
        req: com.testlogon.android.data.billing.AddBankReqDto,
    ): ApiResult<List<PaymentMethod>> {
        addBankCalls++
        return addBankResult
    }

    override suspend fun getConfig(): ApiResult<BillingConfig> =
        ApiResult.Success(BillingConfig(publishableKey = null, currency = "USD"))

    override suspend fun getSettings(): ApiResult<BillingSettings> =
        ApiResult.Success(BillingSettings(false, "USD", null, null))

    override suspend fun getBalance(): ApiResult<BillingBalance> =
        ApiResult.Success(
            BillingBalance(
                owedPending = com.testlogon.android.data.billing.BillingMoney(0, "USD"),
                owedSettled = com.testlogon.android.data.billing.BillingMoney(0, "USD"),
                paymentsPending = com.testlogon.android.data.billing.BillingMoney(0, "USD"),
                paymentsSettled = com.testlogon.android.data.billing.BillingMoney(0, "USD"),
                duePending = null,
                dueSettled = null,
                updatedAtEpochSeconds = null,
            ),
        )

    override suspend fun getSubscriptions(limit: Int): ApiResult<List<Subscription>> =
        ApiResult.Success(emptyList())

    override suspend fun getLedger(limit: Int): ApiResult<LedgerPage> =
        ApiResult.Success(LedgerPage(emptyList()))

    override suspend fun getPayments(limit: Int): ApiResult<LedgerPage> =
        ApiResult.Success(LedgerPage(emptyList()))

    override suspend fun getWallet(): ApiResult<WalletBalance> =
        ApiResult.Success(WalletBalance(com.testlogon.android.data.billing.BillingMoney(0, "USD"), null))
}
