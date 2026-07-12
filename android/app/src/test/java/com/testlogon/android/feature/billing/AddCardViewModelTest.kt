package com.testlogon.android.feature.billing

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.billing.AddBankReqDto
import com.testlogon.android.data.billing.AddCardReqDto
import com.testlogon.android.data.billing.BillingRepository
import com.testlogon.android.data.billing.PaymentMethod
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * [AddCardViewModel] manual add-payment-method form (Card / Bank tabs) wired to the BK-C dev/test
 * endpoints via [BillingRepository.addCard] / [addBank]. Validation runs client-side; a successful add
 * emits [AddCardEvent.Saved]; a backend failure surfaces a mapped form error + a Failure event.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class AddCardViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun model(repo: BillingRepository = FakeAddRepo()) =
        AddCardViewModel(repo, BillingErrorMapper())

    @Test
    fun submitCard_withInvalidFields_setsFieldErrors_andDoesNotCallBackend() = runTest {
        val repo = FakeAddRepo()
        val vm = model(repo)
        vm.onCardNumberChange("4242") // too short
        vm.onExpMonthChange("13") // invalid month
        vm.onExpYearChange("99") // invalid year
        vm.onCvcChange("1") // too short
        vm.submit()
        advanceUntilIdle()

        assertNotNull(vm.uiState.value.cardNumberError)
        assertNotNull(vm.uiState.value.expMonthError)
        assertNotNull(vm.uiState.value.expYearError)
        assertNotNull(vm.uiState.value.cvcError)
        assertEquals(0, repo.addCardCalls)
    }

    @Test
    fun submitCard_valid_callsBackend_andEmitsSaved() = runTest {
        val repo = FakeAddRepo()
        val vm = model(repo)
        val events = mutableListOf<AddCardEvent>()
        val job = launch { vm.events.collect { events += it } }
        advanceUntilIdle()

        vm.onCardNumberChange("4242424242424242")
        vm.onExpMonthChange("12")
        vm.onExpYearChange("2030")
        vm.onCvcChange("123")
        vm.submit()
        advanceUntilIdle()

        assertEquals(1, repo.addCardCalls)
        assertEquals("4242424242424242", repo.lastCard?.cardNumber)
        assertEquals(12, repo.lastCard?.expMonth)
        assertTrue(events.single() is AddCardEvent.Saved)
        assertFalse(vm.uiState.value.isSubmitting)
        job.cancel()
    }

    @Test
    fun submitBank_valid_callsBackend_andEmitsSaved() = runTest {
        val repo = FakeAddRepo()
        val vm = model(repo)
        val events = mutableListOf<AddCardEvent>()
        val job = launch { vm.events.collect { events += it } }
        advanceUntilIdle()

        vm.selectTab(AddMethodTab.BANK)
        vm.onRoutingNumberChange("110000000")
        vm.onAccountNumberChange("000123456789")
        vm.onAccountTypeChange("savings")
        vm.submit()
        advanceUntilIdle()

        assertEquals(1, repo.addBankCalls)
        assertEquals("110000000", repo.lastBank?.routingNumber)
        assertEquals("savings", repo.lastBank?.accountType)
        assertTrue(events.single() is AddCardEvent.Saved)
        job.cancel()
    }

    @Test
    fun submitBank_shortRouting_setsError_andDoesNotCallBackend() = runTest {
        val repo = FakeAddRepo()
        val vm = model(repo)
        vm.selectTab(AddMethodTab.BANK)
        vm.onRoutingNumberChange("123") // not 9 digits
        vm.onAccountNumberChange("00012345")
        vm.submit()
        advanceUntilIdle()

        assertNotNull(vm.uiState.value.routingNumberError)
        assertEquals(0, repo.addBankCalls)
    }

    @Test
    fun submitCard_backendFailure_setsFormError_andEmitsFailure() = runTest {
        val repo = FakeAddRepo().apply {
            addCardResult = ApiResult.Failure(ApiError(status = 400, code = "card_declined", message = "Declined"))
        }
        val vm = model(repo)
        val events = mutableListOf<AddCardEvent>()
        val job = launch { vm.events.collect { events += it } }
        advanceUntilIdle()

        vm.onCardNumberChange("4000000000000002")
        vm.onExpMonthChange("12")
        vm.onExpYearChange("2030")
        vm.onCvcChange("123")
        vm.submit()
        advanceUntilIdle()

        assertNotNull(vm.uiState.value.formError)
        assertTrue(events.single() is AddCardEvent.Failure)
        assertFalse(vm.uiState.value.isSubmitting)
        job.cancel()
    }

    @Test
    fun typingClearsFieldError() = runTest {
        val vm = model()
        vm.submit() // card tab, empty -> errors
        advanceUntilIdle()
        assertNotNull(vm.uiState.value.cardNumberError)
        vm.onCardNumberChange("4242424242424242")
        assertNull(vm.uiState.value.cardNumberError)
    }
}

/** Minimal fake recording add-card/add-bank calls; other reads are unused here. */
private class FakeAddRepo : BillingRepository {
    var addCardResult: ApiResult<List<PaymentMethod>> = ApiResult.Success(emptyList())
    var addBankResult: ApiResult<List<PaymentMethod>> = ApiResult.Success(emptyList())
    var addCardCalls = 0
    var addBankCalls = 0
    var lastCard: AddCardReqDto? = null
    var lastBank: AddBankReqDto? = null

    override suspend fun addCard(req: AddCardReqDto): ApiResult<List<PaymentMethod>> {
        addCardCalls++
        lastCard = req
        return addCardResult
    }

    override suspend fun addBank(req: AddBankReqDto): ApiResult<List<PaymentMethod>> {
        addBankCalls++
        lastBank = req
        return addBankResult
    }

    override suspend fun getPaymentMethods(): ApiResult<List<PaymentMethod>> = ApiResult.Success(emptyList())
    override suspend fun setDefaultPaymentMethod(id: String): ApiResult<List<PaymentMethod>> = ApiResult.Success(emptyList())
    override suspend fun removePaymentMethod(id: String): ApiResult<List<PaymentMethod>> = ApiResult.Success(emptyList())
    override suspend fun getConfig() = throw NotImplementedError()
    override suspend fun getSettings() = throw NotImplementedError()
    override suspend fun getBalance() = throw NotImplementedError()
    override suspend fun getSubscriptions(limit: Int) = throw NotImplementedError()
    override suspend fun getLedger(limit: Int) = throw NotImplementedError()
    override suspend fun getPayments(limit: Int) = throw NotImplementedError()
    override suspend fun getWallet() = throw NotImplementedError()
}
