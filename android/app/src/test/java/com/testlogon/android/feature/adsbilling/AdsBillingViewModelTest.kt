package com.testlogon.android.feature.adsbilling

import androidx.lifecycle.SavedStateHandle
import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.AdBillingEntry
import com.testlogon.android.core.model.ads.AdInvoice
import com.testlogon.android.core.model.ads.DepositResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.billing.AddBankReqDto
import com.testlogon.android.data.billing.AddCardReqDto
import com.testlogon.android.data.billing.BillingBalance
import com.testlogon.android.data.billing.BillingConfig
import com.testlogon.android.data.billing.BillingMoney
import com.testlogon.android.data.billing.BillingRepository
import com.testlogon.android.data.billing.BillingSettings
import com.testlogon.android.data.billing.LedgerPage
import com.testlogon.android.data.billing.PaymentMethod
import com.testlogon.android.data.billing.Subscription
import com.testlogon.android.data.billing.WalletBalance
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.adsbilling.data.AdsBillingRepository
import com.testlogon.android.data.custody.CustodyBalances
import com.testlogon.android.data.custody.CustodyReader
import com.testlogon.android.data.fees.CheckoutPayResult
import com.testlogon.android.data.fees.FeeQuote
import com.testlogon.android.data.fees.FeesRepository
import com.testlogon.android.feature.adsbilling.ui.AdsBillingUiState
import com.testlogon.android.feature.adsbilling.ui.AdsBillingViewModel
import com.testlogon.android.feature.adsbilling.ui.DepositState
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-367 - unit tests for [AdsBillingViewModel]. Uses MainDispatcherRule + runCurrent (NEVER
 * advanceUntilIdle). A fake repository returns canned outcomes + records calls. Covers: load -> Content
 * (tolerating an invoice failure -> null), amount validation gating the confirm, deposit success (balance
 * updated from new_balance_cents + ledger refreshed), the in-flight double-submit guard, a 400 -> a separate
 * DepositState.Error leaving the read state intact, and a refresh failure keeping stale content.
 */
class AdsBillingViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    /** Fake repository: canned outcomes + recorded deposit args + a gate to hold deposit in flight. */
    private class FakeBillingRepo : AdsBillingRepository {
        var accountOutcome: ApiResult<AdAccountSummary> = ApiResult.Success(summary(BALANCE))
        var ledgerOutcomes: ArrayDeque<ApiResult<List<AdBillingEntry>>> = ArrayDeque()
        var invoiceOutcome: ApiResult<AdInvoice> = ApiResult.Success(invoice())
        var depositOutcome: ApiResult<DepositResult> = ApiResult.Success(DepositResult(newBalanceCents = NEW_BALANCE))

        /** When non-null, deposit awaits this gate before returning (to assert the in-flight guard). */
        var depositGate: CompletableDeferred<Unit>? = null

        var depositCount = 0
        var lastDepositCents: Long? = null
        var ledgerCalls = 0

        override suspend fun getAccount(accountId: String) = accountOutcome

        // AND-369 - accounts-list / campaigns reads are unused by the billing VM; stubbed so the fake
        // satisfies the extended repository interface.
        override suspend fun listAccounts(): ApiResult<List<AdAccountSummary>> =
            ApiResult.Success(emptyList())

        override suspend fun getCampaigns(
            accountId: String,
        ): ApiResult<List<com.testlogon.android.core.model.ads.AdCampaign>> =
            ApiResult.Success(emptyList())

        override suspend fun getBillingHistory(accountId: String, limit: Int): ApiResult<List<AdBillingEntry>> {
            ledgerCalls++
            return if (ledgerOutcomes.isNotEmpty()) ledgerOutcomes.removeFirst() else defaultLedger
        }

        // ADV3-4 (B2): interface additions - not exercised by this test, stubbed.
        override suspend fun getCampaign(accountId: String, campaignId: String) =
            error("getCampaign not used in this test")
        override suspend fun updateCampaign(
            accountId: String,
            campaignId: String,
            status: String?,
            budgetCents: Long?,
            bidCpmCents: Int?,
            bidCpcCents: Int?,
            bidCpaCents: Int?,
        ) = error("updateCampaign not used in this test")
        override suspend fun getInvoice(accountId: String, month: String) = invoiceOutcome

        var lastDepositPayWith: String? = null

        override suspend fun deposit(
            accountId: String,
            amountCents: Long,
            paymentMethodId: String?,
            payWith: String?,
            quoteToken: String?,
        ): ApiResult<DepositResult> {
            depositCount++
            lastDepositCents = amountCents
            lastDepositPayWith = payWith
            depositGate?.await()
            return depositOutcome
        }
    }

    /** FE-160 - fees fake: quote/pay outcomes for the crypto-funding path. */
    private class FakeFeesRepo(
        var quoteOutcome: ApiResult<FeeQuote?> = ApiResult.Success(null),
    ) : FeesRepository {
        override suspend fun quoteFee(amountCents: Long, payWith: String): ApiResult<FeeQuote?> = quoteOutcome
        override suspend fun payCheckoutOrder(orderId: String, quote: FeeQuote): ApiResult<CheckoutPayResult> =
            ApiResult.Success(CheckoutPayResult(status = null, orderId = orderId, txnId = null, coinNativeDebited = null))
    }

    /** FE-160 - custody fake: canned balances for the asset picker. */
    private class FakeCustodyReader(
        var balances: ApiResult<CustodyBalances> =
            ApiResult.Success(CustodyBalances(vault = "v", tier = "t", rows = emptyList())),
    ) : CustodyReader {
        override suspend fun getBalance(): ApiResult<CustodyBalances> = balances
        override suspend fun getStaking(): ApiResult<com.testlogon.android.data.custody.StakingDashboard> =
            ApiResult.Failure(ApiError(status = 404, message = "n/a"))
    }

    /** ADV-306 - minimal general-billing fake backing the deposit card picker ([pms] = saved cards). */
    private class FakeGeneralBilling(private val pms: List<PaymentMethod> = emptyList()) : BillingRepository {
        override suspend fun getPaymentMethods(): ApiResult<List<PaymentMethod>> = ApiResult.Success(pms)
        override suspend fun setDefaultPaymentMethod(id: String): ApiResult<List<PaymentMethod>> = ApiResult.Success(pms)
        override suspend fun getTipDefaultPaymentMethodId(): ApiResult<String?> = ApiResult.Success(null)
        override suspend fun setTipDefaultPaymentMethod(id: String): ApiResult<List<PaymentMethod>> = ApiResult.Success(pms)
        override suspend fun removePaymentMethod(id: String): ApiResult<List<PaymentMethod>> = ApiResult.Success(pms)
        override suspend fun addCard(req: AddCardReqDto): ApiResult<List<PaymentMethod>> = ApiResult.Success(pms)
        override suspend fun addBank(req: AddBankReqDto): ApiResult<List<PaymentMethod>> = ApiResult.Success(pms)
        override suspend fun getConfig(): ApiResult<BillingConfig> = ApiResult.Success(BillingConfig(null, "USD"))
        override suspend fun getSettings(): ApiResult<BillingSettings> = ApiResult.Success(BillingSettings(false, "USD", null, null))
        override suspend fun getBalance(): ApiResult<BillingBalance> = ApiResult.Success(
            BillingBalance(BillingMoney(0, "USD"), BillingMoney(0, "USD"), BillingMoney(0, "USD"), BillingMoney(0, "USD"), null, null, null),
        )
        override suspend fun getSubscriptions(limit: Int): ApiResult<List<Subscription>> = ApiResult.Success(emptyList())
        override suspend fun getLedger(limit: Int): ApiResult<LedgerPage> = ApiResult.Success(LedgerPage(emptyList()))
        override suspend fun getPayments(limit: Int): ApiResult<LedgerPage> = ApiResult.Success(LedgerPage(emptyList()))
        override suspend fun getWallet(): ApiResult<WalletBalance> = ApiResult.Success(WalletBalance(BillingMoney(0, "USD"), null))
    }

    private fun vm(
        repo: AdsBillingRepository = FakeBillingRepo(),
        billing: BillingRepository = FakeGeneralBilling(),
        fees: FeesRepository = FakeFeesRepo(),
        custody: CustodyReader = FakeCustodyReader(),
        accountId: String = ACCOUNT_ID,
    ): AdsBillingViewModel = AdsBillingViewModel(
        repository = repo,
        billingRepository = billing,
        feesRepository = fees,
        custodyReader = custody,
        errorParser = ApiErrorParser(Moshi.Builder().build()),
        savedState = SavedStateHandle(mapOf(AdsBillingViewModel.ARG_ACCOUNT_ID to accountId)),
    )

    // ---- load ----

    @Test
    fun load_success_showsContent() = runTest {
        val vm = vm()
        runCurrent()
        val state = vm.uiState.value
        assertTrue(state is AdsBillingUiState.Content)
        state as AdsBillingUiState.Content
        assertEquals(BALANCE, state.account.balanceCents)
        assertEquals(1, state.ledger.size)
        assertEquals("2026-06", state.invoice?.month)
        assertFalse(state.isStale)
    }

    @Test
    fun load_invoiceFailure_tolerated_invoiceNull() = runTest {
        val repo = FakeBillingRepo().apply { invoiceOutcome = ApiResult.Failure(ApiError(404, "no invoice")) }
        val vm = vm(repo = repo)
        runCurrent()
        val state = vm.uiState.value as AdsBillingUiState.Content
        assertNull(state.invoice)
        assertEquals(1, state.ledger.size)
    }

    @Test
    fun load_accountFailure_showsError() = runTest {
        val repo = FakeBillingRepo().apply { accountOutcome = ApiResult.Failure(ApiError(403, "forbidden")) }
        val vm = vm(repo = repo)
        runCurrent()
        assertTrue(vm.uiState.value is AdsBillingUiState.Error)
    }

    // ---- amount validation ----

    @Test
    fun canSubmitDeposit_falseForEmptyBelowMinAndAboveMax() = runTest {
        val vm = vm()
        runCurrent()
        // empty
        assertFalse(vm.canSubmitDeposit)
        // below $50 min
        vm.onAmountChanged("49.99")
        assertFalse(vm.canSubmitDeposit)
        // above $100k max
        vm.onAmountChanged("100000.01")
        assertFalse(vm.canSubmitDeposit)
        // in range
        vm.onAmountChanged("50.00")
        assertTrue(vm.canSubmitDeposit)
    }

    @Test
    fun deposit_ignoredWhenAmountInvalid() = runTest {
        val repo = FakeBillingRepo()
        val vm = vm(repo = repo)
        runCurrent()
        vm.onAmountChanged("10.00") // below min
        vm.deposit()
        runCurrent()
        assertEquals(0, repo.depositCount)
        assertTrue(vm.depositState.value is DepositState.Idle)
    }

    // ---- deposit success ----

    @Test
    fun deposit_success_updatesBalance_refreshesLedger_setsSuccess() = runTest {
        val repo = FakeBillingRepo().apply {
            // Initial load ledger, then the post-deposit refresh returns a longer ledger.
            ledgerOutcomes.addLast(ApiResult.Success(listOf(entry("charge", 2500L))))
            ledgerOutcomes.addLast(
                ApiResult.Success(listOf(entry("deposit", 5000000L), entry("charge", 2500L))),
            )
        }
        val vm = vm(repo = repo)
        runCurrent()
        vm.openDeposit()
        vm.onAmountChanged("50000.00") // $50k -> 5,000,000 cents (in range)
        vm.deposit()
        runCurrent()

        assertEquals(1, repo.depositCount)
        assertEquals(5_000_000L, repo.lastDepositCents)
        val deposit = vm.depositState.value
        assertTrue(deposit is DepositState.Success)
        assertEquals(NEW_BALANCE, (deposit as DepositState.Success).newBalanceCents)
        val content = vm.uiState.value as AdsBillingUiState.Content
        assertEquals(NEW_BALANCE, content.account.balanceCents) // balance updated from new_balance_cents
        assertEquals(2, content.ledger.size) // ledger refreshed
    }

    @Test
    fun deposit_inFlight_blocksDoubleSubmit() = runTest {
        val gate = CompletableDeferred<Unit>()
        val repo = FakeBillingRepo().apply { depositGate = gate }
        val vm = vm(repo = repo)
        runCurrent()
        vm.onAmountChanged("50.00")

        // The first deposit parks on the gate (still Submitting).
        vm.deposit()
        runCurrent()
        assertTrue(vm.depositState.value is DepositState.Submitting)

        // A second deposit while Submitting is ignored (no double-submit).
        vm.deposit()
        runCurrent()
        assertEquals(1, repo.depositCount)

        // Release the gate -> Success.
        gate.complete(Unit)
        runCurrent()
        assertTrue(vm.depositState.value is DepositState.Success)
    }

    // ---- deposit 400 ----

    @Test
    fun deposit_400Minimum_setsDepositError_readStateIntact() = runTest {
        val repo = FakeBillingRepo().apply {
            depositOutcome = ApiResult.Failure(
                ApiError(400, "Minimum deposit", raw = """{"detail":"Minimum deposit is 5000 cents"}"""),
            )
        }
        val vm = vm(repo = repo)
        runCurrent()
        val before = vm.uiState.value as AdsBillingUiState.Content
        vm.onAmountChanged("50.00")
        vm.deposit()
        runCurrent()

        assertTrue(vm.depositState.value is DepositState.Error)
        // The read state is untouched (still Content with the same balance).
        val after = vm.uiState.value as AdsBillingUiState.Content
        assertEquals(before.account.balanceCents, after.account.balanceCents)
    }

    // ---- refresh failure keeps stale ----

    @Test
    fun refreshFailure_withContent_keepsStale() = runTest {
        val repo = FakeBillingRepo()
        val vm = vm(repo = repo)
        runCurrent()
        assertTrue(vm.uiState.value is AdsBillingUiState.Content)

        // Now a retry where the account read fails -> keep prior content + mark stale.
        repo.accountOutcome = ApiResult.Failure(ApiError(500, "server error"))
        vm.onRetry()
        runCurrent()

        val state = vm.uiState.value
        assertTrue(state is AdsBillingUiState.Content)
        assertTrue((state as AdsBillingUiState.Content).isStale)
    }

    private companion object {
        const val ACCOUNT_ID = "acc_1"
        const val BALANCE = 150000L
        const val NEW_BALANCE = 200000L

        val defaultLedger: ApiResult<List<AdBillingEntry>> =
            ApiResult.Success(listOf(AdBillingEntry(entryType = "charge", amountCents = 2500L)))

        fun summary(balance: Long) = AdAccountSummary(
            accountId = ACCOUNT_ID,
            companyName = "Acme Ads",
            status = "active",
            balanceCents = balance,
            lifetimeSpendCents = 9_500_000_000L,
        )

        fun entry(type: String, cents: Long) = AdBillingEntry(entryType = type, amountCents = cents)

        fun invoice() = AdInvoice(
            month = "2026-06",
            totalChargesCents = 750000L,
            totalDepositsCents = 100000L,
            entryCount = 1,
            campaigns = emptyList(),
        )
    }
}
