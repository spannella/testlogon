package com.testlogon.android.feature.ads.accounts

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.AdBillingEntry
import com.testlogon.android.core.model.ads.AdCampaign
import com.testlogon.android.core.model.ads.AdInvoice
import com.testlogon.android.core.model.ads.DepositResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.ads.accounts.ui.AdsAccountsUiState
import com.testlogon.android.feature.ads.accounts.ui.AdsAccountsViewModel
import com.testlogon.android.feature.adsbilling.data.AdsBillingRepository
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-369 - unit tests for [AdsAccountsViewModel]. Uses MainDispatcherRule + runCurrent (NEVER
 * advanceUntilIdle). A fake repository returns canned outcomes + RECORDS the call count BEFORE returning (so
 * the no-extra-call assertion on onAccountSelected is reliable). The VM's IO dispatcher seam is pointed at the
 * rule's test dispatcher so the load coroutine advances under runCurrent. Covers: init load -> Content, empty
 * -> Empty, failure -> Error, refresh keeps content + isRefreshing then clears, a refresh failure keeping
 * stale content, and onAccountSelected recording the id without a new network call.
 */
class AdsAccountsViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    /** Recording fake repo: only listAccounts is exercised; the rest are stubbed for the interface. */
    private class FakeAccountsRepo : AdsBillingRepository {
        var accountsOutcome: ApiResult<List<AdAccountSummary>> = ApiResult.Success(listOf(account("acc_1")))
        var listAccountsCalls = 0

        override suspend fun listAccounts(): ApiResult<List<AdAccountSummary>> {
            listAccountsCalls++ // record BEFORE returning
            return accountsOutcome
        }

        override suspend fun getCampaigns(accountId: String): ApiResult<List<AdCampaign>> =
            ApiResult.Success(emptyList())

        override suspend fun getAccount(accountId: String): ApiResult<AdAccountSummary> =
            ApiResult.Success(account(accountId))

        override suspend fun getBillingHistory(
            accountId: String,
            limit: Int,
        ): ApiResult<List<AdBillingEntry>> = ApiResult.Success(emptyList())

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
        override suspend fun getInvoice(accountId: String, month: String): ApiResult<AdInvoice> =
            ApiResult.Success(AdInvoice(totalChargesCents = 0L, totalDepositsCents = 0L))

        override suspend fun deposit(
            accountId: String,
            amountCents: Long,
            paymentMethodId: String?,
            payWith: String?,
            quoteToken: String?,
        ): ApiResult<DepositResult> = ApiResult.Success(DepositResult())
    }

    private fun vm(repo: AdsBillingRepository = FakeAccountsRepo()): AdsAccountsViewModel =
        AdsAccountsViewModel(repository = repo).apply { ioDispatcher = mainDispatcher.dispatcher }

    @Test
    fun init_load_showsContent() = runTest {
        val repo = FakeAccountsRepo()
        val viewModel = vm(repo = repo)
        runCurrent()

        val state = viewModel.uiState.value
        assertTrue(state is AdsAccountsUiState.Content)
        state as AdsAccountsUiState.Content
        assertEquals(1, state.accounts.size)
        assertEquals("acc_1", state.accounts[0].accountId)
        assertFalse(state.isStale)
        assertFalse(state.isRefreshing)
    }

    @Test
    fun init_emptyList_showsEmpty() = runTest {
        val repo = FakeAccountsRepo().apply { accountsOutcome = ApiResult.Success(emptyList()) }
        val viewModel = vm(repo = repo)
        runCurrent()

        assertTrue(viewModel.uiState.value is AdsAccountsUiState.Empty)
    }

    @Test
    fun init_failure_showsError() = runTest {
        val repo = FakeAccountsRepo().apply { accountsOutcome = ApiResult.Failure(ApiError(403, "forbidden")) }
        val viewModel = vm(repo = repo)
        runCurrent()

        val state = viewModel.uiState.value
        assertTrue(state is AdsAccountsUiState.Error)
        assertEquals(403, (state as AdsAccountsUiState.Error).error.status)
    }

    @Test
    fun refresh_keepsContent_setsRefreshing_thenClears() = runTest {
        val repo = FakeAccountsRepo()
        val viewModel = vm(repo = repo)
        runCurrent()
        assertTrue(viewModel.uiState.value is AdsAccountsUiState.Content)

        viewModel.refresh()
        // Before the coroutine runs, content is kept with the refreshing affordance.
        val refreshing = viewModel.uiState.value
        assertTrue(refreshing is AdsAccountsUiState.Content)
        assertTrue((refreshing as AdsAccountsUiState.Content).isRefreshing)

        runCurrent()
        val done = viewModel.uiState.value as AdsAccountsUiState.Content
        assertFalse(done.isRefreshing)
        assertFalse(done.isStale)
    }

    @Test
    fun refreshFailure_withContent_keepsStale() = runTest {
        val repo = FakeAccountsRepo()
        val viewModel = vm(repo = repo)
        runCurrent()
        assertTrue(viewModel.uiState.value is AdsAccountsUiState.Content)

        repo.accountsOutcome = ApiResult.Failure(ApiError(500, "server error"))
        viewModel.refresh()
        runCurrent()

        val state = viewModel.uiState.value
        assertTrue(state is AdsAccountsUiState.Content)
        state as AdsAccountsUiState.Content
        assertTrue(state.isStale)
        assertFalse(state.isRefreshing)
        assertEquals(1, state.accounts.size) // prior content retained
    }

    @Test
    fun onAccountSelected_recordsId_withoutNewNetworkCall() = runTest {
        val repo = FakeAccountsRepo()
        val viewModel = vm(repo = repo)
        runCurrent()
        val callsAfterLoad = repo.listAccountsCalls

        viewModel.onAccountSelected("acc_1")
        runCurrent()

        val state = viewModel.uiState.value as AdsAccountsUiState.Content
        assertEquals("acc_1", state.selectedAccountId)
        // Selection is local state only - no extra repository read.
        assertEquals(callsAfterLoad, repo.listAccountsCalls)
    }

    private companion object {
        fun account(id: String) = AdAccountSummary(
            accountId = id,
            companyName = "Acme Ads",
            status = "active",
            balanceCents = 150000L,
            lifetimeSpendCents = 9_500_000L,
        )
    }
}
