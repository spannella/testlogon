package com.testlogon.android.feature.ads.campaigns

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.AdBillingEntry
import com.testlogon.android.core.model.ads.AdCampaign
import com.testlogon.android.core.model.ads.AdCampaignStatusDomain
import com.testlogon.android.core.model.ads.AdInvoice
import com.testlogon.android.core.model.ads.DepositResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.ads.campaigns.ui.AdsCampaignsUiState
import com.testlogon.android.feature.ads.campaigns.ui.AdsCampaignsViewModel
import com.testlogon.android.feature.adsbilling.data.AdsBillingRepository
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-369 - unit tests for [AdsCampaignsViewModel]. Uses MainDispatcherRule + runCurrent (NEVER
 * advanceUntilIdle). A fake repository returns canned outcomes + RECORDS the requested accountId BEFORE
 * returning. The VM's IO dispatcher seam is pointed at the rule's test dispatcher so the load coroutine
 * advances under runCurrent. Covers: init load by accountId -> Content, empty -> Empty, failure -> Error, and
 * a refresh failure keeping stale content.
 */
class AdsCampaignsViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    /** Recording fake repo: only getCampaigns is exercised; the rest are stubbed for the interface. */
    private class FakeCampaignsRepo : AdsBillingRepository {
        var campaignsOutcome: ApiResult<List<AdCampaign>> = ApiResult.Success(listOf(campaign("cmp_1")))
        var getCampaignsCalls = 0
        var lastAccountId: String? = null

        override suspend fun getCampaigns(accountId: String): ApiResult<List<AdCampaign>> {
            getCampaignsCalls++ // record BEFORE returning
            lastAccountId = accountId
            return campaignsOutcome
        }

        override suspend fun listAccounts(): ApiResult<List<AdAccountSummary>> =
            ApiResult.Success(emptyList())

        override suspend fun getAccount(accountId: String): ApiResult<AdAccountSummary> =
            ApiResult.Success(
                AdAccountSummary(accountId = accountId, balanceCents = 0L, lifetimeSpendCents = 0L),
            )

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
        ): ApiResult<DepositResult> = ApiResult.Success(DepositResult())
    }

    private fun vm(
        repo: AdsBillingRepository = FakeCampaignsRepo(),
        accountId: String = ACCOUNT_ID,
    ): AdsCampaignsViewModel = AdsCampaignsViewModel(
        repository = repo,
        savedState = SavedStateHandle(mapOf(AdsCampaignsViewModel.ARG_ACCOUNT_ID to accountId)),
    ).apply { ioDispatcher = mainDispatcher.dispatcher }

    @Test
    fun init_load_byAccountId_showsContent() = runTest {
        val repo = FakeCampaignsRepo()
        val viewModel = vm(repo = repo)
        runCurrent()

        assertEquals(ACCOUNT_ID, repo.lastAccountId)
        val state = viewModel.uiState.value
        assertTrue(state is AdsCampaignsUiState.Content)
        state as AdsCampaignsUiState.Content
        assertEquals(1, state.campaigns.size)
        assertEquals("cmp_1", state.campaigns[0].campaignId)
        assertFalse(state.isStale)
    }

    @Test
    fun init_emptyList_showsEmpty() = runTest {
        val repo = FakeCampaignsRepo().apply { campaignsOutcome = ApiResult.Success(emptyList()) }
        val viewModel = vm(repo = repo)
        runCurrent()

        assertTrue(viewModel.uiState.value is AdsCampaignsUiState.Empty)
    }

    @Test
    fun init_failure_showsError() = runTest {
        val repo = FakeCampaignsRepo().apply { campaignsOutcome = ApiResult.Failure(ApiError(500, "boom")) }
        val viewModel = vm(repo = repo)
        runCurrent()

        val state = viewModel.uiState.value
        assertTrue(state is AdsCampaignsUiState.Error)
        assertEquals(500, (state as AdsCampaignsUiState.Error).error.status)
    }

    @Test
    fun refreshFailure_withContent_keepsStale() = runTest {
        val repo = FakeCampaignsRepo()
        val viewModel = vm(repo = repo)
        runCurrent()
        assertTrue(viewModel.uiState.value is AdsCampaignsUiState.Content)

        repo.campaignsOutcome = ApiResult.Failure(ApiError(503, "unavailable"))
        viewModel.refresh()
        runCurrent()

        val state = viewModel.uiState.value
        assertTrue(state is AdsCampaignsUiState.Content)
        state as AdsCampaignsUiState.Content
        assertTrue(state.isStale)
        assertFalse(state.isRefreshing)
        assertEquals(1, state.campaigns.size) // prior content retained
    }

    private companion object {
        const val ACCOUNT_ID = "acc_1"

        fun campaign(id: String) = AdCampaign(
            campaignId = id,
            accountId = ACCOUNT_ID,
            name = "Spring Launch",
            status = "active",
            statusEnum = AdCampaignStatusDomain.ACTIVE,
            budgetCents = 500000L,
            dailyBudgetCents = 50000L,
            spentTodayCents = 12000L,
            lifetimeSpentCents = 340000L,
        )
    }
}
