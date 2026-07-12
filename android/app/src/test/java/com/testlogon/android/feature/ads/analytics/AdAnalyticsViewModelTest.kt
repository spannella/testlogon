package com.testlogon.android.feature.ads.analytics

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.AdAnalyticsSummary
import com.testlogon.android.core.model.ads.AdBillingEntry
import com.testlogon.android.core.model.ads.AdBreakdownEntry
import com.testlogon.android.core.model.ads.AdCampaign
import com.testlogon.android.core.model.ads.AdInvoice
import com.testlogon.android.core.model.ads.AdTimeSeriesPoint
import com.testlogon.android.core.model.ads.BreakdownDimension
import com.testlogon.android.core.model.ads.DateRange
import com.testlogon.android.core.model.ads.DateRangePreset
import com.testlogon.android.core.model.ads.DepositResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.ads.analytics.data.AdAnalyticsRepository
import com.testlogon.android.feature.ads.analytics.ui.AdAnalyticsUiState
import com.testlogon.android.feature.ads.analytics.ui.AdAnalyticsViewModel
import com.testlogon.android.feature.adsbilling.data.AdsBillingRepository
import com.testlogon.android.navigation.AdAnalyticsDest
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.LocalDate

/**
 * AND-368 - unit tests for [AdAnalyticsViewModel]. Uses MainDispatcherRule + runCurrent (NEVER
 * advanceUntilIdle). A fake repository returns canned outcomes + records the requested range. A fixed
 * `today` makes the from/to windows deterministic. Covers: default LAST_28 load -> Content, onRangeChanged
 * re-queries with the new window, no-data -> Empty, summary failure -> Error, a refresh failure keeping
 * stale content, and the sample-account-id resolution to the first real ad account.
 */
class AdAnalyticsViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private val today: LocalDate = LocalDate.of(2026, 6, 9)

    /** Fake repository: canned outcomes + the last range each method saw. */
    private class FakeAnalyticsRepo : AdAnalyticsRepository {
        var summaryOutcome: ApiResult<AdAnalyticsSummary> = ApiResult.Success(summaryWith(120000L))
        var timeseriesOutcome: ApiResult<List<AdTimeSeriesPoint>> =
            ApiResult.Success(listOf(point()))
        var breakdownOutcome: ApiResult<List<AdBreakdownEntry>> =
            ApiResult.Success(listOf(entry()))

        var lastSummaryRange: DateRange? = null
        var lastSummaryAccountId: String? = null
        var summaryCalls = 0

        override suspend fun getSummary(accountId: String, range: DateRange): ApiResult<AdAnalyticsSummary> {
            summaryCalls++
            lastSummaryRange = range
            lastSummaryAccountId = accountId
            return summaryOutcome
        }

        override suspend fun getTimeseries(
            accountId: String,
            range: DateRange,
        ): ApiResult<List<AdTimeSeriesPoint>> = timeseriesOutcome

        override suspend fun getBreakdown(
            accountId: String,
            dimension: BreakdownDimension,
            range: DateRange,
        ): ApiResult<List<AdBreakdownEntry>> = breakdownOutcome
    }

    /** Fake accounts repo: only [listAccounts] is exercised (sample-id resolution); the rest are unused. */
    private class FakeAccountsRepo(
        var accountsOutcome: ApiResult<List<AdAccountSummary>> =
            ApiResult.Success(listOf(account(ACCOUNT_ID))),
    ) : AdsBillingRepository {
        override suspend fun listAccounts(): ApiResult<List<AdAccountSummary>> = accountsOutcome

        override suspend fun getCampaigns(accountId: String): ApiResult<List<AdCampaign>> =
            throw NotImplementedError()

        override suspend fun getAccount(accountId: String): ApiResult<AdAccountSummary> =
            throw NotImplementedError()

        override suspend fun getBillingHistory(accountId: String, limit: Int): ApiResult<List<AdBillingEntry>> =
            throw NotImplementedError()

        override suspend fun getInvoice(accountId: String, month: String): ApiResult<AdInvoice> =
            throw NotImplementedError()

        override suspend fun deposit(
            accountId: String,
            amountCents: Long,
            paymentMethodId: String?,
        ): ApiResult<DepositResult> = throw NotImplementedError()
    }

    private fun vm(
        repo: AdAnalyticsRepository = FakeAnalyticsRepo(),
        accountsRepo: AdsBillingRepository = FakeAccountsRepo(),
        accountId: String = ACCOUNT_ID,
    ): AdAnalyticsViewModel = AdAnalyticsViewModel(
        repository = repo,
        accountsRepository = accountsRepo,
        savedState = SavedStateHandle(mapOf(AdAnalyticsViewModel.ARG_ACCOUNT_ID to accountId)),
    ).apply { today = this@AdAnalyticsViewModelTest.today }

    @Test
    fun load_defaultLast28_showsContent_withLast28Window() = runTest {
        val repo = FakeAnalyticsRepo()
        val viewModel = vm(repo = repo)
        runCurrent()

        val state = viewModel.uiState.value
        assertTrue(state is AdAnalyticsUiState.Content)
        state as AdAnalyticsUiState.Content
        assertEquals(DateRangePreset.LAST_28, state.range)
        assertEquals(120000L, state.summary.impressions)
        assertEquals(1, state.timeseries.size)
        assertEquals(1, state.breakdown.size)
        assertFalse(state.isStale)
        // Default window is the LAST_28 range ending on the fixed today.
        assertEquals(DateRange.of(DateRangePreset.LAST_28, today), repo.lastSummaryRange)
    }

    @Test
    fun onRangeChanged_reQueries_withNewWindow() = runTest {
        val repo = FakeAnalyticsRepo()
        val viewModel = vm(repo = repo)
        runCurrent()
        val callsAfterLoad = repo.summaryCalls

        viewModel.onRangeChanged(DateRangePreset.LAST_7)
        runCurrent()

        assertEquals(callsAfterLoad + 1, repo.summaryCalls)
        assertEquals(DateRange.of(DateRangePreset.LAST_7, today), repo.lastSummaryRange)
        val state = viewModel.uiState.value as AdAnalyticsUiState.Content
        assertEquals(DateRangePreset.LAST_7, state.range)
    }

    @Test
    fun onRangeChanged_sameRange_isNoOp() = runTest {
        val repo = FakeAnalyticsRepo()
        val viewModel = vm(repo = repo)
        runCurrent()
        val callsAfterLoad = repo.summaryCalls

        viewModel.onRangeChanged(DateRangePreset.LAST_28) // already selected
        runCurrent()

        assertEquals(callsAfterLoad, repo.summaryCalls)
    }

    @Test
    fun load_noData_showsEmpty() = runTest {
        val repo = FakeAnalyticsRepo().apply {
            summaryOutcome = ApiResult.Success(
                AdAnalyticsSummary(impressions = 0L, clicks = 0L, spendCents = 0L, ctrPct = 0.0),
            )
            timeseriesOutcome = ApiResult.Success(emptyList())
            breakdownOutcome = ApiResult.Success(emptyList())
        }
        val viewModel = vm(repo = repo)
        runCurrent()

        assertTrue(viewModel.uiState.value is AdAnalyticsUiState.Empty)
    }

    @Test
    fun load_summaryFailure_showsError() = runTest {
        val repo = FakeAnalyticsRepo().apply {
            summaryOutcome = ApiResult.Failure(ApiError(403, "forbidden"))
        }
        val viewModel = vm(repo = repo)
        runCurrent()

        assertTrue(viewModel.uiState.value is AdAnalyticsUiState.Error)
    }

    @Test
    fun refreshFailure_withContent_keepsStale() = runTest {
        val repo = FakeAnalyticsRepo()
        val viewModel = vm(repo = repo)
        runCurrent()
        assertTrue(viewModel.uiState.value is AdAnalyticsUiState.Content)

        repo.summaryOutcome = ApiResult.Failure(ApiError(500, "server error"))
        viewModel.refresh()
        runCurrent()

        val state = viewModel.uiState.value
        assertTrue(state is AdAnalyticsUiState.Content)
        state as AdAnalyticsUiState.Content
        assertTrue(state.isStale)
        assertFalse(state.isRefreshing)
    }

    @Test
    fun load_sampleAccountId_resolvesToFirstRealAccount() = runTest {
        val repo = FakeAnalyticsRepo()
        val accountsRepo = FakeAccountsRepo(
            accountsOutcome = ApiResult.Success(listOf(account("acc_real_1"), account("acc_real_2"))),
        )
        val viewModel = vm(
            repo = repo,
            accountsRepo = accountsRepo,
            accountId = AdAnalyticsDest.SAMPLE_ACCOUNT_ID,
        )
        runCurrent()

        // The stub sample id is replaced by the first real account before the analytics fetch.
        assertEquals("acc_real_1", viewModel.accountId)
        assertEquals("acc_real_1", repo.lastSummaryAccountId)
    }

    private companion object {
        const val ACCOUNT_ID = "acc_1"

        fun account(id: String) = AdAccountSummary(
            accountId = id,
            companyName = "Acme",
            status = "active",
            balanceCents = 100000L,
            lifetimeSpendCents = 500000L,
        )

        fun summaryWith(impressions: Long) = AdAnalyticsSummary(
            impressions = impressions,
            clicks = 3400L,
            spendCents = 250000L,
            ctrPct = 2.83,
        )

        fun point() = AdTimeSeriesPoint(
            date = "2026-06-08",
            impressions = 1000L,
            clicks = 30L,
            spendCents = 2500L,
        )

        fun entry() = AdBreakdownEntry(
            key = "cmp_1",
            campaignName = "Spring Launch",
            impressions = 80000L,
            clicks = 2400L,
            spendCents = 180000L,
            ctrPct = 3.0,
        )
    }
}
