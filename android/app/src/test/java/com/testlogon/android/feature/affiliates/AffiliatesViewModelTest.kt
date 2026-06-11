package com.testlogon.android.feature.affiliates

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.affiliates.AffiliateDashboard
import com.testlogon.android.data.affiliates.AffiliateEarnings
import com.testlogon.android.data.affiliates.AffiliateLink
import com.testlogon.android.data.affiliates.AffiliateMoney
import com.testlogon.android.data.affiliates.AffiliatesRepository
import com.testlogon.android.data.affiliates.LinkStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AffiliatesViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun link(id: String = "afl_1") = AffiliateLink(
        id = id, label = "L", shortUrl = "/r/abc", destinationUrl = "https://x", trackingCode = "abc",
        commissionPercent = 10.0, status = LinkStatus.ACTIVE, rawStatus = "active",
        clicks = 5, uniqueClicks = 4, conversions = 1,
        revenue = AffiliateMoney(2000, "USD"), commissionEarned = AffiliateMoney(1000, "USD"),
        conversionRatePct = 5.0, createdAtEpochSeconds = 1, updatedAtEpochSeconds = 2,
    )

    private fun dashboard(links: List<AffiliateLink>) = AffiliateDashboard(
        links = links,
        earnings = AffiliateEarnings(
            AffiliateMoney(links.sumOf { it.commissionEarned.cents }, "USD"),
            AffiliateMoney(links.sumOf { it.revenue.cents }, "USD"),
            links.sumOf { it.clicks }, links.sumOf { it.conversions }, links.size.toLong(),
        ),
    )

    private class FakeRepo : AffiliatesRepository {
        var result: ApiResult<AffiliateDashboard> = ApiResult.Failure(ApiError(500, "x"))
        var cacheValue: AffiliateDashboard? = null
        override suspend fun loadDashboard(): ApiResult<AffiliateDashboard> = result
        override fun cached(): AffiliateDashboard? = cacheValue
        override fun clear() {}
    }

    @Test
    fun load_success_movesToContent() = runTest {
        val repo = FakeRepo().apply { result = ApiResult.Success(dashboard(listOf(link()))) }
        val vm = AffiliatesViewModel(repo)
        advanceUntilIdle()
        assertEquals(AffiliatesUiState.Phase.Content, vm.uiState.value.phase)
    }

    @Test
    fun load_emptyLinks_movesToEmpty() = runTest {
        val repo = FakeRepo().apply { result = ApiResult.Success(dashboard(emptyList())) }
        val vm = AffiliatesViewModel(repo)
        advanceUntilIdle()
        assertEquals(AffiliatesUiState.Phase.Empty, vm.uiState.value.phase)
    }

    @Test
    fun load_failure_movesToError() = runTest {
        val repo = FakeRepo().apply { result = ApiResult.Failure(ApiError(500, "boom")) }
        val vm = AffiliatesViewModel(repo)
        advanceUntilIdle()
        assertEquals(AffiliatesUiState.Phase.Error, vm.uiState.value.phase)
    }

    @Test
    fun load_networkError_withCache_showsStale() = runTest {
        val repo = FakeRepo().apply {
            result = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
            cacheValue = dashboard(listOf(link()))
        }
        val vm = AffiliatesViewModel(repo)
        advanceUntilIdle()
        assertEquals(AffiliatesUiState.Phase.Content, vm.uiState.value.phase)
        assertTrue(vm.uiState.value.isStale)
    }

    @Test
    fun onCopyLink_emitsCopyUrl_withWebOriginPrefixedShortUrl() = runTest {
        val repo = FakeRepo().apply { result = ApiResult.Success(dashboard(listOf(link(id = "afl_9")))) }
        val vm = AffiliatesViewModel(repo)
        advanceUntilIdle()

        val effects = mutableListOf<AffiliatesEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }
        vm.onCopyLink("afl_9")
        advanceUntilIdle()
        job.cancel()

        val copy = effects.filterIsInstance<AffiliatesEffect.CopyUrl>().single()
        assertEquals("https://app.testlogon.com/r/abc", copy.url)
    }
}
