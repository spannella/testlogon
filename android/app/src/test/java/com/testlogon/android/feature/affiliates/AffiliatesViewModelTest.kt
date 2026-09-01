package com.testlogon.android.feature.affiliates

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.affiliates.AffiliateDashboard
import com.testlogon.android.data.affiliates.AffiliateEarnings
import com.testlogon.android.data.affiliates.AffiliateLink
import com.testlogon.android.data.affiliates.AffiliateLinkCreateRequest
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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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
        var createResult: ApiResult<AffiliateLink> = ApiResult.Failure(ApiError(500, "x"))
        var deleteResult: ApiResult<String> = ApiResult.Failure(ApiError(500, "x"))
        var lastCreateRequest: AffiliateLinkCreateRequest? = null
        var lastDeletedId: String? = null

        override suspend fun loadDashboard(): ApiResult<AffiliateDashboard> = result
        override suspend fun createLink(request: AffiliateLinkCreateRequest): ApiResult<AffiliateLink> {
            lastCreateRequest = request
            return createResult
        }

        override suspend fun deleteLink(linkId: String): ApiResult<String> {
            lastDeletedId = linkId
            return deleteResult
        }

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

    @Test
    fun openCreate_thenDismiss_togglesForm() = runTest {
        val repo = FakeRepo().apply { result = ApiResult.Success(dashboard(listOf(link()))) }
        val vm = AffiliatesViewModel(repo)
        advanceUntilIdle()
        vm.onOpenCreate()
        assertNotNull(vm.uiState.value.createForm)
        vm.onDismissCreate()
        assertNull(vm.uiState.value.createForm)
    }

    @Test
    fun submitCreate_blankTargetId_setsInlineError_noNetworkCall() = runTest {
        val repo = FakeRepo().apply { result = ApiResult.Success(dashboard(listOf(link()))) }
        val vm = AffiliatesViewModel(repo)
        advanceUntilIdle()
        vm.onOpenCreate()
        vm.onSubmitCreate()
        advanceUntilIdle()
        assertNotNull(vm.uiState.value.createForm?.errorRes)
        assertNull(repo.lastCreateRequest)
    }

    @Test
    fun submitCreate_nonNumericCommission_setsInlineError() = runTest {
        val repo = FakeRepo().apply { result = ApiResult.Success(dashboard(listOf(link()))) }
        val vm = AffiliatesViewModel(repo)
        advanceUntilIdle()
        vm.onOpenCreate()
        vm.onCreateFormChanged(targetId = "cat_1", commissionPercent = "abc")
        vm.onSubmitCreate()
        advanceUntilIdle()
        assertNotNull(vm.uiState.value.createForm?.errorRes)
        assertNull(repo.lastCreateRequest)
    }

    @Test
    fun submitCreate_success_closesForm_andShowsContent() = runTest {
        val repo = FakeRepo().apply {
            result = ApiResult.Success(dashboard(listOf(link())))
            createResult = ApiResult.Success(link(id = "afl_new"))
            cacheValue = dashboard(listOf(link(), link(id = "afl_new")))
        }
        val vm = AffiliatesViewModel(repo)
        advanceUntilIdle()
        vm.onOpenCreate()
        vm.onCreateFormChanged(targetId = "cat_1", commissionPercent = "20")
        vm.onSubmitCreate()
        advanceUntilIdle()
        assertNull(vm.uiState.value.createForm)
        assertEquals(AffiliatesUiState.Phase.Content, vm.uiState.value.phase)
        assertEquals("cat_1", repo.lastCreateRequest?.targetId)
        assertEquals(20, repo.lastCreateRequest?.commissionPercent)
    }

    @Test
    fun submitCreate_failure_keepsFormWithError() = runTest {
        val repo = FakeRepo().apply {
            result = ApiResult.Success(dashboard(listOf(link())))
            createResult = ApiResult.Failure(ApiError(409, "exists"))
        }
        val vm = AffiliatesViewModel(repo)
        advanceUntilIdle()
        vm.onOpenCreate()
        vm.onCreateFormChanged(targetId = "cat_1")
        vm.onSubmitCreate()
        advanceUntilIdle()
        assertNotNull(vm.uiState.value.createForm)
        assertNotNull(vm.uiState.value.createForm?.errorRes)
    }

    @Test
    fun requestDelete_thenConfirm_success_removesAndReAggregates() = runTest {
        val repo = FakeRepo().apply {
            result = ApiResult.Success(dashboard(listOf(link(id = "afl_1"), link(id = "afl_2"))))
            deleteResult = ApiResult.Success("afl_1")
            cacheValue = dashboard(listOf(link(id = "afl_2")))
        }
        val vm = AffiliatesViewModel(repo)
        advanceUntilIdle()
        vm.onRequestDelete("afl_1")
        assertNotNull(vm.uiState.value.pendingDelete)
        vm.onConfirmDelete()
        advanceUntilIdle()
        assertNull(vm.uiState.value.pendingDelete)
        assertEquals("afl_1", repo.lastDeletedId)
        assertEquals(1, vm.uiState.value.dashboard?.links?.size)
    }

    @Test
    fun confirmDelete_lastLink_success_movesToEmpty() = runTest {
        val repo = FakeRepo().apply {
            result = ApiResult.Success(dashboard(listOf(link(id = "afl_1"))))
            deleteResult = ApiResult.Success("afl_1")
            cacheValue = dashboard(emptyList())
        }
        val vm = AffiliatesViewModel(repo)
        advanceUntilIdle()
        vm.onRequestDelete("afl_1")
        vm.onConfirmDelete()
        advanceUntilIdle()
        assertEquals(AffiliatesUiState.Phase.Empty, vm.uiState.value.phase)
    }

    @Test
    fun confirmDelete_failure_clearsPending_keepsLink() = runTest {
        val repo = FakeRepo().apply {
            result = ApiResult.Success(dashboard(listOf(link(id = "afl_1"))))
            deleteResult = ApiResult.Failure(ApiError(500, "boom"))
        }
        val vm = AffiliatesViewModel(repo)
        advanceUntilIdle()
        vm.onRequestDelete("afl_1")
        vm.onConfirmDelete()
        advanceUntilIdle()
        // pending resets deleting flag to false but stays open for retry
        assertNotNull(vm.uiState.value.pendingDelete)
        assertEquals(1, vm.uiState.value.dashboard?.links?.size)
    }
}
