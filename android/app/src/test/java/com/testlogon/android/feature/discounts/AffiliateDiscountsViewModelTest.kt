package com.testlogon.android.feature.discounts

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.discounts.AffiliateDiscount
import com.testlogon.android.data.discounts.AffiliateDiscounts
import com.testlogon.android.data.discounts.AffiliateDiscountsRepository
import com.testlogon.android.data.discounts.DiscountKind
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

/**
 * AND-267/268/269 — state-transition coverage for [AffiliateDiscountsViewModel] (Content / Empty / Error /
 * Offline / stale, the one-shot copy/share effects, and the client-side kind filter). Mirrors the AND-265
 * affiliates VM test conventions: FakeRepo + MainDispatcherRule + a cancellable effect collector on an
 * UnconfinedTestDispatcher.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class AffiliateDiscountsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun sampleDiscount(
        creativeId: String = "cr_1",
        promoCode: String? = "SAVE10",
        affiliateCode: String? = "AFF",
        promoValueDisplay: String? = "10% off",
        clickThroughUrl: String? = "https://shop.test/sale",
    ) = AffiliateDiscount(
        creativeId = creativeId,
        campaignId = "cmp_1",
        ownerSub = "u",
        affiliateCode = affiliateCode,
        promoCode = promoCode,
        promoValueDisplay = promoValueDisplay,
        clickThroughUrl = clickThroughUrl,
        clickCount = 5,
        redemptionCount = 1,
        createdAtEpochSeconds = 0,
        updatedAtEpochSeconds = 0,
    )

    private fun discounts(items: List<AffiliateDiscount>) = AffiliateDiscounts(items)

    private class FakeRepo : AffiliateDiscountsRepository {
        var result: ApiResult<AffiliateDiscounts> = ApiResult.Failure(ApiError(500, "x"))
        var cacheValue: AffiliateDiscounts? = null
        override suspend fun loadDiscounts(): ApiResult<AffiliateDiscounts> = result
        override suspend fun loadDiscount(creativeId: String): ApiResult<AffiliateDiscount> =
            ApiResult.Failure(ApiError(404, "nope"))
        override fun cached(): AffiliateDiscounts? = cacheValue
        override fun clear() {}
    }

    @Test
    fun load_success_movesToContent() = runTest {
        val repo = FakeRepo().apply { result = ApiResult.Success(discounts(listOf(sampleDiscount()))) }
        val vm = AffiliateDiscountsViewModel(repo)
        advanceUntilIdle()
        assertEquals(AffiliateDiscountsUiState.Phase.Content, vm.uiState.value.phase)
        assertEquals(1, vm.uiState.value.discounts?.items?.size)
    }

    @Test
    fun load_empty_movesToEmpty() = runTest {
        val repo = FakeRepo().apply { result = ApiResult.Success(discounts(emptyList())) }
        val vm = AffiliateDiscountsViewModel(repo)
        advanceUntilIdle()
        assertEquals(AffiliateDiscountsUiState.Phase.Empty, vm.uiState.value.phase)
    }

    @Test
    fun load_failure_noCache_movesToError() = runTest {
        val repo = FakeRepo().apply { result = ApiResult.Failure(ApiError(500, "boom")) }
        val vm = AffiliateDiscountsViewModel(repo)
        advanceUntilIdle()
        assertEquals(AffiliateDiscountsUiState.Phase.Error, vm.uiState.value.phase)
    }

    @Test
    fun load_networkError_noCache_movesToOffline() = runTest {
        val repo = FakeRepo().apply {
            result = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
        }
        val vm = AffiliateDiscountsViewModel(repo)
        advanceUntilIdle()
        assertEquals(AffiliateDiscountsUiState.Phase.Offline, vm.uiState.value.phase)
    }

    @Test
    fun load_failure_withCache_showsStaleContent() = runTest {
        val repo = FakeRepo().apply {
            result = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
            cacheValue = discounts(listOf(sampleDiscount()))
        }
        val vm = AffiliateDiscountsViewModel(repo)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(AffiliateDiscountsUiState.Phase.Content, s.phase)
        assertTrue(s.isStale)
    }

    @Test
    fun onCopyCode_emitsCopyCode_withPromoCode() = runTest {
        val repo = FakeRepo().apply {
            result = ApiResult.Success(discounts(listOf(sampleDiscount(creativeId = "cr_9", promoCode = "SUMMER20"))))
        }
        val vm = AffiliateDiscountsViewModel(repo)
        advanceUntilIdle()

        val effects = mutableListOf<AffiliateDiscountsEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }
        vm.onCopyCode("cr_9")
        advanceUntilIdle()
        job.cancel()

        val copy = effects.filterIsInstance<AffiliateDiscountsEffect.CopyCode>().single()
        assertEquals("SUMMER20", copy.code)
    }

    @Test
    fun onShareLink_emitsShareLink_withClickThroughUrl() = runTest {
        val repo = FakeRepo().apply {
            result = ApiResult.Success(
                discounts(listOf(sampleDiscount(creativeId = "cr_9", clickThroughUrl = "https://x.test/p"))),
            )
        }
        val vm = AffiliateDiscountsViewModel(repo)
        advanceUntilIdle()

        val effects = mutableListOf<AffiliateDiscountsEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }
        vm.onShareLink("cr_9")
        advanceUntilIdle()
        job.cancel()

        val share = effects.filterIsInstance<AffiliateDiscountsEffect.ShareLink>().single()
        assertEquals("https://x.test/p", share.text)
    }

    @Test
    fun onShareLink_noUrl_fallsBackToCode() = runTest {
        val repo = FakeRepo().apply {
            result = ApiResult.Success(
                discounts(
                    listOf(
                        sampleDiscount(creativeId = "cr_9", clickThroughUrl = null, promoCode = "CODEONLY"),
                    ),
                ),
            )
        }
        val vm = AffiliateDiscountsViewModel(repo)
        advanceUntilIdle()

        val effects = mutableListOf<AffiliateDiscountsEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }
        vm.onShareLink("cr_9")
        advanceUntilIdle()
        job.cancel()

        assertEquals("CODEONLY", effects.filterIsInstance<AffiliateDiscountsEffect.ShareLink>().single().text)
    }

    @Test
    fun filter_appliesClientSide_overDerivedKind() = runTest {
        val percent = sampleDiscount(creativeId = "p", promoValueDisplay = "20% OFF")
        val trial = sampleDiscount(creativeId = "t", promoValueDisplay = "FREE TRIAL")
        val repo = FakeRepo().apply { result = ApiResult.Success(discounts(listOf(percent, trial))) }
        val vm = AffiliateDiscountsViewModel(repo)
        advanceUntilIdle()

        vm.onFilterSelected(DiscountKind.PERCENT)
        val visible = vm.uiState.value.visibleItems
        assertEquals(1, visible.size)
        assertEquals("p", visible.single().creativeId)

        vm.onFilterSelected(null)
        assertEquals(2, vm.uiState.value.visibleItems.size)
    }
}
