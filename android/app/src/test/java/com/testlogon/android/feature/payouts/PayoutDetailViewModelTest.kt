package com.testlogon.android.feature.payouts

import androidx.lifecycle.SavedStateHandle
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-260 — [PayoutDetailViewModel] hydrates from [PayoutCache] by id with ZERO network calls; a cache
 * miss (cold deep-link) resolves to NotFound.
 */
class PayoutDetailViewModelTest {

    @Test
    fun cacheHit_rendersContent() {
        val cache = PayoutCache().apply { put(listOf(samplePayout("po_x"))) }
        val vm = PayoutDetailViewModel(cache, SavedStateHandle(mapOf(PayoutDetailViewModel.ARG_PAYOUT_ID to "po_x")))
        val state = vm.uiState.value
        assertTrue(state is PayoutDetailUiState.Content)
        assertEquals("po_x", (state as PayoutDetailUiState.Content).payout.payoutId)
    }

    @Test
    fun cacheMiss_rendersNotFound() {
        val cache = PayoutCache()
        val vm = PayoutDetailViewModel(cache, SavedStateHandle(mapOf(PayoutDetailViewModel.ARG_PAYOUT_ID to "absent")))
        assertEquals(PayoutDetailUiState.NotFound, vm.uiState.value)
    }
}
