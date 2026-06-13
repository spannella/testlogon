package com.testlogon.android.feature.sponsorship

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.sponsorship.testing.FakeSponsorshipRepo
import com.testlogon.android.feature.sponsorship.testing.FakeSponsorshipRepo.Companion.deal
import com.testlogon.android.feature.sponsorship.ui.SponsorshipFilter
import com.testlogon.android.feature.sponsorship.ui.SponsorshipInboxEffect
import com.testlogon.android.feature.sponsorship.ui.SponsorshipInboxUiState
import com.testlogon.android.feature.sponsorship.ui.SponsorshipInboxViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-365 - tests for [SponsorshipInboxViewModel]: a single GET sorts newest-first, an empty array -> Empty, a
 * failure -> Error, a refresh failure keeps the last-good list with isStale=true, setFilter windows the list
 * CLIENT-SIDE (Pending shows only proposed + negotiating), and a row tap emits OpenDeal(dealId).
 *
 * runCurrent (NOT advanceUntilIdle) drains the init load(); the effect channel is collected on
 * backgroundScope.launch so the test never blocks on it.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SponsorshipInboxViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeSponsorshipRepo()

    private fun vm() = SponsorshipInboxViewModel(repo)

    @Test
    fun load_success_sortsNewestFirst() = runTest {
        repo.dealsResult = ApiResult.Success(
            listOf(
                deal("old", "proposed", createdAt = 100L),
                deal("new", "accepted", createdAt = 300L),
                deal("mid", "completed", createdAt = 200L),
            ),
        )
        val vm = vm()
        runCurrent()

        val state = vm.uiState.value
        assertTrue(state is SponsorshipInboxUiState.Content)
        val ids = (state as SponsorshipInboxUiState.Content).deals.map { it.dealId }
        assertEquals(listOf("new", "mid", "old"), ids)
        assertFalse(state.isStale)
    }

    @Test
    fun load_emptyArray_isEmpty() = runTest {
        repo.dealsResult = ApiResult.Success(emptyList())
        val vm = vm()
        runCurrent()
        assertEquals(SponsorshipInboxUiState.Empty, vm.uiState.value)
    }

    @Test
    fun load_failure_isError() = runTest {
        repo.dealsResult = FakeSponsorshipRepo.sponsorshipFailure(500)
        val vm = vm()
        runCurrent()
        val state = vm.uiState.value
        assertTrue(state is SponsorshipInboxUiState.Error)
        assertEquals(500, (state as SponsorshipInboxUiState.Error).error.status)
    }

    @Test
    fun refreshFailure_keepsLastGood_andFlagsStale() = runTest {
        repo.dealsResult = ApiResult.Success(listOf(deal("d1", "proposed", createdAt = 100L)))
        val vm = vm()
        runCurrent()
        assertTrue(vm.uiState.value is SponsorshipInboxUiState.Content)

        repo.dealsResult = FakeSponsorshipRepo.sponsorshipFailure(503)
        vm.refresh()
        runCurrent()

        val state = vm.uiState.value
        assertTrue(state is SponsorshipInboxUiState.Content)
        state as SponsorshipInboxUiState.Content
        assertEquals(listOf("d1"), state.deals.map { it.dealId })
        assertTrue(state.isStale)
    }

    @Test
    fun setFilter_windowsClientSide_pendingShowsOnlyProposedAndNegotiating() = runTest {
        repo.dealsResult = ApiResult.Success(
            listOf(
                deal("p1", "proposed", createdAt = 500L),
                deal("n1", "negotiating", createdAt = 400L),
                deal("a1", "accepted", createdAt = 300L),
                deal("c1", "completed", createdAt = 200L),
                deal("x1", "cancelled", createdAt = 100L),
            ),
        )
        val vm = vm()
        runCurrent()

        vm.setFilter(SponsorshipFilter.PENDING)
        runCurrent()

        val state = vm.uiState.value as SponsorshipInboxUiState.Content
        assertEquals(SponsorshipFilter.PENDING, state.filter)
        assertEquals(listOf("p1", "n1"), state.deals.map { it.dealId })
    }

    @Test
    fun setFilter_active_showsAcceptedAndContentSubmitted() = runTest {
        repo.dealsResult = ApiResult.Success(
            listOf(
                deal("a1", "accepted", createdAt = 300L),
                deal("s1", "content_submitted", createdAt = 200L),
                deal("p1", "proposed", createdAt = 100L),
            ),
        )
        val vm = vm()
        runCurrent()

        vm.setFilter(SponsorshipFilter.ACTIVE)
        runCurrent()

        val state = vm.uiState.value as SponsorshipInboxUiState.Content
        assertEquals(listOf("a1", "s1"), state.deals.map { it.dealId })
    }

    @Test
    fun onDealClick_emitsOpenDealEffect() = runTest {
        repo.dealsResult = ApiResult.Success(listOf(deal("d1", "proposed", createdAt = 100L)))
        val vm = vm()
        runCurrent()

        val received = mutableListOf<SponsorshipInboxEffect>()
        backgroundScope.launch { vm.effects.collect { received += it } }

        vm.onDealClick("d1")
        runCurrent()

        assertEquals(listOf(SponsorshipInboxEffect.OpenDeal("d1")), received)
    }
}
