package com.testlogon.android.feature.sponsorship

import androidx.lifecycle.SavedStateHandle
import com.squareup.moshi.Moshi
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.core.model.sponsorship.DealAction
import com.testlogon.android.core.model.sponsorship.SponsorshipDealEvent
import com.testlogon.android.core.model.sponsorship.ViewerRole
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.feature.sponsorship.testing.FakeSponsorshipRepo
import com.testlogon.android.feature.sponsorship.testing.FakeSponsorshipRepo.Companion.detail
import com.testlogon.android.feature.sponsorship.ui.CounterFieldError
import com.testlogon.android.feature.sponsorship.ui.SponsorshipDealEffect
import com.testlogon.android.feature.sponsorship.ui.SponsorshipDealUiState
import com.testlogon.android.feature.sponsorship.ui.SponsorshipDealViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-366 - tests for [SponsorshipDealViewModel]: load -> Content with the CLIENT-SIDE viewerRole +
 * availableActions; accept -> accepted + actions hide; reject(reason) -> rejected (reason forwarded);
 * counter(comp,note) -> negotiating + history re-read; an in-flight action disables all + the second call is
 * ignored (no double-submit); a 422 maps the per-field counter error (form stays open); a terminal status
 * yields no actions; a history-load failure is tolerated.
 *
 * runCurrent (NOT advanceUntilIdle) drains the init load(); effects are collected on backgroundScope.launch.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SponsorshipDealViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    /** Minimal AuthStateStore whose sub is settable at construction (synchronous). */
    private class SubAuthStore(sub: String?) : AuthStateStore {
        override val isAuthenticated: StateFlow<Boolean> = MutableStateFlow(sub != null)
        override val userSub: StateFlow<String?> = MutableStateFlow(sub)
        override suspend fun setAuthenticated(userSub: String) = Unit
        override suspend fun clear(reason: LogoutReason) = Unit
        override suspend fun lastLogoutReason(): LogoutReason? = null
        override suspend fun clearLogoutReason() = Unit
    }

    private val repo = FakeSponsorshipRepo()

    private fun vm(currentSub: String? = "adv_d1") = SponsorshipDealViewModel(
        repository = repo,
        errorParser = ApiErrorParser(Moshi.Builder().build()),
        savedState = SavedStateHandle(mapOf(SponsorshipDealViewModel.ARG_DEAL_ID to "d1")),
        authStateStore = SubAuthStore(currentSub),
    )

    @Test
    fun load_success_buildsContent_withRoleAndActions() = runTest {
        repo.dealResult = ApiResult.Success(detail("d1", "proposed"))
        repo.historyResult = ApiResult.Success(listOf(SponsorshipDealEvent(eventId = "e1", eventType = "proposed")))
        val vm = vm(currentSub = "adv_d1")
        runCurrent()

        val state = vm.uiState.value
        assertTrue(state is SponsorshipDealUiState.Content)
        state as SponsorshipDealUiState.Content
        assertEquals(ViewerRole.ADVERTISER, state.viewerRole)
        assertEquals(
            setOf(DealAction.ACCEPT, DealAction.REJECT, DealAction.NEGOTIATE),
            state.availableActions,
        )
        assertEquals(1, state.history.size)
        assertNull(state.actionInFlight)
    }

    @Test
    fun load_failure_isError() = runTest {
        repo.dealResult = FakeSponsorshipRepo.sponsorshipFailure(500)
        val vm = vm()
        runCurrent()
        val state = vm.uiState.value
        assertTrue(state is SponsorshipDealUiState.Error)
        assertEquals(500, (state as SponsorshipDealUiState.Error).error.status)
    }

    @Test
    fun load_historyFailure_tolerated_emptyHistory() = runTest {
        repo.dealResult = ApiResult.Success(detail("d1", "proposed"))
        repo.historyResult = FakeSponsorshipRepo.sponsorshipFailure(500)
        val vm = vm()
        runCurrent()
        val state = vm.uiState.value as SponsorshipDealUiState.Content
        assertTrue(state.history.isEmpty())
    }

    @Test
    fun terminalStatus_noActions() = runTest {
        repo.dealResult = ApiResult.Success(detail("d1", "completed"))
        val vm = vm()
        runCurrent()
        val state = vm.uiState.value as SponsorshipDealUiState.Content
        assertTrue(state.availableActions.isEmpty())
    }

    @Test
    fun accept_movesToAccepted_actionsHide() = runTest {
        repo.dealResult = ApiResult.Success(detail("d1", "proposed"))
        repo.acceptResult = ApiResult.Success(detail("d1", "accepted"))
        val vm = vm()
        runCurrent()

        vm.accept()
        runCurrent()

        val state = vm.uiState.value as SponsorshipDealUiState.Content
        assertEquals("accepted", state.deal.status)
        assertTrue(state.availableActions.isEmpty())
        assertNull(state.actionInFlight)
        assertEquals(1, repo.acceptCallCount)
    }

    @Test
    fun reject_forwardsReason_movesToRejected() = runTest {
        repo.dealResult = ApiResult.Success(detail("d1", "proposed"))
        repo.rejectResult = ApiResult.Success(detail("d1", "rejected"))
        val vm = vm()
        runCurrent()

        vm.reject("budget too low")
        runCurrent()

        assertEquals("budget too low", repo.lastRejectReason)
        val state = vm.uiState.value as SponsorshipDealUiState.Content
        assertEquals("rejected", state.deal.status)
        assertTrue(state.availableActions.isEmpty())
    }

    @Test
    fun counter_forwardsCompensationAndNote_movesToNegotiating_refreshesHistory() = runTest {
        repo.dealResult = ApiResult.Success(detail("d1", "proposed"))
        repo.counterResult = ApiResult.Success(detail("d1", "negotiating"))
        repo.historyResult = ApiResult.Success(listOf(SponsorshipDealEvent(eventId = "e9", eventType = "countered")))
        val vm = vm()
        runCurrent()

        vm.openCounterForm()
        vm.onCounterCompensationChanged("3000.00")
        vm.onCounterNoteChanged("please")
        vm.submitCounter()
        runCurrent()

        assertEquals(300000L, repo.lastCounterCompensation)
        assertEquals("please", repo.lastCounterNote)
        val state = vm.uiState.value as SponsorshipDealUiState.Content
        assertEquals("negotiating", state.deal.status)
        assertEquals(listOf("e9"), state.history.map { it.eventId })
        assertNull(state.counterForm)
    }

    @Test
    fun counter_belowMinimum_clientError_doesNotCallRepo() = runTest {
        repo.dealResult = ApiResult.Success(detail("d1", "proposed"))
        val vm = vm()
        runCurrent()

        vm.openCounterForm()
        vm.onCounterCompensationChanged("5.00") // 500 cents, below 1000 min
        vm.submitCounter()
        runCurrent()

        val state = vm.uiState.value as SponsorshipDealUiState.Content
        assertEquals(CounterFieldError.CLIENT_COMPENSATION_TOO_LOW, state.counterForm?.compensationError)
        assertEquals(0, repo.counterCallCount)
    }

    @Test
    fun counter_422_mapsFieldError_formStaysOpen() = runTest {
        repo.dealResult = ApiResult.Success(detail("d1", "proposed"))
        repo.counterResult = FakeSponsorshipRepo.sponsorship422("compensation_cents")
        val vm = vm()
        runCurrent()

        vm.openCounterForm()
        vm.onCounterCompensationChanged("3000.00")
        vm.submitCounter()
        runCurrent()

        val state = vm.uiState.value as SponsorshipDealUiState.Content
        assertEquals(CounterFieldError.SERVER, state.counterForm?.compensationError)
        assertNull(state.actionInFlight)
    }

    @Test
    fun inFlight_disablesAll_secondCallIgnored() = runTest {
        repo.dealResult = ApiResult.Success(detail("d1", "proposed"))
        // accept never completes within this test window (we suspend by not advancing past the launch).
        val vm = vm()
        runCurrent()

        // First accept sets in-flight (its repo call is queued on the dispatcher).
        vm.accept()
        // A second accept while in flight must be ignored (no second repo call).
        vm.accept()
        // A reject while accept is in flight must be ignored too.
        vm.reject("x")

        runCurrent()
        assertEquals(1, repo.acceptCallCount)
        assertEquals(0, repo.rejectCallCount)
    }

    @Test
    fun actionFailure_emitsRetryableEffect_clearsInFlight() = runTest {
        repo.dealResult = ApiResult.Success(detail("d1", "proposed"))
        repo.acceptResult = FakeSponsorshipRepo.sponsorshipFailure(409)
        val vm = vm()
        runCurrent()

        val effects = mutableListOf<SponsorshipDealEffect>()
        backgroundScope.launch { vm.effects.collect { effects += it } }

        vm.accept()
        runCurrent()

        assertTrue(effects.any { it is SponsorshipDealEffect.ActionFailed })
        val state = vm.uiState.value as SponsorshipDealUiState.Content
        assertNull(state.actionInFlight)
        // Still proposed -> actions remain available for a retry.
        assertTrue(state.availableActions.contains(DealAction.ACCEPT))
    }

    @Test
    fun observerRole_noActions() = runTest {
        repo.dealResult = ApiResult.Success(detail("d1", "proposed"))
        val vm = vm(currentSub = "stranger")
        runCurrent()
        val state = vm.uiState.value as SponsorshipDealUiState.Content
        assertEquals(ViewerRole.OBSERVER, state.viewerRole)
        assertTrue(state.availableActions.isEmpty())
    }
}
