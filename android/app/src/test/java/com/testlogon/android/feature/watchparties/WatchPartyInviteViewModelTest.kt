package com.testlogon.android.feature.watchparties

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.watchparties.InviteResolution
import com.testlogon.android.data.watchparties.WatchPartyStatus
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class WatchPartyInviteViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun resolution(partyId: String = "wp_resolved") = InviteResolution(
        partyId = partyId,
        title = "Party",
        videoTitle = "Video",
        status = WatchPartyStatus.WAITING,
        participantCount = 1,
        maxParticipants = 50,
    )

    private fun handle(code: String = "ABC123") =
        SavedStateHandle(mapOf(WatchPartyInviteViewModel.ARG_INVITE_CODE to code))

    @Test
    fun validCode_resolvesToPartyId() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            resolveResult = ApiResult.Success(resolution("wp_42"))
        }
        val vm = WatchPartyInviteViewModel(repo, handle("GOODCODE"))
        advanceUntilIdle()

        val state = vm.uiState.value
        assertTrue(state is WatchPartyInviteViewModel.InviteUiState.Resolved)
        assertEquals("wp_42", (state as WatchPartyInviteViewModel.InviteUiState.Resolved).partyId)
        assertEquals("GOODCODE", repo.lastResolveCode)
    }

    @Test
    fun invalidCode_failure_movesToFailed() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            resolveResult = ApiResult.Failure(ApiError(404, "not found"))
        }
        val vm = WatchPartyInviteViewModel(repo, handle("BADCODE"))
        advanceUntilIdle()

        assertEquals(WatchPartyInviteViewModel.InviteUiState.Failed, vm.uiState.value)
    }

    @Test
    fun networkError_movesToFailed() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            resolveResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
        }
        val vm = WatchPartyInviteViewModel(repo, handle())
        advanceUntilIdle()

        assertEquals(WatchPartyInviteViewModel.InviteUiState.Failed, vm.uiState.value)
    }

    @Test
    fun onRetry_afterFailure_canResolveOnSecondAttempt() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            resolveResult = ApiResult.Failure(ApiError(404, "not found"))
        }
        val vm = WatchPartyInviteViewModel(repo, handle())
        advanceUntilIdle()
        assertEquals(WatchPartyInviteViewModel.InviteUiState.Failed, vm.uiState.value)

        repo.resolveResult = ApiResult.Success(resolution("wp_retry"))
        vm.onRetry()
        advanceUntilIdle()

        val state = vm.uiState.value
        assertTrue(state is WatchPartyInviteViewModel.InviteUiState.Resolved)
        assertEquals("wp_retry", (state as WatchPartyInviteViewModel.InviteUiState.Resolved).partyId)
    }
}
