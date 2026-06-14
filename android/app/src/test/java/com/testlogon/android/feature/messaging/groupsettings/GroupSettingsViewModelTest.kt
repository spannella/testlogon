package com.testlogon.android.feature.messaging.groupsettings

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.group.FakeGroupRepository
import com.testlogon.android.data.messaging.group.GroupSettings
import com.testlogon.android.data.messaging.group.MembershipStatus
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class GroupSettingsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val groups = FakeGroupRepository()

    private fun settings(
        membership: MembershipStatus = MembershipStatus.ACTIVE,
        mutedUntil: Long = 0L,
    ) = GroupSettings(
        conversationId = "conv_1",
        title = "Eng",
        iconUrl = null,
        membership = membership,
        mutedUntilEpochSeconds = mutedUntil,
    )

    private fun vm(): GroupSettingsViewModel {
        val viewModel = GroupSettingsViewModel(
            groups, SavedStateHandle(mapOf("conversationId" to "conv_1")),
        )
        viewModel.clock = { 100L }
        return viewModel
    }

    @Test
    fun load_success_mapsContentActiveUnmuted() = runTest {
        groups.getSettingsResult = ApiResult.Success(settings(MembershipStatus.ACTIVE, mutedUntil = 0L))
        val viewModel = vm()
        viewModel.load()
        advanceUntilIdle()
        val s = viewModel.uiState.value
        assertEquals(GroupSettingsUiState.Phase.Content, s.phase)
        assertEquals(MembershipStatus.ACTIVE, s.membership)
        assertFalse(s.muted)
    }

    @Test
    fun load_404_mapsNotFound() = runTest {
        groups.getSettingsResult = ApiResult.Failure(ApiError(404, "gone"))
        val viewModel = vm()
        viewModel.load()
        advanceUntilIdle()
        assertEquals(GroupSettingsUiState.Phase.NotFound, viewModel.uiState.value.phase)
    }

    @Test
    fun load_5xx_mapsError() = runTest {
        groups.getSettingsResult = ApiResult.Failure(ApiError(500, "boom"))
        val viewModel = vm()
        viewModel.load()
        advanceUntilIdle()
        assertEquals(GroupSettingsUiState.Phase.Error, viewModel.uiState.value.phase)
    }

    @Test
    fun setMuted_optimistic_thenConfirmedOnSuccess() = runTest {
        groups.getSettingsResult = ApiResult.Success(settings(mutedUntil = 0L))
        groups.setMuteResult = ApiResult.Success(settings(mutedUntil = 9_999_999_999L))
        val viewModel = vm()
        viewModel.load(); advanceUntilIdle()

        viewModel.setMuted(true, MuteDuration.FOREVER)
        // Optimistic immediately (before advancing).
        assertTrue(viewModel.uiState.value.muted)
        advanceUntilIdle()
        assertTrue(viewModel.uiState.value.muted)
        val (cid, muted, until) = groups.setMuteCalls.single()
        assertEquals("conv_1", cid)
        assertTrue(muted)
        // FOREVER => null muted_until.
        assertEquals(null, until)
    }

    @Test
    fun setMuted_failure_revertsAndSetsError() = runTest {
        groups.getSettingsResult = ApiResult.Success(settings(mutedUntil = 0L))
        groups.setMuteResult = ApiResult.Failure(ApiError(500, "nope"))
        val viewModel = vm()
        viewModel.load(); advanceUntilIdle()

        viewModel.setMuted(true)
        assertTrue(viewModel.uiState.value.muted) // optimistic on
        advanceUntilIdle()
        assertFalse(viewModel.uiState.value.muted) // reverted
        assertEquals("nope", viewModel.uiState.value.errorMessage)
    }

    @Test
    fun leave_nonOptimistic_emitsLeftGroupOnSuccess() = runTest {
        groups.getSettingsResult = ApiResult.Success(settings())
        groups.leaveResult = ApiResult.Success(Unit)
        val viewModel = vm()
        viewModel.load(); advanceUntilIdle()

        val events = mutableListOf<GroupSettingsEvent>()
        val job = launch { viewModel.events.collect { events += it } }
        viewModel.leave()
        advanceUntilIdle()
        assertEquals(1, groups.leaveCalls)
        assertTrue(events.any { it is GroupSettingsEvent.LeftGroup })
        job.cancel()
    }

    @Test
    fun acceptInvite_transitionsInvitedToActive() = runTest {
        groups.getSettingsResult = ApiResult.Success(settings(MembershipStatus.INVITED))
        groups.acceptResult = ApiResult.Success(settings(MembershipStatus.ACTIVE))
        val viewModel = vm()
        viewModel.load(); advanceUntilIdle()
        assertEquals(MembershipStatus.INVITED, viewModel.uiState.value.membership)

        viewModel.acceptInvite()
        advanceUntilIdle()
        assertEquals(1, groups.acceptCalls)
        assertEquals(MembershipStatus.ACTIVE, viewModel.uiState.value.membership)
    }

    @Test
    fun actionInFlight_blocksConcurrentSubmit() = runTest {
        groups.getSettingsResult = ApiResult.Success(settings())
        // setMute never completes within this test window if we don't advance; but the guard is the
        // synchronous actionInFlight flag set before the suspend call. Use leave for a clean guard test.
        groups.leaveResult = ApiResult.Success(Unit)
        val viewModel = vm()
        viewModel.load(); advanceUntilIdle()

        viewModel.leave()
        viewModel.leave() // second call ignored while actionInFlight == LEAVE
        advanceUntilIdle()
        assertEquals(1, groups.leaveCalls)
    }
}
