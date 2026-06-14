package com.testlogon.android.feature.messaging.groupdetails

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.group.FakeGroupRepository
import com.testlogon.android.data.messaging.group.GroupParticipant
import com.testlogon.android.data.messaging.group.GroupRole
import com.testlogon.android.data.messaging.group.GroupRoster
import com.testlogon.android.feature.messaging.FakeMessagingRepository
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class GroupDetailsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val groups = FakeGroupRepository()
    private val messaging = FakeMessagingRepository()

    private fun vm(): GroupDetailsViewModel {
        groups.refreshRosterResult = ApiResult.NetworkError(java.io.IOException(), false)
        return GroupDetailsViewModel(
            groups, messaging, SavedStateHandle(mapOf("conversationId" to "conv_1")),
        )
    }

    private fun participant(id: String, role: GroupRole) =
        GroupParticipant(id, id, null, role, 0)

    private fun roster(self: String, vararg p: GroupParticipant) = GroupRoster(
        conversationId = "conv_1",
        participants = p.toList(),
        currentUserRole = p.firstOrNull { it.userId == self }?.role ?: GroupRole.MEMBER,
        currentUserId = self,
    )

    /** Keep uiState hot so combine/stateIn emits. */
    private fun keepHot(viewModel: GroupDetailsViewModel) = viewModel.uiState.onEach { }

    @Test
    fun adminRoster_canManage_isTrue() = runTest {
        val viewModel = vm()
        val job = launch { keepHot(viewModel).launchIn(this) }
        groups.emitRoster(roster("me", participant("me", GroupRole.ADMIN), participant("u2", GroupRole.MEMBER)))
        advanceUntilIdle()
        val content = viewModel.uiState.value as RosterUiState.Content
        assertTrue(content.canManage)
        job.cancel()
    }

    @Test
    fun memberRoster_canManage_isFalse() = runTest {
        val viewModel = vm()
        val job = launch { keepHot(viewModel).launchIn(this) }
        groups.emitRoster(roster("me", participant("me", GroupRole.MEMBER), participant("u2", GroupRole.ADMIN)))
        advanceUntilIdle()
        val content = viewModel.uiState.value as RosterUiState.Content
        assertFalse(content.canManage)
        job.cancel()
    }

    @Test
    fun onChangeRole_admin_callsRepo_andTracksPending() = runTest {
        groups.changeRoleResult = ApiResult.Success(Unit)
        val viewModel = vm()
        val job = launch { keepHot(viewModel).launchIn(this) }
        groups.emitRoster(roster("me", participant("me", GroupRole.ADMIN), participant("u2", GroupRole.MEMBER)))
        advanceUntilIdle()

        viewModel.onChangeRole("u2", GroupRole.ADMIN)
        advanceUntilIdle()
        assertEquals(Triple("conv_1", "u2", GroupRole.ADMIN), groups.changeRoleCalls.single())
        job.cancel()
    }

    @Test
    fun nonAdmin_cannotMutate_noRepoCall() = runTest {
        val viewModel = vm()
        val job = launch { keepHot(viewModel).launchIn(this) }
        groups.emitRoster(roster("me", participant("me", GroupRole.MEMBER), participant("u2", GroupRole.MEMBER)))
        advanceUntilIdle()

        viewModel.onRemove("u2")
        viewModel.onChangeRole("u2", GroupRole.ADMIN)
        advanceUntilIdle()
        assertTrue(groups.removeCalls.isEmpty())
        assertTrue(groups.changeRoleCalls.isEmpty())
        job.cancel()
    }

    @Test
    fun selfRemove_blocked() = runTest {
        val viewModel = vm()
        val job = launch { keepHot(viewModel).launchIn(this) }
        groups.emitRoster(roster("me", participant("me", GroupRole.ADMIN), participant("u2", GroupRole.MEMBER)))
        advanceUntilIdle()

        viewModel.onRemove("me") // self-remove guard
        advanceUntilIdle()
        assertTrue(groups.removeCalls.isEmpty())
        job.cancel()
    }

    @Test
    fun demotingAdmin_withTwoAdmins_isAllowed() = runTest {
        groups.changeRoleResult = ApiResult.Success(Unit)
        val viewModel = vm()
        val job = launch { keepHot(viewModel).launchIn(this) }
        groups.emitRoster(roster("me", participant("me", GroupRole.ADMIN), participant("u2", GroupRole.ADMIN)))
        advanceUntilIdle()

        viewModel.onChangeRole("u2", GroupRole.MEMBER) // 2 admins -> demote allowed
        advanceUntilIdle()
        assertEquals(Triple("conv_1", "u2", GroupRole.MEMBER), groups.changeRoleCalls.single())
        job.cancel()
    }

    @Test
    fun refresh_failure_withCachedRoster_staysContent() = runTest {
        groups.refreshRosterResult = ApiResult.Failure(ApiError(500, "boom"))
        val viewModel = vm()
        val job = launch { keepHot(viewModel).launchIn(this) }
        groups.emitRoster(roster("me", participant("me", GroupRole.ADMIN)))
        advanceUntilIdle()
        viewModel.refresh()
        advanceUntilIdle()
        assertTrue(viewModel.uiState.value is RosterUiState.Content) // cached roster retained
        job.cancel()
    }
}
