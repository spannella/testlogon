package com.testlogon.android.feature.groups

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.groups.GroupMember
import com.testlogon.android.core.model.groups.GroupRole
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.groups.testing.FakeGroupsAuthStore
import com.testlogon.android.feature.groups.testing.FakeGroupsRepo
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-355 - tests for [GroupMembersViewModel]: load splits active vs pending (status=="invited") and
 * derives the viewer role -> canManage gating (admin only); changeRole is optimistic with rollback;
 * removeMember is optimistic with rollback; invite is pessimistic and the invitee shows as a pending entry
 * (re-fetch); a 403 reverts + sets a no-permission notice. Uses runCurrent (NOT advanceUntilIdle).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class GroupMembersViewModelTest {

    @get:Rule
    val mainDispatcherRule = MainDispatcherRule()

    private fun member(id: String, role: GroupRole, status: String = "active") =
        GroupMember(userId = id, role = role, status = status)

    private fun vm(
        repo: FakeGroupsRepo,
        viewerId: String? = "usr_admin",
        groupId: String = "grp_1",
    ) = GroupMembersViewModel(
        repository = repo,
        authStateStore = FakeGroupsAuthStore(viewerId),
        savedState = SavedStateHandle(mapOf(GroupMembersViewModel.ARG_GROUP_ID to groupId)),
    )

    private fun managerRepo(): FakeGroupsRepo = FakeGroupsRepo(
        membersResult = ApiResult.Success(
            listOf(
                member("usr_admin", GroupRole.ADMIN),
                member("usr_mod", GroupRole.MODERATOR),
                member("usr_member", GroupRole.MEMBER),
                member("usr_pending", GroupRole.MEMBER, status = "invited"),
            ),
        ),
    )

    private fun content(vm: GroupMembersViewModel): GroupMembersUiState.Content =
        vm.uiState.value as GroupMembersUiState.Content

    @Test
    fun load_splitsActiveAndPending_andDerivesCanManage() = runTest {
        val vm = vm(managerRepo(), viewerId = "usr_admin")
        runCurrent()
        val state = content(vm)
        assertEquals(3, state.members.size)
        assertEquals(1, state.pending.size)
        assertEquals("usr_pending", state.pending.single().userId)
        assertEquals(GroupRole.ADMIN, state.viewerRole)
        assertTrue(state.canManage)
    }

    @Test
    fun load_nonManager_isReadOnly_canManageFalse() = runTest {
        val vm = vm(managerRepo(), viewerId = "usr_member")
        runCurrent()
        val state = content(vm)
        assertEquals(GroupRole.MEMBER, state.viewerRole)
        assertFalse(state.canManage)
    }

    @Test
    fun changeRole_optimistic_thenKeptOnSuccess() = runTest {
        val repo = managerRepo()
        val vm = vm(repo, viewerId = "usr_admin")
        runCurrent()

        vm.changeRole("usr_member", GroupRole.MODERATOR)
        // optimistic: the row reflects the new role immediately
        assertEquals(GroupRole.MODERATOR, content(vm).members.first { it.userId == "usr_member" }.role)
        assertEquals("usr_member", content(vm).mutatingUserId)

        runCurrent()
        assertEquals(GroupRole.MODERATOR, content(vm).members.first { it.userId == "usr_member" }.role)
        assertNull(content(vm).mutatingUserId)
        assertEquals(GroupRole.MODERATOR, repo.changeRoleArgs.single().third)
    }

    @Test
    fun changeRole_rollsBackOnFailure_withNotice() = runTest {
        val repo = managerRepo().apply { changeRoleResult = FakeGroupsRepo.failure() }
        val vm = vm(repo, viewerId = "usr_admin")
        runCurrent()

        vm.changeRole("usr_member", GroupRole.MODERATOR)
        runCurrent()
        // rolled back to MEMBER
        assertEquals(GroupRole.MEMBER, content(vm).members.first { it.userId == "usr_member" }.role)
        assertNull(content(vm).mutatingUserId)
        assertTrue(content(vm).notice != null)
    }

    @Test
    fun removeMember_optimistic_droppedOnSuccess() = runTest {
        val repo = managerRepo()
        val vm = vm(repo, viewerId = "usr_admin")
        runCurrent()

        vm.removeMember("usr_member")
        // optimistically gone
        assertTrue(content(vm).members.none { it.userId == "usr_member" })
        runCurrent()
        assertTrue(content(vm).members.none { it.userId == "usr_member" })
        assertEquals("grp_1" to "usr_member", repo.removeArgs.single())
    }

    @Test
    fun removeMember_rollsBackOnFailure() = runTest {
        val repo = managerRepo().apply { removeResult = FakeGroupsRepo.failure() }
        val vm = vm(repo, viewerId = "usr_admin")
        runCurrent()

        vm.removeMember("usr_member")
        runCurrent()
        // restored
        assertTrue(content(vm).members.any { it.userId == "usr_member" })
        assertNull(content(vm).mutatingUserId)
        assertTrue(content(vm).notice != null)
    }

    @Test
    fun invite_pessimistic_invitee_appearsAsPending_afterRefetch() = runTest {
        val repo = managerRepo().apply {
            // after invite the re-fetch returns the roster including a new invited (pending) entry
            membersAfterInvite = ApiResult.Success(
                listOf(
                    member("usr_admin", GroupRole.ADMIN),
                    member("usr_mod", GroupRole.MODERATOR),
                    member("usr_member", GroupRole.MEMBER),
                    member("usr_pending", GroupRole.MEMBER, status = "invited"),
                    member("usr_new", GroupRole.MEMBER, status = "invited"),
                ),
            )
        }
        val vm = vm(repo, viewerId = "usr_admin")
        runCurrent()
        val activeBefore = content(vm).members.size

        vm.invite("usr_new")
        runCurrent()

        // the invitee is a PENDING (invited) entry, NOT an active member
        assertTrue(content(vm).pending.any { it.userId == "usr_new" })
        assertEquals(activeBefore, content(vm).members.size)
        assertEquals("grp_1" to "usr_new", repo.inviteArgs.single())
    }

    @Test
    fun mutation_403_revertsAndSetsNoPermissionNotice() = runTest {
        val repo = managerRepo().apply {
            removeResult = FakeGroupsRepo.failure(status = 403, code = "role_required")
        }
        val vm = vm(repo, viewerId = "usr_admin")
        runCurrent()

        vm.removeMember("usr_member")
        runCurrent()
        // reverted + a non-fatal notice surfaced
        assertTrue(content(vm).members.any { it.userId == "usr_member" })
        assertTrue(content(vm).notice != null)
    }

    @Test
    fun changeRole_blockedForNonManager_noNetworkCall() = runTest {
        val repo = managerRepo()
        val vm = vm(repo, viewerId = "usr_member")
        runCurrent()

        vm.changeRole("usr_admin", GroupRole.MODERATOR)
        runCurrent()
        assertTrue(repo.changeRoleArgs.isEmpty())
    }

    @Test
    fun load_membersFailure_isError() = runTest {
        val repo = managerRepo().apply { membersResult = FakeGroupsRepo.failure(status = 500) }
        val vm = vm(repo, viewerId = "usr_admin")
        runCurrent()
        val state = vm.uiState.value
        assertTrue(state is GroupMembersUiState.Error)
        assertEquals(500, (state as GroupMembersUiState.Error).error.status)
    }
}
