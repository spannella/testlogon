package com.testlogon.android.feature.orgs

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.orgs.Org
import com.testlogon.android.core.model.orgs.OrgInvite
import com.testlogon.android.core.model.orgs.OrgMember
import com.testlogon.android.core.model.orgs.OrgRole
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.orgs.testing.FakeAuthStateStore
import com.testlogon.android.feature.orgs.testing.FakeOrgsRepo
import com.testlogon.android.feature.orgs.testing.FakeSelectedOrgStore
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
 * AND-353 - tests for [OrgMembersViewModel]: load derives callerRole + canManage (FR-6); non-managers
 * get a read-only roster; changeRole is optimistic with rollback on failure (FR-4); removeMember drops
 * the row (FR-5); self-protection blocks self-remove + sole-owner demote (FR-7); invite inserts into
 * pendingInvites NOT members. Uses runCurrent (NOT advanceUntilIdle) over a StandardTestDispatcher.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class OrgMembersViewModelTest {

    @get:Rule
    val mainDispatcherRule = MainDispatcherRule()

    private val org = Org(orgId = "org_1", name = "Acme", callerRole = OrgRole.ADMIN)

    private fun member(sub: String, role: OrgRole, status: String = "active") =
        OrgMember(userSub = sub, role = role, status = status)

    private fun vm(
        repo: FakeOrgsRepo,
        callerSub: String? = "usr_admin",
        selected: String? = "org_1",
    ) = OrgMembersViewModel(
        repository = repo,
        selectedOrgStore = FakeSelectedOrgStore(selected),
        authStateStore = FakeAuthStateStore(callerSub),
    )

    private fun managerRepo(): FakeOrgsRepo = FakeOrgsRepo(
        orgsResult = ApiResult.Success(listOf(org)),
        membersResult = ApiResult.Success(
            listOf(
                member("usr_admin", OrgRole.ADMIN),
                member("usr_member", OrgRole.MEMBER),
                member("usr_owner", OrgRole.OWNER),
            ),
        ),
        invitesResult = ApiResult.Success(emptyList()),
    )

    private fun content(vm: OrgMembersViewModel): OrgMembersUiState.Content =
        vm.uiState.value as OrgMembersUiState.Content

    @Test
    fun load_derivesCallerRole_andCanManage_forManager() = runTest {
        val vm = vm(managerRepo(), callerSub = "usr_admin")
        runCurrent()
        val state = content(vm)
        assertEquals(OrgRole.ADMIN, state.callerRole)
        assertTrue(state.canManage)
        assertEquals(3, state.members.size)
    }

    @Test
    fun load_nonManager_isReadOnly_canManageFalse() = runTest {
        val vm = vm(managerRepo(), callerSub = "usr_member")
        runCurrent()
        val state = content(vm)
        assertEquals(OrgRole.MEMBER, state.callerRole)
        assertFalse(state.canManage)
    }

    @Test
    fun changeRole_optimistic_thenKeptOnSuccess() = runTest {
        val repo = managerRepo()
        val vm = vm(repo, callerSub = "usr_admin")
        runCurrent()

        vm.changeRole("usr_member", OrgRole.ADMIN)
        // optimistic: the row reflects the new role immediately (before the network completes)
        assertEquals(OrgRole.ADMIN, content(vm).members.first { it.userSub == "usr_member" }.role)
        assertEquals("usr_member", content(vm).mutatingMemberSub)

        runCurrent()
        assertEquals(OrgRole.ADMIN, content(vm).members.first { it.userSub == "usr_member" }.role)
        assertNull(content(vm).mutatingMemberSub)
        assertEquals(OrgRole.ADMIN, repo.changeRoleArgs.single().third)
    }

    @Test
    fun changeRole_rollsBackOnFailure() = runTest {
        val repo = managerRepo().apply { changeRoleResult = FakeOrgsRepo.failure() }
        val vm = vm(repo, callerSub = "usr_admin")
        runCurrent()

        vm.changeRole("usr_member", OrgRole.ADMIN)
        assertEquals(OrgRole.ADMIN, content(vm).members.first { it.userSub == "usr_member" }.role)

        runCurrent()
        // rolled back to MEMBER
        assertEquals(OrgRole.MEMBER, content(vm).members.first { it.userSub == "usr_member" }.role)
        assertNull(content(vm).mutatingMemberSub)
    }

    @Test
    fun removeMember_dropsRowOnSuccess() = runTest {
        val repo = managerRepo()
        val vm = vm(repo, callerSub = "usr_admin")
        runCurrent()

        vm.removeMember("usr_member")
        runCurrent()
        assertTrue(content(vm).members.none { it.userSub == "usr_member" })
        assertEquals("org_1" to "usr_member", repo.removeArgs.single())
    }

    @Test
    fun selfProtection_blocksRemovingSelf_noNetworkCall() = runTest {
        val repo = managerRepo()
        val vm = vm(repo, callerSub = "usr_admin")
        runCurrent()

        vm.removeMember("usr_admin")
        runCurrent()
        // self still present; no network call recorded
        assertTrue(content(vm).members.any { it.userSub == "usr_admin" })
        assertTrue(repo.removeArgs.isEmpty())
        assertTrue(content(vm).notice != null)
    }

    @Test
    fun selfProtection_blocksDemotingSoleOwner() = runTest {
        val repo = managerRepo()
        val vm = vm(repo, callerSub = "usr_admin")
        runCurrent()

        vm.changeRole("usr_owner", OrgRole.MEMBER)
        runCurrent()
        // owner unchanged; no role-change call recorded
        assertEquals(OrgRole.OWNER, content(vm).members.first { it.userSub == "usr_owner" }.role)
        assertTrue(repo.changeRoleArgs.isEmpty())
    }

    @Test
    fun invite_insertsIntoPendingInvites_notMembers() = runTest {
        val repo = managerRepo().apply {
            inviteResult = ApiResult.Success(
                OrgInvite(inviteId = "inv_1", email = "new@x.com", role = OrgRole.VIEWER),
            )
        }
        val vm = vm(repo, callerSub = "usr_admin")
        runCurrent()
        val membersBefore = content(vm).members.size

        vm.inviteMember("new@x.com", OrgRole.VIEWER)
        runCurrent()

        assertEquals(1, content(vm).pendingInvites.size)
        assertEquals("inv_1", content(vm).pendingInvites.single().inviteId)
        // the roster did NOT grow (an invite is a pending invite, not a member)
        assertEquals(membersBefore, content(vm).members.size)
        assertEquals(OrgRole.VIEWER, repo.inviteArgs.single().third)
    }

    @Test
    fun load_membersFailure_isError() = runTest {
        val repo = managerRepo().apply { membersResult = FakeOrgsRepo.failure(status = 500) }
        val vm = vm(repo, callerSub = "usr_admin")
        runCurrent()
        val state = vm.uiState.value
        assertTrue(state is OrgMembersUiState.Error)
        assertEquals(500, (state as OrgMembersUiState.Error).error.status)
    }
}
