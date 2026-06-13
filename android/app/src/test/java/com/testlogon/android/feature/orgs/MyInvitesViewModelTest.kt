package com.testlogon.android.feature.orgs

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.orgs.OrgInvite
import com.testlogon.android.core.model.orgs.OrgRole
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.orgs.testing.FakeOrgsRepo
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-354 - tests for [MyInvitesViewModel]: load -> Content (the caller's pending invites); accept is
 * OPTIMISTIC remove + rollback on failure (sending the row token); decline removes the row; Empty/Error.
 * runCurrent (NOT advanceUntilIdle).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class MyInvitesViewModelTest {

    @get:Rule
    val mainDispatcherRule = MainDispatcherRule()

    private fun invite(id: String, token: String? = "tok_$id") =
        OrgInvite(inviteId = id, email = "$id@x.com", role = OrgRole.MEMBER, token = token)

    private fun invitesRepo(vararg invites: OrgInvite): FakeOrgsRepo = FakeOrgsRepo(
        invitesResult = ApiResult.Success(invites.toList()),
    )

    private fun invitesVm(repo: FakeOrgsRepo) = MyInvitesViewModel(repository = repo)

    private fun invitesContent(vm: MyInvitesViewModel): MyInvitesUiState.Content =
        vm.uiState.value as MyInvitesUiState.Content

    @Test
    fun load_pendingInvites_isContent() = runTest {
        val vm = invitesVm(invitesRepo(invite("inv_1"), invite("inv_2")))
        runCurrent()
        assertEquals(2, invitesContent(vm).invites.size)
    }

    @Test
    fun load_noInvites_isEmpty() = runTest {
        val vm = invitesVm(invitesRepo())
        runCurrent()
        assertTrue(vm.uiState.value is MyInvitesUiState.Empty)
    }

    @Test
    fun load_failure_isError() = runTest {
        val repo = FakeOrgsRepo(invitesResult = FakeOrgsRepo.failure(status = 500))
        val vm = invitesVm(repo)
        runCurrent()
        val state = vm.uiState.value
        assertTrue(state is MyInvitesUiState.Error)
        assertEquals(500, (state as MyInvitesUiState.Error).error.status)
    }

    @Test
    fun accept_optimisticRemove_keptOnSuccess_sendsToken() = runTest {
        val repo = invitesRepo(invite("inv_1"), invite("inv_2"))
        val vm = invitesVm(repo)
        runCurrent()

        vm.accept("inv_1")
        // optimistic: the row is gone immediately and marked acting
        assertTrue(invitesContent(vm).invites.none { it.inviteId == "inv_1" })
        assertEquals("inv_1", invitesContent(vm).actingInviteId)

        runCurrent()
        assertTrue(invitesContent(vm).invites.none { it.inviteId == "inv_1" })
        assertNull(invitesContent(vm).actingInviteId)
        // the row's token was echoed back
        assertEquals("inv_1" to "tok_inv_1", repo.acceptArgs.single())
    }

    @Test
    fun accept_rollsBackOnFailure_withNotice() = runTest {
        val repo = invitesRepo(invite("inv_1"), invite("inv_2")).apply {
            acceptResult = FakeOrgsRepo.failure()
        }
        val vm = invitesVm(repo)
        runCurrent()

        vm.accept("inv_1")
        assertTrue(invitesContent(vm).invites.none { it.inviteId == "inv_1" })

        runCurrent()
        // rolled back: the row is restored and a notice surfaced
        assertTrue(invitesContent(vm).invites.any { it.inviteId == "inv_1" })
        assertNull(invitesContent(vm).actingInviteId)
        assertTrue(invitesContent(vm).notice != null)
    }

    @Test
    fun decline_removesRowOnSuccess() = runTest {
        val repo = invitesRepo(invite("inv_1"), invite("inv_2"))
        val vm = invitesVm(repo)
        runCurrent()

        vm.decline("inv_2")
        runCurrent()
        assertTrue(invitesContent(vm).invites.none { it.inviteId == "inv_2" })
        assertEquals("inv_2", repo.declineArgs.single())
    }

    @Test
    fun acceptMissingToken_sendsEmptyToken() = runTest {
        val repo = invitesRepo(invite("inv_1", token = null))
        val vm = invitesVm(repo)
        runCurrent()

        vm.accept("inv_1")
        runCurrent()
        // a row with no token accepts with an EMPTY token (server stays authoritative)
        assertEquals("inv_1" to "", repo.acceptArgs.single())
    }

    @Test
    fun decline_lastInvite_isEmpty() = runTest {
        val repo = invitesRepo(invite("inv_1"))
        val vm = invitesVm(repo)
        runCurrent()

        vm.decline("inv_1")
        runCurrent()
        assertTrue(vm.uiState.value is MyInvitesUiState.Empty)
    }
}
