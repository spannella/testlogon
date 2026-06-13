package com.testlogon.android.feature.messaging.helpdesk

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakeAuthStateStore
import com.testlogon.android.data.messaging.helpdesk.ClaimState
import com.testlogon.android.data.messaging.helpdesk.HelpdeskAssignment
import com.testlogon.android.data.messaging.helpdesk.HelpdeskClaimResult
import com.testlogon.android.data.messaging.helpdesk.HelpdeskQueueItem
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRoutingState
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import java.io.IOException

class HelpdeskQueueViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeHelpdeskRepository()
    private val auth = FakeAuthStateStore()

    @Before
    fun seedAgent() {
        // Authenticated agent "usr_me" for the optimistic claim path.
        runBlocking { auth.setAuthenticated("usr_me") }
    }

    private fun vm() = HelpdeskQueueViewModel(repo, auth)

    private fun item(id: String) = HelpdeskQueueItem(
        conversationId = id, title = "T", preview = "p",
        routingState = HelpdeskRoutingState.AWAITING_AGENT, claimState = ClaimState.UNASSIGNED,
        activeAgentUserId = null, unreadCount = 0, lastMessageAtEpochSeconds = 1,
    )

    private fun readyRow(vm: HelpdeskQueueViewModel, id: String): HelpdeskQueueItem =
        (vm.uiState.value as HelpdeskQueueUiState.Ready).items.first { it.conversationId == id }

    @Test
    fun load_success_rendersReady() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1"), item("c2")))
        val vm = vm()
        advanceUntilIdle()
        val s = vm.uiState.value
        assertTrue(s is HelpdeskQueueUiState.Ready)
        assertEquals(2, (s as HelpdeskQueueUiState.Ready).items.size)
    }

    @Test
    fun load_emptyArray_rendersReadyEmpty() = runTest {
        repo.queueResult = ApiResult.Success(emptyList())
        val vm = vm()
        advanceUntilIdle()
        val s = vm.uiState.value
        assertTrue(s is HelpdeskQueueUiState.Ready)
        assertTrue((s as HelpdeskQueueUiState.Ready).items.isEmpty())
    }

    @Test
    fun load_403_rendersNotAuthorized() = runTest {
        repo.queueResult = ApiResult.Failure(ApiError(status = 403, message = "forbidden"))
        val vm = vm()
        advanceUntilIdle()
        assertEquals(HelpdeskQueueUiState.NotAuthorized, vm.uiState.value)
    }

    @Test
    fun load_otherError_rendersError() = runTest {
        repo.queueResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.uiState.value is HelpdeskQueueUiState.Error)
    }

    @Test
    fun refresh_reissuesFetch() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1")))
        val vm = vm()
        advanceUntilIdle()
        assertEquals(1, repo.loadQueueCalls)
        vm.refresh()
        advanceUntilIdle()
        assertEquals(2, repo.loadQueueCalls)
    }

    // ---- AND-378: inline claim from the queue row ----

    @Test
    fun claim_success_optimisticThenReconciledToMe_emitsClaimed() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1")))
        repo.claimResult = ApiResult.Success(
            HelpdeskClaimResult(
                conversationId = "c1",
                assignment = HelpdeskAssignment.ASSIGNED_TO_ME,
                assignedAgentUserId = "usr_me",
                assignmentVersion = 7,
                idempotent = false,
            ),
        )
        val vm = vm()
        advanceUntilIdle()
        val events = mutableListOf<HelpdeskQueueEvent>()
        val ejob = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch { vm.events.toList(events) }
        advanceUntilIdle()

        vm.onClaim("c1")
        advanceUntilIdle()
        ejob.cancel()

        val row = readyRow(vm, "c1")
        assertEquals(ClaimState.CLAIMED_BY_ME, row.claimState)
        assertEquals("usr_me", row.activeAgentUserId)
        assertEquals(HelpdeskRoutingState.ASSIGNED, row.routingState)
        assertTrue((vm.uiState.value as HelpdeskQueueUiState.Ready).inFlight.isEmpty())
        assertEquals(listOf(HelpdeskQueueEvent.Claimed), events)
        assertEquals(listOf("c1"), repo.claimedIds)
    }

    @Test
    fun claim_doubleSubmitGuard_onlyOneRequest() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1")))
        repo.claimResult = ApiResult.Success(
            HelpdeskClaimResult("c1", HelpdeskAssignment.ASSIGNED_TO_ME, "usr_me", 1, false),
        )
        val gate = CompletableDeferred<Unit>()
        repo.claimGate = gate
        val vm = vm()
        advanceUntilIdle()

        vm.onClaim("c1")
        runCurrent()
        // In flight: a second tap is ignored (double-submit guard).
        assertTrue((vm.uiState.value as HelpdeskQueueUiState.Ready).inFlight.contains("c1"))
        vm.onClaim("c1")
        runCurrent()
        gate.complete(Unit)
        advanceUntilIdle()
        assertEquals(listOf("c1"), repo.claimedIds)
    }

    @Test
    fun claim_resolvesToOtherAgent_reconcilesAndEmitsAlreadyClaimed() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1")))
        repo.claimResult = ApiResult.Success(
            HelpdeskClaimResult(
                conversationId = "c1",
                assignment = HelpdeskAssignment.ASSIGNED_TO_OTHER,
                assignedAgentUserId = "usr_other",
                assignmentVersion = 9,
                idempotent = false,
            ),
        )
        val vm = vm()
        advanceUntilIdle()
        val events = mutableListOf<HelpdeskQueueEvent>()
        val ejob = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch { vm.events.toList(events) }
        advanceUntilIdle()

        vm.onClaim("c1")
        advanceUntilIdle()
        ejob.cancel()

        val row = readyRow(vm, "c1")
        assertEquals(ClaimState.CLAIMED_BY_OTHER, row.claimState)
        assertEquals("usr_other", row.activeAgentUserId)
        assertEquals(listOf(HelpdeskQueueEvent.AlreadyClaimed), events)
    }

    @Test
    fun claim_networkError_rollsBackAndEmitsFailed() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1")))
        repo.claimResult = ApiResult.NetworkError(IOException("offline"))
        val vm = vm()
        advanceUntilIdle()
        val events = mutableListOf<HelpdeskQueueEvent>()
        val ejob = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch { vm.events.toList(events) }
        advanceUntilIdle()

        vm.onClaim("c1")
        advanceUntilIdle()
        ejob.cancel()

        val row = readyRow(vm, "c1")
        // Rolled back to the pre-claim snapshot.
        assertEquals(ClaimState.UNASSIGNED, row.claimState)
        assertEquals(HelpdeskRoutingState.AWAITING_AGENT, row.routingState)
        assertTrue(row.activeAgentUserId.isNullOrBlank())
        assertTrue((vm.uiState.value as HelpdeskQueueUiState.Ready).inFlight.isEmpty())
        assertEquals(1, events.size)
        assertTrue(events.first() is HelpdeskQueueEvent.ClaimFailed)
    }

    @Test
    fun claim_onNonClaimableRow_isIgnored() = runTest {
        val assigned = item("c1").copy(
            routingState = HelpdeskRoutingState.ASSIGNED,
            claimState = ClaimState.CLAIMED_BY_OTHER,
            activeAgentUserId = "usr_other",
        )
        repo.queueResult = ApiResult.Success(listOf(assigned))
        val vm = vm()
        advanceUntilIdle()
        vm.onClaim("c1")
        advanceUntilIdle()
        assertTrue(repo.claimedIds.isEmpty())
        assertFalse((vm.uiState.value as HelpdeskQueueUiState.Ready).inFlight.contains("c1"))
    }
}
