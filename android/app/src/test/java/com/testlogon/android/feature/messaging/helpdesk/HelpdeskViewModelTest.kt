package com.testlogon.android.feature.messaging.helpdesk

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.auth.FakeAuthStateStore
import com.testlogon.android.data.messaging.Message
import com.testlogon.android.data.messaging.SendStatus
import com.testlogon.android.feature.messaging.FakeMessagingRepository
import com.testlogon.android.data.messaging.helpdesk.ClaimState
import com.testlogon.android.data.messaging.helpdesk.HelpdeskAssignment
import com.testlogon.android.data.messaging.helpdesk.HelpdeskClaimResult
import com.testlogon.android.data.messaging.helpdesk.HelpdeskQueueItem
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRoutingState
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * AND-380 — unit tests for the unified [HelpdeskViewModel] (TC-AND-380-01..11, plus 403/derived-metrics).
 * No Turbine on the classpath: distinct-emission assertions collect [HelpdeskViewModel.state] into a
 * list via backgroundScope.
 */
class HelpdeskViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeHelpdeskRepository()
    private val messaging = FakeMessagingRepository()
    private val auth = FakeAuthStateStore()

    @Before
    fun seedAgent() {
        runBlocking { auth.setAuthenticated(ME) }
    }

    private fun vm() = HelpdeskViewModel(repo, messaging, auth)

    private fun item(
        id: String,
        owner: String? = null,
        routing: HelpdeskRoutingState = HelpdeskRoutingState.AWAITING_AGENT,
    ) = HelpdeskQueueItem(
        conversationId = id,
        title = "T-$id",
        preview = "p",
        routingState = routing,
        claimState = when {
            owner == null -> ClaimState.UNASSIGNED
            owner == ME -> ClaimState.CLAIMED_BY_ME
            else -> ClaimState.CLAIMED_BY_OTHER
        },
        activeAgentUserId = owner,
        unreadCount = 0,
        lastMessageAtEpochSeconds = 1L,
    )

    private fun claimResult(
        id: String,
        assignment: HelpdeskAssignment = HelpdeskAssignment.ASSIGNED_TO_ME,
        agent: String = ME,
        version: Int = 3,
        idempotent: Boolean = false,
    ) = HelpdeskClaimResult(
        conversationId = id,
        assignment = assignment,
        assignedAgentUserId = agent,
        assignmentVersion = version,
        idempotent = idempotent,
    )

    // ---- TC-01 ----
    @Test
    fun initialLoad_happyPath_populatesQueue() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1"), item("c2")))
        val vm = vm()
        assertTrue(vm.state.value.isLoading)
        advanceUntilIdle()
        val s = vm.state.value
        assertFalse(s.isLoading)
        assertFalse(s.isRefreshing)
        assertEquals(2, s.queue.size)
        assertNull(s.banner)
    }

    // ---- TC-02 ----
    @Test
    fun derivedMetrics_matchCountsAndMakeNoSecondCall() = runTest {
        repo.queueResult = ApiResult.Success(
            listOf(
                item("u1"), item("u2"), item("u3"), // unclaimed
                item("m1", owner = ME), item("m2", owner = ME), // mine
                item("o1", owner = "usr_other"), // other
            ),
        )
        val vm = vm()
        advanceUntilIdle()
        val m = vm.state.value.metrics
        assertEquals(3, m.unassignedCount)
        assertEquals(2, m.assignedToMeCount)
        assertEquals(6, m.openCount)
        // Only the single queue load — there is no metrics endpoint.
        assertEquals(1, repo.loadQueueCalls)
    }

    // ---- TC-03 ----
    @Test
    fun refresh_onTimeout_isStaleWhileRevalidate() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1"), item("c2")))
        val vm = vm()
        advanceUntilIdle()
        // Next load times out.
        repo.queueResult = ApiResult.NetworkError(java.io.IOException("t"), isTimeout = true)
        vm.onIntent(HelpdeskIntent.Refresh)
        advanceUntilIdle()
        val s = vm.state.value
        assertEquals(2, s.queue.size) // prior data retained
        assertTrue(s.isStale)
        assertNotNull(s.banner)
        assertFalse(s.isRefreshing)
    }

    // ---- TC-04 ----
    @Test
    fun setFilter_isLocal_zeroNetwork() = runTest {
        repo.queueResult = ApiResult.Success(
            listOf(item("u1"), item("m1", owner = ME), item("o1", owner = "usr_other")),
        )
        val vm = vm()
        advanceUntilIdle()
        val callsAfterLoad = repo.loadQueueCalls

        vm.onIntent(HelpdeskIntent.SetFilter(QueueFilter.UNCLAIMED))
        assertEquals(listOf("u1"), vm.state.value.filteredQueue.map { it.conversationId })

        vm.onIntent(HelpdeskIntent.SetFilter(QueueFilter.MINE))
        assertEquals(listOf("m1"), vm.state.value.filteredQueue.map { it.conversationId })

        assertEquals(callsAfterLoad, repo.loadQueueCalls) // no extra loads
    }

    // ---- TC-05 ----
    @Test
    fun claim_success_patchesRowAndSelects() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1")))
        repo.claimResult = ApiResult.Success(claimResult("c1"))
        val vm = vm()
        advanceUntilIdle()

        // Hold the claim mid-flight to observe claimingIds.
        val gate = CompletableDeferred<Unit>()
        repo.claimGate = gate
        vm.onIntent(HelpdeskIntent.Claim("c1"))
        runCurrent()
        assertTrue("c1" in vm.state.value.claimingIds)
        gate.complete(Unit)
        advanceUntilIdle()

        val s = vm.state.value
        assertFalse("c1" in s.claimingIds)
        val row = s.queue.first { it.conversationId == "c1" }
        assertEquals(ME, row.activeAgentUserId)
        assertEquals(ClaimState.CLAIMED_BY_ME, row.claimState)
        assertEquals("c1", s.selectedConversation?.conversationId)
    }

    // ---- TC-06 ----
    @Test
    fun claim_idempotent_treatedAsSuccess() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1", owner = ME)))
        repo.claimResult = ApiResult.Success(claimResult("c1", idempotent = true))
        val vm = vm()
        advanceUntilIdle()

        vm.onIntent(HelpdeskIntent.Claim("c1"))
        advanceUntilIdle()

        val s = vm.state.value
        assertNull(s.banner)
        assertEquals(ME, s.queue.first { it.conversationId == "c1" }.activeAgentUserId)
        assertEquals("c1", s.selectedConversation?.conversationId)
    }

    // ---- TC-07 ----
    @Test
    fun claim_lostRace_triggersRefreshAndBanner_noCrash() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1")))
        repo.claimResult = ApiResult.Success(
            claimResult("c1", assignment = HelpdeskAssignment.ASSIGNED_TO_OTHER, agent = "usr_other"),
        )
        val vm = vm()
        advanceUntilIdle()
        val loadsBefore = repo.loadQueueCalls

        vm.onIntent(HelpdeskIntent.Claim("c1"))
        advanceUntilIdle()

        val s = vm.state.value
        assertFalse("c1" in s.claimingIds)
        assertNotNull(s.banner)
        assertTrue(repo.loadQueueCalls > loadsBefore) // refresh fired
    }

    @Test
    fun claim_422Failure_treatedAsConflict() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1")))
        repo.claimResult = ApiResult.Failure(ApiError(status = 422, message = "invalid"))
        val vm = vm()
        advanceUntilIdle()
        val loadsBefore = repo.loadQueueCalls

        vm.onIntent(HelpdeskIntent.Claim("c1"))
        advanceUntilIdle()

        assertFalse("c1" in vm.state.value.claimingIds)
        assertNotNull(vm.state.value.banner)
        assertTrue(repo.loadQueueCalls > loadsBefore)
    }

    // ---- TC-08 ----
    @Test
    fun sendReply_blank_rejectedNoCall() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1", owner = ME)))
        val vm = vm()
        advanceUntilIdle()

        vm.onIntent(HelpdeskIntent.SendReply("c1", "   "))
        advanceUntilIdle()

        assertNotNull(vm.state.value.banner)
        assertFalse(vm.state.value.isSending)
        assertTrue(messaging.markReadCalls.isEmpty()) // sanity: nothing happened
        // No outbox send recorded.
        assertEquals(emptyList<Triple<String, String, String>>(), messaging.imageSendCalls)
    }

    // ---- TC-09 ----
    @Test
    fun sendReply_happyPath_clearsComposerAndReloadsThread() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1", owner = ME)))
        val sent = Message(
            id = "m1",
            clientId = "cid",
            conversationId = "c1",
            senderId = ME,
            text = "hi",
            createdAtEpochSeconds = 1L,
            sendStatus = SendStatus.SENT,
        )
        messaging.sendResult = ApiResult.Success(sent)
        messaging.emitThread(listOf(sent))
        val vm = vm()
        advanceUntilIdle()
        vm.onDraftChange("hi")

        vm.onIntent(HelpdeskIntent.SendReply("c1", "hi"))
        advanceUntilIdle()

        val s = vm.state.value
        assertFalse(s.isSending)
        assertEquals("", s.replyDraft)
        assertEquals(1, s.thread.size)
        assertNull(s.banner)
    }

    // ---- TC-10 ----
    @Test
    fun refresh_reentrant_singleCoherentFinalState() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1")))
        val vm = vm()
        advanceUntilIdle()

        repo.queueResult = ApiResult.Success(listOf(item("c1"), item("c2")))
        vm.onIntent(HelpdeskIntent.Refresh)
        vm.onIntent(HelpdeskIntent.Refresh) // second cancels/replaces the first
        advanceUntilIdle()

        val s = vm.state.value
        assertFalse(s.isRefreshing)
        assertEquals(2, s.queue.size)
    }

    // ---- TC-11 (distinct emissions + dismissError) ----
    @Test
    fun emissions_areDistinct_andDismissErrorClearsBannerOnly() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1")))
        val vm = vm()
        val seen = mutableListOf<HelpdeskUiState>()
        val job = backgroundScope.launch { vm.state.toList(seen) }
        advanceUntilIdle()

        // Setting the same filter twice must not produce duplicate consecutive emissions.
        vm.onIntent(HelpdeskIntent.SetFilter(QueueFilter.ALL))
        vm.onIntent(HelpdeskIntent.SetFilter(QueueFilter.ALL))
        advanceUntilIdle()

        // Seed a banner via a blank reply, then dismiss it.
        vm.onIntent(HelpdeskIntent.SendReply("c1", ""))
        advanceUntilIdle()
        val withBanner = vm.state.value
        assertNotNull(withBanner.banner)

        vm.onIntent(HelpdeskIntent.DismissError)
        advanceUntilIdle()
        val cleared = vm.state.value
        assertNull(cleared.banner)
        assertEquals(withBanner.queue, cleared.queue)
        assertEquals(withBanner.filter, cleared.filter)

        // No two consecutive equal states.
        for (i in 1 until seen.size) {
            assertFalse("duplicate emission at $i: ${seen[i]}", seen[i] == seen[i - 1])
        }
        job.cancel()
    }

    // ---- 403 non-agent ----
    @Test
    fun load_forbidden_surfacesPermissionBanner_noCrash() = runTest {
        repo.queueResult = ApiResult.Failure(ApiError(status = 403, message = "forbidden"))
        val vm = vm()
        advanceUntilIdle()
        val s = vm.state.value
        assertFalse(s.isLoading)
        assertEquals(UiText.Res(com.testlogon.android.R.string.helpdesk_permission_denied), s.banner)
        assertTrue(s.queue.isEmpty())
    }

    // ---- select(null) clears ----
    @Test
    fun selectNull_clearsDetailPane() = runTest {
        repo.queueResult = ApiResult.Success(listOf(item("c1", owner = ME)))
        repo.claimResult = ApiResult.Success(claimResult("c1"))
        val vm = vm()
        advanceUntilIdle()
        vm.onIntent(HelpdeskIntent.Select("c1"))
        advanceUntilIdle()
        assertNotNull(vm.state.value.selectedConversation)

        vm.onIntent(HelpdeskIntent.Select(null))
        advanceUntilIdle()
        assertNull(vm.state.value.selectedConversation)
        assertTrue(vm.state.value.thread.isEmpty())
    }

    private companion object {
        const val ME = "usr_me"
    }
}
