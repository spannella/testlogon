package com.testlogon.android.feature.call.incoming

import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.call.CallAction
import com.testlogon.android.data.call.CallBillingStatus
import com.testlogon.android.data.call.CallEvent
import com.testlogon.android.data.call.CallHeartbeat
import com.testlogon.android.data.call.CallHistoryPage
import com.testlogon.android.data.call.CallInvited
import com.testlogon.android.data.call.CallMode
import com.testlogon.android.data.call.CallRepository
import com.testlogon.android.data.webrtc.IceServer
import com.testlogon.android.data.webrtc.IceServersProvider
import com.testlogon.android.data.webrtc.StubPeerConnectionController
import com.testlogon.android.data.webrtc.StubSignalingTransport
import com.testlogon.android.feature.call.domain.CallManager
import com.testlogon.android.feature.call.domain.CallTiming
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-297 — receive-side state-machine tests with fake [CallRepository] + fake [Ringer] + fake
 * [IncomingCallNotifier]. Verifies: invite -> ring (once), accept -> connecting -> connected, decline ->
 * /decline, timeout (bounded, virtual clock) -> /timeout, remote-cancel, dedupe, busy second invite.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class IncomingCallControllerTest {

    private val fakeClock = Clock { 1_000_000L }

    private class FakeRepo : CallRepository {
        var acceptState = "accepted"
        var acceptFails = false
        var declineCount = 0
        var declineReasons = mutableListOf<String>()
        var timeoutCount = 0

        override suspend fun invite(
            callId: String, conversationId: String, calleeUserId: String, mode: CallMode,
            idempotencyKey: String?, paid: Boolean, rateCentsPerMin: Int?,
        ): ApiResult<CallInvited> =
            ApiResult.Success(CallInvited(callId, conversationId, "self", calleeUserId, "ringing", mode, 0, false, null))

        override suspend fun accept(callId: String, idempotencyKey: String?): ApiResult<CallAction> =
            if (acceptFails) ApiResult.NetworkError(java.io.IOException()) else ApiResult.Success(act(callId, acceptState))

        override suspend fun decline(callId: String, reason: String): ApiResult<CallAction> {
            declineCount++
            declineReasons += reason
            return ApiResult.Success(act(callId, "declined"))
        }

        override suspend fun end(callId: String, reason: String, idempotencyKey: String?): ApiResult<CallAction> =
            ApiResult.Success(act(callId, "ended"))

        override suspend fun timeout(callId: String, reason: String, idempotencyKey: String?): ApiResult<CallAction> {
            timeoutCount++
            return ApiResult.Success(act(callId, "ended"))
        }

        override suspend fun heartbeat(callId: String, clientTsEpochSeconds: Long?): ApiResult<CallHeartbeat> =
            ApiResult.Success(CallHeartbeat(callId, 0, 0, 0, 0, 0, false, 10.0, false, "ok"))

        override suspend fun billing(callId: String): ApiResult<CallBillingStatus> =
            ApiResult.Success(CallBillingStatus(callId, false, 0, 0, 0, 0, 0, ""))

        override suspend fun history(cursor: String?, limit: Int?): ApiResult<CallHistoryPage> =
            ApiResult.Success(CallHistoryPage(emptyList(), null))
        override suspend fun detail(callId: String) =
            ApiResult.Success(
                com.testlogon.android.data.call.CallHistoryEntry(
                    callId, "self", "peer", CallMode.AUDIO,
                    com.testlogon.android.data.call.CallDirection.OUTGOING,
                    com.testlogon.android.data.call.CallStatus.COMPLETED, 0L, 0L, "completed",
                ),
            )
        override suspend fun deleteRecord(callId: String) = ApiResult.Success(Unit)
        override suspend fun stats() =
            ApiResult.Success(com.testlogon.android.data.call.CallStats(0, emptyMap(), emptyMap(), 0L))

        private fun act(callId: String, state: String) = CallAction(callId, "conv", state, 0, null, null, false)
    }

    private class FakeRinger : Ringer {
        var startCount = 0
        var stopCount = 0
        override fun start() { startCount++ }
        override fun stop() { stopCount++ }
    }

    private class FakeNotifier : IncomingCallNotifier {
        var showCount = 0
        override fun showRinging(invite: CallEvent.Invite): Boolean { showCount++; return true }
        override fun cancel(callId: String) {}
    }

    private fun manager(scope: CoroutineScope, repo: CallRepository) = CallManager(
        callRepository = repo,
        iceServers = object : IceServersProvider {
            override suspend fun current(callId: String) = listOf(IceServer(urls = listOf("stun:x")))
        },
        peer = StubPeerConnectionController(),
        signaling = StubSignalingTransport(),
        clock = fakeClock,
        scope = scope,
        timing = CallTiming(),
    )

    private fun invite(id: String = "c_1") = CallEvent.Invite(
        callId = id, conversationId = "conv", callerUserId = "u_caller",
        callerName = "Alex", callerAvatarUrl = null, mode = CallMode.AUDIO, expiresAtEpochSeconds = null,
    )

    private fun controller(scope: CoroutineScope, repo: FakeRepo, ringer: FakeRinger, notifier: FakeNotifier) =
        IncomingCallController(
            callRepository = repo,
            ringer = ringer,
            notifier = notifier,
            callManager = manager(scope, repo),
            clock = fakeClock,
            scope = scope,
            timing = CallTiming(ringTimeoutMs = 1_000),
        )

    @Test
    fun invite_rings_andShowsNotification() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeRepo(); val ringer = FakeRinger(); val notifier = FakeNotifier()
        val controller = controller(scope, repo, ringer, notifier)

        controller.onInvite(invite())
        // AND-297: the ring timeout is a pending bounded delay; runCurrent settles the eager ring/notify
        // work WITHOUT advancing virtual time past it (advanceUntilIdle would fire it and dismiss).
        runCurrent()

        assertTrue(controller.state.value is IncomingCallState.Ringing)
        assertEquals(1, ringer.startCount)
        assertEquals(1, notifier.showCount)
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun duplicateInvite_ringsOnce() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeRepo(); val ringer = FakeRinger(); val notifier = FakeNotifier()
        val controller = controller(scope, repo, ringer, notifier)

        controller.onInvite(invite("dup"))
        controller.onInvite(invite("dup"))
        advanceUntilIdle()

        assertEquals(1, ringer.startCount)
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun secondDistinctInvite_whileRinging_autoDeclinesBusy() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeRepo(); val ringer = FakeRinger(); val notifier = FakeNotifier()
        val controller = controller(scope, repo, ringer, notifier)

        controller.onInvite(invite("a"))
        controller.onInvite(invite("b"))
        // Settle the busy auto-decline without advancing past the first call's ring timeout.
        runCurrent()

        assertEquals(1, repo.declineCount)
        assertEquals("busy", repo.declineReasons.first())
        // First call still ringing.
        assertEquals("a", (controller.state.value as IncomingCallState.Ringing).invite.callId)
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun accept_reachesConnected() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeRepo(); val ringer = FakeRinger(); val notifier = FakeNotifier()
        val controller = controller(scope, repo, ringer, notifier)

        controller.onInvite(invite("c_acc"))
        // Stay at Ringing (ring timeout pending) before accepting; accept() cancels it via stopRinging.
        runCurrent()
        controller.accept()
        advanceUntilIdle()

        assertEquals(IncomingCallState.Connected("c_acc"), controller.state.value)
        assertEquals(1, ringer.stopCount)
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun accept_returningTerminalState_failsScreen() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeRepo().apply { acceptState = "ended" }
        val ringer = FakeRinger(); val notifier = FakeNotifier()
        val controller = controller(scope, repo, ringer, notifier)

        controller.onInvite(invite())
        // Stay at Ringing (ring timeout pending) before accepting; accept() cancels it via stopRinging.
        runCurrent()
        controller.accept()
        advanceUntilIdle()

        assertTrue(controller.state.value is IncomingCallState.Failed)
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun decline_postsDeclined_andDismisses() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeRepo(); val ringer = FakeRinger(); val notifier = FakeNotifier()
        val controller = controller(scope, repo, ringer, notifier)

        controller.onInvite(invite())
        // Stay at Ringing (ring timeout pending) before declining; decline() cancels it via stopRinging.
        runCurrent()
        controller.decline()
        advanceUntilIdle()

        assertEquals(1, repo.declineCount)
        assertEquals("declined", repo.declineReasons.first())
        assertEquals(IncomingCallState.Dismissed, controller.state.value)
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun noAction_timesOut_postsTimeout() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeRepo(); val ringer = FakeRinger(); val notifier = FakeNotifier()
        val controller = controller(scope, repo, ringer, notifier)

        controller.onInvite(invite())
        advanceUntilIdle()
        advanceTimeBy(1_500)
        advanceUntilIdle()

        assertEquals(1, repo.timeoutCount)
        assertEquals(IncomingCallState.Dismissed, controller.state.value)
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun remoteCancel_duringRing_dismisses() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeRepo(); val ringer = FakeRinger(); val notifier = FakeNotifier()
        val controller = controller(scope, repo, ringer, notifier)

        controller.onInvite(invite("c_x"))
        advanceUntilIdle()
        controller.onCallEvent(CallEvent.Ended("c_x"))
        advanceUntilIdle()

        assertEquals(IncomingCallState.Dismissed, controller.state.value)
        assertEquals(1, ringer.stopCount)
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }
}
