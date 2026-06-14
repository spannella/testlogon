package com.testlogon.android.feature.call.domain

import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.core.model.ApiError
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
import com.testlogon.android.data.webrtc.PeerLifecycle
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-296 — outgoing-call state machine tests with a fake [CallRepository] + fake [IceServersProvider]
 * and the FLAGGED WebRTC stubs (StubPeerConnectionController / StubSignalingTransport return
 * NotConfigured). Verifies: invite -> Ringing, media-start asserts the stub NotConfigured
 * (mediaUnavailable + NEVER starts a real peer), ringing-timeout (bounded), remote decline/end, heartbeat
 * terminate -> INSUFFICIENT_BALANCE, hang-up -> end POST -> Ended(HANGUP), single-active guard.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CallManagerTest {

    private val fakeClock = Clock { 1_000_000L }

    private class FakeCallRepository : CallRepository {
        var inviteResult: ApiResult<CallInvited> = ApiResult.Success(
            CallInvited("c", "conv", "self", "peer", "ringing", CallMode.AUDIO, 0, false, null),
        )
        var heartbeatResult: ApiResult<CallHeartbeat> = ApiResult.Success(
            CallHeartbeat("c", 5, 0, 0, 0, 0, false, 10.0, false, "ok"),
        )
        var endCount = 0
        var timeoutCount = 0
        var declineCount = 0

        override suspend fun invite(
            callId: String,
            conversationId: String,
            calleeUserId: String,
            mode: CallMode,
            idempotencyKey: String?,
            paid: Boolean,
            rateCentsPerMin: Int?,
        ): ApiResult<CallInvited> = stamp(inviteResult, callId, conversationId, calleeUserId, mode)

        override suspend fun accept(callId: String, idempotencyKey: String?): ApiResult<CallAction> =
            ApiResult.Success(action(callId, "accepted"))

        override suspend fun decline(callId: String, reason: String): ApiResult<CallAction> {
            declineCount++
            return ApiResult.Success(action(callId, "declined"))
        }

        override suspend fun end(callId: String, reason: String, idempotencyKey: String?): ApiResult<CallAction> {
            endCount++
            return ApiResult.Success(action(callId, "ended"))
        }

        override suspend fun timeout(callId: String, reason: String, idempotencyKey: String?): ApiResult<CallAction> {
            timeoutCount++
            return ApiResult.Success(action(callId, "ended"))
        }

        override suspend fun heartbeat(callId: String, clientTsEpochSeconds: Long?): ApiResult<CallHeartbeat> =
            heartbeatResult

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

        // Fake stamps the requested call id onto the returned invited object (VM reads it back).
        private fun stamp(
            base: ApiResult<CallInvited>,
            callId: String,
            conversationId: String,
            calleeUserId: String,
            mode: CallMode,
        ): ApiResult<CallInvited> = if (base is ApiResult.Success) {
            ApiResult.Success(
                base.data.copy(
                    callId = callId,
                    conversationId = conversationId,
                    calleeUserId = calleeUserId,
                    mode = mode,
                ),
            )
        } else {
            base
        }

        private fun action(callId: String, state: String) =
            CallAction(callId, "conv", state, 0, null, null, false)
    }

    private val fakeIce = object : IceServersProvider {
        override suspend fun current(callId: String): List<IceServer> =
            listOf(IceServer(urls = listOf("stun:stun.example:3478")))
    }

    private fun manager(scope: CoroutineScope, repo: FakeCallRepository, timing: CallTiming) =
        CallManager(
            callRepository = repo,
            iceServers = fakeIce,
            peer = StubPeerConnectionController(),
            signaling = StubSignalingTransport(),
            clock = fakeClock,
            scope = scope,
            timing = timing,
        )

    @Test
    fun placeCall_reachesRinging_andMediaUnavailableFromStub() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeCallRepository()
        val peer = StubPeerConnectionController()
        val mgr = CallManager(repo, fakeIce, peer, StubSignalingTransport(), fakeClock, scope, CallTiming())

        mgr.placeCall("conv_1", "peer_1", CallMode.AUDIO)
        // AND-296: the ring timeout now (correctly) OUTLIVES setup, so it is a pending bounded delay.
        // Use runCurrent (not advanceUntilIdle) to settle the eager invite/negotiate WITHOUT advancing
        // virtual time past the ring-timeout delay (advanceUntilIdle would fire it and end the call).
        runCurrent()

        assertEquals(CallPhase.Ringing, mgr.state.value.phase)
        assertEquals("peer_1", mgr.state.value.call?.peerUserId)
        // Media stub never started a real peer (still Idle) and the control plane flagged it unavailable.
        assertEquals(PeerLifecycle.Idle, peer.lifecycle.value)
        assertTrue(mgr.state.value.mediaUnavailable)

        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun ringingTimeout_postsTimeout_andEndsNoAnswer() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeCallRepository()
        val mgr = manager(scope, repo, CallTiming(ringTimeoutMs = 1_000))

        mgr.placeCall("conv", "peer")
        // Settle setup without advancing past the (now-surviving) 1s ring-timeout delay.
        runCurrent()
        assertEquals(CallPhase.Ringing, mgr.state.value.phase)

        advanceTimeBy(1_500)
        advanceUntilIdle()

        assertEquals(1, repo.timeoutCount)
        assertEquals(CallPhase.Ended(CallEndReason.NO_ANSWER), mgr.state.value.phase)
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun remoteDecline_endsDeclined_withNoEndPost() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeCallRepository()
        val mgr = manager(scope, repo, CallTiming())

        mgr.placeCall("conv", "peer")
        // Stay at Ringing (ring timeout pending) before injecting the remote decline.
        runCurrent()
        val callId = mgr.state.value.call!!.callId

        mgr.onCallEvent(CallEvent.Declined(callId))
        advanceUntilIdle()

        assertEquals(CallPhase.Ended(CallEndReason.DECLINED), mgr.state.value.phase)
        assertEquals(0, repo.endCount)
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun remoteEnd_duringCall_endsRemoteHangup() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeCallRepository()
        val mgr = manager(scope, repo, CallTiming())

        mgr.placeCall("conv", "peer")
        // Stay at Ringing (ring timeout pending) before injecting the remote end.
        runCurrent()
        val callId = mgr.state.value.call!!.callId

        mgr.onCallEvent(CallEvent.Ended(callId))
        advanceUntilIdle()

        assertEquals(CallPhase.Ended(CallEndReason.REMOTE_HANGUP), mgr.state.value.phase)
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun hangUp_postsEnd_andEndsHangup() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeCallRepository()
        val mgr = manager(scope, repo, CallTiming())

        mgr.placeCall("conv", "peer")
        // Stay at Ringing (ring timeout pending) — advanceUntilIdle would time the call out first, making
        // endCall a no-op against an already-terminal phase.
        runCurrent()

        mgr.endCall(CallEndReason.HANGUP)
        advanceUntilIdle()

        assertEquals(1, repo.endCount)
        assertEquals(CallPhase.Ended(CallEndReason.HANGUP), mgr.state.value.phase)
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun inviteFailure_failsNetwork_noPeer() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeCallRepository().apply {
            inviteResult = ApiResult.Failure(ApiError(500, "boom"))
        }
        val peer = StubPeerConnectionController()
        val mgr = CallManager(repo, fakeIce, peer, StubSignalingTransport(), fakeClock, scope, CallTiming())

        mgr.placeCall("conv", "peer")
        advanceUntilIdle()

        assertEquals(CallPhase.Failed(CallEndReason.NETWORK), mgr.state.value.phase)
        assertEquals(PeerLifecycle.Idle, peer.lifecycle.value)
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun heartbeatTerminate_endsInsufficientBalance() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeCallRepository().apply {
            heartbeatResult = ApiResult.Success(
                CallHeartbeat("c", 5, 0, 0, 0, 0, false, 0.0, false, "terminate"),
            )
        }
        val mgr = manager(scope, repo, CallTiming(heartbeatIntervalMs = 1_000))

        mgr.placeCall("conv", "peer")
        // Stay at Ringing (ring timeout pending) before answering; onConnected cancels the ring timeout.
        runCurrent()
        mgr.onConnected()
        assertTrue(mgr.state.value.phase is CallPhase.Connected)

        advanceTimeBy(1_500)
        advanceUntilIdle()

        assertEquals(1, repo.endCount)
        assertEquals(CallPhase.Ended(CallEndReason.INSUFFICIENT_BALANCE), mgr.state.value.phase)
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun singleActiveCall_secondPlaceIgnored() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeCallRepository()
        val mgr = manager(scope, repo, CallTiming())

        mgr.placeCall("conv_a", "peer_a")
        // Stay at Ringing (busy) — advanceUntilIdle would time the first call out, dropping isBusy().
        runCurrent()
        assertTrue(mgr.isBusy())

        mgr.placeCall("conv_b", "peer_b")
        runCurrent()

        // The first call remains; the second was rejected (single-active invariant).
        assertEquals("peer_a", mgr.state.value.call?.peerUserId)
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun connected_seedsLocalTimer_andHeartbeatUpdatesElapsed() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeCallRepository().apply {
            heartbeatResult = ApiResult.Success(
                CallHeartbeat("c", 30, 0, 0, 0, 0, true, 9.0, false, "ok"),
            )
        }
        val mgr = manager(scope, repo, CallTiming(heartbeatIntervalMs = 1_000))

        mgr.placeCall("conv", "peer")
        // Stay at Ringing (ring timeout pending) before answering; onConnected cancels the ring timeout.
        runCurrent()
        mgr.onConnected()
        advanceTimeBy(1_500)
        // One heartbeat fired at 1s (advanceTimeBy above). Do NOT advanceUntilIdle here: with
        // shouldTerminate=false the bounded-by-phase heartbeat loop has no terminal, so advanceUntilIdle
        // would walk delay(1s) forever. runCurrent settles the already-fired heartbeat without looping.
        runCurrent()

        assertEquals(30L, mgr.state.value.elapsedSeconds)
        assertTrue(mgr.state.value.warnLowBalance)
        assertFalse(mgr.state.value.phase.isTerminal)
        // Stop the bounded heartbeat loop so the test scope idles.
        mgr.endCall()
        advanceUntilIdle()
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }
}
