package com.testlogon.android.feature.call.fsm

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.data.webrtc.StubSignalingTransport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-305 — host ([CallStateMachine]) tests with a recording repo + manual-fire timer scheduler. The host
 * serializes events through a single-consumer Channel; we drain it with runCurrent (NEVER advanceUntilIdle
 * on the host's WhileSubscribed/SharedFlow). The fake scheduler fires timers deterministically.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CallStateMachineHostTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule(UnconfinedTestDispatcher())

    private val peer = PeerRef("peer", "conv", "Alex")
    private var clockMs = 1_000L

    private fun host(
        scope: CoroutineScope,
        repo: RecordingCallRepository = RecordingCallRepository(),
        timers: FakeCallTimerScheduler = FakeCallTimerScheduler(),
        store: CallSnapshotStore = InMemoryCallSnapshotStore(),
    ): CallStateMachine = CallStateMachine(
        repo = repo,
        timers = timers,
        snapshotStore = store,
        signaling = StubSignalingTransport(),
        clock = Clock { clockMs },
        scope = scope,
    )

    @Test
    fun startOutgoing_invitesAndArmsTimer_thenFullLifecycleToEnded() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = RecordingCallRepository()
        val timers = FakeCallTimerScheduler()
        val sm = host(scope, repo, timers)

        sm.dispatch(CallEvent.StartOutgoing("call-1", peer, isVideo = false))
        runCurrent()
        assertTrue(sm.state.value is CallState.Dialing)
        assertEquals(listOf("call-1"), repo.invited)
        assertTrue(timers.isArmed(TimerKey.INVITE))

        sm.dispatch(CallEvent.RemoteAccepted("call-1"))
        runCurrent()
        assertTrue(sm.state.value is CallState.Connecting)
        assertTrue(timers.cancelled.contains(TimerKey.INVITE))

        clockMs = 2_000L
        sm.dispatch(CallEvent.IceConnected)
        runCurrent()
        val active = sm.state.value
        assertTrue(active is CallState.Active)
        assertEquals(2_000L, (active as CallState.Active).startedAtMs)

        clockMs = 5_000L
        sm.dispatch(CallEvent.HangUp)
        runCurrent()
        // HangUp from Active -> Ending; the host's end POST was issued.
        assertTrue(sm.state.value is CallState.Ending)
        assertEquals(1, repo.ended.size)
        assertEquals("hangup", repo.ended.first().second)

        scope.coroutineContext[Job]?.cancel()
    }

    @Test
    fun inviteTimeout_firedByScheduler_endsTimedOut_andPostsTimeout() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = RecordingCallRepository()
        val timers = FakeCallTimerScheduler()
        val sm = host(scope, repo, timers)

        sm.dispatch(CallEvent.StartOutgoing("call-1", peer, isVideo = false))
        runCurrent()

        // Fire the armed INVITE timer (deterministic; no advanceUntilIdle on an infinite flow).
        timers.fire(TimerKey.INVITE)
        runCurrent()

        val ended = sm.state.value
        assertTrue(ended is CallState.Ended)
        assertEquals(EndReason.TIMED_OUT, (ended as CallState.Ended).reason)
        assertEquals(listOf("call-1"), repo.timedOut)

        scope.coroutineContext[Job]?.cancel()
    }

    @Test
    fun incomingAccept_postsAccept() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = RecordingCallRepository()
        val sm = host(scope, repo)

        sm.dispatch(CallEvent.IncomingInvite("call-1", peer, isVideo = false))
        runCurrent()
        assertTrue(sm.state.value is CallState.IncomingRinging)

        sm.dispatch(CallEvent.Accept)
        runCurrent()
        assertTrue(sm.state.value is CallState.Connecting)
        assertEquals(listOf("call-1"), repo.accepted)

        scope.coroutineContext[Job]?.cancel()
    }

    @Test
    fun inviteFailure_surfacesErrorEffect_andTearsDown() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = RecordingCallRepository(inviteSucceeds = false)
        val sm = host(scope, repo)

        val effects = mutableListOf<CallEffect>()
        val effectJob = launch { sm.effects.collect { effects += it } }
        runCurrent()

        sm.dispatch(CallEvent.StartOutgoing("call-1", peer, isVideo = false))
        runCurrent()

        assertTrue(effects.any { it is CallEffect.Error })
        // HangUp self-dispatched -> Ending then teardown.
        assertTrue(sm.state.value is CallState.Ending)

        effectJob.cancel()
        scope.coroutineContext[Job]?.cancel()
    }

    @Test
    fun callBusy_secondCall_surfacesCallBusyEffect_stateUnchanged() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val sm = host(scope)

        val effects = mutableListOf<CallEffect>()
        val effectJob = launch { sm.effects.collect { effects += it } }

        sm.dispatch(CallEvent.StartOutgoing("call-1", peer, isVideo = false))
        runCurrent()
        sm.dispatch(CallEvent.RemoteAccepted("call-1"))
        sm.dispatch(CallEvent.IceConnected)
        runCurrent()
        assertTrue(sm.state.value is CallState.Active)

        sm.dispatch(CallEvent.StartOutgoing("call-2", PeerRef("p2", "c2", "Bo"), isVideo = false))
        runCurrent()
        assertTrue(sm.state.value is CallState.Active)
        assertTrue(effects.contains(CallEffect.CallBusy))

        effectJob.cancel()
        scope.coroutineContext[Job]?.cancel()
    }

    @Test
    fun snapshotSavedOnNonTerminal_clearedOnEnded() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val store = InMemoryCallSnapshotStore()
        val sm = host(scope, store = store)

        sm.dispatch(CallEvent.StartOutgoing("call-1", peer, isVideo = false))
        runCurrent()
        assertTrue(store.load() != null)
        assertEquals("call-1", store.load()!!.callId)

        sm.dispatch(CallEvent.RemoteDeclined("call-1"))
        runCurrent()
        assertTrue(sm.state.value is CallState.Ended)
        assertEquals(null, store.load())

        scope.coroutineContext[Job]?.cancel()
    }
}
