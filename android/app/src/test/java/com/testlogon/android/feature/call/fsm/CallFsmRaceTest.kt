package com.testlogon.android.feature.call.fsm

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.data.webrtc.StubSignalingTransport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-305 — ordering/race coverage via the host. Events are serialized through the single-consumer Channel,
 * so the FIRST dispatched event wins a race. We drain with runCurrent (NEVER advanceUntilIdle on the host's
 * WhileSubscribed/SharedFlow).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CallFsmRaceTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule(UnconfinedTestDispatcher())

    private val peer = PeerRef("peer", "conv", "Alex")

    private fun host(scope: CoroutineScope, repo: RecordingCallRepository): CallStateMachine =
        CallStateMachine(
            repo = repo,
            timers = FakeCallTimerScheduler(),
            snapshotStore = InMemoryCallSnapshotStore(),
            signaling = StubSignalingTransport(),
            clock = Clock { 1_000L },
            scope = scope,
        )

    @Test
    fun hangUpThenRemoteAccepted_endsLocalHangup() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = RecordingCallRepository()
        val sm = host(scope, repo)

        sm.dispatch(CallEvent.StartOutgoing("call-1", peer, isVideo = false))
        runCurrent()

        // HangUp first: wins the race -> terminal teardown; the later RemoteAccepted is a no-op on Ending.
        sm.dispatch(CallEvent.HangUp)
        sm.dispatch(CallEvent.RemoteAccepted("call-1"))
        runCurrent()

        val state = sm.state.value
        assertTrue(state is CallState.Ending || state is CallState.Ended)
        val reason = when (state) {
            is CallState.Ending -> state.reason
            is CallState.Ended -> state.reason
            else -> null
        }
        assertEquals(EndReason.LOCAL_HANGUP, reason)

        scope.coroutineContext[Job]?.cancel()
    }

    @Test
    fun remoteAcceptedThenHangUp_reachesConnectingFirst() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = RecordingCallRepository()
        val sm = host(scope, repo)

        sm.dispatch(CallEvent.StartOutgoing("call-1", peer, isVideo = false))
        runCurrent()

        // RemoteAccepted first -> Connecting; the later HangUp then moves Connecting -> Ending.
        sm.dispatch(CallEvent.RemoteAccepted("call-1"))
        runCurrent()
        assertTrue(sm.state.value is CallState.Connecting)

        sm.dispatch(CallEvent.HangUp)
        runCurrent()
        val state = sm.state.value
        assertTrue(state is CallState.Ending)
        assertEquals(EndReason.LOCAL_HANGUP, (state as CallState.Ending).reason)

        scope.coroutineContext[Job]?.cancel()
    }
}
