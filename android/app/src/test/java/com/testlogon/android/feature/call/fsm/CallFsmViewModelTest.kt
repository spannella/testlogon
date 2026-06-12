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
 * AND-305 — thin [CallFsmViewModel] / [IncomingCallFsmViewModel] over a REAL [CallStateMachine] (the
 * established "real host + fakes" idiom from InCallViewModelTest). Reads uiState.value AFTER runCurrent
 * (NEVER advanceUntilIdle on the stateIn(WhileSubscribed) / the infinite 1Hz ticker).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CallFsmViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule(UnconfinedTestDispatcher())

    private val peer = PeerRef("peer", "conv", "Alex")
    private var clockMs = 1_000L

    private fun stateMachine(scope: CoroutineScope, repo: RecordingCallRepository): CallStateMachine =
        CallStateMachine(
            repo = repo,
            timers = FakeCallTimerScheduler(),
            snapshotStore = InMemoryCallSnapshotStore(),
            signaling = StubSignalingTransport(),
            clock = Clock { clockMs },
            scope = scope,
        )

    @Test
    fun uiState_projectsActiveWithDuration() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = RecordingCallRepository()
        clockMs = 1_000L
        val sm = stateMachine(scope, repo)
        val vm = CallFsmViewModel(sm, Clock { clockMs })

        val collectJob = launch { vm.uiState.collect {} }
        runCurrent()

        sm.dispatch(CallEvent.StartOutgoing("call-1", peer, isVideo = true))
        runCurrent()
        assertEquals(CallPhaseLabel.DIALING, vm.uiState.value.phaseLabel)
        assertEquals("Alex", vm.uiState.value.peerName)
        assertTrue(vm.uiState.value.isVideo)

        sm.dispatch(CallEvent.RemoteAccepted("call-1"))
        clockMs = 2_000L
        sm.dispatch(CallEvent.IceConnected)
        runCurrent()
        assertEquals(CallPhaseLabel.ACTIVE, vm.uiState.value.phaseLabel)

        // Advance the clock; the ticker re-projects duration relative to startedAtMs (2_000L).
        clockMs = 5_000L
        runCurrent()
        assertEquals(CallPhaseLabel.ACTIVE, vm.uiState.value.phaseLabel)

        collectJob.cancel()
        scope.coroutineContext[Job]?.cancel()
    }

    @Test
    fun onIntent_hangUp_dispatchesAndEndsCall() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = RecordingCallRepository()
        val sm = stateMachine(scope, repo)
        val vm = CallFsmViewModel(sm, Clock { clockMs })

        val collectJob = launch { vm.uiState.collect {} }
        runCurrent()

        sm.dispatch(CallEvent.StartOutgoing("call-1", peer, isVideo = false))
        runCurrent()
        vm.onIntent(CallIntent.HangUp)
        runCurrent()

        assertTrue(sm.state.value is CallState.Ending || sm.state.value is CallState.Ended)
        assertEquals(1, repo.ended.size)

        collectJob.cancel()
        scope.coroutineContext[Job]?.cancel()
    }

    @Test
    fun startOutgoingIntent_mintsCallId_andInvites() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = RecordingCallRepository()
        val sm = stateMachine(scope, repo)
        val vm = CallFsmViewModel(sm, Clock { clockMs })

        val collectJob = launch { vm.uiState.collect {} }
        runCurrent()

        vm.onIntent(CallIntent.StartOutgoing(peer, isVideo = false))
        runCurrent()
        assertTrue(sm.state.value is CallState.Dialing)
        assertEquals(1, repo.invited.size)

        collectJob.cancel()
        scope.coroutineContext[Job]?.cancel()
    }

    @Test
    fun incomingViewModel_exposesRingingSlice_andAcceptDecline() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = RecordingCallRepository()
        val sm = stateMachine(scope, repo)
        val vm = IncomingCallFsmViewModel(sm)

        val collectJob = launch { vm.uiState.collect {} }
        runCurrent()
        assertEquals(false, vm.uiState.value.isRinging)

        sm.dispatch(CallEvent.IncomingInvite("call-1", peer, isVideo = false))
        runCurrent()
        assertTrue(vm.uiState.value.isRinging)
        assertEquals("call-1", vm.uiState.value.callId)

        vm.accept()
        runCurrent()
        assertEquals(false, vm.uiState.value.isRinging)
        assertEquals(listOf("call-1"), repo.accepted)

        collectJob.cancel()
        scope.coroutineContext[Job]?.cancel()
    }
}
