package com.testlogon.android.feature.call.incall

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.call.CallAction
import com.testlogon.android.data.call.CallBillingStatus
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
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-298 — [InCallViewModel] tests. Drives a REAL [CallManager] (the FLAGGED WebRTC stubs return
 * NotConfigured, so no real peer/media is created) and asserts the VM maps the lifecycle and owns the local
 * optimistic media-control state. Mirrors the OutgoingCallViewModelTest fakes/stubs idiom (no mockk in the
 * project; Mockito is the mocking lib but a real CallManager + fakes is the established pattern here).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class InCallViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule(UnconfinedTestDispatcher())

    private class CountingRepo : CallRepository {
        var endCount = 0
        override suspend fun invite(
            callId: String, conversationId: String, calleeUserId: String, mode: CallMode,
            idempotencyKey: String?, paid: Boolean, rateCentsPerMin: Int?,
        ): ApiResult<CallInvited> =
            ApiResult.Success(CallInvited(callId, conversationId, "self", calleeUserId, "ringing", mode, 0, false, null))
        override suspend fun accept(callId: String, idempotencyKey: String?) = ok(callId)
        override suspend fun decline(callId: String, reason: String) = ok(callId)
        override suspend fun end(callId: String, reason: String, idempotencyKey: String?): ApiResult<CallAction> {
            endCount++
            return ok(callId)
        }
        override suspend fun timeout(callId: String, reason: String, idempotencyKey: String?) = ok(callId)
        override suspend fun heartbeat(callId: String, clientTsEpochSeconds: Long?) =
            ApiResult.Success(CallHeartbeat(callId, 0, 0, 0, 0, 0, false, 10.0, false, "ok"))
        override suspend fun billing(callId: String) =
            ApiResult.Success(CallBillingStatus(callId, false, 0, 0, 0, 0, 0, ""))
        override suspend fun history(cursor: String?, limit: Int?) =
            ApiResult.Success(CallHistoryPage(emptyList(), null))
        private fun ok(callId: String): ApiResult<CallAction> =
            ApiResult.Success(CallAction(callId, "conv", "ended", 0, null, null, false))
    }

    private fun manager(scope: CoroutineScope, repo: CountingRepo): CallManager = CallManager(
        callRepository = repo,
        iceServers = object : IceServersProvider {
            override suspend fun current(callId: String) = listOf(IceServer(urls = listOf("stun:x")))
        },
        peer = StubPeerConnectionController(),
        signaling = StubSignalingTransport(),
        clock = Clock { 0L },
        scope = scope,
        timing = CallTiming(),
    )

    private fun vm(callManager: CallManager): InCallViewModel =
        InCallViewModel(callManager, CallStatsSampler(), SavedStateHandle())

    @Test
    fun connectedVideo_mapsLifecycleAndIsVideo_withDuration() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = CountingRepo()
        val callManager = manager(scope, repo)
        callManager.placeCall("conv", "peer", CallMode.VIDEO, "Alex")
        callManager.onConnected()

        val viewModel = vm(callManager)
        val job = launch { viewModel.uiState.collect {} }
        runCurrent()

        val state = viewModel.uiState.value
        assertEquals(InCallLifecycle.Connected, state.lifecycle)
        assertTrue(state.isVideoCall)
        assertTrue(state.durationLabel.isNotEmpty())

        job.cancel()
        scope.coroutineContext[Job]?.cancel()
    }

    @Test
    fun endCall_isIdempotent_callsEndExactlyOnce() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = CountingRepo()
        val callManager = manager(scope, repo)
        callManager.placeCall("conv", "peer", CallMode.AUDIO, "Alex")
        callManager.onConnected()

        val viewModel = vm(callManager)
        val job = launch { viewModel.uiState.collect {} }
        runCurrent()

        viewModel.onAction(InCallAction.EndCall)
        viewModel.onAction(InCallAction.EndCall)
        runCurrent()

        assertEquals(1, repo.endCount)

        job.cancel()
        scope.coroutineContext[Job]?.cancel()
    }

    @Test
    fun toggleMic_flipsMicEnabled() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val callManager = manager(scope, CountingRepo())
        callManager.placeCall("conv", "peer", CallMode.AUDIO, "Alex")
        callManager.onConnected()

        val viewModel = vm(callManager)
        val job = launch { viewModel.uiState.collect {} }
        runCurrent()

        assertTrue(viewModel.uiState.value.micEnabled)
        viewModel.onAction(InCallAction.ToggleMic)
        runCurrent()
        assertFalse(viewModel.uiState.value.micEnabled)

        job.cancel()
        scope.coroutineContext[Job]?.cancel()
    }

    @Test
    fun toggleCamera_flipsInVideo_butNoOpInAudioOnly() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))

        // Video call: camera toggles.
        val videoManager = manager(scope, CountingRepo())
        videoManager.placeCall("conv", "peer", CallMode.VIDEO, "Alex")
        videoManager.onConnected()
        val videoVm = vm(videoManager)
        val videoJob = launch { videoVm.uiState.collect {} }
        runCurrent()
        assertTrue(videoVm.uiState.value.cameraEnabled)
        videoVm.onAction(InCallAction.ToggleCamera)
        runCurrent()
        assertFalse(videoVm.uiState.value.cameraEnabled)
        videoJob.cancel()

        // Audio-only call (a separate manager instance, so the single-active guard does not interfere).
        val audioManager = manager(scope, CountingRepo())
        audioManager.placeCall("conv2", "peer2", CallMode.AUDIO, "Bo")
        audioManager.onConnected()
        val audioVm = vm(audioManager)
        val audioJob = launch { audioVm.uiState.collect {} }
        runCurrent()
        assertTrue(audioVm.uiState.value.cameraEnabled)
        audioVm.onAction(InCallAction.ToggleCamera)
        runCurrent()
        assertTrue(audioVm.uiState.value.cameraEnabled)
        audioJob.cancel()

        scope.coroutineContext[Job]?.cancel()
    }
}
