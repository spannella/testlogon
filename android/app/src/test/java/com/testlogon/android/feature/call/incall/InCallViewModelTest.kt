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
        InCallViewModel(
            callManager,
            CallStatsSampler(),
            recordingController(),
            com.testlogon.android.data.webrtc.CallMediaHolder(),
            object : com.testlogon.android.core.webrtc.ui.CallPipSourceFactory {
                override fun source(aspectWidth: Int, aspectHeight: Int) =
                    com.testlogon.android.feature.player.CallPipSource(
                        makeView = { throw UnsupportedOperationException() },
                        releaseView = {},
                    )
            },
            com.testlogon.android.core.data.cache.Clock { 0L },
            SavedStateHandle(),
            com.testlogon.android.core.webrtc.ui.PlaceholderVideoRenderer,
        )

    /**
     * AND-302 — a [RecordingController] backed by a no-op repo + the FLAGGED stub capturer + an in-memory
     * pending DAO. The VM tests only need it constructible (the recording sub-state stays Idle); the
     * recording behaviour itself is covered by RecordingStateMachineTest / RecordingRepositoryContractTest.
     */
    private fun recordingController(): com.testlogon.android.feature.call.recording.RecordingController =
        com.testlogon.android.feature.call.recording.RecordingController(
            repository = object : com.testlogon.android.data.call.recording.RecordingRepository {
                override suspend fun request(callId: String) =
                    ApiResult.Success(
                        com.testlogon.android.data.call.recording.RecordingRequest("r1", "requested", 0),
                    )
                override suspend fun consent(callId: String) =
                    ApiResult.Success(
                        com.testlogon.android.data.call.recording.RecordingConsent("r1", "granted", 1),
                    )
                override suspend fun decline(callId: String) = ApiResult.Success(true)
                override suspend fun presign(callId: String, contentType: String, fileSizeBytes: Long) =
                    ApiResult.Success(
                        com.testlogon.android.data.call.recording.RecordingPresign("http://x", "r1", "k", 0),
                    )
                override suspend fun complete(callId: String, recordingId: String, durationSeconds: Float) =
                    ApiResult.Success(
                        com.testlogon.android.data.call.recording.RecordingComplete("r1", "ready", null, null),
                    )
            },
            capturer = com.testlogon.android.data.call.recording.StubRecordingCapturer(),
            pendingDao = FakePendingRecordingDao(),
            storageClient = com.testlogon.android.data.upload.StorageUploadClient(
                okhttp3.OkHttpClient(),
                org.mockito.Mockito.mock(com.testlogon.android.core.network.SettingsStore::class.java),
            ),
            clock = Clock { 0L },
            scope = CoroutineScope(UnconfinedTestDispatcher()),
        )

    private class FakePendingRecordingDao :
        com.testlogon.android.core.data.call.PendingRecordingDao {
        private val rows = mutableMapOf<String, com.testlogon.android.core.data.call.PendingRecordingEntity>()
        override suspend fun upsert(entity: com.testlogon.android.core.data.call.PendingRecordingEntity) {
            rows[entity.recordingId] = entity
        }
        override suspend fun getAll() = rows.values.toList()
        override fun observe() = kotlinx.coroutines.flow.flowOf(rows.values.toList())
        override suspend fun get(recordingId: String) = rows[recordingId]
        override suspend fun delete(recordingId: String) { rows.remove(recordingId) }
    }

    @Test
    fun connectedVideo_mapsLifecycleAndIsVideo_withDuration() = runTest(mainDispatcher.dispatcher.scheduler) {
        // A child of backgroundScope (so runTest cancels it before its end-of-test idle check, stopping the
        // CallManager heartbeat while-loop + the uiState durationTicker), but UNCONFINED so the eager
        // placeCall/onConnected + stateIn collector run inline and uiState.value is settled after runCurrent().
        val scope = CoroutineScope(backgroundScope.coroutineContext + UnconfinedTestDispatcher(testScheduler))
        val repo = CountingRepo()
        val callManager = manager(scope, repo)
        callManager.placeCall("conv", "peer", CallMode.VIDEO, "Alex")
        callManager.onConnected()

        val viewModel = vm(callManager)
        scope.launch { viewModel.uiState.collect {} }
        runCurrent()

        val state = viewModel.uiState.value
        assertEquals(InCallLifecycle.Connected, state.lifecycle)
        assertTrue(state.isVideoCall)
        assertTrue(state.durationLabel.isNotEmpty())
    }

    @Test
    fun endCall_isIdempotent_callsEndExactlyOnce() = runTest(mainDispatcher.dispatcher.scheduler) {
        // A child of backgroundScope (so runTest cancels it before its end-of-test idle check, stopping the
        // CallManager heartbeat while-loop + the uiState durationTicker), but UNCONFINED so the eager
        // placeCall/onConnected + stateIn collector run inline and uiState.value is settled after runCurrent().
        val scope = CoroutineScope(backgroundScope.coroutineContext + UnconfinedTestDispatcher(testScheduler))
        val repo = CountingRepo()
        val callManager = manager(scope, repo)
        callManager.placeCall("conv", "peer", CallMode.AUDIO, "Alex")
        callManager.onConnected()

        val viewModel = vm(callManager)
        scope.launch { viewModel.uiState.collect {} }
        runCurrent()

        viewModel.onAction(InCallAction.EndCall)
        viewModel.onAction(InCallAction.EndCall)
        runCurrent()

        assertEquals(1, repo.endCount)
    }

    @Test
    fun toggleMic_flipsMicEnabled() = runTest(mainDispatcher.dispatcher.scheduler) {
        // A child of backgroundScope (so runTest cancels it before its end-of-test idle check, stopping the
        // CallManager heartbeat while-loop + the uiState durationTicker), but UNCONFINED so the eager
        // placeCall/onConnected + stateIn collector run inline and uiState.value is settled after runCurrent().
        val scope = CoroutineScope(backgroundScope.coroutineContext + UnconfinedTestDispatcher(testScheduler))
        val callManager = manager(scope, CountingRepo())
        callManager.placeCall("conv", "peer", CallMode.AUDIO, "Alex")
        callManager.onConnected()

        val viewModel = vm(callManager)
        scope.launch { viewModel.uiState.collect {} }
        runCurrent()

        assertTrue(viewModel.uiState.value.micEnabled)
        viewModel.onAction(InCallAction.ToggleMic)
        runCurrent()
        assertFalse(viewModel.uiState.value.micEnabled)
    }

    @Test
    fun toggleCamera_flipsInVideo_butNoOpInAudioOnly() = runTest(mainDispatcher.dispatcher.scheduler) {
        // A child of backgroundScope (so runTest cancels it before its end-of-test idle check, stopping the
        // CallManager heartbeat while-loop + the uiState durationTicker), but UNCONFINED so the eager
        // placeCall/onConnected + stateIn collector run inline and uiState.value is settled after runCurrent().
        val scope = CoroutineScope(backgroundScope.coroutineContext + UnconfinedTestDispatcher(testScheduler))

        // Video call: camera toggles.
        val videoManager = manager(scope, CountingRepo())
        videoManager.placeCall("conv", "peer", CallMode.VIDEO, "Alex")
        videoManager.onConnected()
        val videoVm = vm(videoManager)
        scope.launch { videoVm.uiState.collect {} }
        runCurrent()
        assertTrue(videoVm.uiState.value.cameraEnabled)
        videoVm.onAction(InCallAction.ToggleCamera)
        runCurrent()
        assertFalse(videoVm.uiState.value.cameraEnabled)

        // Audio-only call (a separate manager instance, so the single-active guard does not interfere).
        val audioManager = manager(scope, CountingRepo())
        audioManager.placeCall("conv2", "peer2", CallMode.AUDIO, "Bo")
        audioManager.onConnected()
        val audioVm = vm(audioManager)
        scope.launch { audioVm.uiState.collect {} }
        runCurrent()
        assertTrue(audioVm.uiState.value.cameraEnabled)
        audioVm.onAction(InCallAction.ToggleCamera)
        runCurrent()
        assertTrue(audioVm.uiState.value.cameraEnabled)
    }
}
