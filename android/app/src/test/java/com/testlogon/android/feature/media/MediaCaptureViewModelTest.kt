package com.testlogon.android.feature.media

import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.webrtc.BroadcastPublisher
import com.testlogon.android.data.webrtc.CameraFacing
import com.testlogon.android.data.webrtc.GoLiveResult
import com.testlogon.android.data.webrtc.MediaDevice
import com.testlogon.android.data.webrtc.MediaDeviceKind
import com.testlogon.android.data.webrtc.MediaDeviceProvider
import com.testlogon.android.data.webrtc.MediaDevices
import com.testlogon.android.data.webrtc.PublishState
import com.testlogon.android.data.webrtc.ResolutionPreset
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-292/294 — MediaCaptureViewModel: device enumeration wiring + pure selection actions + the FLAGGED
 * capture-start path. Asserts the default-bound stub provider yields disabled camera controls and the stub
 * publisher resolves capture to "unavailable" (never reaches a configured/LIVE state).
 */
class MediaCaptureViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private fun sampleDevice(id: String, kind: MediaDeviceKind, facing: CameraFacing = CameraFacing.UNKNOWN) =
        MediaDevice(id = id, kind = kind, label = id, facing = facing)

    /** Mirrors the bound StubMediaDeviceProvider (EMPTY) by default; can return a fixture inventory. */
    private class FixtureDeviceProvider(private val devices: MediaDevices) : MediaDeviceProvider {
        override suspend fun enumerate(): MediaDevices = devices
    }

    /** Mirrors the bound StubBroadcastPublisher: always NotConfigured, never starts. */
    private class StubLikePublisher(
        var result: GoLiveResult = GoLiveResult.NotConfigured,
    ) : BroadcastPublisher {
        var goLiveCalls = 0
        var stopCalls = 0
        private val _state = MutableStateFlow<PublishState>(PublishState.Unavailable)
        override val state: StateFlow<PublishState> = _state
        override suspend fun goLive(sessionId: String, inputId: String): GoLiveResult {
            goLiveCalls++
            return result
        }
        override fun stop() { stopCalls++ }
    }

    private val dualCams = MediaDevices(
        listOf(
            sampleDevice("cam_front", MediaDeviceKind.CAMERA, CameraFacing.FRONT),
            sampleDevice("cam_back", MediaDeviceKind.CAMERA, CameraFacing.BACK),
            sampleDevice("mic_0", MediaDeviceKind.MICROPHONE),
        ),
    )

    private fun viewModel(
        provider: MediaDeviceProvider = FixtureDeviceProvider(MediaDevices.EMPTY),
        publisher: BroadcastPublisher = StubLikePublisher(),
    ) = MediaCaptureViewModel(deviceProvider = provider, publisher = publisher)

    @Test
    fun init_withStubProvider_yieldsDisabledCameraControls() = runTest {
        val vm = viewModel()
        advanceUntilIdle()
        val s = vm.uiState.value.selection
        assertTrue(s.hasNoCamera)
        assertFalse(s.canSwitchCamera)
        assertFalse(s.captureConfigured)
    }

    @Test
    fun init_withDualCameraFixture_selectsFrontAndEnablesSwitch() = runTest {
        val vm = viewModel(provider = FixtureDeviceProvider(dualCams))
        advanceUntilIdle()
        val s = vm.uiState.value.selection
        assertEquals("cam_front", s.selectedCameraId)
        assertTrue(s.isFrontFacing)
        assertTrue(s.canSwitchCamera)
    }

    @Test
    fun switchCamera_flipsFacing() = runTest {
        val vm = viewModel(provider = FixtureDeviceProvider(dualCams))
        advanceUntilIdle()
        vm.onSwitchCamera()
        assertEquals("cam_back", vm.uiState.value.selection.selectedCameraId)
        assertFalse(vm.uiState.value.selection.isFrontFacing)
    }

    @Test
    fun toggleMute_and_toggleCamera_flipFlags() = runTest {
        val vm = viewModel(provider = FixtureDeviceProvider(dualCams))
        advanceUntilIdle()
        vm.onToggleMute()
        assertTrue(vm.uiState.value.selection.micMuted)
        vm.onToggleCamera()
        assertTrue(vm.uiState.value.selection.cameraOff)
    }

    @Test
    fun selectResolution_updatesState() = runTest {
        val vm = viewModel(provider = FixtureDeviceProvider(dualCams))
        advanceUntilIdle()
        vm.onSelectResolution(ResolutionPreset.FHD_1080)
        assertEquals(ResolutionPreset.FHD_1080, vm.uiState.value.selection.resolution)
    }

    @Test
    fun startCapture_withStubPublisher_resolvesUnavailable_neverConfigured() = runTest {
        val publisher = StubLikePublisher(result = GoLiveResult.NotConfigured)
        val vm = viewModel(publisher = publisher)
        val effects = mutableListOf<MediaCaptureEffect>()
        val job = launch { vm.effects.collect { effects += it } }

        vm.onStartCapture("bcs_1", "in_1")
        advanceUntilIdle()

        assertEquals(1, publisher.goLiveCalls)
        assertTrue(vm.uiState.value.broadcastingUnavailable)
        assertFalse(vm.uiState.value.starting)
        assertFalse(vm.uiState.value.selection.captureConfigured)
        assertTrue(
            effects.any {
                it is MediaCaptureEffect.Notice &&
                    it.kind == MediaCaptureNotice.CAPTURE_UNAVAILABLE
            },
        )
        job.cancel()
    }
}
