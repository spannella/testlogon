package com.testlogon.android.data.webrtc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-292/294 — pure device-selection state-machine tests. No hardware, no SDK, no coroutines: the reducer
 * is a pure function of (state, inventory). Complements (does not duplicate) the existing
 * [WebRtcStubsTest] (stub seams) and [PeerLifecycleReducerTest] (peer reducer).
 */
class CaptureSelectionReducerTest {

    private fun sampleDevice(
        id: String,
        kind: MediaDeviceKind,
        facing: CameraFacing = CameraFacing.UNKNOWN,
        output: AudioOutputKind = AudioOutputKind.UNKNOWN,
    ) = MediaDevice(id = id, kind = kind, label = id, facing = facing, audioOutputKind = output)

    private val frontCam = sampleDevice("cam_front", MediaDeviceKind.CAMERA, CameraFacing.FRONT)
    private val backCam = sampleDevice("cam_back", MediaDeviceKind.CAMERA, CameraFacing.BACK)
    private val mic = sampleDevice("mic_0", MediaDeviceKind.MICROPHONE)
    private val earpiece =
        sampleDevice("out_ear", MediaDeviceKind.AUDIO_OUTPUT, output = AudioOutputKind.EARPIECE)
    private val speaker =
        sampleDevice("out_spk", MediaDeviceKind.AUDIO_OUTPUT, output = AudioOutputKind.SPEAKER)

    private val dualCamInventory =
        MediaDevices(listOf(frontCam, backCam, mic, earpiece, speaker))

    private fun seeded(devices: MediaDevices = dualCamInventory): CaptureSelectionState =
        CaptureSelectionReducer.onDevicesEnumerated(CaptureSelectionState(), devices)

    @Test
    fun onDevicesEnumerated_selectsFrontCameraFirstMicFirstOutput_byDefault() {
        val s = seeded()
        assertEquals("cam_front", s.selectedCameraId)
        assertEquals("mic_0", s.selectedMicId)
        assertEquals("out_ear", s.selectedAudioOutputId)
        assertTrue(s.isFrontFacing)
        assertEquals(2, s.cameraCount)
        assertTrue(s.canSwitchCamera)
        assertFalse(s.hasNoCamera)
        // Capture is NEVER configured by selection alone (engine FLAGGED).
        assertFalse(s.captureConfigured)
    }

    @Test
    fun onDevicesEnumerated_emptyInventory_disablesCameraControls() {
        val s = seeded(MediaDevices.EMPTY)
        assertNull(s.selectedCameraId)
        assertEquals(0, s.cameraCount)
        assertFalse(s.canSwitchCamera)
        assertTrue(s.hasNoCamera)
        // isFrontFacing defaults true (no back camera selected) so mirroring stays in the front default.
        assertTrue(s.isFrontFacing)
    }

    @Test
    fun onDevicesEnumerated_preservesStillPresentPriorSelection() {
        val s = CaptureSelectionReducer.selectCamera(seeded(), "cam_back")
        val reEnum = CaptureSelectionReducer.onDevicesEnumerated(s, dualCamInventory)
        assertEquals("cam_back", reEnum.selectedCameraId)
    }

    @Test
    fun switchCamera_flipsFacing_withTwoCameras() {
        val s = seeded()
        val switched = CaptureSelectionReducer.switchCamera(s)
        assertEquals("cam_back", switched.selectedCameraId)
        assertFalse(switched.isFrontFacing)
        val back = CaptureSelectionReducer.switchCamera(switched)
        assertEquals("cam_front", back.selectedCameraId)
        assertTrue(back.isFrontFacing)
    }

    @Test
    fun switchCamera_isNoOp_withSingleCamera() {
        val single = seeded(MediaDevices(listOf(frontCam, mic)))
        assertEquals(1, single.cameraCount)
        assertFalse(single.canSwitchCamera)
        val switched = CaptureSelectionReducer.switchCamera(single)
        assertSame(single, switched)
        assertEquals("cam_front", switched.selectedCameraId)
    }

    @Test
    fun switchCamera_isNoOp_whenCameraOff() {
        val off = CaptureSelectionReducer.setCameraOff(seeded(), true)
        assertFalse(off.canSwitchCamera)
        assertSame(off, CaptureSelectionReducer.switchCamera(off))
    }

    @Test
    fun selectCamera_unknownId_isIgnored() {
        val s = seeded()
        assertSame(s, CaptureSelectionReducer.selectCamera(s, "nope"))
    }

    @Test
    fun selectMicrophone_and_selectAudioOutput_knownIds() {
        val s = seeded()
        val m = CaptureSelectionReducer.selectMicrophone(s, "mic_0")
        assertEquals("mic_0", m.selectedMicId)
        val o = CaptureSelectionReducer.selectAudioOutput(s, "out_spk")
        assertEquals("out_spk", o.selectedAudioOutputId)
        // Unknown ids ignored.
        assertSame(s, CaptureSelectionReducer.selectMicrophone(s, "mic_x"))
        assertSame(s, CaptureSelectionReducer.selectAudioOutput(s, "out_x"))
    }

    @Test
    fun toggleCamera_and_toggleMute_flipFlags_withoutTeardown() {
        val s = seeded()
        assertFalse(s.cameraOff)
        assertFalse(s.micMuted)
        val camOff = CaptureSelectionReducer.toggleCamera(s)
        assertTrue(camOff.cameraOff)
        assertFalse(CaptureSelectionReducer.toggleCamera(camOff).cameraOff)
        val muted = CaptureSelectionReducer.toggleMute(s)
        assertTrue(muted.micMuted)
        assertFalse(CaptureSelectionReducer.toggleMute(muted).micMuted)
        // Device inventory unchanged by toggles (no re-enumeration / teardown).
        assertEquals(s.devices, muted.devices)
    }

    @Test
    fun setResolution_updatesPreset_dimensionsCorrect() {
        val s = seeded()
        assertEquals(ResolutionPreset.HD_720, s.resolution)
        val fhd = CaptureSelectionReducer.setResolution(s, ResolutionPreset.FHD_1080)
        assertEquals(ResolutionPreset.FHD_1080, fhd.resolution)
        assertEquals(1920, ResolutionPreset.FHD_1080.width)
        assertEquals(1080, ResolutionPreset.FHD_1080.height)
        assertEquals(30, ResolutionPreset.FHD_1080.fps)
        assertEquals(640, ResolutionPreset.SD_480.width)
        assertEquals(1280, ResolutionPreset.HD_720.width)
    }

    @Test
    fun mediaDevices_views_filterByKind() {
        val inv = dualCamInventory
        assertEquals(2, inv.cameras.size)
        assertEquals(1, inv.microphones.size)
        assertEquals(2, inv.audioOutputs.size)
        assertSame(frontCam, inv.defaultCamera)
        assertSame(mic, inv.defaultMicrophone)
        assertSame(earpiece, inv.defaultAudioOutput)
        assertTrue(frontCam.isFrontCamera)
        assertTrue(backCam.isBackCamera)
    }
}
