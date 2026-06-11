package com.testlogon.android.data.webrtc

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-292/294 — asserts the FLAGGED device-enumeration stub never opens hardware: it returns an EMPTY
 * inventory and the selection state collapses to "no camera" with all camera controls disabled, and never
 * marks capture configured. Complements [WebRtcStubsTest] (publisher/controller/transport stubs) — does not
 * duplicate it.
 */
class MediaCaptureStubsTest {

    @Test
    fun stubProvider_enumeratesEmpty_neverOpensHardware() = runTest {
        val provider = StubMediaDeviceProvider()
        val devices = provider.enumerate()
        assertSame(MediaDevices.EMPTY, devices)
        assertTrue(devices.devices.isEmpty())
        assertEquals(0, devices.cameraCount)
        assertFalse(devices.hasCamera)
        assertFalse(devices.hasMultipleCameras)
    }

    @Test
    fun stubProvider_inventory_drivesSelectionToDisabledControls() = runTest {
        val provider = StubMediaDeviceProvider()
        val state = CaptureSelectionReducer.onDevicesEnumerated(
            CaptureSelectionState(),
            provider.enumerate(),
        )
        assertTrue(state.hasNoCamera)
        assertFalse(state.canSwitchCamera)
        // Nothing here configured capture / opened a device.
        assertFalse(state.captureConfigured)
        // switchCamera + toggles remain safe no-ops / pure flips on an empty inventory.
        assertSame(state, CaptureSelectionReducer.switchCamera(state))
    }
}
