package com.testlogon.android.data.webrtc

import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-292 — device-enumeration seam (SCAFFOLD — FLAGGED stub default; never opens hardware).
 *
 * STOP-AND-FLAG (the native WebRTC SDK is a HUMAN-DECISION vendor SDK): a real implementation would walk
 * `org.webrtc.Camera2Enumerator`/`Camera1Enumerator` for cameras and read `AudioManager`/
 * `AudioDeviceInfo` for mics + audio outputs to populate [MediaDevices]. The actual capture START still
 * lives behind the FLAGGED [BroadcastPublisher] (NotConfigured), so even a real provider would only
 * *enumerate* — it would never open a camera/mic. This mirrors the existing stub-seam pattern
 * ([com.testlogon.android.data.billing.CardTokenizer] / [com.testlogon.android.data.payouts.KycVerifier]).
 *
 * [StubMediaDeviceProvider] is bound by default and returns an EMPTY inventory: it NEVER touches
 * Camera2/AudioManager/hardware, NEVER opens a device. The selection state machine ([CaptureSelectionState]
 * / [CaptureSelectionReducer]) operates purely on whatever inventory the provider returns, so it is fully
 * unit-testable with a fixture inventory and never depends on a device.
 */
fun interface MediaDeviceProvider {

    /**
     * Enumerate the currently available capture/output devices. The stub returns [MediaDevices.EMPTY].
     * Suspend so a real implementation can do the (cheap, but off-main) enumeration without blocking.
     */
    suspend fun enumerate(): MediaDevices
}

/**
 * AND-292 — default (FLAGGED) provider. NEVER opens a camera/mic, NEVER reads AudioManager/Camera2; always
 * returns [MediaDevices.EMPTY]. The real (enumeration-only) binding replaces this @Binds once the native
 * WebRTC SDK decision is made. Capture START remains owned by the FLAGGED [BroadcastPublisher].
 */
@Singleton
class StubMediaDeviceProvider @Inject constructor() : MediaDeviceProvider {
    override suspend fun enumerate(): MediaDevices = MediaDevices.EMPTY
}
