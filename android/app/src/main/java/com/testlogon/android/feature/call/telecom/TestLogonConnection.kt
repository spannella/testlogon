package com.testlogon.android.feature.call.telecom

import android.os.Build
import android.telecom.CallAudioState
import android.telecom.Connection
import android.telecom.DisconnectCause
import android.telecom.TelecomManager
import androidx.annotation.RequiresApi
import com.testlogon.android.core.call.audio.CallAudioRouter

/**
 * AND-304 — the self-managed OS [Connection] for one TestLogon call.
 *
 * Bridges the system call surface (lock-screen answer, wired-headset/Bluetooth buttons, audio focus, DND)
 * to the app's control plane via [CallSignaling], and mirrors the system audio state into [CallAudioRouter].
 * Self-managed (PROPERTY_SELF_MANAGED) + VoIP audio mode; API 26+ (the whole self-managed surface is gated
 * upstream in [TelecomCallController], so this class is @RequiresApi 26).
 *
 * Lifecycle hygiene (FR-9): on any terminal callback the connection sets a DisconnectCause, removes itself
 * from the [registry] (no leak / phantom call), and destroys. Every override is otherwise a thin, ordered
 * pair of "tell the OS" + "tell the app".
 *
 * STOP-AND-FLAG: call MEDIA is FLAGGED — the router manages audio focus/route but no WebRTC track exists, so
 * an answered connection is "active" to the OS without a live stream until the native SDK is wired.
 */
@RequiresApi(Build.VERSION_CODES.O)
class TestLogonConnection(
    private val callId: String,
    displayName: String?,
    private val signaling: CallSignaling,
    private val audioRouter: CallAudioRouter,
    private val registry: ConnectionRegistry,
) : Connection() {

    init {
        connectionProperties = PROPERTY_SELF_MANAGED
        audioModeIsVoip = true
        connectionCapabilities = CAPABILITY_HOLD or CAPABILITY_SUPPORT_HOLD or CAPABILITY_MUTE
        displayName?.let { setCallerDisplayName(it, TelecomManager.PRESENTATION_ALLOWED) }
    }

    /** User answered (lock-screen / headset): go active, request focus, accept on the backend. */
    override fun onAnswer() {
        setActive()
        audioRouter.resume()
        signaling.accept(callId)
    }

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onAnswer(videoState: Int) = onAnswer()

    /** User rejected: decline on the backend, mark rejected, destroy. */
    override fun onReject() {
        signaling.decline(callId)
        finishWith(DisconnectCause(DisconnectCause.REJECTED))
    }

    /** User/OS ended an active call: hang up on the backend, mark local disconnect, destroy. */
    override fun onDisconnect() {
        signaling.hangup(callId)
        finishWith(DisconnectCause(DisconnectCause.LOCAL))
    }

    /** Outgoing not-yet-connected call aborted: cancel + destroy (no backend hangup needed). */
    override fun onAbort() {
        finishWith(DisconnectCause(DisconnectCause.CANCELED))
    }

    /** Held: tell the OS + abandon focus (the router pauses). */
    override fun onHold() {
        setOnHold()
        audioRouter.pause()
    }

    /** Resumed from hold: go active + reacquire focus. */
    override fun onUnhold() {
        setActive()
        audioRouter.resume()
    }

    /** System audio state changed (route/mute) — mirror into the router's StateFlow. */
    override fun onCallAudioStateChanged(state: CallAudioState) {
        audioRouter.onSystemAudioState(state)
    }

    /** Logged for completeness; the app's own lifecycle is driven by CallManager, not this state. */
    override fun onStateChanged(state: Int) {
        super.onStateChanged(state)
    }

    /** Sets the disconnect cause, drops the registry reference, and destroys the OS connection. */
    private fun finishWith(cause: DisconnectCause) {
        setDisconnected(cause)
        audioRouter.pause()
        registry.remove(callId)
        destroy()
    }
}
