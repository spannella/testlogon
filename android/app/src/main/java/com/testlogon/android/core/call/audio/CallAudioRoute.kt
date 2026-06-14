package com.testlogon.android.core.call.audio

import com.testlogon.android.feature.call.incall.AudioRoute

/**
 * AND-304 — pure (android-free) audio-route model for the Telecom audio router.
 *
 * REUSES the existing AND-298 [AudioRoute] (EARPIECE / SPEAKER / BLUETOOTH / WIRED) rather than defining a
 * duplicate enum: that enum already covers every Telecom CallAudioState route the self-managed connection
 * can report, so the in-call UI and the Telecom router speak the same vocabulary. [CallAudioRoute] is a type
 * alias kept for a self-documenting name at the Telecom call sites.
 *
 * STOP-AND-FLAG: the route here reflects the SYSTEM audio state reported by Telecom (which output the OS
 * thinks the call is on); real call MEDIA is FLAGGED (no WebRTC track), so toggling/reading the route never
 * touches a live audio stream — see [com.testlogon.android.data.webrtc.PeerConnectionController].
 */
typealias CallAudioRoute = AudioRoute

/**
 * Immutable snapshot of the call's audio state for the router's StateFlow: the [active] output, the set of
 * [available] outputs the user could switch to, and whether the call mic is [muted]. Defaults to earpiece /
 * earpiece+speaker so a not-yet-reported state renders sensibly.
 */
data class CallAudioStateUi(
    val active: CallAudioRoute = CallAudioRoute.EARPIECE,
    val available: Set<CallAudioRoute> = setOf(CallAudioRoute.EARPIECE, CallAudioRoute.SPEAKER),
    val muted: Boolean = false,
)
