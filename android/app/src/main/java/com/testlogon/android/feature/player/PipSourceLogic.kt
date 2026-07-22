package com.testlogon.android.feature.player

/**
 * AND-PIP-CALL — pure, JVM-testable Picture-in-Picture SOURCE selection + call-eligibility logic.
 *
 * PiP now supports TWO kinds of floating content:
 *  - [PipSourceKind.MEDIA3]  — the existing media3 [androidx.media3.common.Player] surface (VOD,
 *    broadcast viewer, messaging video, newsfeed video). Rendered by a video-only PlayerView.
 *  - [PipSourceKind.CALL]    — a LIVE WebRTC video call: the remote participant's LiveKit VideoTrack
 *    rendered by a SurfaceViewRenderer. NOT a media3 Player, so it needs its own render branch.
 *
 * This object keeps the two decisions that must be correct — WHICH source the Activity collapses to in
 * PiP, and WHETHER an active call is even PiP-eligible — out of the Android-touching controller so they
 * are unit-testable without an emulator. All Android/PiP-param math continues to live in [PipParamsLogic].
 */
object PipSourceLogic {

    /** Which kind of content the PiP window should render, or none. */
    enum class PipSourceKind { NONE, MEDIA3, CALL }

    /**
     * Decide which PiP source is active given the two independent registrations. A CALL takes
     * precedence over a media3 player when both are somehow registered (you cannot be watching a VOD
     * and be in a live video call rendering into the same window; the call is the higher-intent
     * foreground activity). Media3 is selected whenever a player is active and no call is. NONE means
     * nothing is eligible — the Activity keeps the normal app shell even if the system forces PiP.
     *
     * @param callActive   true when a CONNECTED VIDEO call is registered (see [isCallPipEligible]).
     * @param media3Active true when a media3 player is registered as the active/PiP video.
     */
    fun selectSource(callActive: Boolean, media3Active: Boolean): PipSourceKind = when {
        callActive -> PipSourceKind.CALL
        media3Active -> PipSourceKind.MEDIA3
        else -> PipSourceKind.NONE
    }

    /**
     * A call is PiP-eligible ONLY when it is a VIDEO call that is CONNECTED. An audio-only call has
     * nothing to show in the floating window (it just keeps running in the ConnectionService), and a
     * not-yet-connected / ended call must never arm auto-enter. Parameterized (no Android types) so it
     * is pure/testable.
     *
     * @param isVideoCall true when the active call's mode is VIDEO.
     * @param isConnected true when the call has reached the Connected phase (media flowing) and is not terminal.
     */
    fun isCallPipEligible(isVideoCall: Boolean, isConnected: Boolean): Boolean =
        isVideoCall && isConnected

    /**
     * Whether the Activity should auto-enter PiP on user-leave (Home press) for a CALL. Same predicate
     * as [isCallPipEligible] gated on PiP support — mirrors [PipParamsLogic.shouldAutoEnterOnLeave] for
     * the media3 path so both branches behave consistently and are testable.
     */
    fun shouldAutoEnterCallOnLeave(callPipEligible: Boolean, pipSupported: Boolean): Boolean =
        callPipEligible && pipSupported
}
