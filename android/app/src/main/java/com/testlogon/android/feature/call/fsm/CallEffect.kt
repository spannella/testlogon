package com.testlogon.android.feature.call.fsm

/**
 * AND-305 — side effects the canonical call FSM ([CallFsm.reduce]) requests.
 *
 * Pure (android-free) DESCRIPTIONS of work — the reducer NEVER performs IO. The host ([CallStateMachine])
 * interprets each effect against REAL seams: Send* route to the existing
 * [com.testlogon.android.data.call.CallRepository] control-plane ops (invite/accept/decline/end/timeout);
 * [SendSignal] routes to the FLAGGED [com.testlogon.android.data.webrtc.SignalingTransport]; StartTimer/
 * CancelTimer drive [CallTimerScheduler]; PlayRingback/StopAudio/Error/CallBusy are surfaced on the host's
 * one-shot effects flow.
 *
 * The repository methods are REUSED as-is (AND-295) — no method is added to CallRepository (it has multiple
 * fake implementations in tests). Anything the repo lacks is modeled here and handled by the host via an
 * EXISTING seam.
 */
sealed interface CallEffect {

    /** Place the call on the control plane (repo.invite). */
    data class SendInvite(val callId: String, val peer: PeerRef, val isVideo: Boolean) : CallEffect

    /** Accept the call on the control plane (repo.accept). */
    data class SendAccept(val callId: String) : CallEffect

    /** Decline the call on the control plane (repo.decline). */
    data class SendDecline(val callId: String) : CallEffect

    /** End the call on the control plane (repo.end). */
    data class SendEnd(val callId: String, val reason: EndReason) : CallEffect

    /** Report no-answer on the control plane (repo.timeout). */
    data class SendTimeout(val callId: String) : CallEffect

    /** Forward a signaling payload through the FLAGGED transport seam (NotConfigured -> no-op). */
    data class SendSignal(val callId: String, val payload: String) : CallEffect

    /** Arm a bounded timer. */
    data class StartTimer(val key: TimerKey, val delayMs: Long) : CallEffect

    /** Cancel a bounded timer. */
    data class CancelTimer(val key: TimerKey) : CallEffect

    /** Start the outgoing ringback tone. */
    data object PlayRingback : CallEffect

    /** Stop all call audio (ringback/ringtone). */
    data object StopAudio : CallEffect

    /** A recoverable error to surface to the UI. */
    data class Error(val message: String) : CallEffect

    /** The single-call invariant rejected a second concurrent call. */
    data object CallBusy : CallEffect
}
