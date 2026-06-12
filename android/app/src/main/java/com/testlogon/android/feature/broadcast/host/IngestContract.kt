package com.testlogon.android.feature.broadcast.host

/**
 * AND-308 — PURE (android-free) ingest contract for the host broadcast camera/mic publish flow.
 *
 * The control plane (create / activate / deactivate / remove input) is REAL; the actual media publish is
 * driven by the FLAGGED [com.testlogon.android.data.webrtc.BroadcastPublisher] seam, which always reports
 * not-configured until the native WebRTC SDK is wired. The phase machine surfaces that as [Unavailable].
 */

/** Where the ingest flow currently is. Pure enum so it is JVM-unit-testable without Android. */
enum class IngestPhase {
    /** Nothing started. */
    Idle,

    /** Local preview is available (the placeholder, while FLAGGED) and the host can start. */
    PreviewReady,

    /** The control-plane input is being created (POST inputs). */
    CreatingInput,

    /** The input exists; handing off to the publisher / negotiating the SDP exchange (FLAGGED). */
    Negotiating,

    /** Publishing media (a real engine would reach here). */
    Connected,

    /**
     * Broadcasting is unavailable because the native WebRTC engine is FLAGGED / not configured. This is
     * the terminal state of the FLAGGED happy path.
     */
    Unavailable,

    /** A control-plane or publish attempt failed. */
    Failed,
}

/**
 * AND-308 — ingest UI state. [mediaUnavailable] drives the prominent "broadcasting not configured" banner
 * (set when the FLAGGED publisher reports not-configured); [error] is a redaction-safe message for
 * control-plane failures.
 */
data class IngestUiState(
    val phase: IngestPhase = IngestPhase.PreviewReady,
    val inputId: String? = null,
    val mediaUnavailable: Boolean = false,
    val error: String? = null,
) {
    /** The start ("Go Live") action is offered only before a start attempt is in flight or resolved. */
    val canStart: Boolean
        get() = phase == IngestPhase.Idle || phase == IngestPhase.PreviewReady || phase == IngestPhase.Failed
}
