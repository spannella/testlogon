package com.testlogon.android.data.webrtc

/**
 * AND-293 — pure (SDK-free) video-renderer model: scaling + mirror + role.
 *
 * These types describe HOW a video track should be painted (aspect handling, horizontal mirror) without
 * referencing org.webrtc.SurfaceViewRenderer / RendererCommon. A real renderer (a future ticket, behind
 * the native WebRTC SDK) maps [VideoScaling] to `RendererCommon.ScalingType` and [mirror] to
 * `SurfaceViewRenderer.setMirror`; until then the [com.testlogon.android.core.webrtc.ui.VideoRenderer]
 * seam paints a placeholder. The mapping is exposed as pure functions so it stays JVM-unit-testable.
 */
enum class VideoScaling {
    /** Letterbox, no crop (maps to SCALE_ASPECT_FIT). */
    FIT,

    /** Crop to fill (maps to SCALE_ASPECT_BALANCED matched / SCALE_ASPECT_FILL mismatched). */
    FILL,
}

/** The SDK-free mirror of org.webrtc.RendererCommon.ScalingType (so mapping is testable without the SDK). */
enum class RendererScalingType { SCALE_ASPECT_FIT, SCALE_ASPECT_BALANCED, SCALE_ASPECT_FILL }

/** Which side of a call a renderer paints (drives default mirroring + placeholder copy). */
enum class VideoRole { LOCAL, REMOTE }

/**
 * AND-293 — pure scaling/attach mapping helpers (AND-293 §4 / §11). Extracted so they are unit-testable
 * without composing or touching the SDK.
 */
object VideoRendererMapping {

    /** The "fit" component of `setScalingType(fit, fill)` for the given [VideoScaling]. */
    fun toFitType(scaling: VideoScaling): RendererScalingType = when (scaling) {
        VideoScaling.FIT -> RendererScalingType.SCALE_ASPECT_FIT
        VideoScaling.FILL -> RendererScalingType.SCALE_ASPECT_BALANCED
    }

    /** The "fill" (mismatched-aspect) component of `setScalingType(fit, fill)`. */
    fun toFillType(scaling: VideoScaling): RendererScalingType = when (scaling) {
        VideoScaling.FIT -> RendererScalingType.SCALE_ASPECT_FIT
        VideoScaling.FILL -> RendererScalingType.SCALE_ASPECT_FILL
    }

    /**
     * Track-swap decision by reference identity (AND-293 §6 identity contract): a sink re-attach is needed
     * only when the next track is a different instance than the currently attached one.
     */
    fun shouldSwap(current: Any?, next: Any?): Boolean = current !== next

    /** Default mirroring: local (front camera) is mirrored; remote is not (AND-293 FR-2 / §2). */
    fun defaultMirror(role: VideoRole): Boolean = role == VideoRole.LOCAL
}
