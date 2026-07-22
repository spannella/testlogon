package com.testlogon.android.feature.player

/**
 * AND-287 — pure, JVM-testable Picture-in-Picture params logic shared by [ActivityPipController].
 *
 * Keeps the two decisions that must be correct — the (clamped) aspect ratio and the API-level
 * capability gates for the smoother auto-enter path — out of the Android-touching controller so they
 * can be unit-tested without an emulator. The controller just constructs [android.util.Rational] /
 * [android.app.PictureInPictureParams] from these results.
 *
 * Android rejects PiP aspect ratios outside ~[1:2.39, 2.39:1]; [safeAspect] clamps to that window.
 * The broadcast viewer (live HLS) reuses the same [ActivityPipController] path as VOD/messaging/feed,
 * so getting the aspect right here fixes the floating-window shape for every caller at once.
 */
object PipParamsLogic {

    /** Android's documented PiP aspect bound: width/height must be within [1/MAX .. MAX]. */
    const val MAX_RATIO: Float = 2.39f

    /**
     * Clamp [width]:[height] to the Android-permitted PiP aspect window, returned as a normalized
     * (num, den) pair suitable for [android.util.Rational]. Non-positive inputs fall back to a safe
     * 16:9 landscape default (mirrors the old inline default), never a crash.
     */
    fun safeAspect(width: Int, height: Int): Pair<Int, Int> {
        if (width <= 0 || height <= 0) return 16 to 9
        val ratio = width.toFloat() / height.toFloat()
        return when {
            ratio > MAX_RATIO -> 239 to 100
            ratio < 1f / MAX_RATIO -> 100 to 239
            else -> width to height
        }
    }

    /**
     * Resolve the aspect to use for PiP: prefer the player's real reported video size ([videoWidth]
     * :[videoHeight]) when known (> 0), else the caller-supplied fallback ([fallbackW]:[fallbackH]).
     * Then clamp to the safe window. This lets the live broadcast (and any player) size the floating
     * window to the actual stream instead of a hardcoded 16:9 when the size is available.
     */
    fun resolveAspect(
        videoWidth: Int,
        videoHeight: Int,
        fallbackW: Int,
        fallbackH: Int,
    ): Pair<Int, Int> =
        if (videoWidth > 0 && videoHeight > 0) safeAspect(videoWidth, videoHeight)
        else safeAspect(fallbackW, fallbackH)

    /**
     * True on API 31+ (Android S), where [android.app.PictureInPictureParams.Builder.setAutoEnterEnabled]
     * and setSeamlessResizeEnabled exist. Below S the controller keeps the onUserLeaveHint manual-enter
     * fallback. Parameterized on [sdkInt] so it is pure/testable.
     */
    fun supportsAutoEnter(sdkInt: Int): Boolean = sdkInt >= 31

    /**
     * Whether the Activity should auto-enter PiP on user-leave (Home press) given the current
     * [videoActive] state and PiP [pipSupported]. On API 31+ the system does this via
     * setAutoEnterEnabled; on 26–30 the Activity calls this from onUserLeaveHint. Same predicate either
     * way so behavior is consistent and testable.
     */
    fun shouldAutoEnterOnLeave(videoActive: Boolean, pipSupported: Boolean): Boolean =
        videoActive && pipSupported
}
