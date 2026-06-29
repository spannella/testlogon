package com.testlogon.android.feature.player

import android.app.Activity
import android.app.PictureInPictureParams
import android.content.Context
import android.content.ContextWrapper
import android.content.pm.PackageManager
import android.os.Build
import android.util.Rational
import androidx.compose.runtime.staticCompositionLocalOf

/**
 * #8 - Picture-in-Picture entry seam for video playback across the app (My Videos, messaging video,
 * newsfeed video). A player composable calls [enterPip] to put the single hosting MainActivity into
 * the system PiP window so a playing video keeps rendering in a floating window when the user leaves
 * the app.
 *
 * The controller also tracks whether a video is currently "active" (playing/visible) so the
 * Activity's onUserLeaveHint can AUTO-enter PiP (the recommended UX) when the user presses Home while
 * a video is up. A player marks itself active via [setVideoActive] while it is on-screen/playing.
 */
interface PipController {

    /** True if this device/OS supports PiP at all (API 26+ and FEATURE_PICTURE_IN_PICTURE). */
    val isPipSupported: Boolean

    /**
     * Request the hosting Activity enter PiP now, sized to [aspectWidth]:[aspectHeight] (defaults
     * 16:9). No-op (returns false) when PiP is unsupported. Safe to call from any video affordance.
     */
    fun enterPip(aspectWidth: Int = 16, aspectHeight: Int = 9): Boolean

    /**
     * Mark whether a video is currently active (playing + visible). When true, the Activity may
     * auto-enter PiP on user-leave (Home press). A player sets true while shown/playing and false on
     * dispose/pause so leaving a non-video screen does not trigger PiP.
     */
    fun setVideoActive(active: Boolean)
}

/**
 * No-op [PipController] used as the CompositionLocal default (e.g. previews / non-Activity hosts). The
 * real implementation is provided by MainActivity.
 */
object NoOpPipController : PipController {
    override val isPipSupported: Boolean = false
    override fun enterPip(aspectWidth: Int, aspectHeight: Int): Boolean = false
    override fun setVideoActive(active: Boolean) { /* no-op */ }
}

/** CompositionLocal carrying the active [PipController] (provided by MainActivity). */
val LocalPipController = staticCompositionLocalOf<PipController> { NoOpPipController }

/**
 * #8 - the real [PipController] backed by an [Activity]. Builds [PictureInPictureParams] with the
 * given aspect ratio (clamped to the Android-permitted 1:2.39 .. 2.39:1 range) and calls
 * enterPictureInPictureMode. Tracks video-active so the Activity's onUserLeaveHint can auto-enter.
 */
class ActivityPipController(private val activity: Activity) : PipController {

    @Volatile
    var videoActive: Boolean = false
        private set

    override val isPipSupported: Boolean
        get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            activity.packageManager.hasSystemFeature(PackageManager.FEATURE_PICTURE_IN_PICTURE)

    override fun enterPip(aspectWidth: Int, aspectHeight: Int): Boolean {
        if (!isPipSupported) return false
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                activity.enterPictureInPictureMode(buildParams(aspectWidth, aspectHeight))
                true
            } else {
                false
            }
        }.getOrDefault(false)
    }

    override fun setVideoActive(active: Boolean) {
        videoActive = active
    }

    private fun buildParams(aspectWidth: Int, aspectHeight: Int): PictureInPictureParams {
        // Android rejects aspect ratios outside ~[1:2.39, 2.39:1]; clamp to a safe landscape default.
        val w = aspectWidth.coerceAtLeast(1)
        val h = aspectHeight.coerceAtLeast(1)
        val ratio = w.toFloat() / h.toFloat()
        val safe = when {
            ratio > 2.39f -> Rational(239, 100)
            ratio < 1f / 2.39f -> Rational(100, 239)
            else -> Rational(w, h)
        }
        return PictureInPictureParams.Builder().setAspectRatio(safe).build()
    }
}

/** Resolves the nearest [Activity] from a Compose [Context]. */
fun Context.findActivityForPip(): Activity? {
    var ctx: Context? = this
    while (ctx is ContextWrapper) {
        if (ctx is Activity) return ctx
        ctx = ctx.baseContext
    }
    return null
}
