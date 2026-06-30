package com.testlogon.android.feature.player

import android.app.Activity
import android.app.PictureInPictureParams
import android.content.Context
import android.content.ContextWrapper
import android.content.pm.PackageManager
import android.os.Build
import android.util.Rational
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.media3.common.Player

/**
 * #8 - Picture-in-Picture entry seam for video playback across the app (My Videos, messaging video,
 * newsfeed video). A player composable calls [enterPip] to put the single hosting MainActivity into
 * the system PiP window so a playing video keeps rendering in a floating window when the user leaves
 * the app.
 *
 * FAIL #7/#8 FIX: PiP captures the WHOLE Activity content surface, so an INLINE player (messaging
 * thread / newsfeed) used to show the thread / feed in the floating window instead of the video. The
 * controller now also tracks the currently-active [Player] (and its aspect ratio) so the hosting
 * Activity can, while in PiP mode, collapse its content to a video-ONLY PlayerView bound to that
 * player (mirroring the VOD detail player, whose surface already fills the window). This makes the
 * floating window show ONLY the video for every player.
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
     * Prefer [enterPipWith] from an inline player so the active player + aspect are registered first.
     */
    fun enterPip(aspectWidth: Int = 16, aspectHeight: Int = 9): Boolean

    /**
     * #8 FAIL-7/8 — register [player] (and its [aspectWidth]:[aspectHeight]) as the active video and
     * IMMEDIATELY enter PiP. While in PiP the Activity renders ONLY this player, so the floating
     * window shows the video, never the surrounding thread / feed.
     */
    fun enterPipWith(player: Player, aspectWidth: Int = 16, aspectHeight: Int = 9): Boolean

    /**
     * Mark whether a video is currently active (playing + visible). When true, the Activity may
     * auto-enter PiP on user-leave (Home press). A player sets true while shown/playing and false on
     * dispose/pause so leaving a non-video screen does not trigger PiP. Pass the [player] (and its
     * aspect) so an auto-enter on Home also collapses to that exact video surface in PiP.
     */
    fun setVideoActive(active: Boolean, player: Player? = null, aspectWidth: Int = 16, aspectHeight: Int = 9)

    /**
     * FAIL #7/#8 — true when [player] is currently retained for the PiP window (PiP entry in flight
     * or active). An inline player composable that is being DISPOSED during the swap to the
     * video-only PiP surface MUST NOT release the ExoPlayer in this case: the controller takes
     * ownership and releases it when PiP exits. Returns false otherwise (normal disposal releases).
     */
    fun isPipRetained(player: Player): Boolean

    /**
     * FAIL #7/#8 — called by an inline player's onDispose when it SKIPS releasing the ExoPlayer because
     * the player is retained for PiP ([isPipRetained] was true). It transfers release ownership to the
     * controller, which releases exactly this player when PiP exits. Players whose lifecycle is owned
     * elsewhere (e.g. the VOD detail controller) never call this, so the controller never releases them.
     */
    fun deferPipRelease(player: Player)
}

/**
 * No-op [PipController] used as the CompositionLocal default (e.g. previews / non-Activity hosts). The
 * real implementation is provided by MainActivity.
 */
object NoOpPipController : PipController {
    override val isPipSupported: Boolean = false
    override fun enterPip(aspectWidth: Int, aspectHeight: Int): Boolean = false
    override fun enterPipWith(player: Player, aspectWidth: Int, aspectHeight: Int): Boolean = false
    override fun setVideoActive(active: Boolean, player: Player?, aspectWidth: Int, aspectHeight: Int) { /* no-op */ }
    override fun isPipRetained(player: Player): Boolean = false
    override fun deferPipRelease(player: Player) { /* no-op */ }
}

/** CompositionLocal carrying the active [PipController] (provided by MainActivity). */
val LocalPipController = staticCompositionLocalOf<PipController> { NoOpPipController }

/**
 * #8 - the real [PipController] backed by an [Activity]. Builds [PictureInPictureParams] with the
 * given aspect ratio (clamped to the Android-permitted 1:2.39 .. 2.39:1 range) and calls
 * enterPictureInPictureMode. Tracks video-active so the Activity's onUserLeaveHint can auto-enter.
 *
 * FAIL #7/#8: also tracks the active [Player] + aspect so MainActivity can render a video-only surface
 * while in PiP. [activePlayerState] is observable so the PiP-mode composable recomposes when the
 * active player changes.
 */
class ActivityPipController(private val activity: Activity) : PipController {

    @Volatile
    var videoActive: Boolean = false
        private set

    /** The player currently eligible to be shown alone in the PiP window (or null). Observable. */
    val activePlayerState = mutableStateOf<Player?>(null)

    /**
     * FAIL #7/#8 — the STABLE snapshot of the player to render alone in the PiP window. Captured at
     * the moment PiP is entered and held until PiP exits, so that the inline player composable being
     * DISPOSED (it leaves composition when MainActivity swaps to the video-only surface) does NOT
     * clear what we render. MainActivity reads this (not [activePlayerState]) while in PiP.
     */
    val pipPlayerState = mutableStateOf<Player?>(null)

    /** True from just before entering PiP until PiP exits; suppresses disposal-driven clears. */
    @Volatile
    var enteringPip: Boolean = false
        private set

    /** The player whose release was deferred to the controller (inline players only); released on exit. */
    @Volatile
    private var deferredReleasePlayer: Player? = null

    /** Aspect of the active player, used to build PiP params on an auto-enter (Home press). */
    @Volatile
    var activeAspectW: Int = 16
        private set

    @Volatile
    var activeAspectH: Int = 9
        private set

    override val isPipSupported: Boolean
        get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            activity.packageManager.hasSystemFeature(PackageManager.FEATURE_PICTURE_IN_PICTURE)

    override fun enterPip(aspectWidth: Int, aspectHeight: Int): Boolean {
        if (!isPipSupported) return false
        // Capture the stable snapshot BEFORE entering PiP so the video-only surface has a player even
        // after the inline composable disposes mid-transition.
        pipPlayerState.value = activePlayerState.value
        enteringPip = true
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                activity.enterPictureInPictureMode(buildParams(aspectWidth, aspectHeight))
                true
            } else {
                false
            }
        }.getOrDefault(false)
    }

    override fun enterPipWith(player: Player, aspectWidth: Int, aspectHeight: Int): Boolean {
        // Register the player FIRST so onPictureInPictureModeChanged can collapse to it immediately.
        activePlayerState.value = player
        activeAspectW = aspectWidth
        activeAspectH = aspectHeight
        videoActive = true
        return enterPip(aspectWidth, aspectHeight)
    }

    override fun setVideoActive(active: Boolean, player: Player?, aspectWidth: Int, aspectHeight: Int) {
        videoActive = active
        if (active) {
            if (player != null) {
                activePlayerState.value = player
                activeAspectW = aspectWidth
                activeAspectH = aspectHeight
            }
        } else {
            // FAIL #7/#8 — never clear the active player while a PiP entry is in flight / active; the
            // inline player composable disposes during the swap to the video-only surface and would
            // otherwise yank the player out from under the floating window.
            if (enteringPip) return
            // Only clear the active player if it is the one being deactivated (avoid clobbering a
            // different player that became active in between).
            if (player == null || activePlayerState.value === player) {
                activePlayerState.value = null
            }
        }
    }

    /**
     * Called by the hosting Activity from onPictureInPictureModeChanged. On EXIT we release the stable
     * pip snapshot + latch so normal disposal semantics resume.
     */
    fun onPipModeChanged(inPip: Boolean) {
        if (!inPip) {
            enteringPip = false
            pipPlayerState.value = null
            // Release ONLY a player whose inline composable deferred release to us (it skipped its own
            // onDispose release because the player was retained for PiP). A VOD/controller-owned player
            // never defers, so we never release it here.
            val held = deferredReleasePlayer
            deferredReleasePlayer = null
            if (held != null) {
                runCatching { held.release() }
            }
        }
    }

    override fun isPipRetained(player: Player): Boolean =
        enteringPip && (pipPlayerState.value === player || activePlayerState.value === player)

    override fun deferPipRelease(player: Player) {
        deferredReleasePlayer = player
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
