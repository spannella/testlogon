package com.testlogon.android.feature.player

import android.app.Activity
import android.app.PictureInPictureParams
import android.content.Context
import android.content.Intent
import android.content.ContextWrapper
import android.content.pm.PackageManager
import android.os.Build
import android.util.Rational
import android.view.View
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
/**
 * CALL-PiP — descriptor for rendering a LIVE video call in the Picture-in-Picture window. Unlike the
 * media3 branch (which hands the controller a [Player] and lets a PlayerView render it), a call renders
 * native WebRTC frames, so the controller is given:
 *  - [makeView]: a factory that builds the call's render [View] (a LiveKit SurfaceViewRenderer bound to
 *    the remote participant's VideoTrack). Invoked by the Activity when it enters PiP and swaps content
 *    to the call surface; the returned View is added to the PiP window. The factory owns init()/bind.
 *  - [releaseView]: releases exactly the View produced by [makeView] (remove the track sink + SurfaceView
 *    release) so returning to full screen / config-change / end does not leak the renderer or black-frame.
 *  - [aspectWidth]/[aspectHeight]: the call video aspect for the PiP params (clamped by PipParamsLogic).
 *
 * The factory indirection keeps org.webrtc / LiveKit types OUT of this SDK-free controller: the call
 * feature supplies the concrete SurfaceViewRenderer wiring.
 */
data class CallPipSource(
    val makeView: (Context) -> View,
    val releaseView: (View) -> Unit,
    val aspectWidth: Int = 16,
    val aspectHeight: Int = 9,
)

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

    /**
     * CALL-PiP — register the ACTIVE VIDEO CALL as the current PiP source. When set, PiP collapses the
     * Activity to a live WebRTC [android.view.View] (a SurfaceViewRenderer bound to the remote track)
     * instead of a media3 PlayerView. [source] carries a renderer-view factory + the remote-track binder
     * + the call aspect; pass null to UNREGISTER the call (on end / audio-only / leaving the call screen).
     * A registered call takes precedence over any media3 player for source selection. Guarded on
     * video-call-connected by the caller (audio-only calls never register — nothing to show).
     */
    fun setCallSource(source: CallPipSource?)

    /**
     * CALL-PiP — mark whether the active call is currently PiP-eligible (a CONNECTED VIDEO call). When
     * true, the Activity may auto-enter PiP on user-leave (Home) exactly like [setVideoActive] does for
     * media3. False on audio-only / not-yet-connected / ended.
     */
    fun setCallActive(active: Boolean)

    /**
     * CALL-PiP — request the hosting Activity LEAVE Picture-in-Picture and return to full screen. Used
     * when a call ends while floating in PiP so the user is not stranded with a dead/last-frame window.
     * No-op when not in PiP / unsupported. Best-effort.
     */
    fun exitPip()
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
    override fun setCallSource(source: CallPipSource?) { /* no-op */ }
    override fun setCallActive(active: Boolean) { /* no-op */ }
    override fun exitPip() { /* no-op */ }
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

    /**
     * CALL-PiP — the active video call's PiP descriptor (or null). Observable so the PiP-mode composable
     * recomposes to (un)mount the call render surface when a call registers/ends. Read by MainActivity
     * while in PiP to build the SurfaceViewRenderer branch.
     */
    val callSourceState = mutableStateOf<CallPipSource?>(null)

    /** CALL-PiP — true when a CONNECTED VIDEO call is registered (arms call auto-enter). */
    @Volatile
    var callActive: Boolean = false
        private set

    override val isPipSupported: Boolean
        get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            activity.packageManager.hasSystemFeature(PackageManager.FEATURE_PICTURE_IN_PICTURE)

    override fun enterPip(aspectWidth: Int, aspectHeight: Int): Boolean {
        android.util.Log.d("TLPIP", "enterPip called videoActive=$videoActive callActive=$callActive callSource=${callSourceState.value != null}")
        if (!isPipSupported) return false
        // Capture the stable snapshot BEFORE entering PiP so the video-only surface has a player even
        // after the inline composable disposes mid-transition.
        pipPlayerState.value = activePlayerState.value
        enteringPip = true
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val entered = activity.enterPictureInPictureMode(buildParams(aspectWidth, aspectHeight))
                android.util.Log.d("TLPIP", "enterPictureInPictureMode returned $entered")
                entered
            } else {
                false
            }
        }.onFailure { android.util.Log.d("TLPIP", "enterPictureInPictureMode threw ${it.javaClass.simpleName}: ${it.message}") }.getOrDefault(false)
    }

    override fun enterPipWith(player: Player, aspectWidth: Int, aspectHeight: Int): Boolean {
        // Register the player FIRST so onPictureInPictureModeChanged can collapse to it immediately.
        activePlayerState.value = player
        activeAspectW = aspectWidth
        activeAspectH = aspectHeight
        videoActive = true
        refreshAutoEnterParams()
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
        // Arm/disarm API 31+ auto-enter to match the current playing state (no-op below S).
        refreshAutoEnterParams()
    }

    override fun setCallSource(source: CallPipSource?) {
        callSourceState.value = source
        if (source != null) {
            activeAspectW = source.aspectWidth
            activeAspectH = source.aspectHeight
        }
        refreshAutoEnterParams()
    }

    override fun setCallActive(active: Boolean) {
        android.util.Log.d("TLPIP", "setCallActive($active)")
        callActive = active
        if (!active) {
            // Leaving eligibility (call ended / audio-only / left the screen): drop the render source so a
            // subsequent forced PiP does not show a stale call surface. Never clears mid-PiP-entry latch
            // used by the media3 path (call source is independent of pipPlayerState).
            if (!enteringPip) callSourceState.value = null
        }
        refreshAutoEnterParams()
    }

    override fun exitPip() {
        if (!isPipSupported) return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        // Standard way to leave PiP programmatically: bring the Activity's own task back to the front via
        // a singleTask launch intent. The system collapses the PiP window and restores full-screen.
        runCatching {
            val intent = activity.packageManager.getLaunchIntentForPackage(activity.packageName)
            if (intent != null) {
                intent.flags = Intent.FLAG_ACTIVITY_REORDER_TO_FRONT or Intent.FLAG_ACTIVITY_NEW_TASK
                activity.startActivity(intent)
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
        // Prefer the active player's REAL reported video size so the floating window matches the actual
        // stream (live HLS broadcast, VOD, inline clip); fall back to the caller-supplied aspect. Clamp
        // to the Android-permitted ~[1:2.39, 2.39:1] window. All pure -> PipParamsLogic (JVM-tested).
        val call = callSourceState.value
        val size = runCatching { activePlayerState.value?.videoSize }.getOrNull()
        val (num, den) = if (call != null) {
            // CALL-PiP — a live call has no media3 videoSize; use the call's reported aspect (clamped).
            PipParamsLogic.resolveAspect(0, 0, call.aspectWidth, call.aspectHeight)
        } else {
            PipParamsLogic.resolveAspect(
                videoWidth = size?.width ?: 0,
                videoHeight = size?.height ?: 0,
                fallbackW = aspectWidth,
                fallbackH = aspectHeight,
            )
        }
        val builder = PictureInPictureParams.Builder().setAspectRatio(Rational(num, den))
        // AND-287 — API 31+ (S) auto-enter + seamless resize for a smoother, tap-free float on Home.
        // On 26-30 we keep the onUserLeaveHint manual-enter fallback (see MainActivity.onUserLeaveHint).
        if (PipParamsLogic.supportsAutoEnter(Build.VERSION.SDK_INT) &&
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
        ) {
            builder.setAutoEnterEnabled(videoActive || callActive)
            builder.setSeamlessResizeEnabled(true)
        }
        return builder.build()
    }

    /**
     * AND-287 — proactively push the current [PictureInPictureParams] to the system so API 31+
     * setAutoEnterEnabled is armed (or disarmed) as the active video / aspect changes, without waiting
     * for an explicit enterPip call. No-op below S (manual onUserLeaveHint path) or when PiP is
     * unsupported. Best-effort; never throws into the caller.
     */
    fun refreshAutoEnterParams() {
        if (!isPipSupported) return
        if (!PipParamsLogic.supportsAutoEnter(Build.VERSION.SDK_INT)) return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        runCatching {
            activity.setPictureInPictureParams(buildParams(activeAspectW, activeAspectH))
        }
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
