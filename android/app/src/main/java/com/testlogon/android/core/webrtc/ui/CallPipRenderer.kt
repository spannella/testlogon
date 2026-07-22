package com.testlogon.android.core.webrtc.ui

import android.content.Context
import android.view.View
import com.testlogon.android.data.webrtc.CallMediaHolder
import com.testlogon.android.feature.player.CallPipSource
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import livekit.org.webrtc.EglBase
import livekit.org.webrtc.RendererCommon
import livekit.org.webrtc.SurfaceViewRenderer
import livekit.org.webrtc.VideoTrack
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/**
 * CALL-PiP — factory seam for building the live-call [CallPipSource]. Injected into the in-call view model
 * so it can register the call as a PiP source WITHOUT the view model depending on the EglBase-backed
 * [CallPipRenderer] directly (keeps the view model JVM-unit-constructible with a trivial fake).
 */
interface CallPipSourceFactory {
    fun source(aspectWidth: Int = 16, aspectHeight: Int = 9): CallPipSource
}

/**
 * CALL-PiP — builds the [com.testlogon.android.feature.player.CallPipSource] used to render a LIVE video
 * call inside the system Picture-in-Picture window.
 *
 * This is the NON-media3 render branch: the PiP window shows the remote participant's LiveKit
 * [VideoTrack] via a native `SurfaceViewRenderer` (NOT an ExoPlayer/PlayerView). The renderer is created
 * fresh when PiP is entered (factory), inits against the shared [EglBase] context (the SAME context the
 * in-call `RealVideoRenderer` uses, so both surfaces share the GL context), and subscribes to
 * [CallMediaHolder.remoteVideo] so it (re)binds the track as a sink whenever it is (re)created or the
 * remote track swaps mid-call. On teardown it removes the sink and releases the SurfaceView — no leak,
 * no black frame retained.
 *
 * The ConnectionService keeps audio + the WebRTC session alive independent of any View, so tearing down /
 * rebuilding this render View across PiP-enter / config-change / return-to-fullscreen never affects the
 * call itself; it only re-attaches a display sink to the already-live remote track.
 */
@Singleton
class CallPipRenderer @Inject constructor(
    private val eglBase: EglBase,
    private val mediaHolder: CallMediaHolder,
) : CallPipSourceFactory {

    // Per-View scope + last-bound track, so releaseView can remove the exact sink and cancel the collector.
    private data class Binding(val scope: CoroutineScope, @Volatile var boundTrack: VideoTrack?)

    private val bindings = ConcurrentHashMap<View, Binding>()

    /**
     * Build a [CallPipSource] whose [CallPipSource.makeView] hosts a SurfaceViewRenderer bound to the live
     * remote track, and whose [CallPipSource.releaseView] cleanly detaches + releases it. [aspectWidth]/
     * [aspectHeight] size the floating window (defaults 16:9; the caller may pass the real negotiated size).
     */
    override fun source(aspectWidth: Int, aspectHeight: Int): CallPipSource = CallPipSource(
        makeView = { ctx -> makeRenderer(ctx) },
        releaseView = { view -> release(view) },
        aspectWidth = aspectWidth,
        aspectHeight = aspectHeight,
    )

    private fun makeRenderer(context: Context): View {
        val view = SurfaceViewRenderer(context).apply {
            init(eglBase.eglBaseContext, null)
            setEnableHardwareScaler(true)
            setScalingType(RendererCommon.ScalingType.SCALE_ASPECT_FILL)
            setMirror(false) // remote participant is never mirrored
        }
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        val binding = Binding(scope, null)
        bindings[view] = binding
        // Rebind the remote track as a sink whenever it appears/changes; detach the previous one.
        mediaHolder.remoteVideo.onEach { track ->
            val prev = binding.boundTrack
            if (prev !== track) {
                if (prev != null) runCatching { prev.removeSink(view) }
                if (track != null) runCatching { track.addSink(view) }
                binding.boundTrack = track
            }
        }.launchIn(scope)
        return view
    }

    private fun release(view: View) {
        val binding = bindings.remove(view) ?: return
        // Stop the track collector first so no new sink is attached during teardown.
        binding.scope.coroutineContext[Job]?.cancel()
        // Detach the current sink + release the SurfaceView SYNCHRONOUSLY on the calling (main) thread —
        // releaseView is invoked from the Activity/Compose main thread when leaving PiP / ending the call.
        val renderer = view as? SurfaceViewRenderer
        binding.boundTrack?.let { t -> if (renderer != null) runCatching { t.removeSink(renderer) } }
        binding.boundTrack = null
        runCatching { renderer?.release() }
    }
}
