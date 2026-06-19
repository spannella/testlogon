package com.testlogon.android.core.webrtc.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import com.testlogon.android.data.webrtc.CallMediaHolder
import com.testlogon.android.data.webrtc.VideoRole
import com.testlogon.android.data.webrtc.VideoScaling
import org.webrtc.EglBase
import org.webrtc.RendererCommon
import org.webrtc.SurfaceViewRenderer
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Real native-WebRTC [VideoRenderer]: hosts an `org.webrtc.SurfaceViewRenderer` inside an `AndroidView`,
 * inits it against the shared [EglBase] context once, attaches the live [org.webrtc.VideoTrack] from
 * [CallMediaHolder] (local or remote per [VideoRole]) as a sink, and releases on dispose. Falls back to the
 * placeholder when no track is present yet.
 */
@Singleton
class RealVideoRenderer @Inject constructor(
    private val eglBase: EglBase,
    private val mediaHolder: CallMediaHolder,
) : VideoRenderer {

    @Composable
    override fun Render(
        role: VideoRole,
        hasTrack: Boolean,
        modifier: Modifier,
        mirror: Boolean,
        scaling: VideoScaling,
    ) {
        val trackFlow = if (role == VideoRole.LOCAL) mediaHolder.localVideo else mediaHolder.remoteVideo
        val track by trackFlow.collectAsState()
        val current = track
        if (current == null) {
            VideoPlaceholder(role = role, modifier = modifier)
            return
        }
        val context = LocalContext.current
        val view = remember {
            SurfaceViewRenderer(context).apply {
                init(eglBase.eglBaseContext, null)
                setEnableHardwareScaler(true)
            }
        }
        LaunchedEffect(mirror, scaling) {
            view.setMirror(mirror)
            view.setScalingType(
                if (scaling == VideoScaling.FILL) {
                    RendererCommon.ScalingType.SCALE_ASPECT_FILL
                } else {
                    RendererCommon.ScalingType.SCALE_ASPECT_FIT
                },
            )
        }
        DisposableEffect(current, view) {
            runCatching { current.addSink(view) }
            onDispose { runCatching { current.removeSink(view) } }
        }
        DisposableEffect(view) {
            onDispose { runCatching { view.release() } }
        }
        AndroidView(factory = { view }, modifier = modifier)
    }
}
