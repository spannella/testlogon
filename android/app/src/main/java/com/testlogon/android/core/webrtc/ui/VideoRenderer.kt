package com.testlogon.android.core.webrtc.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalInspectionMode
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.data.webrtc.VideoRendererMapping
import com.testlogon.android.data.webrtc.VideoRole
import com.testlogon.android.data.webrtc.VideoScaling

/**
 * AND-293 — video-renderer seam (SCAFFOLD — FLAGGED placeholder default; no SurfaceViewRenderer).
 *
 * STOP-AND-FLAG (the native WebRTC SDK is a HUMAN-DECISION vendor SDK): a real renderer would host an
 * `org.webrtc.SurfaceViewRenderer` inside an `AndroidView`, `init(eglContext)` it once, attach the
 * `VideoTrack` as a sink, map [VideoScaling]/[mirror] onto `RendererCommon.ScalingType`/`setMirror`, and
 * `release()` it on dispose (AND-293 §4). That requires the org.webrtc dependency, which is deliberately
 * NOT added. Until then [PlaceholderVideoRenderer] is bound and paints a static "video preview unavailable
 * / broadcasting not configured" placeholder — it NEVER creates a SurfaceViewRenderer, NEVER attaches a
 * sink, NEVER opens a camera. This mirrors the existing stub-seam pattern.
 *
 * The seam is an interface with a `@Composable Render(...)` member so a feature can place a renderer
 * declaratively (`renderer.Render(...)`) and the real binding can swap in the SDK-backed implementation
 * later. The scaling/mirror mapping lives in the pure [VideoRendererMapping] so it is JVM-unit-testable
 * without the SDK.
 */
interface VideoRenderer {

    /**
     * Render a video surface for [role]. [hasTrack] indicates whether a (future, real) [org.webrtc]
     * VideoTrack is present; the placeholder ignores it and always paints the not-configured state.
     * [mirror]/[scaling] are honored by a real renderer; the placeholder records them for parity only.
     */
    @Composable
    fun Render(
        role: VideoRole,
        hasTrack: Boolean,
        modifier: Modifier,
        mirror: Boolean,
        scaling: VideoScaling,
    )
}

/**
 * AND-293 — default (FLAGGED) renderer. NEVER hosts a SurfaceViewRenderer, NEVER attaches a sink, NEVER
 * opens hardware: always paints [VideoPlaceholder]. The real native-WebRTC-backed binding replaces this
 * once the SDK decision is made.
 */
object PlaceholderVideoRenderer : VideoRenderer {
    @Composable
    override fun Render(
        role: VideoRole,
        hasTrack: Boolean,
        modifier: Modifier,
        mirror: Boolean,
        scaling: VideoScaling,
    ) {
        VideoPlaceholder(role = role, modifier = modifier)
    }
}

/**
 * AND-293 — local camera preview composable (mirrored by default — FR-2). With the FLAGGED renderer bound,
 * this paints the placeholder regardless of [hasTrack]; no SurfaceViewRenderer, no camera preview.
 */
@Composable
fun LocalVideoPreview(
    modifier: Modifier = Modifier,
    hasTrack: Boolean = false,
    mirror: Boolean = true,
    scaling: VideoScaling = VideoScaling.FILL,
    renderer: VideoRenderer = PlaceholderVideoRenderer,
) {
    if (LocalInspectionMode.current) {
        VideoPlaceholder(role = VideoRole.LOCAL, modifier = modifier)
        return
    }
    renderer.Render(
        role = VideoRole.LOCAL,
        hasTrack = hasTrack,
        modifier = modifier,
        mirror = mirror,
        scaling = scaling,
    )
}

/**
 * AND-293 — remote peer video composable (unmirrored — FR-1). With the FLAGGED renderer bound, this paints
 * the placeholder regardless of [hasTrack]; no SurfaceViewRenderer.
 */
@Composable
fun RemoteVideoView(
    modifier: Modifier = Modifier,
    hasTrack: Boolean = false,
    scaling: VideoScaling = VideoScaling.FILL,
    renderer: VideoRenderer = PlaceholderVideoRenderer,
) {
    if (LocalInspectionMode.current) {
        VideoPlaceholder(role = VideoRole.REMOTE, modifier = modifier)
        return
    }
    renderer.Render(
        role = VideoRole.REMOTE,
        hasTrack = hasTrack,
        modifier = modifier,
        mirror = VideoRendererMapping.defaultMirror(VideoRole.REMOTE),
        scaling = scaling,
    )
}

/**
 * AND-293 — the placeholder painted whenever no real renderer/track is available (FLAGGED) or in
 * [LocalInspectionMode] (FR-8). Material 3 surface with localized copy; no fixed colors, no hardcoded text.
 */
@Composable
fun VideoPlaceholder(
    role: VideoRole,
    modifier: Modifier = Modifier,
) {
    val description = stringResource(
        if (role == VideoRole.LOCAL) R.string.video_local_preview else R.string.video_remote_feed,
    )
    Surface(
        modifier = modifier
            .testTag(if (role == VideoRole.LOCAL) TAG_LOCAL_PLACEHOLDER else TAG_REMOTE_PLACEHOLDER)
            .semantics { contentDescription = description },
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = stringResource(R.string.video_preview_unavailable),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

private const val TAG_LOCAL_PLACEHOLDER = "video_local_placeholder"
private const val TAG_REMOTE_PLACEHOLDER = "video_remote_placeholder"
