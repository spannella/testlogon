package com.testlogon.android.feature.call.incall

import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CallEnd
import androidx.compose.material.icons.filled.Cameraswitch
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.MicOff
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.SignalCellularAlt
import androidx.compose.material.icons.filled.SignalCellularOff
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material.icons.filled.VideocamOff
import androidx.compose.material.icons.filled.VolumeOff
import androidx.compose.material.icons.filled.VolumeUp
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.webrtc.ui.LocalVideoPreview
import com.testlogon.android.core.webrtc.ui.RemoteVideoView
import com.testlogon.android.feature.call.billing.FinalCostSummary
import com.testlogon.android.feature.call.billing.RunningCostOverlay

/**
 * AND-298 — in-call (1:1) screen.
 *
 * Full-bleed remote surface with a draggable local PiP, a bottom control bar (mute / camera / route / flip /
 * end), a top overlay (peer name + duration + quality glyph), and FLAGGED-media affordances (the
 * "call media unavailable" banner, weak-connection banner, reconnecting spinner). All media toggles are
 * LOCAL UI state (see [InCallViewModel]); native media is not wired. The one-shot terminal effect is
 * collected in a LaunchedEffect so the Route pops exactly once.
 */
@Composable
fun InCallRoute(
    onCallEnded: () -> Unit,
    viewModel: InCallViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.callEnded.collect { onCallEnded() }
    }
    InCallScreen(state = state, onAction = viewModel::onAction)
}

@Composable
fun InCallScreen(
    state: InCallUiState,
    onAction: (InCallAction) -> Unit,
) {
    // Auto-hide the controls after 4s of inactivity in video mode; in audio-only they stay visible.
    LaunchedEffect(state.controlsVisible, state.isVideoCall) {
        if (state.isVideoCall && state.controlsVisible) {
            kotlinx.coroutines.delay(4_000)
            onAction(InCallAction.ToggleControls)
        }
    }

    val tapSource = remember { MutableInteractionSource() }
    Box(
        modifier = Modifier
            .fillMaxSize()
            .clickable(
                interactionSource = tapSource,
                indication = null,
            ) { onAction(InCallAction.ToggleControls) }
            .testTag("incall_screen"),
    ) {
        // Full-bleed remote video (placeholder while media is FLAGGED). Audio-only / no remote video shows
        // a centered avatar + peer name placeholder.
        if (state.isVideoCall && state.hasRemoteVideo) {
            RemoteVideoView(
                modifier = Modifier.fillMaxSize(),
                hasTrack = state.hasRemoteVideo,
            )
        } else {
            RemotePlaceholder(state = state)
        }

        // Local picture-in-picture preview (only in video calls with the camera on).
        if (state.isVideoCall && state.cameraEnabled) {
            LocalVideoPreview(
                modifier = Modifier
                    .padding(16.dp)
                    .size(width = 96.dp, height = 128.dp)
                    .align(state.localTileCorner.alignment)
                    .testTag("incall_local_pip"),
                hasTrack = state.hasLocalVideo,
            )
        }

        // Reconnecting spinner over the remote surface.
        if (state.lifecycle == InCallLifecycle.Reconnecting) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .testTag("incall_reconnecting"),
                contentAlignment = Alignment.Center,
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator()
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = stringResource(R.string.call_reconnecting),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }
        }

        // Top overlay: peer name + duration + quality glyph + banners.
        TopOverlay(
            state = state,
            modifier = Modifier
                .align(Alignment.TopCenter)
                .fillMaxWidth()
                .statusBarsPadding()
                .padding(16.dp),
        )

        // Bottom control bar.
        if (state.lifecycle == InCallLifecycle.Ended) {
            EndedOverlay(
                state = state,
                modifier = Modifier.align(Alignment.Center),
            )
        } else if (state.controlsVisible) {
            ControlBar(
                state = state,
                onAction = onAction,
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .padding(24.dp),
            )
        }
    }
}

@Composable
private fun RemotePlaceholder(state: InCallUiState) {
    val peerName = state.peerName ?: stringResource(R.string.call_unknown_caller)
    Surface(
        modifier = Modifier
            .fillMaxSize()
            .testTag("incall_remote_placeholder"),
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Column(
            modifier = Modifier.fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Icon(
                imageVector = Icons.Filled.Person,
                contentDescription = null,
                modifier = Modifier.size(96.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(12.dp))
            Text(
                text = peerName,
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
    }
}

@Composable
private fun TopOverlay(
    state: InCallUiState,
    modifier: Modifier = Modifier,
) {
    val peerName = state.peerName ?: stringResource(R.string.call_unknown_caller)
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            QualityGlyph(quality = state.quality)
            Spacer(Modifier.size(8.dp))
            Text(
                text = peerName,
                style = MaterialTheme.typography.titleMedium,
            )
        }
        Spacer(Modifier.height(4.dp))
        Text(
            text = state.durationLabel,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier
                .testTag("incall_duration")
                .semantics { liveRegion = LiveRegionMode.Polite },
        )
        // AND-301: running-cost overlay for a paid call (authoritative heartbeat cost / local estimate).
        if (state.paid) {
            Spacer(Modifier.height(4.dp))
            RunningCostOverlay(
                runningCostCents = state.runningCostCents,
                isEstimate = state.isEstimate,
                condition = state.billingCondition,
            )
        }
        if (state.mediaUnavailable) {
            Spacer(Modifier.height(8.dp))
            Banner(
                text = stringResource(R.string.call_media_unavailable),
                tag = "incall_media_unavailable",
            )
        }
        if (state.showWeakBanner) {
            Spacer(Modifier.height(8.dp))
            Banner(
                text = stringResource(R.string.call_weak_connection),
                tag = "incall_weak_banner",
            )
        }
    }
}

@Composable
private fun Banner(text: String, tag: String) {
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        modifier = Modifier.testTag(tag),
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onErrorContainer,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
        )
    }
}

@Composable
private fun QualityGlyph(quality: ConnectionQuality) {
    val (icon, cdRes) = when (quality) {
        ConnectionQuality.EXCELLENT -> Icons.Filled.SignalCellularAlt to R.string.call_quality_excellent
        ConnectionQuality.GOOD -> Icons.Filled.SignalCellularAlt to R.string.call_quality_good
        ConnectionQuality.POOR -> Icons.Filled.SignalCellularAlt to R.string.call_quality_poor
        ConnectionQuality.LOST ->
            Icons.Filled.SignalCellularOff to R.string.call_quality_lost
        // UNKNOWN renders a neutral, undescribed glyph.
        ConnectionQuality.UNKNOWN -> null to null
    }
    if (icon == null || cdRes == null) {
        // Keep the tag present (neutral) so layout/tests are stable.
        Spacer(Modifier.size(0.dp).testTag("incall_quality"))
        return
    }
    Icon(
        imageVector = icon,
        contentDescription = stringResource(cdRes),
        modifier = Modifier
            .size(20.dp)
            .testTag("incall_quality"),
    )
}

@Composable
private fun ControlBar(
    state: InCallUiState,
    onAction: (InCallAction) -> Unit,
    modifier: Modifier = Modifier,
) {
    val micCd = stringResource(if (state.micEnabled) R.string.call_mute_cd else R.string.call_unmute_cd)
    val cameraCd =
        stringResource(if (state.cameraEnabled) R.string.call_camera_off_cd else R.string.call_camera_on_cd)
    val routeCd = stringResource(
        if (state.audioRoute == AudioRoute.SPEAKER) R.string.call_route_speaker_cd
        else R.string.call_route_earpiece_cd,
    )
    val flipCd = stringResource(R.string.call_flip_camera_cd)
    val endCd = stringResource(R.string.call_end_cd)

    Row(
        modifier = modifier,
        horizontalArrangement = Arrangement.SpaceEvenly,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        ControlButton(
            icon = if (state.micEnabled) Icons.Filled.Mic else Icons.Filled.MicOff,
            contentDescription = micCd,
            tag = "incall_mute",
            onClick = { onAction(InCallAction.ToggleMic) },
        )
        ControlButton(
            icon = if (state.cameraEnabled) Icons.Filled.Videocam else Icons.Filled.VideocamOff,
            contentDescription = cameraCd,
            tag = "incall_camera",
            enabled = state.isVideoCall,
            onClick = { onAction(InCallAction.ToggleCamera) },
        )
        ControlButton(
            icon = if (state.audioRoute == AudioRoute.SPEAKER) Icons.Filled.VolumeUp else Icons.Filled.VolumeOff,
            contentDescription = routeCd,
            tag = "incall_route",
            onClick = { onAction(InCallAction.CycleRoute) },
        )
        ControlButton(
            icon = Icons.Filled.Cameraswitch,
            contentDescription = flipCd,
            tag = "incall_flip",
            enabled = state.hasMultipleCameras && state.cameraEnabled,
            onClick = { onAction(InCallAction.FlipCamera) },
        )
        ControlButton(
            icon = Icons.Filled.CallEnd,
            contentDescription = endCd,
            tag = "incall_end",
            tint = MaterialTheme.colorScheme.error,
            onClick = { onAction(InCallAction.EndCall) },
        )
    }
}

@Composable
private fun ControlButton(
    icon: ImageVector,
    contentDescription: String,
    tag: String,
    onClick: () -> Unit,
    enabled: Boolean = true,
    tint: androidx.compose.ui.graphics.Color = MaterialTheme.colorScheme.onSurface,
) {
    IconButton(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier
            .size(48.dp)
            .testTag(tag)
            .semantics { this.contentDescription = contentDescription },
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = if (enabled) tint else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f),
        )
    }
}

@Composable
private fun EndedOverlay(
    state: InCallUiState,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.testTag("incall_ended"),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = stringResource(R.string.call_status_ended),
            style = MaterialTheme.typography.titleMedium,
        )
        if (state.durationLabel.isNotEmpty()) {
            Spacer(Modifier.height(4.dp))
            Text(
                text = state.durationLabel,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        // AND-301: final-cost summary for a paid call (authoritative billed total, or last running value
        // labelled an estimate when the billing read was unavailable).
        if (state.paid && state.finalCostCents != null) {
            Spacer(Modifier.height(4.dp))
            FinalCostSummary(
                finalCostCents = state.finalCostCents,
                finalIsEstimate = state.finalIsEstimate,
            )
        }
    }
}

/** AND-298 — Compose-only mapping of a [PipCorner] to a Box [Alignment] (kept out of the pure contract). */
val PipCorner.alignment: Alignment
    get() = when (this) {
        PipCorner.TOP_START -> Alignment.TopStart
        PipCorner.TOP_END -> Alignment.TopEnd
        PipCorner.BOTTOM_START -> Alignment.BottomStart
        PipCorner.BOTTOM_END -> Alignment.BottomEnd
    }
