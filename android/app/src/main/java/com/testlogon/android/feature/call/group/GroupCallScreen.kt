package com.testlogon.android.feature.call.group

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
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material.icons.filled.VideocamOff
import androidx.compose.material.icons.filled.VolumeOff
import androidx.compose.material.icons.filled.VolumeUp
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.feature.call.incall.AudioRoute

/**
 * AND-299 — group-call screen.
 *
 * A full-bleed [ParticipantGrid] with the REUSED 1:1 control row (mute / camera / route / flip / end) at
 * the bottom and a top overlay (participant count + the FLAGGED "call media unavailable" banner). The
 * control plane (create/join/leave/media/roster) is real; native media is FLAGGED (the mesh seam returns
 * NotConfigured) so the banner is shown and the toggles are local UI state only. The one-shot terminal
 * effect is collected in a LaunchedEffect so the Route pops exactly once.
 */
@Composable
fun GroupCallRoute(
    onCallEnded: () -> Unit,
    viewModel: GroupCallViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.callEnded.collect { onCallEnded() }
    }
    GroupCallScreen(state = state, onAction = viewModel::onAction)
}

@Composable
fun GroupCallScreen(
    state: GroupCallUiState,
    onAction: (GroupCallAction) -> Unit,
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .testTag("groupcall_screen"),
    ) {
        ParticipantGrid(
            participants = state.participants,
            activeSpeakerUserId = state.activeSpeakerUserId,
            modifier = Modifier.fillMaxSize(),
        )

        if (state.phase == GroupCallPhase.Ended) {
            TerminalOverlay(modifier = Modifier.align(Alignment.Center))
        }

        TopOverlay(
            state = state,
            modifier = Modifier
                .align(Alignment.TopCenter)
                .fillMaxWidth()
                .statusBarsPadding()
                .padding(16.dp),
        )

        if (state.phase != GroupCallPhase.Ended) {
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
private fun TopOverlay(
    state: GroupCallUiState,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = stringResource(R.string.group_call_participant_count, state.participants.size),
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.testTag("groupcall_count"),
        )
        if (state.participants.size <= 1) {
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.group_call_waiting),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        if (state.mediaUnavailable) {
            Spacer(Modifier.height(8.dp))
            Surface(
                color = MaterialTheme.colorScheme.errorContainer,
                modifier = Modifier.testTag("groupcall_media_unavailable"),
            ) {
                Text(
                    text = stringResource(R.string.call_media_unavailable),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                )
            }
        }
    }
}

@Composable
private fun ControlBar(
    state: GroupCallUiState,
    onAction: (GroupCallAction) -> Unit,
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
    val leaveCd = stringResource(R.string.group_call_leave_cd)

    Row(
        modifier = modifier,
        horizontalArrangement = Arrangement.SpaceEvenly,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        ControlButton(
            icon = if (state.micEnabled) Icons.Filled.Mic else Icons.Filled.MicOff,
            contentDescription = micCd,
            tag = "groupcall_mute",
            onClick = { onAction(GroupCallAction.ToggleMic) },
        )
        ControlButton(
            icon = if (state.cameraEnabled) Icons.Filled.Videocam else Icons.Filled.VideocamOff,
            contentDescription = cameraCd,
            tag = "groupcall_camera",
            onClick = { onAction(GroupCallAction.ToggleCamera) },
        )
        ControlButton(
            icon = if (state.audioRoute == AudioRoute.SPEAKER) Icons.Filled.VolumeUp else Icons.Filled.VolumeOff,
            contentDescription = routeCd,
            tag = "groupcall_route",
            onClick = { onAction(GroupCallAction.CycleRoute) },
        )
        ControlButton(
            icon = Icons.Filled.Cameraswitch,
            contentDescription = flipCd,
            tag = "groupcall_flip",
            enabled = state.cameraEnabled,
            onClick = { onAction(GroupCallAction.FlipCamera) },
        )
        ControlButton(
            icon = Icons.Filled.CallEnd,
            contentDescription = leaveCd,
            tag = "groupcall_leave",
            tint = MaterialTheme.colorScheme.error,
            onClick = { onAction(GroupCallAction.Leave) },
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
    tint: Color = MaterialTheme.colorScheme.onSurface,
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
private fun TerminalOverlay(modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.testTag("groupcall_ended"),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = stringResource(R.string.call_status_ended),
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(Modifier.size(4.dp))
    }
}
