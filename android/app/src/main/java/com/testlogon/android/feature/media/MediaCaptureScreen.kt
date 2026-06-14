@file:OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.media

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import android.widget.Toast
import com.testlogon.android.R
import com.testlogon.android.core.webrtc.ui.LocalVideoPreview
import com.testlogon.android.data.webrtc.ResolutionPreset

/**
 * AND-292/293 — local media-capture + device-selection screen.
 *
 * Hosts the FLAGGED [com.testlogon.android.core.webrtc.ui.LocalVideoPreview] (placeholder — no camera
 * preview) and the capture control bar (camera toggle, mute, switch, resolution). All selection state is
 * the pure [com.testlogon.android.data.webrtc.CaptureSelectionState]; the capture START is gated behind the
 * FLAGGED [com.testlogon.android.data.webrtc.BroadcastPublisher] and surfaces "capture unavailable".
 */
@Composable
fun MediaCaptureScreen(
    sessionId: String,
    inputId: String,
    viewModel: MediaCaptureViewModel = hiltViewModel(),
) {
    val context = LocalContext.current
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    val unavailableText = stringResource(R.string.capture_unavailable)
    val failedText = stringResource(R.string.capture_failed)

    LaunchedEffect(Unit) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is MediaCaptureEffect.Notice -> {
                    val msg = when (effect.kind) {
                        MediaCaptureNotice.CAPTURE_UNAVAILABLE -> unavailableText
                        MediaCaptureNotice.CAPTURE_FAILED -> failedText
                    }
                    Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    MediaCaptureContent(
        state = state,
        onToggleCamera = viewModel::onToggleCamera,
        onToggleMute = viewModel::onToggleMute,
        onSwitchCamera = viewModel::onSwitchCamera,
        onSelectResolution = viewModel::onSelectResolution,
        onStartCapture = { viewModel.onStartCapture(sessionId, inputId) },
    )
}

@Composable
internal fun MediaCaptureContent(
    state: MediaCaptureUiState,
    onToggleCamera: () -> Unit,
    onToggleMute: () -> Unit,
    onSwitchCamera: () -> Unit,
    onSelectResolution: (ResolutionPreset) -> Unit,
    onStartCapture: () -> Unit,
) {
    val selection = state.selection
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = stringResource(R.string.capture_title),
            style = MaterialTheme.typography.headlineSmall,
        )

        LocalVideoPreview(
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(16f / 9f)
                .testTag(TAG_PREVIEW),
            hasTrack = false,
            mirror = selection.isFrontFacing,
        )

        if (state.broadcastingUnavailable) {
            Text(
                modifier = Modifier.testTag(TAG_UNAVAILABLE),
                text = stringResource(R.string.capture_unavailable),
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        FlowRow(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedButton(
                modifier = Modifier.testTag(TAG_CAMERA_TOGGLE),
                onClick = onToggleCamera,
            ) {
                Text(
                    stringResource(
                        if (selection.cameraOff) R.string.capture_camera_on else R.string.capture_camera_off,
                    ),
                )
            }
            OutlinedButton(
                modifier = Modifier.testTag(TAG_MUTE_TOGGLE),
                onClick = onToggleMute,
            ) {
                Text(
                    stringResource(
                        if (selection.micMuted) R.string.capture_unmute else R.string.capture_mute,
                    ),
                )
            }
            OutlinedButton(
                modifier = Modifier.testTag(TAG_SWITCH_CAMERA),
                enabled = selection.canSwitchCamera,
                onClick = onSwitchCamera,
            ) {
                Text(stringResource(R.string.capture_switch_camera))
            }
        }

        FlowRow(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            ResolutionPreset.entries.forEach { preset ->
                FilterChip(
                    selected = selection.resolution == preset,
                    onClick = { onSelectResolution(preset) },
                    label = { Text(preset.label()) },
                )
            }
        }

        Button(
            modifier = Modifier.testTag(TAG_START),
            enabled = !state.starting,
            onClick = onStartCapture,
        ) {
            Text(stringResource(R.string.capture_start))
        }
    }
}

@Composable
private fun ResolutionPreset.label(): String = stringResource(
    when (this) {
        ResolutionPreset.SD_480 -> R.string.capture_res_480
        ResolutionPreset.HD_720 -> R.string.capture_res_720
        ResolutionPreset.FHD_1080 -> R.string.capture_res_1080
    },
)

private const val TAG_PREVIEW = "capture_preview"
private const val TAG_UNAVAILABLE = "capture_unavailable_text"
private const val TAG_CAMERA_TOGGLE = "capture_camera_toggle"
private const val TAG_MUTE_TOGGLE = "capture_mute_toggle"
private const val TAG_SWITCH_CAMERA = "capture_switch_camera"
private const val TAG_START = "capture_start_button"
