@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.broadcast.host

import android.Manifest
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.webrtc.ui.LocalVideoPreview
import com.testlogon.android.core.webrtc.ui.PlaceholderVideoRenderer
import com.testlogon.android.core.webrtc.ui.VideoRenderer

/** AND-308 — stable testTags for the host ingest (camera/mic publish) screen. */
object IngestTestTags {
    const val SCREEN = "ingest_screen"
    const val PREVIEW = "ingest_preview"
    const val START = "ingest_start"
    const val STOP = "ingest_stop"
    const val UNAVAILABLE = "ingest_unavailable"
    const val HOST_CONTROLS = "ingest_host_controls"
}

/**
 * AND-308 — host ingest entry. Owns the just-in-time CAMERA + RECORD_AUDIO runtime permission request
 * (AndroidX activity-result — NO Accompanist) and delegates rendering to the stateless [IngestScreen].
 *
 * The permission request is REAL (so the flow is correct), even though the FLAGGED engine never opens the
 * camera/mic — once granted, [IngestViewModel.start] drives the FLAGGED publisher which resolves to
 * "broadcasting unavailable". Reached from the host create flow after a session is created (AND-307).
 */
@Composable
fun IngestRoute(
    onBack: () -> Unit,
    // AND-309 — open the host LIVE control surface (start/stop/resume/reschedule + health) for this session.
    onHostControls: () -> Unit = {},
    viewModel: IngestViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { grants ->
        val cameraGranted = grants[Manifest.permission.CAMERA] ?: false
        val micGranted = grants[Manifest.permission.RECORD_AUDIO] ?: false
        // Capture never happens (FLAGGED engine), but the flow is correct: only start once granted.
        if (cameraGranted && micGranted) viewModel.start()
    }

    IngestScreen(
        state = state,
        videoRenderer = viewModel.videoRenderer,
        onStart = {
            permissionLauncher.launch(
                arrayOf(Manifest.permission.CAMERA, Manifest.permission.RECORD_AUDIO),
            )
        },
        onStop = viewModel::stop,
        onHostControls = onHostControls,
        onBack = onBack,
    )
}

/**
 * AND-308 — stateless ingest surface: a local-preview area (the FLAGGED [LocalVideoPreview] placeholder),
 * a "Go Live" start button, the ingest phase, and a prominent "broadcasting unavailable — not configured"
 * banner whenever [IngestUiState.mediaUnavailable] is set (the FLAGGED publisher reported not-configured).
 */
@Composable
fun IngestScreen(
    state: IngestUiState,
    videoRenderer: VideoRenderer = PlaceholderVideoRenderer,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onBack: () -> Unit,
    // AND-309 — when set, an existing input offers a "Manage broadcast" affordance to the control surface.
    onHostControls: () -> Unit = {},
) {
    Scaffold(
        modifier = Modifier.testTag(IngestTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.ingest_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.broadcast_go_live_back_cd),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Local camera preview (FLAGGED -> placeholder; never opens the camera).
            LocalVideoPreview(
                modifier = Modifier
                    .fillMaxWidth()
                    .aspectRatio(16f / 9f)
                    .testTag(IngestTestTags.PREVIEW),
                renderer = videoRenderer,
            )

            if (state.mediaUnavailable) {
                Text(
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(IngestTestTags.UNAVAILABLE),
                    text = stringResource(R.string.ingest_unavailable),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            state.error?.let { message ->
                Text(
                    text = message,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            Button(
                onClick = onStart,
                enabled = state.canStart,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(IngestTestTags.START),
            ) {
                Text(stringResource(R.string.ingest_go_live))
            }

            if (!state.canStart) {
                OutlinedButton(
                    onClick = onStop,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag(IngestTestTags.STOP),
                ) {
                    Text(stringResource(R.string.ingest_stop))
                }
            }

            // AND-309 — once an input exists, the host can open the LIVE control surface.
            if (state.inputId != null) {
                OutlinedButton(
                    onClick = onHostControls,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag(IngestTestTags.HOST_CONTROLS),
                ) {
                    Text(stringResource(R.string.host_control_open))
                }
            }
        }
    }
}
