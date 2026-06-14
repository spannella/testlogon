package com.testlogon.android.feature.call.recording

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.height
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.testlogon.android.R

/**
 * AND-302 — in-call recording upload status: a 0..100 progress bar with Cancel (while uploading) and Retry
 * (on failure). Also surfaces the FLAGGED "recording unavailable" notice and the upload-failed message. 48dp
 * action targets. testTag: recording_upload.
 */
@Composable
fun RecordingUploadStatus(
    state: RecordingUiState,
    onCancel: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier.testTag("recording_upload"),
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            when (state.phase) {
                RecordingPhase.PendingUpload, RecordingPhase.Uploading -> {
                    Text(
                        text = stringResource(R.string.recording_uploading),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Spacer(Modifier.height(6.dp))
                    LinearProgressIndicator(
                        progress = { state.uploadProgress / 100f },
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("recording_upload_progress"),
                    )
                    Spacer(Modifier.height(6.dp))
                    TextButton(
                        onClick = onCancel,
                        modifier = Modifier
                            .heightIn(min = 48.dp)
                            .testTag("recording_upload_cancel"),
                    ) {
                        Text(stringResource(R.string.recording_cancel))
                    }
                }
                RecordingPhase.Failed -> {
                    Text(
                        text = stringResource(R.string.recording_upload_failed),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                    Spacer(Modifier.height(6.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        TextButton(
                            onClick = onRetry,
                            modifier = Modifier
                                .heightIn(min = 48.dp)
                                .testTag("recording_upload_retry"),
                        ) {
                            Text(stringResource(R.string.recording_retry))
                        }
                    }
                }
                else -> {
                    if (state.mediaUnavailable) {
                        Text(
                            text = stringResource(R.string.recording_unavailable),
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.testTag("recording_unavailable"),
                        )
                    }
                }
            }
        }
    }
}
