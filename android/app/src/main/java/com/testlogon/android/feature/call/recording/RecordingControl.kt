package com.testlogon.android.feature.call.recording

import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FiberManualRecord
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.testlogon.android.R

/**
 * AND-302 — the in-call Record button (requester side). Disabled while a request is in flight
 * ([RecordingPhase.RequestPending]) so it cannot be double-fired. 48dp touch target + a contentDescription
 * for accessibility. testTag: recording_button.
 */
@Composable
fun RecordingControl(
    phase: RecordingPhase,
    onRecord: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val enabled = phase == RecordingPhase.Idle
    val cd = stringResource(R.string.recording_request)
    val active = phase == RecordingPhase.Recording
    IconButton(
        onClick = onRecord,
        enabled = enabled,
        modifier = modifier
            .size(48.dp)
            .testTag("recording_button")
            .semantics { contentDescription = cd },
    ) {
        Icon(
            imageVector = Icons.Filled.FiberManualRecord,
            contentDescription = null,
            tint = if (active) {
                MaterialTheme.colorScheme.error
            } else if (enabled) {
                MaterialTheme.colorScheme.onSurface
            } else {
                MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)
            },
        )
    }
}
