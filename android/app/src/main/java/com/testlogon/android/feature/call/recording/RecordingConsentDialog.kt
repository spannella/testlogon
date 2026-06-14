package com.testlogon.android.feature.call.recording

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import com.testlogon.android.R

/**
 * AND-302 — consent prompt shown to the CALLEE when the peer requests to record the call.
 *
 * Pure presentational: it renders the requester name and the Allow/Decline actions; the caller wires the
 * callbacks to [RecordingController.consent]/[RecordingController.decline]. The accept button maps to the
 * REST consent endpoint (the server consent GATE) — capture never starts client-side from this tap alone.
 * testTags: recording_consent (dialog), recording_consent_accept, recording_consent_decline.
 */
@Composable
fun RecordingConsentDialog(
    requesterName: String?,
    onAccept: () -> Unit,
    onDecline: () -> Unit,
) {
    val name = requesterName ?: stringResource(R.string.call_unknown_caller)
    AlertDialog(
        onDismissRequest = onDecline,
        modifier = Modifier.testTag("recording_consent"),
        title = { Text(text = stringResource(R.string.recording_consent_title, name)) },
        confirmButton = {
            TextButton(
                onClick = onAccept,
                modifier = Modifier.testTag("recording_consent_accept"),
            ) {
                Text(stringResource(R.string.recording_consent_accept))
            }
        },
        dismissButton = {
            TextButton(
                onClick = onDecline,
                modifier = Modifier.testTag("recording_consent_decline"),
            ) {
                Text(stringResource(R.string.recording_consent_decline))
            }
        },
    )
}
