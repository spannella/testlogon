@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.watchparties

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.watchparties.WatchPartyStatus

/** Localized label for a party status. */
@Composable
fun statusLabel(status: WatchPartyStatus): String = stringResource(
    when (status) {
        WatchPartyStatus.WAITING -> R.string.watch_parties_status_waiting
        WatchPartyStatus.PLAYING -> R.string.watch_parties_status_playing
        WatchPartyStatus.PAUSED -> R.string.watch_parties_status_paused
        WatchPartyStatus.ENDED -> R.string.watch_parties_status_ended
        WatchPartyStatus.UNKNOWN -> R.string.watch_parties_status_unknown
    },
)

/**
 * Create-party form (web CreatePartyDialog parity: video id [required] + optional title + max
 * participants). Submit is disabled while [isSubmitting] or the video id is blank.
 */
@Composable
fun CreateWatchPartyDialog(
    isSubmitting: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (videoId: String, title: String, maxParticipants: Int?) -> Unit,
) {
    var videoId by remember { mutableStateOf("") }
    var title by remember { mutableStateOf("") }
    var maxText by remember { mutableStateOf("50") }

    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag("watch_parties_create_dialog"),
        title = { Text(stringResource(R.string.watch_parties_create_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = videoId,
                    onValueChange = { videoId = it },
                    label = { Text(stringResource(R.string.watch_parties_create_video_label)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("watch_parties_create_video"),
                )
                OutlinedTextField(
                    value = title,
                    onValueChange = { title = it },
                    label = { Text(stringResource(R.string.watch_parties_create_title_label)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("watch_parties_create_name"),
                )
                OutlinedTextField(
                    value = maxText,
                    onValueChange = { input -> maxText = input.filter { it.isDigit() }.take(3) },
                    label = { Text(stringResource(R.string.watch_parties_create_max_label)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth().testTag("watch_parties_create_max"),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(videoId, title, maxText.toIntOrNull()) },
                enabled = !isSubmitting && videoId.isNotBlank(),
                modifier = Modifier.testTag("watch_parties_create_confirm"),
            ) {
                Text(
                    stringResource(
                        if (isSubmitting) R.string.watch_parties_create_submitting
                        else R.string.watch_parties_create_confirm,
                    ),
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !isSubmitting) {
                Text(stringResource(R.string.action_cancel))
            }
        },
    )
}

/**
 * Transient invite-resolution route (web /party/{inviteCode}). Resolves the code to a party id and
 * invokes [onResolved] so the caller can replace this screen with the real detail destination. Shows a
 * spinner while resolving and a retryable error if the code is invalid / unreachable.
 */
@Composable
fun WatchPartyInviteRoute(
    onResolved: (partyId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: WatchPartyInviteViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(state) {
        val resolved = state as? WatchPartyInviteViewModel.InviteUiState.Resolved ?: return@LaunchedEffect
        onResolved(resolved.partyId)
    }

    Box(modifier = modifier.fillMaxSize().testTag("watch_party_invite_screen")) {
        when (state) {
            is WatchPartyInviteViewModel.InviteUiState.Failed ->
                ErrorState(
                    message = stringResource(R.string.watch_parties_invite_failed),
                    onRetry = viewModel::onRetry,
                    modifier = Modifier.testTag("watch_party_invite_error"),
                )
            else ->
                LoadingState(modifier = Modifier.testTag("watch_party_invite_loading"))
        }
    }
}
