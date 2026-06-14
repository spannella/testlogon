@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.guest

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState

/** AND-312 - stable testTags for the guest accept surface. */
object GuestAcceptTestTags {
    const val SCREEN = "guest_accept_screen"
    const val NAME = "guest_accept_name"
    const val SUBMIT = "guest_accept_submit"
    const val DECLINE = "guest_accept_decline"
    const val JOINED = "guest_accept_joined"
}

/**
 * AND-312 - guest accept entry. Collects [GuestAcceptViewModel] state and delegates to the stateless screen.
 * Reached from the testlogon://guest/accept deep link (identity = sessionId + inviteId, NOT a token).
 */
@Composable
fun GuestAcceptRoute(
    onDone: () -> Unit,
    viewModel: GuestAcceptViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    GuestAcceptScreen(
        state = state,
        onDisplayNameChange = viewModel::onDisplayNameChange,
        onAccept = viewModel::onAccept,
        onDecline = onDone,
    )
}

/**
 * AND-312 - stateless guest accept surface: a best-effort host/broadcast summary, a REQUIRED display-name
 * field, and Accept / Decline buttons. On success it shows a joined confirmation surfacing the joined state
 * (the AND-308 media handoff using input_id / ingest_url is FLAGGED - this screen only confirms the join).
 */
@Composable
fun GuestAcceptScreen(
    state: GuestAcceptUiState,
    onDisplayNameChange: (String) -> Unit,
    onAccept: () -> Unit,
    onDecline: () -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag(GuestAcceptTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.guest_accept_title)) },
                navigationIcon = {
                    IconButton(onClick = onDecline) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.guest_accept_back_cd),
                        )
                    }
                },
            )
        },
    ) { padding ->
        if (state.accepted != null) {
            EmptyState(
                title = stringResource(R.string.guest_accept_joined_title),
                body = stringResource(R.string.guest_accept_joined_body),
                modifier = Modifier
                    .padding(padding)
                    .testTag(GuestAcceptTestTags.JOINED),
            )
            return@Scaffold
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = stringResource(R.string.guest_accept_summary),
                style = MaterialTheme.typography.bodyLarge,
            )

            val nameCd = stringResource(R.string.guest_accept_name_cd)
            OutlinedTextField(
                value = state.displayName,
                onValueChange = onDisplayNameChange,
                singleLine = true,
                enabled = !state.isSubmitting,
                label = { Text(stringResource(R.string.guest_accept_name_label)) },
                isError = state.error != null,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(GuestAcceptTestTags.NAME)
                    .semantics { contentDescription = nameCd },
            )

            if (state.error != null) {
                Text(
                    text = state.error,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier
                        .fillMaxWidth()
                        .semantics { liveRegion = LiveRegionMode.Polite },
                )
            }

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(
                    onClick = onAccept,
                    enabled = state.canSubmit,
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 48.dp)
                        .testTag(GuestAcceptTestTags.SUBMIT),
                ) {
                    if (state.isSubmitting) {
                        CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
                    } else {
                        Text(stringResource(R.string.guest_accept_submit))
                    }
                }
                OutlinedButton(
                    onClick = onDecline,
                    enabled = !state.isSubmitting,
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 48.dp)
                        .testTag(GuestAcceptTestTags.DECLINE),
                ) {
                    Text(stringResource(R.string.guest_accept_decline))
                }
            }
        }
    }
}
