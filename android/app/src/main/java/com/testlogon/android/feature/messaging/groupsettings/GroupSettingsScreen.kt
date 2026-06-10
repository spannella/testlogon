@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.messaging.groupsettings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.messaging.group.MembershipStatus

/** AND-159 — stable testTags for the group settings screen. */
object GroupSettingsTestTags {
    const val SCREEN = "group_settings_screen"
    const val MUTE_SWITCH = "group_settings_mute"
    const val LEAVE = "group_settings_leave"
    const val ACCEPT = "group_settings_accept"
    const val DECLINE = "group_settings_decline"
    const val LEFT_TERMINAL = "group_settings_left"
}

@Composable
fun GroupSettingsRoute(
    onLeftGroup: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: GroupSettingsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is GroupSettingsEvent.LeftGroup -> onLeftGroup()
                is GroupSettingsEvent.ShowSnackbar -> snackbarHostState.showSnackbar(event.text)
            }
        }
    }

    GroupSettingsScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onSetMuted = viewModel::setMuted,
        onLeave = viewModel::leave,
        onAccept = viewModel::acceptInvite,
        onRetry = viewModel::load,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun GroupSettingsScreen(
    state: GroupSettingsUiState,
    onSetMuted: (Boolean, MuteDuration) -> Unit,
    onLeave: () -> Unit,
    onAccept: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    var showLeaveConfirm by remember { mutableStateOf(false) }
    var showMuteSheet by remember { mutableStateOf(false) }

    Scaffold(
        modifier = modifier.testTag(GroupSettingsTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = {
                    Text(state.groupName.ifBlank { stringResource(R.string.group_settings_title) })
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state.phase) {
                GroupSettingsUiState.Phase.Loading -> LoadingState()
                GroupSettingsUiState.Phase.NotFound ->
                    EmptyState(title = stringResource(R.string.group_settings_not_found))
                GroupSettingsUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.group_settings_error),
                        onRetry = onRetry,
                    )
                GroupSettingsUiState.Phase.Content -> ContentBody(
                    state = state,
                    onMuteToggle = { enable ->
                        if (enable) showMuteSheet = true else onSetMuted(false, MuteDuration.FOREVER)
                    },
                    onAccept = onAccept,
                    onLeaveClick = { showLeaveConfirm = true },
                )
            }
        }
    }

    if (showLeaveConfirm) {
        AlertDialog(
            onDismissRequest = { showLeaveConfirm = false },
            title = { Text(stringResource(R.string.group_leave_confirm_title)) },
            text = { Text(stringResource(R.string.group_leave_confirm_body, state.groupName)) },
            confirmButton = {
                TextButton(onClick = { showLeaveConfirm = false; onLeave() }) {
                    Text(stringResource(R.string.group_leave_confirm_action))
                }
            },
            dismissButton = {
                TextButton(onClick = { showLeaveConfirm = false }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }

    if (showMuteSheet) {
        ModalBottomSheet(onDismissRequest = { showMuteSheet = false }) {
            Column(Modifier.fillMaxWidth().padding(16.dp)) {
                Text(
                    stringResource(R.string.group_mute_duration_title),
                    style = MaterialTheme.typography.titleMedium,
                )
                MuteDuration.entries.forEach { d ->
                    val label = when (d) {
                        MuteDuration.EIGHT_HOURS -> stringResource(R.string.group_mute_8h)
                        MuteDuration.ONE_WEEK -> stringResource(R.string.group_mute_1w)
                        MuteDuration.FOREVER -> stringResource(R.string.group_mute_forever)
                    }
                    Text(
                        text = label,
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 48.dp)
                            .clickable { showMuteSheet = false; onSetMuted(true, d) }
                            .padding(vertical = 12.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun ContentBody(
    state: GroupSettingsUiState,
    onMuteToggle: (Boolean) -> Unit,
    onAccept: () -> Unit,
    onLeaveClick: () -> Unit,
) {
    Column(
        Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        when (state.membership) {
            MembershipStatus.INVITED -> {
                Text(
                    stringResource(R.string.group_invite_prompt),
                    style = MaterialTheme.typography.bodyLarge,
                )
                Button(
                    onClick = onAccept,
                    enabled = state.actionInFlight == null,
                    modifier = Modifier.fillMaxWidth().testTag(GroupSettingsTestTags.ACCEPT),
                ) {
                    if (state.actionInFlight == ActionKind.ACCEPT) {
                        CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
                    } else {
                        Text(stringResource(R.string.group_accept_invite))
                    }
                }
                TextButton(
                    onClick = onLeaveClick,
                    enabled = state.actionInFlight == null,
                    modifier = Modifier.fillMaxWidth().testTag(GroupSettingsTestTags.DECLINE),
                ) {
                    Text(stringResource(R.string.group_decline_invite))
                }
            }
            MembershipStatus.LEFT -> {
                Text(
                    stringResource(R.string.group_left_terminal),
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.testTag(GroupSettingsTestTags.LEFT_TERMINAL),
                )
            }
            else -> {
                // Active (or unknown-but-readable): mute switch + leave.
                val muteCd = stringResource(R.string.group_mute_cd)
                Row(
                    Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        stringResource(R.string.group_mute_label),
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.weight(1f),
                    )
                    Switch(
                        checked = state.muted,
                        onCheckedChange = onMuteToggle,
                        enabled = state.actionInFlight != ActionKind.LEAVE,
                        modifier = Modifier
                            .semantics { contentDescription = muteCd }
                            .testTag(GroupSettingsTestTags.MUTE_SWITCH),
                    )
                }
                Button(
                    onClick = onLeaveClick,
                    enabled = state.actionInFlight == null,
                    colors = androidx.compose.material3.ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer,
                        contentColor = MaterialTheme.colorScheme.onErrorContainer,
                    ),
                    modifier = Modifier.fillMaxWidth().testTag(GroupSettingsTestTags.LEAVE),
                ) {
                    if (state.actionInFlight == ActionKind.LEAVE) {
                        CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
                    } else {
                        Text(stringResource(R.string.group_leave_action))
                    }
                }
            }
        }
    }
}

