@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.messaging.groupdetails

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.messaging.group.GroupParticipant
import com.testlogon.android.data.messaging.group.GroupRole

/** AND-158 — stable testTags for the group details (participants) screen. */
object GroupDetailsTestTags {
    const val SCREEN = "group_details_screen"
    const val LIST = "group_details_list"
    const val ROW = "group_details_row"
    const val ADD = "group_details_add"
    const val OVERFLOW = "group_details_overflow"
    const val ROW_SPINNER = "group_details_row_spinner"
    const val ADD_SHEET = "group_details_add_sheet"
    const val SETTINGS = "group_details_settings"
}

@Composable
fun GroupDetailsRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    onOpenSettings: () -> Unit = {},
    viewModel: GroupDetailsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is GroupDetailsEvent.ShowError -> snackbarHostState.showSnackbar(event.message)
            }
        }
    }

    GroupDetailsScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onOpenSettings = onOpenSettings,
        onRefresh = viewModel::refresh,
        onOpenAddPicker = viewModel::onOpenAddPicker,
        onCloseAddPicker = viewModel::onCloseAddPicker,
        onAddPickerQueryChange = viewModel::onAddPickerQueryChange,
        onAddParticipant = viewModel::onAddParticipant,
        onRemove = viewModel::onRemove,
        onChangeRole = viewModel::onChangeRole,
        modifier = modifier,
    )
}

@Composable
fun GroupDetailsScreen(
    state: RosterUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onOpenAddPicker: () -> Unit,
    onCloseAddPicker: () -> Unit,
    onAddPickerQueryChange: (String) -> Unit,
    onAddParticipant: (String) -> Unit,
    onRemove: (String) -> Unit,
    onChangeRole: (String, GroupRole) -> Unit,
    modifier: Modifier = Modifier,
    onOpenSettings: () -> Unit = {},
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    val canManage = (state as? RosterUiState.Content)?.canManage == true
    Scaffold(
        modifier = modifier.testTag(GroupDetailsTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.group_details_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    if (canManage) {
                        IconButton(
                            onClick = onOpenAddPicker,
                            modifier = Modifier.testTag(GroupDetailsTestTags.ADD),
                        ) {
                            Icon(
                                Icons.Filled.PersonAdd,
                                contentDescription = stringResource(R.string.group_add_people_cd),
                            )
                        }
                    }
                    IconButton(
                        onClick = onOpenSettings,
                        modifier = Modifier.testTag(GroupDetailsTestTags.SETTINGS),
                    ) {
                        Icon(
                            Icons.Filled.Settings,
                            contentDescription = stringResource(R.string.group_settings_cd),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is RosterUiState.Loading -> LoadingState()
                is RosterUiState.Error -> ErrorState(message = state.message, onRetry = onRefresh)
                is RosterUiState.Content -> RosterContent(
                    content = state,
                    onRefresh = onRefresh,
                    onRemove = onRemove,
                    onChangeRole = onChangeRole,
                )
            }
        }
    }

    val content = state as? RosterUiState.Content
    val picker = content?.addPicker
    if (picker != null) {
        ModalBottomSheet(
            onDismissRequest = onCloseAddPicker,
            modifier = Modifier.testTag(GroupDetailsTestTags.ADD_SHEET),
        ) {
            val existingIds = content.roster.participants.mapTo(mutableSetOf()) { it.userId }
            Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp)) {
                OutlinedTextField(
                    value = picker.query,
                    onValueChange = onAddPickerQueryChange,
                    singleLine = true,
                    label = { Text(stringResource(R.string.group_create_search_label)) },
                    modifier = Modifier.fillMaxWidth(),
                )
                LazyColumn(Modifier.fillMaxWidth().heightIn(max = 320.dp)) {
                    items(
                        picker.candidates.filterNot { existingIds.contains(it.id) },
                        key = { it.id },
                    ) { c ->
                        Text(
                            text = c.displayName,
                            style = MaterialTheme.typography.bodyLarge,
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(min = 48.dp)
                                .clickable { onAddParticipant(c.id) }
                                .padding(vertical = 12.dp),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun RosterContent(
    content: RosterUiState.Content,
    onRefresh: () -> Unit,
    onRemove: (String) -> Unit,
    onChangeRole: (String, GroupRole) -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = content.isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxSize().testTag(GroupDetailsTestTags.LIST),
        ) {
            items(content.roster.participants, key = { it.userId }) { p ->
                ParticipantRow(
                    participant = p,
                    isSelf = p.userId == content.roster.currentUserId,
                    canManage = content.canManage,
                    isPending = content.pendingUserIds.contains(p.userId),
                    onRemove = { onRemove(p.userId) },
                    onChangeRole = { role -> onChangeRole(p.userId, role) },
                )
            }
        }
    }
}

@Composable
private fun ParticipantRow(
    participant: GroupParticipant,
    isSelf: Boolean,
    canManage: Boolean,
    isPending: Boolean,
    onRemove: () -> Unit,
    onChangeRole: (GroupRole) -> Unit,
) {
    var menuOpen by remember { mutableStateOf(false) }
    var confirmRemove by remember { mutableStateOf(false) }
    if (confirmRemove) {
        AlertDialog(
            onDismissRequest = { confirmRemove = false },
            title = { Text(stringResource(R.string.group_remove_member)) },
            text = {
                Text(
                    stringResource(
                        R.string.group_remove_participant_cd,
                        participant.displayName ?: participant.userId,
                    ),
                )
            },
            confirmButton = {
                TextButton(onClick = { confirmRemove = false; onRemove() }) {
                    Text(stringResource(R.string.group_leave_confirm_action))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmRemove = false }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag(GroupDetailsTestTags.ROW),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                text = participant.displayName ?: participant.userId,
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            val roleLabel = when (participant.role) {
                GroupRole.ADMIN -> stringResource(R.string.group_role_admin)
                else -> stringResource(R.string.group_role_member)
            }
            AssistChip(onClick = {}, enabled = false, label = { Text(roleLabel) })
        }
        when {
            isPending -> CircularProgressIndicator(
                strokeWidth = 2.dp,
                modifier = Modifier.size(20.dp).testTag(GroupDetailsTestTags.ROW_SPINNER),
            )
            // Self / non-admin rows are read-only (no overflow menu).
            canManage && !isSelf -> {
                IconButton(
                    onClick = { menuOpen = true },
                    modifier = Modifier.testTag(GroupDetailsTestTags.OVERFLOW),
                ) {
                    Icon(
                        Icons.Filled.MoreVert,
                        contentDescription = stringResource(
                            R.string.group_member_actions_cd,
                            participant.displayName ?: participant.userId,
                        ),
                    )
                }
                DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                    if (participant.role == GroupRole.ADMIN) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.group_make_member)) },
                            onClick = { menuOpen = false; onChangeRole(GroupRole.MEMBER) },
                        )
                    } else {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.group_make_admin)) },
                            onClick = { menuOpen = false; onChangeRole(GroupRole.ADMIN) },
                        )
                    }
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.group_remove_member)) },
                        onClick = { menuOpen = false; confirmRemove = true },
                    )
                }
            }
        }
    }
}
