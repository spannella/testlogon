@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.groups

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.groups.GroupMember
import com.testlogon.android.core.model.groups.GroupRole
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-355 - stable testTags for the social-group members screen. */
object GroupMembersTestTags {
    const val SCREEN = "group_members_screen"
    const val INVITE = "group_invite"
    const val MEMBER_ROW_PREFIX = "group_member_row_"
    const val ROLE_PREFIX = "group_role_"
    const val REMOVE_PREFIX = "group_remove_"
    const val PENDING_PREFIX = "group_pending_"
}

/** AND-355 - route-level group members entry. */
@Composable
fun GroupMembersRoute(
    onBack: () -> Unit,
    viewModel: GroupMembersViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    GroupMembersScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onInvite = viewModel::invite,
        onChangeRole = viewModel::changeRole,
        onRemove = viewModel::removeMember,
        onNoticeShown = viewModel::consumeNotice,
    )
}

/** AND-355 - stateless social-group members screen (roster + pending invites + manager controls). */
@Composable
fun GroupMembersScreen(
    state: GroupMembersUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onInvite: (userId: String) -> Unit,
    onChangeRole: (userId: String, role: GroupRole) -> Unit,
    onRemove: (userId: String) -> Unit,
    onNoticeShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }

    (state as? GroupMembersUiState.Content)?.notice?.let { notice ->
        LaunchedEffect(notice) {
            snackbarHostState.showSnackbar(notice)
            onNoticeShown()
        }
    }

    Scaffold(
        modifier = modifier.testTag(GroupMembersTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.groups_members_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.groups_back),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        when (state) {
            is GroupMembersUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding))

            is GroupMembersUiState.Error ->
                ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.padding(padding),
                )

            is GroupMembersUiState.Content ->
                GroupMembersContent(
                    state = state,
                    onInvite = onInvite,
                    onChangeRole = onChangeRole,
                    onRemove = onRemove,
                    modifier = Modifier.padding(padding),
                )
        }
    }
}

@Composable
private fun GroupMembersContent(
    state: GroupMembersUiState.Content,
    onInvite: (userId: String) -> Unit,
    onChangeRole: (userId: String, role: GroupRole) -> Unit,
    onRemove: (userId: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    if (state.members.isEmpty() && state.pending.isEmpty() && !state.canManage) {
        EmptyState(
            title = stringResource(R.string.groups_members_empty_title),
            body = stringResource(R.string.groups_members_empty_body),
            modifier = modifier,
        )
        return
    }
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (state.canManage) {
            item {
                InviteRow(enabled = !state.isInviting, onInvite = onInvite)
            }
        }
        item {
            Text(
                text = stringResource(R.string.groups_section_members),
                style = MaterialTheme.typography.titleMedium,
            )
        }
        items(state.members, key = { it.userId }) { member ->
            MemberRow(
                member = member,
                state = state,
                onChangeRole = onChangeRole,
                onRemove = onRemove,
            )
            HorizontalDivider()
        }
        if (state.pending.isNotEmpty()) {
            item {
                Text(
                    text = stringResource(R.string.groups_section_pending),
                    style = MaterialTheme.typography.titleMedium,
                )
            }
            items(state.pending, key = { it.userId }) { invitee ->
                PendingRow(invitee)
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun InviteRow(
    enabled: Boolean,
    onInvite: (userId: String) -> Unit,
) {
    var userId by remember { mutableStateOf("") }
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        OutlinedTextField(
            value = userId,
            onValueChange = { userId = it },
            label = { Text(stringResource(R.string.groups_invite_user_id_label)) },
            singleLine = true,
            enabled = enabled,
            modifier = Modifier.weight(1f),
        )
        Button(
            onClick = {
                onInvite(userId.trim())
                userId = ""
            },
            enabled = enabled && userId.isNotBlank(),
            modifier = Modifier.testTag(GroupMembersTestTags.INVITE),
        ) {
            Text(stringResource(R.string.groups_invite))
        }
    }
}

@Composable
private fun MemberRow(
    member: GroupMember,
    state: GroupMembersUiState.Content,
    onChangeRole: (userId: String, role: GroupRole) -> Unit,
    onRemove: (userId: String) -> Unit,
) {
    val isMutating = state.mutatingUserId == member.userId
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(GroupMembersTestTags.MEMBER_ROW_PREFIX + member.userId)
            .padding(vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            text = member.displayName ?: member.userId,
            style = MaterialTheme.typography.bodyLarge,
        )
        if (state.canManage) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RolePicker(
                    selected = member.role,
                    enabled = !isMutating && member.role != GroupRole.ADMIN,
                    onSelect = { onChangeRole(member.userId, it) },
                    modifier = Modifier
                        .weight(1f)
                        .testTag(GroupMembersTestTags.ROLE_PREFIX + member.userId),
                )
                if (isMutating) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
                } else {
                    TextButton(
                        onClick = { onRemove(member.userId) },
                        modifier = Modifier.testTag(GroupMembersTestTags.REMOVE_PREFIX + member.userId),
                    ) {
                        Text(stringResource(R.string.groups_remove))
                    }
                }
            }
        } else {
            // Non-managers see a READ-ONLY roster: the role is shown as plain text.
            Text(text = roleLabel(member.role), style = MaterialTheme.typography.labelLarge)
        }
    }
}

/** AND-355 - role picker offering moderator/member ONLY (admin is NOT assignable - admin is the owner). */
@Composable
private fun RolePicker(
    selected: GroupRole,
    enabled: Boolean,
    onSelect: (GroupRole) -> Unit,
    modifier: Modifier = Modifier,
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded && enabled,
        onExpandedChange = { if (enabled) expanded = it },
        modifier = modifier,
    ) {
        OutlinedTextField(
            value = roleLabel(selected),
            onValueChange = {},
            readOnly = true,
            enabled = enabled,
            label = { Text(stringResource(R.string.groups_role_label)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(),
        )
        ExposedDropdownMenu(
            expanded = expanded && enabled,
            onDismissRequest = { expanded = false },
        ) {
            GroupRole.ASSIGNABLE.forEach { role ->
                DropdownMenuItem(
                    text = { Text(roleLabel(role)) },
                    onClick = {
                        expanded = false
                        if (role != selected) onSelect(role)
                    },
                )
            }
        }
    }
}

@Composable
private fun PendingRow(invitee: GroupMember) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(GroupMembersTestTags.PENDING_PREFIX + invitee.userId)
            .padding(vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(text = invitee.displayName ?: invitee.userId, style = MaterialTheme.typography.bodyLarge)
        Text(
            text = stringResource(R.string.groups_status_invited),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
