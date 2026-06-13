@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.orgs

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.PersonAdd
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FloatingActionButton
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
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.mutableStateOf
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
import com.testlogon.android.core.model.orgs.OrgInvite
import com.testlogon.android.core.model.orgs.OrgMember
import com.testlogon.android.core.model.orgs.OrgRole
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-353 - stable testTags for the org members screen. */
object OrgMembersTestTags {
    const val SCREEN = "orgs_members_screen"
    const val INVITE = "orgs_invite"
    const val MEMBER_ROW_PREFIX = "orgs_member_row_"
    const val ROLE_PREFIX = "orgs_role_"
    const val REMOVE_PREFIX = "orgs_remove_"
    const val PENDING_INVITE_PREFIX = "orgs_pending_invite_"
}

/**
 * AND-353 - route-level org members entry (reachable from the More hub). Hosts the members roster +
 * pending invites and the manager-only invite affordance.
 */
@Composable
fun OrgMembersRoute(
    onBack: () -> Unit,
    onOpenInvite: () -> Unit,
    viewModel: OrgMembersViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    OrgMembersScreen(
        state = state,
        callerUserSub = viewModel.callerUserSub,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onChangeRole = viewModel::changeRole,
        onRemove = viewModel::removeMember,
        onInvite = onOpenInvite,
        onNoticeShown = viewModel::consumeNotice,
    )
}

/** AND-353 - stateless org members screen. */
@Composable
fun OrgMembersScreen(
    state: OrgMembersUiState,
    callerUserSub: String?,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onChangeRole: (memberSub: String, role: OrgRole) -> Unit,
    onRemove: (memberSub: String) -> Unit,
    onInvite: () -> Unit,
    onNoticeShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    val canManage = (state as? OrgMembersUiState.Content)?.canManage == true

    (state as? OrgMembersUiState.Content)?.notice?.let { notice ->
        LaunchedEffect(notice) {
            snackbarHostState.showSnackbar(notice)
            onNoticeShown()
        }
    }

    Scaffold(
        modifier = modifier.testTag(OrgMembersTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.orgs_members_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.orgs_back),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        floatingActionButton = {
            if (canManage) {
                val inviteCd = stringResource(R.string.orgs_invite_cd)
                FloatingActionButton(
                    onClick = onInvite,
                    modifier = Modifier
                        .testTag(OrgMembersTestTags.INVITE)
                        .semantics { contentDescription = inviteCd },
                ) {
                    Icon(Icons.Outlined.PersonAdd, contentDescription = null)
                }
            }
        },
    ) { padding ->
        when (state) {
            is OrgMembersUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding))

            is OrgMembersUiState.Error ->
                ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.padding(padding),
                )

            is OrgMembersUiState.Content ->
                OrgMembersContent(
                    state = state,
                    callerUserSub = callerUserSub,
                    onChangeRole = onChangeRole,
                    onRemove = onRemove,
                    modifier = Modifier.padding(padding),
                )
        }
    }
}

@Composable
private fun OrgMembersContent(
    state: OrgMembersUiState.Content,
    callerUserSub: String?,
    onChangeRole: (memberSub: String, role: OrgRole) -> Unit,
    onRemove: (memberSub: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    if (state.members.isEmpty() && state.pendingInvites.isEmpty()) {
        EmptyState(
            title = stringResource(R.string.orgs_empty_title),
            body = stringResource(R.string.orgs_empty_body),
            modifier = modifier,
        )
        return
    }
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Text(
                text = state.org.name ?: state.org.orgId,
                style = MaterialTheme.typography.titleLarge,
            )
        }
        item {
            Text(
                text = stringResource(R.string.orgs_section_members),
                style = MaterialTheme.typography.titleMedium,
            )
        }
        items(state.members, key = { it.userSub }) { member ->
            MemberRow(
                member = member,
                state = state,
                callerUserSub = callerUserSub,
                onChangeRole = onChangeRole,
                onRemove = onRemove,
            )
            HorizontalDivider()
        }
        if (state.pendingInvites.isNotEmpty()) {
            item {
                Text(
                    text = stringResource(R.string.orgs_section_pending_invites),
                    style = MaterialTheme.typography.titleMedium,
                )
            }
            items(state.pendingInvites, key = { it.inviteId }) { invite ->
                PendingInviteRow(invite)
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun MemberRow(
    member: OrgMember,
    state: OrgMembersUiState.Content,
    callerUserSub: String?,
    onChangeRole: (memberSub: String, role: OrgRole) -> Unit,
    onRemove: (memberSub: String) -> Unit,
) {
    val isMutating = state.mutatingMemberSub == member.userSub
    val canChangeRole = state.canChangeRole(member) && !isMutating
    val canRemove = state.canRemove(member, callerUserSub) && !isMutating

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(OrgMembersTestTags.MEMBER_ROW_PREFIX + member.userSub)
            .padding(vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        // FLAGGED: there is NO display_name / email on the member wire row, so user_sub is rendered.
        Text(text = member.userSub, style = MaterialTheme.typography.bodyLarge)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = member.status ?: stringResource(R.string.orgs_status_unknown),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (state.canManage) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RolePicker(
                    selected = member.role,
                    enabled = canChangeRole,
                    onSelect = { onChangeRole(member.userSub, it) },
                    modifier = Modifier
                        .weight(1f)
                        .testTag(OrgMembersTestTags.ROLE_PREFIX + member.userSub),
                )
                if (isMutating) {
                    CircularProgressIndicator(
                        strokeWidth = 2.dp,
                        modifier = Modifier.size(20.dp),
                    )
                } else {
                    TextButton(
                        onClick = { onRemove(member.userSub) },
                        enabled = canRemove,
                        modifier = Modifier.testTag(OrgMembersTestTags.REMOVE_PREFIX + member.userSub),
                    ) {
                        Text(stringResource(R.string.orgs_remove))
                    }
                }
            }
        } else {
            // Non-managers see a READ-ONLY roster (FR-6): the role is shown as plain text.
            Text(
                text = roleLabel(member.role),
                style = MaterialTheme.typography.labelLarge,
            )
        }
    }
}

/** AND-353 - role picker offering admin/member/viewer ONLY (owner is NOT assignable). */
@Composable
private fun RolePicker(
    selected: OrgRole,
    enabled: Boolean,
    onSelect: (OrgRole) -> Unit,
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
            label = { Text(stringResource(R.string.orgs_role_label)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(),
        )
        ExposedDropdownMenu(
            expanded = expanded && enabled,
            onDismissRequest = { expanded = false },
        ) {
            OrgRole.ASSIGNABLE.forEach { role ->
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
private fun PendingInviteRow(invite: OrgInvite) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(OrgMembersTestTags.PENDING_INVITE_PREFIX + invite.inviteId)
            .padding(vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(text = invite.email, style = MaterialTheme.typography.bodyLarge)
        Text(
            text = roleLabel(invite.role),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** Maps an [OrgRole] to its display label (UNKNOWN -> a generic label). */
@Composable
internal fun roleLabel(role: OrgRole): String = stringResource(
    when (role) {
        OrgRole.OWNER -> R.string.orgs_role_owner
        OrgRole.ADMIN -> R.string.orgs_role_admin
        OrgRole.MEMBER -> R.string.orgs_role_member
        OrgRole.VIEWER -> R.string.orgs_role_viewer
        OrgRole.UNKNOWN -> R.string.orgs_role_unknown
    },
)
