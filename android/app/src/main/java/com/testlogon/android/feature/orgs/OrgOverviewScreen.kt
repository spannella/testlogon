@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.orgs

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.outlined.Group
import androidx.compose.material.icons.outlined.MarkEmailUnread
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.orgs.OrgRole
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner

/** AND-354 - stable testTags for the org overview hub screen. */
object OrgOverviewTestTags {
    const val SCREEN = "org_overview_screen"
    const val NAME = "org_overview_name"
    const val MEMBERS_NAV = "org_overview_members_nav"
    const val INVITES_NAV = "org_overview_invites_nav"
    const val LEAVE = "org_overview_leave"
    const val TRANSFER = "org_overview_transfer"
}

/**
 * AND-354 - route-level org OVERVIEW entry (the org hub reached from the More-hub "Organizations" entry).
 * Surfaces the active org's name/role/member-count and routes onward to the AND-353 Members screen and the
 * new My-Invites screen.
 */
@Composable
fun OrgOverviewRoute(
    onBack: () -> Unit,
    onOpenMembers: () -> Unit,
    onOpenInvites: () -> Unit,
    onOpenTransfer: () -> Unit,
    viewModel: OrgOverviewViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val leaving by viewModel.leaving.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(viewModel) {
        viewModel.events.collect { event ->
            when (event) {
                is OrgOverviewEvent.Left -> onBack()
                is OrgOverviewEvent.Message -> snackbarHostState.showSnackbar(event.text)
            }
        }
    }

    OrgOverviewScreen(
        state = state,
        leaving = leaving,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onOpenMembers = onOpenMembers,
        onOpenInvites = onOpenInvites,
        onOpenTransfer = onOpenTransfer,
        onLeave = viewModel::leaveOrg,
    )
}

/** AND-354 - stateless org overview hub screen. */
@Composable
fun OrgOverviewScreen(
    state: OrgOverviewUiState,
    leaving: Boolean,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onOpenMembers: () -> Unit,
    onOpenInvites: () -> Unit,
    onOpenTransfer: () -> Unit,
    onLeave: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(OrgOverviewTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.org_overview_title)) },
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
    ) { padding ->
        when (state) {
            is OrgOverviewUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding))

            is OrgOverviewUiState.Empty ->
                EmptyState(
                    title = stringResource(R.string.org_overview_empty_title),
                    body = stringResource(R.string.org_overview_empty_body),
                    modifier = Modifier.padding(padding),
                )

            is OrgOverviewUiState.Error ->
                ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.padding(padding),
                )

            is OrgOverviewUiState.Content ->
                OrgOverviewContent(
                    state = state,
                    leaving = leaving,
                    onRetry = onRetry,
                    onOpenMembers = onOpenMembers,
                    onOpenInvites = onOpenInvites,
                    onOpenTransfer = onOpenTransfer,
                    onLeave = onLeave,
                    modifier = Modifier.padding(padding),
                )
        }
    }
}

@Composable
private fun OrgOverviewContent(
    state: OrgOverviewUiState.Content,
    leaving: Boolean,
    onRetry: () -> Unit,
    onOpenMembers: () -> Unit,
    onOpenInvites: () -> Unit,
    onOpenTransfer: () -> Unit,
    onLeave: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var confirmLeave by remember { mutableStateOf(false) }
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        // FR-9: a stale banner sits above cached content when a refresh failed.
        StaleBanner(stale = state.isStale, refreshing = false, onRetry = onRetry)

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = state.org.name ?: state.org.orgId,
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.testTag(OrgOverviewTestTags.NAME),
            )
            Text(
                text = stringResource(R.string.org_overview_your_role, roleLabel(state.callerRole)),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = if (state.memberCount != null) {
                    stringResource(R.string.org_overview_member_count, state.memberCount)
                } else {
                    stringResource(R.string.org_overview_member_count_unknown)
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            OrgNavRow(
                icon = Icons.Outlined.Group,
                label = stringResource(R.string.org_overview_members),
                onClick = onOpenMembers,
                modifier = Modifier.testTag(OrgOverviewTestTags.MEMBERS_NAV),
            )
            OrgNavRow(
                icon = Icons.Outlined.MarkEmailUnread,
                label = stringResource(R.string.org_overview_my_invites),
                onClick = onOpenInvites,
                modifier = Modifier.testTag(OrgOverviewTestTags.INVITES_NAV),
            )

            // PAR-35(c) - owner-only transfer-ownership entry.
            if (state.callerRole == OrgRole.OWNER) {
                OutlinedButton(
                    onClick = onOpenTransfer,
                    modifier = Modifier.fillMaxWidth().testTag(OrgOverviewTestTags.TRANSFER),
                ) {
                    Text(stringResource(R.string.org_overview_transfer))
                }
            }

            // PAR-35(b) - leave the organization (destructive + confirm).
            Button(
                onClick = { confirmLeave = true },
                enabled = !leaving,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error,
                    contentColor = MaterialTheme.colorScheme.onError,
                ),
                modifier = Modifier.fillMaxWidth().testTag(OrgOverviewTestTags.LEAVE),
            ) {
                Text(stringResource(R.string.org_overview_leave))
            }
        }
    }

    if (confirmLeave) {
        AlertDialog(
            onDismissRequest = { confirmLeave = false },
            title = { Text(stringResource(R.string.org_leave_confirm_title)) },
            text = { Text(stringResource(R.string.org_leave_confirm_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmLeave = false
                    onLeave()
                }) {
                    Text(stringResource(R.string.org_leave_confirm_action))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmLeave = false }) {
                    Text(stringResource(R.string.org_leave_cancel))
                }
            },
        )
    }
}

/** A tappable nav row leading to a sub-screen (Members / My Invites). */
@Composable
private fun OrgNavRow(
    icon: ImageVector,
    label: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Icon(icon, contentDescription = null)
            Text(
                text = label,
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.weight(1f),
            )
            Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null)
        }
    }
}
