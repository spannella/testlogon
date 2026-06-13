@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.orgs

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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.orgs.OrgInvite
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-354 - stable testTags for the my-invites screen. */
object MyInvitesTestTags {
    const val SCREEN = "my_invites_screen"
    const val ROW_PREFIX = "my_invite_row_"
    const val ACCEPT_PREFIX = "my_invite_accept_"
    const val DECLINE_PREFIX = "my_invite_decline_"
}

/**
 * AND-354 - route-level my-invites entry. Lists the caller's own pending invitations with accept/decline
 * affordances per row.
 */
@Composable
fun MyInvitesRoute(
    onBack: () -> Unit,
    viewModel: MyInvitesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    MyInvitesScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onAccept = viewModel::accept,
        onDecline = viewModel::decline,
        onNoticeShown = viewModel::consumeNotice,
    )
}

/** AND-354 - stateless my-invites screen. */
@Composable
fun MyInvitesScreen(
    state: MyInvitesUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onAccept: (inviteId: String) -> Unit,
    onDecline: (inviteId: String) -> Unit,
    onNoticeShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }

    (state as? MyInvitesUiState.Content)?.notice?.let { notice ->
        LaunchedEffect(notice) {
            snackbarHostState.showSnackbar(notice)
            onNoticeShown()
        }
    }

    Scaffold(
        modifier = modifier.testTag(MyInvitesTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.my_invites_title)) },
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
    ) { padding ->
        when (state) {
            is MyInvitesUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding))

            is MyInvitesUiState.Empty ->
                EmptyState(
                    title = stringResource(R.string.my_invites_empty_title),
                    body = stringResource(R.string.my_invites_empty_body),
                    modifier = Modifier.padding(padding),
                )

            is MyInvitesUiState.Error ->
                ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.padding(padding),
                )

            is MyInvitesUiState.Content ->
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(state.invites, key = { it.inviteId }) { invite ->
                        MyInviteRow(
                            invite = invite,
                            acting = state.actingInviteId == invite.inviteId,
                            onAccept = onAccept,
                            onDecline = onDecline,
                        )
                    }
                }
        }
    }
}

@Composable
private fun MyInviteRow(
    invite: OrgInvite,
    acting: Boolean,
    onAccept: (inviteId: String) -> Unit,
    onDecline: (inviteId: String) -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(MyInvitesTestTags.ROW_PREFIX + invite.inviteId),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = invite.orgName ?: invite.orgId ?: stringResource(R.string.my_invites_unknown_org),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = invite.email,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = roleLabel(invite.role),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (acting) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
                } else {
                    TextButton(
                        onClick = { onDecline(invite.inviteId) },
                        modifier = Modifier.testTag(MyInvitesTestTags.DECLINE_PREFIX + invite.inviteId),
                    ) {
                        Text(stringResource(R.string.my_invites_decline))
                    }
                    TextButton(
                        onClick = { onAccept(invite.inviteId) },
                        modifier = Modifier.testTag(MyInvitesTestTags.ACCEPT_PREFIX + invite.inviteId),
                    ) {
                        Text(stringResource(R.string.my_invites_accept))
                    }
                }
            }
        }
    }
}
