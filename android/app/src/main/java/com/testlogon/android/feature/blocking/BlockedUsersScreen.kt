@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.blocking

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
import androidx.compose.material.icons.outlined.Block
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
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.blocking.BlockedUser
import com.testlogon.android.core.ui.blocking.BlockConfirmDialog
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner

/** P0-BLOCK — stable testTags for the Blocked Users screen + its rows. */
object BlockedUsersTestTags {
    const val SCREEN = "blocked_users_screen"
    const val EMPTY = "blocked_users_empty"
    const val ERROR_RETRY = "blocked_users_error_retry"

    fun row(id: String) = "blocked_user_row_$id"
    fun unblock(id: String) = "blocked_user_unblock_$id"
}

/**
 * P0-BLOCK — route-level entry for the Blocked Users management screen. Collects state, wires the
 * one-shot transient-message effect to the snackbar, and forwards the confirm-gated unblock.
 */
@Composable
fun BlockedUsersRoute(
    onBack: () -> Unit,
    viewModel: BlockedUsersViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val updateFailed = stringResource(R.string.block_update_failed)

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is BlockedUsersEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(message = updateFailed)
            }
        }
    }

    BlockedUsersScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onUnblockRequested = viewModel::onUnblockRequested,
        onUnblockConfirmed = viewModel::onUnblockConfirmed,
        onUnblockDismissed = viewModel::onUnblockDismissed,
    )
}

/** P0-BLOCK — stateless Blocked Users list (avatar + name + Unblock, with a confirm dialog). */
@Composable
fun BlockedUsersScreen(
    state: BlockedUsersUiState,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onUnblockRequested: (BlockedUser) -> Unit,
    onUnblockConfirmed: () -> Unit,
    onUnblockDismissed: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(BlockedUsersTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.blocked_users_title)) },
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
        val isRefreshing = (state as? BlockedUsersUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state) {
                is BlockedUsersUiState.Loading -> LoadingState()

                is BlockedUsersUiState.Empty ->
                    EmptyState(
                        modifier = Modifier.testTag(BlockedUsersTestTags.EMPTY),
                        title = stringResource(R.string.blocked_users_empty_title),
                        body = stringResource(R.string.blocked_users_empty_body),
                        imageVector = Icons.Outlined.Block,
                    )

                is BlockedUsersUiState.Error ->
                    ErrorState(
                        modifier = Modifier.testTag(BlockedUsersTestTags.ERROR_RETRY),
                        message = state.message,
                        onRetry = onRetry,
                    )

                is BlockedUsersUiState.Content ->
                    BlockedUsersContent(
                        state = state,
                        onRetry = onRetry,
                        onUnblockRequested = onUnblockRequested,
                    )
            }
        }
    }

    val pending = (state as? BlockedUsersUiState.Content)?.pendingUnblock
    if (pending != null) {
        val handle = pending.displayName?.takeIf { it.isNotBlank() } ?: pending.userId
        BlockConfirmDialog(
            title = stringResource(R.string.unblock_confirm_title, handle),
            body = stringResource(R.string.unblock_confirm_body),
            confirmLabel = stringResource(R.string.unblock_action),
            dismissLabel = stringResource(R.string.block_confirm_cancel),
            onConfirm = onUnblockConfirmed,
            onDismiss = onUnblockDismissed,
        )
    }
}

@Composable
private fun BlockedUsersContent(
    state: BlockedUsersUiState.Content,
    onRetry: () -> Unit,
    onUnblockRequested: (BlockedUser) -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        StaleBanner(stale = state.isStale, refreshing = false, onRetry = onRetry)
        if (state.actionError != null) {
            Text(
                text = state.actionError,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            )
        }
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            items(items = state.items, key = { it.userId }) { user ->
                BlockedUserRow(
                    user = user,
                    unblocking = state.unblockingId == user.userId,
                    onUnblock = { onUnblockRequested(user) },
                )
            }
        }
    }
}

@Composable
private fun BlockedUserRow(
    user: BlockedUser,
    unblocking: Boolean,
    onUnblock: () -> Unit,
) {
    val label = user.displayName?.takeIf { it.isNotBlank() } ?: user.userId
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(BlockedUsersTestTags.row(user.userId)),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            com.testlogon.android.feature.common.TlAvatar(
                name = label,
                photoUrl = user.profilePhotoUrl,
                size = 40.dp,
                textStyle = MaterialTheme.typography.labelLarge,
            )
            Text(
                text = label,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            if (unblocking) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
            } else {
                TextButton(
                    onClick = onUnblock,
                    modifier = Modifier.testTag(BlockedUsersTestTags.unblock(user.userId)),
                ) {
                    Text(stringResource(R.string.unblock_action))
                }
            }
        }
    }
}
