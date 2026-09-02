@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.files.shared

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.FolderShared
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.IconButton
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.getValue
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.model.files.FileShareMath
import com.testlogon.android.core.model.files.ShareExpiryStatus
import com.testlogon.android.core.model.files.SharePermission
import com.testlogon.android.core.model.files.SharedWithMeItemDto
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import java.time.Instant

/** FM-SHARE stable testTags for the "Shared with me" screen. */
object SharedWithMeTestTags {
    const val SCREEN = "shared_with_me_screen"
    const val LIST = "shared_with_me_list"
    const val ROW = "shared_with_me_row"
    const val EMPTY = "shared_with_me_empty"
    const val UNAVAILABLE = "shared_with_me_unavailable"
}

/** FM-SHARE - route wrapper: collects the state and delegates to the stateless [SharedWithMeScreen]. */
@Composable
fun SharedWithMeRoute(
    onBack: () -> Unit,
    onOpenShared: (owner: String, path: String) -> Unit = { _, _ -> },
    viewModel: SharedWithMeViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    SharedWithMeScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onOpenShared = onOpenShared,
    )
}

@Composable
fun SharedWithMeScreen(
    state: SharedWithMeUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onOpenShared: (owner: String, path: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(SharedWithMeTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Shared with me") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.isLoading -> LoadingState()
                state.errorMessage != null -> ErrorState(message = state.errorMessage, onRetry = onRetry)
                !state.available -> EmptyState(
                    title = "Sharing not available",
                    body = "This feature is not enabled for your account.",
                    imageVector = Icons.Outlined.FolderShared,
                    modifier = Modifier.testTag(SharedWithMeTestTags.UNAVAILABLE),
                )
                state.isEmpty -> EmptyState(
                    title = "Nothing shared with you",
                    body = "Files others share with you will appear here.",
                    imageVector = Icons.Outlined.FolderShared,
                    modifier = Modifier.testTag(SharedWithMeTestTags.EMPTY),
                )
                else -> PullToRefreshBox(
                    isRefreshing = state.isRefreshing,
                    onRefresh = onRefresh,
                ) {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag(SharedWithMeTestTags.LIST),
                        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(state.items) { item ->
                            SharedRow(item = item, onOpen = { onOpenShared(item.owner, item.path) })
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SharedRow(
    item: SharedWithMeItemDto,
    onOpen: () -> Unit,
) {
    val now = Instant.now()
    val permission = FileShareMath.parsePermission(item.permission)
    val expiry = FileShareMath.expiryStatus(item.expires_at, now)

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(SharedWithMeTestTags.ROW),
        onClick = onOpen,
    ) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                item.name ?: item.path.substringAfterLast('/').ifEmpty { item.path },
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                "from ${item.owner}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(
                    onClick = onOpen,
                    label = {
                        Text(if (permission == SharePermission.WRITE) "Can edit" else "Read-only")
                    },
                )
                if (expiry == ShareExpiryStatus.EXPIRED) {
                    AssistChip(
                        onClick = onOpen,
                        enabled = false,
                        label = { Text("Expired") },
                        colors = AssistChipDefaults.assistChipColors(),
                    )
                }
                item.size?.let { size ->
                    AssistChip(
                        onClick = onOpen,
                        label = { Text(FileShareMath.formatBytes(size)) },
                    )
                }
            }
        }
    }
}
