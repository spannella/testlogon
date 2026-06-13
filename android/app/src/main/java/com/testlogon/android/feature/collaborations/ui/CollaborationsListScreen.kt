@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.collaborations.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Diversity3
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.R
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-358 - stable testTags for the collaborations list screen + its rows. */
object CollaborationsListTestTags {
    const val SCREEN = "collabs_list_screen"

    fun row(collabId: String) = "collab_row_$collabId"
}

/** AND-358 - route-level list entry; collects the paged collaborations + the viewer id for per-row share. */
@Composable
fun CollaborationsListRoute(
    onBack: () -> Unit,
    onOpenCollaboration: (String) -> Unit,
    viewModel: CollaborationsListViewModel = hiltViewModel(),
) {
    val items = viewModel.items.collectAsLazyPagingItems()
    CollaborationsListScreen(
        items = items,
        viewerId = viewModel.viewerId,
        onBack = onBack,
        onOpenCollaboration = onOpenCollaboration,
    )
}

/** AND-358 - stateless READ-ONLY collaborations list (network Paging-3). */
@Composable
fun CollaborationsListScreen(
    items: LazyPagingItems<Collaboration>,
    viewerId: String?,
    onBack: () -> Unit,
    onOpenCollaboration: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CollaborationsListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.collaborations_list_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.collaborations_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        val refresh = items.loadState.refresh
        PullToRefreshBox(
            isRefreshing = refresh is LoadState.Loading && items.itemCount > 0,
            onRefresh = { items.refresh() },
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when {
                refresh is LoadState.Loading && items.itemCount == 0 ->
                    LoadingState()

                refresh is LoadState.Error && items.itemCount == 0 ->
                    ErrorState(
                        message = stringResource(R.string.collaborations_list_error),
                        onRetry = { items.retry() },
                    )

                items.itemCount == 0 ->
                    EmptyState(
                        title = stringResource(R.string.collaborations_empty_title),
                        body = stringResource(R.string.collaborations_empty_body),
                        imageVector = Icons.Outlined.Diversity3,
                    )

                else -> LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(
                        count = items.itemCount,
                        key = { index -> items[index]?.id ?: "collab_$index" },
                    ) { index ->
                        val collab = items[index] ?: return@items
                        CollaborationRow(
                            collab = collab,
                            viewerShare = collab.shareFor(viewerId),
                            onClick = { onOpenCollaboration(collab.id) },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun CollaborationRow(
    collab: Collaboration,
    viewerShare: Int?,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(CollaborationsListTestTags.row(collab.id))
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(end = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = collab.title.ifBlank { stringResource(R.string.collaborations_untitled) },
                style = MaterialTheme.typography.titleSmall,
            )
            StatusBadge(collab)
        }
        if (viewerShare != null) {
            Text(
                text = stringResource(R.string.collaborations_your_share, viewerShare),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary,
            )
        }
    }
}

@Composable
private fun StatusBadge(collab: Collaboration) {
    val label = statusLabel(collab)
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(label) },
        colors = AssistChipDefaults.assistChipColors(),
    )
}
