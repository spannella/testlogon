@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.groups

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.SubcomposeAsyncImage
import coil.request.ImageRequest
import com.testlogon.android.R
import com.testlogon.android.core.model.groups.Group
import com.testlogon.android.core.model.groups.GroupRole
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner

/** AND-355 - stable testTags for the social-groups list screen. */
object GroupsListTestTags {
    const val SCREEN = "groups_list_screen"
    const val ROW_PREFIX = "group_row_"
}

/** AND-355 - route-level groups list entry (reachable from the More hub). */
@Composable
fun GroupsListRoute(
    onBack: () -> Unit,
    onOpenGroup: (String) -> Unit,
    viewModel: GroupsListViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    GroupsListScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::load,
        onRefresh = viewModel::refresh,
        onOpenGroup = onOpenGroup,
    )
}

/** AND-355 - stateless social-groups list screen (discovery). */
@Composable
fun GroupsListScreen(
    state: GroupsListUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onOpenGroup: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(GroupsListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.groups_list_title)) },
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
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is GroupsListUiState.Loading -> LoadingState()

                is GroupsListUiState.Empty ->
                    EmptyState(
                        title = stringResource(R.string.groups_empty_title),
                        body = stringResource(R.string.groups_empty_body),
                    )

                is GroupsListUiState.Error ->
                    ErrorState(message = state.error.message, onRetry = onRetry)

                is GroupsListUiState.Content ->
                    GroupsListContent(
                        state = state,
                        onRefresh = onRefresh,
                        onRetry = onRetry,
                        onOpenGroup = onOpenGroup,
                    )
            }
        }
    }
}

@Composable
private fun GroupsListContent(
    state: GroupsListUiState.Content,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onOpenGroup: (String) -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = state.isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        Column(Modifier.fillMaxSize()) {
            if (state.staleError != null) {
                OfflineBanner(message = state.staleError.message, onRetry = onRetry)
            }
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                items(state.groups, key = { it.id }) { group ->
                    GroupRow(group = group, onClick = { onOpenGroup(group.id) })
                }
            }
        }
    }
}

@Composable
private fun GroupRow(
    group: Group,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(GroupsListTestTags.ROW_PREFIX + group.id)
            .clickable(onClick = onClick)
            .padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        GroupCover(group)
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = group.name,
                style = MaterialTheme.typography.titleMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            val count = group.memberCount
            if (count != null) {
                Text(
                    text = stringResource(R.string.groups_member_count, count),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        AssistChip(
            onClick = onClick,
            label = { Text(roleLabel(group.myRole)) },
        )
    }
}

@Composable
private fun GroupCover(group: Group) {
    val cd = group.name
    Box(
        modifier = Modifier
            .size(48.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant),
        contentAlignment = Alignment.Center,
    ) {
        val url = group.coverImageUrl
        if (url != null) {
            SubcomposeAsyncImage(
                model = ImageRequest.Builder(LocalContext.current).data(url).crossfade(true).build(),
                contentDescription = cd,
                loading = { Box(Modifier.fillMaxSize().height(48.dp)) },
                modifier = Modifier.fillMaxSize(),
            )
        } else {
            Text(
                text = group.name.take(1).uppercase(),
                style = MaterialTheme.typography.titleMedium,
            )
        }
    }
}

/** Maps a [GroupRole] to its display label (UNKNOWN -> a generic label). */
@Composable
internal fun roleLabel(role: GroupRole): String = stringResource(
    when (role) {
        GroupRole.ADMIN -> R.string.groups_role_admin
        GroupRole.MODERATOR -> R.string.groups_role_moderator
        GroupRole.MEMBER -> R.string.groups_role_member
        GroupRole.UNKNOWN -> R.string.groups_role_unknown
    },
)
