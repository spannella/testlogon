@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.videos

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.videos.VideoSummary

/** AND-189 — stable test tags. */
object VideosScreenTestTags {
    const val SCREEN = "videos_screen"
    const val GRID = "videos_grid"
    const val APPEND_FOOTER = "videos_append_footer"
    const val APPEND_RETRY = "videos_append_retry"
}

/**
 * AND-189 — route-level Videos library. Collects the paged videos and renders [VideosScreen]. Tapping
 * a tile navigates to video detail (AND-190) via [onOpenVideo].
 */
@Composable
fun VideosRoute(
    onOpenVideo: (videoId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: VideosViewModel = hiltViewModel(),
) {
    val items = viewModel.videos.collectAsLazyPagingItems()
    VideosScreen(
        items = items,
        onOpenVideo = onOpenVideo,
        onRefresh = { items.refresh() },
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun VideosScreen(
    items: LazyPagingItems<VideoSummary>,
    onOpenVideo: (videoId: String) -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(VideosScreenTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.videos_library_title)) },
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
        val refreshState = items.loadState.refresh
        val isRefreshing = refreshState is LoadState.Loading && items.itemCount > 0
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            Box(Modifier.fillMaxSize()) {
                when {
                    refreshState is LoadState.Loading && items.itemCount == 0 -> LoadingState()

                    refreshState is LoadState.Error && items.itemCount == 0 -> {
                        val message = (refreshState.error as? VideosLoadException)?.message
                            ?: stringResource(R.string.videos_library_error)
                        ErrorState(message = message, onRetry = items::retry)
                    }

                    refreshState is LoadState.NotLoading && items.itemCount == 0 ->
                        EmptyState(title = stringResource(R.string.videos_library_empty))

                    else -> VideoGrid(items = items, onOpenVideo = onOpenVideo)
                }
            }
        }
    }
}

@Composable
private fun VideoGrid(
    items: LazyPagingItems<VideoSummary>,
    onOpenVideo: (videoId: String) -> Unit,
) {
    LazyVerticalGrid(
        columns = GridCells.Adaptive(minSize = 160.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
        modifier = Modifier.fillMaxSize().testTag(VideosScreenTestTags.GRID),
    ) {
        items(count = items.itemCount, key = { index -> items.peek(index)?.id ?: index }) { index ->
            val video = items[index]
            if (video != null) {
                VideoTile(
                    title = video.title,
                    thumbnailUrl = video.thumbnailUrl,
                    durationSec = video.durationSec,
                    onClick = { onOpenVideo(video.id) },
                )
            }
        }

        when (items.loadState.append) {
            is LoadState.Loading -> item(span = { GridItemSpan(maxLineSpan) }) {
                Box(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(VideosScreenTestTags.APPEND_FOOTER)
                        .semantics { contentDescription = "Loading more videos" },
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp))
                }
            }
            is LoadState.Error -> item(span = { GridItemSpan(maxLineSpan) }) {
                androidx.compose.foundation.layout.Row(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(VideosScreenTestTags.APPEND_FOOTER),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = stringResource(R.string.videos_append_error),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    TextButton(
                        onClick = { items.retry() },
                        modifier = Modifier.testTag(VideosScreenTestTags.APPEND_RETRY),
                    ) { Text(stringResource(R.string.action_retry)) }
                }
            }
            else -> Unit
        }
    }
}
