@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.videos

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.VideoCall
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.derivedStateOf
import kotlinx.coroutines.delay
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
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
    const val REFRESH = "videos_refresh"
    const val UPLOAD_FAB = "videos_upload_fab"
}

/** Client-side poll cadence used to refresh the list while any video is still processing. */
private const val PROCESSING_POLL_MILLIS = 5_000L

/**
 * AND-189 — route-level Videos library. Collects the paged videos and renders [VideosScreen]. Tapping
 * a tile navigates to video detail (AND-190) via [onOpenVideo].
 */
@Composable
fun VideosRoute(
    onOpenVideo: (videoId: String) -> Unit,
    onUploadVideo: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: VideosViewModel = hiltViewModel(),
) {
    val items = viewModel.videos.collectAsLazyPagingItems()
    val pending by viewModel.pending.collectAsStateWithLifecycle()
    VideosScreen(
        items = items,
        pending = pending,
        onReconcilePending = viewModel::reconcilePending,
        onOpenVideo = onOpenVideo,
        onUploadVideo = onUploadVideo,
        onRefresh = { items.refresh() },
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun VideosScreen(
    items: LazyPagingItems<VideoSummary>,
    onOpenVideo: (videoId: String) -> Unit,
    onUploadVideo: () -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    pending: List<VideoSummary> = emptyList(),
    onReconcilePending: (Set<String>) -> Unit = {},
) {
    // Auto-poll: while any loaded video is still processing, refresh the list on a cadence so a
    // dev-published / finished-encoding video flips from "Processing" to "Ready" without the user
    // having to leave + re-enter. Stops as soon as nothing is processing.
    val hasProcessing by remember(items) {
        derivedStateOf {
            (0 until items.itemCount).any { items.peek(it)?.isProcessing == true }
        }
    }
    LaunchedEffect(hasProcessing) {
        while (hasProcessing) {
            delay(PROCESSING_POLL_MILLIS)
            if (items.loadState.refresh !is LoadState.Loading) onRefresh()
        }
    }
    // #5 — once the real rows for any optimistic pending tiles arrive in the page, drop the
    // placeholders so we don't show a duplicate. Recomputed as the page content changes.
    val loadedIds by remember(items) {
        derivedStateOf {
            (0 until items.itemCount).mapNotNull { items.peek(it)?.id }.toSet()
        }
    }
    LaunchedEffect(loadedIds, pending) {
        if (pending.isNotEmpty()) onReconcilePending(loadedIds)
    }
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
                actions = {
                    IconButton(
                        onClick = onRefresh,
                        modifier = Modifier.testTag(VideosScreenTestTags.REFRESH),
                    ) {
                        Icon(
                            Icons.Filled.Refresh,
                            contentDescription = stringResource(R.string.videos_action_refresh),
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = onUploadVideo,
                icon = { Icon(Icons.Filled.VideoCall, contentDescription = null) },
                text = { Text(stringResource(R.string.videos_upload_action)) },
                modifier = Modifier.testTag(VideosScreenTestTags.UPLOAD_FAB),
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
                    // #5 — with optimistic pending tiles, always render the grid so the just-uploaded
                    // video is visible even while the first page is (re)loading or empty.
                    pending.isNotEmpty() -> VideoGrid(items = items, pending = pending, onOpenVideo = onOpenVideo)

                    refreshState is LoadState.Loading && items.itemCount == 0 -> LoadingState()

                    refreshState is LoadState.Error && items.itemCount == 0 -> {
                        val message = (refreshState.error as? VideosLoadException)?.message
                            ?: stringResource(R.string.videos_library_error)
                        ErrorState(message = message, onRetry = items::retry)
                    }

                    refreshState is LoadState.NotLoading && items.itemCount == 0 ->
                        EmptyState(title = stringResource(R.string.videos_library_empty))

                    else -> VideoGrid(items = items, pending = pending, onOpenVideo = onOpenVideo)
                }
            }
        }
    }
}

@Composable
private fun VideoGrid(
    items: LazyPagingItems<VideoSummary>,
    onOpenVideo: (videoId: String) -> Unit,
    pending: List<VideoSummary> = emptyList(),
) {
    // #5 — compute the pending tiles to show (those not yet in the page) in COMPOSABLE scope; the
    // LazyGridScope content lambda is not @Composable, so remember/derivedStateOf must live here.
    val pendingToShow by remember(items.itemCount, pending) {
        derivedStateOf {
            val pageIds = (0 until items.itemCount).mapNotNull { items.peek(it)?.id }.toSet()
            pending.filter { it.id !in pageIds }
        }
    }
    LazyVerticalGrid(
        columns = GridCells.Adaptive(minSize = 160.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
        modifier = Modifier.fillMaxSize().testTag(VideosScreenTestTags.GRID),
    ) {
        // #5 — optimistic just-uploaded tiles (rendered as Processing) ahead of the paged content.
        items(count = pendingToShow.size, key = { i -> "pending_" + pendingToShow[i].id }) { i ->
            val v = pendingToShow[i]
            VideoTile(
                title = v.title,
                thumbnailUrl = v.thumbnailUrl,
                durationSec = v.durationSec,
                statusBadge = stringResource(R.string.videos_status_processing),
                onClick = {},
            )
        }
        items(count = items.itemCount, key = { index -> items.peek(index)?.id ?: index }) { index ->
            val video = items[index]
            if (video != null) {
                val processing = video.isProcessing
                val processingLabel = stringResource(R.string.videos_status_processing)
                VideoTile(
                    title = video.title,
                    thumbnailUrl = video.thumbnailUrl,
                    durationSec = video.durationSec,
                    statusBadge = if (processing) processingLabel else null,
                    // A still-processing video has no playable manifest yet; don't open it.
                    onClick = { if (!processing) onOpenVideo(video.id) },
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
