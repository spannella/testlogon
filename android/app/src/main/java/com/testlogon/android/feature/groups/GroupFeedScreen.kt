@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.groups

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.outlined.Comment
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Image
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.core.model.groups.GroupFeedPost
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import kotlinx.coroutines.flow.collectLatest

/** Batch-8/9 (#10,#11) - stable testTags for the group-feed screen. */
object GroupFeedTestTags {
    const val SCREEN = "group_feed_screen"
    const val COMPOSE_INPUT = "group_feed_compose_input"
    const val COMPOSE_SEND = "group_feed_compose_send"
    const val COMPOSE_ATTACH = "group_feed_compose_attach"
    const val SETTINGS = "group_feed_settings"
    const val EMPTY = "group_feed_empty"
    const val ERROR_RETRY = "group_feed_error_retry"

    fun row(postId: String) = "group_feed_post_$postId"
    fun comments(postId: String) = "group_feed_comments_$postId"
}

/**
 * Batch-8/9 (#10,#11) - route-level group-feed entry (the DEFAULT group landing). The TopAppBar GEAR
 * ([onOpenHub]) reaches the group hub (members / treasury / settings / etc.). Each post opens a comments
 * sheet; the composer attaches images + a paid-lock price (full-newsfeed parity).
 */
@Composable
fun GroupFeedRoute(
    onBack: () -> Unit,
    onOpenHub: () -> Unit,
    // #4 (B-GROUPUNIFY) — open the SHARED newsfeed composer, locked to this group's audience.
    onComposePost: () -> Unit = {},
    viewModel: GroupFeedViewModel = hiltViewModel(),
) {
    val posts = viewModel.posts.collectAsLazyPagingItems()
    val composeState by viewModel.composeState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.refreshSignal.collectLatest { posts.refresh() }
    }
    GroupFeedScreen(
        groupId = viewModel.groupId,
        posts = posts,
        composeState = composeState,
        onBack = onBack,
        onOpenHub = onOpenHub,
        onComposePost = onComposePost,
        onTextChange = viewModel::onTextChange,
        onAttachImage = viewModel::attachImage,
        onRemoveImage = viewModel::removeImage,
        onSubmit = viewModel::submit,
    )
}

@Composable
fun GroupFeedScreen(
    groupId: String,
    posts: LazyPagingItems<GroupFeedPost>,
    composeState: GroupComposeState,
    onBack: () -> Unit,
    onOpenHub: () -> Unit,
    onComposePost: () -> Unit = {},
    onTextChange: (String) -> Unit,
    onAttachImage: (android.net.Uri) -> Unit,
    onRemoveImage: (String) -> Unit,
    onSubmit: () -> Unit,
    modifier: Modifier = Modifier,
) {
    // The post whose comments sheet is open (null = closed).
    var commentsForPost by remember { mutableStateOf<String?>(null) }

    Scaffold(
        modifier = modifier.testTag(GroupFeedTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.group_feed_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.group_feed_back),
                        )
                    }
                },
                actions = {
                    IconButton(
                        onClick = onOpenHub,
                        modifier = Modifier.testTag(GroupFeedTestTags.SETTINGS),
                    ) {
                        Icon(
                            Icons.Outlined.Settings,
                            contentDescription = stringResource(R.string.group_feed_hub),
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            // #4 (B-GROUPUNIFY) — post to this group via the SHARED newsfeed composer (same composer as
            // a normal post; the group is the selected, locked audience). The inline quick-composer below
            // remains for a fast text/image post.
            androidx.compose.material3.ExtendedFloatingActionButton(
                onClick = onComposePost,
                icon = { Icon(Icons.Outlined.Image, contentDescription = null) },
                text = { Text(stringResource(R.string.group_feed_compose_send)) },
                modifier = Modifier.testTag("group_feed_compose_fab"),
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            ComposeBox(
                state = composeState,
                onTextChange = onTextChange,
                onAttachImage = onAttachImage,
                onRemoveImage = onRemoveImage,
                onSubmit = onSubmit,
            )
            HorizontalDivider()
            val refresh = posts.loadState.refresh
            PullToRefreshBox(
                isRefreshing = refresh is LoadState.Loading && posts.itemCount > 0,
                onRefresh = { posts.refresh() },
                modifier = Modifier.fillMaxSize(),
            ) {
                when {
                    refresh is LoadState.Loading && posts.itemCount == 0 ->
                        LoadingState()

                    refresh is LoadState.Error && posts.itemCount == 0 ->
                        ErrorState(
                            modifier = Modifier.testTag(GroupFeedTestTags.ERROR_RETRY),
                            message = stringResource(R.string.group_feed_error),
                            onRetry = { posts.retry() },
                        )

                    posts.itemCount == 0 ->
                        EmptyState(
                            modifier = Modifier.testTag(GroupFeedTestTags.EMPTY),
                            title = stringResource(R.string.group_feed_empty_title),
                            body = stringResource(R.string.group_feed_empty_body),
                        )

                    else -> LazyColumn(modifier = Modifier.fillMaxSize()) {
                        items(
                            count = posts.itemCount,
                            key = { index -> posts[index]?.postId ?: "post_$index" },
                        ) { index ->
                            val post = posts[index] ?: return@items
                            GroupPostRow(post, onOpenComments = { commentsForPost = post.postId })
                            HorizontalDivider()
                        }
                    }
                }
            }
        }
    }

    val openPostId = commentsForPost
    if (openPostId != null) {
        GroupCommentsSheet(
            groupId = groupId,
            postId = openPostId,
            onDismiss = { commentsForPost = null },
            onCountChanged = { /* count refreshes on next feed load */ },
        )
    }
}

@Composable
private fun ComposeBox(
    state: GroupComposeState,
    onTextChange: (String) -> Unit,
    onAttachImage: (android.net.Uri) -> Unit,
    onRemoveImage: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    val imagePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri -> if (uri != null) onAttachImage(uri) }

    Column(
        modifier = Modifier.fillMaxWidth().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedTextField(
            value = state.text,
            onValueChange = onTextChange,
            enabled = !state.sending,
            label = { Text(stringResource(R.string.group_feed_compose_hint)) },
            modifier = Modifier.fillMaxWidth().testTag(GroupFeedTestTags.COMPOSE_INPUT),
        )
        if (state.imageUrls.isNotEmpty()) {
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                items(state.imageUrls, key = { it }) { url ->
                    Box {
                        AsyncImage(
                            model = url,
                            contentDescription = null,
                            contentScale = ContentScale.Crop,
                            modifier = Modifier.size(72.dp).clip(RoundedCornerShape(8.dp)),
                        )
                        IconButton(
                            onClick = { onRemoveImage(url) },
                            modifier = Modifier.align(Alignment.TopEnd).size(24.dp),
                        ) {
                            Icon(Icons.Outlined.Close, contentDescription = stringResource(R.string.group_feed_remove_image))
                        }
                    }
                }
            }
        }
        val err = state.error
        if (err != null) {
            Text(text = err, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            IconButton(
                onClick = { imagePicker.launch("image/*") },
                enabled = !state.uploadingImage && !state.sending && state.imageUrls.size < GroupFeedViewModel.MAX_IMAGES,
                modifier = Modifier.testTag(GroupFeedTestTags.COMPOSE_ATTACH),
            ) {
                if (state.uploadingImage) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                } else {
                    Icon(Icons.Outlined.Image, contentDescription = stringResource(R.string.group_feed_attach_image))
                }
            }
            Box(modifier = Modifier.weight(1f))
            Button(
                onClick = onSubmit,
                enabled = (state.text.isNotBlank() || state.imageUrls.isNotEmpty()) && !state.sending,
                modifier = Modifier.testTag(GroupFeedTestTags.COMPOSE_SEND),
            ) {
                if (state.sending) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                } else {
                    Text(stringResource(R.string.group_feed_compose_send))
                }
            }
        }
    }
}

@Composable
private fun GroupPostRow(post: GroupFeedPost, onOpenComments: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(GroupFeedTestTags.row(post.postId))
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = post.authorName,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f, fill = false),
            )
            if (post.pinned) {
                Text(
                    text = stringResource(R.string.group_feed_pinned),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }
        val text = post.text
        if (post.locked) {
            val price = post.unlockPriceCents
            Text(
                text = if (price != null && price > 0) {
                    stringResource(R.string.group_feed_locked_price, price / 100.0)
                } else {
                    stringResource(R.string.group_feed_locked)
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else if (!text.isNullOrBlank()) {
            Text(text = text, style = MaterialTheme.typography.bodyMedium)
        }

        // Multi-image grid (newsfeed parity): show up to 4 thumbnails in a row.
        if (!post.locked && post.imageUrls.isNotEmpty()) {
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                items(post.imageUrls.take(8), key = { it }) { url ->
                    AsyncImage(
                        model = url,
                        contentDescription = null,
                        contentScale = ContentScale.Crop,
                        modifier = Modifier.size(120.dp).clip(RoundedCornerShape(8.dp)),
                    )
                }
            }
        }

        // Attached video indicator.
        if (!post.locked && post.videoId != null) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .aspectRatio(16f / 9f)
                    .clip(RoundedCornerShape(8.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    Icons.Filled.PlayArrow,
                    contentDescription = stringResource(R.string.group_feed_video),
                    tint = MaterialTheme.colorScheme.primary,
                )
            }
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(
                onClick = onOpenComments,
                modifier = Modifier.testTag(GroupFeedTestTags.comments(post.postId)),
            ) {
                Icon(Icons.AutoMirrored.Outlined.Comment, contentDescription = null, modifier = Modifier.size(18.dp))
                Text(
                    text = if (post.commentCount > 0) {
                        stringResource(R.string.group_feed_comments_count, post.commentCount)
                    } else {
                        stringResource(R.string.group_feed_comment)
                    },
                    modifier = Modifier.padding(start = 6.dp),
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        }
    }
}
