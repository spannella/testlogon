@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.feed.scheduled

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.feed.ScheduledPost
import java.text.DateFormat
import java.util.Date

/** PAR-13 — stable testTags for the scheduled-posts screen + its rows. */
object ScheduledPostsTestTags {
    const val SCREEN = "scheduled_posts_screen"
    const val LIST = "scheduled_posts_list"
    const val EMPTY = "scheduled_posts_empty"
    const val ERROR = "scheduled_posts_error"

    fun row(id: String) = "scheduled_post_row_$id"
    fun cancel(id: String) = "scheduled_post_cancel_$id"
    const val CANCEL_CONFIRM = "scheduled_post_cancel_confirm"
}

/**
 * PAR-13 — route-level entry for the scheduled-posts management screen. Collects state, wires the
 * one-shot message effect to the snackbar, and forwards the confirm-gated cancel.
 */
@Composable
fun ScheduledPostsRoute(
    onBack: () -> Unit,
    viewModel: ScheduledPostsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is ScheduledPostsEffect.ShowMessage -> snackbarHostState.showSnackbar(effect.message)
            }
        }
    }

    ScheduledPostsScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRetry = viewModel::load,
        onLoadMore = viewModel::loadMore,
        onCancel = viewModel::cancel,
    )
}

/** PAR-13 — stateless scheduled-posts list (body preview + publish time + Cancel with confirm). */
@Composable
fun ScheduledPostsScreen(
    state: ScheduledPostsUiState,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onLoadMore: () -> Unit,
    onCancel: (postId: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var pendingCancel by remember { mutableStateOf<String?>(null) }
    val listState = rememberLazyListState()

    Scaffold(
        modifier = modifier.testTag(ScheduledPostsTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.scheduled_posts_title)) },
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
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.loading -> LoadingState()

                state.loadError != null -> ErrorState(
                    message = state.loadError,
                    onRetry = onRetry,
                    modifier = Modifier.testTag(ScheduledPostsTestTags.ERROR),
                )

                state.isEmpty -> EmptyState(
                    title = stringResource(R.string.scheduled_posts_empty_title),
                    body = stringResource(R.string.scheduled_posts_empty_body),
                    modifier = Modifier.testTag(ScheduledPostsTestTags.EMPTY),
                )

                else -> LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize().testTag(ScheduledPostsTestTags.LIST),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(state.posts, key = { it.postId }) { post ->
                        ScheduledPostRow(
                            post = post,
                            cancelling = post.postId in state.cancelling,
                            onCancel = { pendingCancel = post.postId },
                        )
                    }
                    if (state.canLoadMore) {
                        item {
                            LaunchedEffect(state.nextCursor) { onLoadMore() }
                            Box(
                                Modifier.fillMaxWidth().padding(16.dp),
                                contentAlignment = Alignment.Center,
                            ) { CircularProgressIndicator(modifier = Modifier.size(24.dp)) }
                        }
                    }
                }
            }
        }
    }

    pendingCancel?.let { id ->
        AlertDialog(
            onDismissRequest = { pendingCancel = null },
            title = { Text(stringResource(R.string.scheduled_posts_cancel_title)) },
            text = { Text(stringResource(R.string.scheduled_posts_cancel_body)) },
            confirmButton = {
                TextButton(
                    onClick = {
                        onCancel(id)
                        pendingCancel = null
                    },
                    modifier = Modifier.testTag(ScheduledPostsTestTags.CANCEL_CONFIRM),
                ) { Text(stringResource(R.string.scheduled_posts_cancel_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { pendingCancel = null }) {
                    Text(stringResource(R.string.scheduled_posts_cancel_dismiss))
                }
            },
        )
    }
}

@Composable
private fun ScheduledPostRow(
    post: ScheduledPost,
    cancelling: Boolean,
    onCancel: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(ScheduledPostsTestTags.row(post.postId))) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = scheduledTimeLabel(post),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.primary,
            )
            val preview = post.bodyPreview.ifBlank {
                stringResource(
                    if (post.hasMedia) R.string.scheduled_posts_media_only else R.string.scheduled_posts_no_text,
                )
            }
            Text(
                text = preview,
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (cancelling) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp))
                } else {
                    TextButton(
                        onClick = onCancel,
                        modifier = Modifier.testTag(ScheduledPostsTestTags.cancel(post.postId)),
                    ) { Text(stringResource(R.string.scheduled_posts_cancel_action)) }
                }
            }
        }
    }
}

/** Prefer the server's local wall-clock string; otherwise format publish_at (epoch seconds). */
@Composable
private fun scheduledTimeLabel(post: ScheduledPost): String {
    post.scheduledAtLocal?.takeIf { it.isNotBlank() }?.let { local ->
        return stringResource(R.string.scheduled_posts_publishes_at, local)
    }
    post.publishAtEpochSeconds?.let { epoch ->
        val fmt = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
        return stringResource(R.string.scheduled_posts_publishes_at, fmt.format(Date(epoch * 1000L)))
    }
    return stringResource(R.string.scheduled_posts_publishes_pending)
}
