@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminvideo

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
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.VideoLibrary
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.adminvideo.VideoReviewItemDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType

object VideoReviewTestTags {
    const val SCREEN = "video_review_screen"
    const val LIST = "video_review_list"
    const val EMPTY = "video_review_empty"
    const val FORBIDDEN = "video_review_forbidden"
    const val ERROR_RETRY = "video_review_error_retry"
    fun item(id: String) = "video_review_item_$id"
    fun approve(id: String) = "video_review_approve_$id"
    fun reject(id: String) = "video_review_reject_$id"
    const val REJECT_DIALOG_REASON = "video_review_reject_reason"
    const val REJECT_DIALOG_CONFIRM = "video_review_reject_confirm"
}

@Composable
fun VideoReviewRoute(
    onBack: () -> Unit,
    viewModel: VideoReviewViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    VideoReviewScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onApprove = viewModel::approve,
        onReject = viewModel::reject,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun VideoReviewScreen(
    state: VideoReviewUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onApprove: (String, String?) -> Unit,
    onReject: (String, String) -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var rejectTarget by remember { mutableStateOf<String?>(null) }
    val content = state as? VideoReviewUiState.Content

    LaunchedEffect(content?.message, content?.transientError) {
        val msg = content?.message ?: content?.transientError?.let { videoErrorMessage(it) }
        if (msg != null) {
            snackbar.showSnackbar(msg)
            onMessageShown()
        }
    }

    Scaffold(
        modifier = modifier.testTag(VideoReviewTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Video review") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        val isRefreshing = content?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is VideoReviewUiState.Loading -> LoadingState()
                is VideoReviewUiState.Empty -> EmptyState(
                    modifier = Modifier.testTag(VideoReviewTestTags.EMPTY),
                    title = "Queue is clear",
                    body = "No videos are pending review.",
                    imageVector = Icons.Outlined.VideoLibrary,
                )
                is VideoReviewUiState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(VideoReviewTestTags.FORBIDDEN),
                    title = "Not authorised",
                    body = "You need content-moderation admin access to review videos.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is VideoReviewUiState.Error -> ErrorState(
                    modifier = Modifier.testTag(VideoReviewTestTags.ERROR_RETRY),
                    message = videoErrorMessage(state.type),
                    onRetry = onRetry,
                )
                is VideoReviewUiState.Content -> LazyColumn(
                    modifier = Modifier.fillMaxSize().testTag(VideoReviewTestTags.LIST),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    item(key = "header") {
                        Text(
                            "${state.totalPending} pending",
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    items(items = state.items, key = { it.videoId }) { v ->
                        VideoRow(
                            video = v,
                            inFlight = state.actionInFlightId == v.videoId,
                            actionsEnabled = state.actionInFlightId == null,
                            onApprove = { onApprove(v.videoId, null) },
                            onReject = { rejectTarget = v.videoId },
                        )
                    }
                }
            }
        }
    }

    rejectTarget?.let { targetId ->
        RejectDialog(
            onDismiss = { rejectTarget = null },
            onConfirm = { reason ->
                onReject(targetId, reason)
                rejectTarget = null
            },
        )
    }
}

@Composable
private fun VideoRow(
    video: VideoReviewItemDto,
    inFlight: Boolean,
    actionsEnabled: Boolean,
    onApprove: () -> Unit,
    onReject: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(VideoReviewTestTags.item(video.videoId)),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            video.thumbnailUrl?.takeIf { it.isNotBlank() }?.let {
                AsyncImage(
                    model = it,
                    contentDescription = null,
                    modifier = Modifier.fillMaxWidth().padding(bottom = 4.dp),
                )
            }
            Text(
                video.title.ifBlank { "Untitled video" },
                style = MaterialTheme.typography.titleSmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                "by ${video.ownerDisplayName ?: video.ownerUserId}",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(video.status.ifBlank { "-" }.replace('_', ' '), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                Text(video.visibility.ifBlank { "-" }, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            video.description?.takeIf { it.isNotBlank() }?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, maxLines = 3, overflow = TextOverflow.Ellipsis)
            }
            if (inFlight) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                    CircularProgressIndicator()
                }
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    OutlinedButton(
                        onClick = onReject,
                        enabled = actionsEnabled,
                        modifier = Modifier.testTag(VideoReviewTestTags.reject(video.videoId)),
                    ) { Text("Reject") }
                    Button(
                        onClick = onApprove,
                        enabled = actionsEnabled,
                        modifier = Modifier.testTag(VideoReviewTestTags.approve(video.videoId)),
                    ) { Text("Approve") }
                }
            }
        }
    }
}

@Composable
private fun RejectDialog(onDismiss: () -> Unit, onConfirm: (String) -> Unit) {
    var reason by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Reject video") },
        text = {
            OutlinedTextField(
                value = reason,
                onValueChange = { reason = it },
                label = { Text("Reason") },
                modifier = Modifier.fillMaxWidth().testTag(VideoReviewTestTags.REJECT_DIALOG_REASON),
            )
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(reason.trim()) },
                enabled = reason.isNotBlank(),
                modifier = Modifier.testTag(VideoReviewTestTags.REJECT_DIALOG_CONFIRM),
            ) { Text("Reject") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

internal fun videoErrorMessage(type: AdminOpsErrorType): String = when (type) {
    AdminOpsErrorType.AUTH -> "Your session expired. Please sign in again."
    AdminOpsErrorType.SERVER -> "Something went wrong on the server. Try again."
    AdminOpsErrorType.NETWORK -> "You appear to be offline. Check your connection."
}
