@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.groups

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Image
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.material.icons.outlined.Flag
import com.testlogon.android.data.report.ReportTarget
import com.testlogon.android.feature.report.ContentReportSheetHost
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.core.model.groups.GroupComment

/** Batch-9 (#11) - stable testTags for the group comments sheet. */
object GroupCommentsTestTags {
    const val SHEET = "group_comments_sheet"
    const val INPUT = "group_comments_input"
    const val SEND = "group_comments_send"
    const val ATTACH = "group_comments_attach"
    const val EMPTY = "group_comments_empty"
    const val LOAD_MORE = "group_comments_load_more"
    fun row(id: String) = "group_comment_$id"
}

/**
 * Batch-9 (#11) - a modal bottom sheet that shows a group post's comments and a composer (text + image),
 * reaching full parity with the main-feed comments. [onCountChanged] reports the new comment total so the
 * feed row updates optimistically. The ViewModel is created per (groupId, postId) via the assisted factory.
 */
@Composable
fun GroupCommentsSheet(
    groupId: String,
    postId: String,
    onDismiss: () -> Unit,
    onCountChanged: (Int) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: GroupCommentsViewModel = hiltViewModel<GroupCommentsViewModel, GroupCommentsViewModel.Factory>(
        key = "group_comments_$postId",
        creationCallback = { factory -> factory.create(groupId, postId) },
    ),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    // MOD-C1 - group comment report target (reported as feed_comment by its comment id).
    var reportTarget by remember { mutableStateOf<ReportTarget?>(null) }

    val imagePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent(),
    ) { uri -> if (uri != null) viewModel.stageImage(uri) }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = modifier.testTag(GroupCommentsTestTags.SHEET),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp).padding(bottom = 16.dp)) {
            Text(
                text = "Comments",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(bottom = 8.dp),
            )

            when {
                state.loading && state.comments.isEmpty() ->
                    Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator()
                    }

                state.loaded && state.comments.isEmpty() ->
                    Text(
                        text = "No comments yet. Be the first.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.testTag(GroupCommentsTestTags.EMPTY).padding(vertical = 16.dp),
                    )

                else ->
                    LazyColumn(
                        modifier = Modifier.fillMaxWidth().heightIn(max = 360.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(state.comments, key = { it.commentId }) { comment ->
                            CommentRow(
                                comment = comment,
                                onReport = { reportTarget = ReportTarget.Content(comment.commentId, "feed_comment") },
                                onDelete = { viewModel.delete(comment, onCountChanged) },
                            )
                        }
                        if (state.nextCursor != null) {
                            item {
                                TextButton(
                                    onClick = viewModel::loadMore,
                                    modifier = Modifier.testTag(GroupCommentsTestTags.LOAD_MORE),
                                ) { Text("Load more") }
                            }
                        }
                    }
            }

            val err = state.error
            if (err != null) {
                Text(
                    text = err,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }

            val staged = state.stagedImageUrl
            if (staged != null) {
                Box(modifier = Modifier.padding(top = 8.dp)) {
                    AsyncImage(
                        model = staged,
                        contentDescription = "Attached image",
                        contentScale = ContentScale.Crop,
                        modifier = Modifier.size(72.dp).clip(RoundedCornerShape(8.dp)),
                    )
                    IconButton(
                        onClick = viewModel::clearStagedImage,
                        modifier = Modifier.align(Alignment.TopEnd).size(24.dp),
                    ) {
                        Icon(Icons.Outlined.Close, contentDescription = "Remove image")
                    }
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                IconButton(
                    onClick = { imagePicker.launch("image/*") },
                    enabled = !state.uploadingImage && !state.sending,
                    modifier = Modifier.testTag(GroupCommentsTestTags.ATTACH),
                ) {
                    if (state.uploadingImage) {
                        CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                    } else {
                        Icon(Icons.Outlined.Image, contentDescription = "Attach image")
                    }
                }
                OutlinedTextField(
                    value = state.draft,
                    onValueChange = viewModel::onDraftChange,
                    enabled = !state.sending,
                    placeholder = { Text("Add a comment...") },
                    modifier = Modifier.weight(1f).testTag(GroupCommentsTestTags.INPUT),
                )
                IconButton(
                    onClick = { viewModel.submit(onCountChanged) },
                    enabled = (state.draft.isNotBlank() || staged != null) && !state.sending,
                    modifier = Modifier.testTag(GroupCommentsTestTags.SEND),
                ) {
                    if (state.sending) {
                        CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                    } else {
                        Icon(Icons.AutoMirrored.Filled.Send, contentDescription = "Send")
                    }
                }
            }
        }
    }

    // MOD-C1/C3 - group comment report sheet (stacks above the comments sheet); licensing/IP -> DMCA.
    ContentReportSheetHost(target = reportTarget, onDismiss = { reportTarget = null })
}

@Composable
private fun CommentRow(comment: GroupComment, onReport: () -> Unit = {}, onDelete: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().testTag(GroupCommentsTestTags.row(comment.commentId)),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = comment.authorName,
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold,
            )
            val text = comment.text
            if (!text.isNullOrBlank()) {
                Text(text = text, style = MaterialTheme.typography.bodyMedium)
            }
            val img = comment.imageUrl
            if (img != null) {
                AsyncImage(
                    model = img,
                    contentDescription = null,
                    contentScale = ContentScale.Crop,
                    modifier = Modifier.padding(top = 4.dp).size(120.dp).clip(RoundedCornerShape(8.dp)),
                )
            }
        }
        IconButton(
            onClick = onReport,
            modifier = Modifier.size(32.dp).testTag("group_comment_report_" + comment.commentId),
        ) {
            Icon(
                Icons.Outlined.Flag,
                contentDescription = "Report comment",
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        IconButton(onClick = onDelete, modifier = Modifier.size(32.dp)) {
            Icon(
                Icons.Outlined.Delete,
                contentDescription = "Delete comment",
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
