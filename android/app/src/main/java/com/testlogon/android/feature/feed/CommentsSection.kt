package com.testlogon.android.feature.feed

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.R
import com.testlogon.android.data.feed.Comment

/** Stable test tags for the comments surface (AND-174). */
object CommentsTestTags {
    const val SECTION = "comments_section"
    const val EMPTY = "comments_empty"
    const val INPUT = "comments_input"
    const val SEND = "comments_send"
    const val APPEND_FOOTER = "comments_append_footer"
    const val APPEND_RETRY = "comments_append_retry"
    const val RETRY = "comment_retry"
    const val DISCARD = "comment_discard"
    const val DELETE = "comment_delete"
    const val REPLY = "comment_reply"
    fun row(localKey: String) = "comment_$localKey"
}

/**
 * AND-174 — comments surface embedded by the post-detail screen (AND-100).
 *
 * Renders the paged comment list (optimistic header items first), an append footer (loading / retry),
 * an empty state, and a bottom composer. [onCommentCountChanged] notifies the host so it can adjust the
 * post's displayed comment count optimistically. Replies are hidden unless the repository advertises
 * support (default off).
 */
@Composable
fun CommentsSection(
    onCommentCountChanged: (delta: Int) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CommentsViewModel = hiltViewModel(),
) {
    val comments = viewModel.comments.collectAsLazyPagingItems()
    val composer by viewModel.composer.collectAsStateWithLifecycle()
    val authorNames by viewModel.authorNames.collectAsStateWithLifecycle()
    val refreshSignal by viewModel.refreshSignal.collectAsStateWithLifecycle()
    var draft by rememberSaveable { mutableStateOf("") }
    var pendingDelete by remember { mutableStateOf<Comment?>(null) }

    // Reconcile: when an add/delete succeeds the VM bumps refreshSignal; re-fetch the server page.
    androidx.compose.runtime.LaunchedEffect(refreshSignal) {
        if (refreshSignal > 0) comments.refresh()
    }
    // Relay one-shot count deltas to the host.
    androidx.compose.runtime.LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            if (effect is CommentsEffect.CommentCountChanged) onCommentCountChanged(effect.delta)
        }
    }

    Column(modifier = modifier.fillMaxWidth().testTag(CommentsTestTags.SECTION)) {
        Text(
            text = stringResource(R.string.comments_title),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
        )

        CommentsList(
            comments = comments,
            repliesSupported = viewModel.repliesSupported,
            onReply = viewModel::startReply,
            onRetry = viewModel::retry,
            onDiscard = viewModel::discard,
            onDelete = { pendingDelete = it },
            onEdit = { c ->
                draft = c.body
                viewModel.startEdit(c)
            },
            authorNames = authorNames,
            onEnsureAuthorName = viewModel::resolveAuthor,
        )

        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        CommentComposer(
            state = composer,
            draft = draft,
            onBodyChange = {
                draft = it
                viewModel.onBodyChange(it)
            },
            onSend = {
                viewModel.send()
                draft = ""
            },
            onCancelReply = viewModel::cancelReply,
            onCancelEdit = {
                draft = ""
                viewModel.cancelEdit()
            },
        )
    }

    pendingDelete?.let { target ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text(stringResource(R.string.comments_delete_confirm_title)) },
            text = { Text(stringResource(R.string.comments_delete_confirm_body)) },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.delete(target)
                    pendingDelete = null
                }) { Text(stringResource(R.string.comments_delete)) }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) {
                    Text(stringResource(R.string.comments_delete_cancel))
                }
            },
        )
    }
}

@Composable
private fun CommentsList(
    comments: LazyPagingItems<Comment>,
    repliesSupported: Boolean,
    onReply: (Comment) -> Unit,
    onEdit: (Comment) -> Unit,
    onRetry: (String) -> Unit,
    onDiscard: (String) -> Unit,
    onDelete: (Comment) -> Unit,
    authorNames: Map<String, String>,
    onEnsureAuthorName: (authorId: String) -> Unit,
) {
    val refresh = comments.loadState.refresh
    when {
        refresh is LoadState.Loading && comments.itemCount == 0 ->
            Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(modifier = Modifier.size(24.dp))
            }

        refresh is LoadState.Error && comments.itemCount == 0 ->
            FooterError(
                message = (refresh.error as? CommentLoadException)?.message
                    ?: stringResource(R.string.comments_error_generic),
                onRetry = comments::retry,
            )

        refresh is LoadState.NotLoading && comments.itemCount == 0 ->
            Text(
                text = stringResource(R.string.comments_empty),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(24.dp).testTag(CommentsTestTags.EMPTY),
            )

        else -> Column(Modifier.fillMaxWidth()) {
            for (index in 0 until comments.itemCount) {
                val comment = comments[index] ?: continue
                CommentRow(
                    comment = comment,
                    authorName = authorNames[comment.authorId],
                    onEnsureAuthorName = onEnsureAuthorName,
                    repliesSupported = repliesSupported,
                    onReply = onReply,
                    onEdit = onEdit,
                    onRetry = onRetry,
                    onDiscard = onDiscard,
                    onDelete = onDelete,
                    modifier = Modifier.testTag(CommentsTestTags.row(comment.localKey)),
                )
            }
            when (comments.loadState.append) {
                is LoadState.Loading -> Box(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(CommentsTestTags.APPEND_FOOTER),
                    contentAlignment = Alignment.Center,
                ) { CircularProgressIndicator(modifier = Modifier.size(20.dp)) }

                is LoadState.Error -> FooterError(
                    message = stringResource(R.string.comments_error_generic),
                    onRetry = comments::retry,
                )

                else -> Unit
            }
        }
    }
}

@Composable
private fun CommentRow(
    comment: Comment,
    authorName: String?,
    onEnsureAuthorName: (authorId: String) -> Unit,
    repliesSupported: Boolean,
    onReply: (Comment) -> Unit,
    onEdit: (Comment) -> Unit,
    onRetry: (String) -> Unit,
    onDiscard: (String) -> Unit,
    onDelete: (Comment) -> Unit,
    modifier: Modifier = Modifier,
) {
    androidx.compose.runtime.LaunchedEffect(comment.authorId) {
        if (comment.authorId.isNotBlank()) onEnsureAuthorName(comment.authorId)
    }
    if (comment.deleted) {
        Text(
            text = stringResource(R.string.comments_deleted_tombstone),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        )
        return
    }
    val pendingDesc = stringResource(R.string.comments_pending)
    val failedDesc = stringResource(R.string.comments_failed)
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .graphicsLayer { alpha = if (comment.pending) 0.5f else 1f }
            .semantics {
                if (comment.pending) stateDescription = pendingDesc
                if (comment.failed) stateDescription = failedDesc
            },
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(
            text = authorName?.takeIf { it.isNotBlank() } ?: comment.authorId.ifBlank { "You" },
            style = MaterialTheme.typography.labelLarge,
            fontWeight = FontWeight.SemiBold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        val bodyText = if (comment.updatedAtEpochSeconds != null) {
            comment.body + " " + stringResource(R.string.comments_edited)
        } else {
            comment.body
        }
        Text(text = bodyText, style = MaterialTheme.typography.bodyMedium)

        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            if (comment.failed) {
                TextButton(onClick = { onRetry(comment.localKey) }, modifier = Modifier.testTag(CommentsTestTags.RETRY)) {
                    Text(stringResource(R.string.comments_retry))
                }
                TextButton(onClick = { onDiscard(comment.localKey) }, modifier = Modifier.testTag(CommentsTestTags.DISCARD)) {
                    Text(stringResource(R.string.comments_discard))
                }
            }
            if (repliesSupported && !comment.pending && !comment.failed) {
                TextButton(onClick = { onReply(comment) }, modifier = Modifier.testTag(CommentsTestTags.REPLY)) {
                    Text(stringResource(R.string.comments_reply_action))
                }
            }
            if (comment.canEdit && !comment.pending && !comment.failed) {
                IconButton(
                    onClick = { onEdit(comment) },
                    modifier = Modifier.size(48.dp).testTag("comment_edit"),
                ) {
                    Icon(
                        Icons.Outlined.Edit,
                        contentDescription = "Edit comment",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            if (comment.canDelete && !comment.pending) {
                IconButton(
                    onClick = { onDelete(comment) },
                    modifier = Modifier.size(48.dp).testTag(CommentsTestTags.DELETE),
                ) {
                    Icon(
                        Icons.Outlined.Delete,
                        contentDescription = stringResource(R.string.comments_delete),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun CommentComposer(
    state: ComposerState,
    draft: String,
    onBodyChange: (String) -> Unit,
    onSend: () -> Unit,
    onCancelReply: () -> Unit,
    onCancelEdit: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxWidth().padding(8.dp)) {
        if (state.isEditing) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "Editing comment",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.weight(1f),
                )
                IconButton(onClick = onCancelEdit, modifier = Modifier.size(48.dp).testTag("comment_cancel_edit")) {
                    Icon(Icons.Outlined.Close, contentDescription = "Cancel edit")
                }
            }
        }
        state.replyTo?.let { parent ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = stringResource(R.string.comments_replying_to, parent.authorId.ifBlank { "You" }),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f),
                )
                IconButton(onClick = onCancelReply, modifier = Modifier.size(48.dp)) {
                    Icon(Icons.Outlined.Close, contentDescription = stringResource(R.string.comments_cancel_reply))
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = draft,
                onValueChange = onBodyChange,
                modifier = Modifier.weight(1f).testTag(CommentsTestTags.INPUT),
                placeholder = { Text(stringResource(R.string.comments_input_hint)) },
                maxLines = 4,
            )
            IconButton(
                onClick = onSend,
                enabled = state.canSend,
                modifier = Modifier.size(48.dp).testTag(CommentsTestTags.SEND),
            ) {
                Icon(
                    Icons.AutoMirrored.Filled.Send,
                    contentDescription = stringResource(R.string.comments_send),
                    tint = if (state.canSend) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun FooterError(message: String, onRetry: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(16.dp).testTag(CommentsTestTags.APPEND_FOOTER),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(message, style = MaterialTheme.typography.bodyMedium)
        TextButton(onClick = onRetry, modifier = Modifier.testTag(CommentsTestTags.APPEND_RETRY)) {
            Text(stringResource(R.string.comments_retry))
        }
    }
}
