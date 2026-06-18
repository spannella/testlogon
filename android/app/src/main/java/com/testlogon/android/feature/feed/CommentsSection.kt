package com.testlogon.android.feature.feed

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.AttachMoney
import androidx.compose.material.icons.filled.Gif
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.ContentScale
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
import coil.compose.AsyncImage
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
    const val TIP = "comment_tip"
    const val GIF_BUTTON = "comments_gif_button"
    const val PICKER = "comments_media_picker"
    const val GIF_SEARCH = "comments_gif_search"
    const val TIP_SHEET = "comment_tip_sheet"
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
    val picker by viewModel.picker.collectAsStateWithLifecycle()
    val tip by viewModel.tip.collectAsStateWithLifecycle()
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
            onTip = viewModel::openTip,
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
            onOpenMediaPicker = viewModel::openMediaPicker,
            onCancelReply = viewModel::cancelReply,
            onCancelEdit = {
                draft = ""
                viewModel.cancelEdit()
            },
        )
    }

    if (picker.visible) {
        CommentMediaPickerSheet(
            state = picker,
            onDismiss = viewModel::closeMediaPicker,
            onTab = viewModel::setPickerTab,
            onGifQuery = viewModel::onGifQueryChange,
            onPickGif = viewModel::pickGif,
            onPickSticker = viewModel::pickSticker,
        )
    }
    tip.target?.let {
        CommentTipSheet(
            state = tip,
            onConfirm = viewModel::confirmTip,
            onDismiss = viewModel::dismissTip,
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
    onTip: (Comment) -> Unit,
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
                    onTip = onTip,
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
    onTip: (Comment) -> Unit,
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
    // Threaded replies are indented under their parent (backend parent_comment_id).
    val startPad = if (comment.parentId != null) 40.dp else 16.dp
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(start = startPad, end = 16.dp, top = 8.dp, bottom = 8.dp)
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
        val mediaUrl = comment.gifUrl ?: comment.stickerUrl
        if (mediaUrl != null) {
            AsyncImage(
                model = mediaUrl,
                contentDescription = if (comment.gifUrl != null) "GIF comment" else "Sticker comment",
                contentScale = ContentScale.Fit,
                modifier = Modifier
                    .heightIn(max = 140.dp)
                    .clip(RoundedCornerShape(12.dp)),
            )
        } else {
            val bodyText = if (comment.updatedAtEpochSeconds != null) {
                comment.body + " " + stringResource(R.string.comments_edited)
            } else {
                comment.body
            }
            Text(text = bodyText, style = MaterialTheme.typography.bodyMedium)
        }
        if (comment.tipTotalCents > 0) {
            Text(
                text = "Tipped $" + "%.2f".format(comment.tipTotalCents / 100.0),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary,
            )
        }

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
            // Tip another member's comment (creator monetization).
            if (!comment.canDelete && !comment.pending && !comment.failed) {
                TextButton(onClick = { onTip(comment) }, modifier = Modifier.testTag(CommentsTestTags.TIP)) {
                    Icon(
                        Icons.Filled.AttachMoney,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                        tint = MaterialTheme.colorScheme.primary,
                    )
                    Text("Tip")
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
    onOpenMediaPicker: () -> Unit,
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
            // GIF / sticker picker (kept out of edit mode, where only the body is editable).
            if (!state.isEditing) {
                IconButton(
                    onClick = onOpenMediaPicker,
                    modifier = Modifier.size(48.dp).testTag(CommentsTestTags.GIF_BUTTON),
                ) {
                    Icon(
                        Icons.Filled.Gif,
                        contentDescription = "Add a GIF or sticker",
                        tint = MaterialTheme.colorScheme.primary,
                    )
                }
            }
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

/** AND-174 (rich comments) — GIF / sticker picker bottom sheet. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun CommentMediaPickerSheet(
    state: CommentMediaPickerState,
    onDismiss: () -> Unit,
    onTab: (Int) -> Unit,
    onGifQuery: (String) -> Unit,
    onPickGif: (com.testlogon.android.data.messaging.GifResult) -> Unit,
    onPickSticker: (com.testlogon.android.data.messaging.StickerUi) -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState()) {
        Column(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp).testTag(CommentsTestTags.PICKER),
        ) {
            TabRow(selectedTabIndex = state.tab) {
                Tab(selected = state.tab == 0, onClick = { onTab(0) }, text = { Text("GIFs") })
                Tab(selected = state.tab == 1, onClick = { onTab(1) }, text = { Text("Stickers") })
            }
            if (state.tab == 0) {
                OutlinedTextField(
                    value = state.gifQuery,
                    onValueChange = onGifQuery,
                    modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp).testTag(CommentsTestTags.GIF_SEARCH),
                    placeholder = { Text("Search GIFs") },
                    singleLine = true,
                )
                MediaGrid(loading = state.gifLoading, error = state.error, count = state.gifResults.size) {
                    LazyVerticalGrid(
                        columns = GridCells.Fixed(3),
                        modifier = Modifier.height(300.dp),
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        items(state.gifResults, key = { it.id }) { gif ->
                            AsyncImage(
                                model = gif.url,
                                contentDescription = gif.altText ?: "GIF",
                                contentScale = ContentScale.Crop,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(96.dp)
                                    .clip(RoundedCornerShape(8.dp))
                                    .clickable { onPickGif(gif) },
                            )
                        }
                    }
                }
            } else {
                MediaGrid(loading = state.stickersLoading, error = state.error, count = state.stickers.size) {
                    LazyVerticalGrid(
                        columns = GridCells.Fixed(4),
                        modifier = Modifier.height(300.dp),
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        items(state.stickers, key = { it.stickerId }) { st ->
                            AsyncImage(
                                model = st.url,
                                contentDescription = st.altText ?: "Sticker",
                                contentScale = ContentScale.Fit,
                                modifier = Modifier.size(72.dp).clickable { onPickSticker(st) },
                            )
                        }
                    }
                }
            }
            Box(Modifier.fillMaxWidth().height(24.dp))
        }
    }
}

@Composable
private fun MediaGrid(loading: Boolean, error: String?, count: Int, content: @Composable () -> Unit) {
    when {
        loading && count == 0 -> Box(
            Modifier.fillMaxWidth().height(160.dp),
            contentAlignment = Alignment.Center,
        ) { CircularProgressIndicator(modifier = Modifier.size(28.dp)) }
        error != null && count == 0 ->
            Text(error, modifier = Modifier.padding(16.dp), color = MaterialTheme.colorScheme.error)
        count == 0 ->
            Text(
                "Nothing here yet",
                modifier = Modifier.padding(16.dp),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        else -> content()
    }
}

/** AND-174 (comment tipping) — preset-amount tip bottom sheet. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun CommentTipSheet(
    state: CommentTipState,
    onConfirm: (Int) -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState()) {
        Column(
            Modifier.fillMaxWidth().padding(16.dp).testTag(CommentsTestTags.TIP_SHEET),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Send a tip", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                state.presetsCents.forEach { cents ->
                    OutlinedButton(onClick = { onConfirm(cents) }, enabled = !state.submitting) {
                        Text("$" + "%.2f".format(cents / 100.0))
                    }
                }
            }
            if (state.submitting) CircularProgressIndicator(modifier = Modifier.size(24.dp))
            Box(Modifier.fillMaxWidth().height(16.dp))
        }
    }
}
