@file:OptIn(
    androidx.compose.ui.ExperimentalComposeUiApi::class,
    androidx.compose.foundation.layout.ExperimentalLayoutApi::class,
    androidx.compose.material3.ExperimentalMaterial3Api::class,
)

package com.testlogon.android.feature.messaging.thread

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Movie
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.Alignment
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.FilterChip
import androidx.compose.material3.ListItem
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import androidx.compose.ui.platform.testTag
import coil.imageLoader
import com.testlogon.android.R
import com.testlogon.android.data.messaging.MessageEdit
import com.testlogon.android.data.messaging.MessageMedia
import com.testlogon.android.data.messaging.Reaction
import com.testlogon.android.data.messaging.Reactor
import kotlinx.coroutines.launch

/** AND-140 — test tags for the message-action UI (used by Compose UI tests). */
object MessageActionTestTags {
    const val ACTIONS_SHEET = "msg_actions_sheet"
    // TIP-203 - money-reaction (tip) affordances.
    const val TIP_REACT_OPEN = "tip_react_message_open"
    const val TIP_REACT_CHIPS = "tip_react_message_chips"
    fun tipReactChip(key: String): String = "tip_react_message_chip_" + key
    const val EMOJI_PICKER = "msg_emoji_picker"
    const val REACTION_CHIPS = "msg_reaction_chips"
    const val REACTION_DETAILS_SHEET = "msg_reaction_details_sheet"
    const val PINS_SHEET = "msg_pins_sheet"
    const val EDIT_HISTORY_SHEET = "msg_edit_history_sheet"
    const val EDIT_DIALOG = "msg_edit_dialog"
    const val DELETE_DIALOG = "msg_delete_dialog"
    const val REVOKE_DIALOG = "msg_revoke_dialog"
    const val ACTION_PIN = "msg_action_pin"
    const val ACTION_EDIT = "msg_action_edit"
    const val ACTION_DELETE = "msg_action_delete"
    const val ACTION_REVOKE = "msg_action_revoke"
    const val ACTION_HIDE = "msg_action_hide"
    const val ACTION_REPORT = "msg_action_report"
    const val HOLD_NOTICE = "msg_action_hold_notice"
}

/** AND-140 — curated quick-reaction emoji row (matches common chat clients). */
internal const val TIP_REACT_EMOJI = "💰"

internal val QUICK_REACTIONS = listOf("👍", "❤️", "😂", "😮", "😢", "🙏")

/**
 * AND-140 — the long-press action sheet for a message. Edit/Delete/Revoke are gated by [message.isOwn];
 * reactions and hide are available on any (non-tombstone) message. Tip is offered for others' messages
 * (reusing the AND-139 tip flow). Dismisses itself after dispatching the chosen action.
 */
@Composable
fun MessageActionsSheet(
    message: ThreadMessageUi,
    onAction: (ThreadAction) -> Unit,
    onTip: (String) -> Unit,
    onDismiss: () -> Unit,
    // #2 — save an image/video message to the device gallery; null when the message has no saveable
    // media (only image/video clips are offered). Reuses the image save-to-phone path.
    onSaveMedia: ((ThreadMessageUi) -> Unit)? = null,
    // #9 — download/save a FILE or PDF attachment to the phone's Downloads (download-if-needed then
    // save-to-phone). Null hides the row.
    onSaveFile: ((ThreadMessageUi) -> Unit)? = null,
) {
    // AND-164 — destructive/mutating actions are suppressed entirely when the message is on legal hold.
    val allowed = message.allowedActions()
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(MessageActionTestTags.ACTIONS_SHEET).semantics { testTagsAsResourceId = true }) {
        Column(Modifier.fillMaxWidth().padding(bottom = 16.dp)) {
            // Quick-reaction emoji row (always available unless the message is a tombstone).
            if (!message.isTombstone) {
                EmojiReactionPicker(
                    selected = message.reactions.filter { it.reactedByMe }.map { it.emoji }.toSet(),
                    onPick = { emoji ->
                        onAction(ThreadAction.ToggleReaction(message.key, emoji))
                        onDismiss()
                    },
                )
                Divider()
            }

            // TIP-203 - money-REACTION: opens the shared tip sheet (amount + a money glyph) and, on
            // confirm, POSTs the message tip-react. Distinct from the free emoji reactions above and
            // the direct "Send a tip" action below. Not offered on your own message (self-tip 400).
            if (!message.isTombstone && !message.isOwn) {
                AssistChip(
                    onClick = { onAction(ThreadAction.TipReact(message.key, TIP_REACT_EMOJI)); onDismiss() },
                    label = { Text(TIP_REACT_EMOJI + "  " + stringResource(R.string.msg_tip_react)) },
                    modifier = Modifier.padding(horizontal = 12.dp).testTag(MessageActionTestTags.TIP_REACT_OPEN),
                )
                Divider()
            }

            // AND-164 — explain WHY destructive controls are gone (accessible supporting text).
            if (message.onHold && !message.isTombstone) {
                ListItem(
                    headlineContent = { Text(stringResource(R.string.action_unavailable_legal_hold)) },
                    modifier = Modifier.fillMaxWidth().testTag(MessageActionTestTags.HOLD_NOTICE)
                        .semantics { stateDescription = "disabled" },
                )
            }

            if (!message.isTombstone) {
                ActionRow(
                    label = stringResource(R.string.msg_action_reply),
                    tag = "msg_action_reply",
                ) { onAction(ThreadAction.Reply(message.key)); onDismiss() }
            }

            // #2 — Download/save-to-phone for an image or (unlocked/own) video message. Gated content
            // that hasn't been revealed (still a Paid/teaser bubble) has no saveable media, so the row
            // only appears once the media is actually present in the bubble.
            if (onSaveMedia != null && !message.isTombstone && message.hasSaveableMedia()) {
                ActionRow(
                    label = stringResource(R.string.msg_action_save_to_phone),
                    tag = "msg_action_save_media",
                ) { onSaveMedia(message); onDismiss() }
            }

            // #9 — Download for a file/PDF attachment: saves to the phone's Downloads (download-if-needed).
            if (onSaveFile != null && !message.isTombstone &&
                message.media is MessageMedia.File && !message.isDownloadGated()
            ) {
                ActionRow(
                    label = stringResource(R.string.msg_action_download),
                    tag = "msg_action_download_file",
                ) { onSaveFile(message); onDismiss() }
            }

            if (MessageAction.PIN in allowed) {
                if (message.isPinned) {
                    ActionRow(
                        label = stringResource(R.string.msg_action_unpin),
                        tag = MessageActionTestTags.ACTION_PIN,
                    ) { onAction(ThreadAction.SetPinned(message.key, false)); onDismiss() }
                } else if (!message.isTombstone) {
                    ActionRow(
                        label = stringResource(R.string.msg_action_pin),
                        tag = MessageActionTestTags.ACTION_PIN,
                    ) { onAction(ThreadAction.SetPinned(message.key, true)); onDismiss() }
                }
            }

            if (MessageAction.EDIT in allowed && message.isOwn && !message.isTombstone &&
                message.media is com.testlogon.android.data.messaging.MessageMedia.None
            ) {
                ActionRow(
                    label = stringResource(R.string.msg_action_edit),
                    tag = MessageActionTestTags.ACTION_EDIT,
                ) { onAction(ThreadAction.StartEdit(message.key)); onDismiss() }
            }

            if (message.isEdited) {
                ActionRow(label = stringResource(R.string.msg_action_edit_history)) {
                    onAction(ThreadAction.OpenEditHistory(message.key)); onDismiss()
                }
            }

            if (message.reactions.isNotEmpty()) {
                ActionRow(label = stringResource(R.string.msg_action_who_reacted)) {
                    onAction(ThreadAction.OpenReactionDetails(message.key)); onDismiss()
                }
            }

            if (!message.isOwn && !message.isTombstone) {
                if (MessageAction.HIDE in allowed) {
                    ActionRow(
                        label = stringResource(R.string.msg_action_hide),
                        tag = MessageActionTestTags.ACTION_HIDE,
                    ) { onAction(ThreadAction.SetHidden(message.key, true)); onDismiss() }
                }
                ActionRow(label = stringResource(R.string.msg_action_tip)) { onTip(message.key); onDismiss() }
                // AND-163 — report a non-own message (reporting own messages is hidden in UI). Not gated
                // by a hold: reporting is non-destructive.
                ActionRow(
                    label = stringResource(R.string.msg_action_report),
                    tag = MessageActionTestTags.ACTION_REPORT,
                ) { onAction(ThreadAction.Report(message.key)); onDismiss() }
            }

            if (message.isOwn && !message.isTombstone) {
                if (MessageAction.DELETE in allowed) {
                    ActionRow(
                        label = stringResource(R.string.msg_action_delete),
                        tag = MessageActionTestTags.ACTION_DELETE,
                    ) { onAction(ThreadAction.Delete(message.key)); onDismiss() }
                }
                if (MessageAction.REVOKE in allowed) {
                    ActionRow(
                        label = stringResource(R.string.msg_action_revoke),
                        tag = MessageActionTestTags.ACTION_REVOKE,
                    ) { onAction(ThreadAction.Revoke(message.key)); onDismiss() }
                }
            }
        }
    }
}

@Composable
private fun ActionRow(label: String, tag: String? = null, onClick: () -> Unit) {
    val base = Modifier.fillMaxWidth().heightIn(min = 48.dp)
    ListItem(
        headlineContent = { Text(label) },
        modifier = (if (tag != null) base.testTag(tag) else base)
            .toggleable(value = false, onValueChange = { onClick() }),
    )
}

/** AND-140 — a short curated emoji row; tapping toggles the current user's reaction for that emoji. */
@Composable
fun EmojiReactionPicker(
    selected: Set<String>,
    onPick: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    FlowRow(
        modifier = modifier.fillMaxWidth().padding(12.dp).testTag(MessageActionTestTags.EMOJI_PICKER),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        val youReacted = stringResource(R.string.msg_reaction_you_reacted)
        QUICK_REACTIONS.forEach { emoji ->
            val isSelected = emoji in selected
            FilterChip(
                selected = isSelected,
                onClick = { onPick(emoji) },
                label = { Text(emoji) },
                modifier = Modifier.semantics {
                    contentDescription = emoji
                    if (isSelected) stateDescription = youReacted
                },
            )
        }
    }
}

/**
 * AND-140 — under-bubble reaction chip row. Each chip shows emoji + count and highlights when the
 * current user reacted; tapping toggles, long-pressing (here mapped to the chip's secondary affordance)
 * opens the reactor-details sheet.
 */
@Composable
fun ReactionChipsRow(
    reactions: List<Reaction>,
    onToggle: (String) -> Unit,
    onSeeWhoReacted: () -> Unit,
    modifier: Modifier = Modifier,
) {
    if (reactions.isEmpty()) return
    FlowRow(
        modifier = modifier.padding(top = 4.dp).testTag(MessageActionTestTags.REACTION_CHIPS),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        val youReacted = stringResource(R.string.msg_reaction_you_reacted)
        reactions.forEach { r ->
            val cd = stringResource(R.string.msg_reaction_chip_cd, r.emoji, r.count)
            FilterChip(
                selected = r.reactedByMe,
                onClick = { onToggle(r.emoji) },
                label = { Text("${r.emoji} ${r.count}") },
                modifier = Modifier.semantics {
                    contentDescription = cd
                    if (r.reactedByMe) stateDescription = youReacted
                },
            )
        }
        AssistChip(
            onClick = onSeeWhoReacted,
            label = { Text(stringResource(R.string.msg_action_who_reacted)) },
            colors = AssistChipDefaults.assistChipColors(),
        )
    }
}

/**
 * TIP-203 - under-bubble MONEY-reaction chip row (tip reactions), visually distinct from the free
 * emoji [ReactionChipsRow]. Each chip shows the tip glyph + amount (e.g. money + "$5.00").
 */
@Composable
fun TipReactionChipsRow(
    tipReactions: List<com.testlogon.android.data.messaging.TipReaction>,
    modifier: Modifier = Modifier,
) {
    if (tipReactions.isEmpty()) return
    FlowRow(
        modifier = modifier.padding(top = 4.dp).testTag(MessageActionTestTags.TIP_REACT_CHIPS),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        tipReactions.forEach { t ->
            val amount = String.format(java.util.Locale.US, "$%.2f", t.amountCents / 100.0)
            val glyph = t.emoji.ifBlank { TIP_REACT_EMOJI }
            AssistChip(
                onClick = {},
                label = { Text(glyph + " " + amount) },
                colors = AssistChipDefaults.assistChipColors(),
                modifier = Modifier.testTag(MessageActionTestTags.tipReactChip(t.tipPaymentId ?: t.emoji)),
            )
        }
    }
}

/** AND-140 — reactor-details sheet: reactors grouped by emoji. */
@Composable
fun ReactionDetailsSheet(
    state: Async<List<Reactor>>,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(MessageActionTestTags.REACTION_DETAILS_SHEET).semantics { testTagsAsResourceId = true }) {
        Column(Modifier.fillMaxWidth().padding(16.dp)) {
            Text(stringResource(R.string.msg_action_who_reacted))
            when (state) {
                Async.Idle, Async.Loading -> CenterLoader()
                is Async.Error -> Text(state.message)
                is Async.Success -> {
                    val grouped = state.data.groupBy { it.emoji }
                    LazyColumn(Modifier.heightIn(max = 360.dp)) {
                        grouped.forEach { (emoji, reactors) ->
                            item(key = "h_$emoji") { Text("$emoji ${reactors.size}") }
                            items(reactors, key = { "${emoji}_${it.userSub}" }) { reactor ->
                                ListItem(headlineContent = { Text(reactor.displayName) })
                            }
                        }
                    }
                }
            }
        }
    }
}

/** AND-140 — pinned-messages sheet; tapping a row jumps the thread to that message. */
@Composable
fun PinnedMessagesSheet(
    state: Async<List<ThreadMessageUi>>,
    onJumpTo: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(MessageActionTestTags.PINS_SHEET).semantics { testTagsAsResourceId = true }) {
        Column(Modifier.fillMaxWidth().padding(16.dp)) {
            Text(stringResource(R.string.msg_pins_title))
            when (state) {
                Async.Idle, Async.Loading -> CenterLoader()
                is Async.Error -> Text(state.message)
                is Async.Success -> {
                    if (state.data.isEmpty()) {
                        Text(stringResource(R.string.msg_pins_empty))
                    } else {
                        LazyColumn(Modifier.heightIn(max = 360.dp)) {
                            items(state.data, key = { it.key }) { msg ->
                                ListItem(
                                    headlineContent = { Text(msg.text.ifBlank { stringResource(R.string.msg_pins_media) }) },
                                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)
                                        .toggleable(value = false, onValueChange = { onJumpTo(msg.key) }),
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

/** AND-140 — edit-history sheet, newest revision first. */
@Composable
fun EditHistorySheet(
    state: Async<List<MessageEdit>>,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(MessageActionTestTags.EDIT_HISTORY_SHEET).semantics { testTagsAsResourceId = true }) {
        Column(Modifier.fillMaxWidth().padding(16.dp)) {
            Text(stringResource(R.string.msg_edit_history_title))
            when (state) {
                Async.Idle, Async.Loading -> CenterLoader()
                is Async.Error -> Text(state.message)
                is Async.Success -> {
                    if (state.data.isEmpty()) {
                        Text(stringResource(R.string.msg_edit_history_empty))
                    } else {
                        LazyColumn(Modifier.heightIn(max = 360.dp)) {
                            items(state.data, key = { it.revision }) { edit -> Text(edit.body) }
                        }
                    }
                }
            }
        }
    }
}

/**
 * AND-140 / B-MSGEDIT #5 — edit dialog pre-filled with the original text, now with full media control:
 * add/replace a photo, file, or library video (promoting a text message), or remove existing media.
 */
@Composable
fun EditMessageDialog(
    target: EditTarget,
    onSubmit: (String) -> Unit,
    onCancel: () -> Unit,
    onPickPhoto: () -> Unit = {},
    onPickFile: () -> Unit = {},
    onPickVideo: () -> Unit = {},
    onClearStaged: () -> Unit = {},
    onToggleRemoveMedia: () -> Unit = {},
) {
    var value by rememberSaveable(target.messageId, stateSaver = androidx.compose.ui.text.input.TextFieldValue.Saver) {
        mutableStateOf(TextFieldValue(target.originalText, androidx.compose.ui.text.TextRange(target.originalText.length)))
    }
    val hasStagedMedia = target.draftImageLocalUri != null ||
        target.draftImage != null || target.draftFilePath != null || target.draftVideoId != null
    AlertDialog(
        onDismissRequest = onCancel,
        modifier = Modifier.testTag(MessageActionTestTags.EDIT_DIALOG),
        title = { Text(stringResource(R.string.msg_edit_title)) },
        text = {
            Column {
                OutlinedTextField(
                    value = value,
                    onValueChange = { value = it },
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(12.dp))
                when {
                    target.attaching -> {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                            Spacer(Modifier.width(8.dp))
                            Text(
                                text = stringResource(R.string.msg_edit_attaching),
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        }
                    }
                    // A staged photo shows a thumbnail; a staged file/video shows a labelled chip.
                    target.draftImageLocalUri != null -> StagedMediaRow(
                        imageUri = target.draftImageLocalUri,
                        label = stringResource(R.string.msg_edit_photo_attached),
                        onRemove = onClearStaged,
                    )
                    target.draftFilePath != null || target.draftFileName != null -> StagedMediaRow(
                        imageUri = null,
                        label = target.draftFileName ?: stringResource(R.string.msg_edit_file_attached),
                        leadingIcon = Icons.Filled.AttachFile,
                        onRemove = onClearStaged,
                    )
                    target.draftVideoId != null -> StagedMediaRow(
                        imageUri = null,
                        label = target.draftVideoTitle ?: stringResource(R.string.msg_edit_video_attached),
                        leadingIcon = Icons.Filled.Movie,
                        onRemove = onClearStaged,
                    )
                    target.removeMedia -> {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = stringResource(R.string.msg_edit_media_will_be_removed),
                                style = MaterialTheme.typography.bodyMedium,
                                modifier = Modifier.weight(1f),
                            )
                            TextButton(onClick = onToggleRemoveMedia) { Text(stringResource(R.string.action_undo)) }
                        }
                    }
                    else -> {
                        // No staged change yet: offer add-photo / add-file / add-video, and (when the
                        // message already carries media) a remove-media affordance.
                        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            TextButton(
                                onClick = onPickPhoto,
                                modifier = Modifier.testTag("thread_edit_add_photo"),
                            ) {
                                Icon(Icons.Filled.Image, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(4.dp))
                                Text(stringResource(R.string.msg_edit_add_photo))
                            }
                            TextButton(
                                onClick = onPickFile,
                                modifier = Modifier.testTag("thread_edit_add_file"),
                            ) {
                                Icon(Icons.Filled.AttachFile, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(4.dp))
                                Text(stringResource(R.string.msg_edit_add_file))
                            }
                            TextButton(
                                onClick = onPickVideo,
                                modifier = Modifier.testTag("thread_edit_add_video"),
                            ) {
                                Icon(Icons.Filled.Movie, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(4.dp))
                                Text(stringResource(R.string.msg_edit_add_video))
                            }
                        }
                        if (target.hasMedia) {
                            TextButton(
                                onClick = onToggleRemoveMedia,
                                modifier = Modifier.testTag("thread_edit_remove_media"),
                            ) {
                                Icon(Icons.Filled.Close, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(4.dp))
                                Text(stringResource(R.string.msg_edit_remove_media))
                            }
                        }
                    }
                }
                target.error?.let {
                    Spacer(Modifier.height(8.dp))
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
                }
            }
        },
        confirmButton = {
            // Saveable when there's text, a staged media change, or a pending media removal.
            val canSave = !target.attaching &&
                (value.text.isNotBlank() || hasStagedMedia || target.removeMedia)
            TextButton(
                onClick = { onSubmit(value.text) },
                enabled = canSave,
            ) { Text(stringResource(R.string.msg_edit_save)) }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text(stringResource(R.string.action_cancel)) } },
    )
}

/** B-MSGEDIT #5 — one staged-media row: optional thumbnail (photo) or leading icon (file/video) + remove. */
@Composable
private fun StagedMediaRow(
    imageUri: String?,
    label: String,
    onRemove: () -> Unit,
    leadingIcon: androidx.compose.ui.graphics.vector.ImageVector? = null,
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        if (imageUri != null) {
            coil.compose.AsyncImage(
                model = imageUri,
                contentDescription = label,
                modifier = Modifier
                    .size(56.dp)
                    .clip(MaterialTheme.shapes.small)
                    .testTag("thread_edit_staged_thumb"),
                contentScale = androidx.compose.ui.layout.ContentScale.Crop,
            )
            Spacer(Modifier.width(8.dp))
        } else if (leadingIcon != null) {
            Icon(leadingIcon, contentDescription = null, modifier = Modifier.size(28.dp))
            Spacer(Modifier.width(8.dp))
        }
        Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        IconButton(onClick = onRemove, modifier = Modifier.testTag("thread_edit_staged_remove")) {
            Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.action_remove))
        }
    }
}

/** AND-140 — delete-for-me confirmation dialog. */
@Composable
fun DeleteMessageDialog(onConfirm: () -> Unit, onCancel: () -> Unit) {
    AlertDialog(
        onDismissRequest = onCancel,
        modifier = Modifier.testTag(MessageActionTestTags.DELETE_DIALOG),
        title = { Text(stringResource(R.string.msg_delete_title)) },
        text = { Text(stringResource(R.string.msg_delete_body)) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(stringResource(R.string.msg_action_delete)) } },
        dismissButton = { TextButton(onClick = onCancel) { Text(stringResource(R.string.action_cancel)) } },
    )
}

/** AND-140 — revoke-for-everyone confirmation dialog. */
@Composable
fun RevokeMessageDialog(onConfirm: () -> Unit, onCancel: () -> Unit) {
    AlertDialog(
        onDismissRequest = onCancel,
        modifier = Modifier.testTag(MessageActionTestTags.REVOKE_DIALOG),
        title = { Text(stringResource(R.string.msg_revoke_title)) },
        text = { Text(stringResource(R.string.msg_revoke_body)) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(stringResource(R.string.msg_action_revoke)) } },
        dismissButton = { TextButton(onClick = onCancel) { Text(stringResource(R.string.action_cancel)) } },
    )
}

/**
 * AND-140 — single host that owns the action sheet + confirm dialogs + read sheets for the thread.
 * [target] is the message whose action sheet is open (null = closed); confirmations capture the
 * pending message id locally so the right id is dispatched on confirm.
 */
@Composable
fun MessageActionsHost(
    target: ThreadMessageUi?,
    actions: MessageActionsUiState,
    onAction: (ThreadAction) -> Unit,
    onTip: (String) -> Unit,
    onJumpToPinned: (String) -> Unit,
    onSaveFile: ((ThreadMessageUi) -> Unit)? = null,
    onCloseSheet: () -> Unit,
) {
    var pendingDelete by remember { mutableStateOf<String?>(null) }
    var pendingRevoke by remember { mutableStateOf<String?>(null) }
    // #2 — save-to-phone is self-contained here (no VM/repo): saves the image via the shared Coil loader
    // and the video by streaming its url, both to MediaStore, exactly like the full-screen viewers.
    val context = androidx.compose.ui.platform.LocalContext.current
    val saveScope = androidx.compose.runtime.rememberCoroutineScope()

    target?.let { msg ->
        MessageActionsSheet(
            message = msg,
            onAction = { action ->
                when (action) {
                    is ThreadAction.Delete -> pendingDelete = action.messageId
                    is ThreadAction.Revoke -> pendingRevoke = action.messageId
                    else -> onAction(action)
                }
            },
            onTip = onTip,
            onDismiss = onCloseSheet,
            onSaveFile = onSaveFile,
            onSaveMedia = { m ->
                val media = m.media
                saveScope.launch {
                    val ok = when (media) {
                        is com.testlogon.android.data.messaging.MessageMedia.Image ->
                            media.url?.let {
                                com.testlogon.android.feature.messaging.media.saveImageToGallery(
                                    context, it, context.imageLoader,
                                )
                            } ?: false
                        is com.testlogon.android.data.messaging.MessageMedia.VideoClip ->
                            media.playbackUrl?.let {
                                com.testlogon.android.feature.messaging.media.saveVideoToGallery(context, it)
                            } ?: false
                        else -> false
                    }
                    android.widget.Toast.makeText(
                        context,
                        if (ok) "Saved to phone" else "Couldn't save",
                        android.widget.Toast.LENGTH_SHORT,
                    ).show()
                }
            },
        )
    }

    pendingDelete?.let { id ->
        DeleteMessageDialog(
            onConfirm = { onAction(ThreadAction.Delete(id)); pendingDelete = null },
            onCancel = { pendingDelete = null },
        )
    }
    pendingRevoke?.let { id ->
        RevokeMessageDialog(
            onConfirm = { onAction(ThreadAction.Revoke(id)); pendingRevoke = null },
            onCancel = { pendingRevoke = null },
        )
    }

    // B-MSGEDIT #5 — the edit dialog is now rendered by ThreadRoute (it drives the system pickers +
    // the shared library-video picker), so it is intentionally NOT rendered here.

    if (actions.reactionDetailsVisible) {
        ReactionDetailsSheet(state = actions.reactionDetails, onDismiss = { onAction(ThreadAction.DismissSheets) })
    }
    if (actions.pinsSheetVisible) {
        PinnedMessagesSheet(
            state = actions.pinned,
            onJumpTo = onJumpToPinned,
            onDismiss = { onAction(ThreadAction.DismissSheets) },
        )
    }
    if (actions.editHistoryVisible) {
        EditHistorySheet(state = actions.editHistory, onDismiss = { onAction(ThreadAction.DismissSheets) })
    }
}

@Composable
private fun CenterLoader() {
    Row(Modifier.fillMaxWidth().padding(16.dp), horizontalArrangement = Arrangement.Center) {
        CircularProgressIndicator(Modifier.sizeIn(maxWidth = 32.dp, maxHeight = 32.dp))
    }
}

/**
 * #2 — true when the message currently has saveable media in the bubble: a displayable image (url
 * present) or a playable video clip (playbackUrl present). A still-locked/encrypted/view-once teaser
 * has no resolved media url, so the Save row is correctly hidden until the content is revealed.
 */
internal fun ThreadMessageUi.hasSaveableMedia(): Boolean = when (val m = media) {
    is MessageMedia.Image -> !m.url.isNullOrBlank()
    is MessageMedia.VideoClip -> !m.playbackUrl.isNullOrBlank()
    else -> false
}

/**
 * #9 — a file message is download-gated (no save offered yet) when it is still behind a paywall the
 * viewer hasn't unlocked, or an unconsumed view-once. Own messages and already-available files are
 * never gated.
 */
internal fun ThreadMessageUi.isDownloadGated(): Boolean {
    if (isOwn) return false
    if (lockPriceCents != null && (media as? MessageMedia.Paid)?.monetization?.unlocked == false) return true
    if (viewOnce && !consumed) return true
    return false
}

/** AND-140 — tombstone bubble text for a deleted/revoked message. */
@Composable
fun tombstoneLabel(message: ThreadMessageUi): String = when {
    message.isRevoked -> stringResource(R.string.msg_tombstone_revoked)
    message.isDeleted -> stringResource(R.string.msg_tombstone_deleted)
    message.isExpired -> "This message has expired"
    else -> ""
}
