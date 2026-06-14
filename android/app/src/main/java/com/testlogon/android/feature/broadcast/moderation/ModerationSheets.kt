@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.broadcast.moderation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.data.broadcast.chat.ChatMessage

/** AND-313 - stable testTags for the moderation surfaces. */
object ModerationTestTags {
    const val MESSAGE_SHEET = "mod_message_sheet"
    const val USER_SHEET = "mod_user_sheet"
    const val DELETE = "mod_delete"
    const val PIN = "mod_pin"
    const val UNPIN = "mod_unpin"
    const val MUTE = "mod_mute"
    const val MUTE_5M = "mod_mute_5m"
    const val MUTE_1H = "mod_mute_1h"
    const val MUTE_24H = "mod_mute_24h"
    const val BAN = "mod_ban"
    const val BAN_CONFIRM = "mod_ban_confirm"
    const val UNBAN = "mod_unban"
    const val MODERATE_AUTHOR = "mod_moderate_author"
    const val LOG_SCREEN = "mod_log_screen"
    const val LOG_ROW = "mod_log_row"
    const val PINNED_BANNER = "mod_pinned_banner"
}

/**
 * AND-313 - message-scoped moderation sheet: Delete / Pin-or-Unpin / Moderate author. Pin / Unpin are only
 * offered when delegate routing is available ([delegateAvailable]); a host without a creatorId sees Delete +
 * Moderate author only. The caller wraps this in if(canModerate).
 */
@Composable
fun MessageModerationSheet(
    message: ChatMessage,
    isPinned: Boolean,
    delegateAvailable: Boolean,
    onDelete: () -> Unit,
    onPin: () -> Unit,
    onUnpin: () -> Unit,
    onModerateAuthor: () -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(ModerationTestTags.MESSAGE_SHEET)) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = message.text.orEmpty(),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(bottom = 4.dp),
            )
            SheetAction(
                label = stringResource(R.string.moderation_delete),
                contentDescription = stringResource(R.string.moderation_delete_cd),
                testTag = ModerationTestTags.DELETE,
                onClick = onDelete,
            )
            if (delegateAvailable) {
                if (isPinned) {
                    SheetAction(
                        label = stringResource(R.string.moderation_unpin),
                        contentDescription = stringResource(R.string.moderation_unpin_cd),
                        testTag = ModerationTestTags.UNPIN,
                        onClick = onUnpin,
                    )
                } else {
                    SheetAction(
                        label = stringResource(R.string.moderation_pin),
                        contentDescription = stringResource(R.string.moderation_pin_cd),
                        testTag = ModerationTestTags.PIN,
                        onClick = onPin,
                    )
                }
            }
            SheetAction(
                label = stringResource(R.string.moderation_moderate_author),
                contentDescription = stringResource(
                    R.string.moderation_moderate_author_cd,
                    message.senderDisplayName,
                ),
                testTag = ModerationTestTags.MODERATE_AUTHOR,
                onClick = onModerateAuthor,
            )
        }
    }
}

/**
 * AND-313 - user-scoped moderation sheet: Mute (5m / 1h / 24h chips, default 5m) / Ban (optional reason,
 * maxLen 500) with a destructive confirm dialog / Unban. There is NO unmute (a mute expires; the wire has no
 * unmute endpoint). Ban / Unban are only offered when delegate routing is available.
 */
@Composable
fun UserModerationSheet(
    userId: String,
    displayName: String,
    delegateAvailable: Boolean,
    onMute: (MuteSpec) -> Unit,
    onBan: (String?) -> Unit,
    onUnban: () -> Unit,
    onDismiss: () -> Unit,
) {
    var selected by remember { mutableStateOf(MuteSpec.FIVE_MINUTES.durationSeconds) }
    var reason by remember { mutableStateOf("") }
    var showBanConfirm by remember { mutableStateOf(false) }

    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(ModerationTestTags.USER_SHEET)) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = displayName.ifBlank { stringResource(R.string.moderation_unnamed_user) },
                style = MaterialTheme.typography.titleMedium,
            )

            Text(stringResource(R.string.moderation_mute_label), style = MaterialTheme.typography.labelLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                DurationChip(
                    label = stringResource(R.string.moderation_mute_5m),
                    selected = selected == MuteSpec.FIVE_MINUTES.durationSeconds,
                    testTag = ModerationTestTags.MUTE_5M,
                    onClick = { selected = MuteSpec.FIVE_MINUTES.durationSeconds },
                )
                DurationChip(
                    label = stringResource(R.string.moderation_mute_1h),
                    selected = selected == MuteSpec.ONE_HOUR.durationSeconds,
                    testTag = ModerationTestTags.MUTE_1H,
                    onClick = { selected = MuteSpec.ONE_HOUR.durationSeconds },
                )
                DurationChip(
                    label = stringResource(R.string.moderation_mute_24h),
                    selected = selected == MuteSpec.ONE_DAY.durationSeconds,
                    testTag = ModerationTestTags.MUTE_24H,
                    onClick = { selected = MuteSpec.ONE_DAY.durationSeconds },
                )
            }
            TlButton(
                text = stringResource(R.string.moderation_mute),
                onClick = { onMute(MuteSpec(selected)) },
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(ModerationTestTags.MUTE)
                    .semantics {
                        role = Role.Button
                        contentDescription = displayName
                    },
            )

            if (delegateAvailable) {
                OutlinedTextField(
                    value = reason,
                    onValueChange = { if (it.length <= BAN_REASON_MAX) reason = it },
                    label = { Text(stringResource(R.string.moderation_ban_reason_label)) },
                    singleLine = false,
                    modifier = Modifier.fillMaxWidth(),
                )
                TlButton(
                    text = stringResource(R.string.moderation_ban),
                    onClick = { showBanConfirm = true },
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag(ModerationTestTags.BAN),
                )
                TextButton(
                    onClick = onUnban,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag(ModerationTestTags.UNBAN),
                ) {
                    Text(stringResource(R.string.moderation_unban))
                }
            }
        }
    }

    if (showBanConfirm) {
        BanConfirmDialog(
            displayName = displayName,
            onConfirm = {
                showBanConfirm = false
                onBan(reason.ifBlank { null })
            },
            onDismiss = { showBanConfirm = false },
        )
    }
}

/** AND-313 - destructive confirm dialog for a ban. */
@Composable
fun BanConfirmDialog(
    displayName: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.moderation_ban_confirm_title)) },
        text = {
            Text(
                stringResource(
                    R.string.moderation_ban_confirm_body,
                    displayName.ifBlank { stringResource(R.string.moderation_unnamed_user) },
                ),
            )
        },
        confirmButton = {
            TextButton(onClick = onConfirm, modifier = Modifier.testTag(ModerationTestTags.BAN_CONFIRM)) {
                Text(stringResource(R.string.moderation_ban_confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.moderation_ban_cancel)) }
        },
    )
}

/**
 * AND-313 - the pinned-message banner slot composable rendered atop the LiveChatPanel (driven by the VM's
 * pinnedMessage). When [message] is null this renders nothing.
 */
@Composable
fun PinnedMessageBanner(
    message: ChatMessage?,
    canUnpin: Boolean,
    onUnpin: () -> Unit,
    modifier: Modifier = Modifier,
) {
    if (message == null) return
    androidx.compose.material3.Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        modifier = modifier
            .fillMaxWidth()
            .testTag(ModerationTestTags.PINNED_BANNER),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.moderation_pinned_label),
                    style = MaterialTheme.typography.labelSmall,
                )
                Text(
                    text = message.text.orEmpty(),
                    style = MaterialTheme.typography.bodyMedium,
                    maxLines = 2,
                )
            }
            if (canUnpin) {
                TextButton(
                    onClick = onUnpin,
                    modifier = Modifier.heightIn(min = 48.dp).testTag(ModerationTestTags.UNPIN),
                ) {
                    Text(stringResource(R.string.moderation_unpin))
                }
            }
        }
    }
}

@Composable
private fun SheetAction(
    label: String,
    contentDescription: String,
    testTag: String,
    onClick: () -> Unit,
) {
    TextButton(
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(testTag)
            .semantics {
                role = Role.Button
                this.contentDescription = contentDescription
            },
    ) {
        Text(label, modifier = Modifier.fillMaxWidth())
    }
}

@Composable
private fun DurationChip(
    label: String,
    selected: Boolean,
    testTag: String,
    onClick: () -> Unit,
) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label) },
        modifier = Modifier
            .heightIn(min = 48.dp)
            .testTag(testTag)
            .selectable(selected = selected, onClick = onClick, role = Role.RadioButton),
    )
}

private const val BAN_REASON_MAX = 500
