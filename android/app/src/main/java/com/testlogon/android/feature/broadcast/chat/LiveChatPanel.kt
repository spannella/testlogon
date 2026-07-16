@file:OptIn(
    androidx.compose.foundation.ExperimentalFoundationApi::class,
    androidx.compose.material3.ExperimentalMaterial3Api::class,
)

package com.testlogon.android.feature.broadcast.chat

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Reply
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.AddPhotoAlternate
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PlayCircle
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import com.testlogon.android.data.report.ReportTarget
import com.testlogon.android.feature.report.ContentReportSheetHost
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.BuildConfig
import com.testlogon.android.R
import com.testlogon.android.data.broadcast.chat.ChatMessage
import com.testlogon.android.data.broadcast.chat.DeliveryState

/** AND-281 / BCAST-016 — stable testTags for the live-chat panel. */
object LiveChatTestTags {
    const val LIST = "live_chat_list"
    const val COMPOSER = "live_chat_composer"
    const val SEND = "live_chat_send"
    const val BANNER = "live_chat_banner"
    const val ATTACH = "live_chat_attach"
    const val OPTIONS = "live_chat_options"
}

/** Reaction emojis offered on a long-press. */
private val REACTION_EMOJIS = listOf("👍", "❤️", "😂", "🎉", "🔥", "😮")

/**
 * AND-281 / BCAST-016 — the live-chat panel (viewer + host). Subscribes to the SSE stream under
 * repeatOnLifecycle(STARTED). Reverse-scrolling message list (newest at bottom), a rich composer
 * (reply / photo+video attach / gating options), and rich message renderers (reactions, replies, image,
 * locked/PPV, view-once, video, expiring, scheduled). [isHost] gates the broadcaster-only send options
 * (locked / expiring) which the backend rejects for non-broadcasters.
 */
@Composable
fun LiveChatPanel(
    sessionId: String,
    modifier: Modifier = Modifier,
    isHost: Boolean = false,
    viewModel: LiveChatViewModel = hiltViewModel<LiveChatViewModel, LiveChatViewModel.Factory>(
        key = "live_chat_$sessionId",
        creationCallback = { factory -> factory.create(sessionId) },
    ),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val lifecycleOwner = LocalLifecycleOwner.current
    val context = LocalContext.current

    LaunchedEffect(viewModel, lifecycleOwner) {
        lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
            viewModel.onResumeStreaming()
        }
    }

    // BCAST-016 — the unified photo/video picker (same picker seam as the DM composer). On pick we route
    // to the image or video upload path by the resolved MIME type.
    val pickMedia = rememberLauncherForActivityResult(
        ActivityResultContracts.PickVisualMedia(),
    ) { uri ->
        if (uri != null) {
            val isVideo = context.contentResolver.getType(uri)?.startsWith("video/") == true
            if (isVideo) viewModel.onPickVideo(uri.toString()) else viewModel.onPickImage(uri.toString())
        }
    }

    // Message-actions sheet (long-press): react + reply.
    var actionTarget by remember { mutableStateOf<ChatMessage?>(null) }
    // MODX-12 - live-chat message report target.
    var reportTarget by remember { mutableStateOf<ReportTarget?>(null) }
    // Composer options sheet.
    var optionsOpen by remember { mutableStateOf(false) }

    Surface(modifier = modifier, tonalElevation = 1.dp) {
        Column(modifier = Modifier.fillMaxWidth()) {
            when (state) {
                LiveChatUiState.Connecting -> ConnectionBanner(ConnectionStatus.RECONNECTING, onRetry = {})
                is LiveChatUiState.Error -> ConnectionBanner(ConnectionStatus.OFFLINE, onRetry = viewModel::retry)
                is LiveChatUiState.Content -> {
                    val content = state as LiveChatUiState.Content
                    if (content.connection != ConnectionStatus.LIVE) {
                        ConnectionBanner(content.connection, onRetry = viewModel::retry)
                    }
                    ChatMessageList(
                        messages = content.messages,
                        onRetrySend = viewModel::retrySend,
                        onAtBottomChanged = viewModel::onScrolledToBottom,
                        onLongPress = { actionTarget = it },
                        onToggleReaction = viewModel::reactToMessage,
                        onUnlock = viewModel::unlock,
                        onReveal = viewModel::revealViewOnce,
                        onOpenVideo = { url -> openExternally(context, url) },
                        modifier = Modifier.fillMaxWidth().heightIn(max = 280.dp),
                    )
                    content.replyTo?.let { ReplyPreviewBar(it, onCancel = viewModel::onClearReply) }
                    ComposerOptionsBar(content, onOpenOptions = { optionsOpen = true }, onClearReply = viewModel::onClearReply)
                    ChatComposer(
                        text = content.composerText,
                        canSend = content.canSend,
                        attaching = content.attaching,
                        onTextChange = viewModel::onComposerTextChange,
                        onSend = viewModel::send,
                        onAttach = {
                            pickMedia.launch(
                                PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageAndVideo),
                            )
                        },
                        onOptions = { optionsOpen = true },
                    )
                }
            }
        }
    }

    // ---- Message actions bottom sheet (react + reply) ----
    actionTarget?.let { target ->
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(onDismissRequest = { actionTarget = null }, sheetState = sheetState) {
            Column(Modifier.fillMaxWidth().padding(16.dp)) {
                Text(stringResource(R.string.live_chat_react_cd), style = MaterialTheme.typography.labelLarge)
                Row(
                    Modifier.fillMaxWidth().padding(vertical = 12.dp),
                    horizontalArrangement = Arrangement.SpaceEvenly,
                ) {
                    REACTION_EMOJIS.forEach { emoji ->
                        Text(
                            text = emoji,
                            style = MaterialTheme.typography.headlineSmall,
                            modifier = Modifier
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    viewModel.reactToMessage(target.id, emoji)
                                    actionTarget = null
                                }
                                .padding(8.dp),
                        )
                    }
                }
                Divider()
                TextButton(
                    onClick = { viewModel.onReplyTo(target); actionTarget = null },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.AutoMirrored.Filled.Reply, contentDescription = null)
                    Text(stringResource(R.string.live_chat_reply), modifier = Modifier.padding(start = 8.dp))
                }
                if (!target.isSelf) {
                    TextButton(
                        onClick = {
                            reportTarget = ReportTarget.Content(target.id, "broadcast_message", sessionId = target.sessionId)
                            actionTarget = null
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(stringResource(R.string.msg_action_report), modifier = Modifier.padding(start = 8.dp))
                    }
                }
            }
        }
    }

    // MODX-12 - live-chat message report (viewer -> the moderation state machine).
    ContentReportSheetHost(target = reportTarget, onDismiss = { reportTarget = null })

    // ---- Composer options bottom sheet (gating) ----
    if (optionsOpen) {
        val content = state as? LiveChatUiState.Content
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(onDismissRequest = { optionsOpen = false }, sheetState = sheetState) {
            Column(Modifier.fillMaxWidth().padding(16.dp)) {
                Text(stringResource(R.string.live_chat_options_title), style = MaterialTheme.typography.titleMedium)
                val opt = content?.options
                OptionSwitch(
                    label = stringResource(R.string.live_chat_opt_view_once),
                    icon = Icons.Filled.Visibility,
                    checked = opt?.viewOnce == true,
                    onCheckedChange = viewModel::onSetViewOnce,
                )
                OptionSwitch(
                    label = stringResource(R.string.live_chat_opt_schedule),
                    icon = Icons.Filled.Schedule,
                    checked = opt?.sendAtEpochSeconds != null,
                    onCheckedChange = { on ->
                        viewModel.onSetScheduled(if (on) System.currentTimeMillis() / 1000L + 60 else null)
                    },
                )
                if (isHost) {
                    OptionSwitch(
                        label = stringResource(R.string.live_chat_opt_expire),
                        icon = Icons.Filled.Timer,
                        checked = opt?.expiresInSeconds != null,
                        onCheckedChange = { on -> viewModel.onSetExpiry(if (on) 300L else null) },
                    )
                    OptionSwitch(
                        label = stringResource(R.string.live_chat_opt_lock),
                        icon = Icons.Filled.Lock,
                        checked = opt?.lockPriceCents != null,
                        onCheckedChange = { on ->
                            viewModel.onSetLock(
                                if (on) 100L else null,
                                if (on) "Unlock this message" else null,
                            )
                        },
                    )
                }
                TextButton(onClick = { optionsOpen = false }, modifier = Modifier.align(Alignment.End)) {
                    Text(stringResource(R.string.live_chat_done))
                }
            }
        }
    }
}

@Composable
private fun OptionSwitch(
    label: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
        Text(label, modifier = Modifier.weight(1f).padding(start = 12.dp), style = MaterialTheme.typography.bodyLarge)
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun ChatMessageList(
    messages: List<ChatMessage>,
    onRetrySend: (String) -> Unit,
    onAtBottomChanged: (Boolean) -> Unit,
    onLongPress: (ChatMessage) -> Unit,
    onToggleReaction: (String, String) -> Unit,
    onUnlock: (String) -> Unit,
    onReveal: (String) -> Unit,
    onOpenVideo: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    if (messages.isEmpty()) {
        Box(modifier = modifier.padding(24.dp), contentAlignment = Alignment.Center) {
            Text(
                text = stringResource(R.string.live_chat_empty),
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
            )
        }
        return
    }
    val listState = rememberLazyListState()
    val reversed = messages.asReversed()
    LaunchedEffect(messages.size) {
        listState.scrollToItem(0)
        onAtBottomChanged(true)
    }
    LazyColumn(
        state = listState,
        reverseLayout = true,
        modifier = modifier
            .semantics { liveRegion = LiveRegionMode.Polite }
            .testTag(LiveChatTestTags.LIST),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(8.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        items(reversed, key = { it.clientNonce ?: it.id }) { msg ->
            ChatRow(
                msg = msg,
                onRetrySend = onRetrySend,
                onLongPress = onLongPress,
                onToggleReaction = onToggleReaction,
                onUnlock = onUnlock,
                onReveal = onReveal,
                onOpenVideo = onOpenVideo,
            )
        }
    }
}

@Composable
private fun ChatRow(
    msg: ChatMessage,
    onRetrySend: (String) -> Unit,
    onLongPress: (ChatMessage) -> Unit,
    onToggleReaction: (String, String) -> Unit,
    onUnlock: (String) -> Unit,
    onReveal: (String) -> Unit,
    onOpenVideo: (String) -> Unit,
) {
    val failedLabel = stringResource(R.string.live_chat_message_failed)
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .combinedClickable(onClick = {}, onLongClick = { onLongPress(msg) }),
    ) {
        // Sender line (+ host badge + gating badges).
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = if (msg.isSelf) stringResource(R.string.live_chat_you) else msg.senderDisplayName,
                style = MaterialTheme.typography.labelMedium,
                color = if (msg.isSelf) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (msg.isHost) MiniBadge(stringResource(R.string.live_chat_host_badge), MaterialTheme.colorScheme.error)
            if (msg.scheduled) MiniBadge(stringResource(R.string.live_chat_badge_scheduled), MaterialTheme.colorScheme.tertiary)
            if (msg.viewOnce) MiniBadge(stringResource(R.string.live_chat_badge_view_once), MaterialTheme.colorScheme.secondary)
            if (msg.expiresAtEpochSeconds != null && !msg.expired) MiniBadge(stringResource(R.string.live_chat_badge_expiring), MaterialTheme.colorScheme.secondary)
        }

        // Reply quote.
        if (msg.replyToMessageId != null) {
            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = RoundedCornerShape(6.dp),
                modifier = Modifier.padding(top = 2.dp),
            ) {
                Column(Modifier.padding(horizontal = 8.dp, vertical = 4.dp)) {
                    Text(
                        text = msg.replyPreviewSender ?: stringResource(R.string.live_chat_reply),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                    Text(
                        text = msg.replyPreviewText ?: "",
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }

        // Body — dispatch by rich type.
        when {
            msg.expired -> RedactedLine(stringResource(R.string.live_chat_expired))
            msg.isLocked -> LockedBubble(msg, onUnlock)
            msg.viewOnce && !msg.isSelf && msg.viewOnceConsumed && !msg.locallyRevealed ->
                RedactedLine(stringResource(R.string.live_chat_view_once_viewed))
            msg.viewOnce && !msg.isSelf && !msg.locallyRevealed ->
                ViewOncePrompt(onReveal = { onReveal(msg.id) })
            else -> {
                if (msg.hasImage && !msg.imageUrl.isNullOrBlank()) {
                    AsyncImage(
                        model = msg.imageUrl,
                        contentDescription = stringResource(R.string.live_chat_image_cd),
                        contentScale = ContentScale.Crop,
                        modifier = Modifier
                            .padding(top = 2.dp)
                            .widthIn(max = 220.dp)
                            .aspectRatio(1.4f)
                            .clip(RoundedCornerShape(10.dp)),
                    )
                }
                if (msg.hasVideo && !msg.videoUrl.isNullOrBlank()) {
                    VideoTile(msg, onOpenVideo)
                }
                if (!msg.text.isNullOrBlank()) {
                    Text(text = msg.text!!, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 2.dp))
                }
            }
        }

        // Reactions chips.
        if (msg.reactions.isNotEmpty()) {
            Row(Modifier.padding(top = 2.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                msg.reactions.forEach { r ->
                    Surface(
                        color = if (r.reactedBySelf) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.clickable { onToggleReaction(msg.id, r.emoji) },
                    ) {
                        Text(
                            text = "${r.emoji} ${r.count}",
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                        )
                    }
                }
            }
        }

        if (msg.deliveryState == DeliveryState.FAILED && msg.clientNonce != null) {
            Text(
                text = failedLabel,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier
                    .clickable { onRetrySend(msg.clientNonce) }
                    .semantics { role = Role.Button; contentDescription = failedLabel },
            )
        } else if (msg.deliveryState == DeliveryState.SENDING) {
            Text(stringResource(R.string.live_chat_sending), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun MiniBadge(text: String, color: Color) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelSmall,
        color = color,
        modifier = Modifier
            .padding(start = 6.dp)
            .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(4.dp))
            .padding(horizontal = 4.dp),
    )
}

@Composable
private fun RedactedLine(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(top = 2.dp),
    )
}

@Composable
private fun LockedBubble(msg: ChatMessage, onUnlock: (String) -> Unit) {
    val price = ((msg.lockPriceCents ?: 0L) / 100.0)
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = RoundedCornerShape(10.dp),
        modifier = Modifier.padding(top = 2.dp),
    ) {
        Row(Modifier.padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.Lock, contentDescription = null, modifier = Modifier.size(18.dp))
            Column(Modifier.padding(start = 8.dp)) {
                Text(
                    text = msg.lockDescription ?: stringResource(R.string.live_chat_locked),
                    style = MaterialTheme.typography.bodySmall,
                )
                TextButton(onClick = { onUnlock(msg.id) }, contentPadding = androidx.compose.foundation.layout.PaddingValues(0.dp)) {
                    Text(stringResource(R.string.live_chat_unlock_price, String.format("%.2f", price)))
                }
            }
        }
    }
}

@Composable
private fun ViewOncePrompt(onReveal: () -> Unit) {
    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        shape = RoundedCornerShape(10.dp),
        modifier = Modifier.padding(top = 2.dp).clickable { onReveal() },
    ) {
        Row(Modifier.padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.Visibility, contentDescription = null, modifier = Modifier.size(18.dp))
            Text(stringResource(R.string.live_chat_view_once_tap), style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(start = 8.dp))
        }
    }
}

@Composable
private fun VideoTile(msg: ChatMessage, onOpenVideo: (String) -> Unit) {
    Box(
        modifier = Modifier
            .padding(top = 2.dp)
            .widthIn(max = 220.dp)
            .aspectRatio(1.6f)
            .clip(RoundedCornerShape(10.dp))
            .clickable { msg.videoUrl?.let(onOpenVideo) },
        contentAlignment = Alignment.Center,
    ) {
        AsyncImage(
            model = msg.thumbnailUrl ?: msg.videoUrl,
            contentDescription = stringResource(R.string.live_chat_video_cd),
            contentScale = ContentScale.Crop,
            modifier = Modifier.fillMaxWidth(),
        )
        Icon(
            Icons.Filled.PlayCircle,
            contentDescription = stringResource(R.string.live_chat_video_cd),
            tint = Color.White,
            modifier = Modifier.size(44.dp),
        )
    }
}

@Composable
private fun ReplyPreviewBar(replyTo: ChatMessage, onCancel: () -> Unit) {
    Surface(color = MaterialTheme.colorScheme.surfaceVariant, modifier = Modifier.fillMaxWidth()) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(Icons.AutoMirrored.Filled.Reply, contentDescription = null, modifier = Modifier.size(18.dp))
            Column(Modifier.weight(1f).padding(start = 8.dp)) {
                Text(
                    text = stringResource(R.string.live_chat_replying_to, replyTo.senderDisplayName.ifBlank { stringResource(R.string.live_chat_you) }),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary,
                )
                Text(replyTo.text ?: "", style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            IconButton(onClick = onCancel) { Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.live_chat_cancel_reply)) }
        }
    }
}

@Composable
private fun ComposerOptionsBar(
    content: LiveChatUiState.Content,
    onOpenOptions: () -> Unit,
    onClearReply: () -> Unit,
) {
    val opt = content.options
    if (!opt.hasGating) return
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Icons.Filled.Tune, contentDescription = null, modifier = Modifier.size(14.dp), tint = MaterialTheme.colorScheme.primary)
        val parts = buildList {
            if (opt.viewOnce) add(stringResource(R.string.live_chat_badge_view_once))
            if (opt.lockPriceCents != null) add(stringResource(R.string.live_chat_opt_lock))
            if (opt.expiresInSeconds != null) add(stringResource(R.string.live_chat_badge_expiring))
            if (opt.sendAtEpochSeconds != null) add(stringResource(R.string.live_chat_badge_scheduled))
        }
        Text(
            text = parts.joinToString(" · "),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.weight(1f).padding(start = 6.dp).clickable { onOpenOptions() },
        )
    }
}

@Composable
private fun ChatComposer(
    text: String,
    canSend: Boolean,
    attaching: Boolean,
    onTextChange: (String) -> Unit,
    onSend: () -> Unit,
    onAttach: () -> Unit,
    onOptions: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onAttach, enabled = !attaching, modifier = Modifier.testTag(LiveChatTestTags.ATTACH)) {
            Icon(Icons.Filled.AddPhotoAlternate, contentDescription = stringResource(R.string.live_chat_attach_cd))
        }
        IconButton(onClick = onOptions, modifier = Modifier.testTag(LiveChatTestTags.OPTIONS)) {
            Icon(Icons.Filled.Tune, contentDescription = stringResource(R.string.live_chat_options_title))
        }
        OutlinedTextField(
            value = text,
            onValueChange = onTextChange,
            placeholder = { Text(stringResource(if (attaching) R.string.live_chat_uploading else R.string.live_chat_composer_hint)) },
            singleLine = true,
            enabled = !attaching,
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                imeAction = androidx.compose.ui.text.input.ImeAction.Send,
            ),
            keyboardActions = KeyboardActions(onSend = { if (canSend) onSend() }),
            modifier = Modifier.weight(1f).testTag(LiveChatTestTags.COMPOSER),
        )
        val sendCd = stringResource(R.string.live_chat_send_cd)
        IconButton(
            onClick = onSend,
            enabled = canSend,
            modifier = Modifier
                .testTag(LiveChatTestTags.SEND)
                .semantics { role = Role.Button; contentDescription = sendCd },
        ) {
            Icon(Icons.AutoMirrored.Filled.Send, contentDescription = sendCd)
        }
    }
}

@Composable
private fun ConnectionBanner(status: ConnectionStatus, onRetry: () -> Unit) {
    val (labelRes, clickable) = when (status) {
        ConnectionStatus.LIVE -> R.string.live_chat_connecting to false
        ConnectionStatus.RECONNECTING -> R.string.live_chat_reconnecting to false
        ConnectionStatus.OFFLINE -> R.string.live_chat_offline to true
    }
    val label = stringResource(labelRes)
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .then(if (clickable) Modifier.clickable { onRetry() } else Modifier)
            .padding(8.dp)
            .semantics { liveRegion = LiveRegionMode.Assertive }
            .testTag(LiveChatTestTags.BANNER),
        contentAlignment = Alignment.Center,
    ) {
        Text(text = label, style = MaterialTheme.typography.labelMedium)
    }
}

/** Resolves a (possibly server-relative) media url and opens it in the system player / browser. */
private fun openExternally(context: android.content.Context, url: String) {
    val abs = if (url.startsWith("/")) BuildConfig.API_BASE_URL.trimEnd('/') + url else url
    runCatching {
        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(abs)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
}
