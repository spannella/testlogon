@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.delegates.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.delegates.ManagedCreator
import com.testlogon.android.core.network.delegates.DelegatedBroadcastBanOut
import com.testlogon.android.core.network.delegates.DelegatedBroadcastModLogEntry
import com.testlogon.android.core.network.delegates.DelegatedBroadcastModeratorOut
import com.testlogon.android.core.network.delegates.DelegatedConversationOut
import com.testlogon.android.core.network.delegates.DelegatedPostOut

/** AND-360 - stable testTags for the delegate console demonstration screen. */
object DelegateConsoleTestTags {
    const val SCREEN = "delegate_console_screen"
    const val POST_INPUT = "delegate_console_post_input"
    const val POST_SUBMIT = "delegate_console_post_submit"
    const val MESSAGE_INPUT_PREFIX = "delegate_console_message_input_"
    const val MESSAGE_SUBMIT_PREFIX = "delegate_console_message_submit_"
    const val POST_ROW_PREFIX = "delegate_console_post_row_"
    const val CONVERSATION_ROW_PREFIX = "delegate_console_conversation_row_"
    // FULL-PARITY — open the full messaging thread/composer for this conversation (creator-attributed).
    const val CONVERSATION_OPEN_PREFIX = "delegate_console_conversation_open_"
    // T4 — managed-creators picker (shown when NOT in delegate mode).
    const val MANAGED_ROW_PREFIX = "delegate_console_managed_row_"
    const val MANAGED_ENTER_PREFIX = "delegate_console_managed_enter_"
    const val MANAGED_RETRY = "delegate_console_managed_retry"
    // AND-360 — broadcast moderation console section.
    const val MOD_SESSION_INPUT = "delegate_mod_session_input"
    const val MOD_LOAD = "delegate_mod_load"
    const val MOD_REGISTER = "delegate_mod_register"
    const val MOD_START = "delegate_mod_start"
    const val MOD_STOP = "delegate_mod_stop"
    const val MOD_ANNOUNCE_INPUT = "delegate_mod_announce_input"
    const val MOD_ANNOUNCE_SUBMIT = "delegate_mod_announce_submit"
    const val MOD_USER_INPUT = "delegate_mod_user_input"
    const val MOD_BAN = "delegate_mod_ban"
    const val MOD_MUTE = "delegate_mod_mute"
    const val MOD_MESSAGE_INPUT = "delegate_mod_message_input"
    const val MOD_PIN = "delegate_mod_pin"
    const val MOD_DELETE = "delegate_mod_delete"
    const val MOD_BAN_ROW_PREFIX = "delegate_mod_ban_row_"
    const val MOD_UNBAN_PREFIX = "delegate_mod_unban_"
    const val MOD_MODERATOR_ROW_PREFIX = "delegate_mod_moderator_row_"
    const val MOD_LOG_ROW_PREFIX = "delegate_mod_log_row_"
}

/**
 * AND-360 - route-level delegate console. Reachable from the More hub behind the managed-creator state. It
 * lists the managed creator's delegate feed posts + conversations and offers create-post / send-message
 * gated by feed_post / chat_respond, plus the broadcast MODERATION console (broadcast_moderate /
 * broadcast_control), with the persistent banner - proving "a delegate can act in delegated surfaces"
 * WITHOUT touching the mature feed / messaging screens.
 */
@Composable
fun DelegateConsoleRoute(
    onBack: () -> Unit,
    onOpenThread: (String) -> Unit = {},
    viewModel: DelegateConsoleViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    DelegateConsoleScreen(
        state = state,
        onBack = onBack,
        onExit = viewModel::exit,
        onCreatePost = viewModel::createPost,
        onSendMessage = viewModel::sendMessage,
        onNoticeShown = viewModel::consumeNotice,
        onEnterCreator = viewModel::enter,
        onRetryManaged = viewModel::loadManagedCreators,
        onOpenThread = onOpenThread,
        modActions = DelegateModActions(
            onSessionChange = viewModel::setModerationSession,
            onLoad = viewModel::loadModeration,
            onRegister = viewModel::registerAsModerator,
            onStart = viewModel::startBroadcast,
            onStop = viewModel::stopBroadcast,
            onAnnounce = viewModel::postAnnouncement,
            onBan = { userId, reason -> viewModel.banViewer(userId, reason) },
            onUnban = viewModel::unbanViewer,
            onMute = { userId, reason -> viewModel.muteViewer(userId, reason) },
            onPin = viewModel::pinMessage,
            onDelete = viewModel::deleteChatMessage,
        ),
    )
}

/** AND-360 - the moderation console callbacks bundled so the screen signature stays readable. */
data class DelegateModActions(
    val onSessionChange: (String) -> Unit = {},
    val onLoad: () -> Unit = {},
    val onRegister: () -> Unit = {},
    val onStart: () -> Unit = {},
    val onStop: () -> Unit = {},
    val onAnnounce: (String) -> Unit = {},
    val onBan: (userId: String, reason: String?) -> Unit = { _, _ -> },
    val onUnban: (String) -> Unit = {},
    val onMute: (userId: String, reason: String?) -> Unit = { _, _ -> },
    val onPin: (String) -> Unit = {},
    val onDelete: (String) -> Unit = {},
)

/** AND-360 - stateless delegate console screen. */
@Composable
fun DelegateConsoleScreen(
    state: DelegateConsoleUiState,
    onBack: () -> Unit,
    onExit: () -> Unit,
    onCreatePost: (String) -> Unit,
    onSendMessage: (conversationId: String, text: String) -> Unit,
    onNoticeShown: () -> Unit,
    onEnterCreator: (String) -> Unit = {},
    onRetryManaged: () -> Unit = {},
    onOpenThread: (String) -> Unit = {},
    modActions: DelegateModActions = DelegateModActions(),
) {
    val snackbarHostState = remember { SnackbarHostState() }
    val loadFailedMessage = stringResource(R.string.delegate_console_load_failed)
    val actionFailedMessage = stringResource(R.string.delegate_console_action_failed)

    LaunchedEffect(state.notice) {
        if (state.notice != null) {
            snackbarHostState.showSnackbar(actionFailedMessage)
            onNoticeShown()
        }
    }
    LaunchedEffect(state.loadFailed) {
        if (state.loadFailed) snackbarHostState.showSnackbar(loadFailedMessage)
    }

    Scaffold(
        modifier = Modifier.testTag(DelegateConsoleTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.delegate_console_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.delegate_console_back),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            if (state.active) {
                DelegationBanner(creatorName = state.creatorName, onExit = onExit)
            }
            if (!state.active) {
                ManagedCreatorsPicker(
                    state = state,
                    onEnterCreator = onEnterCreator,
                    onRetryManaged = onRetryManaged,
                )
            } else {
                DelegateConsoleContent(
                    state = state,
                    onCreatePost = onCreatePost,
                    onSendMessage = onSendMessage,
                    onOpenThread = onOpenThread,
                    modActions = modActions,
                )
            }
        }
    }
}

/**
 * T4 — the managed-creators picker shown when NOT in delegate mode. This is the fix for the dead-end: it
 * lists the creators the current user may act for and offers an "Enter" action per row that calls
 * [onEnterCreator] -> DelegationContextProvider.enter(creatorId), putting the app into delegate context.
 * Loading / error / empty states are all handled so the console is never a blank "you are not a delegate"
 * wall.
 */
@Composable
private fun ManagedCreatorsPicker(
    state: DelegateConsoleUiState,
    onEnterCreator: (String) -> Unit,
    onRetryManaged: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            stringResource(R.string.delegate_console_not_delegate_title),
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            stringResource(R.string.delegate_console_not_delegate_body),
            style = MaterialTheme.typography.bodyMedium,
        )

        when {
            state.managedLoading && state.managedCreators.isEmpty() -> {
                CircularProgressIndicator()
            }
            state.managedError && state.managedCreators.isEmpty() -> {
                Text(
                    stringResource(R.string.delegate_console_managed_error),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
                OutlinedButton(
                    onClick = onRetryManaged,
                    modifier = Modifier.testTag(DelegateConsoleTestTags.MANAGED_RETRY),
                ) {
                    Text(stringResource(R.string.delegate_console_managed_retry))
                }
            }
            state.managedCreators.isEmpty() -> {
                Text(
                    stringResource(R.string.delegate_console_managed_empty),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            else -> {
                Text(
                    stringResource(R.string.delegate_console_managed_heading),
                    style = MaterialTheme.typography.titleSmall,
                )
                LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(state.managedCreators, key = { it.creatorId }) { creator ->
                        ManagedCreatorRow(
                            creator = creator,
                            entering = state.entering == creator.creatorId,
                            enabled = state.entering == null,
                            onEnter = { onEnterCreator(creator.creatorId) },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ManagedCreatorRow(
    creator: ManagedCreator,
    entering: Boolean,
    enabled: Boolean,
    onEnter: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(DelegateConsoleTestTags.MANAGED_ROW_PREFIX + creator.creatorId),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                creator.label ?: creator.creatorId,
                style = MaterialTheme.typography.bodyLarge,
            )
            creator.status?.let { status ->
                Text(status, style = MaterialTheme.typography.labelSmall)
            }
        }
        if (entering) {
            CircularProgressIndicator(modifier = Modifier.size(24.dp))
        } else {
            Button(
                onClick = onEnter,
                enabled = enabled,
                modifier = Modifier.testTag(DelegateConsoleTestTags.MANAGED_ENTER_PREFIX + creator.creatorId),
            ) {
                Text(stringResource(R.string.delegate_console_managed_enter))
            }
        }
    }
}

@Composable
private fun DelegateConsoleContent(
    state: DelegateConsoleUiState,
    onCreatePost: (String) -> Unit,
    onSendMessage: (conversationId: String, text: String) -> Unit,
    onOpenThread: (String) -> Unit = {},
    modActions: DelegateModActions = DelegateModActions(),
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Text(
                stringResource(R.string.delegate_console_feed_heading),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(top = 12.dp),
            )
        }
        if (!state.canReadFeed) {
            item { Text(stringResource(R.string.delegate_console_no_feed_permission)) }
        } else {
            if (state.canPostFeed) {
                item { PostComposer(onCreatePost = onCreatePost) }
            }
            if (state.posts.isEmpty()) {
                item { Text(stringResource(R.string.delegate_console_feed_empty)) }
            } else {
                items(state.posts, key = { it.postId }) { post -> PostRow(post) }
            }
        }

        item { HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp)) }

        item {
            Text(
                stringResource(R.string.delegate_console_messages_heading),
                style = MaterialTheme.typography.titleMedium,
            )
        }
        if (!state.canReadChat) {
            item { Text(stringResource(R.string.delegate_console_no_chat_permission)) }
        } else if (state.conversations.isEmpty()) {
            item { Text(stringResource(R.string.delegate_console_messages_empty)) }
        } else {
            items(state.conversations, key = { it.conversationId }) { conversation ->
                ConversationRow(
                    conversation = conversation,
                    canRespond = state.canRespond,
                    onSendMessage = onSendMessage,
                    onOpenThread = onOpenThread,
                )
            }
        }

        // ---- AND-360 broadcast moderation console ----
        item { HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp)) }
        item {
            Text(
                stringResource(R.string.delegate_mod_heading),
                style = MaterialTheme.typography.titleMedium,
            )
        }
        moderationSection(state = state.moderation, actions = modActions)
    }
}

/**
 * AND-360 - the broadcast moderation console section (rendered inside the delegate console LazyColumn as
 * `items`). Gated by broadcast_moderate for the section + broadcast_control for start/stop. The reads
 * degrade-on-404 to empty in the repository, so an empty list = "nothing to show" not an error.
 */
private fun androidx.compose.foundation.lazy.LazyListScope.moderationSection(
    state: DelegateModConsoleState,
    actions: DelegateModActions,
) {
    if (!state.canModerate) {
        item { Text(stringResource(R.string.delegate_mod_no_permission)) }
        return
    }
    item { ModerationSessionBar(state = state, actions = actions) }
    if (state.canControl) {
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = actions.onStart,
                    enabled = !state.busy && state.sessionId.isNotBlank(),
                    modifier = Modifier.testTag(DelegateConsoleTestTags.MOD_START),
                ) { Text(stringResource(R.string.delegate_mod_start)) }
                OutlinedButton(
                    onClick = actions.onStop,
                    enabled = !state.busy && state.sessionId.isNotBlank(),
                    modifier = Modifier.testTag(DelegateConsoleTestTags.MOD_STOP),
                ) { Text(stringResource(R.string.delegate_mod_stop)) }
            }
        }
    }
    if (state.readFailed) {
        item {
            Text(
                stringResource(R.string.delegate_mod_read_failed),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
    item { ModerationActionBar(state = state, actions = actions) }

    // Moderators
    item {
        Text(
            stringResource(R.string.delegate_mod_moderators_heading),
            style = MaterialTheme.typography.titleSmall,
        )
    }
    if (state.moderators.isEmpty()) {
        item { Text(stringResource(R.string.delegate_mod_moderators_empty)) }
    } else {
        items(state.moderators, key = { it.delegateId }) { mod -> ModeratorRow(mod) }
    }

    // Bans
    item {
        Text(
            stringResource(R.string.delegate_mod_bans_heading),
            style = MaterialTheme.typography.titleSmall,
        )
    }
    if (state.bans.isEmpty()) {
        item { Text(stringResource(R.string.delegate_mod_bans_empty)) }
    } else {
        items(state.bans, key = { it.userId }) { ban ->
            BanRow(ban = ban, enabled = !state.busy, onUnban = { actions.onUnban(ban.userId) })
        }
    }

    // Log
    item {
        Text(
            stringResource(R.string.delegate_mod_log_heading),
            style = MaterialTheme.typography.titleSmall,
        )
    }
    if (state.log.isEmpty()) {
        item { Text(stringResource(R.string.delegate_mod_log_empty)) }
    } else {
        items(state.log, key = { it.eventId }) { entry -> LogRow(entry) }
    }
    item { HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp)) }
}

@Composable
private fun ModerationSessionBar(state: DelegateModConsoleState, actions: DelegateModActions) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedTextField(
            value = state.sessionId,
            onValueChange = actions.onSessionChange,
            placeholder = { Text(stringResource(R.string.delegate_mod_session_hint)) },
            modifier = Modifier.weight(1f).testTag(DelegateConsoleTestTags.MOD_SESSION_INPUT),
        )
        Button(
            onClick = actions.onLoad,
            enabled = state.sessionId.isNotBlank() && !state.loading,
            modifier = Modifier.testTag(DelegateConsoleTestTags.MOD_LOAD),
        ) { Text(stringResource(R.string.delegate_mod_load)) }
    }
    if (state.registered) {
        Text(
            stringResource(R.string.delegate_mod_registered),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.tertiary,
        )
    } else {
        OutlinedButton(
            onClick = actions.onRegister,
            enabled = state.sessionId.isNotBlank() && !state.busy,
            modifier = Modifier.testTag(DelegateConsoleTestTags.MOD_REGISTER),
        ) { Text(stringResource(R.string.delegate_mod_register)) }
    }
}

@Composable
private fun ModerationActionBar(state: DelegateModConsoleState, actions: DelegateModActions) {
    var announce by remember { mutableStateOf("") }
    var userId by remember { mutableStateOf("") }
    var messageId by remember { mutableStateOf("") }
    val enabled = !state.busy && state.sessionId.isNotBlank()
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        // Announcement
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = announce,
                onValueChange = { announce = it },
                placeholder = { Text(stringResource(R.string.delegate_mod_announce_hint)) },
                modifier = Modifier.weight(1f).testTag(DelegateConsoleTestTags.MOD_ANNOUNCE_INPUT),
            )
            Button(
                onClick = { actions.onAnnounce(announce); announce = "" },
                enabled = enabled && announce.isNotBlank(),
                modifier = Modifier.testTag(DelegateConsoleTestTags.MOD_ANNOUNCE_SUBMIT),
            ) { Text(stringResource(R.string.delegate_mod_announce)) }
        }
        // Viewer target: ban / mute
        OutlinedTextField(
            value = userId,
            onValueChange = { userId = it },
            placeholder = { Text(stringResource(R.string.delegate_mod_target_user_hint)) },
            modifier = Modifier.fillMaxWidth().testTag(DelegateConsoleTestTags.MOD_USER_INPUT),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = { actions.onBan(userId, null) },
                enabled = enabled && userId.isNotBlank(),
                modifier = Modifier.testTag(DelegateConsoleTestTags.MOD_BAN),
            ) { Text(stringResource(R.string.delegate_mod_ban)) }
            OutlinedButton(
                onClick = { actions.onMute(userId, null) },
                enabled = enabled && userId.isNotBlank(),
                modifier = Modifier.testTag(DelegateConsoleTestTags.MOD_MUTE),
            ) { Text(stringResource(R.string.delegate_mod_mute)) }
        }
        // Message target: pin / delete
        OutlinedTextField(
            value = messageId,
            onValueChange = { messageId = it },
            placeholder = { Text(stringResource(R.string.delegate_mod_target_message_hint)) },
            modifier = Modifier.fillMaxWidth().testTag(DelegateConsoleTestTags.MOD_MESSAGE_INPUT),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = { actions.onPin(messageId) },
                enabled = enabled && messageId.isNotBlank(),
                modifier = Modifier.testTag(DelegateConsoleTestTags.MOD_PIN),
            ) { Text(stringResource(R.string.delegate_mod_pin)) }
            OutlinedButton(
                onClick = { actions.onDelete(messageId) },
                enabled = enabled && messageId.isNotBlank(),
                modifier = Modifier.testTag(DelegateConsoleTestTags.MOD_DELETE),
            ) { Text(stringResource(R.string.delegate_mod_delete)) }
        }
    }
}

@Composable
private fun ModeratorRow(mod: DelegatedBroadcastModeratorOut) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(DelegateConsoleTestTags.MOD_MODERATOR_ROW_PREFIX + mod.delegateId),
    ) {
        Text(mod.displayName ?: mod.delegateId, style = MaterialTheme.typography.bodyMedium)
        mod.status?.let { Text(it, style = MaterialTheme.typography.labelSmall) }
    }
}

@Composable
private fun BanRow(ban: DelegatedBroadcastBanOut, enabled: Boolean, onUnban: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(DelegateConsoleTestTags.MOD_BAN_ROW_PREFIX + ban.userId),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(ban.userId, style = MaterialTheme.typography.bodyMedium)
            ban.reason?.let { Text(it, style = MaterialTheme.typography.labelSmall) }
        }
        OutlinedButton(
            onClick = onUnban,
            enabled = enabled,
            modifier = Modifier.testTag(DelegateConsoleTestTags.MOD_UNBAN_PREFIX + ban.userId),
        ) { Text(stringResource(R.string.delegate_mod_unban)) }
    }
}

@Composable
private fun LogRow(entry: DelegatedBroadcastModLogEntry) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(DelegateConsoleTestTags.MOD_LOG_ROW_PREFIX + entry.eventId),
    ) {
        Text(
            com.testlogon.android.core.model.delegates.DelegateModMath.moderationLabel(entry.moderationType),
            style = MaterialTheme.typography.bodyMedium,
        )
        val target = entry.targetUserId ?: entry.targetMessageId
        if (target != null) {
            Text(target, style = MaterialTheme.typography.labelSmall)
        }
    }
}

@Composable
private fun PostComposer(onCreatePost: (String) -> Unit) {
    var text by remember { mutableStateOf("") }
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            placeholder = { Text(stringResource(R.string.delegate_console_compose_post_hint)) },
            modifier = Modifier
                .weight(1f)
                .testTag(DelegateConsoleTestTags.POST_INPUT),
        )
        Button(
            onClick = {
                onCreatePost(text)
                text = ""
            },
            modifier = Modifier.testTag(DelegateConsoleTestTags.POST_SUBMIT),
        ) {
            Text(stringResource(R.string.delegate_console_post_action))
        }
    }
}

@Composable
private fun PostRow(post: DelegatedPostOut) {
    Column(modifier = Modifier.fillMaxWidth().testTag(DelegateConsoleTestTags.POST_ROW_PREFIX + post.postId)) {
        Text(post.text.orEmpty(), style = MaterialTheme.typography.bodyMedium)
        if (post.approvalStatus != null) {
            Text(
                stringResource(R.string.delegate_console_post_pending),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.tertiary,
            )
        }
    }
}

@Composable
private fun ConversationRow(
    conversation: DelegatedConversationOut,
    canRespond: Boolean,
    onSendMessage: (conversationId: String, text: String) -> Unit,
    onOpenThread: (String) -> Unit = {},
) {
    var text by remember(conversation.conversationId) { mutableStateOf("") }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onOpenThread(conversation.conversationId) }
            .testTag(DelegateConsoleTestTags.CONVERSATION_ROW_PREFIX + conversation.conversationId),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            conversation.title ?: conversation.conversationId,
            style = MaterialTheme.typography.bodyMedium,
        )
        conversation.lastMessagePreview?.let {
            Text(it, style = MaterialTheme.typography.bodySmall)
        }
        // FULL-PARITY: open the SAME full messaging thread/composer as normal messaging (image / video /
        // gallery / file / gating / scheduled / countdown / lottery / reactions / replies / edit). Every
        // send routes to the creator-attributed delegate endpoints while managing this creator.
        OutlinedButton(
            onClick = { onOpenThread(conversation.conversationId) },
            modifier = Modifier.testTag(
                DelegateConsoleTestTags.CONVERSATION_OPEN_PREFIX + conversation.conversationId,
            ),
        ) {
            Text(stringResource(R.string.delegate_console_open_conversation))
        }
        if (canRespond) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    placeholder = { Text(stringResource(R.string.delegate_console_compose_message_hint)) },
                    modifier = Modifier
                        .weight(1f)
                        .testTag(DelegateConsoleTestTags.MESSAGE_INPUT_PREFIX + conversation.conversationId),
                )
                Button(
                    onClick = {
                        onSendMessage(conversation.conversationId, text)
                        text = ""
                    },
                    modifier = Modifier.testTag(
                        DelegateConsoleTestTags.MESSAGE_SUBMIT_PREFIX + conversation.conversationId,
                    ),
                ) {
                    Text(stringResource(R.string.delegate_console_send_action))
                }
            }
        }
    }
}
