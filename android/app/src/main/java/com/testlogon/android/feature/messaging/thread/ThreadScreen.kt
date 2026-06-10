package com.testlogon.android.feature.messaging.thread

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.EmojiEmotions
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.Poll
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.messaging.MessageMedia
import com.testlogon.android.feature.messaging.media.FileMessageBubble
import com.testlogon.android.feature.messaging.media.FullScreenImageViewer
import com.testlogon.android.feature.messaging.media.InlineVideoPlayer
import com.testlogon.android.feature.messaging.media.openDownloadedFile
import com.testlogon.android.feature.messaging.media.rememberImageViewerState
import com.testlogon.android.feature.messaging.relativeTimeFromSeconds
import com.testlogon.android.feature.messaging.voice.RecordingOverlay
import com.testlogon.android.feature.messaging.voice.VoiceMessageBubble
import com.testlogon.android.feature.messaging.voice.VoicePreviewCard
import com.testlogon.android.feature.messaging.voice.VoiceTestTags
import kotlinx.coroutines.launch

/** Stable testTags for the thread screen (AND-123 / AND-124). */
object ThreadTestTags {
    const val SCREEN = "thread_screen"
    const val LIST = "thread_list"
    const val MESSAGE = "thread_message"
    const val OWN_MESSAGE = "thread_message_own"
    const val COMPOSER = "thread_composer"
    const val SEND = "thread_send"
    const val SCROLL_TO_BOTTOM = "thread_scroll_to_bottom"
    const val RETRY = "thread_retry"
    const val ATTACH_IMAGE = "thread_attach_image"
    const val ATTACH_FILE = "thread_attach_file"
    const val SHARE_VIDEO = "thread_share_video"
    const val IMAGE_BUBBLE = "thread_image_bubble"
    const val VIDEO_BUBBLE = "thread_video_bubble"
    const val VIDEO_PICKER = "thread_video_picker"

    // AND-140 / AND-141
    const val TOMBSTONE = "thread_tombstone"
    const val OPEN_PINS = "thread_open_pins"
    const val DISCARD_DRAFT = "thread_discard_draft"

    /** AND-158/159 — open group details/settings. */
    const val OPEN_GROUP_DETAILS = "thread_open_group_details"
}

/** AND-123 — route-level thread, reached from the conversation list. */
@Composable
fun ThreadRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    onOpenGroupDetails: () -> Unit = {},
    viewModel: ThreadViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    // AND-146 — remote typers in this conversation.
    val typingUsers by viewModel.typingUsers.collectAsStateWithLifecycle()
    // AND-151 — in-conversation search state.
    val searchUi by viewModel.searchState.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()
    val imageViewer = rememberImageViewerState()
    val context = LocalContext.current
    val snackbarHostState = remember { androidx.compose.material3.SnackbarHostState() }
    val routeScope = rememberCoroutineScope()
    val noCalendarAppMessage = stringResource(R.string.calendar_no_app)

    // AND-139 — surface the one-shot tip confirmation as a snackbar, then clear it.
    LaunchedEffect(state.transientMessage) {
        state.transientMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.onTransientMessageShown()
        }
    }

    // AND-140 — surface a one-shot action error (rollback feedback) as a snackbar, then clear it.
    LaunchedEffect(state.actions.transientError) {
        state.actions.transientError?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.onActionErrorShown()
        }
    }

    // AND-130 — system photo picker (no storage permission on any supported API level).
    val pickImage = rememberLauncherForActivityResult(
        ActivityResultContracts.PickVisualMedia(),
    ) { uri -> if (uri != null) viewModel.onImagePicked(uri) }

    // AND-132 — system document picker (OpenDocument, wildcard MIME; no storage permission needed).
    val pickFile = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) {
            // Take a (best-effort) persistable read grant for the duration of the upload.
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri, android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION,
                )
            }
            val info = resolveFileInfo(context, uri)
            viewModel.onFilePicked(uri, info.first, info.second, info.third)
        }
    }

    // AND-133 — RECORD_AUDIO runtime permission (requested at record time, API 23+).
    val requestMicPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) viewModel.onStartRecording() else viewModel.onPermissionDenied(permanently = false)
    }

    // AND-133 — observe the shared voice player so bubbles reflect play/pause + position.
    val voicePlayback by viewModel.voicePlayer.playback.collectAsStateWithLifecycle()

    // AND-125 — mark the conversation read on ON_START (in-session guard lives in the ViewModel).
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_START) viewModel.onThreadVisible()
            // AND-141 — flush the buffered draft immediately on ON_STOP (bypass debounce).
            // AND-146 — and send a final typing stop on leaving the screen.
            if (event == Lifecycle.Event.ON_STOP) {
                viewModel.flushDraft()
                viewModel.onScreenStopped()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is ThreadEvent.ScrollToBottom -> listState.animateScrollToItem(0)
                is ThreadEvent.OpenImageViewer -> imageViewer.open(event.url)
                is ThreadEvent.OpenFile -> openDownloadedFile(context, event.localPath, event.mimeType)
                is ThreadEvent.ScrollToMessage -> {
                    // AND-140 — jump-to-pinned: the list is reverseLayout, so map the key to its index.
                    val idx = state.messages.indexOfFirst { it.key == event.messageKey }
                    if (idx >= 0) listState.animateScrollToItem(state.messages.size - 1 - idx)
                }
            }
        }
    }

    // AND-151 — when the active search match changes, jump the thread to that message (reuses the
    // existing ScrollToMessage effect). The VM emits the scroll event keyed by message id.
    LaunchedEffect(searchUi.activeMatch?.messageId) {
        searchUi.activeMatch?.let { viewModel.onJumpToSearchMatch(it.messageId) }
    }

    // Reverse pagination: when the last (oldest) visible item nears the end, load older history.
    val shouldLoadOlder by remember {
        derivedStateOf {
            val total = listState.layoutInfo.totalItemsCount
            val lastVisible = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
            total > 0 && lastVisible >= total - 3
        }
    }
    LaunchedEffect(shouldLoadOlder, state.messages.size) {
        if (shouldLoadOlder) viewModel.loadOlder()
    }

    ThreadScreen(
        state = state,
        listState = listState,
        voicePlayback = voicePlayback,
        typingUsers = typingUsers,
        onBack = onBack,
        onOpenGroupDetails = onOpenGroupDetails,
        onRetry = viewModel::retry,
        onDraftChange = viewModel::onDraftChange,
        onSend = viewModel::onSend,
        onRetrySend = viewModel::onRetry,
        onAttachImage = {
            pickImage.launch(
                PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly),
            )
        },
        onAttachFile = { pickFile.launch(arrayOf("*/*")) },
        onShareVideo = viewModel::onOpenVideoPicker,
        onDismissVideoPicker = viewModel::onDismissVideoPicker,
        onPickVideo = viewModel::onShareVideo,
        onOpenImage = viewModel::onOpenImage,
        onDownloadFile = viewModel::onDownloadFile,
        onRecordVoice = {
            val granted = android.content.pm.PackageManager.PERMISSION_GRANTED ==
                androidx.core.content.ContextCompat.checkSelfPermission(
                    context, android.Manifest.permission.RECORD_AUDIO,
                )
            if (granted) viewModel.onStartRecording() else requestMicPermission.launch(android.Manifest.permission.RECORD_AUDIO)
        },
        onStopVoice = viewModel::onStopRecording,
        onCancelVoice = viewModel::onCancelRecording,
        onSendVoice = viewModel::onSendVoice,
        onToggleVoice = viewModel::onToggleVoice,
        onSeekVoice = viewModel::onSeekVoice,
        onOpenMediaPicker = viewModel::openMediaPicker,
        onCloseMediaPicker = viewModel::closeMediaPicker,
        onMediaTab = viewModel::selectMediaTab,
        onGifQuery = viewModel::onGifQueryChange,
        onGifSelect = viewModel::onGifSelected,
        onSelectCollection = viewModel::onSelectCollection,
        onStickerSelect = viewModel::onStickerSelected,
        onEmojiSelect = viewModel::onCustomEmojiSelected,
        onOpenPollComposer = viewModel::onOpenPollComposer,
        onDismissPollComposer = viewModel::onDismissPollComposer,
        onCreatePoll = viewModel::onCreatePoll,
        onPollVote = viewModel::onPollVote,
        onPollConfirm = viewModel::onPollConfirm,
        onAttachCountdown = viewModel::onOpenCountdownPicker,
        onDismissCountdownPicker = viewModel::onDismissCountdownPicker,
        onCountdownTitleChange = viewModel::onCountdownTitleChange,
        onCountdownTargetChange = viewModel::onCountdownTargetChange,
        onSendCountdown = viewModel::onSendCountdown,
        nowSeconds = System.currentTimeMillis() / 1000L,
        onUnlock = viewModel::onUnlockClick,
        onTip = viewModel::onTipOpen,
        onAddToCalendar = { event ->
            if (!launchAddToCalendar(context, event)) {
                routeScope.launch { snackbarHostState.showSnackbar(noCalendarAppMessage) }
            }
        },
        onTipPreset = viewModel::onTipPresetSelect,
        onTipCustomChange = viewModel::onTipCustomChange,
        onTipNoteChange = viewModel::onTipNoteChange,
        onTipConfirm = viewModel::onTipConfirm,
        onTipDismiss = viewModel::onTipDismiss,
        onAction = viewModel::onAction,
        onJumpToPinned = viewModel::onJumpToPinned,
        onDiscardDraft = viewModel::onDiscardDraft,
        searchActive = searchUi.active,
        onOpenSearch = viewModel::onOpenSearch,
        searchBar = {
            ThreadSearchBar(
                state = searchUi,
                onQueryChange = viewModel::onSearchQueryChange,
                onClose = viewModel::onCloseSearch,
                onNext = viewModel::onSearchNext,
                onPrev = viewModel::onSearchPrev,
            )
        },
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )

    // AND-130 — full-screen viewer overlay.
    imageViewer.url?.let { url ->
        FullScreenImageViewer(url = url, onClose = { imageViewer.close() })
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreadScreen(
    state: ThreadUiState,
    listState: androidx.compose.foundation.lazy.LazyListState,
    voicePlayback: com.testlogon.android.feature.messaging.voice.VoicePlaybackState,
    // AND-146 — remote typers shown above the composer.
    typingUsers: List<com.testlogon.android.feature.messaging.typing.TypingUiUser> = emptyList(),
    onBack: () -> Unit,
    // AND-158/159 — open the group details/settings surface from the thread top bar.
    onOpenGroupDetails: () -> Unit = {},
    onRetry: () -> Unit,
    onDraftChange: (String) -> Unit,
    onSend: () -> Unit,
    onRetrySend: (String) -> Unit,
    onAttachImage: () -> Unit,
    onAttachFile: () -> Unit,
    onShareVideo: () -> Unit,
    onDismissVideoPicker: () -> Unit,
    onPickVideo: (String) -> Unit,
    onOpenImage: (String) -> Unit,
    onDownloadFile: (ThreadMessageUi) -> Unit,
    onRecordVoice: () -> Unit,
    onStopVoice: () -> Unit,
    onCancelVoice: () -> Unit,
    onSendVoice: () -> Unit,
    onToggleVoice: (String, String?) -> Unit,
    onSeekVoice: (String, Float) -> Unit,
    onOpenMediaPicker: () -> Unit,
    onCloseMediaPicker: () -> Unit,
    onMediaTab: (MediaTab) -> Unit,
    onGifQuery: (String) -> Unit,
    onGifSelect: (com.testlogon.android.data.messaging.GifResult) -> Unit,
    onSelectCollection: (String) -> Unit,
    onStickerSelect: (String, String, String, String?) -> Unit,
    onEmojiSelect: (String) -> Unit,
    onOpenPollComposer: () -> Unit,
    onDismissPollComposer: () -> Unit,
    onCreatePoll: (com.testlogon.android.data.messaging.MeetingPollDraft) -> Unit,
    onPollVote: (String, String, com.testlogon.android.data.messaging.SlotVote?) -> Unit,
    onPollConfirm: (String, String) -> Unit,
    onAttachCountdown: () -> Unit,
    onDismissCountdownPicker: () -> Unit,
    onCountdownTitleChange: (String) -> Unit,
    onCountdownTargetChange: (Long?) -> Unit,
    onSendCountdown: () -> Unit,
    nowSeconds: Long,
    onUnlock: (String) -> Unit,
    onTip: (String) -> Unit,
    onAddToCalendar: (MessageMedia.CalendarEvent) -> Unit,
    onTipPreset: (Long) -> Unit,
    onTipCustomChange: (String) -> Unit,
    onTipNoteChange: (String) -> Unit,
    onTipConfirm: () -> Unit,
    onTipDismiss: () -> Unit,
    onAction: (ThreadAction) -> Unit = {},
    onJumpToPinned: (String) -> Unit = {},
    onDiscardDraft: () -> Unit = {},
    // AND-151 — in-conversation search: when [searchActive] the search bar replaces the app bar.
    searchActive: Boolean = false,
    onOpenSearch: () -> Unit = {},
    searchBar: @Composable () -> Unit = {},
    snackbarHostState: androidx.compose.material3.SnackbarHostState =
        remember { androidx.compose.material3.SnackbarHostState() },
    modifier: Modifier = Modifier,
) {
    // AND-140 — the message whose long-press action sheet is open (null = closed).
    var actionTarget by remember { mutableStateOf<ThreadMessageUi?>(null) }
    Scaffold(
        modifier = modifier.testTag(ThreadTestTags.SCREEN),
        snackbarHost = { androidx.compose.material3.SnackbarHost(snackbarHostState) },
        topBar = {
            if (searchActive) {
                searchBar()
            } else {
                TopAppBar(
                title = {
                    Text(
                        text = state.title.ifBlank { stringResource(R.string.thread_default_title) },
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    // AND-151 — open in-conversation search.
                    IconButton(
                        onClick = onOpenSearch,
                        modifier = Modifier.testTag(ThreadSearchTestTags.OPEN),
                    ) {
                        Icon(
                            Icons.Filled.Search,
                            contentDescription = stringResource(R.string.search_in_conversation),
                        )
                    }
                    // AND-158/159 — open group details (participants / settings).
                    IconButton(
                        onClick = onOpenGroupDetails,
                        modifier = Modifier.testTag(ThreadTestTags.OPEN_GROUP_DETAILS),
                    ) {
                        Icon(
                            Icons.Outlined.Info,
                            contentDescription = stringResource(R.string.group_details_cd),
                        )
                    }
                    // AND-140 — open the pinned-messages sheet.
                    IconButton(
                        onClick = { onAction(ThreadAction.OpenPinsList) },
                        modifier = Modifier.testTag(ThreadTestTags.OPEN_PINS),
                    ) {
                        Icon(
                            Icons.Filled.PushPin,
                            contentDescription = stringResource(R.string.msg_pins_title),
                        )
                    }
                    // AND-141 — discard the current draft (enabled only when a draft exists).
                    if (state.hasDraft) {
                        IconButton(
                            onClick = onDiscardDraft,
                            modifier = Modifier.testTag(ThreadTestTags.DISCARD_DRAFT),
                        ) {
                            Icon(
                                Icons.Filled.DeleteOutline,
                                contentDescription = stringResource(R.string.draft_discard),
                            )
                        }
                    }
                },
                )
            }
        },
        bottomBar = {
            // AND-133 — the composer swaps to the recording overlay / preview card while a voice
            // capture/preview is active; otherwise the normal text composer is shown.
            when (val voice = state.voice) {
                is VoiceComposerUiState.Recording -> RecordingOverlay(
                    elapsedMs = voice.elapsedMs,
                    peaks = voice.peaks,
                    countdownSeconds = voice.countdownSeconds,
                    onCancel = onCancelVoice,
                    onStop = onStopVoice,
                    modifier = Modifier.navigationBarsPadding().imePadding(),
                )
                is VoiceComposerUiState.Preview -> VoicePreviewCard(
                    durationMs = voice.durationMs,
                    peaks = voice.peaks,
                    onCancel = onCancelVoice,
                    onSend = onSendVoice,
                    modifier = Modifier.navigationBarsPadding().imePadding(),
                )
                else -> Column {
                    // AND-146 — typing indicator sits directly above the composer.
                    com.testlogon.android.feature.messaging.typing.TypingIndicator(users = typingUsers)
                    MessageComposer(
                        composer = state.composer,
                        onDraftChange = onDraftChange,
                        onSend = onSend,
                        onAttachImage = onAttachImage,
                        onAttachFile = onAttachFile,
                        onShareVideo = onShareVideo,
                        onRecordVoice = onRecordVoice,
                        onAttachMedia = onOpenMediaPicker,
                        onAttachPoll = onOpenPollComposer,
                        onAttachCountdown = onAttachCountdown,
                    )
                }
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.isLoadingInitial && state.messages.isEmpty() -> LoadingState()
                state.errorMessage != null && state.messages.isEmpty() ->
                    ErrorState(message = state.errorMessage, onRetry = onRetry)
                state.messages.isEmpty() ->
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text(
                            stringResource(R.string.thread_empty),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                else -> ThreadList(
                    state = state,
                    listState = listState,
                    voicePlayback = voicePlayback,
                    onRetrySend = onRetrySend,
                    onOpenImage = onOpenImage,
                    onDownloadFile = onDownloadFile,
                    onToggleVoice = onToggleVoice,
                    onSeekVoice = onSeekVoice,
                    onPollVote = onPollVote,
                    onPollConfirm = onPollConfirm,
                    onUnlock = onUnlock,
                    onTip = onTip,
                    onAddToCalendar = onAddToCalendar,
                    onAction = onAction,
                    onMessageLongPress = { actionTarget = it },
                )
            }
        }
    }

    // AND-140 — long-press action sheet + confirm dialogs + read sheets.
    MessageActionsHost(
        target = actionTarget,
        actions = state.actions,
        onAction = onAction,
        onTip = onTip,
        onJumpToPinned = onJumpToPinned,
        onCloseSheet = { actionTarget = null },
    )

    if (state.videoPicker.visible) {
        VideoPickerSheet(
            picker = state.videoPicker,
            onDismiss = onDismissVideoPicker,
            onPick = onPickVideo,
        )
    }

    if (state.mediaPicker.visible) {
        MediaPickerSheet(
            state = state.mediaPicker,
            onTab = onMediaTab,
            onGifQuery = onGifQuery,
            onGifSelect = onGifSelect,
            onSelectCollection = onSelectCollection,
            onStickerSelect = onStickerSelect,
            onEmojiSelect = onEmojiSelect,
            onDismiss = onCloseMediaPicker,
        )
    }

    if (state.pollComposerVisible) {
        MeetingPollComposerSheet(
            initialSlots = defaultPollSlots(),
            onSubmit = onCreatePoll,
            onDismiss = onDismissPollComposer,
        )
    }

    if (state.countdownPicker.visible) {
        CountdownPickerSheet(
            state = state.countdownPicker,
            nowSeconds = nowSeconds,
            onTitleChange = onCountdownTitleChange,
            onTargetChange = onCountdownTargetChange,
            onSend = onSendCountdown,
            onDismiss = onDismissCountdownPicker,
        )
    }

    if (state.tipSheet.messageId != null) {
        TipSheet(
            state = state.tipSheet,
            onPreset = onTipPreset,
            onCustomChange = onTipCustomChange,
            onNoteChange = onTipNoteChange,
            onConfirm = onTipConfirm,
            onDismiss = onTipDismiss,
        )
    }
}

/**
 * AND-136 — two sensible default candidate slots (tomorrow + the day after, 30-min windows) so the
 * composer opens valid (>=2 slots). ISO-8601 UTC; a fuller date/time picker is a follow-up.
 */
private fun defaultPollSlots(): List<com.testlogon.android.data.messaging.MeetingPollSlotDraft> {
    fun slot(daysAhead: Int, hour: Int): com.testlogon.android.data.messaging.MeetingPollSlotDraft {
        val dayMs = 24L * 60 * 60 * 1000
        val base = System.currentTimeMillis() + daysAhead * dayMs
        val cal = java.util.Calendar.getInstance(java.util.TimeZone.getTimeZone("UTC")).apply {
            timeInMillis = base
            set(java.util.Calendar.HOUR_OF_DAY, hour)
            set(java.util.Calendar.MINUTE, 0)
            set(java.util.Calendar.SECOND, 0)
            set(java.util.Calendar.MILLISECOND, 0)
        }
        val fmt = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", java.util.Locale.ROOT).apply {
            timeZone = java.util.TimeZone.getTimeZone("UTC")
        }
        val start = fmt.format(cal.time)
        cal.add(java.util.Calendar.MINUTE, 30)
        val end = fmt.format(cal.time)
        return com.testlogon.android.data.messaging.MeetingPollSlotDraft(start, end)
    }
    return listOf(slot(1, 15), slot(2, 21))
}

@Composable
private fun ThreadList(
    state: ThreadUiState,
    listState: androidx.compose.foundation.lazy.LazyListState,
    voicePlayback: com.testlogon.android.feature.messaging.voice.VoicePlaybackState,
    onRetrySend: (String) -> Unit,
    onOpenImage: (String) -> Unit,
    onDownloadFile: (ThreadMessageUi) -> Unit,
    onToggleVoice: (String, String?) -> Unit,
    onSeekVoice: (String, Float) -> Unit,
    onPollVote: (String, String, com.testlogon.android.data.messaging.SlotVote?) -> Unit,
    onPollConfirm: (String, String) -> Unit,
    onUnlock: (String) -> Unit,
    onTip: (String) -> Unit,
    onAddToCalendar: (MessageMedia.CalendarEvent) -> Unit,
    onAction: (ThreadAction) -> Unit,
    onMessageLongPress: (ThreadMessageUi) -> Unit,
) {
    // reverseLayout: index 0 is the newest message at the visual bottom.
    val reversed = remember(state.messages) { state.messages.asReversed() }
    val scope = rememberCoroutineScope()
    val showFab by remember {
        derivedStateOf { listState.firstVisibleItemIndex > 2 }
    }

    Box(Modifier.fillMaxSize()) {
        LazyColumn(
            state = listState,
            reverseLayout = true,
            modifier = Modifier.fillMaxSize().testTag(ThreadTestTags.LIST),
        ) {
            items(reversed, key = { it.key }) { message ->
                MessageBubble(
                    message = message,
                    download = state.downloads[message.key] ?: FileDownloadUi.NotDownloaded,
                    voicePlayback = voicePlayback,
                    polls = state.polls,
                    unlock = state.unlocks[message.key] ?: UnlockUiState(),
                    onRetry = { onRetrySend(message.key) },
                    onOpenImage = onOpenImage,
                    onDownloadFile = { onDownloadFile(message) },
                    onToggleVoice = onToggleVoice,
                    onSeekVoice = onSeekVoice,
                    onPollVote = onPollVote,
                    onPollConfirm = onPollConfirm,
                    onUnlock = { onUnlock(message.key) },
                    onTip = { onTip(message.key) },
                    onAddToCalendar = onAddToCalendar,
                    onLongPress = { onMessageLongPress(message) },
                    onToggleReaction = { emoji -> onAction(ThreadAction.ToggleReaction(message.key, emoji)) },
                    onSeeWhoReacted = { onAction(ThreadAction.OpenReactionDetails(message.key)) },
                    onOpenEditHistory = { onAction(ThreadAction.OpenEditHistory(message.key)) },
                )
            }
            if (state.isLoadingOlder) {
                item {
                    Box(
                        Modifier.fillMaxWidth().padding(16.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp))
                    }
                }
            }
        }
        if (showFab) {
            FloatingActionButton(
                onClick = { scope.launch { listState.animateScrollToItem(0) } },
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(16.dp)
                    .testTag(ThreadTestTags.SCROLL_TO_BOTTOM),
            ) {
                Icon(
                    Icons.Filled.ArrowDownward,
                    contentDescription = stringResource(R.string.thread_scroll_to_latest),
                )
            }
        }
    }
}

@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
private fun MessageBubble(
    message: ThreadMessageUi,
    download: FileDownloadUi,
    voicePlayback: com.testlogon.android.feature.messaging.voice.VoicePlaybackState,
    polls: Map<String, MeetingPollCardUiState>,
    unlock: UnlockUiState,
    onRetry: () -> Unit,
    onOpenImage: (String) -> Unit,
    onDownloadFile: () -> Unit,
    onToggleVoice: (String, String?) -> Unit,
    onSeekVoice: (String, Float) -> Unit,
    onPollVote: (String, String, com.testlogon.android.data.messaging.SlotVote?) -> Unit,
    onPollConfirm: (String, String) -> Unit,
    onUnlock: () -> Unit,
    onTip: () -> Unit,
    onAddToCalendar: (MessageMedia.CalendarEvent) -> Unit,
    onLongPress: () -> Unit = {},
    onToggleReaction: (String) -> Unit = {},
    onSeeWhoReacted: () -> Unit = {},
    onOpenEditHistory: () -> Unit = {},
) {
    val alignment = if (message.isOwn) Alignment.End else Alignment.Start
    val bubbleColor = if (message.isOwn) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }
    val relative = remember(message.createdAtEpochSeconds) {
        relativeTimeFromSeconds(message.createdAtEpochSeconds)
    }
    val stateDesc = when {
        message.isFailed -> "Failed to send"
        message.isSending -> "Sending"
        else -> "Sent"
    }
    val tag = if (message.isOwn) ThreadTestTags.OWN_MESSAGE else ThreadTestTags.MESSAGE

    // AND-140 — a revoked/deleted message renders a tombstone bubble and offers no further actions.
    if (message.isTombstone) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp),
            horizontalAlignment = alignment,
        ) {
            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier.widthIn(max = 280.dp).testTag(ThreadTestTags.TOMBSTONE),
            ) {
                Text(
                    text = tombstoneLabel(message),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                )
            }
        }
        return
    }

    // AND-140 — long-press any message to open the action sheet (reactions / pin / edit / etc.).
    val pressModifier = Modifier.combinedClickable(onClick = {}, onLongClick = onLongPress)
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp)
            .then(pressModifier),
        horizontalAlignment = alignment,
    ) {
        if (message.isPinned) {
            Text(
                text = stringResource(R.string.msg_pinned_indicator),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.semantics { stateDescription = "Pinned" },
            )
        }
        when (val media = message.media) {
            is MessageMedia.Image -> ImageBubble(media = media, onOpenImage = onOpenImage)
            is MessageMedia.VideoShare -> VideoBubble(media = media)
            is MessageMedia.File -> FileMessageBubble(
                file = media,
                download = download,
                isOwn = message.isOwn,
                onDownload = onDownloadFile,
            )
            is MessageMedia.Voice -> VoiceMessageBubble(
                voice = media,
                isOwn = message.isOwn,
                playing = voicePlayback.activeMessageId == message.key && voicePlayback.playing,
                positionMs = if (voicePlayback.activeMessageId == message.key) voicePlayback.positionMs else 0L,
                onTogglePlay = { onToggleVoice(message.key, media.audioUrl ?: media.localUri) },
                onSeek = { f -> onSeekVoice(message.key, f) },
            )
            is MessageMedia.Voicemail -> VoicemailBubble(
                media = media,
                isOwn = message.isOwn,
                onPlay = { onToggleVoice(message.key, media.mediaUrl ?: media.localUri) },
            )
            is MessageMedia.Gif -> GifBubble(media = media)
            is MessageMedia.Sticker -> StickerBubble(media = media)
            is MessageMedia.Countdown -> CountdownBubble(media = media, isOwn = message.isOwn)
            is MessageMedia.CalendarEvent -> CalendarEventBubble(
                media = media,
                isOwn = message.isOwn,
                onAddToCalendar = { onAddToCalendar(media) },
            )
            is MessageMedia.CalendarShare -> CalendarShareBubble(media = media, isOwn = message.isOwn)
            is MessageMedia.Paid -> PaidMessageBubble(
                monetization = media.monetization,
                isOwn = message.isOwn,
                unlock = unlock,
                onUnlock = onUnlock,
            )
            is MessageMedia.MeetingPoll -> {
                val pollState = polls[media.pollId]
                if (pollState != null) {
                    MeetingPollCard(
                        state = pollState,
                        onVote = { slotId, vote -> onPollVote(media.pollId, slotId, vote) },
                        onConfirm = { slotId -> onPollConfirm(media.pollId, slotId) },
                    )
                } else {
                    Surface(
                        color = bubbleColor,
                        shape = MaterialTheme.shapes.medium,
                        modifier = Modifier.widthIn(max = 280.dp),
                    ) {
                        Text(
                            text = media.title.ifBlank { stringResource(R.string.poll_label) },
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                        )
                    }
                }
            }
            MessageMedia.None -> Surface(
                color = bubbleColor,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier
                    .widthIn(max = 280.dp)
                    .testTag(tag)
                    .semantics { stateDescription = stateDesc },
            ) {
                Text(
                    text = message.text,
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                )
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (message.isFailed) {
                IconButton(
                    onClick = onRetry,
                    modifier = Modifier
                        .size(28.dp)
                        .testTag(ThreadTestTags.RETRY)
                        .semantics { contentDescription = "Retry sending message" },
                ) {
                    Icon(
                        Icons.Filled.ErrorOutline,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(16.dp),
                    )
                }
                Text(
                    text = stringResource(R.string.thread_send_failed),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.error,
                )
            } else {
                Text(
                    text = if (message.isSending) stringResource(R.string.thread_sending) else relative,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            // AND-140 — "edited" marker; tapping opens the edit-history sheet.
            if (message.isEdited) {
                Text(
                    text = "  ${stringResource(R.string.msg_edited_label)}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.combinedClickable(onClick = onOpenEditHistory, onLongClick = {})
                        .semantics { contentDescription = "Edited; open edit history" },
                )
            }
        }
        // AND-140 — under-bubble reaction chip row.
        ReactionChipsRow(
            reactions = message.reactions,
            onToggle = onToggleReaction,
            onSeeWhoReacted = onSeeWhoReacted,
        )
    }
}

/** AND-130 — image bubble: optimistic local thumbnail + progress, else remote Coil image. */
@Composable
private fun ImageBubble(media: MessageMedia.Image, onOpenImage: (String) -> Unit) {
    val display = media.url ?: media.localUri
    val cd = stringResource(R.string.thread_image_cd)
    Box(
        modifier = Modifier
            .width(220.dp)
            .aspectRatio(if ((media.width ?: 0) > 0 && (media.height ?: 0) > 0) {
                media.width!!.toFloat() / media.height!!.toFloat()
            } else {
                1f
            })
            .clip(RoundedCornerShape(12.dp))
            .testTag(ThreadTestTags.IMAGE_BUBBLE)
            .clickable(enabled = media.url != null) { media.url?.let(onOpenImage) }
            .semantics { contentDescription = cd },
        contentAlignment = Alignment.Center,
    ) {
        AsyncImage(
            model = display,
            contentDescription = cd,
            contentScale = ContentScale.Crop,
            modifier = Modifier.fillMaxSize(),
        )
        val progress = media.uploadProgress
        if (progress != null && media.url == null) {
            Box(
                Modifier.fillMaxSize().semantics { stateDescription = "Sending image" },
                contentAlignment = Alignment.Center,
            ) {
                CircularProgressIndicator(
                    progress = { progress },
                    color = Color.White,
                    modifier = Modifier.size(36.dp),
                )
            }
        }
    }
}

/** AND-131 — video bubble: inline HLS player (poster -> play -> in-bubble playback). */
@Composable
private fun VideoBubble(media: MessageMedia.VideoShare) {
    InlineVideoPlayer(
        video = media,
        modifier = Modifier
            .width(240.dp)
            .clip(RoundedCornerShape(12.dp))
            .testTag(ThreadTestTags.VIDEO_BUBBLE),
    )
}

/** AND-131 — bottom-sheet picker listing the user's published videos to share. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun VideoPickerSheet(
    picker: VideoPickerState,
    onDismiss: () -> Unit,
    onPick: (String) -> Unit,
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(ThreadTestTags.VIDEO_PICKER),
    ) {
        Column(
            Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(16.dp),
        ) {
            Text(
                stringResource(R.string.video_picker_title),
                style = MaterialTheme.typography.titleMedium,
            )
            when {
                picker.loading -> Box(
                    Modifier.fillMaxWidth().padding(24.dp),
                    contentAlignment = Alignment.Center,
                ) { CircularProgressIndicator() }
                picker.errorMessage != null -> Text(
                    picker.errorMessage,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(vertical = 16.dp),
                )
                picker.videos.isEmpty() -> Text(
                    stringResource(R.string.video_picker_empty),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 16.dp),
                )
                else -> LazyColumn(Modifier.fillMaxWidth()) {
                    items(picker.videos, key = { it.videoId }) { v ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onPick(v.videoId) }
                                .padding(vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            AsyncImage(
                                model = v.thumbnailUrl,
                                contentDescription = stringResource(R.string.video_thumbnail_cd),
                                contentScale = ContentScale.Crop,
                                modifier = Modifier
                                    .width(64.dp)
                                    .aspectRatio(16f / 9f)
                                    .clip(RoundedCornerShape(6.dp)),
                            )
                            Text(
                                v.title,
                                style = MaterialTheme.typography.bodyLarge,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.padding(start = 12.dp).weight(1f),
                            )
                        }
                    }
                }
            }
        }
    }
}

/**
 * AND-132 — resolve (displayName, sizeBytes, mimeType) for a picked content uri via the
 * ContentResolver. Returns sensible fallbacks when the provider omits columns. Not @Composable.
 */
private fun resolveFileInfo(
    context: android.content.Context,
    uri: android.net.Uri,
): Triple<String, Long, String> {
    var name = "file"
    var size = 0L
    runCatching {
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val nameIdx = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            val sizeIdx = cursor.getColumnIndex(android.provider.OpenableColumns.SIZE)
            if (cursor.moveToFirst()) {
                if (nameIdx >= 0 && !cursor.isNull(nameIdx)) name = cursor.getString(nameIdx)
                if (sizeIdx >= 0 && !cursor.isNull(sizeIdx)) size = cursor.getLong(sizeIdx)
            }
        }
    }
    val mime = context.contentResolver.getType(uri) ?: "application/octet-stream"
    return Triple(name, size, mime)
}

@Composable
private fun MessageComposer(
    composer: ComposerState,
    onDraftChange: (String) -> Unit,
    onSend: () -> Unit,
    onAttachImage: () -> Unit,
    onAttachFile: () -> Unit,
    onShareVideo: () -> Unit,
    onRecordVoice: () -> Unit,
    onAttachMedia: () -> Unit,
    onAttachPoll: () -> Unit,
    onAttachCountdown: () -> Unit,
) {
    Surface(tonalElevation = 2.dp) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .imePadding()
                .navigationBarsPadding()
                .padding(horizontal = 4.dp, vertical = 8.dp)
                .testTag(ThreadTestTags.COMPOSER),
            verticalAlignment = Alignment.Bottom,
        ) {
            IconButton(
                onClick = onAttachImage,
                modifier = Modifier.size(44.dp).testTag(ThreadTestTags.ATTACH_IMAGE),
            ) {
                Icon(
                    Icons.Filled.Image,
                    contentDescription = stringResource(R.string.thread_attach_image),
                    tint = MaterialTheme.colorScheme.primary,
                )
            }
            IconButton(
                onClick = onAttachFile,
                modifier = Modifier.size(44.dp).testTag(ThreadTestTags.ATTACH_FILE),
            ) {
                Icon(
                    Icons.Filled.AttachFile,
                    contentDescription = stringResource(R.string.thread_attach_file),
                    tint = MaterialTheme.colorScheme.primary,
                )
            }
            IconButton(
                onClick = onShareVideo,
                modifier = Modifier.size(44.dp).testTag(ThreadTestTags.SHARE_VIDEO),
            ) {
                Icon(
                    Icons.Filled.Videocam,
                    contentDescription = stringResource(R.string.thread_share_video),
                    tint = MaterialTheme.colorScheme.primary,
                )
            }
            IconButton(
                onClick = onRecordVoice,
                modifier = Modifier.size(44.dp).testTag(VoiceTestTags.RECORD),
            ) {
                Icon(
                    Icons.Filled.Mic,
                    contentDescription = stringResource(R.string.thread_record_voice),
                    tint = MaterialTheme.colorScheme.primary,
                )
            }
            IconButton(
                onClick = onAttachMedia,
                modifier = Modifier.size(44.dp).testTag(RichMessageTestTags.ATTACH_MEDIA),
            ) {
                Icon(
                    Icons.Filled.EmojiEmotions,
                    contentDescription = stringResource(R.string.composer_add_media),
                    tint = MaterialTheme.colorScheme.primary,
                )
            }
            IconButton(
                onClick = onAttachPoll,
                modifier = Modifier.size(44.dp).testTag(RichMessageTestTags.ATTACH_POLL),
            ) {
                Icon(
                    Icons.Filled.Poll,
                    contentDescription = stringResource(R.string.composer_add_poll),
                    tint = MaterialTheme.colorScheme.primary,
                )
            }
            IconButton(
                onClick = onAttachCountdown,
                modifier = Modifier.size(44.dp).testTag(PaidMessageTestTags.COUNTDOWN_BUBBLE + "_attach"),
            ) {
                Icon(
                    Icons.Filled.Timer,
                    contentDescription = stringResource(R.string.composer_add_countdown),
                    tint = MaterialTheme.colorScheme.primary,
                )
            }
            OutlinedTextField(
                value = composer.draft,
                onValueChange = onDraftChange,
                modifier = Modifier.weight(1f),
                placeholder = { Text(stringResource(R.string.thread_composer_hint)) },
                isError = composer.overLimit,
                maxLines = 5,
                supportingText = if (composer.overLimit) {
                    { Text(stringResource(R.string.thread_composer_over_limit)) }
                } else {
                    null
                },
            )
            IconButton(
                onClick = onSend,
                enabled = composer.isSendEnabled,
                modifier = Modifier
                    .padding(start = 4.dp)
                    .size(48.dp)
                    .testTag(ThreadTestTags.SEND),
            ) {
                Icon(
                    Icons.AutoMirrored.Filled.Send,
                    contentDescription = stringResource(R.string.thread_send),
                    tint = if (composer.isSendEnabled) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)
                    },
                )
            }
        }
    }
}
