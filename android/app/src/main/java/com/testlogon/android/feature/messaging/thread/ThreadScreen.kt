@file:OptIn(
    androidx.compose.ui.ExperimentalComposeUiApi::class,
    androidx.compose.foundation.layout.ExperimentalLayoutApi::class,
)
package com.testlogon.android.feature.messaging.thread

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.isImeVisible
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.ui.input.pointer.changedToUpIgnoreConsumed
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.CalendarMonth
import androidx.compose.material.icons.filled.Casino
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.EditCalendar
import androidx.compose.material.icons.filled.Event
import androidx.compose.material.icons.filled.FolderShared
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.DoneAll
import androidx.compose.material.icons.filled.EmojiEmotions
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Movie
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.GraphicEq
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.PlayCircle
import androidx.compose.material.icons.filled.Poll
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material.icons.filled.PermMedia
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Switch
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.TextButton
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
import com.testlogon.android.feature.messaging.media.VideoClipBubble
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

    /** #8 — scheduled-messages manager. */
    const val OPEN_SCHEDULED = "thread_open_scheduled"
    const val SCHEDULED_SHEET = "thread_scheduled_sheet"
    const val SCHEDULED_ITEM = "thread_scheduled_item"
    const val SCHEDULED_EDIT = "thread_scheduled_edit"
    const val SCHEDULED_REMOVE = "thread_scheduled_remove"
    const val SCHEDULED_EDIT_SAVE = "thread_scheduled_edit_save"

    /** AND-158/159 — open group details/settings. */
    const val OPEN_GROUP_DETAILS = "thread_open_group_details"

    /** #19 — the single "+" that opens the conversation-actions dropdown menu. */
    const val TOPBAR_MENU = "thread_topbar_menu"
}

/** AND-123 — route-level thread, reached from the conversation list. */
@Composable
fun ThreadRoute(
    onBack: () -> Unit,
    onPlaceCall: (String) -> Unit = {},
    modifier: Modifier = Modifier,
    onOpenGroupDetails: () -> Unit = {},
    viewModel: ThreadViewModel = hiltViewModel(),
    reportViewModel: com.testlogon.android.feature.messaging.report.ReportViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    // AND-163 — report sheet state (owned by the separate ReportViewModel/ReportSheet).
    val reportState by reportViewModel.uiState.collectAsStateWithLifecycle()
    val reportConfirmation = stringResource(R.string.report_confirmation)
    // AND-146 — remote typers in this conversation.
    val typingUsers by viewModel.typingUsers.collectAsStateWithLifecycle()
    // AND-151 — in-conversation search state.
    val searchUi by viewModel.searchState.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()
    val imageViewer = rememberImageViewerState()
    val context = LocalContext.current
    val keyboardController = androidx.compose.ui.platform.LocalSoftwareKeyboardController.current
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

    // #25/#27/#28 — ONE unified media picker (no storage permission). Accepts BOTH images and videos in
    // a single PickMultipleVisualMedia(ImageAndVideo) flow and STAGES every pick (a photo+video MIX, and
    // multiple videos, are allowed) MERGED with anything already staged, so reopening the picker and
    // selecting more ADDS to the selection rather than wiping it (the system picker can't pre-select).
    val pickMedia = rememberLauncherForActivityResult(
        ActivityResultContracts.PickMultipleVisualMedia(20),
    ) { uris ->
        if (uris.isEmpty()) return@rememberLauncherForActivityResult
        val items = uris.map { uri ->
            val isVideo = context.contentResolver.getType(uri)?.startsWith("video/") == true
            uri.toString() to isVideo
        }
        viewModel.onMediaPicked(items)
    }

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
                is ThreadEvent.Toast ->
                    android.widget.Toast.makeText(context, event.message, android.widget.Toast.LENGTH_SHORT).show()
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
        onPlaceCall = onPlaceCall,
        onOpenGroupDetails = onOpenGroupDetails,
        onRetry = viewModel::retry,
        onDraftChange = viewModel::onDraftChange,
        onSend = viewModel::onSend,
        onRetrySend = viewModel::onRetry,
        onAttachImage = {
            // MV1 — single attach action for BOTH photos and short videos.
            pickMedia.launch(
                PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageAndVideo),
            )
        },
        onAttachFile = { pickFile.launch(arrayOf("*/*")) },
        onShareVideo = viewModel::onOpenVideoPicker,
        onDismissVideoPicker = viewModel::onDismissVideoPicker,
        onPickVideo = viewModel::onShareVideo,
        onOpenImage = viewModel::onOpenImage,
        onDownloadFile = viewModel::onDownloadFile,
        onSaveFile = viewModel::onSaveFileToPhone,
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
        onCountdownTimeZoneChange = viewModel::onCountdownTimeZoneChange,
        onCountdownRevealTextChange = viewModel::onCountdownRevealTextChange,
        onCountdownPickRevealImage = viewModel::onCountdownPickRevealImage,
        onCountdownRemoveRevealImage = viewModel::onCountdownRemoveRevealImage,
        onSendCountdown = viewModel::onSendCountdown,
        onAttachCountdownToMessage = viewModel::onAttachCountdownToMessage,
        onAttachLottery = viewModel::onAttachLottery,
        onDismissLottery = viewModel::onDismissLotteryComposer,
        onSendLottery = { outcomes, imageUri, coverText -> viewModel.onSendLottery(outcomes, imageUri, coverText) },
        onAttachFindDateTime = viewModel::onAttachFindDateTime,
        onDismissFindDateTime = viewModel::onDismissFindDateTimeComposer,
        onSendFindDateTime = viewModel::onSendFindDateTime,
        onAttachCalendarEvent = viewModel::onAttachCalendarEvent,
        onDismissCalendarEvent = viewModel::onDismissCalendarEventComposer,
        onSelectCalendarForEvent = viewModel::onSelectCalendarForEvent,
        onSendCalendarEvent = viewModel::onSendCalendarEvent,
        onAttachCalendarShare = viewModel::onAttachCalendarShare,
        onDismissCalendarShare = viewModel::onDismissCalendarShareComposer,
        onSelectCalendarForShare = viewModel::onSelectCalendarForShare,
        onSendCalendarShare = viewModel::onSendCalendarShare,
        onAttachFileShare = viewModel::onAttachFileShare,
        onDismissFileShare = viewModel::onDismissFileShareComposer,
        onSendFileShare = viewModel::onSendFileShare,
        onOpenMessageOptions = viewModel::openMessageOptions,
        onClearMessageOptions = viewModel::clearMessageOptions,
        onRemoveStagedImage = viewModel::onRemoveStagedImage,
        onRemoveStagedVideo = viewModel::onRemoveStagedVideo,
        onRemoveStagedFile = viewModel::onRemoveStagedFile,
        nowSeconds = rememberNowTicker(),
        onUnlock = viewModel::onUnlockClick,
        onTip = viewModel::onTipOpen,
        onOpenEncrypted = viewModel::openEncryptUnlock,
        onOpenViewOnce = viewModel::openViewOnce,
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
        onAction = { action ->
            // AND-163 — intercept Report to open the dedicated report sheet; everything else to the VM.
            if (action is ThreadAction.Report) {
                reportViewModel.open(state.conversationId, action.messageId)
            } else {
                viewModel.onAction(action)
            }
        },
        onJumpToPinned = viewModel::onJumpToPinned,
        onJumpToMessage = viewModel::onJumpToMessage,
        onDiscardDraft = viewModel::onDiscardDraft,
        searchActive = searchUi.active,
        onOpenSearch = viewModel::onOpenSearch,
        onOpenScheduled = viewModel::openScheduledManager,
        searchBar = {
            ThreadSearchBar(
                state = searchUi,
                onQueryChange = viewModel::onSearchQueryChange,
                onClose = viewModel::onCloseSearch,
                onNext = viewModel::onSearchNext,
                onPrev = viewModel::onSearchPrev,
                onPickMatch = { match ->
                    // #17 — jump the thread to the tapped result (the activeMatch effect scrolls there).
                    keyboardController?.hide()
                    viewModel.onSelectSearchMatch(match.messageId)
                },
            )
        },
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )

    // AND-130 — full-screen viewer overlay.
    imageViewer.url?.let { url ->
        FullScreenImageViewer(url = url, onClose = { imageViewer.close() })
    }

    // AND-163 — report sheet + one-shot confirmation snackbar.
    com.testlogon.android.feature.messaging.report.ReportSheet(
        state = reportState,
        onReason = reportViewModel::onReasonSelected,
        onStatement = reportViewModel::onStatementChanged,
        onSubmit = reportViewModel::submit,
        onDismiss = reportViewModel::dismiss,
    )
    LaunchedEffect(Unit) {
        reportViewModel.events.collect { event ->
            when (event) {
                com.testlogon.android.feature.messaging.report.ReportEvent.Submitted ->
                    snackbarHostState.showSnackbar(reportConfirmation)
            }
        }
    }

    // Send-options sheet: view-once / locked / scheduled for the next message.
    if (state.messageOptionsVisible) {
        MessageOptionsSheet(
            options = state.composer.options,
            nowSeconds = rememberNowTicker(),
            onViewOnceChange = viewModel::setViewOnce,
            onLockPriceChange = viewModel::setLockPrice,
            onScheduleChange = viewModel::setScheduledAt,
            onScheduleTzChange = viewModel::setScheduledTimeZone,
            onExpiresChange = viewModel::setExpiresIn,
            onEncryptedChange = viewModel::setEncrypted,
            onPassphraseChange = viewModel::setEncryptionPassphrase,
            onDismiss = viewModel::closeMessageOptions,
        )
    }

    // MSG — receiver passphrase-unlock dialog for an encrypted message.
    val enc = state.encryptUnlock
    if (enc.messageKey != null) {
        AlertDialog(
            onDismissRequest = viewModel::dismissEncryptUnlock,
            title = { Text("Unlock encrypted message") },
            text = {
                Column {
                    Text("Enter the passphrase the sender shared with you.")
                    OutlinedTextField(
                        value = enc.passphrase,
                        onValueChange = viewModel::onEncryptPassphraseChange,
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp).testTag("thread_unlock_passphrase"),
                        label = { Text("Passphrase") },
                        singleLine = true,
                        visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                        isError = enc.error != null,
                    )
                    enc.error?.let {
                        Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = viewModel::submitEncryptUnlock, modifier = Modifier.testTag("thread_unlock_confirm")) { Text("Unlock") }
            },
            dismissButton = { TextButton(onClick = viewModel::dismissEncryptUnlock) { Text("Cancel") } },
        )
    }

    // MSG — view-once content popup; closing it consumes the message permanently.
    val vo = state.viewOnceViewer
    if (vo.messageKey != null) {
        AlertDialog(
            onDismissRequest = viewModel::dismissViewOnce,
            title = { Text(vo.title) },
            text = {
                when {
                    vo.loading -> androidx.compose.material3.CircularProgressIndicator(
                        modifier = Modifier.testTag("thread_view_once_loading"),
                    )
                    vo.imageFile != null -> AsyncImage(
                        // Pass a File (not the path String): a leading-"/" string is otherwise
                        // rewritten to an http url by the Coil RelativeUrlMapper and fails to load.
                        model = java.io.File(vo.imageFile),
                        contentDescription = "View-once image",
                        modifier = Modifier.fillMaxWidth().testTag("thread_view_once_content"),
                    )
                    vo.error -> Text(
                        "Couldn't load this once-only content.",
                        modifier = Modifier.testTag("thread_view_once_content"),
                    )
                    else -> Text(vo.text, modifier = Modifier.testTag("thread_view_once_content"))
                }
            },
            confirmButton = {
                TextButton(onClick = viewModel::dismissViewOnce, modifier = Modifier.testTag("thread_view_once_close")) { Text("Close") }
            },
        )
    }

    // #7 — dedicated photo picker for the scheduled-message EDIT dialog (images only; the server
    // promotes a text-only scheduled message to an image when one is attached here).
    val pickScheduledEditPhoto = rememberLauncherForActivityResult(
        ActivityResultContracts.PickVisualMedia(),
    ) { uri ->
        if (uri != null) viewModel.onScheduledEditAttachImage(uri.toString())
    }
    // #4 (B-MSGEDIT) — document picker for attaching a FILE to a scheduled message being edited.
    val pickScheduledEditFile = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri, android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION,
                )
            }
            val info = resolveFileInfo(context, uri)
            viewModel.onScheduledEditAttachFile(uri.toString(), info.first, info.third)
        }
    }

    // #8 — scheduled-messages manager (list pending scheduled sends; edit/remove each).
    if (state.scheduledManager.visible) {
        ScheduledMessagesSheet(
            state = state.scheduledManager,
            onEdit = viewModel::openScheduledEdit,
            onRemove = viewModel::cancelScheduled,
            onDismiss = viewModel::closeScheduledManager,
        )
        LaunchedEffect(state.scheduledManager.error) {
            state.scheduledManager.error?.let {
                snackbarHostState.showSnackbar(it)
                viewModel.onScheduledManagerErrorShown()
            }
        }
        // #8 — inline edit dialog (text + send time) for one scheduled message.
        state.scheduledManager.editing?.let { editing ->
            ScheduledEditDialog(
                editing = editing,
                onTextChange = viewModel::onScheduledEditTextChange,
                onTimeChange = viewModel::onScheduledEditTimeChange,
                onTimeZoneChange = viewModel::onScheduledEditTimeZoneChange,
                onSave = viewModel::saveScheduledEdit,
                onDismiss = viewModel::closeScheduledEdit,
                // #7 — attach/replace a photo (even on a text-only scheduled message).
                onPickPhoto = {
                    pickScheduledEditPhoto.launch(
                        PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly),
                    )
                },
                onRemovePhoto = viewModel::onScheduledEditRemoveImage,
                // #4 (B-MSGEDIT) — attach a FILE or a library VIDEO to a scheduled message.
                onPickFile = { pickScheduledEditFile.launch(arrayOf("*/*")) },
                onPickVideo = viewModel::onOpenVideoPickerForScheduledEdit,
                onRemoveAttachment = viewModel::onScheduledEditRemoveAttachment,
            )
        }
    }

    // #5 (B-MSGEDIT) — system pickers for the NORMAL message-edit dialog (photo / file). A picked
    // item uploads immediately and stages onto the open edit dialog; video uses the library picker.
    val pickEditPhoto = rememberLauncherForActivityResult(
        ActivityResultContracts.PickVisualMedia(),
    ) { uri ->
        if (uri != null) viewModel.onEditAttachImage(uri.toString())
    }
    val pickEditFile = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri, android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION,
                )
            }
            val info = resolveFileInfo(context, uri)
            viewModel.onEditAttachFile(uri.toString(), info.first, info.third)
        }
    }
    // #5 — the rich edit dialog (text + add/replace/remove media). Rendered here (not in
    // MessageActionsHost) so it can drive the system pickers above and the shared video picker.
    state.actions.editing?.let { editTarget ->
        EditMessageDialog(
            target = editTarget,
            onSubmit = { viewModel.onAction(ThreadAction.SubmitEdit(editTarget.messageId, it)) },
            onCancel = { viewModel.onAction(ThreadAction.CancelEdit) },
            onPickPhoto = {
                pickEditPhoto.launch(
                    PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly),
                )
            },
            onPickFile = { pickEditFile.launch(arrayOf("*/*")) },
            onPickVideo = viewModel::onOpenVideoPickerForEdit,
            onClearStaged = viewModel::onEditClearStagedMedia,
            onToggleRemoveMedia = viewModel::onEditToggleRemoveMedia,
        )
    }
}

/** Bottom sheet to set send-time options (view-once / locked / scheduled / expiring) on the next message. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MessageOptionsSheet(
    options: MessageOptions,
    nowSeconds: Long,
    onViewOnceChange: (Boolean) -> Unit,
    onLockPriceChange: (String) -> Unit,
    onScheduleChange: (Long?) -> Unit,
    onScheduleTzChange: (String) -> Unit,
    onExpiresChange: (Long?) -> Unit,
    onEncryptedChange: (Boolean) -> Unit,
    onPassphraseChange: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var lockInput by remember {
        mutableStateOf(options.lockPriceCents?.let { "%.2f".format(it / 100.0) } ?: "")
    }
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag("thread_options_sheet").semantics { testTagsAsResourceId = true }) {
        Column(
            Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 4.dp),
        ) {
            Text("Message options", style = MaterialTheme.typography.titleMedium)
            // Encrypted (client-side encryption envelope)
            Row(
                Modifier.fillMaxWidth().padding(vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text("Encrypted", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        "Send end-to-end encrypted (no plaintext on the server)",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(
                    checked = options.encrypted,
                    onCheckedChange = onEncryptedChange,
                    modifier = Modifier.testTag("thread_option_encrypted"),
                )
            }
            if (options.encrypted) {
                OutlinedTextField(
                    value = options.encryptionPassphrase,
                    onValueChange = onPassphraseChange,
                    modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp).testTag("thread_option_passphrase"),
                    label = { Text("Passphrase") },
                    placeholder = { Text("Recipient must know this to unlock") },
                    singleLine = true,
                    visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    isError = options.encryptionPassphrase.isBlank(),
                )
            }
            // View once
            Row(
                Modifier.fillMaxWidth().padding(vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text("View once", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        "Disappears after it's opened once",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(
                    checked = options.viewOnce,
                    onCheckedChange = onViewOnceChange,
                    modifier = Modifier.testTag("thread_option_view_once"),
                )
            }
            // Locked (pay to unlock)
            Text("Lock behind a price", style = MaterialTheme.typography.bodyLarge)
            OutlinedTextField(
                value = lockInput,
                onValueChange = { lockInput = it; onLockPriceChange(it) },
                modifier = Modifier.fillMaxWidth().padding(top = 4.dp).testTag("thread_option_lock_price"),
                label = { Text("Unlock price (USD)") },
                placeholder = { Text("e.g. 4.99") },
                singleLine = true,
            )
            // Scheduled send — arbitrary date + time + timezone (#21)
            Text("Schedule send", style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(top = 12.dp))
            com.testlogon.android.feature.common.TimeZonePicker(
                selectedZoneId = options.scheduledTimeZoneId,
                onZoneChange = onScheduleTzChange,
                modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                testTag = "thread_option_schedule_tz",
            )
            Row(
                Modifier.fillMaxWidth().padding(top = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                com.testlogon.android.feature.common.DateTimePickerField(
                    selectedEpochSeconds = options.scheduledAtEpochSeconds,
                    onPicked = onScheduleChange,
                    modifier = Modifier.weight(1f),
                    placeholder = "Send now (tap to schedule)",
                    testTag = "thread_option_schedule",
                    zoneId = options.scheduledTimeZoneId,
                )
                if (options.scheduledAtEpochSeconds != null) {
                    TextButton(onClick = { onScheduleChange(null) }) { Text("Clear") }
                }
            }
            // Expiring (self-destruct after delivery)
            Text("Expires after", style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(top = 12.dp))
            Row(Modifier.padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf(60L to "1 min", 300L to "5 min", 3_600L to "1 hour", 86_400L to "1 day").forEach { (secs, label) ->
                    FilterChip(
                        selected = options.expiresInSeconds == secs,
                        onClick = { onExpiresChange(if (options.expiresInSeconds == secs) null else secs) },
                        label = { Text(label) },
                        modifier = Modifier.testTag("thread_option_expire_$secs"),
                    )
                }
            }
            Button(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth().padding(top = 16.dp).testTag("thread_options_done"),
            ) { Text("Done") }
            Box(Modifier.fillMaxWidth().height(16.dp))
        }
    }
}


/**
 * MSG — a live "Disappears in Xm" status line for an expiring message, styled like the timestamp.
 * Ticks once per second from the device clock (lifecycle-scoped) and flips to "Disappeared" at zero.
 */
@Composable
private fun ExpiryCountdownLine(expiresAtEpochSeconds: Long) {
    val now by remember(expiresAtEpochSeconds) {
        kotlinx.coroutines.flow.flow {
            while (true) {
                emit(System.currentTimeMillis() / 1000L)
                kotlinx.coroutines.delay(1_000L)
            }
        }
    }.collectAsStateWithLifecycle(initialValue = System.currentTimeMillis() / 1000L)
    val remaining = (expiresAtEpochSeconds - now).coerceAtLeast(0L)
    val text = if (remaining <= 0L) "Disappeared" else "Disappears in " + expiryLabel(remaining)
    Text(
        text = text,
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(top = 2.dp).testTag("thread_expiry_countdown"),
    )
}

/** MSG — a tappable teaser bubble for gated content (encrypted / view-once) on the receiver. */
@Composable
private fun GatedTeaserBubble(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    hint: String,
    onClick: () -> Unit,
    testTag: String,
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.medium,
        tonalElevation = 1.dp,
        modifier = Modifier
            .widthIn(max = 280.dp)
            .clickable(onClick = onClick)
            .testTag(testTag),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
        ) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(18.dp))
            Column(Modifier.padding(start = 8.dp)) {
                Text(label, style = MaterialTheme.typography.bodyLarge)
                Text(hint, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
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
    onAttachVideoClip: () -> Unit = {},
    onAttachFile: () -> Unit,
    onShareVideo: () -> Unit,
    onDismissVideoPicker: () -> Unit,
    onPickVideo: (String) -> Unit,
    onOpenImage: (String) -> Unit,
    onDownloadFile: (ThreadMessageUi) -> Unit,
    onSaveFile: (ThreadMessageUi) -> Unit = {},
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
    onCountdownTimeZoneChange: (String) -> Unit,
    onCountdownRevealTextChange: (String) -> Unit,
    onCountdownPickRevealImage: (String) -> Unit,
    onCountdownRemoveRevealImage: () -> Unit,
    onSendCountdown: () -> Unit,
    onAttachCountdownToMessage: () -> Unit,
    // MSG: new in-app composers.
    onAttachLottery: () -> Unit = {},
    onRemoveStagedImage: (Int) -> Unit = {},
    onRemoveStagedVideo: () -> Unit = {},
    onDismissLottery: () -> Unit = {},
    onSendLottery: (List<com.testlogon.android.data.messaging.LotteryOutcomeDraft>, String?, String?) -> Unit = { _, _, _ -> },
    onAttachFindDateTime: () -> Unit = {},
    onDismissFindDateTime: () -> Unit = {},
    onSendFindDateTime: (com.testlogon.android.data.messaging.FindDateTimeDraft) -> Unit = {},
    onAttachCalendarEvent: () -> Unit = {},
    onDismissCalendarEvent: () -> Unit = {},
    onSelectCalendarForEvent: (String) -> Unit = {},
    onSendCalendarEvent: (String, String) -> Unit = { _, _ -> },
    onAttachCalendarShare: () -> Unit = {},
    onDismissCalendarShare: () -> Unit = {},
    onSelectCalendarForShare: (String) -> Unit = {},
    onSendCalendarShare: (String, String, Boolean) -> Unit = { _, _, _ -> },
    onAttachFileShare: () -> Unit = {},
    onDismissFileShare: () -> Unit = {},
    onSendFileShare: (String) -> Unit = {},
    onOpenMessageOptions: () -> Unit = {},
    onClearMessageOptions: () -> Unit = {},
    onRemoveStagedFile: () -> Unit = {},
    nowSeconds: Long,
    onUnlock: (String) -> Unit,
    onTip: (String) -> Unit,
    onOpenEncrypted: (String) -> Unit,
    onOpenViewOnce: (String) -> Unit,
    onAddToCalendar: (MessageMedia.CalendarEvent) -> Unit,
    onTipPreset: (Long) -> Unit,
    onTipCustomChange: (String) -> Unit,
    onTipNoteChange: (String) -> Unit,
    onTipConfirm: () -> Unit,
    onTipDismiss: () -> Unit,
    onAction: (ThreadAction) -> Unit = {},
    onJumpToPinned: (String) -> Unit = {},
    onJumpToMessage: (String) -> Unit = {},
    onDiscardDraft: () -> Unit = {},
    // AND-151 — in-conversation search: when [searchActive] the search bar replaces the app bar.
    searchActive: Boolean = false,
    onOpenSearch: () -> Unit = {},
    onOpenScheduled: () -> Unit = {},
    onPlaceCall: (String) -> Unit = {},
    searchBar: @Composable () -> Unit = {},
    snackbarHostState: androidx.compose.material3.SnackbarHostState =
        remember { androidx.compose.material3.SnackbarHostState() },
    modifier: Modifier = Modifier,
) {
    // AND-140 — the message whose long-press action sheet is open (null = closed).
    var actionTarget by remember { mutableStateOf<ThreadMessageUi?>(null) }
    // #25/#27 — the gallery VIDEO item currently open in the full-screen player (null = closed).
    var galleryVideoUrl by remember { mutableStateOf<String?>(null) }
    // #3 KEYBOARD DISMISS — clear the composer's focus + hide the IME without leaving the thread.
    val focusManager = androidx.compose.ui.platform.LocalFocusManager.current
    val keyboardController = androidx.compose.ui.platform.LocalSoftwareKeyboardController.current
    val imeVisible = androidx.compose.foundation.layout.WindowInsets.isImeVisible
    val dismissKeyboard = {
        keyboardController?.hide()
        focusManager.clearFocus(force = true)
    }
    // #3 — a back-press first dismisses the keyboard (when it's up) instead of leaving the conversation.
    androidx.activity.compose.BackHandler(enabled = imeVisible && !searchActive) {
        dismissKeyboard()
    }
    Scaffold(
        modifier = modifier.testTag(ThreadTestTags.SCREEN),
        snackbarHost = { androidx.compose.material3.SnackbarHost(snackbarHostState) },
        topBar = {
            if (searchActive) {
                searchBar()
            } else {
                TopAppBar(
                title = {
                    androidx.compose.foundation.layout.Row(
                        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                        horizontalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(8.dp),
                    ) {
                        val headerTitle = state.title.ifBlank { stringResource(R.string.thread_default_title) }
                        // #15 - a 1:1 DM shows TWO overlapping circles (peer in front/left, me behind/
                        // right); group/unknown threads keep the single avatar.
                        if (state.isDm) {
                            com.testlogon.android.feature.common.DmAvatarPair(
                                // Prefer the resolved peer name; fall back to the peer id (so the front
                                // circle shows the peer's initials, never the generic "Conversation").
                                peerName = state.title.ifBlank { state.peerUserSub.orEmpty() },
                                peerPhotoUrl = state.peerPhotoUrl,
                                myName = state.myName,
                                myPhotoUrl = state.myPhotoUrl,
                                size = 32.dp,
                            )
                        } else {
                            // ID15 - peer avatar (photo when resolved, else monogram) beside the title.
                            com.testlogon.android.feature.common.TlAvatar(
                                name = headerTitle,
                                photoUrl = state.peerPhotoUrl,
                                size = 32.dp,
                                textStyle = MaterialTheme.typography.labelMedium,
                            )
                        }
                        Text(
                            text = headerTitle,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
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
                    // #19 — the top bar had FIVE separate action buttons (search / call / info / pins /
                    // schedule, + a conditional discard-draft). They're now folded behind a SINGLE "+"
                    // that opens a dropdown menu. Each entry keeps its original testTag so existing
                    // on-device automation still finds it (as a menu item).
                    var menuOpen by remember { mutableStateOf(false) }
                    IconButton(
                        onClick = { menuOpen = true },
                        modifier = Modifier.testTag(ThreadTestTags.TOPBAR_MENU),
                    ) {
                        Icon(Icons.Filled.Add, contentDescription = "Conversation actions")
                    }
                    androidx.compose.material3.DropdownMenu(
                        expanded = menuOpen,
                        onDismissRequest = { menuOpen = false },
                        modifier = Modifier.semantics { testTagsAsResourceId = true },
                    ) {
                        // AND-151 — in-conversation search.
                        androidx.compose.material3.DropdownMenuItem(
                            text = { Text(stringResource(R.string.search_in_conversation)) },
                            leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                            onClick = { menuOpen = false; onOpenSearch() },
                            modifier = Modifier.testTag(ThreadSearchTestTags.OPEN),
                        )
                        // 1:1 video call — only when the DM peer is resolved.
                        state.peerUserSub?.let { callee ->
                            androidx.compose.material3.DropdownMenuItem(
                                text = { Text("Video call") },
                                leadingIcon = { Icon(Icons.Filled.Call, contentDescription = null) },
                                onClick = {
                                    menuOpen = false
                                    onPlaceCall(
                                        com.testlogon.android.feature.call.nav.CallRoutes.outgoing(
                                            conversationId = state.conversationId,
                                            calleeUserId = callee,
                                            mode = com.testlogon.android.data.call.CallMode.VIDEO.wire,
                                            peerName = state.title.takeIf { it.isNotBlank() } ?: state.peerUserSub,
                                        ),
                                    )
                                },
                                modifier = Modifier.testTag("thread_call_video"),
                            )
                        }
                        // AND-158/159 — group details (participants / settings).
                        androidx.compose.material3.DropdownMenuItem(
                            text = { Text(stringResource(R.string.group_details_cd)) },
                            leadingIcon = { Icon(Icons.Outlined.Info, contentDescription = null) },
                            onClick = { menuOpen = false; onOpenGroupDetails() },
                            modifier = Modifier.testTag(ThreadTestTags.OPEN_GROUP_DETAILS),
                        )
                        // AND-140 — pinned messages.
                        androidx.compose.material3.DropdownMenuItem(
                            text = { Text(stringResource(R.string.msg_pins_title)) },
                            leadingIcon = { Icon(Icons.Filled.PushPin, contentDescription = null) },
                            onClick = { menuOpen = false; onAction(ThreadAction.OpenPinsList) },
                            modifier = Modifier.testTag(ThreadTestTags.OPEN_PINS),
                        )
                        // #8 — scheduled-messages manager.
                        androidx.compose.material3.DropdownMenuItem(
                            text = { Text(stringResource(R.string.msg_scheduled_title)) },
                            leadingIcon = { Icon(Icons.Filled.Schedule, contentDescription = null) },
                            onClick = { menuOpen = false; onOpenScheduled() },
                            modifier = Modifier.testTag(ThreadTestTags.OPEN_SCHEDULED),
                        )
                        // AND-141 — discard the current draft (only when one exists).
                        if (state.hasDraft) {
                            androidx.compose.material3.DropdownMenuItem(
                                text = { Text(stringResource(R.string.draft_discard)) },
                                leadingIcon = { Icon(Icons.Filled.DeleteOutline, contentDescription = null) },
                                onClick = { menuOpen = false; onDiscardDraft() },
                                modifier = Modifier.testTag(ThreadTestTags.DISCARD_DRAFT),
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
                        onAttachVideoClip = onAttachVideoClip,
                        onAttachFile = onAttachFile,
                        onShareVideo = onShareVideo,
                        onRecordVoice = onRecordVoice,
                        onAttachMedia = onOpenMediaPicker,
                        onAttachPoll = onOpenPollComposer,
                        onAttachCountdown = onAttachCountdown,
                        onAttachLottery = onAttachLottery,
                        onAttachFindDateTime = onAttachFindDateTime,
                        onAttachCalendarEvent = onAttachCalendarEvent,
                        onAttachCalendarShare = onAttachCalendarShare,
                        onAttachFileShare = onAttachFileShare,
                        onOpenMessageOptions = onOpenMessageOptions,
                        onClearMessageOptions = onClearMessageOptions,
                        onRemoveStagedImage = onRemoveStagedImage,
                        onRemoveStagedVideo = onRemoveStagedVideo,
                        onRemoveStagedFile = onRemoveStagedFile,
                        onCancelReply = { onAction(ThreadAction.CancelReply) },
                    )
                }
            }
        },
    ) { padding ->
        Box(
            Modifier
                .fillMaxSize()
                .padding(padding)
                // #3 KEYBOARD DISMISS — observe taps in the INITIAL pass so we see them BEFORE the child
                // LazyColumn's scroll gesture (which otherwise swallows a plain detectTapGestures on the
                // list). We never CONSUME the event, so scrolling + bubble clicks keep working; we only
                // hide the IME when the gesture is a clean tap (down→up, no real drag) and the IME is up.
                .pointerInput(Unit) {
                    awaitEachGesture {
                        val down = awaitFirstDown(
                            requireUnconsumed = false,
                            pass = androidx.compose.ui.input.pointer.PointerEventPass.Initial,
                        )
                        var moved = false
                        val slop = viewConfiguration.touchSlop
                        while (true) {
                            val event = awaitPointerEvent(
                                pass = androidx.compose.ui.input.pointer.PointerEventPass.Initial,
                            )
                            val change = event.changes.firstOrNull { it.id == down.id }
                                ?: event.changes.firstOrNull() ?: break
                            if ((change.position - down.position).getDistance() > slop) moved = true
                            if (change.changedToUpIgnoreConsumed() || !change.pressed) {
                                if (!moved) dismissKeyboard()
                                break
                            }
                        }
                    }
                },
        ) {
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
                    onOpenGalleryVideo = { galleryVideoUrl = it },
                    onDownloadFile = onDownloadFile,
                    onToggleVoice = onToggleVoice,
                    onSeekVoice = onSeekVoice,
                    onPollVote = onPollVote,
                    onPollConfirm = onPollConfirm,
                    onUnlock = onUnlock,
                    onTip = onTip,
                    onOpenEncrypted = onOpenEncrypted,
                    onOpenViewOnce = onOpenViewOnce,
                    onAddToCalendar = onAddToCalendar,
                    onAction = onAction,
                    onMessageLongPress = { actionTarget = it },
                    onJumpToMessage = onJumpToMessage,
                    nowSeconds = nowSeconds,
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
        onSaveFile = onSaveFile,
        onCloseSheet = { actionTarget = null },
    )

    // #25/#27 — full-screen player for a tapped gallery VIDEO item.
    galleryVideoUrl?.let { url ->
        com.testlogon.android.feature.messaging.media.GalleryVideoViewer(
            url = url,
            onDismiss = { galleryVideoUrl = null },
        )
    }

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
            onTimeZoneChange = onCountdownTimeZoneChange,
            onRevealTextChange = onCountdownRevealTextChange,
            onPickRevealImage = onCountdownPickRevealImage,
            onRemoveRevealImage = onCountdownRemoveRevealImage,
            onSend = onSendCountdown,
            onAttach = onAttachCountdownToMessage,
            onDismiss = onDismissCountdownPicker,
        )
    }

    if (state.lotteryComposerVisible) {
        LotteryComposerSheet(onSend = onSendLottery, onDismiss = onDismissLottery)
    }
    if (state.findDateTimeComposerVisible) {
        FindDateTimeComposerSheet(onSend = onSendFindDateTime, onDismiss = onDismissFindDateTime)
    }
    if (state.calendarEventComposer.visible) {
        CalendarEventComposerSheet(
            state = state.calendarEventComposer,
            onSelectCalendar = onSelectCalendarForEvent,
            onSendEvent = onSendCalendarEvent,
            onDismiss = onDismissCalendarEvent,
        )
    }
    if (state.calendarShareComposer.visible) {
        CalendarShareComposerSheet(
            state = state.calendarShareComposer,
            onSelectCalendar = onSelectCalendarForShare,
            onSend = onSendCalendarShare,
            onDismiss = onDismissCalendarShare,
        )
    }
    if (state.fileShareComposer.visible) {
        FileShareComposerSheet(
            state = state.fileShareComposer,
            onSendFile = onSendFileShare,
            onDismiss = onDismissFileShare,
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

/**
 * M12 — a short preview of a replied-to message for the quoted-reply card. Uses the message text when
 * present, else a media-kind placeholder ([image]/[file]/etc.) so non-text originals still read sensibly.
 */
private fun replyQuoteSnippet(m: ThreadMessageUi): String {
    val text = m.text.trim()
    if (text.isNotBlank()) return text
    return when (m.media) {
        is MessageMedia.Image -> "[image]"
        is MessageMedia.Gallery -> "[photos]"
        is MessageMedia.VideoShare -> "[video]"
        is MessageMedia.VideoClip -> "[video]"
        is MessageMedia.File -> "[file]"
        is MessageMedia.Voice -> "[voice message]"
        is MessageMedia.Voicemail -> "[voicemail]"
        is MessageMedia.Gif -> "[GIF]"
        is MessageMedia.Sticker -> "[sticker]"
        is MessageMedia.MeetingPoll, is MessageMedia.FindDateTime -> "[poll]"
        is MessageMedia.Countdown -> "[countdown]"
        is MessageMedia.CalendarEvent, is MessageMedia.CalendarShare -> "[calendar]"
        is MessageMedia.Paid -> "[locked]"
        MessageMedia.None -> "message"
    }
}

@Composable
private fun ThreadList(
    state: ThreadUiState,
    listState: androidx.compose.foundation.lazy.LazyListState,
    voicePlayback: com.testlogon.android.feature.messaging.voice.VoicePlaybackState,
    onRetrySend: (String) -> Unit,
    onOpenImage: (String) -> Unit,
    onOpenGalleryVideo: (String) -> Unit = {},
    onDownloadFile: (ThreadMessageUi) -> Unit,
    onToggleVoice: (String, String?) -> Unit,
    onSeekVoice: (String, Float) -> Unit,
    onPollVote: (String, String, com.testlogon.android.data.messaging.SlotVote?) -> Unit,
    onPollConfirm: (String, String) -> Unit,
    onUnlock: (String) -> Unit,
    onTip: (String) -> Unit,
    onOpenEncrypted: (String) -> Unit,
    onOpenViewOnce: (String) -> Unit,
    onAddToCalendar: (MessageMedia.CalendarEvent) -> Unit,
    onAction: (ThreadAction) -> Unit,
    onMessageLongPress: (ThreadMessageUi) -> Unit,
    onJumpToMessage: (String) -> Unit = {},
    nowSeconds: Long,
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
            itemsIndexed(reversed, key = { _, m -> m.key }) { index, message ->
                val repliedTo = message.replyToMessageId?.let { rid -> reversed.firstOrNull { it.key == rid } }
                // Day divider above the first (oldest) message of each calendar day. In the reversed
                // list, the chronologically-older neighbour sits at index+1.
                val older = reversed.getOrNull(index + 1)
                if (older == null ||
                    !sameLocalDay(message.createdAtEpochSeconds, older.createdAtEpochSeconds)
                ) {
                    DateDivider(message.createdAtEpochSeconds)
                }
                MessageBubble(
                    message = message,
                    repliedToPreview = repliedTo?.let {
                        (if (it.isOwn) "You" else "Them") + ": " + replyQuoteSnippet(it)
                    },
                    // M11 — tapping the quoted reply jumps the thread to the original message.
                    onReplyQuoteClick = repliedTo?.let { orig -> { onJumpToMessage(orig.key) } },
                    download = state.downloads[message.key] ?: FileDownloadUi.NotDownloaded,
                    voicePlayback = voicePlayback,
                    polls = state.polls,
                    unlock = state.unlocks[message.key] ?: UnlockUiState(),
                    onRetry = { onRetrySend(message.key) },
                    onOpenImage = onOpenImage,
                    onOpenGalleryVideo = onOpenGalleryVideo,
                    onDownloadFile = { onDownloadFile(message) },
                    onToggleVoice = onToggleVoice,
                    onSeekVoice = onSeekVoice,
                    onPollVote = onPollVote,
                    onPollConfirm = onPollConfirm,
                    onUnlock = { onUnlock(message.key) },
                    onTip = { onTip(message.key) },
                    onOpenEncrypted = { onOpenEncrypted(message.key) },
                    onOpenViewOnce = { onOpenViewOnce(message.key) },
                    onAddToCalendar = onAddToCalendar,
                    onLongPress = { onMessageLongPress(message) },
                    onToggleReaction = { emoji -> onAction(ThreadAction.ToggleReaction(message.key, emoji)) },
                    onSeeWhoReacted = { onAction(ThreadAction.OpenReactionDetails(message.key)) },
                    onOpenEditHistory = { onAction(ThreadAction.OpenEditHistory(message.key)) },
                    nowSeconds = nowSeconds,
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

/**
 * MSG — a coarse wall-clock ticker (epoch seconds) for relative timestamps. Re-emits on a fixed
 * cadence so "Just now" rolls over to "1 minute ago", etc., without per-frame recomposition.
 */
@Composable
private fun rememberNowTicker(periodMs: Long = 15_000L): Long {
    val now by remember {
        kotlinx.coroutines.flow.flow {
            while (true) {
                emit(System.currentTimeMillis() / 1000L)
                kotlinx.coroutines.delay(periodMs)
            }
        }
    }.collectAsStateWithLifecycle(initialValue = System.currentTimeMillis() / 1000L)
    return now
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
    onOpenGalleryVideo: (String) -> Unit = {},
    onDownloadFile: () -> Unit,
    onToggleVoice: (String, String?) -> Unit,
    onSeekVoice: (String, Float) -> Unit,
    onPollVote: (String, String, com.testlogon.android.data.messaging.SlotVote?) -> Unit,
    onPollConfirm: (String, String) -> Unit,
    onUnlock: () -> Unit,
    onTip: () -> Unit,
    onOpenEncrypted: () -> Unit = {},
    onOpenViewOnce: () -> Unit = {},
    onAddToCalendar: (MessageMedia.CalendarEvent) -> Unit,
    onLongPress: () -> Unit = {},
    onToggleReaction: (String) -> Unit = {},
    onSeeWhoReacted: () -> Unit = {},
    onOpenEditHistory: () -> Unit = {},
    repliedToPreview: String? = null,
    /** M11 — non-null when this message is a reply: tapping the quote jumps to the original. */
    onReplyQuoteClick: (() -> Unit)? = null,
    nowSeconds: Long = System.currentTimeMillis() / 1000L,
) {
    val alignment = if (message.isOwn) Alignment.End else Alignment.Start
    val bubbleColor = if (message.isOwn) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }
    val relative = remember(message.createdAtEpochSeconds, nowSeconds) {
        relativeTimeFromSeconds(message.createdAtEpochSeconds, nowSeconds * 1000L)
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
        // Quoted reply context: the message this bubble is replying to. M11 — tap to jump to the original.
        if (repliedToPreview != null) {
            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.7f),
                shape = MaterialTheme.shapes.small,
                modifier = Modifier
                    .widthIn(max = 280.dp)
                    .padding(bottom = 2.dp)
                    .testTag("thread_reply_quote")
                    .then(
                        if (onReplyQuoteClick != null) {
                            Modifier.clickable(onClick = onReplyQuoteClick)
                        } else {
                            Modifier
                        },
                    ),
            ) {
                Text(
                    text = repliedToPreview,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                )
            }
        }
        // MSG — receiver-side gated bubbles: encrypted (tap to enter passphrase) and view-once (tap to
        // view, then consumed). The sender sees a normal "sent" treatment. These take precedence over
        // the media dispatch because the gated content must never render until the user acts.
        // G1/G3 — a still-locked PPV message (the server withholds ALL gated payload, incl. the
        // encryption envelope, until the user pays) MUST gate on the PRICE first: render the locked
        // teaser (with an encrypted indicator when applicable) and suppress the encrypted/view-once
        // teasers so the paywall is never bypassed by the encryption/view-once gate. After unlock the
        // server returns the (still-encrypted) message and the encrypted-teaser path takes over.
        val lockedNotUnlocked = !message.isOwn &&
            (message.media as? MessageMedia.Paid)?.monetization?.unlocked == false
        val isEncryptedImage = !lockedNotUnlocked && message.isEncrypted && message.media is MessageMedia.Image
        // #6 — an encrypted VIDEO (kind="video" -> MessageMedia.VideoClip) must get the same encrypted
        // teaser treatment as an encrypted image, not fall through to a normal playable clip. Recipient
        // only; the sender sees their own clip with an "Encrypted" badge (computed below).
        val isEncryptedVideo = !lockedNotUnlocked && message.isEncrypted &&
            !message.isOwn && message.media is MessageMedia.VideoClip
        val showEncryptedLocked = !lockedNotUnlocked &&
            message.isEncrypted && !message.isOwn && message.decryptedText == null &&
            !isEncryptedImage && !isEncryptedVideo
        val showViewOnceHidden = !lockedNotUnlocked && message.viewOnce && !message.isOwn && !message.consumed
        val showListenOnceConsumed = !lockedNotUnlocked &&
            (message.media as? MessageMedia.Voice)?.consumptionPolicy == "listen_once" &&
            !message.isOwn && message.consumed
        if (isEncryptedImage) {
            GatedTeaserBubble(
                icon = Icons.Filled.Lock,
                label = "Encrypted image",
                hint = "Tap to view",
                onClick = onOpenEncrypted,
                testTag = "thread_encrypted_image",
            )
        } else if (isEncryptedVideo) {
            // #6 — encrypted video recipient: show the encrypted/enter-passphrase teaser (mirrors the
            // encrypted-image teaser). Tapping prompts for the passphrase like other encrypted content.
            GatedTeaserBubble(
                icon = Icons.Filled.Lock,
                label = "Encrypted video",
                hint = "Tap to unlock",
                onClick = onOpenEncrypted,
                testTag = "thread_encrypted_video",
            )
        } else if (showEncryptedLocked) {
            GatedTeaserBubble(
                icon = Icons.Filled.Lock,
                label = "Encrypted message",
                hint = "Tap to unlock",
                onClick = onOpenEncrypted,
                testTag = RichMessageTestTags.ENCRYPTED_INDICATOR,
            )
        } else if (showListenOnceConsumed) {
            GatedTeaserBubble(
                icon = Icons.Filled.GraphicEq,
                label = "Voice message",
                hint = "Played",
                onClick = {},
                testTag = "thread_listen_once_played",
            )
        } else if (showViewOnceHidden) {
            GatedTeaserBubble(
                icon = Icons.Filled.Visibility,
                label = "View once",
                hint = "Tap to view",
                onClick = onOpenViewOnce,
                testTag = "thread_view_once_bubble",
            )
        } else when (val media = message.media) {
            is MessageMedia.Image -> ImageBubble(
                media = media,
                onOpenImage = onOpenImage,
                onLongPress = onLongPress,
                badge = if (message.isOwn) {
                    when {
                        // R2 — the SENDER's own locked image maps to a plain Image (gated media IS
                        // present for them), so the "$X to unlock" Paid badge never renders. Surface
                        // the lock + price here, mirroring the view-once / Disappears own badges.
                        message.lockPriceCents != null ->
                            "Locked ${formatMoney(message.lockPriceCents, message.lockCurrency)}"
                        message.viewOnce -> "View once"
                        message.expiresAtEpochSeconds != null -> "Disappears"
                        else -> null
                    }
                } else {
                    null
                },
            )
            is MessageMedia.Gallery -> GalleryBubble(media = media, onOpenImage = onOpenImage, onOpenVideo = onOpenGalleryVideo, onLongPress = onLongPress)
            is MessageMedia.VideoShare -> VideoBubble(media = media)
            is MessageMedia.VideoClip -> VideoClipBubble(
                media = media,
                modifier = Modifier
                    .width(240.dp)
                    .clip(RoundedCornerShape(12.dp)),
                // #5/#6 — the SENDER's own gated video maps to a plain VideoClip (the media IS present
                // for them / unlocked viewers), so no recipient teaser/paywall renders. Surface the gate
                // as a corner badge — "Locked $X" / "Encrypted" / "View once" / "Disappears" — exactly
                // like ImageBubble, so they can see they sent it gated.
                badge = if (message.isOwn) {
                    when {
                        message.lockPriceCents != null ->
                            "Locked ${formatMoney(message.lockPriceCents, message.lockCurrency)}"
                        message.isEncrypted -> "Encrypted"
                        message.viewOnce -> "View once"
                        message.expiresAtEpochSeconds != null -> "Disappears"
                        else -> null
                    }
                } else {
                    null
                },
            )
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
            is MessageMedia.FindDateTime -> FindDateTimeCard(media = media)
            is MessageMedia.Paid -> PaidMessageBubble(
                monetization = media.monetization,
                isOwn = message.isOwn,
                unlock = unlock,
                onUnlock = onUnlock,
                // G1 — a locked+encrypted message shows BOTH a locked teaser AND an encrypted
                // indicator. The receiver must unlock (pay) first; decrypting alone reveals nothing.
                isEncrypted = message.isEncrypted,
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
            MessageMedia.None -> {
              // #6 (B-COUNTDOWN3) — a countdown-only message (no real body, or body == title) shows
              // ONLY the countdown overlay below; suppress the empty/duplicate base bubble.
              val bodyText = (message.decryptedText ?: message.text).trim()
              val countdownOnly = message.countdown != null && !message.isEncrypted &&
                  (bodyText.isEmpty() || bodyText == message.countdown.title?.trim())
              if (!countdownOnly) Surface(
                color = bubbleColor,
                contentColor = if (message.isOwn) {
                    MaterialTheme.colorScheme.onPrimaryContainer
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
                shape = bubbleShape(message.isOwn),
                tonalElevation = 1.dp,
                modifier = Modifier
                    .widthIn(max = 280.dp)
                    .testTag(tag)
                    .semantics { stateDescription = stateDesc },
              ) {
                if (message.isEncrypted && message.decryptedText == null) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .padding(horizontal = 14.dp, vertical = 9.dp)
                            .testTag(RichMessageTestTags.ENCRYPTED_INDICATOR),
                    ) {
                        Icon(
                            Icons.Filled.Lock,
                            contentDescription = "Encrypted message",
                            modifier = Modifier.size(16.dp),
                        )
                        Text(
                            text = message.text.ifBlank { "Encrypted message" },
                            style = MaterialTheme.typography.bodyLarge,
                            modifier = Modifier.padding(start = 6.dp),
                        )
                    }
                } else {
                    Text(
                        text = message.decryptedText ?: message.text,
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 9.dp),
                    )
                }
              }
            }
        }
        // #10 — a media message (file/image/gallery/video) may carry a text CAPTION. Render it just
        // below the media bubble (not for the text-only `None` bubble, which already shows the body, nor
        // for still-gated/teaser bubbles where `text` is a placeholder/ciphertext).
        run {
            val mediaWithCaption = message.media !is MessageMedia.None &&
                message.media !is MessageMedia.Paid
            // #6 — when a countdown overlay carries the same headline as the body (legacy standalone
            // countdown), the title is shown by the overlay; don't ALSO render it as a caption.
            val dupOfCountdownTitle = message.countdown?.title
                ?.let { it.isNotBlank() && it.trim() == (message.decryptedText ?: message.text).trim() } == true
            val captionText = if (dupOfCountdownTitle) "" else (message.decryptedText ?: message.text).trim()
            val gated = isEncryptedImage || isEncryptedVideo || showEncryptedLocked ||
                showViewOnceHidden || showListenOnceConsumed || lockedNotUnlocked
            if (mediaWithCaption && captionText.isNotBlank() && !gated) {
                Surface(
                    color = bubbleColor,
                    shape = bubbleShape(message.isOwn),
                    tonalElevation = 1.dp,
                    modifier = Modifier
                        .widthIn(max = 280.dp)
                        .padding(top = 2.dp)
                        .testTag("thread_media_caption"),
                ) {
                    Text(
                        text = captionText,
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 9.dp),
                    )
                }
            }
        }
        // #6 (B-COUNTDOWN3) — a countdown can ride ANY message (text/image/video/file). Render it as an
        // overlay strip below the bubble: it ticks live and FLIPS to the reveal at the target with no
        // manual refresh. Gated/teaser bubbles still gate first; a still-locked message keeps no overlay.
        message.countdown?.let { cd ->
            CountdownOverlay(countdown = cd, isOwn = message.isOwn)
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
            // Delivery/read receipt on the user's own, acked messages (AND-147 counts), shown as
            // check glyphs: ✓ sent, ✓✓ delivered, ✓✓ (primary tint) read.
            if (message.isOwn && !message.isSending && !message.isFailed) {
                ReceiptIndicator(
                    deliveredCount = message.deliveredCount,
                    seenCount = message.seenCount,
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
        // MSG — expiring message: a small live "Disappears in Xm" status line under the bubble.
        // G2 — once a locked message is UNLOCKED the server clears its expiry (it never disappears for
        // a payer), so suppress the countdown for an unlocked locked message even if a stale
        // expires_at is still cached. A still-locked message keeps its countdown (it expires unpaid).
        if (message.expiresAtEpochSeconds != null && !message.isExpired && !message.isUnlockedLocked) {
            ExpiryCountdownLine(expiresAtEpochSeconds = message.expiresAtEpochSeconds)
        }
        // AND-140 — under-bubble reaction chip row.
        ReactionChipsRow(
            reactions = message.reactions,
            onToggle = onToggleReaction,
            onSeeWhoReacted = onSeeWhoReacted,
        )
    }
}

/** Asymmetric chat-bubble shape: rounded on three corners with a small "tail" corner toward the sender's side. */
private fun bubbleShape(isOwn: Boolean): RoundedCornerShape =
    if (isOwn) {
        RoundedCornerShape(topStart = 18.dp, topEnd = 18.dp, bottomEnd = 4.dp, bottomStart = 18.dp)
    } else {
        RoundedCornerShape(topStart = 18.dp, topEnd = 18.dp, bottomEnd = 18.dp, bottomStart = 4.dp)
    }

/**
 * AND-147 — own-message delivery state as check glyphs (matches mainstream chat clients):
 * ✓ sent, ✓✓ delivered, ✓✓ in the primary tint once read.
 */
@Composable
private fun ReceiptIndicator(deliveredCount: Int, seenCount: Int) {
    val read = seenCount > 0
    val delivered = deliveredCount > 0
    val label = when {
        read -> "Read"
        delivered -> "Delivered"
        else -> "Sent"
    }
    Icon(
        imageVector = if (delivered || read) Icons.Filled.DoneAll else Icons.Filled.Check,
        contentDescription = label,
        tint = if (read) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier
            .padding(start = 4.dp)
            .size(15.dp)
            .testTag("thread_receipt"),
    )
}

/** A centered pill day-divider ("Today" / "Yesterday" / "MMM d, yyyy") between calendar days. */
@Composable
private fun DateDivider(epochSeconds: Long) {
    Box(
        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
        contentAlignment = Alignment.Center,
    ) {
        Surface(
            color = MaterialTheme.colorScheme.surfaceVariant,
            contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
            shape = RoundedCornerShape(12.dp),
        ) {
            Text(
                text = dayLabel(epochSeconds),
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
            )
        }
    }
}

/** True when two epoch-second timestamps fall on the same local calendar day. minSdk24-safe (no java.time). */
private fun sameLocalDay(a: Long, b: Long): Boolean {
    val ca = java.util.Calendar.getInstance().apply { timeInMillis = a * 1000L }
    val cb = java.util.Calendar.getInstance().apply { timeInMillis = b * 1000L }
    return ca.get(java.util.Calendar.YEAR) == cb.get(java.util.Calendar.YEAR) &&
        ca.get(java.util.Calendar.DAY_OF_YEAR) == cb.get(java.util.Calendar.DAY_OF_YEAR)
}

/** Human day label for a divider. minSdk24-safe (Calendar + SimpleDateFormat, no java.time). */
private fun dayLabel(epochSeconds: Long): String {
    val nowSec = System.currentTimeMillis() / 1000L
    return when {
        sameLocalDay(epochSeconds, nowSec) -> "Today"
        sameLocalDay(epochSeconds, nowSec - 86_400L) -> "Yesterday"
        else -> java.text.SimpleDateFormat("MMM d, yyyy", java.util.Locale.getDefault())
            .format(java.util.Date(epochSeconds * 1000L))
    }
}

/**
 * C6 — gallery (multi-image) bubble: a 2-column grid of thumbnails (max 4 shown, with a "+N" overlay
 * on the last when there are more). Each thumbnail opens full-screen. Sent as ONE message.
 */
@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
private fun GalleryBubble(
    media: MessageMedia.Gallery,
    onOpenImage: (String) -> Unit,
    onOpenVideo: (String) -> Unit = {},
    onLongPress: () -> Unit = {},
) {
    val images = media.images
    val maxShown = 4
    val shown = images.take(maxShown)
    val overflow = (images.size - maxShown).coerceAtLeast(0)
    val cols = if (shown.size == 1) 1 else 2
    Column(
        modifier = Modifier
            .width(220.dp)
            .clip(RoundedCornerShape(12.dp))
            .testTag("thread_gallery_bubble"),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        shown.chunked(cols).forEachIndexed { rowIdx, rowItems ->
            Row(horizontalArrangement = Arrangement.spacedBy(2.dp), modifier = Modifier.fillMaxWidth()) {
                rowItems.forEachIndexed { colIdx, gi ->
                    val flatIndex = rowIdx * cols + colIdx
                    val isLastShown = flatIndex == shown.lastIndex
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .aspectRatio(1f)
                            .clip(RoundedCornerShape(6.dp))
                            .combinedClickable(
                                onClick = {
                                    if (gi.isVideo) gi.url?.let(onOpenVideo) else gi.url?.let(onOpenImage)
                                },
                                onLongClick = onLongPress,
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        AsyncImage(
                            // #25/#27 — a video item shows its poster (preview frame) when present,
                            // else its object url (Coil's VideoFrameDecoder grabs a frame).
                            model = if (gi.isVideo) (gi.posterUrl ?: gi.url) else gi.url,
                            contentDescription = if (gi.isVideo) "Gallery video" else "Gallery image",
                            contentScale = ContentScale.Crop,
                            modifier = Modifier.fillMaxSize(),
                        )
                        // #25/#27 — a video item gets a centered play glyph so it reads as playable.
                        if (gi.isVideo) {
                            Icon(
                                Icons.Filled.PlayCircle,
                                contentDescription = null,
                                tint = Color.White.copy(alpha = 0.9f),
                                modifier = Modifier.size(36.dp),
                            )
                        }
                        if (isLastShown && overflow > 0) {
                            Box(
                                modifier = Modifier
                                    .fillMaxSize()
                                    .background(Color.Black.copy(alpha = 0.45f)),
                                contentAlignment = Alignment.Center,
                            ) {
                                Text("+$overflow", color = Color.White, style = MaterialTheme.typography.titleMedium)
                            }
                        }
                    }
                }
                // Pad an odd final row so a lone item doesn't stretch full width.
                if (rowItems.size < cols) {
                    repeat(cols - rowItems.size) { Spacer(Modifier.weight(1f)) }
                }
            }
        }
    }
}

/** AND-130 — image bubble: optimistic local thumbnail + progress, else remote Coil image. */
@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
private fun ImageBubble(
    media: MessageMedia.Image,
    onOpenImage: (String) -> Unit,
    onLongPress: () -> Unit = {},
    badge: String? = null,
) {
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
            .combinedClickable(
                onClick = { media.url?.let(onOpenImage) },
                onLongClick = onLongPress,
            )
            .semantics { contentDescription = cd },
        contentAlignment = Alignment.Center,
    ) {
        AsyncImage(
            model = display,
            contentDescription = cd,
            contentScale = ContentScale.Crop,
            modifier = Modifier.fillMaxSize(),
        )
        if (badge != null) {
            Box(
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .padding(6.dp)
                    .background(Color.Black.copy(alpha = 0.55f), RoundedCornerShape(8.dp))
                    .padding(horizontal = 6.dp, vertical = 2.dp),
            ) {
                Text(badge, color = Color.White, style = MaterialTheme.typography.labelSmall)
            }
        }
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
    onAttachVideoClip: () -> Unit = {},
    onAttachFile: () -> Unit,
    onShareVideo: () -> Unit,
    onRecordVoice: () -> Unit,
    onAttachMedia: () -> Unit,
    onAttachPoll: () -> Unit,
    onAttachCountdown: () -> Unit,
    onAttachLottery: () -> Unit = {},
    onAttachFindDateTime: () -> Unit = {},
    onAttachCalendarEvent: () -> Unit = {},
    onAttachCalendarShare: () -> Unit = {},
    onAttachFileShare: () -> Unit = {},
    onOpenMessageOptions: () -> Unit = {},
    onClearMessageOptions: () -> Unit = {},
    onRemoveStagedImage: (Int) -> Unit = {},
    onRemoveStagedVideo: () -> Unit = {},
    onRemoveStagedFile: () -> Unit = {},
    onCancelReply: () -> Unit = {},
) {
    Surface(tonalElevation = 2.dp) {
        var actionsExpanded by remember { mutableStateOf(false) }
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .imePadding()
                .navigationBarsPadding()
                .padding(horizontal = 4.dp, vertical = 8.dp)
                .testTag(ThreadTestTags.COMPOSER),
        ) {
            // Reply banner: shows which message the next send will reply to, with a cancel.
            composer.replyingTo?.let { reply ->
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp)
                        .testTag("thread_reply_banner"),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            text = "Replying to ${reply.senderLabel}",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary,
                        )
                        Text(
                            text = reply.preview,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    IconButton(
                        onClick = onCancelReply,
                        modifier = Modifier.size(40.dp).testTag("thread_cancel_reply"),
                    ) {
                        Icon(Icons.Filled.Close, contentDescription = "Cancel reply", tint = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            // The attachment actions are tucked behind the + toggle so the text field gets the full
            // width when typing; tapping + reveals them (and any choice collapses the row again).
            if (actionsExpanded) {
                Row(
                    modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    IconButton(
                        onClick = { actionsExpanded = false; onOpenMessageOptions() },
                        modifier = Modifier.size(44.dp).testTag("thread_msg_options"),
                    ) {
                        Icon(Icons.Filled.Tune, contentDescription = "Message options (view once, locked, schedule)", tint = MaterialTheme.colorScheme.primary)
                    }
                    IconButton(
                        onClick = { actionsExpanded = false; onAttachImage() },
                        modifier = Modifier.size(44.dp).testTag(ThreadTestTags.ATTACH_IMAGE),
                    ) {
                        // MV1 — single attach action for photos AND short videos.
                        Icon(Icons.Filled.PermMedia, contentDescription = "Attach photo or video", tint = MaterialTheme.colorScheme.primary)
                    }
                    IconButton(
                        onClick = { actionsExpanded = false; onAttachFile() },
                        modifier = Modifier.size(44.dp).testTag(ThreadTestTags.ATTACH_FILE),
                    ) {
                        Icon(Icons.Filled.AttachFile, contentDescription = stringResource(R.string.thread_attach_file), tint = MaterialTheme.colorScheme.primary)
                    }
                    IconButton(
                        onClick = { actionsExpanded = false; onShareVideo() },
                        modifier = Modifier.size(44.dp).testTag(ThreadTestTags.SHARE_VIDEO),
                    ) {
                        Icon(Icons.Filled.Videocam, contentDescription = stringResource(R.string.thread_share_video), tint = MaterialTheme.colorScheme.primary)
                    }
                    IconButton(
                        onClick = { actionsExpanded = false; onRecordVoice() },
                        modifier = Modifier.size(44.dp).testTag(VoiceTestTags.RECORD),
                    ) {
                        Icon(Icons.Filled.Mic, contentDescription = stringResource(R.string.thread_record_voice), tint = MaterialTheme.colorScheme.primary)
                    }
                    IconButton(
                        onClick = { actionsExpanded = false; onAttachMedia() },
                        modifier = Modifier.size(44.dp).testTag(RichMessageTestTags.ATTACH_MEDIA),
                    ) {
                        Icon(Icons.Filled.EmojiEmotions, contentDescription = stringResource(R.string.composer_add_media), tint = MaterialTheme.colorScheme.primary)
                    }
                    IconButton(
                        onClick = { actionsExpanded = false; onAttachPoll() },
                        modifier = Modifier.size(44.dp).testTag(RichMessageTestTags.ATTACH_POLL),
                    ) {
                        Icon(Icons.Filled.Poll, contentDescription = stringResource(R.string.composer_add_poll), tint = MaterialTheme.colorScheme.primary)
                    }
                    IconButton(
                        onClick = { actionsExpanded = false; onAttachCountdown() },
                        modifier = Modifier.size(44.dp).testTag(PaidMessageTestTags.COUNTDOWN_BUBBLE + "_attach"),
                    ) {
                        Icon(Icons.Filled.Timer, contentDescription = stringResource(R.string.composer_add_countdown), tint = MaterialTheme.colorScheme.primary)
                    }
                    IconButton(
                        onClick = { actionsExpanded = false; onAttachLottery() },
                        modifier = Modifier.size(44.dp).testTag(RichMessageTestTags.ATTACH_LOTTERY),
                    ) {
                        Icon(Icons.Filled.Casino, contentDescription = "Create a lottery", tint = MaterialTheme.colorScheme.primary)
                    }
                    IconButton(
                        onClick = { actionsExpanded = false; onAttachFindDateTime() },
                        modifier = Modifier.size(44.dp).testTag(RichMessageTestTags.ATTACH_FADT),
                    ) {
                        Icon(Icons.Filled.EditCalendar, contentDescription = "Find a time poll", tint = MaterialTheme.colorScheme.primary)
                    }
                    IconButton(
                        onClick = { actionsExpanded = false; onAttachCalendarEvent() },
                        modifier = Modifier.size(44.dp).testTag(RichMessageTestTags.ATTACH_CAL_EVENT),
                    ) {
                        Icon(Icons.Filled.Event, contentDescription = "Share a calendar event", tint = MaterialTheme.colorScheme.primary)
                    }
                    IconButton(
                        onClick = { actionsExpanded = false; onAttachCalendarShare() },
                        modifier = Modifier.size(44.dp).testTag(RichMessageTestTags.ATTACH_CAL_SHARE),
                    ) {
                        Icon(Icons.Filled.CalendarMonth, contentDescription = "Share a calendar", tint = MaterialTheme.colorScheme.primary)
                    }
                    IconButton(
                        onClick = { actionsExpanded = false; onAttachFileShare() },
                        modifier = Modifier.size(44.dp).testTag(RichMessageTestTags.ATTACH_FILE_SHARE),
                    ) {
                        Icon(Icons.Filled.FolderShared, contentDescription = "Share a file", tint = MaterialTheme.colorScheme.primary)
                    }
                }
            }
            // Active send-options chip (view-once / locked / scheduled), with a quick clear.
            composer.options.summary?.let { summary ->
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 2.dp).testTag("thread_options_chip"),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(Icons.Filled.Tune, contentDescription = null, modifier = Modifier.size(14.dp), tint = MaterialTheme.colorScheme.primary)
                    Text(
                        summary,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.weight(1f).padding(start = 4.dp),
                    )
                    IconButton(onClick = onClearMessageOptions, modifier = Modifier.size(28.dp)) {
                        Icon(Icons.Filled.Close, contentDescription = "Clear options", modifier = Modifier.size(14.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            // #25/#27/#28 — staged media preview: a horizontal row of thumbnails (photos AND videos,
            // in pick order), each with a remove 'x'; video items get a play glyph. The text field is
            // the shared caption. A mix / multiple items send as ONE gallery message.
            if (composer.stagedMedia.isNotEmpty()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState())
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                        .testTag("thread_staged_image"),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    composer.stagedMedia.forEachIndexed { index, staged ->
                        Box(modifier = Modifier.testTag("thread_staged_image_$index")) {
                            AsyncImage(
                                model = staged.localUri,
                                contentDescription = if (staged.isVideo) "Staged video" else "Staged image",
                                contentScale = ContentScale.Crop,
                                modifier = Modifier.size(72.dp).clip(RoundedCornerShape(12.dp)),
                            )
                            if (staged.isVideo) {
                                Icon(
                                    Icons.Filled.PlayCircle,
                                    contentDescription = null,
                                    tint = Color.White,
                                    modifier = Modifier.align(Alignment.Center).size(28.dp),
                                )
                            }
                            IconButton(
                                onClick = { onRemoveStagedImage(index) },
                                modifier = Modifier
                                    .align(Alignment.TopEnd)
                                    .size(24.dp)
                                    .background(Color.Black.copy(alpha = 0.55f), RoundedCornerShape(12.dp))
                                    .testTag("thread_remove_staged_image_$index"),
                            ) {
                                Icon(Icons.Filled.Close, contentDescription = "Remove", tint = Color.White, modifier = Modifier.size(16.dp))
                            }
                        }
                    }
                }
            }
            // #29 — staged FILE preview: an icon + name + size with a remove 'x'; the text field is the
            // caption and the message options apply before Send.
            composer.stagedFile?.let { staged ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                        .testTag("thread_staged_file"),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        Icons.Filled.AttachFile,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(28.dp),
                    )
                    Text(
                        text = staged.name,
                        style = MaterialTheme.typography.bodyMedium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f).padding(horizontal = 8.dp),
                    )
                    IconButton(
                        onClick = onRemoveStagedFile,
                        modifier = Modifier.size(28.dp).testTag("thread_remove_staged_file"),
                    ) {
                        Icon(Icons.Filled.Close, contentDescription = "Remove file", tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(16.dp))
                    }
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.Bottom,
            ) {
                IconButton(
                    onClick = { actionsExpanded = !actionsExpanded },
                    modifier = Modifier.size(44.dp).testTag("thread_actions_toggle"),
                ) {
                    Icon(
                        if (actionsExpanded) Icons.Filled.Close else Icons.Filled.Add,
                        contentDescription = if (actionsExpanded) "Hide attachment options" else "Show attachment options",
                        tint = MaterialTheme.colorScheme.primary,
                    )
                }
                OutlinedTextField(
                    value = composer.draft,
                    onValueChange = onDraftChange,
                    modifier = Modifier.weight(1f).testTag("thread_input"),
                    placeholder = {
                        Text(
                            if (composer.hasStagedMedia) "Add a caption…" else stringResource(R.string.thread_composer_hint),
                        )
                    },
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
}

// ============================================================================================
// #8 SCHEDULED MESSAGES MANAGER
// ============================================================================================

/** #8 - format an epoch-seconds due time for the manager rows / edit field. */
private fun formatScheduledTime(epochSeconds: Long): String =
    SimpleDateFormat("MMM d, yyyy 'at' h:mm a", Locale.getDefault()).format(Date(epochSeconds * 1000L))

/**
 * #8 - bottom sheet listing the caller's pending scheduled messages. Each row shows the body/preview
 * and the due time with Edit + Remove actions. Empty/loading states handled inline.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ScheduledMessagesSheet(
    state: ScheduledManagerUiState,
    onEdit: (String) -> Unit,
    onRemove: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(horizontal = 20.dp, vertical = 8.dp)
                .testTag(ThreadTestTags.SCHEDULED_SHEET),
        ) {
            Text(
                text = stringResource(R.string.msg_scheduled_title),
                style = MaterialTheme.typography.titleLarge,
            )
            Spacer(Modifier.height(12.dp))
            when {
                state.loading && state.items.isEmpty() -> {
                    Box(modifier = Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator()
                    }
                }
                state.isEmpty -> {
                    Text(
                        text = stringResource(R.string.msg_scheduled_empty),
                        style = MaterialTheme.typography.bodyLarge,
                    )
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = stringResource(R.string.msg_scheduled_empty_hint),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(16.dp))
                }
                else -> {
                    LazyColumn(modifier = Modifier.fillMaxWidth().heightIn(max = 420.dp)) {
                        items(state.items, key = { it.id }) { item ->
                            ScheduledMessageRow(
                                item = item,
                                onEdit = { onEdit(item.id) },
                                onRemove = { onRemove(item.id) },
                            )
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                }
            }
        }
    }
}

/** #8 - one row in the scheduled-messages manager. */
@Composable
private fun ScheduledMessageRow(
    item: com.testlogon.android.data.messaging.ScheduledMessage,
    onEdit: () -> Unit,
    onRemove: () -> Unit,
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp)
            .testTag(ThreadTestTags.SCHEDULED_ITEM),
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Filled.Schedule,
                    contentDescription = null,
                    modifier = Modifier.size(16.dp),
                    tint = MaterialTheme.colorScheme.primary,
                )
                Spacer(Modifier.width(6.dp))
                Text(
                    text = formatScheduledTime(item.deliverAtEpochSeconds),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            Spacer(Modifier.height(6.dp))
            Text(
                text = item.displayText,
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                TextButton(
                    onClick = onEdit,
                    modifier = Modifier.testTag(ThreadTestTags.SCHEDULED_EDIT),
                ) { Text(stringResource(R.string.msg_scheduled_edit)) }
                Spacer(Modifier.width(4.dp))
                TextButton(
                    onClick = onRemove,
                    modifier = Modifier.testTag(ThreadTestTags.SCHEDULED_REMOVE),
                ) {
                    Text(
                        text = stringResource(R.string.msg_scheduled_remove),
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        }
    }
}

/** #8 - edit dialog for one scheduled message: change the body (text-kind) and/or the send time. */
@Composable
private fun ScheduledEditDialog(
    editing: ScheduledEditState,
    onTextChange: (String) -> Unit,
    onTimeChange: (Long) -> Unit,
    onTimeZoneChange: (String) -> Unit,
    onSave: () -> Unit,
    onDismiss: () -> Unit,
    onPickPhoto: () -> Unit,
    onRemovePhoto: () -> Unit,
    onPickFile: () -> Unit = {},
    onPickVideo: () -> Unit = {},
    onRemoveAttachment: () -> Unit = {},
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.msg_scheduled_edit_title)) },
        text = {
            Column(modifier = Modifier.testTag(ThreadTestTags.SCHEDULED_EDIT)) {
                if (editing.textEditable) {
                    OutlinedTextField(
                        value = editing.draftText,
                        onValueChange = onTextChange,
                        modifier = Modifier.fillMaxWidth().testTag("thread_scheduled_edit_text"),
                        label = { Text(stringResource(R.string.msg_scheduled_edit)) },
                    )
                    Spacer(Modifier.height(12.dp))
                }
                // #7 (B-SCHED3) — attach (or replace) a PHOTO on a still-pending scheduled message.
                // Offered even for a text-only message: the server promotes it to an image on save.
                if (editing.canAttachImage) {
                    when {
                        editing.attaching -> {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                                Spacer(Modifier.width(8.dp))
                                Text(
                                    text = stringResource(R.string.msg_scheduled_photo_attaching),
                                    style = MaterialTheme.typography.bodyMedium,
                                )
                            }
                        }
                        editing.draftImageLocalUri != null -> {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                AsyncImage(
                                    model = editing.draftImageLocalUri,
                                    contentDescription = stringResource(R.string.msg_scheduled_photo_attached),
                                    modifier = Modifier
                                        .size(56.dp)
                                        .clip(MaterialTheme.shapes.small)
                                        .testTag("thread_scheduled_edit_photo_preview"),
                                    contentScale = ContentScale.Crop,
                                )
                                Spacer(Modifier.width(8.dp))
                                Text(
                                    text = stringResource(R.string.msg_scheduled_photo_attached),
                                    style = MaterialTheme.typography.bodyMedium,
                                    modifier = Modifier.weight(1f),
                                )
                                IconButton(
                                    onClick = onRemovePhoto,
                                    modifier = Modifier.testTag("thread_scheduled_edit_photo_remove"),
                                ) {
                                    Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.action_remove))
                                }
                            }
                        }
                        // #4 (B-MSGEDIT) — a staged FILE shows a labelled chip with a remove action.
                        editing.draftFileName != null -> {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Filled.AttachFile, contentDescription = null, modifier = Modifier.size(28.dp))
                                Spacer(Modifier.width(8.dp))
                                Text(
                                    text = editing.draftFileName,
                                    style = MaterialTheme.typography.bodyMedium,
                                    modifier = Modifier.weight(1f),
                                )
                                IconButton(
                                    onClick = onRemoveAttachment,
                                    modifier = Modifier.testTag("thread_scheduled_edit_file_remove"),
                                ) {
                                    Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.action_remove))
                                }
                            }
                        }
                        // #4 (B-MSGEDIT) — a staged library VIDEO shows a labelled chip with a remove action.
                        editing.draftVideoId != null -> {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Filled.Movie, contentDescription = null, modifier = Modifier.size(28.dp))
                                Spacer(Modifier.width(8.dp))
                                Text(
                                    text = editing.draftVideoTitle ?: stringResource(R.string.msg_edit_video_attached),
                                    style = MaterialTheme.typography.bodyMedium,
                                    modifier = Modifier.weight(1f),
                                )
                                IconButton(
                                    onClick = onRemoveAttachment,
                                    modifier = Modifier.testTag("thread_scheduled_edit_video_remove"),
                                ) {
                                    Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.action_remove))
                                }
                            }
                        }
                        else -> {
                            // #4 (B-MSGEDIT) — add a photo / file / library video to the scheduled message.
                            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                TextButton(
                                    onClick = onPickPhoto,
                                    modifier = Modifier.testTag("thread_scheduled_edit_photo_add"),
                                ) {
                                    Icon(Icons.Filled.Image, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(Modifier.width(4.dp))
                                    Text(stringResource(R.string.msg_edit_add_photo))
                                }
                                TextButton(
                                    onClick = onPickFile,
                                    modifier = Modifier.testTag("thread_scheduled_edit_file_add"),
                                ) {
                                    Icon(Icons.Filled.AttachFile, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(Modifier.width(4.dp))
                                    Text(stringResource(R.string.msg_edit_add_file))
                                }
                                TextButton(
                                    onClick = onPickVideo,
                                    modifier = Modifier.testTag("thread_scheduled_edit_video_add"),
                                ) {
                                    Icon(Icons.Filled.Movie, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(Modifier.width(4.dp))
                                    Text(stringResource(R.string.msg_edit_add_video))
                                }
                            }
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                }
                Text(
                    text = stringResource(R.string.msg_scheduled_send_time),
                    style = MaterialTheme.typography.labelMedium,
                )
                Spacer(Modifier.height(4.dp))
                // #21/#22 — timezone the new send time is interpreted in (defaults to device zone).
                com.testlogon.android.feature.common.TimeZonePicker(
                    selectedZoneId = editing.timeZoneId,
                    onZoneChange = onTimeZoneChange,
                    modifier = Modifier.fillMaxWidth(),
                    testTag = "thread_scheduled_edit_tz",
                )
                Spacer(Modifier.height(4.dp))
                com.testlogon.android.feature.common.DateTimePickerField(
                    selectedEpochSeconds = editing.draftDeliverAtEpochSeconds.takeIf { it > 0L },
                    onPicked = onTimeChange,
                    testTag = "thread_scheduled_edit_time",
                    zoneId = editing.timeZoneId,
                )
                editing.error?.let {
                    Spacer(Modifier.height(8.dp))
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = onSave,
                enabled = !editing.saving && !editing.attaching,
                modifier = Modifier.testTag(ThreadTestTags.SCHEDULED_EDIT_SAVE),
            ) { Text(stringResource(R.string.msg_scheduled_save)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        },
    )
}
