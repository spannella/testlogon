package com.testlogon.android.feature.messaging.thread

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Image
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
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
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
import com.testlogon.android.feature.messaging.media.FullScreenImageViewer
import com.testlogon.android.feature.messaging.media.InlineVideoPlayer
import com.testlogon.android.feature.messaging.media.rememberImageViewerState
import com.testlogon.android.feature.messaging.relativeTimeFromSeconds
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
    const val SHARE_VIDEO = "thread_share_video"
    const val IMAGE_BUBBLE = "thread_image_bubble"
    const val VIDEO_BUBBLE = "thread_video_bubble"
    const val VIDEO_PICKER = "thread_video_picker"
}

/** AND-123 — route-level thread, reached from the conversation list. */
@Composable
fun ThreadRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ThreadViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()
    val imageViewer = rememberImageViewerState()

    // AND-130 — system photo picker (no storage permission on any supported API level).
    val pickImage = rememberLauncherForActivityResult(
        ActivityResultContracts.PickVisualMedia(),
    ) { uri -> if (uri != null) viewModel.onImagePicked(uri) }

    // AND-125 — mark the conversation read on ON_START (in-session guard lives in the ViewModel).
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_START) viewModel.onThreadVisible()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is ThreadEvent.ScrollToBottom -> listState.animateScrollToItem(0)
                is ThreadEvent.OpenImageViewer -> imageViewer.open(event.url)
            }
        }
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
        onBack = onBack,
        onRetry = viewModel::retry,
        onDraftChange = viewModel::onDraftChange,
        onSend = viewModel::onSend,
        onRetrySend = viewModel::onRetry,
        onAttachImage = {
            pickImage.launch(
                PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly),
            )
        },
        onShareVideo = viewModel::onOpenVideoPicker,
        onDismissVideoPicker = viewModel::onDismissVideoPicker,
        onPickVideo = viewModel::onShareVideo,
        onOpenImage = viewModel::onOpenImage,
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
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onDraftChange: (String) -> Unit,
    onSend: () -> Unit,
    onRetrySend: (String) -> Unit,
    onAttachImage: () -> Unit,
    onShareVideo: () -> Unit,
    onDismissVideoPicker: () -> Unit,
    onPickVideo: (String) -> Unit,
    onOpenImage: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(ThreadTestTags.SCREEN),
        topBar = {
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
            )
        },
        bottomBar = {
            MessageComposer(
                composer = state.composer,
                onDraftChange = onDraftChange,
                onSend = onSend,
                onAttachImage = onAttachImage,
                onShareVideo = onShareVideo,
            )
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
                    onRetrySend = onRetrySend,
                    onOpenImage = onOpenImage,
                )
            }
        }
    }

    if (state.videoPicker.visible) {
        VideoPickerSheet(
            picker = state.videoPicker,
            onDismiss = onDismissVideoPicker,
            onPick = onPickVideo,
        )
    }
}

@Composable
private fun ThreadList(
    state: ThreadUiState,
    listState: androidx.compose.foundation.lazy.LazyListState,
    onRetrySend: (String) -> Unit,
    onOpenImage: (String) -> Unit,
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
                    onRetry = { onRetrySend(message.key) },
                    onOpenImage = onOpenImage,
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

@Composable
private fun MessageBubble(
    message: ThreadMessageUi,
    onRetry: () -> Unit,
    onOpenImage: (String) -> Unit,
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

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp),
        horizontalAlignment = alignment,
    ) {
        when (val media = message.media) {
            is MessageMedia.Image -> ImageBubble(media = media, onOpenImage = onOpenImage)
            is MessageMedia.VideoShare -> VideoBubble(media = media)
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
        }
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

@Composable
private fun MessageComposer(
    composer: ComposerState,
    onDraftChange: (String) -> Unit,
    onSend: () -> Unit,
    onAttachImage: () -> Unit,
    onShareVideo: () -> Unit,
) {
    Surface(tonalElevation = 2.dp) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .imePadding()
                .navigationBarsPadding()
                .padding(horizontal = 8.dp, vertical = 8.dp)
                .testTag(ThreadTestTags.COMPOSER),
            verticalAlignment = Alignment.Bottom,
        ) {
            IconButton(
                onClick = onAttachImage,
                modifier = Modifier.size(48.dp).testTag(ThreadTestTags.ATTACH_IMAGE),
            ) {
                Icon(
                    Icons.Filled.Image,
                    contentDescription = stringResource(R.string.thread_attach_image),
                    tint = MaterialTheme.colorScheme.primary,
                )
            }
            IconButton(
                onClick = onShareVideo,
                modifier = Modifier.size(48.dp).testTag(ThreadTestTags.SHARE_VIDEO),
            ) {
                Icon(
                    Icons.Filled.Videocam,
                    contentDescription = stringResource(R.string.thread_share_video),
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
