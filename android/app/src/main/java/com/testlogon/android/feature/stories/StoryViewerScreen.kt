@file:OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.stories

import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectVerticalDragGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material.icons.outlined.FavoriteBorder
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.hilt.navigation.compose.hiltViewModel
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.data.stories.SegmentKind
import com.testlogon.android.feature.player.VideoPlayer
import com.testlogon.android.feature.player.VideoPlayerControlsConfig
import com.testlogon.android.feature.blocking.BlockInteractionViewModel
import com.testlogon.android.core.ui.blocking.BlockConfirmDialog

/** Stable test tags for the story viewer (AND-199 / AND-200). */
object StoryViewerTestTags {
    const val SCREEN = "story_viewer"
    const val CLOSE = "story_viewer_close"
    const val PROGRESS = "story_progress_bar"
    const val IMAGE = "story_segment_image"
    const val VIDEO = "story_segment_video"
    const val REPLY_FIELD = "story_reply_field"
    const val REPLY_SEND = "story_reply_send"
    const val REACTION_ROW = "story_reaction_row"
    const val VIEWS_COUNT = "story_views_count"
    const val OVERFLOW = "story_viewer_overflow"
    const val MENU_REPORT = "story_viewer_menu_report"
    const val MENU_BLOCK = "story_viewer_menu_block"
}

/** Default quick-reaction emoji set (AND-200 FR-7). */
val STORY_REACTION_EMOJIS = listOf("❤️", "😂", "😮", "😢", "👏", "🔥")

/**
 * AND-199 / AND-200 — full-screen story viewer route. Drains the one-shot [StoryViewerEffect] flow
 * (Dismiss/ReactionSent/ReplySent/ShowError) and renders the viewer over the shared player for video
 * segments. The player is owned by the ViewModel (released in onCleared) — no second ExoPlayer.
 */
@Composable
fun StoryViewerRoute(
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: StoryViewerViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effectFlow.collect { effect ->
            when (effect) {
                is StoryViewerEffect.Dismiss -> onDismiss()
                else -> Unit // ReactionSent/ReplySent/ShowError surface in-screen (FR-7/FR-8).
            }
        }
    }

    StoryViewerScreen(
        state = state,
        onClose = viewModel::onClose,
        onNext = viewModel::next,
        onPrevious = viewModel::previous,
        onPauseHold = viewModel::onPauseHold,
        onReplyTextChange = viewModel::onReplyTextChange,
        onReactionsToggle = viewModel::onReactionsToggle,
        onReaction = viewModel::sendReaction,
        onSendReply = viewModel::sendReply,
        videoContent = { modifier2 ->
            VideoPlayer(
                controller = viewModel.controllerForUi,
                modifier = modifier2,
                config = VideoPlayerControlsConfig(showFullscreen = false),
            )
        },
        modifier = modifier,
    )
}

/**
 * AND-199 / AND-200 — stateless viewer surface: segment progress bars on top, the active segment media
 * (image via Coil / video via the injected [videoContent]), tap-left/right navigation, hold-to-pause,
 * swipe-down to dismiss, and the reaction/reply composer (or a viewers-count affordance for own
 * stories).
 */
@Composable
fun StoryViewerScreen(
    state: StoryViewerUiState,
    onClose: () -> Unit,
    onNext: () -> Unit,
    onPrevious: () -> Unit,
    onPauseHold: (Boolean) -> Unit,
    onReplyTextChange: (String) -> Unit,
    onReactionsToggle: (Boolean) -> Unit,
    onReaction: (String) -> Unit,
    onSendReply: (String) -> Unit,
    videoContent: @Composable (Modifier) -> Unit,
    modifier: Modifier = Modifier,
) {
    Box(
        modifier = modifier
            .fillMaxSize()
            .background(Color.Black)
            .testTag(StoryViewerTestTags.SCREEN),
    ) {
        // PAR-18: report/block affordance state. Playback is paused while the overflow menu / report
        // sheet / block dialog is open (reuses the same paused gating that hides the chrome).
        var menuOpen by remember { mutableStateOf(false) }
        val segmentForMenu = state.currentSegment
        val authorForMenu = state.currentAuthor
        val canModerate = !state.isOwnStory && segmentForMenu != null && authorForMenu != null
        val blockVm: BlockInteractionViewModel = androidx.hilt.navigation.compose.hiltViewModel()
        val blockState by blockVm.uiState.collectAsStateWithLifecycle()
        LaunchedEffect(authorForMenu?.userId) {
            authorForMenu?.let { blockVm.hydrate(it.userId, it.displayLabel) }
        }
        // Tap zones + hold-to-pause + swipe-down dismiss over the whole media area.
        Box(
            modifier = Modifier
                .fillMaxSize()
                .pointerInput(state.segmentIndex, state.authorIndex) {
                    detectTapGestures(
                        onTap = { offset ->
                            if (offset.x < size.width / 2f) onPrevious() else onNext()
                        },
                        onPress = {
                            onPauseHold(true)
                            tryAwaitRelease()
                            onPauseHold(false)
                        },
                    )
                }
                .pointerInput(Unit) {
                    var dragged = 0f
                    detectVerticalDragGestures(
                        onDragEnd = {
                            if (dragged > SWIPE_DISMISS_THRESHOLD_PX) onClose()
                            dragged = 0f
                        },
                    ) { _, dragAmount -> if (dragAmount > 0) dragged += dragAmount }
                },
        ) {
            when (val segment = state.currentSegment) {
                null -> if (state.phase == ViewerPhase.LOADING) LoadingOverlay()
                else -> when (segment.kind) {
                    SegmentKind.IMAGE -> AsyncImage(
                        model = segment.mediaUrl,
                        contentDescription = stringResource(R.string.story_image_cd),
                        contentScale = ContentScale.Fit,
                        modifier = Modifier.fillMaxSize().testTag(StoryViewerTestTags.IMAGE),
                    )
                    SegmentKind.VIDEO -> videoContent(
                        Modifier.fillMaxSize().testTag(StoryViewerTestTags.VIDEO),
                    )
                }
            }
        }

        // Top chrome: per-segment progress bars + close. Hidden while paused (FR-4).
        if (!state.paused || menuOpen) {
            Column(modifier = Modifier.fillMaxWidth().padding(12.dp).align(Alignment.TopCenter)) {
                SegmentProgressBar(
                    segmentCount = state.segments.size.coerceAtLeast(1),
                    activeIndex = state.segmentIndex,
                    activeProgress = state.progress,
                )
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    // PAR-18: report/block overflow. Hidden on the viewer's own story.
                    if (canModerate) {
                        Box {
                            IconButton(
                                onClick = {
                                    menuOpen = true
                                    onPauseHold(true)
                                },
                                modifier = Modifier.testTag(StoryViewerTestTags.OVERFLOW),
                            ) {
                                Icon(
                                    Icons.Filled.MoreVert,
                                    contentDescription = stringResource(R.string.story_more_actions),
                                    tint = Color.White,
                                )
                            }
                            DropdownMenu(
                                expanded = menuOpen,
                                onDismissRequest = {
                                    menuOpen = false
                                    onPauseHold(false)
                                },
                            ) {
                                DropdownMenuItem(
                                    text = {
                                        Text(
                                            stringResource(
                                                R.string.story_block_author,
                                                authorForMenu?.displayLabel.orEmpty(),
                                            ),
                                        )
                                    },
                                    onClick = {
                                        menuOpen = false
                                        blockVm.onBlockRequested()
                                    },
                                    modifier = Modifier.testTag(StoryViewerTestTags.MENU_BLOCK),
                                )
                            }
                        }
                    }
                    IconButton(
                        onClick = onClose,
                        modifier = Modifier.testTag(StoryViewerTestTags.CLOSE),
                    ) {
                        Icon(
                            Icons.Filled.Close,
                            contentDescription = stringResource(R.string.story_close),
                            tint = Color.White,
                        )
                    }
                }
            }
        }

        // Bottom chrome: composer (others) or viewer-count (own story). Hidden while paused.
        if (!state.paused) {
            StoryComposer(
                composer = state.composer,
                isOwn = state.isOwnStory,
                viewerCount = state.currentSegment?.viewCount,
                onReplyTextChange = onReplyTextChange,
                onReactionsToggle = onReactionsToggle,
                onReaction = onReaction,
                onSendReply = onSendReply,
                modifier = Modifier.align(Alignment.BottomCenter).padding(12.dp),
            )
        }

        // PAR-18: shared block confirm dialog, wired exactly as PublicProfileScreen does.
        if (blockState.confirmVisible) {
            BlockConfirmDialog(
                title = stringResource(R.string.block_confirm_title, authorForMenu?.displayLabel.orEmpty()),
                body = stringResource(R.string.block_confirm_body),
                confirmLabel = stringResource(R.string.block_confirm_cta),
                dismissLabel = stringResource(R.string.block_confirm_cancel),
                onConfirm = {
                    blockVm.onBlockConfirmed()
                    onPauseHold(false)
                },
                onDismiss = {
                    blockVm.onBlockDismissed()
                    onPauseHold(false)
                },
            )
        }
    }
}

/** AND-200 FR-1 — N equal-width segment bars; active fills to [activeProgress], past ones full. */
@Composable
fun SegmentProgressBar(
    segmentCount: Int,
    activeIndex: Int,
    activeProgress: Float,
    modifier: Modifier = Modifier,
) {
    val cd = stringResource(R.string.story_progress_cd, activeIndex + 1, segmentCount)
    Row(
        modifier = modifier
            .fillMaxWidth()
            .testTag(StoryViewerTestTags.PROGRESS)
            .semantics {
                contentDescription = cd
                progressBarRangeInfo = ProgressBarRangeInfo(activeProgress, 0f..1f)
            },
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        for (i in 0 until segmentCount) {
            val fraction = when {
                i < activeIndex -> 1f
                i == activeIndex -> activeProgress.coerceIn(0f, 1f)
                else -> 0f
            }
            Box(
                modifier = Modifier
                    .weight(1f)
                    .height(3.dp)
                    .clip(RoundedCornerShape(2.dp))
                    .background(Color.White.copy(alpha = 0.3f)),
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth(fraction)
                        .height(3.dp)
                        .clip(RoundedCornerShape(2.dp))
                        .background(Color.White),
                )
            }
        }
    }
}

/**
 * AND-200 FR-7/FR-8/FR-9 — bottom composer. For another user's story: a reaction row + a reply field
 * with a send button. For the current user's own story: a read-only viewers-count affordance.
 */
@Composable
fun StoryComposer(
    composer: ComposerState,
    isOwn: Boolean,
    viewerCount: Int?,
    onReplyTextChange: (String) -> Unit,
    onReactionsToggle: (Boolean) -> Unit,
    onReaction: (String) -> Unit,
    onSendReply: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    if (isOwn) {
        Text(
            text = stringResource(R.string.story_views_count, viewerCount ?: 0),
            color = Color.White,
            style = MaterialTheme.typography.labelLarge,
            modifier = modifier.testTag(StoryViewerTestTags.VIEWS_COUNT),
        )
        return
    }

    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        if (composer.reactionsExpanded) {
            FlowRow(
                modifier = Modifier.fillMaxWidth().testTag(StoryViewerTestTags.REACTION_ROW),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                STORY_REACTION_EMOJIS.forEach { emoji ->
                    Text(
                        text = emoji,
                        style = MaterialTheme.typography.headlineSmall,
                        modifier = Modifier
                            .clip(RoundedCornerShape(50))
                            .background(Color.White.copy(alpha = 0.15f))
                            .padding(horizontal = 10.dp, vertical = 6.dp)
                            .semantics { role = Role.Button; contentDescription = emoji }
                            .testTag("story_reaction_$emoji")
                            .pointerInput(emoji) {
                                detectTapGestures(onTap = { if (!composer.sending) onReaction(emoji) })
                            },
                    )
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { onReactionsToggle(!composer.reactionsExpanded) }) {
                Icon(
                    Icons.Outlined.FavoriteBorder,
                    contentDescription = stringResource(R.string.story_react),
                    tint = Color.White,
                )
            }
            OutlinedTextField(
                value = composer.replyText,
                onValueChange = onReplyTextChange,
                placeholder = { Text(stringResource(R.string.story_reply_hint)) },
                singleLine = true,
                modifier = Modifier.weight(1f).testTag(StoryViewerTestTags.REPLY_FIELD),
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(imeAction = ImeAction.Send),
            )
            val canSend = composer.replyText.isNotBlank() && !composer.sending
            IconButton(
                onClick = { if (canSend) onSendReply(composer.replyText) },
                enabled = canSend,
                modifier = Modifier.testTag(StoryViewerTestTags.REPLY_SEND),
            ) {
                Icon(
                    Icons.Filled.Send,
                    contentDescription = stringResource(R.string.story_reply_send),
                    tint = if (canSend) Color.White else Color.Gray,
                )
            }
        }
    }
}

@Composable
private fun LoadingOverlay() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        CircularProgressIndicator(color = Color.White)
    }
}

/** Swipe-down dismiss threshold in raw pixels (≈ a healthy fling/drag). */
private const val SWIPE_DISMISS_THRESHOLD_PX = 300f
