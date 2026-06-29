package com.testlogon.android.feature.player

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Forward10
import androidx.compose.material.icons.filled.Fullscreen
import androidx.compose.material.icons.filled.FullscreenExit
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Replay10
import androidx.compose.material.icons.filled.PictureInPictureAlt
import androidx.compose.material.icons.outlined.HighQuality
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.media3.common.util.UnstableApi
import androidx.media3.ui.PlayerView
import com.testlogon.android.R

/** AND-168 — stable testTags for the reusable video player UI. */
object VideoPlayerTestTags {
    const val SURFACE = "video_player_surface"
    const val PLAY_PAUSE = "video_player_play_pause"
    const val SCRUBBER = "video_player_scrubber"
    const val TIME_LABEL = "video_player_time_label"
    const val BUFFERING = "video_player_buffering"
    const val ERROR_PANEL = "video_player_error"
    const val RETRY = "video_player_retry"
    const val FULLSCREEN = "video_player_fullscreen"
    const val PIP = "video_player_pip"
    const val LIVE_BADGE = "video_player_live_badge"
    const val QUALITY = "video_player_quality"
}

/** AND-168 §3 — declarative config for the control overlay. */
data class VideoPlayerControlsConfig(
    val seekStepMs: Long = 10_000L,
    val showFullscreen: Boolean = true,
)

/**
 * AND-168 — the reusable Compose video player. Binds a lifecycle-scoped [VideoPlayerController]
 * (created by AND-166's [VideoPlayerFactory], NOT here) to a Media3 [PlayerView] surface and overlays
 * Compose controls: play/pause, scrubber + time labels (pure-formatted via [PlayerTimeFormat]),
 * buffering spinner, fullscreen toggle, and an error panel with Retry. Reusable across
 * feed/message/content video. The composable does NOT create or release the player (AND-166 owns
 * that) — it only pauses on ON_STOP and unbinds the surface on dispose.
 *
 * @param controller the lifecycle-scoped controller whose [VideoPlayerController.state] drives the UI.
 * @param isFullscreen hoisted fullscreen flag (the host owns orientation; see [onFullscreenToggle]).
 * @param onFullscreenToggle emitted on the fullscreen affordance; the host flips immersive mode.
 * @param watermark AND-170 forensic-overlay hook; defaults to NotRequired (no overlay node, FR-3).
 *   Hosts opt in by passing [WatermarkUiState.Required]/[WatermarkUiState.PendingIdentity].
 * @param compactWatermark AND-170 — true in PiP to render the reduced-size overlay variant (FR-5).
 * @param quality AND-169 quality-selector hook; when non-null an overflow affordance opens the
 *   [QualitySheet]. Defaults to null (no quality UI) so existing call sites are unaffected.
 * @param onQualitySelected AND-169 — fired when the user picks a quality option.
 * @param onCapToggled AND-169 — fired when the user toggles the metered cap.
 */
@OptIn(UnstableApi::class, ExperimentalMaterial3Api::class)
@Composable
fun VideoPlayer(
    controller: VideoPlayerController,
    modifier: Modifier = Modifier,
    config: VideoPlayerControlsConfig = VideoPlayerControlsConfig(),
    isFullscreen: Boolean = false,
    onFullscreenToggle: (Boolean) -> Unit = {},
    watermark: WatermarkUiState = WatermarkUiState.NotRequired,
    compactWatermark: Boolean = false,
    quality: QualitySheetState? = null,
    onQualitySelected: (VideoQuality) -> Unit = {},
    onCapToggled: (Boolean) -> Unit = {},
) {
    val uiState by controller.state.collectAsStateWithLifecycle()
    var showQualitySheet by remember { mutableStateOf(false) }

    // #8 — system Picture-in-Picture. Register this player as the active video while it is composed +
    // playing so the Activity can auto-enter PiP on Home; the PiP control enters on demand.
    val pipController = LocalPipController.current
    DisposableEffect(uiState.isPlaying) {
        pipController.setVideoActive(uiState.isPlaying)
        onDispose { pipController.setVideoActive(false) }
    }

    // Pause on ON_STOP; unbind the surface on dispose (player release is the controller owner's job).
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner, controller) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_STOP -> controller.pause()
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    Box(
        modifier = modifier.testTag(VideoPlayerTestTags.SURFACE),
        contentAlignment = Alignment.Center,
    ) {
        AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { ctx ->
                PlayerView(ctx).apply {
                    useController = false // we render our own Compose controls (AND-168 FR-1).
                    setShowBuffering(PlayerView.SHOW_BUFFERING_NEVER)
                    player = controller.player()
                }
            },
            onReset = { it.player = null },
            onRelease = { it.player = null },
        )

        // AND-170 — forensic overlay sits ABOVE the video frame but BELOW the control chrome; it is
        // touch pass-through so controls remain operable, and absent entirely when not required (FR-3).
        WatermarkOverlay(state = watermark, compact = compactWatermark)

        when {
            uiState.error != null -> ErrorPanel(
                error = uiState.error!!,
                onRetry = { controller.retry() },
            )
            uiState.phase == PlaybackPhase.BUFFERING -> CircularProgressIndicator(
                modifier = Modifier
                    .size(48.dp)
                    .testTag(VideoPlayerTestTags.BUFFERING),
                color = Color.White,
            )
            else -> ControlsOverlay(
                state = uiState,
                config = config,
                isFullscreen = isFullscreen,
                showPip = pipController.isPipSupported,
                onPlayPause = { controller.playPause() },
                onSkip = { controller.skipBy(it) },
                onSeek = { controller.seekTo(it) },
                onFullscreenToggle = { onFullscreenToggle(!isFullscreen) },
                onEnterPip = { pipController.enterPip() },
            )
        }

        if (uiState.isLive) {
            Text(
                text = stringResource(R.string.player_live_badge),
                color = Color.White,
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(8.dp)
                    .background(Color.Red, MaterialTheme.shapes.small)
                    .padding(horizontal = 6.dp, vertical = 2.dp)
                    .testTag(VideoPlayerTestTags.LIVE_BADGE),
            )
        }

        // AND-169 — quality affordance + sheet (only when the host opts in by passing `quality`).
        if (quality != null && uiState.error == null) {
            val qualityCd = stringResource(R.string.cd_video_quality)
            IconButton(
                onClick = { showQualitySheet = true },
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .testTag(VideoPlayerTestTags.QUALITY),
            ) {
                Icon(
                    imageVector = Icons.Outlined.HighQuality,
                    contentDescription = qualityCd,
                    tint = Color.White,
                    modifier = Modifier.semantics { role = Role.Button; contentDescription = qualityCd },
                )
            }
            if (showQualitySheet) {
                QualitySheet(
                    state = quality,
                    onSelect = onQualitySelected,
                    onToggleCap = onCapToggled,
                    onDismiss = { showQualitySheet = false },
                )
            }
        }
    }
}

@Composable
private fun ControlsOverlay(
    state: PlayerUiState,
    config: VideoPlayerControlsConfig,
    isFullscreen: Boolean,
    showPip: Boolean,
    onPlayPause: () -> Unit,
    onSkip: (Long) -> Unit,
    onSeek: (Long) -> Unit,
    onFullscreenToggle: () -> Unit,
    onEnterPip: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.25f))
            .padding(12.dp),
        verticalArrangement = Arrangement.SpaceBetween,
    ) {
        // Transport row (rewind / play-pause / forward) centered in the available space.
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            val rewindLabel = stringResource(R.string.player_rewind_10)
            IconButton(onClick = { onSkip(-config.seekStepMs) }) {
                Icon(
                    imageVector = Icons.Filled.Replay10,
                    contentDescription = rewindLabel,
                    tint = Color.White,
                    modifier = Modifier
                        .size(36.dp)
                        .semantics { role = Role.Button; contentDescription = rewindLabel },
                )
            }
            val playLabel = if (state.isPlaying) {
                stringResource(R.string.player_pause)
            } else {
                stringResource(R.string.player_play)
            }
            IconButton(
                onClick = onPlayPause,
                modifier = Modifier.testTag(VideoPlayerTestTags.PLAY_PAUSE),
            ) {
                Icon(
                    imageVector = if (state.isPlaying) Icons.Filled.Pause else Icons.Filled.PlayArrow,
                    contentDescription = playLabel,
                    tint = Color.White,
                    modifier = Modifier
                        .size(48.dp)
                        .semantics { role = Role.Button; contentDescription = playLabel },
                )
            }
            val forwardLabel = stringResource(R.string.player_forward_10)
            IconButton(onClick = { onSkip(config.seekStepMs) }) {
                Icon(
                    imageVector = Icons.Filled.Forward10,
                    contentDescription = forwardLabel,
                    tint = Color.White,
                    modifier = Modifier
                        .size(36.dp)
                        .semantics { role = Role.Button; contentDescription = forwardLabel },
                )
            }
        }

        // Bottom bar: time label + scrubber (VOD only) + fullscreen toggle.
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = PlayerTimeFormat.positionLabel(state.positionMs, state.durationMs),
                color = Color.White,
                style = MaterialTheme.typography.labelMedium,
                modifier = Modifier.testTag(VideoPlayerTestTags.TIME_LABEL),
            )
            if (state.isSeekable) {
                Scrubber(
                    state = state,
                    onSeek = onSeek,
                    modifier = Modifier
                        .weight(1f)
                        .padding(horizontal = 8.dp),
                )
            } else {
                androidx.compose.foundation.layout.Spacer(Modifier.weight(1f))
            }
            if (showPip) {
                val pipLabel = stringResource(R.string.player_pip)
                IconButton(
                    onClick = onEnterPip,
                    modifier = Modifier.testTag(VideoPlayerTestTags.PIP),
                ) {
                    Icon(
                        imageVector = Icons.Filled.PictureInPictureAlt,
                        contentDescription = pipLabel,
                        tint = Color.White,
                        modifier = Modifier.semantics { role = Role.Button; contentDescription = pipLabel },
                    )
                }
            }
            if (config.showFullscreen) {
                val fsLabel = if (isFullscreen) {
                    stringResource(R.string.player_exit_fullscreen)
                } else {
                    stringResource(R.string.player_fullscreen)
                }
                IconButton(
                    onClick = onFullscreenToggle,
                    modifier = Modifier.testTag(VideoPlayerTestTags.FULLSCREEN),
                ) {
                    Icon(
                        imageVector = if (isFullscreen) {
                            Icons.Filled.FullscreenExit
                        } else {
                            Icons.Filled.Fullscreen
                        },
                        contentDescription = fsLabel,
                        tint = Color.White,
                        modifier = Modifier.semantics { role = Role.Button; contentDescription = fsLabel },
                    )
                }
            }
        }
    }
}

@Composable
private fun Scrubber(
    state: PlayerUiState,
    onSeek: (Long) -> Unit,
    modifier: Modifier = Modifier,
) {
    // Local scrub override: dragging shows a live preview; a single seekTo is issued on release.
    var scrubbing by remember { mutableStateOf(false) }
    var scrubFraction by remember { mutableFloatStateOf(0f) }
    val displayFraction = if (scrubbing) scrubFraction else state.progressFraction
    Slider(
        value = displayFraction,
        onValueChange = {
            scrubbing = true
            scrubFraction = it
        },
        onValueChangeFinished = {
            scrubbing = false
            val target = (state.durationMs * scrubFraction).toLong()
            onSeek(target)
        },
        modifier = modifier.testTag(VideoPlayerTestTags.SCRUBBER),
    )
}

@Composable
private fun ErrorPanel(
    error: PlayerError,
    onRetry: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.6f))
            .testTag(VideoPlayerTestTags.ERROR_PANEL),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        val message = if (error.isRetryable) {
            stringResource(R.string.player_error_connection)
        } else {
            stringResource(R.string.player_error_unplayable)
        }
        Text(text = message, color = Color.White, style = MaterialTheme.typography.bodyMedium)
        if (error.isRetryable) {
            val retryLabel = stringResource(R.string.player_retry)
            Text(
                text = retryLabel,
                color = Color.White,
                style = MaterialTheme.typography.labelLarge,
                modifier = Modifier
                    .padding(top = 12.dp)
                    .clickable(onClick = onRetry)
                    .testTag(VideoPlayerTestTags.RETRY)
                    .semantics { role = Role.Button; contentDescription = retryLabel },
            )
        }
    }
}
