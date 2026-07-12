package com.testlogon.android.feature.vod.adsupported

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.feature.player.VideoPlayer
import com.testlogon.android.feature.player.VideoPlayerControlsConfig
import com.testlogon.android.feature.player.VideoPlayerController
import kotlinx.coroutines.delay
import com.testlogon.android.feature.player.PlaybackPhase as PlayerPlaybackPhase

/** ADV-202 - stable test tags for the pre-roll (AVOD) player screen. */
object AdSupportedPlayerTestTags {
    const val SCREEN = "avod_player_screen"
    const val LOADING = "avod_loading"
    const val ERROR = "avod_error"
    const val AD_IMAGE = "avod_ad_image"
    const val AD_VIDEO = "avod_ad_video"
    const val CONTENT = "avod_content_player"
}

/** Media3 sampling cadence for feeding ad/content positions back into the ViewModel. */
private const val POSITION_SAMPLE_MS = 200L

private const val CREATIVE_VIDEO = "video"

/**
 * ADV-202 - route-level pre-roll (AVOD) player. Requests the live pre-roll ad (the backend ADV-201
 * serve_ad(surface=preroll) schedule minted onto the ad-supported session start), renders the ad
 * creative (image or video) with the reused [AdOverlay] skip-after-N countdown, GATES the main video
 * until the pre-roll is reported complete/skipped (the ViewModel only enters CONTENT after the server
 * break report, which is where ADV-203 charges the advertiser + credits the video poster), then plays
 * the gated content - all on ONE lifecycle-scoped ExoPlayer owned by the ViewModel.
 */
@Composable
fun AdSupportedPlayerRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: AdSupportedPlayerViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    AdSupportedPlayerScreen(
        state = state,
        controllerFor = { viewModel.controller },
        onSkip = viewModel::onSkipAd,
        onAdPosition = viewModel::onAdPosition,
        onContentPosition = viewModel::onContentPosition,
        onAdCompleted = viewModel::onAdCompleted,
        onRetry = viewModel::retry,
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdSupportedPlayerScreen(
    state: AdSupportedUiState,
    controllerFor: () -> VideoPlayerController,
    onSkip: () -> Unit,
    onAdPosition: (Long) -> Unit,
    onContentPosition: (Long) -> Unit,
    onAdCompleted: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AdSupportedPlayerTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.avod_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .background(Color.Black),
            contentAlignment = Alignment.Center,
        ) {
            when (val s = state) {
                is AdSupportedUiState.Loading -> CircularProgressIndicator(
                    color = Color.White,
                    modifier = Modifier
                        .size(48.dp)
                        .testTag(AdSupportedPlayerTestTags.LOADING),
                )

                is AdSupportedUiState.Error -> Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.testTag(AdSupportedPlayerTestTags.ERROR),
                ) {
                    Text(
                        text = s.message,
                        color = Color.White,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    TextButton(onClick = onRetry) { Text(stringResource(R.string.avod_retry)) }
                }

                is AdSupportedUiState.Ready -> ReadyPlayer(
                    state = s,
                    controller = controllerFor(),
                    onSkip = onSkip,
                    onAdPosition = onAdPosition,
                    onContentPosition = onContentPosition,
                    onAdCompleted = onAdCompleted,
                )
            }
        }
    }
}

@Composable
private fun ReadyPlayer(
    state: AdSupportedUiState.Ready,
    controller: VideoPlayerController,
    onSkip: () -> Unit,
    onAdPosition: (Long) -> Unit,
    onContentPosition: (Long) -> Unit,
    onAdCompleted: () -> Unit,
) {
    val br = state.currentBreak
    val isAd = state.phase == PlaybackPhase.AD && br != null
    val isImageAd = isAd && br!!.creativeType != CREATIVE_VIDEO
    val isVideoAd = isAd && br!!.creativeType == CREATIVE_VIDEO

    // Bind the ONE reused controller to the current source, exactly once per transition. Image ads
    // render via Coil (no player media); the controller is paused so the gated content never bleeds
    // through underneath the overlay.
    val bindKey = when {
        isVideoAd -> "advideo:" + br!!.breakId
        isImageAd -> "adimage:" + br!!.breakId
        else -> "content:" + state.contentUrl + ":" + state.playbackUnlocked
    }
    LaunchedEffect(bindKey) {
        when {
            isVideoAd -> controller.setMediaUri(br!!.creativeUrl, autoPlay = true)
            isImageAd -> controller.pause()
            state.phase == PlaybackPhase.CONTENT && state.contentUrl.isNotBlank() ->
                controller.setMediaUri(state.contentUrl, autoPlay = state.playbackUnlocked)
        }
    }

    // Feed positions + detect completion.
    if (isImageAd && br != null) {
        // Image creatives have no player timeline: drive the countdown from a wall clock so the skip
        // affordance enables and the impression/completion fires at the creative duration.
        LaunchedEffect(br.breakId) {
            val startedAt = System.currentTimeMillis()
            while (true) {
                val elapsed = System.currentTimeMillis() - startedAt
                onAdPosition(elapsed)
                if (elapsed >= br.durationMs) {
                    onAdCompleted()
                    break
                }
                delay(POSITION_SAMPLE_MS)
            }
        }
    } else {
        LaunchedEffect(state.phase, br?.breakId) {
            while (true) {
                val ps = controller.state.value
                if (state.phase == PlaybackPhase.AD) {
                    onAdPosition(ps.positionMs)
                    if (isVideoAd && ps.phase == PlayerPlaybackPhase.ENDED) {
                        onAdCompleted()
                        break
                    }
                } else {
                    onContentPosition(ps.positionMs)
                }
                delay(POSITION_SAMPLE_MS)
            }
        }
    }

    // Render.
    Box(modifier = Modifier.fillMaxSize()) {
        if (isImageAd && br != null) {
            AsyncImage(
                model = br.creativeUrl,
                contentDescription = stringResource(R.string.avod_ad_badge),
                contentScale = ContentScale.Fit,
                modifier = Modifier
                    .fillMaxSize()
                    .testTag(AdSupportedPlayerTestTags.AD_IMAGE),
            )
        } else {
            VideoPlayer(
                controller = controller,
                modifier = Modifier
                    .fillMaxSize()
                    .testTag(
                        if (isVideoAd) AdSupportedPlayerTestTags.AD_VIDEO
                        else AdSupportedPlayerTestTags.CONTENT,
                    ),
                config = VideoPlayerControlsConfig(showFullscreen = false),
            )
        }

        // The ad chrome (badge, "Ad N of M", remaining time, skip-after-N countdown) sits above the
        // creative while the pre-roll plays; it is absent during content playback.
        if (isAd) {
            AdOverlay(
                state = state,
                onSkip = onSkip,
                modifier = Modifier.fillMaxSize(),
            )
        }
    }
}
