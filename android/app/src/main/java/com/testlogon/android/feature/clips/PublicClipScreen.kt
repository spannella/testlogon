@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.clips

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
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
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.clips.Clip
import com.testlogon.android.feature.player.VideoPlayer

/** AND-196 — stable test tags for the public clip viewer. */
object PublicClipTestTags {
    const val SCREEN = "public_clip_screen"
    const val PLAYER = "public_clip_player"
    const val POSTER = "public_clip_poster"
    const val UNAVAILABLE = "public_clip_unavailable"
}

/**
 * AND-196 — route-level public clip viewer (deep-linked by `/c/{clipId}`). Hoists the
 * [PublicClipViewModel], collects state, and renders [PublicClipScreen]. The reusable AND-168
 * [VideoPlayer] is bound to the VM's lifecycle-scoped controller; when no playable URL was resolved the
 * screen falls back to the clip poster (web parity).
 */
@Composable
fun PublicClipRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    onOpenFeed: () -> Unit = {},
    viewModel: PublicClipViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()

    // Hand the resolved HLS source to the reused player once it is available.
    LaunchedEffect(state) {
        if ((state as? PublicClipUiState.Content)?.playbackUrl != null) viewModel.setPlaybackSource()
    }

    PublicClipScreen(
        state = state,
        playerContent = { playerModifier ->
            VideoPlayer(
                controller = viewModel.controller,
                modifier = playerModifier.testTag(PublicClipTestTags.PLAYER),
            )
        },
        onBack = onBack,
        onRetry = viewModel::retry,
        onOpenFeed = onOpenFeed,
        modifier = modifier,
    )
}

@Composable
fun PublicClipScreen(
    state: PublicClipUiState,
    playerContent: @Composable (Modifier) -> Unit,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onOpenFeed: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val title = (state as? PublicClipUiState.Content)?.clip?.title.orEmpty()
    Scaffold(
        modifier = modifier.testTag(PublicClipTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(title) },
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
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                PublicClipUiState.Loading -> LoadingState()
                PublicClipUiState.Offline -> ErrorState(
                    message = stringResource(R.string.state_offline_message),
                    onRetry = onRetry,
                )
                PublicClipUiState.Unavailable -> ErrorState(
                    modifier = Modifier.testTag(PublicClipTestTags.UNAVAILABLE),
                    message = stringResource(R.string.clip_unavailable),
                    onRetry = onOpenFeed,
                    retryLabel = stringResource(R.string.clip_open_feed),
                )
                is PublicClipUiState.Content -> ClipContent(
                    clip = state.clip,
                    playbackUrl = state.playbackUrl,
                    playerContent = playerContent,
                )
            }
        }
    }
}

@Composable
private fun ClipContent(
    clip: Clip,
    playbackUrl: String?,
    playerContent: @Composable (Modifier) -> Unit,
) {
    val surfaceModifier = Modifier
        .fillMaxWidth()
        .aspectRatio(9f / 16f)
    if (playbackUrl != null) {
        playerContent(surfaceModifier)
    } else {
        // No resolvable stream URL (web parity: thumbnail only) — never synthesize a URL.
        Box(modifier = surfaceModifier.background(Color.Black), contentAlignment = Alignment.Center) {
            AsyncImage(
                model = clip.thumbnailUrl,
                contentDescription = clip.title,
                contentScale = ContentScale.Fit,
                modifier = Modifier.fillMaxSize().testTag(PublicClipTestTags.POSTER),
            )
            if (clip.isProcessing) {
                Text(
                    text = stringResource(R.string.clip_processing),
                    color = Color.White,
                    modifier = Modifier
                        .background(Color.Black.copy(alpha = 0.6f))
                        .padding(12.dp)
                        .semantics { contentDescription = clip.title },
                )
            }
        }
    }
}
