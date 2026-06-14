@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.clips

import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.VolumeOff
import androidx.compose.material.icons.filled.VolumeUp
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.clips.Clip
import com.testlogon.android.feature.player.VideoPlayer

/** AND-196 / AND-394 — stable test tags for the public clip viewer. */
object PublicClipTestTags {
    const val SCREEN = "public_clip_screen"
    const val PLAYER = "public_clip_player"
    const val POSTER = "public_clip_poster"
    const val UNAVAILABLE = "public_clip_unavailable"
    const val META = "public_clip_meta"
    const val SHARE = "public_clip_share"
    const val MUTE = "public_clip_mute"
    const val CTA = "public_clip_cta"
}

/**
 * AND-196 / AND-394 — route-level public clip viewer (deep-linked by `/c/{clipId}`). Hoists the
 * [PublicClipViewModel], collects state, and renders [PublicClipScreen]. The reusable AND-168
 * [VideoPlayer] is bound to the VM's lifecycle-scoped controller; when no playable URL was resolved the
 * screen falls back to the clip poster (web parity).
 *
 * AND-394: collects the VM's one-shot [PublicClipViewModel.shareRequests] and launches the system share
 * sheet with the server-canonical (or local fallback) URL + title; wires the anonymous→app CTA.
 */
@Composable
fun PublicClipRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    onOpenFeed: () -> Unit = {},
    onOpenAuth: (clipId: String) -> Unit = {},
    viewModel: PublicClipViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val context = LocalContext.current

    // Hand the resolved HLS source to the reused player once it is available.
    LaunchedEffect(state) {
        if ((state as? PublicClipUiState.Content)?.playbackUrl != null) viewModel.setPlaybackSource()
    }

    // AND-394 — drive the OS share sheet from the VM's one-shot share events. The payload is the bare
    // canonical URL + title; it never carries a token/cookie/session id.
    val shareChooserTitle = stringResource(R.string.clip_action_share)
    LaunchedEffect(viewModel) {
        viewModel.shareRequests.collect { request ->
            val send = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, request.url)
                putExtra(Intent.EXTRA_SUBJECT, request.title)
            }
            runCatching {
                context.startActivity(
                    Intent.createChooser(send, shareChooserTitle)
                        .apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) },
                )
            }
        }
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
        onShare = viewModel::share,
        onToggleMute = viewModel::toggleMute,
        onOpenAuth = onOpenAuth,
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
    onShare: () -> Unit = {},
    onToggleMute: () -> Unit = {},
    onOpenAuth: (clipId: String) -> Unit = {},
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
                    isMuted = state.isMuted,
                    hasSession = state.hasSession,
                    playerContent = playerContent,
                    onShare = onShare,
                    onToggleMute = onToggleMute,
                    onOpenAuth = onOpenAuth,
                )
            }
        }
    }
}

@Composable
private fun ClipContent(
    clip: Clip,
    playbackUrl: String?,
    isMuted: Boolean,
    hasSession: Boolean,
    playerContent: @Composable (Modifier) -> Unit,
    onShare: () -> Unit,
    onToggleMute: () -> Unit,
    onOpenAuth: (clipId: String) -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
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

        ClipMetaSection(
            clip = clip,
            isMuted = isMuted,
            hasSession = hasSession,
            onShare = onShare,
            onToggleMute = onToggleMute,
            onOpenAuth = onOpenAuth,
        )
    }
}

/**
 * AND-394 — clip metadata caption + actions. Attribution is by display-name strings only (no
 * `@handle`/avatar in the verified schema); missing optional fields degrade silently (no empty rows).
 */
@Composable
private fun ClipMetaSection(
    clip: Clip,
    isMuted: Boolean,
    hasSession: Boolean,
    onShare: () -> Unit,
    onToggleMute: () -> Unit,
    onOpenAuth: (clipId: String) -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp)
            .testTag(PublicClipTestTags.META),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (clip.title.isNotBlank()) {
            Text(
                text = clip.title,
                style = MaterialTheme.typography.titleMedium,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }

        val attribution = clipAttribution(clip)
        if (attribution.isNotBlank()) {
            Text(
                text = attribution,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        val counts = buildList {
            add(stringResource(R.string.clip_view_count, clip.viewCount))
            add(stringResource(R.string.clip_share_count, clip.shareCount))
        }.joinToString(" · ")
        Text(
            text = counts,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            val muteLabel = if (isMuted) {
                stringResource(R.string.clip_action_unmute)
            } else {
                stringResource(R.string.clip_action_mute)
            }
            IconButton(onClick = onToggleMute, modifier = Modifier.testTag(PublicClipTestTags.MUTE)) {
                Icon(
                    imageVector = if (isMuted) Icons.Filled.VolumeOff else Icons.Filled.VolumeUp,
                    contentDescription = muteLabel,
                )
            }
            val shareLabel = stringResource(R.string.clip_action_share)
            IconButton(onClick = onShare, modifier = Modifier.testTag(PublicClipTestTags.SHARE)) {
                Icon(imageVector = Icons.Filled.Share, contentDescription = shareLabel)
            }
        }

        // AND-394 — anonymous→app bridge CTA (FR-6/AC-7): label/target depend on the session.
        val ctaLabel = if (hasSession) {
            stringResource(R.string.clip_cta_open_in_app)
        } else {
            stringResource(R.string.clip_cta_sign_in)
        }
        OutlinedButton(
            onClick = { onOpenAuth(clip.clipId) },
            modifier = Modifier
                .fillMaxWidth()
                .testTag(PublicClipTestTags.CTA),
        ) {
            Text(ctaLabel)
        }
    }
}

/** Pure attribution string (broadcaster + creator display names); blank when neither is present. */
@Composable
private fun clipAttribution(clip: Clip): String {
    val broadcaster = clip.broadcasterDisplayName.takeIf { it.isNotBlank() }
    val creator = clip.creatorDisplayName.takeIf { it.isNotBlank() }
    return when {
        broadcaster != null && creator != null ->
            stringResource(R.string.clip_attribution_full, broadcaster, creator)
        broadcaster != null -> stringResource(R.string.clip_attribution_broadcaster, broadcaster)
        creator != null -> stringResource(R.string.clip_attribution_creator, creator)
        else -> ""
    }
}
