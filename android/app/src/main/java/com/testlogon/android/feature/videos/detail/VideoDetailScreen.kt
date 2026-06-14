@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.videos.detail

import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.filled.FavoriteBorder
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.videos.VideoSummary
import com.testlogon.android.feature.player.VideoPlayer
import com.testlogon.android.feature.videos.VideoDurationFormat
import com.testlogon.android.feature.videos.VideoTile
import com.testlogon.android.feature.videos.purchase.PurchaseEvent
import com.testlogon.android.feature.videos.purchase.PurchaseTierSheet
import com.testlogon.android.feature.videos.purchase.PurchaseViewModel
import com.testlogon.android.feature.vod.rental.VodRentalPanel
import com.testlogon.android.feature.vod.rental.VodRentalViewModel

/** AND-190 — stable test tags. */
object VideoDetailTestTags {
    const val SCREEN = "video_detail_screen"
    const val TITLE = "video_detail_title"
    const val DESCRIPTION = "video_detail_description"
    const val LIKE = "video_detail_like"
    const val SHARE = "video_detail_share"
    const val PLAYER = "video_detail_player"
    const val PLAYBACK_BLOCK = "video_detail_playback_block"
    const val POSTER = "video_detail_poster"
    const val RELATED = "video_detail_related"
}

/**
 * AND-190 — route-level video detail. Hoists the [VideoDetailViewModel], collects state, and renders
 * [VideoDetailScreen]. The reusable AND-168 [VideoPlayer] is bound to the VM's lifecycle-scoped
 * controller; tapping a related tile re-navigates to the same detail route.
 */
@Composable
fun VideoDetailRoute(
    onBack: () -> Unit,
    onOpenVideo: (videoId: String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: VideoDetailViewModel = hiltViewModel(),
    rentalViewModel: VodRentalViewModel = hiltViewModel(),
    purchaseViewModel: PurchaseViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val rentalState by rentalViewModel.state.collectAsStateWithLifecycle()
    val purchaseState by purchaseViewModel.uiState.collectAsStateWithLifecycle()

    // Hand the resolved HLS source to the reused player once it is available.
    LaunchedEffect(state.playbackUrl) {
        if (state.playbackUrl != null) viewModel.setPlaybackSource()
    }

    // AND-193 — the purchase sheet opens on the "Unlock" entry point; on Unlocked the Room-backed
    // entitlement flips the detail to unlocked (server-authoritative; no optimistic unlock).
    var showPurchaseSheet by remember { mutableStateOf(false) }
    LaunchedEffect(purchaseViewModel) {
        purchaseViewModel.events.collect { event ->
            when (event) {
                is PurchaseEvent.Unlocked -> {
                    showPurchaseSheet = false
                    viewModel.retryDetail()
                }
                else -> Unit
            }
        }
    }

    VideoDetailScreen(
        state = state,
        playerContent = { playerModifier ->
            // Reuse the AND-166/168 player surface + controls; no second player, no eager ExoPlayer.
            VideoPlayer(
                controller = viewModel.controller,
                modifier = playerModifier.testTag(VideoDetailTestTags.PLAYER),
            )
        },
        monetizationContent = {
            // AND-192/193 — gating affordances under the player. When the title is locked
            // (not entitled) the rent/unlock affordances show; entitled play is owned by the player.
            if (state.detail?.isEntitled == false) {
                VodRentalPanel(
                    state = rentalState,
                    onRent = { tier -> rentalViewModel.rent(tier) },
                    onPlay = { rentalViewModel.beginPlayback() },
                )
                androidx.compose.material3.TextButton(onClick = {
                    showPurchaseSheet = true
                    purchaseViewModel.loadTiers()
                }) {
                    Text(stringResource(R.string.vod_unlock))
                }
            }
            if (showPurchaseSheet) {
                PurchaseTierSheet(
                    state = purchaseState,
                    onTierSelected = purchaseViewModel::onTierSelected,
                    onConfirm = purchaseViewModel::onConfirm,
                    onRetry = purchaseViewModel::retry,
                    onDismiss = { showPurchaseSheet = false },
                )
            }
        },
        onBack = onBack,
        onRetryDetail = viewModel::retryDetail,
        onToggleLike = viewModel::toggleLike,
        onOpenVideo = onOpenVideo,
        modifier = modifier,
    )
}

@Composable
fun VideoDetailScreen(
    state: VideoDetailUiState,
    playerContent: @Composable (Modifier) -> Unit,
    onBack: () -> Unit,
    onRetryDetail: () -> Unit,
    onToggleLike: () -> Unit,
    onOpenVideo: (videoId: String) -> Unit,
    modifier: Modifier = Modifier,
    monetizationContent: @Composable () -> Unit = {},
) {
    Scaffold(
        modifier = modifier.testTag(VideoDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(state.detail?.title.orEmpty(), maxLines = 1, overflow = TextOverflow.Ellipsis) },
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
            when {
                state.isLoading && state.detail == null -> LoadingState()

                state.detailError != null && state.detail == null -> {
                    val message = detailErrorMessage(state.detailError)
                    if (state.detailError.retryable) {
                        ErrorState(message = message, onRetry = onRetryDetail)
                    } else {
                        ErrorState(message = message, onRetry = onBack, retryLabel = stringResource(R.string.action_back))
                    }
                }

                state.detail != null -> DetailContent(
                    state = state,
                    playerContent = playerContent,
                    monetizationContent = monetizationContent,
                    onToggleLike = onToggleLike,
                    onOpenVideo = onOpenVideo,
                )
            }
        }
    }
}

@Composable
private fun DetailContent(
    state: VideoDetailUiState,
    playerContent: @Composable (Modifier) -> Unit,
    monetizationContent: @Composable () -> Unit,
    onToggleLike: () -> Unit,
    onOpenVideo: (videoId: String) -> Unit,
) {
    val detail = state.detail ?: return
    val context = LocalContext.current
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        // Player surface (reused AND-168 VideoPlayer) when playable; otherwise poster + block message.
        val surfaceModifier = Modifier
            .fillMaxWidth()
            .aspectRatio(16f / 9f)
        if (state.playbackUrl != null) {
            playerContent(surfaceModifier)
        } else {
            BlockedPlayerSurface(
                thumbnailUrl = detail.thumbnailUrl,
                title = detail.title,
                block = state.playbackBlock,
                modifier = surfaceModifier,
            )
        }

        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            // AND-192/193 — rent/unlock gating affordances (hidden when the title is entitled).
            monetizationContent()

            Text(
                text = detail.title.ifBlank { stringResource(R.string.video_untitled) },
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.testTag(VideoDetailTestTags.TITLE),
            )

            val meta = buildList {
                VideoDurationFormat.badge(detail.durationSec)?.let { add(it) }
                detail.reviewStatus?.let { add(it) }
            }.joinToString(" · ")
            if (meta.isNotBlank()) {
                Text(text = meta, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            // Actions: like (toggle) + share (external).
            Row(verticalAlignment = Alignment.CenterVertically) {
                val likeLabel = if (state.liked) {
                    stringResource(R.string.video_detail_unlike)
                } else {
                    stringResource(R.string.video_detail_like)
                }
                IconButton(
                    onClick = onToggleLike,
                    modifier = Modifier.testTag(VideoDetailTestTags.LIKE),
                ) {
                    Icon(
                        imageVector = if (state.liked) Icons.Filled.Favorite else Icons.Filled.FavoriteBorder,
                        contentDescription = likeLabel,
                    )
                }
                val shareLabel = stringResource(R.string.video_detail_share)
                IconButton(
                    onClick = {
                        val text = detail.playbackUrl ?: detail.thumbnailUrl
                        if (text != null) {
                            runCatching {
                                context.startActivity(
                                    Intent.createChooser(
                                        Intent(Intent.ACTION_SEND).apply {
                                            type = "text/plain"
                                            putExtra(Intent.EXTRA_TEXT, text)
                                        },
                                        shareLabel,
                                    ),
                                )
                            }
                        }
                    },
                    modifier = Modifier.testTag(VideoDetailTestTags.SHARE),
                ) {
                    Icon(imageVector = Icons.Filled.Share, contentDescription = shareLabel)
                }
            }

            if (!detail.description.isNullOrBlank()) {
                Text(
                    text = detail.description,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.testTag(VideoDetailTestTags.DESCRIPTION),
                )
            }

            if (state.related.isNotEmpty()) {
                Text(
                    text = stringResource(R.string.video_detail_up_next),
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
                RelatedRail(items = state.related, onOpenVideo = onOpenVideo)
            }

            VideoCommentsSection()
        }
    }
}

@Composable
private fun RelatedRail(
    items: List<VideoSummary>,
    onOpenVideo: (videoId: String) -> Unit,
) {
    LazyRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier.fillMaxWidth().testTag(VideoDetailTestTags.RELATED),
    ) {
        items(items.size, key = { items[it].id }) { index ->
            val video = items[index]
            VideoTile(
                title = video.title,
                thumbnailUrl = video.thumbnailUrl,
                durationSec = video.durationSec,
                onClick = { onOpenVideo(video.id) },
                modifier = Modifier.width(200.dp),
            )
        }
    }
}

@Composable
private fun BlockedPlayerSurface(
    thumbnailUrl: String?,
    title: String,
    block: PlaybackBlock?,
    modifier: Modifier = Modifier,
) {
    Box(modifier = modifier.background(Color.Black), contentAlignment = Alignment.Center) {
        AsyncImage(
            model = thumbnailUrl,
            contentDescription = title,
            modifier = Modifier.fillMaxSize().testTag(VideoDetailTestTags.POSTER),
        )
        val message = when (block) {
            PlaybackBlock.PROCESSING -> stringResource(R.string.video_detail_processing)
            PlaybackBlock.FORBIDDEN -> stringResource(R.string.video_detail_forbidden)
            PlaybackBlock.NO_SOURCE, null -> stringResource(R.string.video_detail_no_source)
        }
        Text(
            text = message,
            color = Color.White,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier
                .background(Color.Black.copy(alpha = 0.6f))
                .padding(12.dp)
                .testTag(VideoDetailTestTags.PLAYBACK_BLOCK)
                .semantics { contentDescription = message },
        )
    }
}

/** Maps the VM's framework-free message constants onto localized resources. */
@Composable
private fun detailErrorMessage(error: DetailError): String = when (error.message) {
    VideoDetailViewModel.NOT_FOUND_MESSAGE -> stringResource(R.string.video_detail_not_found)
    VideoDetailViewModel.FORBIDDEN_MESSAGE -> stringResource(R.string.video_detail_forbidden)
    VideoDetailViewModel.OFFLINE_MESSAGE -> stringResource(R.string.state_offline_message)
    else -> error.message
}
