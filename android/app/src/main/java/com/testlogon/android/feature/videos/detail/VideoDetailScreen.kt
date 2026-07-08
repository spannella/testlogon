@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.videos.detail

import com.testlogon.android.feature.ads.cta.AdCtaRouter
import com.testlogon.android.feature.ads.cta.CtaDestination
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
import androidx.compose.foundation.layout.size
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
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.testlogon.android.feature.player.VideoPlayerControlsConfig
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
import com.testlogon.android.feature.feed.TipSheet
import com.testlogon.android.feature.feed.TipEffect
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Button
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.clickable
import androidx.compose.material.icons.filled.AttachMoney
import androidx.compose.material.icons.filled.AddReaction
import androidx.compose.material3.DropdownMenu
import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.launch

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
    const val TIP = "video_detail_tip"
    const val REACT = "video_detail_react"
    const val REACTION_CHIP = "video_detail_reaction_chip"
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
    onCtaNavigate: (CtaDestination) -> Unit = {},
    modifier: Modifier = Modifier,
    viewModel: VideoDetailViewModel = hiltViewModel(),
    rentalViewModel: VodRentalViewModel = hiltViewModel(),
    purchaseViewModel: PurchaseViewModel = hiltViewModel(),
    tipViewModel: VideoTipViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val rentalState by rentalViewModel.state.collectAsStateWithLifecycle()
    val purchaseState by purchaseViewModel.uiState.collectAsStateWithLifecycle()
    val tipState by tipViewModel.state.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    // B-VIDSOCIAL2 — surface tip snackbars + push the new running tip total into the detail header.
    LaunchedEffect(tipViewModel) {
        tipViewModel.effects.collect { e -> if (e is TipEffect.ShowSnackbar) snackbarHostState.showSnackbar(e.message) }
    }
    LaunchedEffect(tipViewModel) {
        tipViewModel.tipTotals.collect { total -> viewModel.applyTipTotal(total) }
    }

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

    // #6 — fullscreen toggle for the VOD player. The SAME lifecycle-scoped controller (one ExoPlayer)
    // is reused: when fullscreen is on we render the reused [VideoPlayer] in a full-screen Dialog and
    // hide the inline surface, so playback position is preserved and there is never a second player.
    var isFullscreen by remember { mutableStateOf(false) }
    VideoDetailScreen(
        state = state,
        playerContent = { playerModifier ->
            // Reuse the AND-166/168 player surface + controls; no second player, no eager ExoPlayer.
            // While fullscreen, the inline slot collapses to the poster backdrop (the Dialog owns the
            // single PlayerView) so the one ExoPlayer is never bound to two surfaces at once.
            if (!isFullscreen) {
                // ADV — ad-aware surface: plays the pre-roll creative + AdOverlay for an ad_supported
                // title, then the SAME controller streams the content once the pre-roll is reported.
                DetailAdAwarePlayer(
                    state = state,
                    controller = viewModel.controller,
                    onAdPosition = viewModel::onAdPosition,
                    onAdCompleted = viewModel::onAdCompleted,
                    onSkipAd = viewModel::onSkipAd,
                    onFullscreenToggle = { isFullscreen = true },
                    onCta = { action ->
                        // ADV2-210 (F2): money side (CPC + CPA stash / tip = no charge) then route.
                        viewModel.onCtaTap(action)
                        if (action.isTip) {
                            state.detail?.id?.let { tipViewModel.open(it) }
                        } else {
                            onCtaNavigate(
                                AdCtaRouter.destinationFor(action, state.detail?.ownerUserId ?: ""),
                            )
                        }
                    },
                    modifier = playerModifier,
                )
            } else {
                androidx.compose.foundation.layout.Box(
                    playerModifier.background(Color.Black).testTag(VideoDetailTestTags.PLAYER),
                )
            }
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
        onToggleReaction = viewModel::toggleReaction,
        onTip = { state.detail?.id?.let { tipViewModel.open(it) } },
        onOpenVideo = onOpenVideo,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )

    // B-VIDSOCIAL2 — the reused feed tip sheet, pointed at the video tip endpoint.
    TipSheet(
        state = tipState,
        onSelectPreset = tipViewModel::selectPreset,
        onCustomAmount = tipViewModel::setCustomAmount,
        onSend = tipViewModel::send,
        onDismiss = tipViewModel::dismiss,
        onVisibility = tipViewModel::setVisibility,
    )

    // #6 — full-screen overlay reusing the SAME controller; dismiss returns to the inline surface.
    if (isFullscreen) {
        Dialog(
            onDismissRequest = { isFullscreen = false },
            properties = DialogProperties(usePlatformDefaultWidth = false),
        ) {
            Box(Modifier.fillMaxSize().background(Color.Black)) {
                VideoPlayer(
                    controller = viewModel.controller,
                    modifier = Modifier.fillMaxSize().testTag("video_detail_fullscreen_player"),
                    config = VideoPlayerControlsConfig(showFullscreen = true),
                    isFullscreen = true,
                    onFullscreenToggle = { isFullscreen = false },
                )
            }
        }
    }
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
    onToggleReaction: (emoji: String) -> Unit = {},
    onTip: () -> Unit = {},
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
    monetizationContent: @Composable () -> Unit = {},
) {
    Scaffold(
        modifier = modifier.testTag(VideoDetailTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
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
                    onToggleReaction = onToggleReaction,
                    onTip = onTip,
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
    onToggleReaction: (emoji: String) -> Unit,
    onTip: () -> Unit,
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
                // B-VIDSOCIAL2 — tip the creator (feed-post parity). Hidden on your own video.
                if (!state.isMine) {
                    IconButton(
                        onClick = onTip,
                        modifier = Modifier.testTag(VideoDetailTestTags.TIP),
                    ) {
                        Icon(
                            imageVector = Icons.Filled.AttachMoney,
                            contentDescription = stringResource(R.string.tip_send),
                        )
                    }
                }
                if (state.tipTotalCents > 0) {
                    Text(
                        text = formatCents(state.tipTotalCents) + " tipped",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            // B-VIDSOCIAL2 — video-level emoji reactions (feed-post parity).
            VideoReactionsRow(
                reactions = state.reactions,
                myReactions = state.myReactions,
                onToggleReaction = onToggleReaction,
            )

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

/**
 * B-VIDSOCIAL2 — emoji reaction chips + an add-reaction picker for the video, mirroring the feed
 * post / video-comment reaction row. Tapping a chip toggles that reaction; the picker adds a new one.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun VideoReactionsRow(
    reactions: Map<String, Int>,
    myReactions: Set<String>,
    onToggleReaction: (emoji: String) -> Unit,
) {
    var showPicker by remember { mutableStateOf(false) }
    val allowed = listOf("\uD83D\uDC4D", "\u2764\uFE0F", "\uD83D\uDE02", "\uD83D\uDD25", "\uD83D\uDE2E")
    FlowRow(
        modifier = Modifier.fillMaxWidth().padding(top = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        reactions.forEach { (emoji, count) ->
            val mine = emoji in myReactions
            Surface(
                color = if (mine) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .testTag(VideoDetailTestTags.REACTION_CHIP)
                    .clickable { onToggleReaction(emoji) },
            ) {
                Text(
                    text = "$emoji $count",
                    style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                )
            }
        }
        Box {
            IconButton(
                onClick = { showPicker = true },
                modifier = Modifier.size(32.dp).testTag(VideoDetailTestTags.REACT),
            ) {
                Icon(
                    Icons.Filled.AddReaction,
                    contentDescription = "Add reaction",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(18.dp),
                )
            }
            DropdownMenu(expanded = showPicker, onDismissRequest = { showPicker = false }) {
                Row(Modifier.padding(horizontal = 4.dp)) {
                    allowed.forEach { emoji ->
                        androidx.compose.material3.TextButton(
                            onClick = { showPicker = false; onToggleReaction(emoji) },
                        ) { Text(emoji, style = MaterialTheme.typography.titleMedium) }
                    }
                }
            }
        }
    }
}

/** Formats whole cents as a $-amount (e.g. 500 -> "$5.00"). */
private fun formatCents(cents: Int): String {
    val dollars = cents / 100
    val rem = cents % 100
    return "$" + dollars + "." + rem.toString().padStart(2, '0')
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
