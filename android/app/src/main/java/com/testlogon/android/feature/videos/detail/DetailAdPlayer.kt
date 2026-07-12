package com.testlogon.android.feature.videos.detail

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import coil.compose.AsyncImage
import com.testlogon.android.data.ads.CtaAction
import com.testlogon.android.feature.ads.cta.AdCtaBar
import com.testlogon.android.feature.player.VideoPlayer
import com.testlogon.android.feature.player.VideoPlayerController
import com.testlogon.android.feature.vod.adsupported.AdOverlay
import com.testlogon.android.feature.vod.adsupported.AdOverlayTestTags
import com.testlogon.android.feature.vod.adsupported.AdSupportedUiState
import com.testlogon.android.feature.vod.adsupported.PlaybackPhase
import kotlinx.coroutines.delay
import com.testlogon.android.feature.player.PlaybackPhase as PlayerPlaybackPhase

/** ADV — the ad chrome tags reused on the normal detail player, so verification can target the pre-roll. */
object DetailAdPlayerTestTags {
    const val AD_IMAGE = "video_detail_ad_image"
    const val AD_VIDEO = "video_detail_ad_video"
}

private const val POSITION_SAMPLE_MS = 200L
private const val CREATIVE_VIDEO = "video"

/**
 * ADV — the ad-aware player surface for the NORMAL video-detail screen. It is the same reused
 * [VideoPlayer] (one lifecycle-scoped ExoPlayer) that plays the main content; when
 * [VideoDetailUiState.adActive] it instead renders the pre-roll creative (image via Coil, or video on
 * the shared controller) with the reused [AdOverlay] skip-after-N countdown. The content stays GATED
 * (VM.contentGated) until the pre-roll is reported complete/skipped, at which point the ViewModel binds
 * the content to this SAME controller. The rest of the detail screen — comments, likes, reactions, tip
 * — remains composed underneath the whole time, so the viewer can engage during and after the ad.
 */
@Composable
fun DetailAdAwarePlayer(
    state: VideoDetailUiState,
    controller: VideoPlayerController,
    onAdPosition: (Long) -> Unit,
    onAdCompleted: () -> Unit,
    onSkipAd: () -> Unit,
    onFullscreenToggle: () -> Unit,
    onCta: (CtaAction) -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val br = state.adBreak
    val isAd = state.adActive && br != null
    val isImageAd = isAd && br!!.creativeType != CREATIVE_VIDEO
    val isVideoAd = isAd && br!!.creativeType == CREATIVE_VIDEO

    // Bind the ad creative to the ONE reused controller exactly once per transition. Content binding is
    // owned by the ViewModel (it flips the gate + prepares the content on this same controller).
    val bindKey = when {
        isVideoAd -> "advideo:" + br!!.breakId
        isImageAd -> "adimage:" + br!!.breakId
        else -> "content"
    }
    LaunchedEffect(bindKey) {
        when {
            isVideoAd -> controller.setMediaUri(br!!.creativeUrl, autoPlay = true)
            isImageAd -> controller.pause() // image ad has no player media; don't bleed content through
            else -> Unit
        }
    }

    // Drive the ad countdown. Image creatives have no player timeline → wall clock; video creatives feed
    // the shared controller position and complete on ENDED.
    if (isImageAd && br != null) {
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
    } else if (isVideoAd && br != null) {
        LaunchedEffect(br.breakId) {
            while (true) {
                val ps = controller.state.value
                onAdPosition(ps.positionMs)
                if (ps.phase == PlayerPlaybackPhase.ENDED) {
                    onAdCompleted()
                    break
                }
                delay(POSITION_SAMPLE_MS)
            }
        }
    }

    Box(modifier = modifier) {
        if (isImageAd && br != null) {
            AsyncImage(
                model = br.creativeUrl,
                contentDescription = null,
                contentScale = ContentScale.Fit,
                modifier = Modifier.fillMaxSize().testTag(DetailAdPlayerTestTags.AD_IMAGE),
            )
        } else {
            VideoPlayer(
                controller = controller,
                modifier = Modifier
                    .fillMaxSize()
                    .testTag(if (isVideoAd) DetailAdPlayerTestTags.AD_VIDEO else VideoDetailTestTags.PLAYER),
                isFullscreen = false,
                onFullscreenToggle = { onFullscreenToggle() },
            )
        }

        if (isAd && br != null) {
            AdOverlay(
                state = AdSupportedUiState.Ready(
                    contentUrl = "",
                    phase = PlaybackPhase.AD,
                    currentBreak = br,
                    adRemainingMs = state.adRemainingMs,
                    skipEnabled = state.adSkipEnabled,
                    skipCountdownMs = state.adSkipCountdownMs,
                    playbackUnlocked = false,
                    nextRequiredBreakId = null,
                    breaksCompleted = state.adBreaksCompleted,
                    breaksTotal = state.adBreaksTotal,
                    adsFree = false,
                ),
                onSkip = onSkipAd,
                modifier = Modifier.fillMaxSize().testTag(AdOverlayTestTags.SKIP + "_container"),
            )
            // ADV2-210 (F2) — the structured click-through CTA bar over the pre-roll. Buy/subscribe
            // taps fire CPC + stash the ad_click_id for CPA; tip deep-links with no advertiser charge.
            AdCtaBar(
                ctas = br.ctas,
                onCta = onCta,
                modifier = Modifier
                    .align(Alignment.BottomStart)
                    .fillMaxWidth()
                    .padding(start = 12.dp, end = 12.dp, bottom = 64.dp),
            )
        }
    }
}
