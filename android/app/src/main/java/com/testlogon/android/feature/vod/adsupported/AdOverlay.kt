package com.testlogon.android.feature.vod.adsupported

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.testlogon.android.R

/** AND-194 — stable test tags for the ad overlay. */
object AdOverlayTestTags {
    const val BADGE = "avod_ad_badge"
    const val PROGRESS = "avod_ad_progress"
    const val SKIP = "avod_ad_skip"
}

/**
 * AND-194 — the ad overlay rendered over the reused player while [PlaybackPhase.AD]. Shows the "Ad"
 * badge, "Ad N of M", remaining time, and a skip countdown that becomes a "Skip Ad" button after the
 * break's skip offset. Stateless — driven by the [AdSupportedUiState.Ready] and a skip callback. The
 * skip control exposes a TalkBack contentDescription and a ≥48dp target (Material Button default).
 */
@Composable
fun AdOverlay(
    state: AdSupportedUiState.Ready,
    onSkip: () -> Unit,
    modifier: Modifier = Modifier,
) {
    if (state.phase != PlaybackPhase.AD) return
    val remainingSeconds = (state.adRemainingMs / 1000L).toInt()
    val skipSeconds = (state.skipCountdownMs / 1000L).toInt()

    Box(modifier = modifier.fillMaxSize().padding(12.dp)) {
        Column(
            modifier = Modifier.align(Alignment.TopStart),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = stringResource(R.string.avod_ad_badge),
                color = Color.White,
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier
                    .background(Color.Black.copy(alpha = 0.6f), MaterialTheme.shapes.small)
                    .padding(horizontal = 6.dp, vertical = 2.dp)
                    .testTag(AdOverlayTestTags.BADGE),
            )
            val progress = stringResource(
                R.string.avod_ad_progress,
                state.breaksCompleted + 1,
                state.breaksTotal.coerceAtLeast(1),
            )
            Text(
                text = progress,
                color = Color.White,
                style = MaterialTheme.typography.labelMedium,
                modifier = Modifier
                    .testTag(AdOverlayTestTags.PROGRESS)
                    .semantics {
                        contentDescription = progress
                        liveRegion = LiveRegionMode.Polite
                    },
            )
            Text(
                text = stringResource(R.string.avod_ad_remaining, remainingSeconds),
                color = Color.White,
                style = MaterialTheme.typography.labelSmall,
            )
        }

        val skipCd = if (state.skipEnabled) {
            stringResource(R.string.avod_skip_cd)
        } else {
            stringResource(R.string.avod_skip_disabled_cd, skipSeconds)
        }
        Button(
            onClick = onSkip,
            enabled = state.skipEnabled,
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .testTag(AdOverlayTestTags.SKIP)
                .semantics { contentDescription = skipCd },
        ) {
            Text(
                text = if (state.skipEnabled) {
                    stringResource(R.string.avod_skip_ad)
                } else {
                    stringResource(R.string.avod_skip_in, skipSeconds)
                },
            )
        }
    }
}
