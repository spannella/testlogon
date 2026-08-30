@file:OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)

package com.testlogon.android.feature.messaging.thread

import android.content.Intent
import android.net.Uri
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Place
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.SubcomposeAsyncImage
import com.testlogon.android.feature.messaging.LiveLocationModel
import com.testlogon.android.feature.messaging.LocationCardModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.flow

object LiveLocationCardTestTags {
    const val CARD = "thread_live_location_card"
    const val THUMB = "thread_live_location_card_thumb"
    const val THUMB_FALLBACK = "thread_live_location_card_thumb_fallback"
    const val LIVE_BADGE = "thread_live_location_live_badge"
    const val COUNTDOWN = "thread_live_location_countdown"
    const val OPEN = "thread_live_location_open"
    const val STOP = "thread_live_location_stop"
    const val ENDED = "thread_live_location_ended"
}

/**
 * FE-131 (EPIC D, BE-131) - the live-location chat card. Reuses the FE-130 static-map thumbnail
 * (which re-composes as [LiveLocationModel.LiveShare.lat]/lng change, so a relayed position update
 * moves the pin), a pulsing LIVE badge + a live 1s countdown to expiry, and "Open in Maps". The
 * SHARER ([isOwn]) also sees a "Stop sharing" button while the share is active. When the share is
 * stopped or expires the card flips to a static "Live location ended" state (auto-expiry needs no
 * round-trip - the 1s ticker crossing [LiveLocationModel.LiveShare.expiresAtSec] flips it).
 *
 * The 1s ticker is lifecycle-scoped (collectAsStateWithLifecycle pauses it below STARTED) - the same
 * no-leak idiom as [RevealLockedBubble] / the reveal countdown.
 *
 * @param onStop invoked when the sharer taps Stop (only rendered when [isOwn] AND active).
 */
@Composable
fun LiveLocationCard(
    share: LiveLocationModel.LiveShare,
    isOwn: Boolean,
    onStop: () -> Unit,
    modifier: Modifier = Modifier,
    nowProvider: () -> Long = { System.currentTimeMillis() / 1000L },
) {
    val context = LocalContext.current

    val now by remember(share.expiresAtSec, share.stoppedAtSec) {
        flow {
            while (true) {
                emit(nowProvider())
                delay(1_000L)
            }
        }
    }.collectAsStateWithLifecycle(initialValue = nowProvider())

    val active = LiveLocationModel.isLiveActive(share.expiresAtSec, share.stoppedAtSec, now)
    val remainingLabel = LiveLocationModel.liveRemainingLabel(share.expiresAtSec, share.stoppedAtSec, now)
    val coords = LocationCardModel.formatCoords(share.lat, share.lng)
    val primary = share.label?.takeIf { it.isNotBlank() } ?: "Live location"
    val cd = if (active) {
        "Live location, $remainingLabel, $coords"
    } else {
        "Live location ended, last seen $coords"
    }

    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = modifier
            .widthIn(max = 260.dp)
            .testTag(LiveLocationCardTestTags.CARD)
            .semantics { contentDescription = cd },
    ) {
        Column {
            Box {
                SubcomposeAsyncImage(
                    // Re-composes when lat/lng change -> the pin moves as updates arrive.
                    model = LocationCardModel.staticMapThumbUrl(share.lat, share.lng),
                    contentDescription = null,
                    contentScale = ContentScale.Crop,
                    loading = { MapThumbPlaceholderLive() },
                    error = { MapThumbPlaceholderLive() },
                    modifier = Modifier
                        .fillMaxWidth()
                        .aspectRatio(2f)
                        .testTag(LiveLocationCardTestTags.THUMB),
                )
                if (active) {
                    LivePulseBadge(
                        modifier = Modifier
                            .align(Alignment.TopStart)
                            .padding(8.dp),
                    )
                }
            }
            Column(Modifier.padding(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Filled.Place,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp),
                    )
                    Text(
                        primary,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.padding(start = 6.dp),
                    )
                }
                Text(
                    text = if (active) remainingLabel else "Live location ended",
                    style = MaterialTheme.typography.bodySmall,
                    color = if (active) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    modifier = Modifier
                        .padding(top = 2.dp, start = 24.dp)
                        .testTag(if (active) LiveLocationCardTestTags.COUNTDOWN else LiveLocationCardTestTags.ENDED),
                )
                Row(
                    Modifier.fillMaxWidth().padding(top = 10.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OutlinedButton(
                        onClick = { openLiveMaps(context, share) },
                        modifier = Modifier.weight(1f).testTag(LiveLocationCardTestTags.OPEN),
                    ) { Text("Open in Maps") }
                    if (isOwn && active) {
                        OutlinedButton(
                            onClick = onStop,
                            modifier = Modifier.testTag(LiveLocationCardTestTags.STOP),
                        ) {
                            Icon(Icons.Filled.Stop, contentDescription = "Stop sharing", modifier = Modifier.size(18.dp))
                            Text("  Stop")
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LivePulseBadge(modifier: Modifier = Modifier) {
    val transition = rememberInfiniteTransition(label = "live_pulse")
    val alpha by transition.animateFloat(
        initialValue = 1f,
        targetValue = 0.35f,
        animationSpec = infiniteRepeatable(
            animation = tween(700),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "live_pulse_alpha",
    )
    Surface(
        color = Color(0xFFD32F2F),
        shape = RoundedCornerShape(8.dp),
        modifier = modifier.testTag(LiveLocationCardTestTags.LIVE_BADGE),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
        ) {
            Box(
                Modifier
                    .size(8.dp)
                    .alpha(alpha)
                    .clip(CircleShape)
                    .background(Color.White),
            )
            Text(
                "LIVE",
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                color = Color.White,
                modifier = Modifier.padding(start = 6.dp),
            )
        }
    }
}

@Composable
private fun MapThumbPlaceholderLive() {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.secondaryContainer)
            .testTag(LiveLocationCardTestTags.THUMB_FALLBACK),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            Icons.Filled.Place,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(40.dp),
        )
    }
}

private fun openLiveMaps(context: android.content.Context, share: LiveLocationModel.LiveShare) {
    val geo = LocationCardModel.geoUri(share.lat, share.lng)
    val web = LocationCardModel.mapsOpenUrl(share.lat, share.lng, share.label)
    val ok = runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(geo))) }.isSuccess
    if (!ok) runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(web))) }
}
