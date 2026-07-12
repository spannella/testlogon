package com.testlogon.android.feature.common

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * #15 — the 1:1 DM avatar: TWO overlapping profile circles. The OTHER user's photo sits IN FRONT on
 * the LEFT; MY photo sits BEHIND on the RIGHT. Each circle falls back to a monogram (via [TlAvatar])
 * when its photo url is null/blank, and a thin ring separates the front circle from the one behind.
 *
 * The total footprint is [size] tall and ~1.5×[size] wide (the two circles overlap by ~half).
 */
@Composable
fun DmAvatarPair(
    peerName: String?,
    peerPhotoUrl: String?,
    myName: String?,
    myPhotoUrl: String?,
    modifier: Modifier = Modifier,
    size: Dp = 32.dp,
    ringColor: Color = MaterialTheme.colorScheme.surface,
) {
    // Each circle is slightly smaller than the row height so the ring + overlap read cleanly.
    val circle = size * 0.82f
    val overlap = circle * 0.55f
    val totalWidth = circle + (circle - overlap)

    Box(modifier = modifier.size(width = totalWidth, height = size)) {
        // BEHIND, on the RIGHT: my own photo.
        Box(
            modifier = Modifier
                .align(Alignment.CenterEnd)
                .size(circle)
                .clip(CircleShape),
        ) {
            TlAvatar(
                name = myName,
                photoUrl = myPhotoUrl,
                size = circle,
                textStyle = MaterialTheme.typography.labelSmall,
            )
        }
        // IN FRONT, on the LEFT: the other user's photo, with a ring to separate it from the one behind.
        Box(
            modifier = Modifier
                .align(Alignment.CenterStart)
                .size(circle)
                .clip(CircleShape)
                .background(ringColor)
                .border(width = 1.5.dp, color = ringColor, shape = CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            TlAvatar(
                name = peerName,
                photoUrl = peerPhotoUrl,
                size = circle,
                textStyle = MaterialTheme.typography.labelSmall,
            )
        }
    }
}
