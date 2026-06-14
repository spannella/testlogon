package com.testlogon.android.feature.feed

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.outlined.BrokenImage
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.unit.dp
import coil.compose.SubcomposeAsyncImage
import coil.request.ImageRequest
import androidx.compose.ui.platform.LocalContext
import com.testlogon.android.data.feed.Media
import com.testlogon.android.data.feed.MediaType

/** Stable test tags for feed media (AND-103). */
object FeedMediaTestTags {
    const val GRID = "feed_media_grid"
    const val CELL = "feed_media_cell"
    const val OVERFLOW = "feed_media_overflow"
    const val PLAY = "feed_media_play"
}

private const val MAX_VISIBLE = 4
private val CELL_RADIUS = 12.dp

/**
 * AND-103 — social-style media grid for a post.
 *  - 0: nothing
 *  - 1: single, max-height-bounded (object-cover via ContentScale.Crop)
 *  - 2: side-by-side 1:1
 *  - 3: top large 16:9 + two square below
 *  - 4: 2x2 1:1
 *  - 5+: 2x2 with a "+N" overlay on the 4th cell (N = count - 4)
 *
 * Coil's SubcomposeAsyncImage gives loading/error slots and disposes (cancels) the request when the
 * cell leaves composition — i.e. requests are cancelled on scroll. Video cells overlay a play icon.
 */
@Composable
fun FeedMediaGrid(
    media: List<Media>,
    modifier: Modifier = Modifier,
    onItemClick: (index: Int) -> Unit = {},
) {
    if (media.isEmpty()) return
    val spacing = 4.dp
    Column(
        modifier = modifier.fillMaxWidth().testTag(FeedMediaTestTags.GRID),
        verticalArrangement = Arrangement.spacedBy(spacing),
    ) {
        when (media.size) {
            1 -> MediaCell(media[0], 0, media.size, Modifier.fillMaxWidth().aspectRatio(4f / 3f), onItemClick)
            2 -> Row(horizontalArrangement = Arrangement.spacedBy(spacing)) {
                MediaCell(media[0], 0, media.size, Modifier.weight(1f).aspectRatio(1f), onItemClick)
                MediaCell(media[1], 1, media.size, Modifier.weight(1f).aspectRatio(1f), onItemClick)
            }
            3 -> {
                MediaCell(media[0], 0, media.size, Modifier.fillMaxWidth().aspectRatio(16f / 9f), onItemClick)
                Row(horizontalArrangement = Arrangement.spacedBy(spacing)) {
                    MediaCell(media[1], 1, media.size, Modifier.weight(1f).aspectRatio(1f), onItemClick)
                    MediaCell(media[2], 2, media.size, Modifier.weight(1f).aspectRatio(1f), onItemClick)
                }
            }
            else -> {
                Row(horizontalArrangement = Arrangement.spacedBy(spacing)) {
                    MediaCell(media[0], 0, media.size, Modifier.weight(1f).aspectRatio(1f), onItemClick)
                    MediaCell(media[1], 1, media.size, Modifier.weight(1f).aspectRatio(1f), onItemClick)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(spacing)) {
                    MediaCell(media[2], 2, media.size, Modifier.weight(1f).aspectRatio(1f), onItemClick)
                    MediaCell(media[3], 3, media.size, Modifier.weight(1f).aspectRatio(1f), onItemClick)
                }
            }
        }
    }
}

@Composable
private fun MediaCell(
    item: Media,
    index: Int,
    total: Int,
    modifier: Modifier = Modifier,
    onItemClick: (index: Int) -> Unit,
) {
    val isVideo = item.type == MediaType.VIDEO
    val overflow = if (index == MAX_VISIBLE - 1 && total > MAX_VISIBLE) total - MAX_VISIBLE else 0
    val cd = when {
        isVideo -> "Video"
        overflow > 0 -> "Image, $overflow more"
        else -> "Image"
    }
    val model = item.thumbnailUrl ?: item.url
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(CELL_RADIUS))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .clickable { onItemClick(index) }
            .testTag(FeedMediaTestTags.CELL)
            .clearAndSetSemantics { contentDescription = cd },
    ) {
        SubcomposeAsyncImage(
            model = ImageRequest.Builder(LocalContext.current).data(model).crossfade(true).build(),
            contentDescription = null,
            contentScale = ContentScale.Crop,
            modifier = Modifier.fillMaxSize(),
            loading = { ThumbnailPlaceholder() },
            error = { ThumbnailError() },
        )
        if (isVideo) {
            Box(
                modifier = Modifier
                    .align(Alignment.Center)
                    .size(44.dp)
                    .clip(RoundedCornerShape(50))
                    .background(Color.Black.copy(alpha = 0.5f))
                    .testTag(FeedMediaTestTags.PLAY),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Filled.PlayArrow, contentDescription = null, tint = Color.White)
            }
            item.durationSeconds?.let { secs ->
                Box(
                    modifier = Modifier
                        .align(Alignment.BottomEnd)
                        .clip(RoundedCornerShape(4.dp))
                        .background(Color.Black.copy(alpha = 0.6f)),
                ) {
                    Text(
                        text = formatDuration(secs),
                        style = MaterialTheme.typography.labelSmall,
                        color = Color.White,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                    )
                }
            }
        }
        if (overflow > 0) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(Color.Black.copy(alpha = 0.5f))
                    .testTag(FeedMediaTestTags.OVERFLOW),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = "+$overflow",
                    style = MaterialTheme.typography.titleLarge,
                    color = Color.White,
                )
            }
        }
    }
}

@Composable
private fun ThumbnailPlaceholder() {
    Box(modifier = Modifier.fillMaxSize().background(MaterialTheme.colorScheme.surfaceVariant))
}

@Composable
private fun ThumbnailError() {
    Box(
        modifier = Modifier.fillMaxSize().background(MaterialTheme.colorScheme.surfaceVariant),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            Icons.Outlined.BrokenImage,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(32.dp),
        )
    }
}

/** Seconds -> "m:ss" (e.g. 42 -> "0:42", 95 -> "1:35"). */
internal fun formatDuration(totalSeconds: Long): String {
    val s = if (totalSeconds < 0) 0 else totalSeconds
    val m = s / 60
    val rem = s % 60
    return "$m:${rem.toString().padStart(2, '0')}"
}
