package com.testlogon.android.feature.videos

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImage
import androidx.compose.foundation.Image
import androidx.compose.ui.platform.LocalContext
import coil.compose.rememberAsyncImagePainter
import coil.decode.VideoFrameDecoder
import coil.request.ImageRequest
import coil.request.videoFrameMillis
import com.testlogon.android.R

/** AND-189 / AND-191 — stable test tags for the shared video grid tile. */
object VideoTileTestTags {
    const val TILE = "video_tile"
    const val THUMBNAIL = "video_tile_thumbnail"
    const val TITLE = "video_tile_title"
    const val DURATION = "video_tile_duration"
    const val STATUS = "video_tile_status"
}

/**
 * AND-189 / AND-191 — a reusable poster tile for the videos library and the VOD catalog. Shows a 16:9
 * Coil thumbnail with an optional mm:ss duration badge (bottom-end, RTL-safe) and the title below
 * (max 2 lines, ellipsized). The whole tile is a single focusable click target whose
 * contentDescription is the title; the duration badge is folded into the tile semantics.
 */
@Composable
fun VideoTile(
    title: String,
    thumbnailUrl: String?,
    durationSec: Int?,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    statusBadge: String? = null,
) {
    val durationBadge = VideoDurationFormat.badge(durationSec)
    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .testTag(VideoTileTestTags.TILE)
            .clearAndSetSemantics {
                contentDescription = if (statusBadge != null) "$title, $statusBadge" else title
            },
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(16f / 9f)
                .clip(RoundedCornerShape(8.dp))
                .background(MaterialTheme.colorScheme.surfaceVariant),
        ) {
            val isVideoThumb = remember(thumbnailUrl) {
                thumbnailUrl?.substringBefore('?')?.let { u ->
                    u.endsWith(".mp4", true) || u.endsWith(".mov", true) || u.endsWith(".webm", true) || u.endsWith(".m4v", true)
                } == true
            }
            if (isVideoThumb) {
                // B-VIDPLAY: thumbnail_url points at the uploaded mp4 object; decode its first frame.
                val context = LocalContext.current
                val poster = rememberAsyncImagePainter(
                    model = ImageRequest.Builder(context)
                        .data(thumbnailUrl)
                        .videoFrameMillis(0L)
                        .decoderFactory(VideoFrameDecoder.Factory())
                        .crossfade(true)
                        .build(),
                )
                Image(
                    painter = poster,
                    contentDescription = null,
                    contentScale = ContentScale.Crop,
                    modifier = Modifier
                        .fillMaxWidth()
                        .aspectRatio(16f / 9f)
                        .testTag(VideoTileTestTags.THUMBNAIL),
                )
            } else {
                AsyncImage(
                    model = thumbnailUrl,
                    contentDescription = null,
                    contentScale = ContentScale.Crop,
                    modifier = Modifier
                        .fillMaxWidth()
                        .aspectRatio(16f / 9f)
                        .testTag(VideoTileTestTags.THUMBNAIL),
                )
            }
            if (statusBadge != null) {
                Text(
                    text = statusBadge,
                    color = Color.White,
                    style = MaterialTheme.typography.labelSmall,
                    modifier = Modifier
                        .align(Alignment.TopStart)
                        .padding(6.dp)
                        .clip(RoundedCornerShape(4.dp))
                        .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.92f))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                        .testTag(VideoTileTestTags.STATUS),
                )
            }
            if (durationBadge != null) {
                Text(
                    text = durationBadge,
                    color = Color.White,
                    style = MaterialTheme.typography.labelSmall,
                    modifier = Modifier
                        .align(Alignment.BottomEnd)
                        .padding(6.dp)
                        .clip(RoundedCornerShape(4.dp))
                        .background(Color.Black.copy(alpha = 0.7f))
                        .padding(horizontal = 4.dp, vertical = 1.dp)
                        .testTag(VideoTileTestTags.DURATION),
                )
            }
        }
        Text(
            text = title.ifBlank { stringResource(R.string.video_untitled) },
            style = MaterialTheme.typography.bodyMedium,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 4.dp, vertical = 6.dp)
                .testTag(VideoTileTestTags.TITLE),
        )
    }
}
