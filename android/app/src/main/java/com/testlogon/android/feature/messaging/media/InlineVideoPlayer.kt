package com.testlogon.android.feature.messaging.media

import android.content.Intent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PlayCircle
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.net.toUri
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.media3.common.MediaItem
import androidx.media3.common.util.UnstableApi
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.ui.PlayerView
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.data.messaging.MessageMedia

/** Stable testTags for the inline video player (AND-131). */
object InlineVideoTestTags {
    const val POSTER = "video_poster"
    const val PLAYER = "video_player"
    const val OPEN_EXTERNAL = "video_open_external"
}

/**
 * AND-131 — inline video-share cell. Shows the server poster + a play overlay until tapped, then
 * builds an HLS [MediaItem] from `hls_manifest_url` with `?token=<playback_token>` (mirroring the web
 * VideoShareCard) and plays it in-bubble.
 *
 * The [ExoPlayer] is created per-cell via [remember] and RELEASED on composable disposal — it is
 * never an eager singleton @Provides. A lifecycle observer pauses on ON_PAUSE and releases on
 * ON_STOP. Degraded paths (no manifest, or DRM) fall back to "Open externally".
 */
@OptIn(UnstableApi::class)
@Composable
fun InlineVideoPlayer(
    video: MessageMedia.VideoShare,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val aspect = remember(video.width, video.height) {
        val w = video.width ?: 16
        val h = video.height ?: 9
        if (w > 0 && h > 0) w.toFloat() / h.toFloat() else 16f / 9f
    }

    val manifestUrl = remember(video.hlsManifestUrl, video.playbackToken) { video.tokenizedManifestUrl() }
    val canPlayInline = manifestUrl != null && !video.drmEnabled

    var playing by remember(video.videoId) { mutableStateOf(false) }

    Box(
        modifier = modifier
            .aspectRatio(aspect)
            .testTag(InlineVideoTestTags.PLAYER),
        contentAlignment = Alignment.Center,
    ) {
        if (playing && canPlayInline) {
            val player = remember(manifestUrl) {
                ExoPlayer.Builder(context).build().apply {
                    setMediaItem(MediaItem.fromUri(manifestUrl!!))
                    prepare()
                    playWhenReady = true
                }
            }

            // Pause on ON_PAUSE; release on dispose / ON_STOP (lifecycle-scoped, not a singleton).
            val lifecycleOwner = LocalLifecycleOwner.current
            DisposableEffect(lifecycleOwner, player) {
                val observer = LifecycleEventObserver { _, event ->
                    when (event) {
                        Lifecycle.Event.ON_PAUSE -> player.pause()
                        Lifecycle.Event.ON_STOP -> player.playWhenReady = false
                        else -> Unit
                    }
                }
                lifecycleOwner.lifecycle.addObserver(observer)
                onDispose {
                    lifecycleOwner.lifecycle.removeObserver(observer)
                    player.release()
                }
            }

            AndroidView(
                factory = { ctx ->
                    PlayerView(ctx).apply {
                        this.player = player
                        useController = true
                    }
                },
                modifier = Modifier.fillMaxSize(),
            )
        } else {
            // Poster + play overlay (or "Open externally" in a degraded/DRM case).
            AsyncImage(
                model = video.thumbnailUrl,
                contentDescription = stringResource(R.string.video_thumbnail_cd),
                modifier = Modifier
                    .fillMaxSize()
                    .testTag(InlineVideoTestTags.POSTER),
            )
            if (canPlayInline) {
                val playLabel = stringResource(R.string.video_play)
                Icon(
                    imageVector = Icons.Filled.PlayCircle,
                    contentDescription = playLabel,
                    tint = Color.White,
                    modifier = Modifier
                        .size(64.dp)
                        .clickable { playing = true }
                        .semantics { role = Role.Button; contentDescription = playLabel },
                )
            } else {
                val externalLabel = stringResource(R.string.video_open_externally)
                Text(
                    text = externalLabel,
                    color = Color.White,
                    style = MaterialTheme.typography.labelLarge,
                    modifier = Modifier
                        .testTag(InlineVideoTestTags.OPEN_EXTERNAL)
                        .clickable {
                            val target = manifestUrl ?: video.thumbnailUrl
                            if (target != null) {
                                runCatching {
                                    context.startActivity(Intent(Intent.ACTION_VIEW, target.toUri()))
                                }
                            }
                        }
                        .semantics { role = Role.Button; contentDescription = externalLabel },
                )
            }
        }
    }
}

/** AND-131 — appends the short-lived playback token to the HLS manifest (mirrors VideoShareCard). */
internal fun MessageMedia.VideoShare.tokenizedManifestUrl(): String? {
    val base = hlsManifestUrl ?: return null
    val token = playbackToken ?: return base
    val sep = if (base.contains("?")) "&" else "?"
    return "$base${sep}token=$token"
}
