package com.testlogon.android.feature.messaging.media

import android.content.Intent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Fullscreen
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.IconButton
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.testlogon.android.BuildConfig
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
import coil.compose.rememberAsyncImagePainter
import coil.decode.VideoFrameDecoder
import coil.request.ImageRequest
import coil.request.videoFrameMillis
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
    // #19 — tapping a video message opens it FULL-SCREEN (reuses the shared player dialog below).
    var fullScreen by remember(video.videoId) { mutableStateOf(false) }

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
                // #19 — primary tap opens FULL-SCREEN playback (matches the image full-screen viewer
                // pattern); long-form library video plays best full-bleed.
                Icon(
                    imageVector = Icons.Filled.PlayCircle,
                    contentDescription = playLabel,
                    tint = Color.White,
                    modifier = Modifier
                        .size(64.dp)
                        .clickable { fullScreen = true }
                        .semantics { role = Role.Button; contentDescription = playLabel },
                )
                // Secondary affordance: play INLINE in the bubble (top-right expand glyph inverted).
                Icon(
                    imageVector = Icons.Filled.Fullscreen,
                    contentDescription = playLabel,
                    tint = Color.White,
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(6.dp)
                        .size(28.dp)
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

    if (fullScreen && manifestUrl != null) {
        FullScreenVideoViewer(url = manifestUrl, onDismiss = { fullScreen = false })
    }
}

/**
 * AND-131 — appends the short-lived playback token to the HLS manifest (mirrors VideoShareCard).
 * Delegates to the shared, JVM-tested [com.testlogon.android.feature.player.MediaSourceResolver.tokenizedManifestUrl]
 * (AND-167) so the token-append rule lives in one place.
 */
internal fun MessageMedia.VideoShare.tokenizedManifestUrl(): String? =
    com.testlogon.android.feature.player.MediaSourceResolver.tokenizedManifestUrl(
        manifestUrl = hlsManifestUrl,
        playbackToken = playbackToken,
    )

// ==================== MV2: uploaded short-video clip bubble ====================

/** MV2 — stable testTags for the uploaded video-clip bubble. */
object VideoClipTestTags {
    const val BUBBLE = "video_clip_bubble"
    const val POSTER = "video_clip_poster"
    const val PLAY = "video_clip_play"
    const val FULLSCREEN = "video_clip_fullscreen"
    const val PLAYER = "video_clip_player"
    const val VIEWER = "video_clip_viewer"
    const val VIEWER_CLOSE = "video_clip_viewer_close"
}

/**
 * MV2 — an uploaded SHORT video clip (kind="video"). Renders a poster (first frame, decoded by Coil's
 * VideoFrameDecoder from the object url) with a play glyph. Tapping the play glyph plays it INLINE in
 * the bubble (lifecycle-scoped ExoPlayer, released on dispose); the expand glyph opens a FULL-SCREEN
 * player. While an optimistic outbox row is still uploading ([uploadProgress] != null) only the local
 * poster + a progress ring show.
 *
 * The ExoPlayer is created per-cell via [remember] and RELEASED on disposal — never an eager singleton.
 */
@OptIn(UnstableApi::class)
@Composable
fun VideoClipBubble(
    media: MessageMedia.VideoClip,
    modifier: Modifier = Modifier,
) {
    val source = media.playbackUrl ?: media.localUri
    val uploading = media.uploadProgress != null && media.uploadProgress < 1f
    val canPlay = media.playbackUrl != null && !uploading

    var playingInline by remember(source) { mutableStateOf(false) }
    var fullScreen by remember(source) { mutableStateOf(false) }

    val context = LocalContext.current
    // RG20 — resolve a server-relative ("/mock/s3/...") object url the SAME way ExoPlayer does, so the
    // poster frame decodes from the exact bytes that will play. (The app ImageLoader also maps relative
    // urls, but resolving here is explicit and lets us attach VideoFrameDecoder + a first-frame request.)
    val posterModel = remember(source) {
        source?.let { if (it.startsWith("/")) BuildConfig.API_BASE_URL.trimEnd('/') + it else it }
    }
    // RG20 — an EXPLICIT request that forces the video-frame decoder + the first keyframe, with a
    // painter state we can observe so we can keep a dark backdrop (never a blank/transparent bubble)
    // until the frame is ready, and surface the play glyph regardless of decode outcome.
    val posterPainter = rememberAsyncImagePainter(
        model = ImageRequest.Builder(context)
            .data(posterModel)
            .videoFrameMillis(0L)
            .decoderFactory(VideoFrameDecoder.Factory())
            .crossfade(true)
            .build(),
    )

    Box(
        modifier = modifier
            .aspectRatio(16f / 9f)
            .background(Color.Black)
            .testTag(VideoClipTestTags.BUBBLE),
        contentAlignment = Alignment.Center,
    ) {
        if (playingInline && canPlay) {
            ClipExoPlayer(
                url = media.playbackUrl!!,
                autoPlay = true,
                modifier = Modifier.fillMaxSize().testTag(VideoClipTestTags.PLAYER),
            )
        } else {
            // Poster: a video frame decoded from the (remote or local) source via VideoFrameDecoder,
            // painted over a black backdrop so the bubble is NEVER blank (RG20) — even while the frame
            // is still decoding or if decode fails, the dark poster + play glyph are visible.
            androidx.compose.foundation.Image(
                painter = posterPainter,
                contentDescription = stringResource(R.string.video_thumbnail_cd),
                contentScale = ContentScale.Crop,
                modifier = Modifier
                    .fillMaxSize()
                    .testTag(VideoClipTestTags.POSTER),
            )
            if (uploading) {
                CircularProgressIndicator(
                    color = Color.White,
                    modifier = Modifier.size(40.dp),
                )
            } else if (canPlay) {
                val playLabel = stringResource(R.string.video_play)
                Icon(
                    imageVector = Icons.Filled.PlayCircle,
                    contentDescription = playLabel,
                    tint = Color.White,
                    modifier = Modifier
                        .size(64.dp)
                        .clickable { playingInline = true }
                        .semantics { role = Role.Button; contentDescription = playLabel }
                        .testTag(VideoClipTestTags.PLAY),
                )
                // Expand-to-fullscreen affordance (top-right).
                Icon(
                    imageVector = Icons.Filled.Fullscreen,
                    contentDescription = "Play full screen",
                    tint = Color.White,
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(6.dp)
                        .size(28.dp)
                        .clickable { fullScreen = true }
                        .semantics { role = Role.Button; contentDescription = "Play full screen" }
                        .testTag(VideoClipTestTags.FULLSCREEN),
                )
            }
        }
    }

    if (fullScreen && media.playbackUrl != null) {
        FullScreenVideoViewer(url = media.playbackUrl, onDismiss = { fullScreen = false })
    }
}

/**
 * MV2 — a lifecycle-scoped ExoPlayer rendered in a [PlayerView]. Pauses on ON_PAUSE, stops on ON_STOP,
 * and releases on disposal.
 */
@OptIn(UnstableApi::class)
@Composable
private fun ClipExoPlayer(
    url: String,
    autoPlay: Boolean,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val resolved = remember(url) {
        if (url.startsWith("/")) BuildConfig.API_BASE_URL.trimEnd('/') + url else url
    }
    val player = remember(resolved) {
        ExoPlayer.Builder(context).build().apply {
            setMediaItem(MediaItem.fromUri(resolved))
            prepare()
            playWhenReady = autoPlay
        }
    }
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
        factory = { ctx -> PlayerView(ctx).apply { this.player = player; useController = true } },
        modifier = modifier,
    )
}

/** MV2 — full-screen video player dialog for an uploaded clip. */
@OptIn(UnstableApi::class)
@Composable
private fun FullScreenVideoViewer(url: String, onDismiss: () -> Unit) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black)
                .testTag(VideoClipTestTags.VIEWER),
            contentAlignment = Alignment.Center,
        ) {
            ClipExoPlayer(url = url, autoPlay = true, modifier = Modifier.fillMaxSize())
            IconButton(
                onClick = onDismiss,
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .padding(8.dp)
                    .testTag(VideoClipTestTags.VIEWER_CLOSE),
            ) {
                Icon(Icons.Filled.Close, contentDescription = "Close", tint = Color.White)
            }
        }
    }
}

