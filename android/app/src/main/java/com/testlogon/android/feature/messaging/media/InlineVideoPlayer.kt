package com.testlogon.android.feature.messaging.media

import android.content.Intent
import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Download
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
import androidx.compose.material.icons.filled.PictureInPictureAlt
import androidx.compose.material.icons.filled.PlayCircle
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
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
import kotlinx.coroutines.launch

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

            // #8 — register inline HLS playback as the active video for system PiP auto-enter.
            val pip = com.testlogon.android.feature.player.LocalPipController.current
            DisposableEffect(player) {
                // FAIL #7/#8 — register THIS ExoPlayer so an auto-enter PiP (Home) collapses to the
                // video, not the thread.
                pip.setVideoActive(true, player, 16, 9)
                onDispose { pip.setVideoActive(false, player) }
            }
            // Pause on ON_PAUSE; release on dispose / ON_STOP (lifecycle-scoped, not a singleton).
            val lifecycleOwner = LocalLifecycleOwner.current
            DisposableEffect(lifecycleOwner, player) {
                val observer = LifecycleEventObserver { _, event ->
                    when (event) {
                        // FAIL #7/#8 — keep playing while entering/in PiP (the floating window IS the
                        // video). pip.enteringPip is set before onPause fires on Home->PiP.
                        Lifecycle.Event.ON_PAUSE -> if (!pip.isPipRetained(player)) player.pause()
                        Lifecycle.Event.ON_STOP -> if (!pip.isPipRetained(player)) { player.playWhenReady = false }
                        else -> Unit
                    }
                }
                lifecycleOwner.lifecycle.addObserver(observer)
                onDispose {
                    lifecycleOwner.lifecycle.removeObserver(observer)
                    // FAIL #7/#8 — if this player is retained for the PiP window, the controller owns
                    // its release (on PiP exit); releasing here would blank the floating video.
                    if (pip.isPipRetained(player)) pip.deferPipRelease(player) else player.release()
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
    const val VIEWER_SAVE = "video_clip_viewer_save"
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
    // #5/#6 — an optional gating tag rendered as a corner badge over the poster (mirrors ImageBubble's
    // `badge`): the SENDER's own locked/encrypted/view-once/expiring video shows e.g. "Locked $5.00",
    // "Encrypted", "View once" or "Disappears" so they can tell at a glance that they gated the clip.
    badge: String? = null,
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
            // #1 — keep full-screen reachable DURING inline playback. Before this, once you tapped the
            // inline play glyph the only controls were ExoPlayer's transport bar (no expand), so you
            // could no longer go full-screen. This overlay expand button stays available while playing.
            val fsLabel = stringResource(R.string.video_play)
            IconButton(
                onClick = { fullScreen = true },
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(4.dp)
                    .size(36.dp)
                    .background(Color.Black.copy(alpha = 0.45f), androidx.compose.foundation.shape.CircleShape)
                    .testTag(VideoClipTestTags.FULLSCREEN),
            ) {
                Icon(
                    imageVector = Icons.Filled.Fullscreen,
                    contentDescription = "Play full screen",
                    tint = Color.White,
                    modifier = Modifier.size(22.dp).semantics { contentDescription = fsLabel },
                )
            }
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
        // #5/#6 — gating tag for the SENDER's own gated video (locked/encrypted/view-once/expiring),
        // mirroring ImageBubble's badge so a video reads the same as a gated image. Shown over the
        // poster AND during playback (top-start, clear of the top-end expand control).
        if (badge != null) {
            Box(
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .padding(6.dp)
                    .background(Color.Black.copy(alpha = 0.55f), RoundedCornerShape(8.dp))
                    .padding(horizontal = 6.dp, vertical = 2.dp)
                    .testTag("video_clip_badge"),
            ) {
                Text(badge, color = Color.White, style = MaterialTheme.typography.labelSmall)
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
    // #8 — register this messaging video as the active video so pressing Home auto-enters system PiP
    // (and offer an explicit PiP control below). Cleared on dispose.
    val pip = com.testlogon.android.feature.player.LocalPipController.current
    DisposableEffect(player) {
        // FAIL #7/#8 — register THIS player as the active PiP video so both the explicit PiP control
        // below and an auto-enter on Home collapse the floating window to the VIDEO (not the
        // messaging thread / news feed that hosts this inline player).
        pip.setVideoActive(true, player, 16, 9)
        onDispose { pip.setVideoActive(false, player) }
    }
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner, player) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                // FAIL #7/#8 — keep playing while entering/in PiP.
                Lifecycle.Event.ON_PAUSE -> if (!pip.isPipRetained(player)) player.pause()
                Lifecycle.Event.ON_STOP -> if (!pip.isPipRetained(player)) { player.playWhenReady = false }
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            // FAIL #7/#8 — skip release while this player is shown in PiP (controller releases on exit).
            if (pip.isPipRetained(player)) pip.deferPipRelease(player) else player.release()
        }
    }
    Box(modifier = modifier, contentAlignment = Alignment.TopEnd) {
        AndroidView(
            factory = { ctx -> PlayerView(ctx).apply { this.player = player; useController = true } },
            modifier = Modifier.fillMaxSize(),
        )
        if (pip.isPipSupported) {
            IconButton(
                onClick = { pip.enterPipWith(player, 16, 9) },
                modifier = Modifier
                    .padding(4.dp)
                    .size(36.dp)
                    .background(Color.Black.copy(alpha = 0.45f), androidx.compose.foundation.shape.CircleShape)
                    .testTag("video_clip_pip"),
            ) {
                Icon(
                    imageVector = Icons.Filled.PictureInPictureAlt,
                    contentDescription = stringResource(R.string.player_pip),
                    tint = Color.White,
                    modifier = Modifier.size(22.dp),
                )
            }
        }
    }
}

/** MV2 — full-screen video player dialog for an uploaded clip. */
@OptIn(UnstableApi::class)
@Composable
private fun FullScreenVideoViewer(url: String, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var saving by remember { mutableStateOf(false) }
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
            // #2 — DOWNLOAD/save-to-device control in the full-screen player (mirrors the image viewer's
            // save action). Streams the clip bytes to MediaStore Movies/TestLogon (no runtime perm on
            // API29+). Disabled while a save is in flight.
            IconButton(
                enabled = !saving,
                onClick = {
                    saving = true
                    scope.launch {
                        val ok = saveVideoToGallery(context, url)
                        Toast.makeText(
                            context,
                            if (ok) "Saved to Movies" else "Couldn't save video",
                            Toast.LENGTH_SHORT,
                        ).show()
                        saving = false
                    }
                },
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(8.dp)
                    .testTag(VideoClipTestTags.VIEWER_SAVE),
            ) {
                Icon(Icons.Filled.Download, contentDescription = "Save to phone", tint = Color.White)
            }
        }
    }
}

/**
 * #25/#27 — public full-screen player for a gallery VIDEO item (an object url). Reuses the same
 * ExoPlayer-backed dialog as a video clip, so tapping a video tile inside a mixed gallery plays it.
 */
@Composable
fun GalleryVideoViewer(url: String, onDismiss: () -> Unit) {
    FullScreenVideoViewer(url = url, onDismiss = onDismiss)
}

/**
 * #2 — saves a (remote or server-relative) video clip url to the device gallery (MediaStore
 * Movies/TestLogon). On API29+ no runtime permission is needed (scoped storage + IS_PENDING). A
 * server-relative "/mock/s3/..." url is resolved against the API base the SAME way ExoPlayer does.
 * Best-effort; returns false on any failure. Self-contained (no VM/repo), like saveImageToGallery.
 */
internal suspend fun saveVideoToGallery(context: android.content.Context, url: String): Boolean =
    kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        runCatching {
            val resolved = if (url.startsWith("/")) BuildConfig.API_BASE_URL.trimEnd('/') + url else url
            val name = "TestLogon_" + resolved.substringAfterLast('/').substringBefore('?')
                .ifBlank { "video" }
                .let { if (it.endsWith(".mp4", true) || it.endsWith(".mov", true) || it.endsWith(".webm", true)) it else "$it.mp4" }
            val values = android.content.ContentValues().apply {
                put(android.provider.MediaStore.Video.Media.DISPLAY_NAME, name)
                put(android.provider.MediaStore.Video.Media.MIME_TYPE, "video/mp4")
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                    put(android.provider.MediaStore.Video.Media.RELATIVE_PATH, android.os.Environment.DIRECTORY_MOVIES + "/TestLogon")
                    put(android.provider.MediaStore.Video.Media.IS_PENDING, 1)
                }
            }
            val resolver = context.contentResolver
            val itemUri = resolver.insert(android.provider.MediaStore.Video.Media.EXTERNAL_CONTENT_URI, values)
                ?: return@runCatching false
            val conn = (java.net.URL(resolved).openConnection() as java.net.HttpURLConnection).apply {
                connectTimeout = 15000
                readTimeout = 30000
            }
            try {
                conn.inputStream.use { input ->
                    resolver.openOutputStream(itemUri)?.use { out -> input.copyTo(out) }
                        ?: return@runCatching false
                }
            } finally {
                conn.disconnect()
            }
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                values.clear()
                values.put(android.provider.MediaStore.Video.Media.IS_PENDING, 0)
                resolver.update(itemUri, values, null, null)
            }
            true
        }.getOrDefault(false)
    }

