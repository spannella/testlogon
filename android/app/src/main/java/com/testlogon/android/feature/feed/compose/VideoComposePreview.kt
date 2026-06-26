package com.testlogon.android.feature.feed.compose

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.media3.common.MediaItem
import androidx.media3.common.util.UnstableApi
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.ui.PlayerView
import coil.compose.rememberAsyncImagePainter
import coil.decode.VideoFrameDecoder
import coil.request.ImageRequest
import coil.request.videoFrameMillis

/**
 * #1 / #2 / FD20 — a shared local-video preview cell for the post composer + editor. Renders a REAL
 * first-frame thumbnail of a picked (local content uri) clip via Coil's [VideoFrameDecoder], a working
 * play button that opens a local full-screen ExoPlayer, an optional uploading spinner, and a remove "x".
 * Unlike the messaging VideoClipBubble (which only plays a server `playbackUrl`), this plays the LOCAL
 * uri directly, so a just-picked / replacement clip previews + plays before any upload completes.
 */
@Composable
fun LocalVideoPreviewCell(
    localUri: String,
    uploading: Boolean,
    onRemove: () -> Unit,
    modifier: Modifier = Modifier,
    testTag: String = "local_video_preview",
) {
    var playing by remember(localUri) { mutableStateOf(false) }
    Box(modifier = modifier.size(width = 140.dp, height = 96.dp).testTag(testTag)) {
        val ctx = LocalContext.current
        val framePainter = rememberAsyncImagePainter(
            model = ImageRequest.Builder(ctx)
                .data(localUri)
                .videoFrameMillis(0L)
                .decoderFactory(VideoFrameDecoder.Factory())
                .crossfade(true)
                .build(),
        )
        Image(
            painter = framePainter,
            contentDescription = "Video preview",
            contentScale = ContentScale.Crop,
            modifier = Modifier
                .fillMaxSize()
                .clip(RoundedCornerShape(12.dp))
                .background(Color.Black)
                .testTag(testTag + "_thumb"),
        )
        Icon(
            Icons.Filled.PlayArrow,
            contentDescription = "Play video",
            tint = Color.White,
            modifier = Modifier
                .align(Alignment.Center)
                .size(40.dp)
                .clickable { playing = true }
                .testTag(testTag + "_play"),
        )
        if (uploading) {
            CircularProgressIndicator(
                modifier = Modifier.align(Alignment.BottomEnd).padding(4.dp).size(18.dp),
                color = Color.White,
            )
        }
        Box(
            modifier = Modifier
                .align(Alignment.TopEnd)
                .padding(4.dp)
                .size(22.dp)
                .clip(CircleShape)
                .background(Color.Black.copy(alpha = 0.55f))
                .clickable(onClick = onRemove)
                .testTag(testTag + "_remove"),
            contentAlignment = Alignment.Center,
        ) {
            Icon(Icons.Filled.Close, contentDescription = "Remove", tint = Color.White, modifier = Modifier.size(14.dp))
        }
    }
    if (playing) {
        LocalVideoFullScreenPlayer(uri = localUri, onDismiss = { playing = false })
    }
}

/**
 * FD20 — a local full-screen player for a picked (not-yet-uploaded) video, so the preview's play button
 * actually plays. Lifecycle-scoped ExoPlayer, released on dismiss.
 */
@OptIn(UnstableApi::class)
@Composable
fun LocalVideoFullScreenPlayer(uri: String, onDismiss: () -> Unit) {
    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Box(Modifier.fillMaxSize().background(Color.Black), contentAlignment = Alignment.Center) {
            val ctx = LocalContext.current
            val player = remember(uri) {
                ExoPlayer.Builder(ctx).build().apply {
                    setMediaItem(MediaItem.fromUri(uri)); prepare(); playWhenReady = true
                }
            }
            val owner = LocalLifecycleOwner.current
            DisposableEffect(owner, player) {
                val obs = LifecycleEventObserver { _, e ->
                    when (e) {
                        Lifecycle.Event.ON_PAUSE -> player.pause()
                        Lifecycle.Event.ON_STOP -> player.playWhenReady = false
                        else -> Unit
                    }
                }
                owner.lifecycle.addObserver(obs)
                onDispose { owner.lifecycle.removeObserver(obs); player.release() }
            }
            AndroidView(
                factory = { c -> PlayerView(c).apply { this.player = player; useController = true } },
                modifier = Modifier.fillMaxSize().testTag("local_video_fullscreen"),
            )
            IconButton(
                onClick = onDismiss,
                modifier = Modifier.align(Alignment.TopStart).padding(8.dp),
            ) { Icon(Icons.Filled.Close, contentDescription = "Close", tint = Color.White) }
        }
    }
}
