package com.testlogon.android.feature.videos.upload

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Movie
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.focus.FocusManager
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import android.net.Uri
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.filled.PlayCircle
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
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

@Composable
fun VideoUploadRoute(
    onBack: () -> Unit,
    // #5 — reports the newly uploaded video (id + title) so the gallery can show it IMMEDIATELY as a
    // pending tile (even before the server finishes processing) instead of nothing until a manual
    // refresh. Defaults to a no-op so existing callers that only pop still compile.
    onUploaded: (videoId: String, title: String) -> Unit = { _, _ -> },
    viewModel: VideoUploadViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val context = androidx.compose.ui.platform.LocalContext.current
    androidx.compose.runtime.LaunchedEffect(state.uploadedVideoId) {
        val id = state.uploadedVideoId
        if (id != null) {
            onUploaded(id, state.title)
            onBack()
        }
    }
    val pickVideo = rememberLauncherForActivityResult(
        ActivityResultContracts.PickVisualMedia(),
    ) { uri -> if (uri != null) viewModel.onVideoPicked(uri, displayNameOf(context, uri)) }
    // SAF / system file manager (DocumentsUI) — an explicit "browse files" path that, unlike the
    // photo picker, opens a real file browser the user navigates to pick any video document.
    val browseVideo = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri -> if (uri != null) viewModel.onVideoPicked(uri, displayNameOf(context, uri)) }

    VideoUploadScreen(
        state = state,
        onBack = onBack,
        onPickVideo = {
            pickVideo.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.VideoOnly))
        },
        onBrowseFiles = { browseVideo.launch(arrayOf("video/*")) },
        onTitleChange = viewModel::onTitleChange,
        onDescriptionChange = viewModel::onDescriptionChange,
        onUpload = viewModel::upload,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VideoUploadScreen(
    state: VideoUploadUiState,
    onBack: () -> Unit,
    onPickVideo: () -> Unit,
    onBrowseFiles: () -> Unit = {},
    onTitleChange: (String) -> Unit,
    onDescriptionChange: (String) -> Unit,
    onUpload: () -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag("video_upload_screen"),
        topBar = {
            TopAppBar(
                title = { Text("Upload video") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    TextButton(
                        onClick = onUpload,
                        enabled = state.canUpload,
                        modifier = Modifier.testTag("video_upload_submit"),
                    ) { Text("Upload") }
                },
            )
        },
    ) { padding ->
        val focusManager = LocalFocusManager.current
        val keyboard = LocalSoftwareKeyboardController.current
        Column(
            Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp)
                // #4 — tap anywhere outside a text field clears focus + hides the IME so the
                // upload title/description boxes can be dismissed by clicking out.
                .pointerInput(Unit) {
                    detectTapGestures(onTap = { focusManager.clearFocus(); keyboard?.hide() })
                },
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            OutlinedButton(
                onClick = onPickVideo,
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp).testTag("video_upload_pick"),
            ) {
                Icon(Icons.Filled.Movie, contentDescription = null, modifier = Modifier.size(18.dp))
                Text(
                    state.fileName ?: "Select a video from your device",
                    modifier = Modifier.padding(start = 8.dp),
                )
            }

            OutlinedButton(
                onClick = onBrowseFiles,
                modifier = Modifier.fillMaxWidth().testTag("video_upload_browse"),
            ) {
                Icon(Icons.Filled.FolderOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                Text("Browse files", modifier = Modifier.padding(start = 8.dp))
            }

            // #7 — once a video is picked, show a PLAYABLE local preview of the selected content URI
            // (poster frame decoded by Coil's VideoFrameDecoder, tap-to-play a lifecycle-scoped
            // ExoPlayer) so the user confirms the right clip before/while it uploads — not just a name.
            state.pickedUri?.let { picked ->
                LocalVideoPreview(
                    uri = picked,
                    modifier = Modifier.fillMaxWidth().testTag("video_upload_preview"),
                )
            }

            OutlinedTextField(
                value = state.title,
                onValueChange = onTitleChange,
                modifier = Modifier.fillMaxWidth().testTag("video_upload_title"),
                label = { Text("Title") },
                singleLine = true,
            )
            OutlinedTextField(
                value = state.description,
                onValueChange = onDescriptionChange,
                modifier = Modifier.fillMaxWidth().testTag("video_upload_desc"),
                label = { Text("Description") },
                minLines = 3,
            )

            state.error?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
            if (state.uploading) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    CircularProgressIndicator(modifier = Modifier.size(22.dp))
                    Text("Uploading…", style = MaterialTheme.typography.bodyMedium)
                }
            }

            Button(
                onClick = onUpload,
                enabled = state.canUpload,
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp).testTag("video_upload_button"),
            ) { Text("Publish video") }

            Box(Modifier.fillMaxWidth().height(8.dp))
        }
    }
}

/** Resolves a content URI's human-readable file name (falls back to the last path segment). */
private fun displayNameOf(context: android.content.Context, uri: android.net.Uri): String? =
    runCatching {
        context.contentResolver.query(
            uri,
            arrayOf(android.provider.OpenableColumns.DISPLAY_NAME),
            null,
            null,
            null,
        )?.use { c -> if (c.moveToFirst()) c.getString(0) else null }
    }.getOrNull() ?: uri.lastPathSegment


/**
 * #7 — a self-contained PLAYABLE preview of a picked (content://) video URI. Shows a poster frame
 * (Coil [VideoFrameDecoder], first keyframe) over a black backdrop with a play overlay; tapping plays
 * the local clip inline in a lifecycle-scoped [ExoPlayer] that is RELEASED on disposal (never an eager
 * singleton). No network: it plays the picked content URI directly, so the user can confirm the right
 * file before/while it uploads.
 */
@OptIn(UnstableApi::class)
@Composable
private fun LocalVideoPreview(
    uri: String,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    var playing by remember(uri) { mutableStateOf(false) }
    val posterPainter = rememberAsyncImagePainter(
        model = ImageRequest.Builder(context)
            .data(uri)
            .videoFrameMillis(0L)
            .decoderFactory(VideoFrameDecoder.Factory())
            .crossfade(true)
            .build(),
    )
    Box(
        modifier = modifier
            .aspectRatio(16f / 9f)
            .clip(RoundedCornerShape(8.dp))
            .background(Color.Black),
        contentAlignment = Alignment.Center,
    ) {
        if (playing) {
            val player = remember(uri) {
                ExoPlayer.Builder(context).build().apply {
                    setMediaItem(MediaItem.fromUri(Uri.parse(uri)))
                    prepare()
                    playWhenReady = true
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
                modifier = Modifier.fillMaxSize().testTag("video_upload_preview_player"),
            )
        } else {
            Image(
                painter = posterPainter,
                contentDescription = "Selected video preview",
                contentScale = ContentScale.Crop,
                modifier = Modifier.fillMaxSize().testTag("video_upload_preview_poster"),
            )
            Icon(
                Icons.Filled.PlayCircle,
                contentDescription = "Play preview",
                tint = Color.White,
                modifier = Modifier
                    .size(56.dp)
                    .clickable { playing = true }
                    .testTag("video_upload_preview_play"),
            )
        }
    }
}
