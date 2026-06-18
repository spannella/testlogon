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
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@Composable
fun VideoUploadRoute(
    onBack: () -> Unit,
    viewModel: VideoUploadViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val context = androidx.compose.ui.platform.LocalContext.current
    androidx.compose.runtime.LaunchedEffect(state.uploadedVideoId) {
        if (state.uploadedVideoId != null) onBack()
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
        Column(
            Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp),
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
