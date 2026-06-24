package com.testlogon.android.feature.feed.compose

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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Movie
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.data.feed.PostVisibility
import com.testlogon.android.feature.common.DateTimePickerField

@Composable
fun ComposePostRoute(
    onBack: () -> Unit,
    viewModel: ComposePostViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    androidx.compose.runtime.LaunchedEffect(state.posted) {
        if (state.posted) onBack()
    }
    val pickImages = rememberLauncherForActivityResult(
        ActivityResultContracts.PickMultipleVisualMedia(5),
    ) { uris -> viewModel.onImagesPicked(uris) }
    val pickVideo = rememberLauncherForActivityResult(
        ActivityResultContracts.PickVisualMedia(),
    ) { uri -> viewModel.onVideoPicked(uri) }

    ComposePostScreen(
        state = state,
        onBack = onBack,
        onBodyChange = viewModel::onBodyChange,
        onVisibilityChange = viewModel::onVisibilityChange,
        onLockPriceChange = viewModel::onLockPriceChange,
        onScheduleChange = viewModel::onScheduleChange,
        onAddPhotos = {
            pickImages.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
        },
        onAddVideo = {
            pickVideo.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.VideoOnly))
        },
        onRemoveImage = viewModel::removeImage,
        onRemoveVideo = viewModel::removeVideo,
        onPost = viewModel::post,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ComposePostScreen(
    state: ComposePostUiState,
    onBack: () -> Unit,
    onBodyChange: (String) -> Unit,
    onVisibilityChange: (PostVisibility) -> Unit,
    onLockPriceChange: (String) -> Unit,
    onScheduleChange: (Long?) -> Unit,
    onAddPhotos: () -> Unit,
    onAddVideo: () -> Unit,
    onRemoveImage: (String) -> Unit,
    onRemoveVideo: () -> Unit,
    onPost: () -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag("compose_post_screen"),
        topBar = {
            TopAppBar(
                title = { Text("New post") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    TextButton(onClick = onPost, enabled = state.canPost, modifier = Modifier.testTag("compose_post_submit")) {
                        Text("Post")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            OutlinedTextField(
                value = state.body,
                onValueChange = onBodyChange,
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp).testTag("compose_post_body"),
                placeholder = { Text("Share something with your audience…") },
                minLines = 3,
            )

            // Media attachment
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onAddPhotos, modifier = Modifier.testTag("compose_add_photos")) {
                    Icon(Icons.Filled.Image, contentDescription = null, modifier = Modifier.size(18.dp))
                    Text("Add photos", modifier = Modifier.padding(start = 6.dp))
                }
                OutlinedButton(
                    onClick = onAddVideo,
                    enabled = !state.uploadingVideo && state.videoId == null,
                    modifier = Modifier.testTag("compose_add_video"),
                ) {
                    Icon(Icons.Filled.Movie, contentDescription = null, modifier = Modifier.size(18.dp))
                    Text("Add video", modifier = Modifier.padding(start = 6.dp))
                }
                if (state.uploadingMedia || state.uploadingVideo) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp))
                }
            }

            // FD7 — image thumbnails preview (each with a remove "x").
            if (state.imageUrls.isNotEmpty()) {
                LazyRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth().testTag("compose_image_previews"),
                ) {
                    items(state.imageUrls, key = { it }) { url ->
                        Box(modifier = Modifier.size(96.dp)) {
                            AsyncImage(
                                model = url,
                                contentDescription = "Attached photo",
                                contentScale = ContentScale.Crop,
                                modifier = Modifier
                                    .fillMaxSize()
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(MaterialTheme.colorScheme.surfaceVariant)
                                    .testTag("compose_image_thumb"),
                            )
                            RemoveBadge(
                                onClick = { onRemoveImage(url) },
                                modifier = Modifier.align(Alignment.TopEnd).testTag("compose_image_remove"),
                            )
                        }
                    }
                }
            }

            // FD8 — attached-video preview chip (with remove).
            if (state.videoId != null) {
                Box(modifier = Modifier.size(width = 140.dp, height = 96.dp).testTag("compose_video_preview")) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .clip(RoundedCornerShape(12.dp))
                            .background(MaterialTheme.colorScheme.surfaceVariant),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(Icons.Filled.PlayArrow, contentDescription = null, modifier = Modifier.size(36.dp))
                    }
                    RemoveBadge(
                        onClick = onRemoveVideo,
                        modifier = Modifier.align(Alignment.TopEnd).testTag("compose_video_remove"),
                    )
                }
                Text(
                    "Video attached",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                )
            }

            Text("Who can see this", style = MaterialTheme.typography.labelLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                PostVisibility.entries.forEach { v ->
                    FilterChip(
                        selected = state.visibility == v,
                        onClick = { onVisibilityChange(v) },
                        label = { Text(v.label) },
                        modifier = Modifier.testTag("compose_vis_${v.wire}"),
                    )
                }
            }

            Text("Monetize (optional)", style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(top = 4.dp))
            OutlinedTextField(
                value = state.lockPriceInput,
                onValueChange = onLockPriceChange,
                modifier = Modifier.fillMaxWidth().testTag("compose_post_price"),
                label = { Text("Unlock price (USD) — leave blank for free") },
                placeholder = { Text("e.g. 4.99") },
                singleLine = true,
            )

            Text("Schedule (optional)", style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(top = 4.dp))
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                DateTimePickerField(
                    selectedEpochSeconds = state.publishAtEpochSeconds,
                    onPicked = onScheduleChange,
                    modifier = Modifier.weight(1f),
                    placeholder = "Publish now (tap to schedule)",
                    testTag = "compose_post_schedule",
                )
                if (state.publishAtEpochSeconds != null) {
                    TextButton(onClick = { onScheduleChange(null) }) { Text("Clear") }
                }
            }

            state.error?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
            if (state.submitting) {
                Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(modifier = Modifier.size(28.dp))
                }
            }
            Box(Modifier.fillMaxWidth().height(8.dp))
        }
    }
}

/** A small circular "x" remove badge overlaid on a media thumbnail. */
@Composable
private fun RemoveBadge(onClick: () -> Unit, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .padding(4.dp)
            .size(22.dp)
            .clip(CircleShape)
            .background(Color.Black.copy(alpha = 0.55f))
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            Icons.Filled.Close,
            contentDescription = "Remove",
            tint = Color.White,
            modifier = Modifier.size(14.dp),
        )
    }
}
