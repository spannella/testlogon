package com.testlogon.android.feature.feed.own

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Movie
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.input.ImeAction
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
import com.testlogon.android.data.messaging.MessageMedia
import com.testlogon.android.feature.messaging.media.VideoClipBubble

/**
 * FD1 / FD-EDIT — edit an owned post's TEXT, PHOTOS, AUDIENCE (visibility) and PAID-LOCK. Loads the
 * current values on entry and saves them via PATCH /posts/{id} (B-POST contract). Reuses the
 * compose-screen photo picker + visibility chips + lock-price field.
 */
@Composable
fun EditPostRoute(
    postId: String,
    onBack: () -> Unit,
    viewModel: EditPostViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    LaunchedEffect(postId) { viewModel.load(postId) }
    LaunchedEffect(state.saved) { if (state.saved) onBack() }

    val pickImages = rememberLauncherForActivityResult(
        ActivityResultContracts.PickMultipleVisualMedia(5),
    ) { uris -> viewModel.onImagesPicked(uris) }
    // #3 — single-video picker (VOD upload -> video_id). Picking a video replaces any attached one.
    val pickVideo = rememberLauncherForActivityResult(
        ActivityResultContracts.PickVisualMedia(),
    ) { uri -> viewModel.onVideoPicked(uri) }

    EditPostScreen(
        state = state,
        onBack = onBack,
        onBodyChange = viewModel::onBodyChange,
        onVisibilityChange = viewModel::onVisibilityChange,
        onLockPriceChange = viewModel::onLockPriceChange,
        onAddPhotos = {
            pickImages.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
        },
        onRemoveImage = viewModel::removeImage,
        onAddVideo = {
            pickVideo.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.VideoOnly))
        },
        onRemoveVideo = viewModel::removeVideo,
        onSave = viewModel::save,
    )
}

/** Visibility chips offered for an in-place edit (subscribers is not an editable target). */
private val EDIT_VISIBILITY_OPTIONS = listOf(PostVisibility.PUBLIC, PostVisibility.FOLLOWERS)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditPostScreen(
    state: EditPostUiState,
    onBack: () -> Unit,
    onBodyChange: (String) -> Unit,
    onVisibilityChange: (PostVisibility) -> Unit,
    onLockPriceChange: (String) -> Unit,
    onAddPhotos: () -> Unit,
    onRemoveImage: (String) -> Unit,
    onAddVideo: () -> Unit = {},
    onRemoveVideo: () -> Unit = {},
    onSave: () -> Unit,
) {
    val focusManager = LocalFocusManager.current
    Scaffold(
        // #17 — tap anywhere outside the text field to clear focus / dismiss the keyboard.
        modifier = Modifier
            .testTag("edit_post_screen")
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
            ) { focusManager.clearFocus() },
        topBar = {
            TopAppBar(
                title = { Text("Edit post") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    TextButton(
                        onClick = onSave,
                        enabled = state.canSave,
                        modifier = Modifier.testTag("edit_post_save"),
                    ) { Text("Save") }
                },
            )
        },
    ) { padding ->
        if (state.loading) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(modifier = Modifier.size(28.dp))
            }
            return@Scaffold
        }
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            OutlinedTextField(
                value = state.body,
                onValueChange = onBodyChange,
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp).testTag("edit_post_body"),
                placeholder = { Text("Update your post…") },
                minLines = 4,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                keyboardActions = KeyboardActions(onDone = { focusManager.clearFocus() }),
            )

            // Photos / attachments.
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onAddPhotos, modifier = Modifier.testTag("edit_add_photos")) {
                    Icon(Icons.Filled.Image, contentDescription = null, modifier = Modifier.size(18.dp))
                    Text("Add photos", modifier = Modifier.padding(start = 6.dp))
                }
                if (state.uploadingMedia) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp))
                }
            }
            if (state.imageUrls.isNotEmpty()) {
                LazyRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth().testTag("edit_image_previews"),
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
                                    .testTag("edit_image_thumb"),
                            )
                            RemoveBadge(
                                onClick = { onRemoveImage(url) },
                                modifier = Modifier.align(Alignment.TopEnd).testTag("edit_image_remove"),
                            )
                        }
                    }
                }
            }

            // #3 — VIDEO: show the attached video (playable) + add/replace/remove. Hidden while photos
            // are attached (the backend treats video and photos as mutually exclusive); the Add-video
            // button itself stays available and clears photos when used.
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = onAddVideo,
                    enabled = !state.uploadingVideo,
                    modifier = Modifier.testTag("edit_add_video"),
                ) {
                    Icon(Icons.Filled.Movie, contentDescription = null, modifier = Modifier.size(18.dp))
                    Text(
                        if (state.videoId != null) "Replace video" else "Add video",
                        modifier = Modifier.padding(start = 6.dp),
                    )
                }
                if (state.uploadingVideo) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp))
                }
            }
            val videoSource = state.videoPlaybackUrl ?: state.videoLocalUri
            if (videoSource != null) {
                Box(modifier = Modifier.fillMaxWidth().testTag("edit_video_preview")) {
                    VideoClipBubble(
                        media = MessageMedia.VideoClip(
                            playbackUrl = state.videoPlaybackUrl,
                            localUri = state.videoLocalUri,
                            uploadProgress = if (state.uploadingVideo) 0.5f else null,
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    RemoveBadge(
                        onClick = onRemoveVideo,
                        modifier = Modifier.align(Alignment.TopEnd).testTag("edit_video_remove"),
                    )
                }
            }

            Text("Who can see this", style = MaterialTheme.typography.labelLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                EDIT_VISIBILITY_OPTIONS.forEach { v ->
                    FilterChip(
                        selected = state.visibility == v,
                        onClick = { onVisibilityChange(v) },
                        label = { Text(v.label) },
                        modifier = Modifier.testTag("edit_vis_${v.wire}"),
                    )
                }
            }

            Text(
                "Monetize (optional)",
                style = MaterialTheme.typography.labelLarge,
                modifier = Modifier.padding(top = 4.dp),
            )
            OutlinedTextField(
                value = state.lockPriceInput,
                onValueChange = onLockPriceChange,
                modifier = Modifier.fillMaxWidth().testTag("edit_post_price"),
                label = { Text("Unlock price (USD) — leave blank to unlock") },
                placeholder = { Text("e.g. 4.99") },
                singleLine = true,
            )

            state.error?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
            if (state.submitting) {
                Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(modifier = Modifier.size(28.dp))
                }
            }
            Box(Modifier.fillMaxWidth().size(8.dp))
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
