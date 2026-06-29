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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
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
import androidx.compose.runtime.setValue
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
import androidx.compose.foundation.Image
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
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
import coil.compose.AsyncImage
import coil.compose.rememberAsyncImagePainter
import coil.decode.VideoFrameDecoder
import coil.request.ImageRequest
import coil.request.videoFrameMillis
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import com.testlogon.android.core.model.groups.Group
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
        onTargetGroupChange = viewModel::onTargetGroupChange,
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

// #2 — accept count + max so callers can express "video added" without a separate flag.
private const val MAX_POST_VIDEOS = 10

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ComposePostScreen(
    state: ComposePostUiState,
    onBack: () -> Unit,
    onBodyChange: (String) -> Unit,
    onVisibilityChange: (PostVisibility) -> Unit,
    onTargetGroupChange: (Group?) -> Unit,
    onLockPriceChange: (String) -> Unit,
    onScheduleChange: (Long?) -> Unit,
    onAddPhotos: () -> Unit,
    onAddVideo: () -> Unit,
    onRemoveImage: (String) -> Unit,
    onRemoveVideo: (String) -> Unit,
    onPost: () -> Unit,
) {
    val focusManager = LocalFocusManager.current
    Scaffold(
        // #17 — tap anywhere outside the text field to clear focus / dismiss the keyboard.
        modifier = Modifier
            .testTag("compose_post_screen")
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
            ) { focusManager.clearFocus() },
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
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp).testTag("compose_post_body"),
                placeholder = { Text("Share something with your audience…") },
                minLines = 3,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                keyboardActions = KeyboardActions(onDone = { focusManager.clearFocus() }),
            )

            // Media attachment
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onAddPhotos, modifier = Modifier.testTag("compose_add_photos")) {
                    Icon(Icons.Filled.Image, contentDescription = null, modifier = Modifier.size(18.dp))
                    Text("Add photos", modifier = Modifier.padding(start = 6.dp))
                }
                OutlinedButton(
                    // #2 — allow attaching MULTIPLE videos (up to the cap), alongside any photos.
                    onClick = onAddVideo,
                    enabled = state.videos.size < MAX_POST_VIDEOS,
                    modifier = Modifier.testTag("compose_add_video"),
                ) {
                    Icon(Icons.Filled.Movie, contentDescription = null, modifier = Modifier.size(18.dp))
                    Text(if (state.videos.isEmpty()) "Add video" else "Add another", modifier = Modifier.padding(start = 6.dp))
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

            // #2 / FD20 — attached-video previews: one REAL first-frame thumbnail per picked clip (Coil
            // VideoFrameDecoder), each with a working local-playback play button + a remove "x". Multiple
            // videos may be attached (and coexist with photos). Shows as soon as each clip is picked.
            if (state.videos.isNotEmpty()) {
                LazyRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth().testTag("compose_video_previews"),
                ) {
                    items(state.videos, key = { it.localUri }) { v ->
                        LocalVideoPreviewCell(
                            localUri = v.localUri,
                            uploading = v.uploading,
                            onRemove = { onRemoveVideo(v.localUri) },
                            testTag = "compose_video_preview",
                        )
                    }
                }
                Text(
                    if (state.uploadingVideo) "Uploading video…" else "Video attached",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                )
            }

            // #4 (B-GROUPUNIFY) — audience: post to your personal feed OR to one of your groups (the
            // SAME composer either way; the group is just the selected audience). Hidden as switchable
            // when the audience was locked by the caller (composing from a group feed).
            AudiencePicker(
                state = state,
                onTargetGroupChange = onTargetGroupChange,
            )

            // The public/followers/subscribers visibility only applies to a PERSONAL-feed post; a group
            // post's visibility is the group's own audience model.
            if (state.targetGroup == null) {
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

/**
 * #4 (B-GROUPUNIFY) — audience selector: "Personal feed" plus a chip per group. Selecting a group routes
 * the post to that group (which the backend bridges back into the unified feed). When the audience is
 * locked (composing from inside a group) the selected group is shown read-only.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AudiencePicker(
    state: ComposePostUiState,
    onTargetGroupChange: (Group?) -> Unit,
) {
    if (state.groupLocked) {
        Text("Posting to", style = MaterialTheme.typography.labelLarge)
        FilterChip(
            selected = true,
            onClick = {},
            enabled = false,
            label = { Text("Group: ${state.targetGroup?.name ?: "this group"}") },
            modifier = Modifier.testTag("compose_audience_locked"),
        )
        return
    }
    if (state.myGroups.isEmpty()) return
    Text("Post to", style = MaterialTheme.typography.labelLarge)
    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
        modifier = Modifier.testTag("compose_audience_picker"),
    ) {
        FilterChip(
            selected = state.targetGroup == null,
            onClick = { onTargetGroupChange(null) },
            label = { Text("Personal feed") },
            modifier = Modifier.testTag("compose_audience_personal"),
        )
        state.myGroups.forEach { g ->
            FilterChip(
                selected = state.targetGroup?.id == g.id,
                onClick = { onTargetGroupChange(g) },
                label = { Text(g.name) },
                modifier = Modifier.testTag("compose_audience_group_${g.id}"),
            )
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
