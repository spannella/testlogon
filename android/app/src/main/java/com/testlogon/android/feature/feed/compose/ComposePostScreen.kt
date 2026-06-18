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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Image
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
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
                if (state.uploadingMedia) CircularProgressIndicator(modifier = Modifier.size(20.dp))
            }
            if (state.imageUrls.isNotEmpty()) {
                Text(
                    "${state.imageUrls.size} photo${if (state.imageUrls.size == 1) "" else "s"} attached",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.testTag("compose_media_count"),
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
