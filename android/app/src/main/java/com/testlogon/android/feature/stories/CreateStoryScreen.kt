package com.testlogon.android.feature.stories

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Image
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.R

/** PAR-01 - stable test tags for the create-story surface. */
object CreateStoryTestTags {
    const val SCREEN = "create_story_screen"
    const val PICK = "create_story_pick"
    const val PREVIEW = "create_story_preview"
    const val OVERLAY = "create_story_overlay"
    const val LINK_URL = "create_story_link_url"
    const val LINK_LABEL = "create_story_link_label"
    const val SHARE = "create_story_share"
}

/**
 * PAR-01 - create-a-story route. Picks a single image (image-only picker), uploads it via the shared
 * image-upload rail (CommentImageUploader), then posts POST /ui/stories. Pops back on success; a 429
 * daily-limit or any error is surfaced via the Scaffold snackbar.
 */
@Composable
fun CreateStoryRoute(
    onBack: () -> Unit,
    viewModel: CreateStoryViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val posted by viewModel.posted.collectAsStateWithLifecycle()

    LaunchedEffect(posted) {
        if (posted) {
            viewModel.onPostedHandled()
            onBack()
        }
    }

    val pickImage = rememberLauncherForActivityResult(
        ActivityResultContracts.PickVisualMedia(),
    ) { uri -> viewModel.onImagePicked(uri) }

    CreateStoryScreen(
        state = state,
        onBack = onBack,
        onPickImage = {
            pickImage.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
        },
        onOverlayChange = viewModel::onOverlayChange,
        onLinkUrlChange = viewModel::onLinkUrlChange,
        onLinkLabelChange = viewModel::onLinkLabelChange,
        onShare = viewModel::share,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CreateStoryScreen(
    state: CreateStoryUiState,
    onBack: () -> Unit,
    onPickImage: () -> Unit,
    onOverlayChange: (String) -> Unit,
    onLinkUrlChange: (String) -> Unit,
    onLinkLabelChange: (String) -> Unit,
    onShare: () -> Unit,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(state.errorText) {
        state.errorText?.let { snackbarHostState.showSnackbar(it) }
    }

    Scaffold(
        modifier = Modifier.testTag(CreateStoryTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.create_story_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.create_story_back),
                        )
                    }
                },
                actions = {
                    TextButton(
                        onClick = onShare,
                        enabled = state.canShare,
                        modifier = Modifier.testTag(CreateStoryTestTags.SHARE),
                    ) {
                        Text(stringResource(R.string.create_story_share))
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Image picker + preview.
            OutlinedButton(
                onClick = onPickImage,
                modifier = Modifier.padding(top = 12.dp).testTag(CreateStoryTestTags.PICK),
            ) {
                Icon(Icons.Filled.Image, contentDescription = null, modifier = Modifier.size(18.dp))
                Text(
                    stringResource(
                        if (state.media is StoryMediaState.Idle) {
                            R.string.create_story_pick
                        } else {
                            R.string.create_story_change_photo
                        },
                    ),
                    modifier = Modifier.padding(start = 6.dp),
                )
            }

            when (val media = state.media) {
                is StoryMediaState.Idle -> Unit
                is StoryMediaState.Uploading -> ImagePreview(model = media.uri, uploading = true)
                is StoryMediaState.Ready -> ImagePreview(model = media.uri, uploading = false)
                is StoryMediaState.Failed -> {
                    ImagePreview(model = media.uri, uploading = false)
                    Text(
                        media.message,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }

            OutlinedTextField(
                value = state.overlayText,
                onValueChange = onOverlayChange,
                modifier = Modifier.fillMaxWidth().testTag(CreateStoryTestTags.OVERLAY),
                label = { Text(stringResource(R.string.create_story_overlay_label)) },
                placeholder = { Text(stringResource(R.string.create_story_overlay_hint)) },
                minLines = 2,
            )

            Text(
                stringResource(R.string.create_story_link_section),
                style = MaterialTheme.typography.labelLarge,
                modifier = Modifier.padding(top = 4.dp),
            )
            OutlinedTextField(
                value = state.linkUrl,
                onValueChange = onLinkUrlChange,
                modifier = Modifier.fillMaxWidth().testTag(CreateStoryTestTags.LINK_URL),
                label = { Text(stringResource(R.string.create_story_link_url_label)) },
                placeholder = { Text(stringResource(R.string.create_story_link_url_hint)) },
                singleLine = true,
            )
            OutlinedTextField(
                value = state.linkLabel,
                onValueChange = onLinkLabelChange,
                modifier = Modifier.fillMaxWidth().testTag(CreateStoryTestTags.LINK_LABEL),
                label = { Text(stringResource(R.string.create_story_link_label_label)) },
                singleLine = true,
            )

            if (state.isSubmitting) {
                Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(modifier = Modifier.size(28.dp))
                }
            }
        }
    }
}

/** Square-ish preview of the picked story image, with an upload spinner overlay while uploading. */
@Composable
private fun ImagePreview(model: Any?, uploading: Boolean) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .aspectRatio(0.75f)
            .clip(RoundedCornerShape(16.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .testTag(CreateStoryTestTags.PREVIEW),
        contentAlignment = Alignment.Center,
    ) {
        AsyncImage(
            model = model,
            contentDescription = stringResource(R.string.create_story_preview_cd),
            contentScale = ContentScale.Crop,
            modifier = Modifier.fillMaxSize(),
        )
        if (uploading) {
            Box(
                Modifier.fillMaxSize().background(MaterialTheme.colorScheme.scrim.copy(alpha = 0.35f)),
                contentAlignment = Alignment.Center,
            ) {
                CircularProgressIndicator()
            }
        }
    }
}
