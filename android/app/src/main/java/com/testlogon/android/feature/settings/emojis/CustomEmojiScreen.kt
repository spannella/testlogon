@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.settings.emojis

import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Image
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** Route-level entry for the custom-emoji settings screen. Owns the image picker (GetContent -> bytes). */
@Composable
fun CustomEmojiRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CustomEmojiViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        runCatching {
            val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: return@rememberLauncherForActivityResult
            val type = context.contentResolver.getType(uri) ?: "image/png"
            val name = queryDisplayName(context, uri) ?: "emoji"
            viewModel.onImagePicked(bytes, type, name)
        }
    }

    CustomEmojiScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::load,
        onShortcodeChanged = viewModel::onShortcodeChanged,
        onNameChanged = viewModel::onNameChanged,
        onCategoryChanged = viewModel::onCategoryChanged,
        onPickImage = { picker.launch("image/*") },
        onUpload = viewModel::upload,
        onDelete = viewModel::delete,
        modifier = modifier,
    )
}

private fun queryDisplayName(context: android.content.Context, uri: Uri): String? =
    runCatching {
        context.contentResolver.query(uri, null, null, null, null)?.use { c ->
            val idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && c.moveToFirst()) c.getString(idx) else null
        }
    }.getOrNull()

@Composable
fun CustomEmojiScreen(
    state: CustomEmojiUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onShortcodeChanged: (String) -> Unit,
    onNameChanged: (String) -> Unit,
    onCategoryChanged: (String) -> Unit,
    onPickImage: () -> Unit,
    onUpload: () -> Unit,
    onDelete: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CustomEmojiTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Custom Emojis") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            CustomEmojiUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is CustomEmojiUiState.Error -> ErrorState(
                message = state.message,
                onRetry = onRetry,
                modifier = Modifier.padding(padding).testTag(CustomEmojiTestTags.ERROR_RETRY),
            )
            is CustomEmojiUiState.Content -> Content(
                state = state,
                padding = padding,
                onShortcodeChanged = onShortcodeChanged,
                onNameChanged = onNameChanged,
                onCategoryChanged = onCategoryChanged,
                onPickImage = onPickImage,
                onUpload = onUpload,
                onDelete = onDelete,
            )
        }
    }
}

@Composable
private fun Content(
    state: CustomEmojiUiState.Content,
    padding: androidx.compose.foundation.layout.PaddingValues,
    onShortcodeChanged: (String) -> Unit,
    onNameChanged: (String) -> Unit,
    onCategoryChanged: (String) -> Unit,
    onPickImage: () -> Unit,
    onUpload: () -> Unit,
    onDelete: (String) -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // Upload form.
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Upload a personal emoji", style = MaterialTheme.typography.titleMedium)
                OutlinedTextField(
                    value = state.form.shortcode,
                    onValueChange = onShortcodeChanged,
                    label = { Text("Shortcode (e.g. my_cat)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(CustomEmojiTestTags.SHORTCODE_INPUT),
                )
                OutlinedTextField(
                    value = state.form.name,
                    onValueChange = onNameChanged,
                    label = { Text("Name (optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(CustomEmojiTestTags.NAME_INPUT),
                )
                OutlinedTextField(
                    value = state.form.category,
                    onValueChange = onCategoryChanged,
                    label = { Text("Category") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(CustomEmojiTestTags.CATEGORY_INPUT),
                )
                OutlinedButton(
                    onClick = onPickImage,
                    modifier = Modifier.testTag(CustomEmojiTestTags.PICK_IMAGE),
                ) {
                    Icon(Icons.Outlined.Image, contentDescription = null, modifier = Modifier.size(18.dp))
                    Text(
                        state.form.pickedFileName ?: "Choose image (PNG/GIF, max 256KB)",
                        modifier = Modifier.padding(start = 8.dp),
                    )
                }
                state.form.error?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                Button(
                    onClick = onUpload,
                    enabled = state.form.canSubmit,
                    modifier = Modifier.testTag(CustomEmojiTestTags.UPLOAD),
                ) {
                    if (state.form.uploading) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                    } else {
                        Text("Upload")
                    }
                }
            }
        }

        state.message?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
        }

        Text(
            "My emojis (${state.personalCount} / 100 used)",
            style = MaterialTheme.typography.titleMedium,
        )

        if (state.emojis.isEmpty()) {
            Text(
                "You haven't uploaded any custom emojis yet.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            LazyVerticalGrid(
                columns = GridCells.Adaptive(minSize = 110.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                modifier = Modifier.fillMaxSize(),
            ) {
                items(state.emojis, key = { it.emojiId }) { emoji ->
                    EmojiCard(
                        emoji = emoji,
                        deleting = state.deletingId == emoji.emojiId,
                        onDelete = { onDelete(emoji.emojiId) },
                    )
                }
            }
        }
    }
}

@Composable
private fun EmojiCard(
    emoji: CustomEmoji,
    deleting: Boolean,
    onDelete: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(CustomEmojiTestTags.card(emoji.shortcode))) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Box(modifier = Modifier.size(48.dp), contentAlignment = Alignment.Center) {
                if (emoji.imageUrl != null) {
                    AsyncImage(
                        model = emoji.imageUrl,
                        contentDescription = emoji.altText.ifBlank { emoji.shortcode },
                        modifier = Modifier.size(48.dp),
                    )
                } else {
                    Icon(Icons.Outlined.Image, contentDescription = null, modifier = Modifier.size(32.dp))
                }
            }
            Text(":${emoji.shortcode}:", style = MaterialTheme.typography.labelSmall, maxLines = 1)
            Text(
                emoji.category,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
            )
            if (deleting) {
                CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
            } else {
                IconButton(onClick = onDelete, modifier = Modifier.testTag(CustomEmojiTestTags.delete(emoji.shortcode))) {
                    Icon(
                        Icons.Outlined.Delete,
                        contentDescription = "Delete",
                        tint = MaterialTheme.colorScheme.error,
                    )
                }
            }
        }
    }
}
