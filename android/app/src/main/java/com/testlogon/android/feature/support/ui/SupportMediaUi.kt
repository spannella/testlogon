@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.support.ui

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.InsertDriveFile
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Folder
import androidx.compose.material.icons.outlined.PlayCircle
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import coil.compose.AsyncImage
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.feature.support.data.SupportMediaItem
import com.testlogon.android.feature.support.data.SupportMediaUploader
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B10 B-HELPMEDIA #5 - shared rendering for ticket media: the composer's staged-attachment strip, the
 * per-message media list in the thread, and the file-manager picker dialog. Images render inline; videos
 * and files render as tappable rows (tap opens the asset externally; file-manager refs without a direct
 * URL are non-tappable placeholders since downloading them belongs to the Files feature).
 */

/** Best-effort open of a media asset's URL in an external viewer. No-op when there is nothing to open. */
private fun openExternally(context: android.content.Context, url: String?) {
    val u = url?.takeIf { it.isNotBlank() } ?: return
    runCatching {
        context.startActivity(
            Intent(Intent.ACTION_VIEW, Uri.parse(u)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
    }.onFailure { if (it is ActivityNotFoundException) Unit else Unit }
}

/** A horizontal strip of staged attachments shown above a composer; each chip has a remove button. */
@Composable
fun StagedMediaStrip(
    media: List<StagedMedia>,
    onRemove: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    if (media.isEmpty()) return
    LazyRow(
        modifier = modifier.fillMaxWidth().testTag(SupportTestTags.STAGED_STRIP),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(media, key = { it.localId }) { m ->
            Box {
                val previewModel = m.localPreview ?: m.item?.displayUrl
                if (m.isImage && previewModel != null) {
                    AsyncImage(
                        model = previewModel,
                        contentDescription = "Attachment",
                        contentScale = ContentScale.Crop,
                        modifier = Modifier.size(72.dp).clip(RoundedCornerShape(8.dp)),
                    )
                } else {
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        modifier = Modifier.size(72.dp),
                    ) {
                        Column(
                            Modifier.padding(6.dp),
                            verticalArrangement = Arrangement.Center,
                            horizontalAlignment = Alignment.CenterHorizontally,
                        ) {
                            Icon(
                                if (m.item?.isVideo == true) Icons.Outlined.PlayCircle
                                else Icons.AutoMirrored.Outlined.InsertDriveFile,
                                contentDescription = null,
                            )
                            Text(
                                m.label ?: "File",
                                style = MaterialTheme.typography.labelSmall,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
                if (m.uploading) {
                    Box(
                        Modifier.size(72.dp).background(
                            MaterialTheme.colorScheme.scrim.copy(alpha = 0.35f),
                            RoundedCornerShape(8.dp),
                        ),
                        contentAlignment = Alignment.Center,
                    ) {
                        CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp)
                    }
                } else {
                    IconButton(
                        onClick = { onRemove(m.localId) },
                        modifier = Modifier.align(Alignment.TopEnd).size(24.dp),
                    ) {
                        Icon(Icons.Outlined.Close, contentDescription = "Remove attachment")
                    }
                }
            }
        }
    }
}

/** Renders one message's media list inline in the thread bubble. */
@Composable
fun MessageMediaList(media: List<SupportMediaItem>, modifier: Modifier = Modifier) {
    if (media.isEmpty()) return
    val context = LocalContext.current
    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        media.forEach { item ->
            when {
                item.isImage && item.displayUrl != null ->
                    AsyncImage(
                        model = item.displayUrl,
                        contentDescription = item.displayName,
                        contentScale = ContentScale.Crop,
                        modifier = Modifier
                            .size(200.dp)
                            .clip(RoundedCornerShape(8.dp)),
                    )
                else -> MediaFileRow(item) { openExternally(context, item.url) }
            }
        }
    }
}

@Composable
private fun MediaFileRow(item: SupportMediaItem, onClick: () -> Unit) {
    val tappable = !item.url.isNullOrBlank()
    Surface(
        shape = RoundedCornerShape(8.dp),
        color = MaterialTheme.colorScheme.surface,
        modifier = Modifier
            .fillMaxWidth()
            .then(if (tappable) Modifier.clickable(onClick = onClick) else Modifier),
    ) {
        Row(
            Modifier.padding(10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Icon(
                if (item.isVideo) Icons.Outlined.PlayCircle else Icons.AutoMirrored.Outlined.InsertDriveFile,
                contentDescription = null,
            )
            Column(Modifier.weight(1f)) {
                Text(
                    item.displayName,
                    style = MaterialTheme.typography.bodyMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                val sub = buildString {
                    if (item.isVideo) append("Video")
                    item.sizeBytes?.let {
                        if (isNotEmpty()) append(" - ")
                        append(humanSize(it))
                    }
                }
                if (sub.isNotBlank()) {
                    Text(sub, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

private fun humanSize(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024) return "%.0f KB".format(kb)
    val mb = kb / 1024.0
    return "%.1f MB".format(mb)
}

// --------------------------- file-manager picker dialog ---------------------------

data class FilePickerUiState(
    val loading: Boolean = true,
    val query: String = "",
    val files: List<FileNode> = emptyList(),
    val error: String? = null,
)

@HiltViewModel
class FilePickerViewModel @Inject constructor(
    private val uploader: SupportMediaUploader,
) : ViewModel() {
    private val _uiState = MutableStateFlow(FilePickerUiState())
    val uiState: StateFlow<FilePickerUiState> = _uiState.asStateFlow()

    init { refresh() }

    fun onQueryChange(v: String) {
        _uiState.value = _uiState.value.copy(query = v)
        refresh()
    }

    fun refresh() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(loading = true, error = null)
            when (val r = uploader.listManagerFiles(_uiState.value.query)) {
                is ApiResult.Success -> _uiState.value = _uiState.value.copy(loading = false, files = r.data)
                is ApiResult.Failure -> _uiState.value = _uiState.value.copy(loading = false, error = r.error.message)
                is ApiResult.NetworkError -> _uiState.value = _uiState.value.copy(loading = false, error = "You appear to be offline.")
            }
        }
    }
}

/** A dialog listing the user's file-manager files; picking one returns it as a file_ref attachment. */
@Composable
fun FileManagerPickerDialog(
    onDismiss: () -> Unit,
    onPick: (FileNode) -> Unit,
    viewModel: FilePickerViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Attach from Files") },
        text = {
            Column(Modifier.fillMaxWidth()) {
                OutlinedTextField(
                    value = state.query,
                    onValueChange = viewModel::onQueryChange,
                    placeholder = { Text("Search files") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(SupportTestTags.FILE_PICKER_SEARCH),
                )
                Spacer(Modifier.height(8.dp))
                when {
                    state.loading -> Box(Modifier.fillMaxWidth().padding(24.dp), Alignment.Center) {
                        CircularProgressIndicator()
                    }
                    state.error != null -> Text(state.error!!, color = MaterialTheme.colorScheme.error)
                    state.files.isEmpty() -> Text(
                        "No files in your file manager yet.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    else -> LazyColumn(
                        Modifier.fillMaxWidth().heightIn(max = 320.dp).testTag(SupportTestTags.FILE_PICKER_LIST),
                        verticalArrangement = Arrangement.spacedBy(2.dp),
                    ) {
                        items(state.files, key = { it.path }) { node ->
                            Row(
                                Modifier
                                    .fillMaxWidth()
                                    .clickable { onPick(node) }
                                    .padding(vertical = 10.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp),
                            ) {
                                Icon(Icons.Outlined.Folder, contentDescription = null)
                                Column(Modifier.weight(1f)) {
                                    Text(node.name, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    node.sizeBytes?.let {
                                        Text(
                                            humanSize(it),
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}
