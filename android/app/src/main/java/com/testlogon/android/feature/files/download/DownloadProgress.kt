@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.files.download

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.testlogon.android.R

/** AND-334 - stable test tags for the download progress / open / save surface. */
object DownloadTestTags {
    const val SHEET = "download_sheet"
    const val PROGRESS = "download_progress"
    const val CANCEL = "download_cancel"
    const val OPEN = "download_open"
    const val SAVE = "download_save"
    const val RETRY = "download_retry"
}

/**
 * AND-334 - a modal bottom sheet that reflects the [FileDownloadUiState]: a progress bar with a cancel
 * while downloading; open + save-to-downloads when the file is cached; a retry on a retryable error.
 * Stateless - the caller supplies the state and the action callbacks (so it is reducer-testable).
 */
@Composable
fun DownloadSheet(
    state: FileDownloadUiState,
    fileName: String,
    onCancel: () -> Unit,
    onOpen: () -> Unit,
    onSave: () -> Unit,
    onRetry: () -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = modifier.testTag(DownloadTestTags.SHEET),
    ) {
        DownloadContent(
            state = state,
            fileName = fileName,
            onCancel = onCancel,
            onOpen = onOpen,
            onSave = onSave,
            onRetry = onRetry,
        )
    }
}

/** The sheet body, extracted so reducer tests can render it without the sheet container. */
@Composable
fun DownloadContent(
    state: FileDownloadUiState,
    fileName: String,
    onCancel: () -> Unit,
    onOpen: () -> Unit,
    onSave: () -> Unit,
    onRetry: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = fileName,
            style = MaterialTheme.typography.titleMedium,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        when (state) {
            is FileDownloadUiState.InProgress -> InProgressBody(state = state, onCancel = onCancel)
            is FileDownloadUiState.Success -> SuccessBody(onOpen = onOpen, onSave = onSave)
            is FileDownloadUiState.Error -> ErrorBody(state = state, onRetry = onRetry)
            FileDownloadUiState.Cancelled -> Text(
                text = stringResource(R.string.files_download_cancelled),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            FileDownloadUiState.Idle -> Unit
        }
    }
}

@Composable
private fun InProgressBody(
    state: FileDownloadUiState.InProgress,
    onCancel: () -> Unit,
) {
    val cancelCd = stringResource(R.string.files_download_cancel)
    Row(
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = stringResource(R.string.files_download_in_progress),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            val fraction = state.fraction
            if (fraction != null) {
                LinearProgressIndicator(
                    progress = { fraction },
                    modifier = Modifier.fillMaxWidth().testTag(DownloadTestTags.PROGRESS),
                )
            } else {
                LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth().testTag(DownloadTestTags.PROGRESS),
                )
            }
        }
        IconButton(
            onClick = onCancel,
            modifier = Modifier.size(48.dp).testTag(DownloadTestTags.CANCEL),
        ) {
            Icon(Icons.Filled.Close, contentDescription = cancelCd)
        }
    }
}

@Composable
private fun SuccessBody(
    onOpen: () -> Unit,
    onSave: () -> Unit,
) {
    Text(
        text = stringResource(R.string.files_download_done),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        TextButton(
            onClick = onOpen,
            modifier = Modifier.heightIn(min = 48.dp).testTag(DownloadTestTags.OPEN),
        ) {
            Icon(Icons.Filled.OpenInNew, contentDescription = null, modifier = Modifier.size(18.dp))
            Text(
                text = stringResource(R.string.files_download_open),
                modifier = Modifier.padding(start = 8.dp),
            )
        }
        TextButton(
            onClick = onSave,
            modifier = Modifier.heightIn(min = 48.dp).testTag(DownloadTestTags.SAVE),
        ) {
            Icon(Icons.Filled.Download, contentDescription = null, modifier = Modifier.size(18.dp))
            Text(
                text = stringResource(R.string.files_download_save),
                modifier = Modifier.padding(start = 8.dp),
            )
        }
    }
}

@Composable
private fun ErrorBody(
    state: FileDownloadUiState.Error,
    onRetry: () -> Unit,
) {
    Text(
        text = state.message,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.error,
    )
    if (state.retryable) {
        TextButton(
            onClick = onRetry,
            modifier = Modifier.heightIn(min = 48.dp).testTag(DownloadTestTags.RETRY),
        ) {
            Text(stringResource(R.string.action_retry))
        }
    }
}
