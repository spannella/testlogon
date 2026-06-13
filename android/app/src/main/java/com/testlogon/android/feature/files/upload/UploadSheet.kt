@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.files.upload

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.testlogon.android.R

/** AND-333 - stable test tags for the upload sheet + the Files-screen upload affordance. */
object UploadTestTags {
    const val SHEET = "upload_sheet"
    const val FAB = "upload_fab"
    const val PROGRESS = "upload_progress"
    const val CANCEL = "upload_cancel"
    const val RETRY = "upload_retry"

    /** Per-row tag: upload_job_<id>. */
    fun row(id: String): String = "upload_job_$id"
}

/**
 * AND-333 - modal bottom sheet listing active + finished uploads, one row each with name, a progress
 * bar, a state label, and a per-row cancel (while in-flight) / retry (when failed) control. Stateless:
 * the caller supplies [jobs] and the action callbacks (so it is reducer-testable).
 */
@Composable
fun UploadSheet(
    jobs: List<UploadJob>,
    onCancel: (String) -> Unit,
    onRetry: (String) -> Unit,
    onDismissJob: (String) -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = modifier.testTag(UploadTestTags.SHEET),
    ) {
        Column(Modifier.fillMaxWidth().padding(bottom = 24.dp)) {
            Text(
                text = stringResource(R.string.files_upload_title),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            )
            if (jobs.isEmpty()) {
                Text(
                    text = stringResource(R.string.files_upload_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                )
            } else {
                LazyColumn(Modifier.fillMaxWidth().heightIn(max = 360.dp)) {
                    items(jobs, key = { it.id }) { job ->
                        UploadRow(
                            job = job,
                            onCancel = onCancel,
                            onRetry = onRetry,
                            onDismissJob = onDismissJob,
                        )
                    }
                }
            }
        }
    }
}

/** One upload row: name + progress + state label, with a cancel (in-flight) or retry (failed) action. */
@Composable
fun UploadRow(
    job: UploadJob,
    onCancel: (String) -> Unit,
    onRetry: (String) -> Unit,
    onDismissJob: (String) -> Unit,
) {
    val cancelCd = stringResource(R.string.files_upload_cancel)
    val retryCd = stringResource(R.string.files_upload_retry)
    val dismissCd = stringResource(R.string.files_upload_dismiss)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag(UploadTestTags.row(job.id)),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = job.displayName,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = stateLabel(job),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (job.isActive) {
                if (job.state == UploadState.UPLOADING) {
                    LinearProgressIndicator(
                        progress = { job.progress },
                        modifier = Modifier.fillMaxWidth().testTag(UploadTestTags.PROGRESS),
                    )
                } else {
                    LinearProgressIndicator(
                        modifier = Modifier.fillMaxWidth().testTag(UploadTestTags.PROGRESS),
                    )
                }
            }
        }
        when {
            job.isActive -> IconButton(
                onClick = { onCancel(job.id) },
                modifier = Modifier.size(48.dp).testTag(UploadTestTags.CANCEL),
            ) {
                Icon(Icons.Filled.Close, contentDescription = cancelCd)
            }
            job.isFailed -> {
                IconButton(
                    onClick = { onRetry(job.id) },
                    modifier = Modifier.size(48.dp).testTag(UploadTestTags.RETRY),
                ) {
                    Icon(Icons.Filled.Refresh, contentDescription = retryCd)
                }
            }
            else -> IconButton(
                onClick = { onDismissJob(job.id) },
                modifier = Modifier.size(48.dp),
            ) {
                Icon(Icons.Filled.Close, contentDescription = dismissCd)
            }
        }
    }
}

/** Spinner-free indeterminate hint reused for CANCELLED rows (kept compact). */
@Composable
private fun stateLabel(job: UploadJob): String = when (job.state) {
    UploadState.QUEUED -> stringResource(R.string.files_upload_state_queued)
    UploadState.PREPARING -> stringResource(R.string.files_upload_state_preparing)
    UploadState.UPLOADING -> stringResource(
        R.string.files_upload_state_uploading,
        (job.progress * 100f).toInt(),
    )
    UploadState.CONFIRMING -> stringResource(R.string.files_upload_state_confirming)
    UploadState.DONE -> stringResource(R.string.files_upload_state_done)
    UploadState.FAILED -> job.error ?: stringResource(R.string.files_upload_state_failed)
    UploadState.CANCELLED -> stringResource(R.string.files_upload_state_cancelled)
}

/** A tiny inline spinner some callers may reuse; kept for parity with browse loading idioms. */
@Composable
internal fun UploadInlineSpinner() {
    Box(Modifier.padding(8.dp)) {
        CircularProgressIndicator(modifier = Modifier.size(20.dp))
    }
}
