@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.sshrecordings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.sshrecordings.RecordingDto
import com.testlogon.android.feature.infracommon.infraErrorMessage
import com.testlogon.android.feature.infracommon.statusColor

object SshRecordingsTestTags {
    const val SCREEN = "sshrecordings_screen"
    const val LIST = "sshrecordings_list"
    const val EMPTY = "sshrecordings_empty"
    const val FORBIDDEN = "sshrecordings_forbidden"
    const val DISABLED = "sshrecordings_disabled"
    const val ERROR_RETRY = "sshrecordings_error_retry"
    const val PLAYBACK = "sshrecordings_playback"
    fun row(id: String) = "sshrecordings_row_$id"
    fun view(id: String) = "sshrecordings_view_$id"
    fun delete(id: String) = "sshrecordings_delete_$id"
}

@Composable
fun SshRecordingsRoute(
    onBack: () -> Unit,
    viewModel: SshRecordingsViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    SshRecordingsScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onView = viewModel::openPlayback,
        onDelete = viewModel::delete,
        onDismissPlayback = viewModel::dismissPlayback,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun SshRecordingsScreen(
    state: RecordingsUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onView: (RecordingDto) -> Unit,
    onDelete: (String) -> Unit,
    onDismissPlayback: () -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var deleteTarget by remember { mutableStateOf<RecordingDto?>(null) }
    val clipboard = LocalClipboardManager.current

    LaunchedEffect(state.message, state.transientError) {
        val msg = state.message ?: state.transientError?.let { infraErrorMessage(it) }
        if (msg != null) { snackbar.showSnackbar(msg); onMessageShown() }
    }

    Scaffold(
        modifier = modifier.testTag(SshRecordingsTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("SSH recordings") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        val isRefreshing = (state.data as? RecordingsDataState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (val d = state.data) {
                is RecordingsDataState.Loading -> LoadingState()
                is RecordingsDataState.Empty -> EmptyState(
                    modifier = Modifier.testTag(SshRecordingsTestTags.EMPTY),
                    title = "No recordings",
                    body = "Recorded SSH sessions appear here for playback.",
                    imageVector = Icons.Outlined.Terminal,
                )
                is RecordingsDataState.Disabled -> EmptyState(
                    modifier = Modifier.testTag(SshRecordingsTestTags.DISABLED),
                    title = "Recording disabled",
                    body = "SSH session recording is turned off for this environment.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is RecordingsDataState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(SshRecordingsTestTags.FORBIDDEN),
                    title = "Not authorised",
                    body = "You do not have access to SSH recordings.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is RecordingsDataState.Error -> ErrorState(
                    modifier = Modifier.testTag(SshRecordingsTestTags.ERROR_RETRY),
                    message = infraErrorMessage(d.type),
                    onRetry = onRetry,
                )
                is RecordingsDataState.Content -> LazyColumn(
                    modifier = Modifier.fillMaxSize().testTag(SshRecordingsTestTags.LIST),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(items = d.recordings, key = { it.recordingId }) { rec ->
                        RecordingRow(
                            rec = rec,
                            loadingPlayback = state.loadingPlaybackId == rec.recordingId,
                            inFlight = state.actionInFlightId == rec.recordingId,
                            actionsEnabled = state.actionInFlightId == null && state.loadingPlaybackId == null,
                            onView = { onView(rec) },
                            onDelete = { deleteTarget = rec },
                        )
                    }
                }
            }
        }
    }

    deleteTarget?.let { rec ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text("Delete recording?") },
            text = { Text("Delete the recording for ${rec.hostname}?") },
            confirmButton = { TextButton(onClick = { onDelete(rec.recordingId); deleteTarget = null }) { Text("Delete") } },
            dismissButton = { TextButton(onClick = { deleteTarget = null }) { Text("Cancel") } },
        )
    }

    state.playback?.let { pb ->
        AlertDialog(
            modifier = Modifier.testTag(SshRecordingsTestTags.PLAYBACK),
            onDismissRequest = onDismissPlayback,
            title = { Text("${pb.recording.hostname} - ${pb.eventCount} events") },
            text = {
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    modifier = Modifier.fillMaxWidth().heightIn(max = 360.dp),
                ) {
                    Text(
                        pb.transcript,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(8.dp).verticalScroll(rememberScrollState()),
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { clipboard.setText(AnnotatedString(pb.transcript)) }) { Text("Copy") }
            },
            dismissButton = { TextButton(onClick = onDismissPlayback) { Text("Close") } },
        )
    }
}

@Composable
private fun RecordingRow(
    rec: RecordingDto,
    loadingPlayback: Boolean,
    inFlight: Boolean,
    actionsEnabled: Boolean,
    onView: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(SshRecordingsTestTags.row(rec.recordingId))) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                "${if (rec.username.isNotBlank()) "${rec.username}@" else ""}${rec.hostname}:${rec.port}",
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(
                    onClick = {},
                    enabled = false,
                    label = { Text(rec.status) },
                    colors = androidx.compose.material3.AssistChipDefaults.assistChipColors(
                        disabledLabelColor = statusColor(rec.status),
                    ),
                )
                AssistChip(onClick = {}, enabled = false, label = { Text("${rec.durationSeconds}s") })
                AssistChip(onClick = {}, enabled = false, label = { Text("${rec.eventCount} events") })
            }
            if (inFlight) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = onView,
                        enabled = actionsEnabled,
                        modifier = Modifier.testTag(SshRecordingsTestTags.view(rec.recordingId)),
                    ) { Text(if (loadingPlayback) "Loading..." else "View") }
                    OutlinedButton(
                        onClick = onDelete,
                        enabled = actionsEnabled,
                        modifier = Modifier.testTag(SshRecordingsTestTags.delete(rec.recordingId)),
                    ) { Text("Delete") }
                }
            }
        }
    }
}
