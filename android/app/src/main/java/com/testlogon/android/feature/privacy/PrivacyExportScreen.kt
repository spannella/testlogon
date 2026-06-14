@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.privacy

import android.text.format.DateUtils
import android.text.format.Formatter
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.CloudOff
import androidx.compose.material.icons.outlined.Download
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.data.privacy.ExportStatus

/** AND-385 - test tags for the privacy-export screen (Compose UI tests). */
object PrivacyExportTestTags {
    const val SCREEN = "privacy_export_screen"
    const val LIST = "privacy_export_list"
    const val EMPTY = "privacy_export_empty"
    const val OFFLINE_BANNER = "privacy_export_offline"
    const val REQUEST = "privacy_export_request"
    const val REFRESH = "privacy_export_refresh"
    const val ROW = "privacy_export_row"
    const val DOWNLOAD = "privacy_export_download"
    const val RETRY = "privacy_export_retry"
    const val STATUS_CHIP = "privacy_export_status"
}

/**
 * AND-385 - the navigation entry point. Drives an initial load on first resume and pauses the bounded poll
 * loop when the screen is not resumed; surfaces transient errors + the download-saved confirmation via a
 * SnackbarHost.
 */
@Composable
fun PrivacyExportRoute(
    onBack: () -> Unit,
    viewModel: PrivacyExportViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(Unit) { viewModel.load() }

    val errorMessage = state.error?.message
    LaunchedEffect(errorMessage) {
        if (errorMessage != null) {
            snackbarHostState.showSnackbar(errorMessage)
            viewModel.onErrorShown()
        }
    }
    val savedName = state.lastSavedName
    LaunchedEffect(savedName) {
        if (savedName != null) {
            snackbarHostState.showSnackbar(context.getString(R.string.privacy_export_saved))
            viewModel.onSavedShown()
        }
    }

    PrivacyExportScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRequestExport = { viewModel.onRequestExport() },
        onRefresh = viewModel::onRefresh,
        onDownload = viewModel::onDownload,
        onRetry = viewModel::onRetry,
    )
}

/** AND-385 - the stateless screen (FR-1..FR-6). */
@Composable
fun PrivacyExportScreen(
    state: PrivacyExportUiState,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onRequestExport: () -> Unit,
    onRefresh: () -> Unit,
    onDownload: (String) -> Unit,
    onRetry: (String) -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag(PrivacyExportTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.privacy_export_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Outlined.ArrowBack,
                            contentDescription = stringResource(R.string.privacy_export_back),
                        )
                    }
                },
                actions = {
                    IconButton(
                        onClick = onRefresh,
                        modifier = Modifier.testTag(PrivacyExportTestTags.REFRESH),
                    ) {
                        Icon(
                            Icons.Outlined.Refresh,
                            contentDescription = stringResource(R.string.privacy_export_refresh_cd),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        bottomBar = {
            Button(
                onClick = onRequestExport,
                enabled = state.canRequest && !state.requestInFlight,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
                    .testTag(PrivacyExportTestTags.REQUEST),
            ) {
                if (state.requestInFlight) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.size(8.dp))
                }
                Text(stringResource(R.string.privacy_export_request))
            }
        },
    ) { padding ->
        PullToRefreshBox(
            isRefreshing = state.isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when {
                state.isLoading ->
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator()
                    }
                state.requests.isEmpty() ->
                    EmptyState(isOffline = state.isOffline, onRefresh = onRefresh)
                else ->
                    Column(Modifier.fillMaxSize()) {
                        if (state.isOffline) OfflineBanner()
                        LazyColumn(
                            modifier = Modifier
                                .fillMaxSize()
                                .testTag(PrivacyExportTestTags.LIST),
                        ) {
                            items(state.requests, key = { it.id }) { row ->
                                ExportRequestRow(
                                    row = row,
                                    downloading = row.id in state.downloading,
                                    onDownload = { onDownload(row.id) },
                                    onRetry = { onRetry(row.id) },
                                )
                                HorizontalDivider()
                            }
                        }
                    }
            }
        }
    }
}

@Composable
private fun OfflineBanner() {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag(PrivacyExportTestTags.OFFLINE_BANNER),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Icon(Icons.Outlined.CloudOff, contentDescription = null)
        Text(stringResource(R.string.privacy_export_offline))
    }
}

@Composable
private fun EmptyState(isOffline: Boolean, onRefresh: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
            .testTag(PrivacyExportTestTags.EMPTY),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(stringResource(R.string.privacy_export_empty_title))
        Spacer(Modifier.height(8.dp))
        Text(stringResource(R.string.privacy_export_empty_body))
        if (isOffline) {
            Spacer(Modifier.height(16.dp))
            OutlinedButton(onClick = onRefresh) {
                Text(stringResource(R.string.privacy_export_retry))
            }
        }
    }
}

@Composable
private fun ExportRequestRow(
    row: ExportRequestUi,
    downloading: Boolean,
    onDownload: () -> Unit,
    onRetry: () -> Unit,
) {
    val context = LocalContext.current
    val requestedDisplay = remember(row.requestedAtEpochMs) {
        DateUtils.getRelativeTimeSpanString(
            row.requestedAtEpochMs,
            System.currentTimeMillis(),
            DateUtils.MINUTE_IN_MILLIS,
        ).toString()
    }
    val sizeDisplay = row.sizeBytes?.let { Formatter.formatShortFileSize(context, it) }
    val statusText = statusLabel(row.status, row.expired)
    val statusCd = stringResource(R.string.privacy_export_status_cd, statusText)

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp)
            .testTag(PrivacyExportTestTags.ROW),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(Modifier.weight(1f)) {
            Text(stringResource(R.string.privacy_export_requested_at, requestedDisplay))
            AssistChip(
                onClick = {},
                enabled = false,
                label = { Text(statusText) },
                colors = AssistChipDefaults.assistChipColors(),
                modifier = Modifier
                    .testTag(PrivacyExportTestTags.STATUS_CHIP)
                    .semantics {
                        liveRegion = LiveRegionMode.Polite
                        contentDescription = statusCd
                    },
            )
            if (sizeDisplay != null) Text(sizeDisplay)
        }
        when {
            row.downloadable ->
                Button(
                    onClick = onDownload,
                    enabled = !downloading,
                    modifier = Modifier.testTag(PrivacyExportTestTags.DOWNLOAD),
                ) {
                    if (downloading) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    } else {
                        Icon(
                            Icons.Outlined.Download,
                            contentDescription = stringResource(R.string.privacy_export_download_cd),
                        )
                    }
                }
            row.retryable ->
                OutlinedButton(
                    onClick = onRetry,
                    modifier = Modifier.testTag(PrivacyExportTestTags.RETRY),
                ) {
                    Text(stringResource(R.string.privacy_export_retry))
                }
            else -> Unit
        }
    }
}

@Composable
private fun statusLabel(status: ExportStatus, expired: Boolean): String {
    if (expired && status == ExportStatus.COMPLETED) {
        return stringResource(R.string.privacy_export_status_expired)
    }
    return stringResource(
        when (status) {
            ExportStatus.PENDING -> R.string.privacy_export_status_pending
            ExportStatus.PROCESSING -> R.string.privacy_export_status_processing
            ExportStatus.COMPLETED -> R.string.privacy_export_status_completed
            ExportStatus.FAILED -> R.string.privacy_export_status_failed
            ExportStatus.CANCELLED -> R.string.privacy_export_status_cancelled
            ExportStatus.REJECTED -> R.string.privacy_export_status_rejected
            ExportStatus.HELD -> R.string.privacy_export_status_held
            ExportStatus.UNKNOWN -> R.string.privacy_export_status_unknown
        },
    )
}
