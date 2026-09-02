@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.files.usage

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.PieChart
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.getValue
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.model.files.FileShareMath
import com.testlogon.android.core.model.files.UsageDailyItemDto
import com.testlogon.android.core.model.files.UsageStorageFileDto
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** FM-SHARE stable testTags for the Storage-usage screen. */
object StorageUsageTestTags {
    const val SCREEN = "storage_usage_screen"
    const val CONTENT = "storage_usage_content"
    const val TOTAL = "storage_usage_total"
    const val UNAVAILABLE = "storage_usage_unavailable"
    const val TOP_FILE_ROW = "storage_usage_top_file_row"
    const val DAILY_ROW = "storage_usage_daily_row"
}

/**
 * FM-SHARE - route wrapper: collects the usage state and delegates to the stateless [StorageUsageScreen].
 */
@Composable
fun StorageUsageRoute(
    onBack: () -> Unit,
    viewModel: StorageUsageViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    StorageUsageScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
    )
}

@Composable
fun StorageUsageScreen(
    state: StorageUsageUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(StorageUsageTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Storage usage") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.isLoading -> LoadingState()
                state.errorMessage != null -> ErrorState(message = state.errorMessage, onRetry = onRetry)
                !state.available -> EmptyState(
                    title = "Storage usage not available",
                    body = "This feature is not enabled for your account.",
                    imageVector = Icons.Outlined.PieChart,
                    modifier = Modifier.testTag(StorageUsageTestTags.UNAVAILABLE),
                )
                state.isEmpty -> EmptyState(
                    title = "No usage yet",
                    body = "Upload files to see your storage usage here.",
                    imageVector = Icons.Outlined.PieChart,
                )
                else -> PullToRefreshBox(
                    isRefreshing = state.isRefreshing,
                    onRefresh = onRefresh,
                ) {
                    UsageContent(state)
                }
            }
        }
    }
}

@Composable
private fun UsageContent(state: StorageUsageUiState) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(StorageUsageTestTags.CONTENT),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.fillMaxWidth().padding(16.dp)) {
                    Text("Total stored", style = MaterialTheme.typography.labelMedium)
                    Text(
                        FileShareMath.formatBytes(state.storageBytesCurrent),
                        style = MaterialTheme.typography.headlineSmall,
                        modifier = Modifier.testTag(StorageUsageTestTags.TOTAL),
                    )
                }
            }
        }

        if (state.topFiles.isNotEmpty()) {
            item {
                Text(
                    "Largest files",
                    style = MaterialTheme.typography.titleMedium,
                )
            }
            items(state.topFiles) { file -> TopFileRow(file) }
        }

        if (state.dailyRows.isNotEmpty()) {
            item {
                val range = if (state.rangeFrom != null && state.rangeTo != null) {
                    "Daily transfer (${state.rangeFrom} - ${state.rangeTo})"
                } else {
                    "Daily transfer"
                }
                Text(range, style = MaterialTheme.typography.titleMedium)
            }
            items(state.dailyRows) { row -> DailyRow(row) }
        }
    }
}

@Composable
private fun TopFileRow(file: UsageStorageFileDto) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(StorageUsageTestTags.TOP_FILE_ROW)
            .padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            file.path,
            style = MaterialTheme.typography.bodyMedium,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f).padding(end = 12.dp),
        )
        Text(
            FileShareMath.formatBytes(file.size),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
    HorizontalDivider()
}

@Composable
private fun DailyRow(row: UsageDailyItemDto) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(StorageUsageTestTags.DAILY_ROW)
            .padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(row.day_utc, style = MaterialTheme.typography.bodyMedium)
        Text(
            "up ${FileShareMath.formatBytes(row.upload_bytes_total)} / down ${FileShareMath.formatBytes(row.download_bytes_total)}",
            style = MaterialTheme.typography.bodySmall,
        )
    }
    HorizontalDivider()
}
