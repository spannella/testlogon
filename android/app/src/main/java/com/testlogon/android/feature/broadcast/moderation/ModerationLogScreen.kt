@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.broadcast.moderation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/**
 * AND-313 - moderation-log entry. Collects [ModerationViewModel] state and delegates to the stateless
 * [ModerationLogScreen]. Loads the log once on first composition; refresh is pull-to-refresh only (NO poll
 * loop, NO paging). Reached from the chat panel / host control surface (BroadcastModerationLogDest).
 */
@Composable
fun ModerationLogRoute(
    onBack: () -> Unit,
    viewModel: ModerationViewModel = hiltViewModel(),
) {
    val state by viewModel.logState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) { viewModel.loadLog() }
    ModerationLogScreen(
        state = state,
        onRefresh = viewModel::refresh,
        onUnban = viewModel::unban,
        onRetry = viewModel::loadLog,
        onBack = onBack,
    )
}

/**
 * AND-313 - stateless moderation-log surface: a plain LazyColumn of log rows (newest-first) plus the current
 * bans (each ban row offers Unban). Loading / Empty / Error / Offline reuse the AND-021 core-ui state
 * composables; pull-to-refresh drives [onRefresh].
 */
@Composable
fun ModerationLogScreen(
    state: ModerationLogUiState,
    onRefresh: () -> Unit,
    onUnban: (String) -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag(ModerationTestTags.LOG_SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.moderation_log_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.moderation_back_cd),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                ModerationLogUiState.Loading -> LoadingState()

                ModerationLogUiState.Empty -> EmptyState(
                    title = stringResource(R.string.moderation_log_empty_title),
                    body = stringResource(R.string.moderation_log_empty_body),
                )

                is ModerationLogUiState.Error ->
                    if (state.offline) {
                        OfflineBanner(message = state.message, onRetry = onRetry)
                    } else {
                        ErrorState(
                            message = state.message,
                            onRetry = onRetry,
                            title = stringResource(R.string.moderation_log_error_title),
                        )
                    }

                is ModerationLogUiState.Content -> PullToRefreshBox(
                    isRefreshing = state.isRefreshing,
                    onRefresh = onRefresh,
                    modifier = Modifier.fillMaxSize(),
                ) {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(12.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        if (state.bans.isNotEmpty()) {
                            items(state.bans, key = { "ban_${it.userId}" }) { ban ->
                                BanRow(ban = ban, onUnban = { onUnban(ban.userId) })
                            }
                        }
                        items(state.entries, key = { it.id }) { entry ->
                            LogRow(entry = entry)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LogRow(entry: ModerationLogEntry) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(ModerationTestTags.LOG_ROW)
            .padding(vertical = 4.dp),
    ) {
        Text(
            text = stringResource(actionLabelRes(entry.action)),
            style = MaterialTheme.typography.titleSmall,
        )
        val detail = entry.targetLabel.ifBlank { entry.moderatorName }
        Text(
            text = stringResource(R.string.moderation_log_row_summary, entry.moderatorName, detail),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (!entry.reason.isNullOrBlank()) {
            Text(
                text = stringResource(R.string.moderation_log_row_reason, entry.reason),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Text(
            text = formatTimestamp(entry.createdAt),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun BanRow(ban: ModerationBan, onUnban: () -> Unit) {
    val name = ban.displayName ?: ban.userId
    Box(modifier = Modifier.fillMaxWidth().testTag(ModerationTestTags.LOG_ROW)) {
        Column(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
            Text(
                text = stringResource(R.string.moderation_log_ban_row, name),
                style = MaterialTheme.typography.titleSmall,
            )
            if (!ban.reason.isNullOrBlank()) {
                Text(
                    text = stringResource(R.string.moderation_log_row_reason, ban.reason),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            TextButton(
                onClick = onUnban,
                modifier = Modifier.heightIn(min = 48.dp).testTag(ModerationTestTags.UNBAN),
            ) {
                Text(stringResource(R.string.moderation_unban))
            }
        }
    }
}

private fun actionLabelRes(action: ModerationActionType): Int = when (action) {
    ModerationActionType.MUTE -> R.string.moderation_action_mute
    ModerationActionType.UNMUTE -> R.string.moderation_action_unmute
    ModerationActionType.BAN -> R.string.moderation_action_ban
    ModerationActionType.UNBAN -> R.string.moderation_action_unban
    ModerationActionType.DELETE -> R.string.moderation_action_delete
    ModerationActionType.PIN -> R.string.moderation_action_pin
    ModerationActionType.UNPIN -> R.string.moderation_action_unpin
    ModerationActionType.UNKNOWN -> R.string.moderation_action_unknown
}

private val TIMESTAMP_FORMATTER: DateTimeFormatter =
    DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM)

private fun formatTimestamp(instant: Instant): String =
    runCatching {
        TIMESTAMP_FORMATTER.withZone(ZoneId.systemDefault()).format(instant)
    }.getOrDefault(instant.toString())
