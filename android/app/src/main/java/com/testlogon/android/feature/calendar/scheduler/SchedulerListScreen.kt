@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.calendar.scheduler

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.scheduler.ActionStatuses
import com.testlogon.android.data.scheduler.ScheduledAction
import com.testlogon.android.feature.calendar.CalendarDateFormat

/** AND-275 — stable test tags for the scheduled-actions list. */
object SchedulerListTestTags {
    const val SCREEN = "scheduler_list_screen"
    const val LIST = "scheduler_list"
    const val CREATE = "scheduler_create_fab"
    fun item(id: String) = "scheduler_item_$id"
    fun cancel(id: String) = "scheduler_cancel_$id"
}

/**
 * AND-275 — the scheduled-actions list. The FAB opens the create sheet; tapping a pending row opens the
 * edit/reschedule sheet; a pending row also exposes Cancel.
 */
@Composable
fun SchedulerListRoute(
    onBack: () -> Unit,
    onCreate: () -> Unit,
    onEdit: (actionId: String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: SchedulerListViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    SchedulerListScreen(
        state = state,
        onBack = onBack,
        onCreate = onCreate,
        onEdit = onEdit,
        onCancel = viewModel::onCancel,
        onRetry = viewModel::retry,
        canCancel = viewModel::canCancel,
        modifier = modifier,
    )
}

@Composable
fun SchedulerListScreen(
    state: SchedulerListUiState,
    onBack: () -> Unit,
    onCreate: () -> Unit,
    onEdit: (String) -> Unit,
    onCancel: (String) -> Unit,
    onRetry: () -> Unit,
    canCancel: (ScheduledAction) -> Boolean,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(SchedulerListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.scheduler_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = onCreate,
                modifier = Modifier.testTag(SchedulerListTestTags.CREATE),
            ) {
                Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.scheduler_create))
            }
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is SchedulerListUiState.Loading -> LoadingState()
                is SchedulerListUiState.Empty ->
                    EmptyState(
                        title = stringResource(R.string.scheduler_empty_title),
                        body = stringResource(R.string.scheduler_empty_body),
                    )
                is SchedulerListUiState.Error ->
                    if (state.isOffline) {
                        OfflineBanner(onRetry = onRetry)
                    } else {
                        ErrorState(message = state.message, onRetry = onRetry)
                    }
                is SchedulerListUiState.Content ->
                    ActionList(state, onEdit, onCancel, canCancel)
            }
        }
    }
}

@Composable
private fun ActionList(
    content: SchedulerListUiState.Content,
    onEdit: (String) -> Unit,
    onCancel: (String) -> Unit,
    canCancel: (ScheduledAction) -> Boolean,
) {
    LazyColumn(
        Modifier.fillMaxSize().testTag(SchedulerListTestTags.LIST),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(content.actions, key = { it.actionId }) { action ->
            ActionRow(
                action = action,
                showCancel = canCancel(action),
                cancelling = content.cancellingId == action.actionId,
                onEdit = { if (action.status == ActionStatuses.PENDING) onEdit(action.actionId) },
                onCancel = { onCancel(action.actionId) },
            )
        }
    }
}

@Composable
private fun ActionRow(
    action: ScheduledAction,
    showCancel: Boolean,
    cancelling: Boolean,
    onEdit: () -> Unit,
    onCancel: () -> Unit,
) {
    Surface(
        tonalElevation = 1.dp,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onEdit)
            .testTag(SchedulerListTestTags.item(action.actionId)),
    ) {
        Column(Modifier.padding(12.dp)) {
            Text(
                text = action.title.ifBlank { action.actionType },
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = CalendarDateFormat.formatDateTime(action.scheduledAt.toEpochMilli(), "UTC"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = action.status,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
                if (showCancel) {
                    TextButton(
                        onClick = onCancel,
                        enabled = !cancelling,
                        modifier = Modifier.testTag(SchedulerListTestTags.cancel(action.actionId)),
                    ) {
                        Text(stringResource(R.string.scheduler_cancel))
                    }
                }
            }
        }
    }
}
