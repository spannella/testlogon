@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.broadcast.qna

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.PushPin
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.broadcast.qna.QaHostQuestion
import com.testlogon.android.data.broadcast.qna.QaStats

/** Host-console route (web LiveQaPage host view). */
@Composable
fun LiveQaHostRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: LiveQaHostViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LiveQaHostScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::load,
        onToggleMode = viewModel::setMode,
        onSelectFilter = viewModel::selectFilter,
        onFeature = viewModel::feature,
        onAnswer = viewModel::answer,
        onDismiss = viewModel::dismiss,
        onTogglePin = viewModel::togglePin,
        onRemove = viewModel::remove,
        modifier = modifier,
    )
}

@Composable
fun LiveQaHostScreen(
    state: LiveQaHostUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onToggleMode: (Boolean) -> Unit,
    onSelectFilter: (QaQueueFilter) -> Unit,
    onFeature: (String) -> Unit,
    onAnswer: (String) -> Unit,
    onDismiss: (String) -> Unit,
    onTogglePin: (String, Boolean) -> Unit,
    onRemove: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(LiveQaHostTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.live_qa_host_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.live_qa_host_back_cd),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                LiveQaHostUiState.Loading -> LoadingState()
                is LiveQaHostUiState.Error -> ErrorState(
                    message = state.message,
                    onRetry = onRetry,
                    modifier = Modifier.testTag(LiveQaHostTestTags.ERROR_RETRY),
                )
                is LiveQaHostUiState.Content -> HostContent(
                    state = state,
                    onToggleMode = onToggleMode,
                    onSelectFilter = onSelectFilter,
                    onFeature = onFeature,
                    onAnswer = onAnswer,
                    onDismiss = onDismiss,
                    onTogglePin = onTogglePin,
                    onRemove = onRemove,
                )
            }
        }
    }
}

@Composable
private fun HostContent(
    state: LiveQaHostUiState.Content,
    onToggleMode: (Boolean) -> Unit,
    onSelectFilter: (QaQueueFilter) -> Unit,
    onFeature: (String) -> Unit,
    onAnswer: (String) -> Unit,
    onDismiss: (String) -> Unit,
    onTogglePin: (String, Boolean) -> Unit,
    onRemove: (String) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(LiveQaHostTestTags.QUEUE),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            Card {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            stringResource(R.string.live_qa_host_mode_label),
                            style = MaterialTheme.typography.titleMedium,
                        )
                        Text(
                            stringResource(
                                if (state.qaModeEnabled) R.string.live_qa_host_mode_on
                                else R.string.live_qa_host_mode_off,
                            ),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        checked = state.qaModeEnabled,
                        enabled = !state.togglingMode,
                        onCheckedChange = onToggleMode,
                        modifier = Modifier.testTag(LiveQaHostTestTags.MODE_SWITCH),
                    )
                }
            }
        }

        state.stats?.let { stats ->
            item { StatsCard(stats) }
        }

        item {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                QaQueueFilter.values().forEach { f ->
                    FilterChip(
                        selected = state.filter == f,
                        onClick = { onSelectFilter(f) },
                        label = { Text(filterLabel(f)) },
                    )
                }
            }
        }

        if (!state.qaModeEnabled) {
            item {
                EmptyState(
                    title = stringResource(R.string.live_qa_host_disabled_title),
                    body = stringResource(R.string.live_qa_host_disabled_body),
                )
            }
        } else if (state.questions.isEmpty() && !state.loadingQueue) {
            item {
                EmptyState(
                    title = stringResource(R.string.live_qa_host_empty_title),
                    body = stringResource(R.string.live_qa_host_empty_body),
                )
            }
        } else {
            items(state.questions, key = { it.id }) { q ->
                HostQuestionCard(
                    q = q,
                    busy = state.actingOnId == q.id,
                    onFeature = { onFeature(q.id) },
                    onAnswer = { onAnswer(q.id) },
                    onDismiss = { onDismiss(q.id) },
                    onTogglePin = { onTogglePin(q.id, !q.pinned) },
                    onRemove = { onRemove(q.id) },
                )
            }
        }
    }
}

@Composable
private fun StatsCard(stats: QaStats) {
    Card {
        Column(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(stringResource(R.string.live_qa_host_stats_title), style = MaterialTheme.typography.titleSmall)
            Text(
                stringResource(
                    R.string.live_qa_host_stats_line,
                    stats.totalQuestions,
                    stats.pending,
                    stats.answered,
                    stats.featured,
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                stringResource(R.string.live_qa_host_stats_line2, stats.totalUpvotes, stats.answerRate),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun HostQuestionCard(
    q: QaHostQuestion,
    busy: Boolean,
    onFeature: () -> Unit,
    onAnswer: () -> Unit,
    onDismiss: () -> Unit,
    onTogglePin: () -> Unit,
    onRemove: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(LiveQaHostTestTags.row(q.id))) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (q.pinned) {
                    Icon(
                        Icons.Outlined.PushPin,
                        contentDescription = null,
                        modifier = Modifier.padding(end = 4.dp),
                    )
                }
                Text(
                    q.authorDisplayName,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f),
                )
                AssistChip(
                    onClick = {},
                    enabled = false,
                    label = { Text(stringResource(R.string.live_qa_host_votes, q.upvotes)) },
                )
            }
            Text(q.text, style = MaterialTheme.typography.bodyMedium)
            HorizontalDivider()
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (!q.isFeatured) {
                    FilledTonalButton(
                        onClick = onFeature,
                        enabled = !busy,
                        modifier = Modifier.testTag(LiveQaHostTestTags.feature(q.id)),
                    ) { Text(stringResource(R.string.live_qa_host_action_feature)) }
                }
                if (!q.isAnswered) {
                    OutlinedButton(
                        onClick = onAnswer,
                        enabled = !busy,
                        modifier = Modifier.testTag(LiveQaHostTestTags.answer(q.id)),
                    ) { Text(stringResource(R.string.live_qa_host_action_answer)) }
                }
                OutlinedButton(
                    onClick = onTogglePin,
                    enabled = !busy,
                ) {
                    Text(
                        stringResource(
                            if (q.pinned) R.string.live_qa_host_action_unpin
                            else R.string.live_qa_host_action_pin,
                        ),
                    )
                }
                TextButton(
                    onClick = onDismiss,
                    enabled = !busy,
                    modifier = Modifier.testTag(LiveQaHostTestTags.dismiss(q.id)),
                ) { Text(stringResource(R.string.live_qa_host_action_dismiss)) }
                TextButton(onClick = onRemove, enabled = !busy) {
                    Text(stringResource(R.string.live_qa_host_action_remove))
                }
            }
        }
    }
}

@Composable
private fun filterLabel(f: QaQueueFilter): String = when (f) {
    QaQueueFilter.PENDING -> stringResource(R.string.live_qa_host_filter_pending)
    QaQueueFilter.FEATURED -> stringResource(R.string.live_qa_host_filter_featured)
    QaQueueFilter.ANSWERED -> stringResource(R.string.live_qa_host_filter_answered)
}
