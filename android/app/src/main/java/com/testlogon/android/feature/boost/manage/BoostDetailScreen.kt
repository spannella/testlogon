@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.boost.manage

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.model.ads.ContentBoost
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import java.text.DateFormat
import java.util.Date

/** Stable testTags for the boost detail screen. */
object BoostDetailTestTags {
    const val SCREEN = "boost_detail_screen"
    const val CONTENT = "boost_detail_content"
    const val ERROR_RETRY = "boost_detail_error_retry"
    const val STATUS = "boost_detail_status"
    const val SPENT = "boost_detail_spent"
    const val REMAINING = "boost_detail_remaining"
    const val CANCEL = "boost_detail_cancel"
    const val REFRESH = "boost_detail_refresh"
}

@Composable
fun BoostDetailRoute(
    onBack: () -> Unit,
    viewModel: BoostDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    BoostDetailScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onRefresh = viewModel::refresh,
        onCancel = viewModel::cancel,
    )
}

@Composable
fun BoostDetailScreen(
    state: BoostDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(BoostDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Boost") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is BoostDetailUiState.Loading -> LoadingState()
                is BoostDetailUiState.Error -> ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.testTag(BoostDetailTestTags.ERROR_RETRY),
                )
                is BoostDetailUiState.Content -> DetailBody(state, onRefresh, onCancel)
            }
        }
    }
}

@Composable
private fun DetailBody(
    state: BoostDetailUiState.Content,
    onRefresh: () -> Unit,
    onCancel: () -> Unit,
) {
    val boost = state.boost
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .testTag(BoostDetailTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(boost.boostId, style = MaterialTheme.typography.titleLarge)

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                DetailRow("Status", boost.status, valueTag = BoostDetailTestTags.STATUS)
                HorizontalDivider()
                DetailRow("Budget", formatCents(boost.budgetCents))
                boost.spentCents?.let { spent ->
                    DetailRow("Spent", spendLabel(spent, boost), valueTag = BoostDetailTestTags.SPENT)
                }
                boost.remainingCents?.let {
                    DetailRow("Remaining", formatCents(it), valueTag = BoostDetailTestTags.REMAINING)
                }
                boost.durationSeconds?.let {
                    DetailRow("Duration", "${it / 60L} min")
                }
                boost.endsAt?.let {
                    DetailRow("Ends at", formatEpoch(it))
                }
                SpendProgress(boost)
            }
        }

        if (state.cancelledRefundCents != null) {
            Text(
                "Boost cancelled. Refunded ${formatCents(state.cancelledRefundCents)} to your wallet.",
                color = MaterialTheme.colorScheme.primary,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        if (state.actionError != null) {
            Text(state.actionError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
        }

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(
                onClick = onRefresh,
                enabled = !state.refreshing && !state.cancelling,
                modifier = Modifier.testTag(BoostDetailTestTags.REFRESH),
            ) {
                if (state.refreshing) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
                } else {
                    Text("Refresh")
                }
            }
            if (state.canCancel) {
                Button(
                    onClick = onCancel,
                    enabled = !state.cancelling && !state.refreshing,
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                    modifier = Modifier.testTag(BoostDetailTestTags.CANCEL),
                ) {
                    if (state.cancelling) {
                        CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
                    } else {
                        Text("Cancel & refund remaining")
                    }
                }
            }
        }
    }
}

@Composable
private fun SpendProgress(boost: ContentBoost) {
    val spent = boost.spentCents ?: return
    if (boost.budgetCents <= 0L) return
    val pct = (spent.toFloat() / boost.budgetCents.toFloat()).coerceIn(0f, 1f)
    LinearProgressIndicator(progress = { pct }, modifier = Modifier.fillMaxWidth())
}

@Composable
private fun DetailRow(label: String, value: String, valueTag: String? = null) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            modifier = if (valueTag != null) Modifier.testTag(valueTag) else Modifier,
        )
    }
}

private fun spendLabel(spent: Long, boost: ContentBoost): String {
    val pct = if (boost.budgetCents > 0L) ((spent * 100L) / boost.budgetCents) else 0L
    return "${formatCents(spent)} (${pct}%)"
}

private fun formatEpoch(epochSeconds: Long): String =
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(epochSeconds * 1000L))
