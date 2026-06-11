@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.disputes

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.disputes.Dispute

/** AND-245 — stable testTags for the dispute detail screen. */
object DisputeDetailTestTags {
    const val SCREEN = "dispute_detail_screen"
    const val CONTENT = "dispute_detail_content"
    const val NOT_FOUND = "dispute_detail_not_found"
    const val STATUS = "dispute_detail_status"
}

/** AND-245 — route-level dispute detail (status, reason, amount, evidence/resolution, deadline). */
@Composable
fun DisputeDetailRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: DisputeDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    DisputeDetailScreen(state = state, onRetry = viewModel::load, onBack = onBack, modifier = modifier)
}

@Composable
fun DisputeDetailScreen(
    state: DisputeDetailUiState,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(DisputeDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.disputes_detail_title)) },
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
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (val s = state) {
                is DisputeDetailUiState.Loading -> LoadingState()
                is DisputeDetailUiState.NotFound ->
                    EmptyState(
                        title = stringResource(R.string.disputes_not_found),
                        modifier = Modifier.testTag(DisputeDetailTestTags.NOT_FOUND),
                    )
                is DisputeDetailUiState.Failure ->
                    ErrorState(message = s.message.asString(), onRetry = onRetry)
                is DisputeDetailUiState.Content -> DisputeDetailContent(s.dispute)
            }
        }
    }
}

@Composable
private fun DisputeDetailContent(dispute: Dispute) {
    val statusText = stringResource(disputeStatusLabelRes(dispute.status))
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .testTag(DisputeDetailTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(formatDisputeMoney(dispute.amount), style = MaterialTheme.typography.headlineSmall)
                AssistChip(
                    onClick = {},
                    label = { Text(statusText) },
                    modifier = Modifier.testTag(DisputeDetailTestTags.STATUS),
                )
                formatDisputeDate(dispute.createdAtEpochSeconds)?.let {
                    Text(
                        stringResource(R.string.disputes_detail_opened_on, it),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                formatDisputeDate(dispute.deadlineAtEpochSeconds)?.let {
                    Text(
                        stringResource(R.string.disputes_detail_evidence_due, it),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.disputes_detail_reason_label), style = MaterialTheme.typography.titleSmall)
                Text(dispute.reason, style = MaterialTheme.typography.bodyMedium)
            }
        }
        dispute.resolution?.let { resolution ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        stringResource(R.string.disputes_detail_resolution_label),
                        style = MaterialTheme.typography.titleSmall,
                    )
                    Text(resolution, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}
