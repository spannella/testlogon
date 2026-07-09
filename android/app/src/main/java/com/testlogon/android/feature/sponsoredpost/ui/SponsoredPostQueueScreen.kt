@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.sponsoredpost.ui

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
import androidx.compose.material.icons.outlined.Campaign
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
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
import com.testlogon.android.feature.sponsoredpost.data.SponsoredPostProposal

/** ADV2-408 - stable testTags for the creator approval queue. */
object SponsoredPostQueueTestTags {
    const val SCREEN = "spcp_queue_screen"
    const val EMPTY = "spcp_queue_empty"
    const val ERROR_RETRY = "spcp_queue_error_retry"

    fun row(id: String) = "spcp_queue_row_$id"
    fun approve(id: String) = "spcp_queue_approve_$id"
    fun reject(id: String) = "spcp_queue_reject_$id"
}

/** ADV2-408 - route-level creator approval-queue entry. */
@Composable
fun SponsoredPostQueueRoute(
    onBack: () -> Unit,
    viewModel: SponsoredPostQueueViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val acting by viewModel.acting.collectAsStateWithLifecycle()
    SponsoredPostQueueScreen(
        state = state,
        acting = acting,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onApprove = viewModel::approve,
        onReject = viewModel::reject,
    )
}

/** ADV2-408 - stateless creator approval queue. Each pending proposal -> Approve (publish) / Reject. */
@Composable
fun SponsoredPostQueueScreen(
    state: SponsoredPostQueueUiState,
    acting: Set<String>,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onApprove: (String) -> Unit,
    onReject: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(SponsoredPostQueueTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.spcp_queue_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.spcp_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        PullToRefreshBox(
            isRefreshing = false,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is SponsoredPostQueueUiState.Loading -> LoadingState()

                is SponsoredPostQueueUiState.Empty ->
                    EmptyState(
                        modifier = Modifier.testTag(SponsoredPostQueueTestTags.EMPTY),
                        title = stringResource(R.string.spcp_queue_empty_title),
                        body = stringResource(R.string.spcp_queue_empty_body),
                        imageVector = Icons.Outlined.Campaign,
                    )

                is SponsoredPostQueueUiState.Error ->
                    ErrorState(
                        modifier = Modifier.testTag(SponsoredPostQueueTestTags.ERROR_RETRY),
                        message = state.message,
                        onRetry = onRetry,
                    )

                is SponsoredPostQueueUiState.Content ->
                    LazyColumn(modifier = Modifier.fillMaxSize()) {
                        items(items = state.proposals, key = { it.proposalId }) { proposal ->
                            ProposalCard(
                                proposal = proposal,
                                busy = proposal.proposalId in acting,
                                onApprove = { onApprove(proposal.proposalId) },
                                onReject = { onReject(proposal.proposalId) },
                            )
                        }
                    }
            }
        }
    }
}

@Composable
private fun ProposalCard(
    proposal: SponsoredPostProposal,
    busy: Boolean,
    onApprove: () -> Unit,
    onReject: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 6.dp)
            .testTag(SponsoredPostQueueTestTags.row(proposal.proposalId)),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(
                    R.string.spcp_queue_from,
                    proposal.advertiserSub ?: stringResource(R.string.spcp_queue_advertiser_unknown),
                ),
                style = MaterialTheme.typography.titleSmall,
            )
            val body = proposal.body
            if (!body.isNullOrBlank()) {
                Text(
                    text = body,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 5,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            val disclosure = proposal.disclosure
            if (!disclosure.isNullOrBlank()) {
                Text(
                    text = disclosure,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                text = stringResource(R.string.spcp_queue_publish_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = onReject,
                    enabled = !busy,
                    modifier = Modifier.testTag(SponsoredPostQueueTestTags.reject(proposal.proposalId)),
                ) {
                    Text(stringResource(R.string.spcp_queue_reject))
                }
                Button(
                    onClick = onApprove,
                    enabled = !busy,
                    modifier = Modifier.testTag(SponsoredPostQueueTestTags.approve(proposal.proposalId)),
                ) {
                    Text(stringResource(R.string.spcp_queue_approve))
                }
            }
        }
    }
}
