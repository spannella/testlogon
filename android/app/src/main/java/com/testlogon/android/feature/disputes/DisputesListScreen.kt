@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.disputes

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.disputes.Dispute

/** AND-245 — stable testTags for the disputes list screen. */
object DisputesListTestTags {
    const val SCREEN = "disputes_screen"
    const val LIST = "disputes_list"
    const val EMPTY = "disputes_empty"
    const val ERROR = "disputes_error"
    const val ROW = "dispute_row"
}

/** AND-245 — route-level disputes list, reachable from billing / the More hub. */
@Composable
fun DisputesListRoute(
    onDisputeClick: (disputeId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: DisputesListViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    DisputesListScreen(
        state = state,
        onDisputeClick = onDisputeClick,
        onRetry = viewModel::load,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun DisputesListScreen(
    state: DisputesListUiState,
    onDisputeClick: (String) -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(DisputesListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.disputes_title)) },
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
                is DisputesListUiState.Loading ->
                    LoadingState(message = stringResource(R.string.disputes_loading))

                is DisputesListUiState.Empty ->
                    EmptyState(
                        title = stringResource(R.string.disputes_empty),
                        modifier = Modifier.testTag(DisputesListTestTags.EMPTY),
                    )

                is DisputesListUiState.Failure ->
                    ErrorState(
                        message = s.message.asString(),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(DisputesListTestTags.ERROR),
                    )

                is DisputesListUiState.Content ->
                    LazyColumn(modifier = Modifier.fillMaxSize().testTag(DisputesListTestTags.LIST)) {
                        items(items = s.disputes, key = { it.id }) { dispute ->
                            DisputeRow(dispute = dispute, onClick = { onDisputeClick(dispute.id) })
                        }
                    }
            }
        }
    }
}

@Composable
private fun DisputeRow(dispute: Dispute, onClick: () -> Unit) {
    val dateText = formatDisputeDate(dispute.createdAtEpochSeconds)
        ?: stringResource(R.string.disputes_date_unknown)
    val amountText = formatDisputeMoney(dispute.amount)
    val statusText = stringResource(disputeStatusLabelRes(dispute.status))
    val cd = "$amountText, $statusText, $dateText"
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(DisputesListTestTags.ROW)
            .clearAndSetSemantics { contentDescription = cd },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(text = amountText, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = "$dateText · ${dispute.reason}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        AssistChip(
            onClick = onClick,
            label = { Text(statusText) },
            modifier = Modifier.padding(start = 8.dp),
        )
    }
}
