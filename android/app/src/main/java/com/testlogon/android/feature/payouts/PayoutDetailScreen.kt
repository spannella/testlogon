@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.payouts

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.data.payouts.Payout
import com.testlogon.android.data.payouts.PayoutStatus

/** AND-260 — stable testTags for the payout detail screen. */
object PayoutDetailTestTags {
    const val SCREEN = "payout_detail_screen"
    const val CONTENT = "payout_detail_content"
    const val NOT_FOUND = "payout_detail_not_found"
    const val REJECT_REASON = "payout_detail_reject_reason"
}

/** AND-260 — route-level payout detail entry (cache-hydrated; no network call). */
@Composable
fun PayoutDetailRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PayoutDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    PayoutDetailScreen(state = state, onBack = onBack, modifier = modifier)
}

@Composable
fun PayoutDetailScreen(
    state: PayoutDetailUiState,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(PayoutDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.payout_detail_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("payout_detail_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            is PayoutDetailUiState.Content -> PayoutDetailContent(
                payout = state.payout,
                modifier = Modifier.padding(padding),
            )
            PayoutDetailUiState.NotFound -> EmptyState(
                title = stringResource(R.string.payout_detail_not_found_title),
                body = stringResource(R.string.payout_detail_not_found_body),
                modifier = Modifier.padding(padding).testTag(PayoutDetailTestTags.NOT_FOUND),
            )
        }
    }
}

@Composable
private fun PayoutDetailContent(payout: Payout, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .testTag(PayoutDetailTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = formatPayoutMoney(payout.amount),
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.semantics { heading() },
            )
            PayoutStatusChip(status = payout.status)
        }

        HorizontalDivider()

        DetailRow(
            label = stringResource(R.string.payout_detail_method),
            value = stringResource(payoutMethodLabelRes(payout.method)),
        )
        DetailRow(
            label = stringResource(R.string.payout_detail_created),
            value = formatPayoutDate(payout.createdAtEpochSeconds)
                ?: stringResource(R.string.payout_date_unknown),
        )
        DetailRow(
            label = stringResource(R.string.payout_detail_updated),
            value = formatPayoutDate(payout.updatedAtEpochSeconds)
                ?: stringResource(R.string.payout_date_unknown),
        )
        if (payout.completedAtEpochSeconds != null) {
            DetailRow(
                label = stringResource(R.string.payout_detail_completed),
                value = formatPayoutDate(payout.completedAtEpochSeconds)
                    ?: stringResource(R.string.payout_date_unknown),
            )
        }
        if (payout.notes.isNotBlank()) {
            DetailRow(label = stringResource(R.string.payout_detail_notes), value = payout.notes)
        }
        if (payout.status == PayoutStatus.REJECTED && payout.rejectReason.isNotBlank()) {
            HorizontalDivider()
            Column(
                modifier = Modifier.fillMaxWidth().testTag(PayoutDetailTestTags.REJECT_REASON),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = stringResource(R.string.payout_detail_reject_reason),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.error,
                )
                Text(text = payout.rejectReason, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(start = 16.dp),
        )
    }
}
