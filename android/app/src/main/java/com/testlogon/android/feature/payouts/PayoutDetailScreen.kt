@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.payouts

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
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
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.payouts.PayoutDetail
import com.testlogon.android.data.payouts.PayoutStatus
import com.testlogon.android.data.payouts.PayoutTimelineEntry

/** PAY-53 — stable testTags for the payout statement/detail screen. */
object PayoutDetailTestTags {
    const val SCREEN = "payout_detail_screen"
    const val CONTENT = "payout_detail_content"
    const val LOADING = "payout_detail_loading"
    const val ERROR = "payout_detail_error"
    const val NOT_FOUND = "payout_detail_not_found"
    const val TIMELINE = "payout_detail_timeline"
    const val FAIL_REASON = "payout_detail_fail_reason"
    // Legacy AND-260 alias kept for any existing test references.
    const val REJECT_REASON = "payout_detail_reject_reason"
}

/** PAY-53 — route-level payout statement/detail entry (real GET /ui/payouts/{id}; server-resolved). */
@Composable
fun PayoutDetailRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PayoutDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    PayoutDetailScreen(state = state, onBack = onBack, onRetry = viewModel::load, modifier = modifier)
}

@Composable
fun PayoutDetailScreen(
    state: PayoutDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
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
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                PayoutDetailUiState.Loading ->
                    LoadingState(
                        message = stringResource(R.string.payout_detail_loading),
                        modifier = Modifier.testTag(PayoutDetailTestTags.LOADING),
                    )

                is PayoutDetailUiState.Content -> PayoutDetailContent(detail = state.detail)

                PayoutDetailUiState.NotFound -> EmptyState(
                    title = stringResource(R.string.payout_detail_not_found_title),
                    body = stringResource(R.string.payout_detail_not_found_body),
                    modifier = Modifier.testTag(PayoutDetailTestTags.NOT_FOUND),
                )

                is PayoutDetailUiState.Error -> ErrorState(
                    message = state.message?.asString() ?: stringResource(R.string.payout_detail_error_generic),
                    onRetry = onRetry,
                    modifier = Modifier.testTag(PayoutDetailTestTags.ERROR),
                )
            }
        }
    }
}

@Composable
private fun PayoutDetailContent(detail: PayoutDetail, modifier: Modifier = Modifier) {
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
                text = formatPayoutMoney(detail.amount),
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.semantics { heading() },
            )
            PayoutStatusChip(status = detail.displayStatus)
        }

        HorizontalDivider()

        // Destination: the normalized method type + the resolved last-4 (PAY-B tokenized method).
        val methodLine = stringResource(payoutMethodLabelRes(detail.method)) +
            (if (detail.methodLast4.isNotBlank()) " ••${detail.methodLast4}" else "")
        DetailRow(label = stringResource(R.string.payout_detail_method), value = methodLine)

        DetailRow(
            label = stringResource(R.string.payout_detail_created),
            value = formatPayoutDate(detail.createdAtEpochSeconds)
                ?: stringResource(R.string.payout_date_unknown),
        )
        if (detail.completedAtEpochSeconds != null) {
            DetailRow(
                label = stringResource(R.string.payout_detail_completed),
                value = formatPayoutDate(detail.completedAtEpochSeconds)
                    ?: stringResource(R.string.payout_date_unknown),
            )
        }
        // Transfer reference (the honest transfer seam ref; empty until the transfer runs).
        if (detail.transferRef.isNotBlank() || detail.transferProvider.isNotBlank()) {
            val provider = detail.transferProvider.ifBlank { stringResource(R.string.payout_detail_provider_unknown) }
            DetailRow(label = stringResource(R.string.payout_detail_provider), value = provider)
            if (detail.transferRef.isNotBlank()) {
                DetailRow(label = stringResource(R.string.payout_detail_transfer_ref), value = detail.transferRef)
            }
        }
        if (detail.transferAttempts > 0) {
            DetailRow(
                label = stringResource(R.string.payout_detail_attempts),
                value = detail.transferAttempts.toString(),
            )
        }
        if (detail.notes.isNotBlank()) {
            DetailRow(label = stringResource(R.string.payout_detail_notes), value = detail.notes)
        }

        // Hold reason (manual-hold pauses the runner).
        if (detail.manualHold && detail.holdReason.isNotBlank()) {
            ReasonBlock(
                title = stringResource(R.string.payout_detail_hold_reason),
                body = detail.holdReason,
                color = MaterialTheme.colorScheme.tertiary,
            )
        }

        // Failure / return reason.
        val failure = detail.failureReason
        if (failure.isNotBlank() &&
            detail.status in setOf(PayoutStatus.FAILED, PayoutStatus.RETURNED, PayoutStatus.REJECTED)
        ) {
            ReasonBlock(
                title = stringResource(R.string.payout_detail_fail_reason),
                body = failure,
                color = MaterialTheme.colorScheme.error,
                testTag = PayoutDetailTestTags.FAIL_REASON,
            )
            if (detail.debitReversed) {
                Text(
                    text = stringResource(R.string.payout_detail_debit_reversed),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        // Lifecycle timeline.
        if (detail.timeline.isNotEmpty()) {
            HorizontalDivider()
            Text(
                text = stringResource(R.string.payout_detail_timeline_title),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.semantics { heading() },
            )
            Column(
                modifier = Modifier.fillMaxWidth().testTag(PayoutDetailTestTags.TIMELINE),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                detail.timeline.forEach { TimelineRow(it) }
            }
        }
    }
}

@Composable
private fun TimelineRow(entry: PayoutTimelineEntry) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Surface(
            shape = CircleShape,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(10.dp).padding(top = 4.dp),
        ) {}
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = stringResource(payoutTimelineStatusLabelRes(entry.status)),
                style = MaterialTheme.typography.bodyLarge,
            )
            val ts = formatPayoutDate(entry.tsEpochSeconds)
            Text(
                text = ts ?: stringResource(R.string.payout_date_pending),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (entry.note.isNotBlank()) {
                Text(
                    text = entry.note,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun ReasonBlock(
    title: String,
    body: String,
    color: androidx.compose.ui.graphics.Color,
    testTag: String? = null,
) {
    HorizontalDivider()
    Column(
        modifier = (if (testTag != null) Modifier.testTag(testTag) else Modifier).fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(text = title, style = MaterialTheme.typography.labelLarge, color = color)
        Text(text = body, style = MaterialTheme.typography.bodyMedium)
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
