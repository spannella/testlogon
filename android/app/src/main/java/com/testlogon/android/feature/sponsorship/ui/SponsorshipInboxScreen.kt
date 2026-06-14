@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.sponsorship.ui

import android.text.format.DateUtils
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Handshake
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import com.testlogon.android.core.model.sponsorship.SponsorshipDeal
import com.testlogon.android.core.model.sponsorship.SponsorshipDealStatus
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner

/** AND-365 - stable testTags for the sponsorship inbox screen + its rows / chips. */
object SponsorshipInboxTestTags {
    const val SCREEN = "sponsorship_inbox_screen"
    const val EMPTY = "sponsorship_empty"
    const val ERROR_RETRY = "sponsorship_error_retry"

    fun filter(key: String) = "sponsorship_filter_$key"

    fun row(dealId: String) = "sponsorship_deal_row_$dealId"

    fun status(dealId: String) = "sponsorship_status_$dealId"
}

/**
 * AND-365 - route-level entry. Collects the inbox state and wires the one-shot OpenDeal effect to a GUARDED
 * navigate (the deal-detail destination is owned downstream by AND-366; a thin placeholder is registered so
 * the tap-through never crashes).
 */
@Composable
fun SponsorshipInboxRoute(
    onBack: () -> Unit,
    onOpenDeal: (String) -> Unit,
    viewModel: SponsorshipInboxViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is SponsorshipInboxEffect.OpenDeal -> onOpenDeal(effect.dealId)
            }
        }
    }

    SponsorshipInboxScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onFilterSelected = viewModel::setFilter,
        onDealClick = viewModel::onDealClick,
    )
}

/** AND-365 - stateless READ-ONLY sponsorship inbox (single GET + client-side sort/filter; no paging). */
@Composable
fun SponsorshipInboxScreen(
    state: SponsorshipInboxUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onFilterSelected: (SponsorshipFilter) -> Unit,
    onDealClick: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(SponsorshipInboxTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.sponsorship_inbox_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.sponsorship_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        PullToRefreshBox(
            isRefreshing = false,
            onRefresh = onRefresh,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state) {
                is SponsorshipInboxUiState.Loading -> LoadingState()

                is SponsorshipInboxUiState.Empty ->
                    EmptyState(
                        modifier = Modifier.testTag(SponsorshipInboxTestTags.EMPTY),
                        title = stringResource(R.string.sponsorship_empty_title),
                        body = stringResource(R.string.sponsorship_empty_body),
                        imageVector = Icons.Outlined.Handshake,
                    )

                is SponsorshipInboxUiState.Error ->
                    ErrorState(
                        modifier = Modifier.testTag(SponsorshipInboxTestTags.ERROR_RETRY),
                        message = state.error.message,
                        onRetry = onRetry,
                    )

                is SponsorshipInboxUiState.Content ->
                    ContentBody(
                        state = state,
                        onRetry = onRetry,
                        onFilterSelected = onFilterSelected,
                        onDealClick = onDealClick,
                    )
            }
        }
    }
}

@Composable
private fun ContentBody(
    state: SponsorshipInboxUiState.Content,
    onRetry: () -> Unit,
    onFilterSelected: (SponsorshipFilter) -> Unit,
    onDealClick: (String) -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        StaleBanner(stale = state.isStale, refreshing = false, onRetry = onRetry)
        FilterRow(selected = state.filter, onFilterSelected = onFilterSelected)
        LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(items = state.deals, key = { it.dealId }) { deal ->
                SponsorshipDealRow(deal = deal, onClick = { onDealClick(deal.dealId) })
            }
        }
    }
}

@Composable
private fun FilterRow(
    selected: SponsorshipFilter,
    onFilterSelected: (SponsorshipFilter) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 12.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        SponsorshipFilter.entries.forEach { filter ->
            FilterChip(
                selected = filter == selected,
                onClick = { onFilterSelected(filter) },
                label = { Text(stringResource(filterLabelRes(filter))) },
                modifier = Modifier.testTag(SponsorshipInboxTestTags.filter(filter.key)),
            )
        }
    }
}

@Composable
private fun SponsorshipDealRow(
    deal: SponsorshipDeal,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(SponsorshipInboxTestTags.row(deal.dealId))
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(end = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = stringResource(
                    R.string.sponsorship_from_advertiser,
                    deal.advertiserSub ?: stringResource(R.string.sponsorship_advertiser_unknown),
                ),
                style = MaterialTheme.typography.titleSmall,
            )
            val brief = deal.brief
            if (!brief.isNullOrBlank()) {
                Text(
                    text = brief,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            StatusChip(deal)
            val received = relativeTime(deal.createdAt)
            if (received.isNotBlank()) {
                Text(
                    text = stringResource(R.string.sponsorship_received, received),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            val deadline = deal.deadline
            if (!deadline.isNullOrBlank()) {
                Text(
                    text = stringResource(R.string.sponsorship_deadline, deadline),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        val compensationCents = deal.compensationCents
        if (compensationCents != null) {
            Text(
                text = formatCents(compensationCents),
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
            )
        }
    }
}

@Composable
private fun StatusChip(deal: SponsorshipDeal) {
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(statusLabel(deal)) },
        colors = AssistChipDefaults.assistChipColors(),
        modifier = Modifier.testTag(SponsorshipInboxTestTags.status(deal.dealId)),
    )
}

/** The localized filter-chip label for a [SponsorshipFilter]. */
private fun filterLabelRes(filter: SponsorshipFilter): Int = when (filter) {
    SponsorshipFilter.ALL -> R.string.sponsorship_filter_all
    SponsorshipFilter.PENDING -> R.string.sponsorship_filter_pending
    SponsorshipFilter.ACTIVE -> R.string.sponsorship_filter_active
    SponsorshipFilter.COMPLETED -> R.string.sponsorship_filter_completed
    SponsorshipFilter.CANCELLED -> R.string.sponsorship_filter_cancelled
}

/**
 * AND-365 - the human status label. A recognized [SponsorshipDealStatus] uses a localized string; an UNKNOWN
 * status falls back to the RAW wire string (or a generic "Unknown" when blank), forward-compat for any new
 * server token.
 */
@Composable
private fun statusLabel(deal: SponsorshipDeal): String = when (deal.statusEnum) {
    SponsorshipDealStatus.PROPOSED -> stringResource(R.string.sponsorship_status_proposed)
    SponsorshipDealStatus.NEGOTIATING -> stringResource(R.string.sponsorship_status_negotiating)
    SponsorshipDealStatus.ACCEPTED -> stringResource(R.string.sponsorship_status_accepted)
    SponsorshipDealStatus.CONTENT_SUBMITTED -> stringResource(R.string.sponsorship_status_content_submitted)
    SponsorshipDealStatus.COMPLETED -> stringResource(R.string.sponsorship_status_completed)
    SponsorshipDealStatus.REJECTED -> stringResource(R.string.sponsorship_status_rejected)
    SponsorshipDealStatus.CANCELLED -> stringResource(R.string.sponsorship_status_cancelled)
    SponsorshipDealStatus.UNKNOWN ->
        deal.status.ifBlank { stringResource(R.string.sponsorship_status_unknown) }
}

/**
 * AND-365 - relative-time copy from an INTEGER epoch-SECONDS value. UI-only (android.text.format), returns ""
 * for null / non-positive timestamps. Mirrors the AND-358 collaborations helper.
 */
private fun relativeTime(epochSeconds: Long?, nowMs: Long = System.currentTimeMillis()): String {
    if (epochSeconds == null || epochSeconds <= 0L) return ""
    return DateUtils.getRelativeTimeSpanString(
        epochSeconds * 1000L,
        nowMs,
        DateUtils.MINUTE_IN_MILLIS,
    ).toString()
}
