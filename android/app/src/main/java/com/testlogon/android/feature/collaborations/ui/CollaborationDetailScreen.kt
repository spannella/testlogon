@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.collaborations.ui

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.LockClock
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.collaborations.CollabStatus
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.model.collaborations.SplitDistribution
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-358 - stable testTags shared by the collaborations list + detail screens. */
object CollaborationsTestTags {
    const val DETAIL_SCREEN = "collab_detail_screen"
    const val STATUS = "collab_status"
    const val SPLIT_TOTAL = "collab_split_total"
    const val SPLIT_WARNING = "collab_split_warning"
    const val SESSION_EXPIRED = "collab_session_expired"
    const val STALE = "collab_stale"

    fun splitRow(userId: String) = "collab_split_row_$userId"
    fun distribution(index: Int) = "collab_distribution_$index"
}

/** AND-358 - route-level detail entry; collects the detail state + viewer id. */
@Composable
fun CollaborationDetailRoute(
    onBack: () -> Unit,
    viewModel: CollaborationDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    CollaborationDetailScreen(
        state = state,
        viewerId = viewModel.viewerId,
        onBack = onBack,
        onRetry = viewModel::retry,
    )
}

/** AND-358 - stateless READ-ONLY collaboration detail (two parties + status + revenue split + amounts). */
@Composable
fun CollaborationDetailScreen(
    state: CollaborationDetailUiState,
    viewerId: String?,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CollaborationsTestTags.DETAIL_SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.collaboration_detail_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.collaborations_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            is CollaborationDetailUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding))

            is CollaborationDetailUiState.SessionExpired ->
                EmptyState(
                    title = stringResource(R.string.collaborations_session_expired_title),
                    body = stringResource(R.string.collaborations_session_expired_body),
                    imageVector = Icons.Outlined.LockClock,
                    modifier = Modifier
                        .padding(padding)
                        .testTag(CollaborationsTestTags.SESSION_EXPIRED),
                )

            is CollaborationDetailUiState.Error ->
                ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.padding(padding),
                )

            is CollaborationDetailUiState.Content ->
                DetailBody(
                    state = state,
                    viewerId = viewerId,
                    modifier = Modifier.padding(padding),
                )
        }
    }
}

@Composable
private fun DetailBody(
    state: CollaborationDetailUiState.Content,
    viewerId: String?,
    modifier: Modifier = Modifier,
) {
    val collab = state.collab
    LazyColumn(modifier = modifier.fillMaxSize()) {
        if (state.isStale) {
            item(key = "stale") { StaleRow() }
        }
        item(key = "header") { Header(collab) }
        item(key = "parties") { PartiesSection(collab) }
        item(key = "split_heading") {
            SectionHeading(stringResource(R.string.collaboration_split_heading))
        }
        items(collab.shares, key = { "share_${it.userId}" }) { share ->
            SplitRow(
                userId = share.userId,
                percent = share.percent,
                isViewer = viewerId != null && share.userId == viewerId,
            )
        }
        item(key = "split_total") { SplitTotalRow(collab) }
        if (!collab.splitTotalsOk) {
            item(key = "split_warning") { SplitWarning(collab) }
        }
        if (state.distributions.isNotEmpty()) {
            item(key = "dist_heading") {
                SectionHeading(stringResource(R.string.collaboration_distributions_heading))
            }
            itemsIndexed(state.distributions) { index, dist ->
                DistributionRow(dist = dist, index = index)
            }
        }
    }
}

@Composable
private fun StaleRow() {
    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        modifier = Modifier
            .fillMaxWidth()
            .testTag(CollaborationsTestTags.STALE),
    ) {
        Text(
            text = stringResource(R.string.collaborations_stale_banner),
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
        )
    }
}

@Composable
private fun Header(collab: Collaboration) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = collab.title.ifBlank { stringResource(R.string.collaborations_untitled) },
            style = MaterialTheme.typography.headlineSmall,
        )
        AssistChip(
            onClick = {},
            enabled = false,
            label = { Text(statusLabel(collab)) },
            colors = AssistChipDefaults.assistChipColors(),
            modifier = Modifier.testTag(CollaborationsTestTags.STATUS),
        )
        val description = collab.description
        if (!description.isNullOrBlank()) {
            Text(text = description, style = MaterialTheme.typography.bodyMedium)
        }
        val created = relativeTime(collab.createdAt)
        if (created.isNotBlank()) {
            Text(
                text = stringResource(R.string.collaboration_created, created),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        val updated = relativeTime(collab.updatedAt)
        if (updated.isNotBlank()) {
            Text(
                text = stringResource(R.string.collaboration_updated, updated),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun PartiesSection(collab: Collaboration) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        SectionHeading(stringResource(R.string.collaboration_parties_heading))
        LabelValueRow(
            label = stringResource(R.string.collaboration_party_initiator),
            value = collab.initiatorId ?: stringResource(R.string.collaborations_unknown_party),
        )
        LabelValueRow(
            label = stringResource(R.string.collaboration_party_recipient),
            value = collab.recipientId ?: stringResource(R.string.collaborations_unknown_party),
        )
    }
}

@Composable
private fun SplitRow(userId: String, percent: Int, isViewer: Boolean) {
    val label = if (isViewer) {
        stringResource(R.string.collaboration_split_you, userId)
    } else {
        userId
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(CollaborationsTestTags.splitRow(userId))
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(text = label, style = MaterialTheme.typography.bodyMedium)
        Text(
            text = stringResource(R.string.collaboration_percent, percent),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

@Composable
private fun SplitTotalRow(collab: Collaboration) {
    HorizontalDivider()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(CollaborationsTestTags.SPLIT_TOTAL)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = stringResource(R.string.collaboration_split_total),
            style = MaterialTheme.typography.titleSmall,
        )
        Text(
            text = stringResource(R.string.collaboration_percent, collab.splitTotalPercent),
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold,
        )
    }
}

@Composable
private fun SplitWarning(collab: Collaboration) {
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp)
            .testTag(CollaborationsTestTags.SPLIT_WARNING),
    ) {
        Text(
            text = stringResource(R.string.collaboration_split_warning, collab.splitTotalPercent),
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(12.dp),
        )
    }
}

@Composable
private fun DistributionRow(dist: SplitDistribution, index: Int) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(CollaborationsTestTags.distribution(index))
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = dist.userId ?: stringResource(R.string.collaborations_unknown_party),
            style = MaterialTheme.typography.bodyMedium,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                text = stringResource(R.string.collaboration_percent, dist.percent),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            val cents = dist.amountCents
            if (cents != null) {
                Text(
                    text = formatCents(cents, FALLBACK_CURRENCY),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

@Composable
private fun SectionHeading(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleSmall,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
    )
}

@Composable
private fun LabelValueRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(text = label, style = MaterialTheme.typography.bodyMedium)
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/**
 * AND-358 - the human status label. A recognized [CollabStatus] uses a localized string; an UNKNOWN status
 * falls back to the RAW wire string (or a generic "Unknown" when blank), since the wire status set is free.
 */
@Composable
fun statusLabel(collab: Collaboration): String = when (collab.statusEnum) {
    CollabStatus.PROPOSED -> stringResource(R.string.collaboration_status_proposed)
    CollabStatus.ACTIVE -> stringResource(R.string.collaboration_status_active)
    CollabStatus.COMPLETED -> stringResource(R.string.collaboration_status_completed)
    CollabStatus.CANCELLED -> stringResource(R.string.collaboration_status_cancelled)
    CollabStatus.DECLINED -> stringResource(R.string.collaboration_status_declined)
    CollabStatus.UNKNOWN ->
        collab.status.ifBlank { stringResource(R.string.collaboration_status_unknown) }
}

/**
 * AND-358 - relative-time copy from an INTEGER epoch-SECONDS value. UI-only (android.text.format), returns ""
 * for null / epoch timestamps. Mirrors the AND-356 syndicate helper.
 */
private fun relativeTime(epochSeconds: Long?, nowMs: Long = System.currentTimeMillis()): String {
    if (epochSeconds == null || epochSeconds <= 0L) return ""
    return DateUtils.getRelativeTimeSpanString(
        epochSeconds * 1000L,
        nowMs,
        DateUtils.MINUTE_IN_MILLIS,
    ).toString()
}

/**
 * AND-358 - the currency used to render the optional distribution amount_cents. The wire does NOT ship a
 * currency on the distributions, so a stable USD fallback keeps formatCents from crashing (currency display is
 * deferred with the rest of the per-distribution metadata).
 */
private const val FALLBACK_CURRENCY = "USD"
