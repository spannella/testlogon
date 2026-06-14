@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kyc.cases

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Circle
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.kyc.KycCaseStatus
import com.testlogon.android.feature.kyc.cases.model.KycCaseSummary
import com.testlogon.android.feature.kyc.cases.model.TimelineEvent
import java.time.Instant

/** AND-329 - stable testTags for the KYC case-detail screen. */
object KycCaseDetailTestTags {
    const val SCREEN = "kyc_case_detail"
    const val STATUS = "kyc_case_status"
    const val REASON_CODES = "kyc_case_reason_codes"
    const val REVERIFY = "kyc_case_reverify"
    const val RETRY = "kyc_case_detail_retry"

    /** Per-timeline-event row tag, suffixed by the event index (oldest -> newest). */
    fun timelineEvent(index: Int): String = "kyc_timeline_event_$index"
}

/**
 * AND-329 - route-level READ-ONLY case-detail screen (status + synthesized timeline + reason codes). Forwards
 * [onBack] + [onReVerify] (the re-verify CTA for expired / needs-more-info cases -> AND-320 tier status).
 */
@Composable
fun KycCaseDetailRoute(
    onBack: () -> Unit,
    onReVerify: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: KycCaseDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    KycCaseDetailScreen(
        state = state,
        onBack = onBack,
        onReVerify = onReVerify,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        modifier = modifier,
    )
}

@Composable
fun KycCaseDetailScreen(
    state: KycCaseDetailUiState,
    onBack: () -> Unit,
    onReVerify: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(KycCaseDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.kyc_case_detail_title)) },
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
            when (state) {
                is KycCaseDetailUiState.Loading ->
                    CircularProgressIndicator(Modifier.align(Alignment.Center))

                is KycCaseDetailUiState.Content -> ContentBody(
                    state = state,
                    onReVerify = onReVerify,
                    onRefresh = onRefresh,
                )

                is KycCaseDetailUiState.Error -> ErrorBody(
                    message = state.message,
                    retryable = state.retryable,
                    onRetry = onRetry,
                )
            }
        }
    }
}

@Composable
private fun ContentBody(
    state: KycCaseDetailUiState.Content,
    onReVerify: () -> Unit,
    onRefresh: () -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = state.refreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (state.isStale) {
                Text(
                    text = stringResource(R.string.kyc_cases_stale),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            StatusCard(state.case)

            if (state.reasonCodes.isNotEmpty()) {
                ReasonCodesCard(state.reasonCodes)
            }

            HorizontalDivider()
            Text(
                text = stringResource(R.string.kyc_timeline_heading),
                style = MaterialTheme.typography.titleSmall,
            )
            state.timeline.forEachIndexed { index, event ->
                TimelineRow(index = index, event = event)
            }

            if (needsReVerify(state.case.status)) {
                Button(
                    onClick = onReVerify,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag(KycCaseDetailTestTags.REVERIFY),
                ) {
                    Text(stringResource(R.string.kyc_case_reverify))
                }
            }
        }
    }
}

@Composable
private fun StatusCard(case: KycCaseSummary) {
    val label = stringResource(kycStatusLabel(case.status))
    Card(modifier = Modifier.fillMaxWidth().testTag(KycCaseDetailTestTags.STATUS)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = stringResource(R.string.kyc_case_status_heading),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(text = label, style = MaterialTheme.typography.headlineSmall)
            Text(
                text = case.caseId,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ReasonCodesCard(reasonCodes: List<String>) {
    Card(modifier = Modifier.fillMaxWidth().testTag(KycCaseDetailTestTags.REASON_CODES)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = stringResource(R.string.kyc_case_reason_codes_heading),
                style = MaterialTheme.typography.titleSmall,
            )
            reasonCodes.forEach { code ->
                Text(text = code, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun TimelineRow(index: Int, event: TimelineEvent) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(KycCaseDetailTestTags.timelineEvent(index)),
        verticalAlignment = Alignment.Top,
    ) {
        Icon(
            imageVector = Icons.Filled.Circle,
            contentDescription = null,
            modifier = Modifier.padding(top = 4.dp, end = 12.dp).size(12.dp),
            tint = MaterialTheme.colorScheme.primary,
        )
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = stringResource(timelineKindLabel(event.kind)),
                style = MaterialTheme.typography.bodyLarge,
            )
            Text(
                text = relativeTime(event.at),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            event.note?.let {
                Text(text = it, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun ErrorBody(message: String, retryable: Boolean, onRetry: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(text = message, style = MaterialTheme.typography.bodyLarge)
        if (retryable) {
            Button(
                onClick = onRetry,
                modifier = Modifier.heightIn(min = 48.dp).testTag(KycCaseDetailTestTags.RETRY),
            ) {
                Text(stringResource(R.string.kyc_case_retry))
            }
        }
    }
}

/** Re-verify CTA shows for cases that need the user to act again (expired or needs-more-info). */
private fun needsReVerify(status: KycCaseStatus): Boolean =
    status == KycCaseStatus.EXPIRED || status == KycCaseStatus.NEEDS_MORE_INFO

/** Locale-aware relative time via [DateUtils.getRelativeTimeSpanString]. */
private fun relativeTime(instant: Instant): String =
    DateUtils.getRelativeTimeSpanString(
        instant.toEpochMilli(),
        System.currentTimeMillis(),
        DateUtils.MINUTE_IN_MILLIS,
        DateUtils.FORMAT_ABBREV_RELATIVE,
    ).toString()
