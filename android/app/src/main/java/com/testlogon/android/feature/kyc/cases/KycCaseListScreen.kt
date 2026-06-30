@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kyc.cases

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.NotificationsActive
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
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
import com.testlogon.android.feature.kyc.cases.model.KycCaseSummary
import com.testlogon.android.feature.kyc.cases.model.MonitoringState
import java.time.Instant

/** AND-329 - stable testTags for the KYC case-list screen. */
object KycCaseListTestTags {
    const val SCREEN = "kyc_cases_screen"
    const val MONITORING_BANNER = "kyc_monitoring_banner"
    const val EMPTY = "kyc_case_empty"
    const val RETRY = "kyc_case_retry"

    /** The always-visible "Start / Continue verification" CTA shown above the case list. */
    const val START_VERIFICATION = "kyc_cases_start_verification"

    /** Per-case row tag, suffixed by the case id. */
    fun row(caseId: String): String = "kyc_case_row_$caseId"
}

/**
 * AND-329 - route-level READ-ONLY case-list screen. Sources its state from the VM and forwards [onOpenCase]
 * (tap a row) + [onStartVerification] (the Empty / banner CTA -> AND-320 tier status).
 */
@Composable
fun KycCaseListRoute(
    onOpenCase: (String) -> Unit,
    onStartVerification: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: KycCaseListViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    KycCaseListScreen(
        state = state,
        onOpenCase = onOpenCase,
        onStartVerification = onStartVerification,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        modifier = modifier,
    )
}

@Composable
fun KycCaseListScreen(
    state: KycCaseListUiState,
    onOpenCase: (String) -> Unit,
    onStartVerification: () -> Unit,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(KycCaseListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.kyc_cases_title)) },
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
                is KycCaseListUiState.Loading ->
                    CircularProgressIndicator(Modifier.align(Alignment.Center))

                is KycCaseListUiState.Content -> ContentBody(
                    state = state,
                    onOpenCase = onOpenCase,
                    onStartVerification = onStartVerification,
                    onRefresh = onRefresh,
                )

                is KycCaseListUiState.Empty -> EmptyBody(
                    monitoring = state.monitoring,
                    onStartVerification = onStartVerification,
                )

                is KycCaseListUiState.Error -> ErrorBody(
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
    state: KycCaseListUiState.Content,
    onOpenCase: (String) -> Unit,
    onStartVerification: () -> Unit,
    onRefresh: () -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = state.refreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "start_verification_cta") {
                StartVerificationCta(onStartVerification = onStartVerification)
            }
            if (state.monitoring.active) {
                item(key = "monitoring") {
                    MonitoringBanner(
                        monitoring = state.monitoring,
                        onAction = onStartVerification,
                    )
                }
            }
            if (state.isStale) {
                item(key = "stale") {
                    Text(
                        text = stringResource(R.string.kyc_cases_stale),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            items(state.cases, key = { it.caseId }) { case ->
                CaseRow(case = case, onOpenCase = onOpenCase)
            }
        }
    }
}

@Composable
private fun StartVerificationCta(onStartVerification: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
        ),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                text = stringResource(R.string.kyc_cases_verify_prompt),
                style = MaterialTheme.typography.titleMedium,
            )
            Button(
                onClick = onStartVerification,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(KycCaseListTestTags.START_VERIFICATION),
            ) {
                Text(stringResource(R.string.kyc_cases_continue_verification))
            }
        }
    }
}

@Composable
private fun CaseRow(case: KycCaseSummary, onOpenCase: (String) -> Unit) {
    val statusLabel = stringResource(kycStatusLabel(case.status))
    val relative = relativeTime(case.createdAt)
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(KycCaseListTestTags.row(case.caseId)),
        onClick = { onOpenCase(case.caseId) },
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(text = case.caseId, style = MaterialTheme.typography.titleMedium)
                Text(
                    text = stringResource(R.string.kyc_cases_created, relative),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                AssistChip(
                    onClick = {},
                    enabled = false,
                    label = { Text(statusLabel) },
                    colors = AssistChipDefaults.assistChipColors(),
                )
                Icon(
                    Icons.AutoMirrored.Filled.ArrowForward,
                    contentDescription = null,
                    modifier = Modifier.padding(start = 8.dp).size(20.dp),
                )
            }
        }
    }
}

@Composable
private fun MonitoringBanner(monitoring: MonitoringState, onAction: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(KycCaseListTestTags.MONITORING_BANNER),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.tertiaryContainer,
        ),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                // Status is conveyed by icon + text, never colour alone.
                Icon(
                    imageVector = Icons.Filled.NotificationsActive,
                    contentDescription = null,
                    modifier = Modifier.size(24.dp),
                )
                Text(
                    text = stringResource(R.string.kyc_monitoring_title),
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
            Text(
                text = stringResource(monitoringMessage(monitoring.message)),
                style = MaterialTheme.typography.bodyMedium,
            )
            monitoring.nextReviewDate?.let {
                Text(
                    text = stringResource(R.string.kyc_monitoring_next_review, relativeTime(it)),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            monitoring.graceDeadline?.let {
                Text(
                    text = stringResource(R.string.kyc_monitoring_grace_deadline, relativeTime(it)),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Button(
                onClick = onAction,
                modifier = Modifier.heightIn(min = 48.dp),
            ) {
                Text(stringResource(R.string.kyc_monitoring_cta))
            }
        }
    }
}

@Composable
private fun EmptyBody(monitoring: MonitoringState, onStartVerification: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
            .testTag(KycCaseListTestTags.EMPTY),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        if (monitoring.active) {
            MonitoringBanner(monitoring = monitoring, onAction = onStartVerification)
        }
        Text(
            text = stringResource(R.string.kyc_cases_empty_title),
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            text = stringResource(R.string.kyc_cases_empty_body),
            style = MaterialTheme.typography.bodyMedium,
        )
        Button(
            onClick = onStartVerification,
            modifier = Modifier
                .heightIn(min = 48.dp)
                .testTag(KycCaseListTestTags.START_VERIFICATION),
        ) {
            Text(stringResource(R.string.kyc_cases_continue_verification))
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
                modifier = Modifier.heightIn(min = 48.dp).testTag(KycCaseListTestTags.RETRY),
            ) {
                Text(stringResource(R.string.kyc_case_retry))
            }
        }
    }
}

/**
 * Locale-aware relative time (e.g. "3 days ago" / "in 2 hours") via [DateUtils.getRelativeTimeSpanString],
 * which respects the device locale + 12/24h settings.
 */
private fun relativeTime(instant: Instant): String =
    DateUtils.getRelativeTimeSpanString(
        instant.toEpochMilli(),
        System.currentTimeMillis(),
        DateUtils.MINUTE_IN_MILLIS,
        DateUtils.FORMAT_ABBREV_RELATIVE,
    ).toString()

/** Maps the monitoring message token to a localized string. */
private fun monitoringMessage(token: String?): Int = when (token) {
    "schedule:needs_review" -> R.string.kyc_monitoring_msg_needs_review
    "schedule:grace_period" -> R.string.kyc_monitoring_msg_grace_period
    "schedule:downgraded" -> R.string.kyc_monitoring_msg_downgraded
    "trigger" -> R.string.kyc_monitoring_msg_trigger
    else -> R.string.kyc_monitoring_msg_generic
}
