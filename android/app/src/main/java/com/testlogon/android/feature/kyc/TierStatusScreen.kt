@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kyc

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.RadioButtonUnchecked
import androidx.compose.material.icons.outlined.Verified
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.kyc.model.Requirement
import com.testlogon.android.feature.kyc.model.Tier
import com.testlogon.android.feature.kyc.model.TierHistory
import kotlinx.coroutines.flow.collectLatest
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/** AND-320 — stable testTags for the Tier Status screen. */
object TierStatusTestTags {
    const val SCREEN = "kyc_tier_screen"
    const val CURRENT = "kyc_tier_current"
    const val EVALUATE = "kyc_tier_evaluate"
    const val MAX = "kyc_tier_max"
    const val HISTORY = "kyc_tier_history"
    const val ELIGIBLE = "kyc_tier_eligible"
    const val BEGIN = "kyc_tier_begin"

    fun requirement(key: String): String = "kyc_tier_requirement_$key"

    fun requirementAction(key: String): String = "kyc_tier_requirement_action_$key"
}

/**
 * AND-320 — Tier Status route. Collects [TierStatusViewModel.state] + one-shot [TierStatusViewModel.events]
 * (promotion celebration / failure snackbars) and renders the stateless [TierStatusScreen]. [onOpenCase] is
 * defaulted to a no-op because the KYC case screens land in a later ticket; requirements carry no case id,
 * so it is currently unused here but kept on the signature for forward-compatibility.
 */
@Composable
fun TierStatusRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    onOpenCase: (caseId: String) -> Unit = {},
    onStartRequirement: (key: String) -> Unit = {},
    viewModel: TierStatusViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current
    val promotedTemplate = stringResource(R.string.kyc_tier_promoted)

    LaunchedEffect(viewModel) {
        viewModel.events.collectLatest { event ->
            val message = when (event) {
                is TierEvent.Snackbar -> event.message
                is TierEvent.Promoted ->
                    promotedTemplate.format(context.getString(tierNameRes(event.toTierLevel)))
            }
            snackbarHostState.showSnackbar(message)
        }
    }

    TierStatusScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onEvaluate = viewModel::onEvaluate,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onStartRequirement = onStartRequirement,
        modifier = modifier,
    )
}

@Composable
fun TierStatusScreen(
    state: TierUiState,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onEvaluate: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onStartRequirement: (key: String) -> Unit = {},
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(TierStatusTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.kyc_tier_title)) },
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
                is TierUiState.Loading -> LoadingState()
                is TierUiState.Error -> ErrorState(
                    message = state.message,
                    onRetry = onRetry,
                )
                is TierUiState.Content -> TierStatusContent(
                    state = state,
                    onEvaluate = onEvaluate,
                    onRefresh = onRefresh,
                    onStartRequirement = onStartRequirement,
                )
            }
        }
    }
}

@Composable
private fun TierStatusContent(
    state: TierUiState.Content,
    onEvaluate: () -> Unit,
    onRefresh: () -> Unit,
    onStartRequirement: (key: String) -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = state.refreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "current") { CurrentTierCard(state.current, state.updatedAtText()) }

            if (state.stale && state.inlineError != null) {
                item(key = "stale") { StaleNotice(state.inlineError) }
            }

            if (state.isMaxTier) {
                item(key = "max") { MaxTierNotice() }
            } else {
                if (state.eligibleForTarget) {
                    item(key = "eligible") { EligibilityBanner(state.target) }
                }
                // A clear, always-present primary CTA so the first verification view is never a dead end:
                // it carries the user into the actual verification steps (the next unmet requirement, or the
                // document/case flow when none of the requirements map to a screen).
                item(key = "begin") {
                    BeginVerificationButton(
                        requirements = state.requirements,
                        onStart = onStartRequirement,
                    )
                }
                item(key = "req_header") { RequirementsHeader(state.target) }
                items(state.requirements, key = { it.key }) { requirement ->
                    RequirementRow(requirement, onStartRequirement)
                }
                item(key = "evaluate") { EvaluateBar(state.evaluating, onEvaluate) }
            }

            if (state.history.isNotEmpty()) {
                item(key = "history_header") { HistoryHeader() }
                items(state.history, key = { "${it.changedAt.epochSecond}_${it.toTier}" }) { entry ->
                    HistoryRow(entry)
                }
            }
        }
    }
}

@Composable
private fun CurrentTierCard(current: Tier, updatedAt: String?) {
    Card(Modifier.fillMaxWidth().testTag(TierStatusTestTags.CURRENT)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Icon(
                Icons.Outlined.Verified,
                contentDescription = null,
                modifier = Modifier.size(40.dp),
                tint = MaterialTheme.colorScheme.primary,
            )
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    text = stringResource(R.string.kyc_tier_current_label),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = stringResource(tierNameRes(current.level)),
                    style = MaterialTheme.typography.headlineSmall,
                )
                if (updatedAt != null) {
                    Text(
                        text = stringResource(R.string.kyc_tier_updated_at, updatedAt),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun StaleNotice(message: String) {
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(
            text = stringResource(R.string.kyc_tier_stale, message),
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
        )
    }
}

@Composable
private fun EligibilityBanner(target: Tier?) {
    val targetName = target?.let { stringResource(tierNameRes(it.level)) }.orEmpty()
    Surface(
        color = MaterialTheme.colorScheme.primaryContainer,
        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        modifier = Modifier.fillMaxWidth().testTag(TierStatusTestTags.ELIGIBLE),
    ) {
        Text(
            text = stringResource(R.string.kyc_tier_eligible, targetName),
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(16.dp),
        )
    }
}

@Composable
private fun RequirementsHeader(target: Tier?) {
    val targetName = target?.let { stringResource(tierNameRes(it.level)) }.orEmpty()
    Text(
        text = stringResource(R.string.kyc_tier_requirements_header, targetName),
        style = MaterialTheme.typography.titleMedium,
    )
}

@Composable
private fun RequirementRow(requirement: Requirement, onStartRequirement: (key: String) -> Unit) {
    val label = requirementLabelRes(requirement.key)
        ?.let { stringResource(it) }
        ?: requirement.key
    val stateCd = stringResource(
        if (requirement.met) R.string.kyc_tier_req_met_cd else R.string.kyc_tier_req_unmet_cd,
    )
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(TierStatusTestTags.requirement(requirement.key)),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(
            imageVector = if (requirement.met) {
                Icons.Outlined.CheckCircle
            } else {
                Icons.Outlined.RadioButtonUnchecked
            },
            // Decorative: the row's own contentDescription conveys met/unmet.
            contentDescription = null,
            tint = if (requirement.met) {
                MaterialTheme.colorScheme.primary
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant
            },
        )
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier
                .weight(1f)
                .clearAndSetSemantics { contentDescription = "$label, $stateCd" },
        )
        // Each UNMET requirement carries its own actionable CTA -> the relevant verification step.
        if (!requirement.met) {
            TextButton(
                onClick = { onStartRequirement(requirement.key) },
                modifier = Modifier
                    .heightIn(min = 48.dp)
                    .testTag(TierStatusTestTags.requirementAction(requirement.key)),
            ) {
                Text(stringResource(R.string.kyc_tier_req_action))
            }
        }
    }
}

/**
 * The primary "Begin verification" CTA. It targets the first UNMET requirement (so the user always has a real
 * next step from this first screen); if everything is met it falls back to a generic verification entry (the
 * empty key routes to the document/case flow at the nav layer).
 */
@Composable
private fun BeginVerificationButton(
    requirements: List<Requirement>,
    onStart: (key: String) -> Unit,
) {
    val firstUnmet = requirements.firstOrNull { !it.met }?.key.orEmpty()
    Button(
        onClick = { onStart(firstUnmet) },
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(TierStatusTestTags.BEGIN),
    ) {
        Text(stringResource(R.string.kyc_tier_begin_verification))
    }
}

@Composable
private fun EvaluateBar(evaluating: Boolean, onEvaluate: () -> Unit) {
    Button(
        onClick = onEvaluate,
        enabled = !evaluating,
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(TierStatusTestTags.EVALUATE),
    ) {
        if (evaluating) {
            CircularProgressIndicator(
                modifier = Modifier.size(20.dp),
                strokeWidth = 2.dp,
                color = MaterialTheme.colorScheme.onPrimary,
            )
        } else {
            Text(stringResource(R.string.kyc_tier_check_eligibility))
        }
    }
}

@Composable
private fun MaxTierNotice() {
    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        modifier = Modifier.fillMaxWidth().testTag(TierStatusTestTags.MAX),
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Icon(Icons.Outlined.Verified, contentDescription = null)
            Text(
                text = stringResource(R.string.kyc_tier_max_reached),
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Start,
            )
        }
    }
}

@Composable
private fun HistoryHeader() {
    Text(
        text = stringResource(R.string.kyc_tier_history_header),
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.testTag(TierStatusTestTags.HISTORY),
    )
}

@Composable
private fun HistoryRow(entry: TierHistory) {
    val fromName = stringResource(tierNameRes(entry.fromTier))
    val toName = stringResource(tierNameRes(entry.toTier))
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(
            text = stringResource(R.string.kyc_tier_history_change, fromName, toName),
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            text = "${formatTimestamp(entry.changedAt)} · ${entry.reason}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

// ---- formatting ----

private val TIMESTAMP_FORMATTER: DateTimeFormatter =
    DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM)

private fun formatTimestamp(instant: Instant): String =
    runCatching { TIMESTAMP_FORMATTER.withZone(ZoneId.systemDefault()).format(instant) }
        .getOrDefault(instant.toString())

private fun TierUiState.Content.updatedAtText(): String? = updatedAt?.let(::formatTimestamp)
