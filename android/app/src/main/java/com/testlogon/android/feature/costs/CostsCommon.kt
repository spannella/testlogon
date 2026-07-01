@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.costs

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.FilterChip
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.data.costs.AlertSeverity

/** Shared testTags for the cost screens. */
object CostsTestTags {
    const val OVERVIEW_SCREEN = "cost_overview_screen"
    const val BREAKDOWN_SCREEN = "cost_breakdown_screen"
    const val BUDGETS_SCREEN = "budget_manager_screen"
    const val ALERTS_SCREEN = "cost_alerts_screen"
    const val LOADING = "costs_loading"
    const val EMPTY = "costs_empty"
    const val ERROR = "costs_error"
    const val OFFLINE = "costs_offline"
    const val SESSION_EXPIRED = "costs_session_expired"
    const val ALERT_BANNER = "cost_alert_banner"
    const val CREATE_BUDGET = "create_budget_button"
    const val BUDGET_FORM = "budget_form_dialog"
    const val BUDGET_SAVE = "budget_save_button"
    const val ALERT_FILTER = "alert_filter"
    const val BUDGET_CARD_PREFIX = "budget_card_"
    const val ALERT_CARD_PREFIX = "alert_card_"
    const val TICKET_ROW_PREFIX = "ticket_row_"
}

@Composable
fun CostsBackIcon(onBack: () -> Unit, tag: String) {
    IconButton(onClick = onBack, modifier = Modifier.testTag(tag)) {
        Icon(
            Icons.AutoMirrored.Filled.ArrowBack,
            contentDescription = stringResource(R.string.action_back),
        )
    }
}

@Composable
fun SectionHeader(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold,
        color = MaterialTheme.colorScheme.onSurface,
    )
}

@Composable
fun SeverityPill(severity: AlertSeverity) {
    val (container, content) = when (severity) {
        AlertSeverity.CRITICAL -> MaterialTheme.colorScheme.errorContainer to MaterialTheme.colorScheme.onErrorContainer
        AlertSeverity.WARNING -> MaterialTheme.colorScheme.tertiaryContainer to MaterialTheme.colorScheme.onTertiaryContainer
        AlertSeverity.INFO -> MaterialTheme.colorScheme.secondaryContainer to MaterialTheme.colorScheme.onSecondaryContainer
        AlertSeverity.UNKNOWN -> MaterialTheme.colorScheme.surfaceVariant to MaterialTheme.colorScheme.onSurfaceVariant
    }
    val label = when (severity) {
        AlertSeverity.CRITICAL -> stringResource(R.string.costs_severity_critical)
        AlertSeverity.WARNING -> stringResource(R.string.costs_severity_warning)
        AlertSeverity.INFO -> stringResource(R.string.costs_severity_info)
        AlertSeverity.UNKNOWN -> stringResource(R.string.costs_severity_unknown)
    }
    Surface(color = container, contentColor = content, shape = MaterialTheme.shapes.small) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
        )
    }
}

/** A labelled horizontal row of single-select FilterChips (a lightweight enum picker). */
@Composable
fun CostsSegmented(label: String, options: List<String>, selected: String, onSelect: (String) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(
            modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            options.forEach { opt ->
                FilterChip(
                    selected = selected == opt,
                    onClick = { onSelect(opt) },
                    label = { Text(opt) },
                )
            }
        }
    }
}

/** Renders the shared non-content phases; returns true if it handled the phase (content should not render). */
@Composable
fun CostsPhaseScaffold(
    phase: CostsPhase,
    errorMessage: String?,
    onRetry: () -> Unit,
    content: @Composable () -> Unit,
) {
    Box(modifier = Modifier.fillMaxSize()) {
        when (phase) {
            CostsPhase.Loading ->
                com.testlogon.android.core.ui.state.LoadingState(modifier = Modifier.testTag(CostsTestTags.LOADING))
            CostsPhase.Error ->
                com.testlogon.android.core.ui.state.ErrorState(
                    message = errorMessage ?: stringResource(R.string.costs_error_generic),
                    onRetry = onRetry,
                    modifier = Modifier.testTag(CostsTestTags.ERROR),
                )
            CostsPhase.Offline ->
                com.testlogon.android.core.ui.state.ErrorState(
                    message = errorMessage ?: stringResource(R.string.costs_error_generic),
                    onRetry = onRetry,
                    modifier = Modifier.testTag(CostsTestTags.OFFLINE),
                )
            CostsPhase.SessionExpired ->
                com.testlogon.android.core.ui.state.EmptyState(
                    title = stringResource(R.string.costs_session_expired_title),
                    body = stringResource(R.string.costs_session_expired_body),
                    modifier = Modifier.testTag(CostsTestTags.SESSION_EXPIRED),
                )
            CostsPhase.Empty, CostsPhase.Content -> content()
        }
    }
}
