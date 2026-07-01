@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.costs

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.data.costs.CostAlert
import com.testlogon.android.data.costs.formatCents

@Composable
fun CostAlertsRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CostAlertsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { e ->
            if (e is CostsEffect.ShowMessage) snackbar.showSnackbar(context.getString(e.resId))
        }
    }
    LaunchedEffect(state.phase) {
        if (state.phase == CostsPhase.SessionExpired) onSessionExpired()
    }

    Scaffold(
        modifier = modifier.testTag(CostsTestTags.ALERTS_SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.costs_alerts_title)) },
                navigationIcon = { CostsBackIcon(onBack, "costs_alerts_back") },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding).fillMaxSize()) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp).testTag(CostsTestTags.ALERT_FILTER),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                FilterChip(
                    selected = state.unacknowledgedOnly,
                    onClick = { viewModel.onFilterChange(true) },
                    label = { Text(stringResource(R.string.costs_filter_unack)) },
                )
                FilterChip(
                    selected = !state.unacknowledgedOnly,
                    onClick = { viewModel.onFilterChange(false) },
                    label = { Text(stringResource(R.string.costs_filter_all)) },
                )
            }
            CostsPhaseScaffold(state.phase, state.errorMessage, viewModel::onRetry) {
                PullToRefreshBox(
                    isRefreshing = state.isRefreshing,
                    onRefresh = viewModel::onRefresh,
                    modifier = Modifier.fillMaxSize(),
                ) {
                    if (state.phase == CostsPhase.Empty) {
                        EmptyState(
                            title = stringResource(R.string.costs_alerts_empty_title),
                            body = stringResource(R.string.costs_alerts_empty_body),
                            modifier = Modifier.testTag(CostsTestTags.EMPTY),
                        )
                    } else {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize(),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            items(state.alerts, key = { it.id }) { a ->
                                AlertCard(alert = a, onAcknowledge = { viewModel.onAcknowledge(a.id) })
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AlertCard(alert: CostAlert, onAcknowledge: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().testTag(CostsTestTags.ALERT_CARD_PREFIX + alert.id)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.weight(1f)) {
                    SeverityPill(alert.severity)
                    Text(alert.title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                }
                if (!alert.acknowledged) {
                    OutlinedButton(onClick = onAcknowledge, modifier = Modifier.testTag("alert_ack_${alert.id}")) {
                        Text(stringResource(R.string.costs_acknowledge))
                    }
                } else {
                    AssistChip(
                        onClick = {},
                        enabled = false,
                        leadingIcon = { androidx.compose.material3.Icon(Icons.Outlined.CheckCircle, null) },
                        label = { Text(stringResource(R.string.costs_acknowledged)) },
                    )
                }
            }
            Text(alert.message, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (alert.budgetLimitCents != null) {
                Text(
                    stringResource(R.string.costs_spent_of, formatCents(alert.currentSpendCents), formatCents(alert.budgetLimitCents)),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            alert.autoActionTaken?.let {
                Text(it, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.error)
            }
        }
    }
}
