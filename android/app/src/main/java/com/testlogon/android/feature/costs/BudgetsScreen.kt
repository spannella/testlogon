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
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Savings
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.data.costs.Budget
import com.testlogon.android.data.costs.formatCents

@Composable
fun BudgetsRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: BudgetsViewModel = hiltViewModel(),
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
        modifier = modifier.testTag(CostsTestTags.BUDGETS_SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.costs_budgets_title)) },
                navigationIcon = { CostsBackIcon(onBack, "costs_budgets_back") },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = viewModel::onOpenForm, modifier = Modifier.testTag(CostsTestTags.CREATE_BUDGET)) {
                Icon(Icons.Outlined.Add, contentDescription = stringResource(R.string.costs_new_budget))
            }
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding).fillMaxSize()) {
            CostsPhaseScaffold(state.phase, state.errorMessage, viewModel::onRetry) {
                PullToRefreshBox(
                    isRefreshing = state.isRefreshing,
                    onRefresh = viewModel::onRefresh,
                    modifier = Modifier.fillMaxSize(),
                ) {
                    if (state.phase == CostsPhase.Empty) {
                        EmptyState(
                            title = stringResource(R.string.costs_budgets_empty_title),
                            body = stringResource(R.string.costs_budgets_empty_body),
                            imageVector = Icons.Outlined.Savings,
                            actionLabel = stringResource(R.string.costs_new_budget),
                            onAction = viewModel::onOpenForm,
                            modifier = Modifier.testTag(CostsTestTags.EMPTY),
                        )
                    } else {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize(),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            items(state.budgets, key = { it.id }) { b ->
                                BudgetCard(
                                    budget = b,
                                    onDelete = { viewModel.onDelete(b.id) },
                                    onToggleAutoPause = { viewModel.onToggleAutoPause(b.id, it) },
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (state.form.isOpen) {
        CreateBudgetDialog(
            form = state.form,
            onDismiss = viewModel::onDismissForm,
            onNameChange = viewModel::onNameChange,
            onScopeChange = viewModel::onScopeChange,
            onScopeRefChange = viewModel::onScopeRefChange,
            onPeriodChange = viewModel::onPeriodChange,
            onLimitChange = viewModel::onLimitChange,
            onThresholdChange = viewModel::onThresholdChange,
            onSubmit = viewModel::onSubmitForm,
        )
    }
}

@Composable
private fun BudgetCard(budget: Budget, onDelete: () -> Unit, onToggleAutoPause: (Boolean) -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().testTag(CostsTestTags.BUDGET_CARD_PREFIX + budget.id)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(budget.name, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Text(
                        buildString {
                            append(budget.scope)
                            budget.scopeRef?.let { append(" · $it") }
                            append(" · ${budget.period}")
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                IconButton(onClick = onDelete) {
                    Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.costs_delete_budget))
                }
            }
            Text(
                stringResource(R.string.costs_budget_limit_line, formatCents(budget.limitCents), budget.alertThresholdPct),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Switch(checked = budget.autoPauseOnExceed, onCheckedChange = onToggleAutoPause)
                Text(stringResource(R.string.costs_auto_pause), style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun CreateBudgetDialog(
    form: BudgetFormState,
    onDismiss: () -> Unit,
    onNameChange: (String) -> Unit,
    onScopeChange: (String) -> Unit,
    onScopeRefChange: (String) -> Unit,
    onPeriodChange: (String) -> Unit,
    onLimitChange: (String) -> Unit,
    onThresholdChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.fillMaxWidth().testTag(CostsTestTags.BUDGET_FORM)) {
            Column(Modifier.fillMaxWidth().padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.costs_create_budget), style = MaterialTheme.typography.titleLarge)
                OutlinedTextField(
                    value = form.name,
                    onValueChange = onNameChange,
                    label = { Text(stringResource(R.string.costs_field_name)) },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth().testTag("budget_name_input"),
                )
                CostsSegmented(
                    label = stringResource(R.string.costs_field_scope),
                    options = listOf("overall", "agent_type", "agent_instance"),
                    selected = form.scope,
                    onSelect = onScopeChange,
                )
                if (form.scope != "overall") {
                    OutlinedTextField(
                        value = form.scopeRef,
                        onValueChange = onScopeRefChange,
                        label = { Text(stringResource(R.string.costs_field_scope_ref)) },
                        placeholder = { Text("e.g. coder") },
                        singleLine = true,
                        enabled = !form.isSubmitting,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                CostsSegmented(
                    label = stringResource(R.string.costs_field_period),
                    options = listOf("daily", "weekly", "monthly"),
                    selected = form.period,
                    onSelect = onPeriodChange,
                )
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedTextField(
                        value = form.limitDollars,
                        onValueChange = onLimitChange,
                        label = { Text(stringResource(R.string.costs_field_limit)) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        enabled = !form.isSubmitting,
                        modifier = Modifier.weight(1f).testTag("budget_limit_input"),
                    )
                    OutlinedTextField(
                        value = form.thresholdPct,
                        onValueChange = onThresholdChange,
                        label = { Text(stringResource(R.string.costs_field_threshold)) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        enabled = !form.isSubmitting,
                        modifier = Modifier.weight(1f),
                    )
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = onDismiss, enabled = !form.isSubmitting) {
                        Text(stringResource(R.string.action_cancel))
                    }
                    TextButton(onClick = onSubmit, enabled = form.canSubmit, modifier = Modifier.testTag(CostsTestTags.BUDGET_SAVE)) {
                        Text(stringResource(R.string.costs_save))
                    }
                }
            }
        }
    }
}
