@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.stylist

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Rule
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.stylist.DesignRule
import com.testlogon.android.data.stylist.RuleSeverity

object StylistRulesTestTags {
    const val SCREEN = "stylist_rules_screen"
    const val LIST = "stylist_rules_list"
    const val LOADING = "stylist_rules_loading"
    const val EMPTY = "stylist_rules_empty"
    const val ERROR = "stylist_rules_error"
    const val OFFLINE = "stylist_rules_offline"
    const val SESSION_EXPIRED = "stylist_rules_session_expired"
    const val ADD = "stylist_rule_add"
    const val FORM = "stylist_rule_form"
    const val FORM_NAME = "stylist_rule_name"
    const val FORM_DESC = "stylist_rule_desc"
    const val FORM_SUBMIT = "stylist_rule_submit"
    const val ROW_PREFIX = "stylist_rule_row_"
    const val DELETE_PREFIX = "stylist_rule_delete_"
}

@Composable
fun StylistRulesRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: StylistRulesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is StylistEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }
    LaunchedEffect(state.phase) {
        if (state.phase == StylistRulesUiState.Phase.SessionExpired) onSessionExpired()
    }

    StylistRulesScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onOpenCreate = viewModel::onOpenCreate,
        onDismissCreate = viewModel::onDismissCreate,
        onNameChange = viewModel::onNameChange,
        onCategoryChange = viewModel::onCategoryChange,
        onDescriptionChange = viewModel::onDescriptionChange,
        onSeverityChange = viewModel::onSeverityChange,
        onSubmitRule = viewModel::onSubmitRule,
        onToggleRule = viewModel::onToggleRule,
        onDeleteRule = viewModel::onDeleteRule,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun StylistRulesScreen(
    state: StylistRulesUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onOpenCreate: () -> Unit,
    onDismissCreate: () -> Unit,
    onNameChange: (String) -> Unit,
    onCategoryChange: (String) -> Unit,
    onDescriptionChange: (String) -> Unit,
    onSeverityChange: (String) -> Unit,
    onSubmitRule: () -> Unit,
    onToggleRule: (DesignRule) -> Unit,
    onDeleteRule: (DesignRule) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(StylistRulesTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.stylist_rules_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    IconButton(onClick = onOpenCreate, modifier = Modifier.testTag(StylistRulesTestTags.ADD)) {
                        Icon(Icons.Outlined.Add, contentDescription = stringResource(R.string.stylist_rule_add))
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                StylistRulesUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(StylistRulesTestTags.LOADING))
                StylistRulesUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.stylist_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(StylistRulesTestTags.ERROR),
                    )
                StylistRulesUiState.Phase.Offline ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.stylist_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(StylistRulesTestTags.OFFLINE),
                    )
                StylistRulesUiState.Phase.SessionExpired ->
                    EmptyState(
                        title = stringResource(R.string.stylist_session_expired_title),
                        body = stringResource(R.string.stylist_session_expired_body),
                        modifier = Modifier.testTag(StylistRulesTestTags.SESSION_EXPIRED),
                    )
                StylistRulesUiState.Phase.Empty ->
                    PullToRefreshBox(isRefreshing = state.isRefreshing, onRefresh = onRefresh, modifier = Modifier.fillMaxSize()) {
                        EmptyState(
                            title = stringResource(R.string.stylist_rules_empty_title),
                            body = stringResource(R.string.stylist_rules_empty_body),
                            imageVector = Icons.Outlined.Rule,
                            actionLabel = stringResource(R.string.stylist_rule_add),
                            onAction = onOpenCreate,
                            modifier = Modifier.testTag(StylistRulesTestTags.EMPTY),
                        )
                    }
                StylistRulesUiState.Phase.Content ->
                    PullToRefreshBox(isRefreshing = state.isRefreshing, onRefresh = onRefresh, modifier = Modifier.fillMaxSize()) {
                        LazyColumn(
                            modifier = Modifier.testTag(StylistRulesTestTags.LIST).fillMaxSize(),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            items(state.rules, key = { it.id }) { rule ->
                                RuleCard(rule = rule, onToggle = { onToggleRule(rule) }, onDelete = { onDeleteRule(rule) })
                            }
                        }
                    }
            }
        }
    }

    if (state.create.isOpen) {
        CreateRuleDialog(
            form = state.create,
            onDismiss = onDismissCreate,
            onNameChange = onNameChange,
            onCategoryChange = onCategoryChange,
            onDescriptionChange = onDescriptionChange,
            onSeverityChange = onSeverityChange,
            onSubmit = onSubmitRule,
        )
    }
}

@Composable
private fun RuleCard(rule: DesignRule, onToggle: () -> Unit, onDelete: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(StylistRulesTestTags.ROW_PREFIX + rule.id),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = rule.name,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f),
                )
                Switch(checked = rule.enabled, onCheckedChange = { onToggle() })
                IconButton(onClick = onDelete, modifier = Modifier.testTag(StylistRulesTestTags.DELETE_PREFIX + rule.id)) {
                    Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.stylist_rule_delete))
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                LabelChip(rule.category)
                LabelChip(rule.severity.name.lowercase(), isError = rule.severity == RuleSeverity.ERROR)
            }
            if (rule.description.isNotBlank()) {
                Text(
                    text = rule.description,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun LabelChip(text: String, isError: Boolean = false) {
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(text) },
        colors = AssistChipDefaults.assistChipColors(
            disabledContainerColor = if (isError) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.secondaryContainer,
            disabledLabelColor = MaterialTheme.colorScheme.onSurface,
        ),
        border = null,
    )
}

@Composable
private fun CreateRuleDialog(
    form: RuleFormState,
    onDismiss: () -> Unit,
    onNameChange: (String) -> Unit,
    onCategoryChange: (String) -> Unit,
    onDescriptionChange: (String) -> Unit,
    onSeverityChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.fillMaxWidth().testTag(StylistRulesTestTags.FORM)) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(stringResource(R.string.stylist_rule_new), style = MaterialTheme.typography.titleLarge)
                OutlinedTextField(
                    value = form.name,
                    onValueChange = onNameChange,
                    label = { Text(stringResource(R.string.stylist_rule_field_name)) },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth().testTag(StylistRulesTestTags.FORM_NAME),
                )
                DropdownField(
                    label = stringResource(R.string.stylist_rule_field_category),
                    value = form.category,
                    options = RuleFormState.CATEGORIES,
                    onSelect = onCategoryChange,
                    enabled = !form.isSubmitting,
                )
                DropdownField(
                    label = stringResource(R.string.stylist_rule_field_severity),
                    value = form.severity,
                    options = RuleFormState.SEVERITIES,
                    onSelect = onSeverityChange,
                    enabled = !form.isSubmitting,
                )
                OutlinedTextField(
                    value = form.description,
                    onValueChange = onDescriptionChange,
                    label = { Text(stringResource(R.string.stylist_rule_field_description)) },
                    minLines = 3,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth().testTag(StylistRulesTestTags.FORM_DESC),
                )
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = onDismiss, enabled = !form.isSubmitting) {
                        Text(stringResource(R.string.action_cancel))
                    }
                    TextButton(
                        onClick = onSubmit,
                        enabled = form.canSubmit,
                        modifier = Modifier.testTag(StylistRulesTestTags.FORM_SUBMIT),
                    ) {
                        Text(stringResource(R.string.stylist_rule_create))
                    }
                }
            }
        }
    }
}

@Composable
private fun DropdownField(
    label: String,
    value: String,
    options: List<String>,
    onSelect: (String) -> Unit,
    enabled: Boolean,
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { if (enabled) expanded = it },
        modifier = Modifier.fillMaxWidth(),
    ) {
        OutlinedTextField(
            value = value,
            onValueChange = {},
            readOnly = true,
            enabled = enabled,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier.menuAnchor().fillMaxWidth(),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { option ->
                DropdownMenuItem(
                    text = { Text(option) },
                    onClick = {
                        onSelect(option)
                        expanded = false
                    },
                )
            }
        }
    }
}
