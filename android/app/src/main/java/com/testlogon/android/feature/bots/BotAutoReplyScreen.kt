@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.bots

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
import androidx.compose.material.icons.outlined.ChatBubbleOutline
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
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
import com.testlogon.android.data.bots.AutoReplyMatchType
import com.testlogon.android.data.bots.AutoReplyRule

/** Stable testTags for the auto-reply screen. */
object BotAutoReplyTestTags {
    const val SCREEN = "bot_auto_reply_screen"
    const val LIST = "bot_auto_reply_list"
    const val LOADING = "bot_auto_reply_loading"
    const val EMPTY = "bot_auto_reply_empty"
    const val ERROR = "bot_auto_reply_error"
    const val OFFLINE = "bot_auto_reply_offline"
    const val SESSION_EXPIRED = "bot_auto_reply_session_expired"
    const val NEW = "bot_auto_reply_new"
    const val FORM = "bot_auto_reply_form"
    const val FORM_TRIGGER = "bot_auto_reply_form_trigger"
    const val FORM_RESPONSE = "bot_auto_reply_form_response"
    const val FORM_PRIORITY = "bot_auto_reply_form_priority"
    const val FORM_SUBMIT = "bot_auto_reply_form_submit"
    const val ROW_PREFIX = "bot_auto_reply_row_"
}

/** Route-level auto-reply rules for one bot. Mirrors the web bots/{botId}/auto-reply page. */
@Composable
fun BotAutoReplyRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: BotAutoReplyViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is AutoReplyEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }

    LaunchedEffect(state.phase) {
        if (state.phase == BotsPhase.SessionExpired) onSessionExpired()
    }

    BotAutoReplyScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onOpenCreate = viewModel::onOpenCreate,
        onOpenEdit = viewModel::onOpenEdit,
        onDismissForm = viewModel::onDismissForm,
        onTriggerChange = viewModel::onTriggerChange,
        onResponseChange = viewModel::onResponseChange,
        onMatchTypeChange = viewModel::onMatchTypeChange,
        onPriorityChange = viewModel::onPriorityChange,
        onEnabledChange = viewModel::onEnabledChange,
        onSubmitForm = viewModel::onSubmitForm,
        onDelete = viewModel::onDelete,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun BotAutoReplyScreen(
    state: AutoReplyUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onOpenCreate: () -> Unit,
    onOpenEdit: (String) -> Unit,
    onDismissForm: () -> Unit,
    onTriggerChange: (String) -> Unit,
    onResponseChange: (String) -> Unit,
    onMatchTypeChange: (AutoReplyMatchType) -> Unit,
    onPriorityChange: (String) -> Unit,
    onEnabledChange: (Boolean) -> Unit,
    onSubmitForm: () -> Unit,
    onDelete: (String) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(BotAutoReplyTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.bots_auto_reply_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("bot_auto_reply_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    val newCd = stringResource(R.string.bots_rule_new)
                    IconButton(onClick = onOpenCreate, modifier = Modifier.testTag(BotAutoReplyTestTags.NEW)) {
                        Icon(Icons.Outlined.Add, contentDescription = newCd)
                    }
                },
            )
        },
        floatingActionButton = {
            if (state.phase == BotsPhase.Content || state.phase == BotsPhase.Empty) {
                FloatingActionButton(onClick = onOpenCreate) {
                    Icon(Icons.Outlined.Add, contentDescription = stringResource(R.string.bots_rule_new))
                }
            }
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                BotsPhase.Loading ->
                    LoadingState(modifier = Modifier.testTag(BotAutoReplyTestTags.LOADING))

                BotsPhase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.bots_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(BotAutoReplyTestTags.ERROR),
                    )

                BotsPhase.Offline ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.bots_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(BotAutoReplyTestTags.OFFLINE),
                    )

                BotsPhase.SessionExpired ->
                    EmptyState(
                        title = stringResource(R.string.bots_session_expired_title),
                        body = stringResource(R.string.bots_session_expired_body),
                        modifier = Modifier.testTag(BotAutoReplyTestTags.SESSION_EXPIRED),
                    )

                BotsPhase.Empty ->
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        EmptyState(
                            title = stringResource(R.string.bots_auto_reply_empty_title),
                            body = stringResource(R.string.bots_auto_reply_empty_body),
                            imageVector = Icons.Outlined.ChatBubbleOutline,
                            actionLabel = stringResource(R.string.bots_rule_new),
                            onAction = onOpenCreate,
                            modifier = Modifier.testTag(BotAutoReplyTestTags.EMPTY),
                        )
                    }

                BotsPhase.Content -> {
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        LazyColumn(
                            modifier = Modifier
                                .testTag(BotAutoReplyTestTags.LIST)
                                .fillMaxSize(),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            items(state.rules, key = { it.id }) { rule ->
                                AutoReplyCard(
                                    rule = rule,
                                    isMutating = state.isMutating,
                                    onEdit = { onOpenEdit(rule.id) },
                                    onDelete = { onDelete(rule.id) },
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (state.form.isOpen) {
        AutoReplyFormDialog(
            form = state.form,
            onDismiss = onDismissForm,
            onTriggerChange = onTriggerChange,
            onResponseChange = onResponseChange,
            onMatchTypeChange = onMatchTypeChange,
            onPriorityChange = onPriorityChange,
            onEnabledChange = onEnabledChange,
            onSubmit = onSubmitForm,
        )
    }
}

@Composable
private fun AutoReplyCard(
    rule: AutoReplyRule,
    isMutating: Boolean,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
) {
    var confirmDelete by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(BotAutoReplyTestTags.ROW_PREFIX + rule.id),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                MatchTypeChip(matchType = rule.matchType)
                Text(
                    text = stringResource(R.string.bots_rule_priority, rule.priority),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (!rule.enabled) {
                    Text(
                        text = stringResource(R.string.bots_rule_disabled),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }

            Text(
                text = rule.triggerPattern,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 2,
                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
            )
            Text(
                text = rule.responseTemplate,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 3,
                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
            )

            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                TextButton(onClick = onEdit, enabled = !isMutating) {
                    Text(stringResource(R.string.bots_rule_edit))
                }
                TextButton(onClick = { confirmDelete = true }, enabled = !isMutating) {
                    Text(stringResource(R.string.bots_rule_delete))
                }
            }
        }
    }

    if (confirmDelete) {
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(stringResource(R.string.bots_rule_delete_confirm_title)) },
            text = { Text(stringResource(R.string.bots_rule_delete_confirm_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    onDelete()
                }) {
                    Text(stringResource(R.string.bots_rule_delete))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmDelete = false }) {
                    Text(stringResource(R.string.bots_cancel))
                }
            },
        )
    }
}

@Composable
private fun MatchTypeChip(matchType: AutoReplyMatchType) {
    val labelRes = when (matchType) {
        AutoReplyMatchType.KEYWORD -> R.string.bots_match_keyword
        AutoReplyMatchType.CONTAINS -> R.string.bots_match_contains
        AutoReplyMatchType.EXACT -> R.string.bots_match_exact
        AutoReplyMatchType.REGEX -> R.string.bots_match_regex
    }
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(stringResource(labelRes)) },
        colors = AssistChipDefaults.assistChipColors(
            disabledContainerColor = MaterialTheme.colorScheme.secondaryContainer,
            disabledLabelColor = MaterialTheme.colorScheme.onSurface,
        ),
        border = null,
    )
}

@Composable
private fun AutoReplyFormDialog(
    form: AutoReplyFormState,
    onDismiss: () -> Unit,
    onTriggerChange: (String) -> Unit,
    onResponseChange: (String) -> Unit,
    onMatchTypeChange: (AutoReplyMatchType) -> Unit,
    onPriorityChange: (String) -> Unit,
    onEnabledChange: (Boolean) -> Unit,
    onSubmit: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.fillMaxWidth().testTag(BotAutoReplyTestTags.FORM)) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    text = stringResource(
                        if (form.isEditing) R.string.bots_rule_edit_title else R.string.bots_rule_create_title,
                    ),
                    style = MaterialTheme.typography.titleLarge,
                )
                OutlinedTextField(
                    value = form.triggerPattern,
                    onValueChange = onTriggerChange,
                    label = { Text(stringResource(R.string.bots_field_trigger)) },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth().testTag(BotAutoReplyTestTags.FORM_TRIGGER),
                )
                OutlinedTextField(
                    value = form.responseTemplate,
                    onValueChange = onResponseChange,
                    label = { Text(stringResource(R.string.bots_field_response)) },
                    minLines = 3,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth().testTag(BotAutoReplyTestTags.FORM_RESPONSE),
                )
                MatchTypeDropdown(
                    selected = form.matchType,
                    enabled = !form.isSubmitting,
                    onSelected = onMatchTypeChange,
                )
                OutlinedTextField(
                    value = form.priority,
                    onValueChange = onPriorityChange,
                    label = { Text(stringResource(R.string.bots_field_priority)) },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth().testTag(BotAutoReplyTestTags.FORM_PRIORITY),
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(stringResource(R.string.bots_field_enabled))
                    Switch(
                        checked = form.enabled,
                        onCheckedChange = onEnabledChange,
                        enabled = !form.isSubmitting,
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                ) {
                    TextButton(onClick = onDismiss, enabled = !form.isSubmitting) {
                        Text(stringResource(R.string.bots_cancel))
                    }
                    TextButton(
                        onClick = onSubmit,
                        enabled = form.canSubmit,
                        modifier = Modifier.testTag(BotAutoReplyTestTags.FORM_SUBMIT),
                    ) {
                        Text(stringResource(R.string.bots_save))
                    }
                }
            }
        }
    }
}

@Composable
private fun MatchTypeDropdown(
    selected: AutoReplyMatchType,
    enabled: Boolean,
    onSelected: (AutoReplyMatchType) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val options = AutoReplyMatchType.values()

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { if (enabled) expanded = it },
    ) {
        OutlinedTextField(
            value = stringResource(matchTypeLabel(selected)),
            onValueChange = {},
            readOnly = true,
            enabled = enabled,
            label = { Text(stringResource(R.string.bots_field_match_type)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { option ->
                DropdownMenuItem(
                    text = { Text(stringResource(matchTypeLabel(option))) },
                    onClick = {
                        onSelected(option)
                        expanded = false
                    },
                )
            }
        }
    }
}

private fun matchTypeLabel(matchType: AutoReplyMatchType): Int = when (matchType) {
    AutoReplyMatchType.KEYWORD -> R.string.bots_match_keyword
    AutoReplyMatchType.CONTAINS -> R.string.bots_match_contains
    AutoReplyMatchType.EXACT -> R.string.bots_match_exact
    AutoReplyMatchType.REGEX -> R.string.bots_match_regex
}
