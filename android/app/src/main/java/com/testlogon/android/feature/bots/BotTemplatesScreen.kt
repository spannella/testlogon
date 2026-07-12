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
import androidx.compose.material.icons.outlined.Description
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
import com.testlogon.android.data.bots.BotTemplate
import com.testlogon.android.data.bots.TemplateCategory

/** Stable testTags for the templates screen. */
object BotTemplatesTestTags {
    const val SCREEN = "bot_templates_screen"
    const val LIST = "bot_templates_list"
    const val LOADING = "bot_templates_loading"
    const val EMPTY = "bot_templates_empty"
    const val ERROR = "bot_templates_error"
    const val OFFLINE = "bot_templates_offline"
    const val SESSION_EXPIRED = "bot_templates_session_expired"
    const val NEW = "bot_templates_new"
    const val FORM = "bot_templates_form"
    const val FORM_NAME = "bot_templates_form_name"
    const val FORM_TEXT = "bot_templates_form_text"
    const val FORM_SUBMIT = "bot_templates_form_submit"
    const val ROW_PREFIX = "bot_templates_row_"
}

/** Route-level message templates for one bot. Mirrors the web bots/{botId}/templates page. */
@Composable
fun BotTemplatesRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: BotTemplatesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is TemplatesEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }

    LaunchedEffect(state.phase) {
        if (state.phase == BotsPhase.SessionExpired) onSessionExpired()
    }

    BotTemplatesScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onOpenCreate = viewModel::onOpenCreate,
        onDismissForm = viewModel::onDismissForm,
        onNameChange = viewModel::onNameChange,
        onTextChange = viewModel::onTextChange,
        onCategoryChange = viewModel::onCategoryChange,
        onSubmitForm = viewModel::onSubmitForm,
        onDelete = viewModel::onDelete,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun BotTemplatesScreen(
    state: TemplatesUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onOpenCreate: () -> Unit,
    onDismissForm: () -> Unit,
    onNameChange: (String) -> Unit,
    onTextChange: (String) -> Unit,
    onCategoryChange: (TemplateCategory) -> Unit,
    onSubmitForm: () -> Unit,
    onDelete: (String) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(BotTemplatesTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.bots_templates_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("bot_templates_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    val newCd = stringResource(R.string.bots_template_new)
                    IconButton(onClick = onOpenCreate, modifier = Modifier.testTag(BotTemplatesTestTags.NEW)) {
                        Icon(Icons.Outlined.Add, contentDescription = newCd)
                    }
                },
            )
        },
        floatingActionButton = {
            if (state.phase == BotsPhase.Content || state.phase == BotsPhase.Empty) {
                FloatingActionButton(onClick = onOpenCreate) {
                    Icon(Icons.Outlined.Add, contentDescription = stringResource(R.string.bots_template_new))
                }
            }
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                BotsPhase.Loading ->
                    LoadingState(modifier = Modifier.testTag(BotTemplatesTestTags.LOADING))

                BotsPhase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.bots_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(BotTemplatesTestTags.ERROR),
                    )

                BotsPhase.Offline ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.bots_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(BotTemplatesTestTags.OFFLINE),
                    )

                BotsPhase.SessionExpired ->
                    EmptyState(
                        title = stringResource(R.string.bots_session_expired_title),
                        body = stringResource(R.string.bots_session_expired_body),
                        modifier = Modifier.testTag(BotTemplatesTestTags.SESSION_EXPIRED),
                    )

                BotsPhase.Empty ->
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        EmptyState(
                            title = stringResource(R.string.bots_templates_empty_title),
                            body = stringResource(R.string.bots_templates_empty_body),
                            imageVector = Icons.Outlined.Description,
                            actionLabel = stringResource(R.string.bots_template_new),
                            onAction = onOpenCreate,
                            modifier = Modifier.testTag(BotTemplatesTestTags.EMPTY),
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
                                .testTag(BotTemplatesTestTags.LIST)
                                .fillMaxSize(),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            items(state.templates, key = { it.id }) { template ->
                                TemplateCard(
                                    template = template,
                                    isMutating = state.isMutating,
                                    onDelete = { onDelete(template.id) },
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (state.form.isOpen) {
        TemplateFormDialog(
            form = state.form,
            onDismiss = onDismissForm,
            onNameChange = onNameChange,
            onTextChange = onTextChange,
            onCategoryChange = onCategoryChange,
            onSubmit = onSubmitForm,
        )
    }
}

@Composable
private fun TemplateCard(
    template: BotTemplate,
    isMutating: Boolean,
    onDelete: () -> Unit,
) {
    var confirmDelete by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(BotTemplatesTestTags.ROW_PREFIX + template.id),
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
                Text(
                    text = template.name,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f),
                )
                CategoryChip(category = template.category)
            }
            Text(
                text = template.text,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 4,
                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                TextButton(onClick = { confirmDelete = true }, enabled = !isMutating) {
                    Text(stringResource(R.string.bots_template_delete))
                }
            }
        }
    }

    if (confirmDelete) {
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(stringResource(R.string.bots_template_delete_confirm_title)) },
            text = { Text(stringResource(R.string.bots_template_delete_confirm_body, template.name)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    onDelete()
                }) {
                    Text(stringResource(R.string.bots_template_delete))
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
private fun CategoryChip(category: TemplateCategory) {
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(stringResource(categoryLabel(category))) },
        colors = AssistChipDefaults.assistChipColors(
            disabledContainerColor = MaterialTheme.colorScheme.secondaryContainer,
            disabledLabelColor = MaterialTheme.colorScheme.onSurface,
        ),
        border = null,
    )
}

@Composable
private fun TemplateFormDialog(
    form: TemplateFormState,
    onDismiss: () -> Unit,
    onNameChange: (String) -> Unit,
    onTextChange: (String) -> Unit,
    onCategoryChange: (TemplateCategory) -> Unit,
    onSubmit: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.fillMaxWidth().testTag(BotTemplatesTestTags.FORM)) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    text = stringResource(R.string.bots_template_create_title),
                    style = MaterialTheme.typography.titleLarge,
                )
                OutlinedTextField(
                    value = form.name,
                    onValueChange = onNameChange,
                    label = { Text(stringResource(R.string.bots_field_template_name)) },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth().testTag(BotTemplatesTestTags.FORM_NAME),
                )
                OutlinedTextField(
                    value = form.text,
                    onValueChange = onTextChange,
                    label = { Text(stringResource(R.string.bots_field_template_text)) },
                    minLines = 4,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth().testTag(BotTemplatesTestTags.FORM_TEXT),
                )
                CategoryDropdown(
                    selected = form.category,
                    enabled = !form.isSubmitting,
                    onSelected = onCategoryChange,
                )
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
                        modifier = Modifier.testTag(BotTemplatesTestTags.FORM_SUBMIT),
                    ) {
                        Text(stringResource(R.string.bots_template_create_action))
                    }
                }
            }
        }
    }
}

@Composable
private fun CategoryDropdown(
    selected: TemplateCategory,
    enabled: Boolean,
    onSelected: (TemplateCategory) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val options = TemplateCategory.values()

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { if (enabled) expanded = it },
    ) {
        OutlinedTextField(
            value = stringResource(categoryLabel(selected)),
            onValueChange = {},
            readOnly = true,
            enabled = enabled,
            label = { Text(stringResource(R.string.bots_field_category)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { option ->
                DropdownMenuItem(
                    text = { Text(stringResource(categoryLabel(option))) },
                    onClick = {
                        onSelected(option)
                        expanded = false
                    },
                )
            }
        }
    }
}

private fun categoryLabel(category: TemplateCategory): Int = when (category) {
    TemplateCategory.GREETING -> R.string.bots_category_greeting
    TemplateCategory.SUPPORT -> R.string.bots_category_support
    TemplateCategory.PROMOTION -> R.string.bots_category_promotion
    TemplateCategory.FAREWELL -> R.string.bots_category_farewell
    TemplateCategory.AWAY -> R.string.bots_category_away
    TemplateCategory.CUSTOM -> R.string.bots_category_custom
}
