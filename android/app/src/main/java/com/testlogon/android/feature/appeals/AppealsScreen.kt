@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.appeals

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
import androidx.compose.material.icons.outlined.Gavel
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.DropdownMenuItem
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
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
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
import com.testlogon.android.data.appeals.EnforcementOption
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.appeals.Appeal
import com.testlogon.android.data.appeals.AppealStatus

/** Stable testTags for the appeals screen. */
object AppealsTestTags {
    const val SCREEN = "appeals_screen"
    const val LIST = "appeals_list"
    const val LOADING = "appeals_loading"
    const val EMPTY = "appeals_empty"
    const val ERROR = "appeals_error"
    const val OFFLINE = "appeals_offline"
    const val SESSION_EXPIRED = "appeals_session_expired"
    const val NEW = "appeals_new"
    const val FORM = "appeals_submit_form"
    const val FORM_ENFORCEMENT_ID = "appeals_form_enforcement_id"
    const val FORM_TEXT = "appeals_form_text"
    const val FORM_SUBMIT = "appeals_form_submit"
    const val ROW_PREFIX = "appeals_row_"
    const val WITHDRAW_PREFIX = "appeals_withdraw_"
}

/** Route-level "My appeals" entry (reachable from the More hub). Mirrors the web /appeals page. */
@Composable
fun AppealsRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    prefillEnforcementId: String? = null,
    viewModel: AppealsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    // MODX-13: a ban/removal alert deep-link opens the submit form with the enforcement preselected.
    LaunchedEffect(prefillEnforcementId) {
        if (!prefillEnforcementId.isNullOrBlank()) viewModel.onPrefillEnforcement(prefillEnforcementId)
    }
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is AppealsEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }

    LaunchedEffect(state.phase) {
        if (state.phase == AppealsUiState.Phase.SessionExpired) onSessionExpired()
    }

    AppealsScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onOpenSubmit = viewModel::onOpenSubmit,
        onDismissSubmit = viewModel::onDismissSubmit,
        onEnforcementIdChange = viewModel::onEnforcementIdChange,
        onSelectEnforcement = viewModel::onSelectEnforcement,
        onAppealTextChange = viewModel::onAppealTextChange,
        onSubmit = viewModel::onSubmit,
        onWithdraw = viewModel::onWithdraw,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun AppealsScreen(
    state: AppealsUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onOpenSubmit: () -> Unit,
    onDismissSubmit: () -> Unit,
    onEnforcementIdChange: (String) -> Unit,
    onSelectEnforcement: (String) -> Unit,
    onAppealTextChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onWithdraw: (String) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(AppealsTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.appeals_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("appeals_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    val newCd = stringResource(R.string.appeals_new)
                    IconButton(onClick = onOpenSubmit, modifier = Modifier.testTag(AppealsTestTags.NEW)) {
                        Icon(Icons.Outlined.Add, contentDescription = newCd)
                    }
                },
            )
        },
        floatingActionButton = {
            if (state.phase == AppealsUiState.Phase.Content || state.phase == AppealsUiState.Phase.Empty) {
                FloatingActionButton(onClick = onOpenSubmit) {
                    Icon(Icons.Outlined.Add, contentDescription = stringResource(R.string.appeals_new))
                }
            }
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                AppealsUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(AppealsTestTags.LOADING))

                AppealsUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.appeals_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(AppealsTestTags.ERROR),
                    )

                AppealsUiState.Phase.Offline ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.appeals_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(AppealsTestTags.OFFLINE),
                    )

                AppealsUiState.Phase.SessionExpired ->
                    EmptyState(
                        title = stringResource(R.string.appeals_session_expired_title),
                        body = stringResource(R.string.appeals_session_expired_body),
                        modifier = Modifier.testTag(AppealsTestTags.SESSION_EXPIRED),
                    )

                AppealsUiState.Phase.Empty ->
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        EmptyState(
                            title = stringResource(R.string.appeals_empty_title),
                            body = stringResource(R.string.appeals_empty_body),
                            imageVector = Icons.Outlined.Gavel,
                            actionLabel = stringResource(R.string.appeals_new),
                            onAction = onOpenSubmit,
                            modifier = Modifier.testTag(AppealsTestTags.EMPTY),
                        )
                    }

                AppealsUiState.Phase.Content -> {
                    val appeals = state.page?.appeals.orEmpty()
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        LazyColumn(
                            modifier = Modifier
                                .testTag(AppealsTestTags.LIST)
                                .fillMaxSize(),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            if (state.isStale) {
                                item { OfflineBanner(onRetry = onRetry) }
                            }
                            items(appeals, key = { it.id }) { appeal ->
                                AppealCard(
                                    appeal = appeal,
                                    isMutating = state.isMutating,
                                    onWithdraw = { onWithdraw(appeal.id) },
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (state.submit.isOpen) {
        SubmitAppealDialog(
            form = state.submit,
            onDismiss = onDismissSubmit,
            onEnforcementIdChange = onEnforcementIdChange,
            onSelectEnforcement = onSelectEnforcement,
            onAppealTextChange = onAppealTextChange,
            onSubmit = onSubmit,
        )
    }
}

@Composable
private fun AppealCard(
    appeal: Appeal,
    isMutating: Boolean,
    onWithdraw: () -> Unit,
) {
    var confirmWithdraw by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(false) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(AppealsTestTags.ROW_PREFIX + appeal.id),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            ) {
                StatusChip(status = appeal.status)
                appeal.enforcementType?.let { type ->
                    Text(
                        text = type,
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            Text(
                text = appeal.appealText,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 3,
                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
            )

            val created = appeal.formattedCreated()
            if (created.isNotBlank()) {
                Text(
                    text = stringResource(R.string.appeals_submitted_on, created),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            if (appeal.hasDecision) {
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        text = stringResource(R.string.appeals_decision_label),
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = appeal.decisionNote.orEmpty(),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            if (appeal.canWithdraw) {
                TextButton(
                    onClick = { confirmWithdraw = true },
                    enabled = !isMutating,
                    modifier = Modifier.testTag(AppealsTestTags.WITHDRAW_PREFIX + appeal.id),
                ) {
                    Text(stringResource(R.string.appeals_withdraw))
                }
            }
        }
    }

    if (confirmWithdraw) {
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { confirmWithdraw = false },
            title = { Text(stringResource(R.string.appeals_withdraw_confirm_title)) },
            text = { Text(stringResource(R.string.appeals_withdraw_confirm_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmWithdraw = false
                    onWithdraw()
                }) {
                    Text(stringResource(R.string.appeals_withdraw))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmWithdraw = false }) {
                    Text(stringResource(R.string.appeals_cancel))
                }
            },
        )
    }
}

@Composable
private fun StatusChip(status: AppealStatus) {
    val labelRes = when (status) {
        AppealStatus.SUBMITTED -> R.string.appeals_status_submitted
        AppealStatus.UNDER_REVIEW -> R.string.appeals_status_under_review
        AppealStatus.UPHELD -> R.string.appeals_status_upheld
        AppealStatus.MODIFIED -> R.string.appeals_status_modified
        AppealStatus.REVERSED -> R.string.appeals_status_reversed
        AppealStatus.WITHDRAWN -> R.string.appeals_status_withdrawn
        AppealStatus.UNKNOWN -> R.string.appeals_status_unknown
    }
    val container = when (status) {
        AppealStatus.REVERSED, AppealStatus.MODIFIED -> MaterialTheme.colorScheme.tertiaryContainer
        AppealStatus.UPHELD -> MaterialTheme.colorScheme.errorContainer
        AppealStatus.WITHDRAWN, AppealStatus.UNKNOWN -> MaterialTheme.colorScheme.surfaceVariant
        else -> MaterialTheme.colorScheme.secondaryContainer
    }
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(stringResource(labelRes)) },
        colors = AssistChipDefaults.assistChipColors(
            disabledContainerColor = container,
            disabledLabelColor = MaterialTheme.colorScheme.onSurface,
        ),
        border = null,
    )
}

@Composable
@OptIn(ExperimentalMaterial3Api::class)
private fun SubmitAppealDialog(
    form: SubmitFormState,
    onDismiss: () -> Unit,
    onEnforcementIdChange: (String) -> Unit,
    onSelectEnforcement: (String) -> Unit,
    onAppealTextChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier.fillMaxWidth().testTag(AppealsTestTags.FORM),
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    text = stringResource(R.string.appeals_submit_title),
                    style = MaterialTheme.typography.titleLarge,
                )
                Text(
                    text = stringResource(R.string.appeals_submit_helper),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                // MODX-13: pick the enforcement to appeal from your own history — never hand-type
                // an opaque id. Falls back to a text field only if the picker loaded empty.
                if (form.options.isNotEmpty()) {
                    EnforcementPicker(
                        options = form.options,
                        selectedId = form.enforcementId,
                        enabled = !form.isSubmitting,
                        onSelect = onSelectEnforcement,
                    )
                } else if (form.optionsLoading) {
                    Text(
                        text = stringResource(R.string.appeals_options_loading),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    OutlinedTextField(
                        value = form.enforcementId,
                        onValueChange = onEnforcementIdChange,
                        label = { Text(stringResource(R.string.appeals_field_enforcement_id)) },
                        singleLine = true,
                        enabled = !form.isSubmitting,
                        modifier = Modifier.fillMaxWidth().testTag(AppealsTestTags.FORM_ENFORCEMENT_ID),
                    )
                }
                OutlinedTextField(
                    value = form.appealText,
                    onValueChange = onAppealTextChange,
                    label = { Text(stringResource(R.string.appeals_field_appeal_text)) },
                    minLines = 4,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth().testTag(AppealsTestTags.FORM_TEXT),
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                ) {
                    TextButton(onClick = onDismiss, enabled = !form.isSubmitting) {
                        Text(stringResource(R.string.appeals_cancel))
                    }
                    TextButton(
                        onClick = onSubmit,
                        enabled = form.canSubmit,
                        modifier = Modifier.testTag(AppealsTestTags.FORM_SUBMIT),
                    ) {
                        Text(stringResource(R.string.appeals_submit_action))
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun EnforcementPicker(
    options: List<EnforcementOption>,
    selectedId: String,
    enabled: Boolean,
    onSelect: (String) -> Unit,
) {
    var expanded by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(false) }
    val selected = options.firstOrNull { it.enforcementId == selectedId }
    val display = selected?.label() ?: stringResource(R.string.appeals_field_enforcement_id)
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { if (enabled) expanded = it },
    ) {
        OutlinedTextField(
            value = display,
            onValueChange = {},
            readOnly = true,
            enabled = enabled,
            label = { Text(stringResource(R.string.appeals_field_enforcement)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor()
                .testTag(AppealsTestTags.FORM_ENFORCEMENT_ID),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { opt ->
                DropdownMenuItem(
                    text = {
                        Column {
                            Text(opt.label(), style = MaterialTheme.typography.bodyMedium)
                            if (opt.hasAppeal) {
                                Text(
                                    stringResource(R.string.appeals_option_already_appealed),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    },
                    onClick = { onSelect(opt.enforcementId); expanded = false },
                )
            }
        }
    }
}
