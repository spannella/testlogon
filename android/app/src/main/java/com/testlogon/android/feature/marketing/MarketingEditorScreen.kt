@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.marketing

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
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
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object MarketingEditorTestTags {
    const val SCREEN = "marketing_editor_screen"
    const val CONTENT = "marketing_editor_content"
    const val LOADING = "marketing_editor_loading"
    const val ERROR = "marketing_editor_error"
    const val OFFLINE = "marketing_editor_offline"
    const val SESSION_EXPIRED = "marketing_editor_session_expired"
    const val TITLE = "marketing_editor_title"
    const val BODY = "marketing_editor_body"
    const val SAVE = "marketing_editor_save"
    const val APPROVE = "marketing_editor_approve"
    const val SCHEDULE = "marketing_editor_schedule"
}

@Composable
fun MarketingEditorRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: MarketingEditorViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is MarketingEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }
    LaunchedEffect(state.phase) {
        if (state.phase == MarketingEditorUiState.Phase.SessionExpired) onSessionExpired()
    }

    MarketingEditorScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onTitleChange = viewModel::onTitleChange,
        onBodyChange = viewModel::onBodyChange,
        onSummaryChange = viewModel::onSummaryChange,
        onTagsChange = viewModel::onTagsChange,
        onSeoTitleChange = viewModel::onSeoTitleChange,
        onSeoDescriptionChange = viewModel::onSeoDescriptionChange,
        onScheduleAtChange = viewModel::onScheduleAtChange,
        onSave = viewModel::onSave,
        onApprove = viewModel::onApprove,
        onSchedule = viewModel::onSchedule,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun MarketingEditorScreen(
    state: MarketingEditorUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onTitleChange: (String) -> Unit,
    onBodyChange: (String) -> Unit,
    onSummaryChange: (String) -> Unit,
    onTagsChange: (String) -> Unit,
    onSeoTitleChange: (String) -> Unit,
    onSeoDescriptionChange: (String) -> Unit,
    onScheduleAtChange: (Long?) -> Unit,
    onSave: () -> Unit,
    onApprove: () -> Unit,
    onSchedule: () -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(MarketingEditorTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.marketing_editor_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    val content = state.content
                    if (content != null && content.canApprove) {
                        TextButton(onClick = onApprove, enabled = !state.isApproving, modifier = Modifier.testTag(MarketingEditorTestTags.APPROVE)) {
                            Text(stringResource(R.string.marketing_approve))
                        }
                    }
                    TextButton(onClick = onSave, enabled = !state.isSaving && state.phase == MarketingEditorUiState.Phase.Content, modifier = Modifier.testTag(MarketingEditorTestTags.SAVE)) {
                        Text(stringResource(R.string.marketing_save))
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                MarketingEditorUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(MarketingEditorTestTags.LOADING))
                MarketingEditorUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.marketing_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(MarketingEditorTestTags.ERROR),
                    )
                MarketingEditorUiState.Phase.Offline ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.marketing_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(MarketingEditorTestTags.OFFLINE),
                    )
                MarketingEditorUiState.Phase.SessionExpired ->
                    EmptyState(
                        title = stringResource(R.string.marketing_session_expired_title),
                        body = stringResource(R.string.marketing_session_expired_body),
                        modifier = Modifier.testTag(MarketingEditorTestTags.SESSION_EXPIRED),
                    )
                MarketingEditorUiState.Phase.Content ->
                    EditorForm(
                        state = state,
                        onTitleChange = onTitleChange,
                        onBodyChange = onBodyChange,
                        onSummaryChange = onSummaryChange,
                        onTagsChange = onTagsChange,
                        onSeoTitleChange = onSeoTitleChange,
                        onSeoDescriptionChange = onSeoDescriptionChange,
                        onScheduleAtChange = onScheduleAtChange,
                        onSchedule = onSchedule,
                    )
            }
        }
    }
}

@Composable
private fun EditorForm(
    state: MarketingEditorUiState,
    onTitleChange: (String) -> Unit,
    onBodyChange: (String) -> Unit,
    onSummaryChange: (String) -> Unit,
    onTagsChange: (String) -> Unit,
    onSeoTitleChange: (String) -> Unit,
    onSeoDescriptionChange: (String) -> Unit,
    onScheduleAtChange: (Long?) -> Unit,
    onSchedule: () -> Unit,
) {
    Column(
        modifier = Modifier
            .testTag(MarketingEditorTestTags.CONTENT)
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        state.content?.let { LabelChip(it.status.name.lowercase()) }
        OutlinedTextField(
            value = state.title,
            onValueChange = onTitleChange,
            label = { Text(stringResource(R.string.marketing_field_title)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag(MarketingEditorTestTags.TITLE),
        )
        OutlinedTextField(
            value = state.body,
            onValueChange = onBodyChange,
            label = { Text(stringResource(R.string.marketing_field_body)) },
            minLines = 8,
            modifier = Modifier.fillMaxWidth().testTag(MarketingEditorTestTags.BODY),
        )
        OutlinedTextField(
            value = state.summary,
            onValueChange = onSummaryChange,
            label = { Text(stringResource(R.string.marketing_field_summary)) },
            minLines = 2,
            modifier = Modifier.fillMaxWidth(),
        )
        SectionCard(stringResource(R.string.marketing_seo_meta)) {
            OutlinedTextField(
                value = state.seoTitle,
                onValueChange = onSeoTitleChange,
                label = { Text(stringResource(R.string.marketing_meta_title)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = state.seoDescription,
                onValueChange = onSeoDescriptionChange,
                label = { Text(stringResource(R.string.marketing_meta_description)) },
                minLines = 2,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        SectionCard(stringResource(R.string.marketing_tags)) {
            OutlinedTextField(
                value = state.tags,
                onValueChange = onTagsChange,
                label = { Text(stringResource(R.string.marketing_tags_hint)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        ScheduleCard(state = state, onScheduleAtChange = onScheduleAtChange, onSchedule = onSchedule)
    }
}

@Composable
private fun SectionCard(title: String, content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth(), elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)) {
        Column(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            content()
        }
    }
}

@Composable
private fun ScheduleCard(
    state: MarketingEditorUiState,
    onScheduleAtChange: (Long?) -> Unit,
    onSchedule: () -> Unit,
) {
    var showDatePicker by remember { mutableStateOf(false) }
    val canSchedule = state.content?.canSchedule == true
    SectionCard(stringResource(R.string.marketing_schedule)) {
        val at = state.scheduleAtSeconds
        Text(
            text = if (at != null) formatDateTime(at) else stringResource(R.string.marketing_schedule_none),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedButton(onClick = { showDatePicker = true }, enabled = canSchedule) {
            Text(stringResource(R.string.marketing_pick_date))
        }
        Button(
            onClick = onSchedule,
            enabled = canSchedule && at != null && !state.isScheduling,
            modifier = Modifier.testTag(MarketingEditorTestTags.SCHEDULE),
        ) {
            Text(stringResource(R.string.marketing_schedule_action))
        }
        if (!canSchedule) {
            Text(
                stringResource(R.string.marketing_schedule_gate),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }

    if (showDatePicker) {
        val pickerState = rememberDatePickerState(
            initialSelectedDateMillis = (state.scheduleAtSeconds?.times(1000L)) ?: System.currentTimeMillis(),
        )
        DatePickerDialog(
            onDismissRequest = { showDatePicker = false },
            confirmButton = {
                TextButton(onClick = {
                    pickerState.selectedDateMillis?.let { onScheduleAtChange(it / 1000L) }
                    showDatePicker = false
                }) { Text(stringResource(R.string.action_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { showDatePicker = false }) { Text(stringResource(R.string.action_cancel)) }
            },
        ) {
            DatePicker(state = pickerState)
        }
    }
}

private fun formatDateTime(epochSeconds: Long): String {
    val fmt = SimpleDateFormat("MMM d, yyyy", Locale.getDefault())
    return fmt.format(Date(epochSeconds * 1000L))
}
