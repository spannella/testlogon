@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.questionnaire.builder.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.questionnaire.builder.data.QnrQuestion
import com.testlogon.android.feature.questionnaire.builder.data.QnrQuestionType

/**
 * Route + stateless screen for the questionnaire BUILDER editor (web QuestionnaireBuilderPage parity).
 * Edits draft metadata, manages sections + questions of all nine types, and publishes an immutable version.
 */
@Composable
fun BuilderRoute(
    onBack: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: BuilderViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is BuilderEffect.NavigateToLogin -> onNavigateToLogin()
                is BuilderEffect.DraftCreated -> Unit
            }
        }
    }

    BuilderScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::load,
        callbacks = BuilderCallbacks(
            onTitleChange = viewModel::onTitleChange,
            onDescriptionChange = viewModel::onDescriptionChange,
            onSaveMetadata = viewModel::saveMetadata,
            onVisibilityChange = viewModel::onVisibilityChange,
            onAddSection = viewModel::addSection,
            onSectionTitleChange = viewModel::onSectionTitleChange,
            onSaveSection = viewModel::saveSection,
            onDeleteSection = viewModel::deleteSection,
            onAddQuestion = viewModel::addQuestion,
            onQuestionEdit = viewModel::onQuestionEdit,
            onQuestionTypeChange = viewModel::onQuestionTypeChange,
            onSaveQuestion = viewModel::saveQuestion,
            onDeleteQuestion = viewModel::deleteQuestion,
            onOpenPublish = viewModel::openPublish,
            onDismissPublish = viewModel::dismissPublish,
            onConfirmPublish = viewModel::confirmPublish,
        ),
    )
}

/** Bundles the many builder callbacks to keep the screen signature tractable. */
data class BuilderCallbacks(
    val onTitleChange: (String) -> Unit,
    val onDescriptionChange: (String) -> Unit,
    val onSaveMetadata: () -> Unit,
    val onVisibilityChange: (String) -> Unit,
    val onAddSection: () -> Unit,
    val onSectionTitleChange: (String, String) -> Unit,
    val onSaveSection: (String) -> Unit,
    val onDeleteSection: (String) -> Unit,
    val onAddQuestion: (String, QnrQuestionType) -> Unit,
    val onQuestionEdit: (String, String, (QnrQuestion) -> QnrQuestion) -> Unit,
    val onQuestionTypeChange: (String, String, QnrQuestionType) -> Unit,
    val onSaveQuestion: (String, String) -> Unit,
    val onDeleteQuestion: (String, String) -> Unit,
    val onOpenPublish: () -> Unit,
    val onDismissPublish: () -> Unit,
    val onConfirmPublish: () -> Unit,
)

@Composable
fun BuilderScreen(
    state: BuilderUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    callbacks: BuilderCallbacks,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(QuestionnaireBuilderTestTags.BUILDER_SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Questionnaire builder") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    if (state is BuilderUiState.Content) {
                        TextButton(
                            onClick = callbacks.onOpenPublish,
                            enabled = !state.busy,
                            modifier = Modifier.testTag(QuestionnaireBuilderTestTags.PUBLISH),
                        ) { Text("Publish") }
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            is BuilderUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is BuilderUiState.Error -> ErrorState(
                message = state.message,
                onRetry = onRetry,
                modifier = Modifier.padding(padding),
            )
            is BuilderUiState.Content -> BuilderContent(
                state = state,
                callbacks = callbacks,
                modifier = Modifier.padding(padding),
            )
        }
    }

    val publish = (state as? BuilderUiState.Content)?.publish
    if (publish != null) {
        PublishDialog(
            publish = publish,
            onDismiss = callbacks.onDismissPublish,
            onConfirm = callbacks.onConfirmPublish,
        )
    }
}

@Composable
private fun BuilderContent(
    state: BuilderUiState.Content,
    callbacks: BuilderCallbacks,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        if (state.actionError != null) {
            item("error") {
                Text(
                    text = state.actionError,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
        if (state.publishedVersionId != null) {
            item("published") {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = "Published · version ${state.publishedVersionId}",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(16.dp),
                    )
                }
            }
        }

        item("metadata") {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Metadata", style = MaterialTheme.typography.titleMedium)
                    OutlinedTextField(
                        value = state.title,
                        onValueChange = callbacks.onTitleChange,
                        label = { Text("Title") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag(QuestionnaireBuilderTestTags.BUILDER_TITLE),
                    )
                    OutlinedTextField(
                        value = state.description,
                        onValueChange = callbacks.onDescriptionChange,
                        label = { Text("Description") },
                        minLines = 2,
                        modifier = Modifier.fillMaxWidth().testTag(QuestionnaireBuilderTestTags.BUILDER_DESCRIPTION),
                    )
                    VisibilityPicker(value = state.visibility, onChange = callbacks.onVisibilityChange)
                    OutlinedButton(onClick = callbacks.onSaveMetadata, enabled = !state.busy) {
                        Text("Save metadata")
                    }
                }
            }
        }

        item("sections-header") {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Sections", style = MaterialTheme.typography.titleMedium)
                Button(
                    onClick = callbacks.onAddSection,
                    enabled = !state.busy,
                    modifier = Modifier.testTag(QuestionnaireBuilderTestTags.ADD_SECTION),
                ) {
                    Icon(Icons.Outlined.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                    Text("Add section", modifier = Modifier.padding(start = 6.dp))
                }
            }
        }

        if (state.sections.isEmpty()) {
            item("no-sections") {
                Text(
                    "No sections yet. Add a section to start adding questions.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        items(items = state.sections, key = { it.section.sectionId }) { bs ->
            SectionCard(builderSection = bs, busy = state.busy, callbacks = callbacks)
        }
    }
}

@Composable
private fun SectionCard(
    builderSection: BuilderSection,
    busy: Boolean,
    callbacks: BuilderCallbacks,
) {
    val sectionId = builderSection.section.sectionId
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = builderSection.section.title,
                    onValueChange = { callbacks.onSectionTitleChange(sectionId, it) },
                    label = { Text("Section title") },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
                IconButton(onClick = { callbacks.onDeleteSection(sectionId) }, enabled = !busy) {
                    Icon(Icons.Outlined.Delete, contentDescription = "Delete section")
                }
            }
            OutlinedButton(onClick = { callbacks.onSaveSection(sectionId) }, enabled = !busy) {
                Text("Save section")
            }

            HorizontalDivider()

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Questions", style = MaterialTheme.typography.titleSmall)
                Button(
                    onClick = { callbacks.onAddQuestion(sectionId, QnrQuestionType.TEXT) },
                    enabled = !busy,
                    modifier = Modifier.testTag(QuestionnaireBuilderTestTags.addQuestion(sectionId)),
                ) {
                    Icon(Icons.Outlined.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                    Text("Add question", modifier = Modifier.padding(start = 6.dp))
                }
            }

            if (builderSection.questions.isEmpty()) {
                Text(
                    "No questions in this section yet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            builderSection.questions.forEach { question ->
                QuestionCard(sectionId = sectionId, question = question, busy = busy, callbacks = callbacks)
            }
        }
    }
}

@Composable
private fun QuestionCard(
    sectionId: String,
    question: QnrQuestion,
    busy: Boolean,
    callbacks: BuilderCallbacks,
) {
    val qid = question.questionId
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(QuestionnaireBuilderTestTags.questionCard(qid)),
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = question.label,
                onValueChange = { v -> callbacks.onQuestionEdit(sectionId, qid) { it.copy(label = v) } },
                label = { Text("Label") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            QuestionTypePicker(
                value = question.type,
                onChange = { callbacks.onQuestionTypeChange(sectionId, qid, it) },
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Required", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                Switch(
                    checked = question.required,
                    onCheckedChange = { v -> callbacks.onQuestionEdit(sectionId, qid) { it.copy(required = v) } },
                    enabled = !busy,
                )
            }
            OutlinedTextField(
                value = question.hint,
                onValueChange = { v -> callbacks.onQuestionEdit(sectionId, qid) { it.copy(hint = v) } },
                label = { Text("Hint text") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            QuestionConfigEditor(
                type = question.type,
                config = question.configJson,
                onChange = { cfg -> callbacks.onQuestionEdit(sectionId, qid) { it.copy(configJson = cfg) } },
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = { callbacks.onSaveQuestion(sectionId, qid) },
                    enabled = !busy,
                    modifier = Modifier.weight(1f),
                ) { Text("Save question") }
                IconButton(onClick = { callbacks.onDeleteQuestion(sectionId, qid) }, enabled = !busy) {
                    Icon(Icons.Outlined.Delete, contentDescription = "Delete question")
                }
            }
        }
    }
}

@Composable
private fun PublishDialog(
    publish: PublishState,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(QuestionnaireBuilderTestTags.PUBLISH_DIALOG),
        title = { Text("Publish questionnaire") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                if (publish.publishedVersionId != null) {
                    Text(
                        "Published version ${publish.publishedVersionId}",
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.primary,
                    )
                    if (publish.publishedSlug != null) {
                        Text("Slug: ${publish.publishedSlug}", style = MaterialTheme.typography.bodySmall)
                    }
                } else {
                    Text("Readiness checks:", style = MaterialTheme.typography.bodyMedium)
                    publish.checks.forEach { check ->
                        Text(
                            text = check,
                            style = MaterialTheme.typography.bodySmall,
                            color = if (publish.ready) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.error,
                        )
                    }
                }
            }
        },
        confirmButton = {
            if (publish.publishedVersionId != null) {
                TextButton(onClick = onDismiss) { Text("Done") }
            } else {
                Button(
                    onClick = onConfirm,
                    enabled = publish.ready && !publish.publishing,
                    modifier = Modifier.testTag(QuestionnaireBuilderTestTags.PUBLISH_CONFIRM),
                ) {
                    if (publish.publishing) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp))
                    } else {
                        Text("Confirm publish")
                    }
                }
            }
        },
        dismissButton = {
            if (publish.publishedVersionId == null) {
                TextButton(onClick = onDismiss) { Text("Cancel") }
            }
        },
    )
}
