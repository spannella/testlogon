@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.questionnaire.builder.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * Route + stateless screen for creating a new questionnaire draft (title + description + visibility).
 * On a successful create the [BuilderEffect.DraftCreated] effect fires and the screen pops back, handing
 * the new questionnaire id to the caller so it opens the builder.
 */
@Composable
fun CreateDraftRoute(
    onBack: () -> Unit,
    onCreated: (String) -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: CreateDraftViewModel = hiltViewModel(),
) {
    val form by viewModel.form.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is BuilderEffect.DraftCreated -> onCreated(effect.questionnaireId)
                is BuilderEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }

    CreateDraftScreen(
        form = form,
        onBack = onBack,
        onTitleChange = viewModel::onTitleChange,
        onDescriptionChange = viewModel::onDescriptionChange,
        onVisibilityChange = viewModel::onVisibilityChange,
        onSubmit = viewModel::submit,
    )
}

@Composable
fun CreateDraftScreen(
    form: CreateDraftForm,
    onBack: () -> Unit,
    onTitleChange: (String) -> Unit,
    onDescriptionChange: (String) -> Unit,
    onVisibilityChange: (String) -> Unit,
    onSubmit: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(QuestionnaireBuilderTestTags.CREATE_SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("New questionnaire") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            OutlinedTextField(
                value = form.title,
                onValueChange = onTitleChange,
                label = { Text("Title") },
                singleLine = true,
                isError = form.titleError != null,
                supportingText = form.titleError?.let { { Text(it) } },
                modifier = Modifier.fillMaxWidth().testTag(QuestionnaireBuilderTestTags.CREATE_TITLE),
            )
            OutlinedTextField(
                value = form.description,
                onValueChange = onDescriptionChange,
                label = { Text("Description (optional)") },
                minLines = 3,
                modifier = Modifier.fillMaxWidth().testTag(QuestionnaireBuilderTestTags.CREATE_DESCRIPTION),
            )
            VisibilityPicker(value = form.visibility, onChange = onVisibilityChange)

            if (form.submitError != null) {
                Text(
                    text = form.submitError,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            Button(
                onClick = onSubmit,
                enabled = form.canSubmit,
                modifier = Modifier.fillMaxWidth().testTag(QuestionnaireBuilderTestTags.CREATE_SUBMIT),
            ) {
                if (form.submitting) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp))
                } else {
                    Text("Create")
                }
            }
        }
    }
}
