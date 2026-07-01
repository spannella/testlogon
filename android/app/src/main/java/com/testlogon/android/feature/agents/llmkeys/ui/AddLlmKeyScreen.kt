@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.agents.llmkeys.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
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
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/** AGENTS-BASICS - stable testTags for the add-LLM-key screen. */
object AddLlmKeyTestTags {
    const val SCREEN = "llm_key_add_screen"
    const val LABEL = "llm_key_add_label"
    const val API_KEY = "llm_key_add_api_key"
    const val SUBMIT = "llm_key_add_submit"
}

// Fallback provider set when the providers catalog call is unavailable (mirrors LlmKeyCreateIn pattern).
private val FALLBACK_PROVIDERS = listOf("openai", "anthropic", "deepseek", "gemini", "custom")

@Composable
fun AddLlmKeyRoute(
    onBack: () -> Unit,
    onAdded: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: AddLlmKeyViewModel = hiltViewModel(),
) {
    val form by viewModel.form.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is LlmKeysEffect.AddSucceeded -> onAdded()
                is LlmKeysEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }
    AddLlmKeyScreen(
        form = form,
        onBack = onBack,
        onProviderChange = viewModel::onProviderChange,
        onLabelChange = viewModel::onLabelChange,
        onApiKeyChange = viewModel::onApiKeyChange,
        onBaseUrlChange = viewModel::onBaseUrlChange,
        onModelPreferenceChange = viewModel::onModelPreferenceChange,
        onSubmit = viewModel::submit,
    )
}

@Composable
fun AddLlmKeyScreen(
    form: AddLlmKeyForm,
    onBack: () -> Unit,
    onProviderChange: (String) -> Unit,
    onLabelChange: (String) -> Unit,
    onApiKeyChange: (String) -> Unit,
    onBaseUrlChange: (String) -> Unit,
    onModelPreferenceChange: (String) -> Unit,
    onSubmit: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val providerIds = form.providers.map { it.provider }.ifEmpty { FALLBACK_PROVIDERS }
    Scaffold(
        modifier = modifier.testTag(AddLlmKeyTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Add LLM key") },
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
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text("Provider", style = MaterialTheme.typography.titleSmall)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                providerIds.forEach { p ->
                    FilterChip(selected = form.provider == p, onClick = { onProviderChange(p) }, label = { Text(p) })
                }
            }

            OutlinedTextField(
                value = form.label,
                onValueChange = onLabelChange,
                label = { Text("Label") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                modifier = Modifier.fillMaxWidth().testTag(AddLlmKeyTestTags.LABEL),
            )

            OutlinedTextField(
                value = form.apiKey,
                onValueChange = onApiKeyChange,
                label = { Text("API key") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                supportingText = { Text("Stored encrypted; never shown again after saving.") },
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                modifier = Modifier.fillMaxWidth().testTag(AddLlmKeyTestTags.API_KEY),
            )

            OutlinedTextField(
                value = form.baseUrl,
                onValueChange = onBaseUrlChange,
                label = { Text("Base URL (optional)") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Next),
                modifier = Modifier.fillMaxWidth(),
            )

            OutlinedTextField(
                value = form.modelPreference,
                onValueChange = onModelPreferenceChange,
                label = { Text("Preferred model (optional)") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                modifier = Modifier.fillMaxWidth(),
            )

            if (form.submitError != null) {
                Text(form.submitError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
            }

            Button(
                onClick = onSubmit,
                enabled = form.canSubmit,
                modifier = Modifier.fillMaxWidth().testTag(AddLlmKeyTestTags.SUBMIT),
            ) {
                if (form.submitting) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.heightIn(max = 20.dp))
                } else {
                    Text("Save key")
                }
            }
        }
    }
}
