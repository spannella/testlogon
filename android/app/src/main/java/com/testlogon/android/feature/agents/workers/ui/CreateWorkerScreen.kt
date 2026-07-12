@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agents.workers.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
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
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.foundation.text.KeyboardOptions

/** AGENTS-BASICS - stable testTags for the create-worker screen. */
object CreateWorkerTestTags {
    const val SCREEN = "worker_create_screen"
    const val LABEL = "worker_create_label"
    const val SUBMIT = "worker_create_submit"
}

private val AGENT_TYPES = listOf("coder", "qa", "reviewer", "devops", "custom")

@Composable
fun CreateWorkerRoute(
    onBack: () -> Unit,
    onCreated: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: CreateWorkerViewModel = hiltViewModel(),
) {
    val form by viewModel.form.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is WorkersEffect.CreateSucceeded -> onCreated()
                is WorkersEffect.NavigateToLogin -> onNavigateToLogin()
                else -> Unit
            }
        }
    }
    CreateWorkerScreen(
        form = form,
        onBack = onBack,
        onLabelChange = viewModel::onLabelChange,
        onAgentTypeChange = viewModel::onAgentTypeChange,
        onToolChange = viewModel::onToolChange,
        onComputeChange = viewModel::onComputeChange,
        onLlmKeyChange = viewModel::onLlmKeyChange,
        onRepoUrlChange = viewModel::onRepoUrlChange,
        onSubmit = viewModel::submit,
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun CreateWorkerScreen(
    form: CreateWorkerForm,
    onBack: () -> Unit,
    onLabelChange: (String) -> Unit,
    onAgentTypeChange: (String) -> Unit,
    onToolChange: (String) -> Unit,
    onComputeChange: (String, String) -> Unit,
    onLlmKeyChange: (String) -> Unit,
    onRepoUrlChange: (String) -> Unit,
    onSubmit: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CreateWorkerTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("New worker") },
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
            OutlinedTextField(
                value = form.label,
                onValueChange = onLabelChange,
                label = { Text("Label") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                modifier = Modifier.fillMaxWidth().testTag(CreateWorkerTestTags.LABEL),
            )

            Text("Agent type", style = MaterialTheme.typography.titleSmall)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AGENT_TYPES.forEach { t ->
                    FilterChip(selected = form.agentType == t, onClick = { onAgentTypeChange(t) }, label = { Text(t) })
                }
            }

            if (form.tools.isNotEmpty()) {
                Text("Tool", style = MaterialTheme.typography.titleSmall)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    form.tools.forEach { tool ->
                        FilterChip(
                            selected = form.tool == tool.tool,
                            onClick = { onToolChange(tool.tool) },
                            label = { Text(tool.displayName) },
                        )
                    }
                }
            }

            if (form.computeOptions.isNotEmpty()) {
                Text("Compute", style = MaterialTheme.typography.titleSmall)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    form.computeOptions.forEach { opt ->
                        val selected = form.computeType == opt.computeType && form.instanceType == opt.instanceType
                        FilterChip(
                            selected = selected,
                            onClick = { onComputeChange(opt.computeType, opt.instanceType) },
                            label = { Text("${opt.instanceType} (${opt.vcpu}vCPU)") },
                        )
                    }
                }
            }

            Text("LLM key", style = MaterialTheme.typography.titleSmall)
            if (form.llmKeyOptions.isEmpty()) {
                Text(
                    if (form.loadingOptions) "Loading keys…" else "No LLM keys. Add one in Agent Studio → LLM keys first.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    form.llmKeyOptions.forEach { (id, label) ->
                        FilterChip(
                            selected = form.selectedLlmKeyId == id,
                            onClick = { onLlmKeyChange(id) },
                            label = { Text(label) },
                        )
                    }
                }
            }

            OutlinedTextField(
                value = form.repoUrl,
                onValueChange = onRepoUrlChange,
                label = { Text("Repo URL (optional)") },
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
                modifier = Modifier.fillMaxWidth().testTag(CreateWorkerTestTags.SUBMIT),
            ) {
                if (form.submitting) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.heightIn(max = 20.dp))
                } else {
                    Text("Create worker")
                }
            }
        }
    }
}
