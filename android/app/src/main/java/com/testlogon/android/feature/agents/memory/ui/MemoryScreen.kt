@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agents.memory.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.AssistChip
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
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.agents.memory.data.MemoryEntry
import kotlinx.coroutines.launch

/** AGENTS-BASICS - stable testTags for the per-worker memory screen. */
object MemoryTestTags {
    const val SCREEN = "agent_memory_screen"
    const val IDENTITY_TEXT = "agent_memory_identity_text"
    const val IDENTITY_SAVE = "agent_memory_identity_save"
    const val PROJECT_SAVE = "agent_memory_project_save"
    const val ADD_ENTRY_TITLE = "agent_memory_add_title"
    const val ADD_ENTRY_CONTENT = "agent_memory_add_content"
    const val ADD_ENTRY_SAVE = "agent_memory_add_save"
    fun entry(id: String) = "agent_memory_entry_$id"
    fun entryDelete(id: String) = "agent_memory_entry_delete_$id"
}

@Composable
fun MemoryRoute(
    onBack: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: MemoryViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is MemoryEffect.NavigateToLogin -> onNavigateToLogin()
                is MemoryEffect.Toast -> scope.launch { snackbar.showSnackbar(effect.message) }
            }
        }
    }
    MemoryScreen(
        state = state,
        snackbar = snackbar,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onSaveIdentity = viewModel::saveIdentity,
        onSaveProject = viewModel::saveProject,
        onAddEntry = viewModel::addEntry,
        onDeleteEntry = viewModel::deleteEntry,
    )
}

@Composable
fun MemoryScreen(
    state: MemoryUiState,
    snackbar: SnackbarHostState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onSaveIdentity: (identityText: String, customInstructions: String) -> Unit,
    onSaveProject: (repoUrl: String, branchConvention: String, codingStandards: String, testFramework: String) -> Unit,
    onAddEntry: (category: String, title: String, content: String, importance: Int) -> Unit,
    onDeleteEntry: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(MemoryTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Agent memory") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            is MemoryUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is MemoryUiState.Error ->
                ErrorState(modifier = Modifier.padding(padding), message = state.message, onRetry = onRetry)
            is MemoryUiState.Content ->
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding)
                        .verticalScroll(rememberScrollState())
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    if (state.actionError != null) {
                        Text(
                            text = state.actionError,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                    IdentitySection(state, onSaveIdentity)
                    ProjectSection(state, onSaveProject)
                    EntriesSection(state, onAddEntry, onDeleteEntry)
                }
        }
    }
}

@Composable
private fun IdentitySection(
    state: MemoryUiState.Content,
    onSave: (String, String) -> Unit,
) {
    var identityText by rememberSaveable(state.identity.identityText) { mutableStateOf(state.identity.identityText) }
    var instructions by rememberSaveable(state.identity.customInstructions) {
        mutableStateOf(state.identity.customInstructions)
    }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Agent identity", style = MaterialTheme.typography.titleMedium)
            if (state.identity.agentType.isNotBlank()) {
                AssistChip(onClick = {}, label = { Text(state.identity.agentType) })
            }
            OutlinedTextField(
                value = identityText,
                onValueChange = { identityText = it },
                label = { Text("Identity / system prompt") },
                modifier = Modifier.fillMaxWidth().testTag(MemoryTestTags.IDENTITY_TEXT),
                minLines = 3,
                enabled = !state.saving,
            )
            OutlinedTextField(
                value = instructions,
                onValueChange = { instructions = it },
                label = { Text("Custom instructions") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 2,
                enabled = !state.saving,
            )
            SaveButton(
                saving = state.saving,
                tag = MemoryTestTags.IDENTITY_SAVE,
                onClick = { onSave(identityText, instructions) },
            )
        }
    }
}

@Composable
private fun ProjectSection(
    state: MemoryUiState.Content,
    onSave: (String, String, String, String) -> Unit,
) {
    var repoUrl by rememberSaveable(state.project.repoUrl) { mutableStateOf(state.project.repoUrl) }
    var branch by rememberSaveable(state.project.branchConvention) { mutableStateOf(state.project.branchConvention) }
    var standards by rememberSaveable(state.project.codingStandards) { mutableStateOf(state.project.codingStandards) }
    var framework by rememberSaveable(state.project.testFramework) { mutableStateOf(state.project.testFramework) }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Project context", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(
                value = repoUrl,
                onValueChange = { repoUrl = it },
                label = { Text("Repository URL") },
                modifier = Modifier.fillMaxWidth(),
                enabled = !state.saving,
            )
            OutlinedTextField(
                value = branch,
                onValueChange = { branch = it },
                label = { Text("Branch convention") },
                modifier = Modifier.fillMaxWidth(),
                enabled = !state.saving,
            )
            OutlinedTextField(
                value = framework,
                onValueChange = { framework = it },
                label = { Text("Test framework") },
                modifier = Modifier.fillMaxWidth(),
                enabled = !state.saving,
            )
            OutlinedTextField(
                value = standards,
                onValueChange = { standards = it },
                label = { Text("Coding standards") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 2,
                enabled = !state.saving,
            )
            SaveButton(
                saving = state.saving,
                tag = MemoryTestTags.PROJECT_SAVE,
                onClick = { onSave(repoUrl, branch, standards, framework) },
            )
        }
    }
}

@Composable
private fun EntriesSection(
    state: MemoryUiState.Content,
    onAdd: (String, String, String, Int) -> Unit,
    onDelete: (String) -> Unit,
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Memory entries", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                if (state.totalTokens > 0) {
                    Text("${state.totalTokens} tok", style = MaterialTheme.typography.labelMedium)
                }
            }
            if (state.entries.isEmpty()) {
                Text(
                    "No memory entries yet.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                state.entries.forEach { entry ->
                    EntryRow(entry = entry, enabled = !state.saving, onDelete = { onDelete(entry.memoryId) })
                    HorizontalDivider()
                }
            }
            AddEntryForm(saving = state.saving, onAdd = onAdd)
        }
    }
}

@Composable
private fun EntryRow(entry: MemoryEntry, enabled: Boolean, onDelete: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().testTag(MemoryTestTags.entry(entry.memoryId)),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(entry.title, style = MaterialTheme.typography.titleSmall)
            Text(
                text = listOf(entry.category, "importance ${entry.importance}").filter { it.isNotBlank() }
                    .joinToString(" · "),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(entry.content, style = MaterialTheme.typography.bodySmall)
        }
        IconButton(
            onClick = onDelete,
            enabled = enabled,
            modifier = Modifier.testTag(MemoryTestTags.entryDelete(entry.memoryId)),
        ) {
            Icon(Icons.Outlined.Delete, contentDescription = "Delete entry", tint = MaterialTheme.colorScheme.error)
        }
    }
}

@Composable
private fun AddEntryForm(saving: Boolean, onAdd: (String, String, String, Int) -> Unit) {
    var title by rememberSaveable { mutableStateOf("") }
    var content by rememberSaveable { mutableStateOf("") }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Add an entry", style = MaterialTheme.typography.titleSmall)
        OutlinedTextField(
            value = title,
            onValueChange = { title = it },
            label = { Text("Title") },
            modifier = Modifier.fillMaxWidth().testTag(MemoryTestTags.ADD_ENTRY_TITLE),
            enabled = !saving,
        )
        OutlinedTextField(
            value = content,
            onValueChange = { content = it },
            label = { Text("Content") },
            modifier = Modifier.fillMaxWidth().testTag(MemoryTestTags.ADD_ENTRY_CONTENT),
            minLines = 2,
            enabled = !saving,
        )
        OutlinedButton(
            onClick = {
                onAdd("learning", title, content, 3)
                title = ""; content = ""
            },
            enabled = !saving && title.isNotBlank() && content.isNotBlank(),
            modifier = Modifier.testTag(MemoryTestTags.ADD_ENTRY_SAVE),
        ) {
            Icon(Icons.Outlined.Add, contentDescription = null)
            Text(" Add entry")
        }
    }
}

@Composable
private fun SaveButton(saving: Boolean, tag: String, onClick: () -> Unit) {
    Button(onClick = onClick, enabled = !saving, modifier = Modifier.testTag(tag)) {
        if (saving) {
            CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
        } else {
            Text("Save")
        }
    }
}
