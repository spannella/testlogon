@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.workflow

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/** WFL — stable testTags for the drip-sequences screen. */
object DripSequencesTestTags {
    const val SCREEN = "drip_sequences_screen"
    const val FAB_CREATE = "drip_sequences_fab_create"
    const val CREATE_SUBMIT = "drip_sequence_create_submit"
    fun row(sequenceId: String): String = "drip_sequence_row_$sequenceId"
}

@Composable
fun DripSequencesRoute(
    onBack: () -> Unit,
    viewModel: DripSequencesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    DripSequencesScreen(
        state = state,
        onBack = onBack,
        onCreate = { name, desc, stages, onDone ->
            viewModel.createSequence(name, desc, stages, onDone)
        },
        onMessageShown = viewModel::consumeMessage,
    )
}

@Composable
fun DripSequencesScreen(
    state: DripSequencesUiState,
    onBack: () -> Unit,
    onCreate: (String, String, List<DripStage>, () -> Unit) -> Unit,
    onMessageShown: () -> Unit,
) {
    val snackbar = remember { SnackbarHostState() }
    var showCreate by rememberSaveable { mutableStateOf(false) }

    val message = (state as? DripSequencesUiState.Content)?.message
    LaunchedEffect(message) {
        if (message != null) {
            snackbar.showSnackbar(message)
            onMessageShown()
        }
    }

    Scaffold(
        modifier = Modifier.testTag(DripSequencesTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Drip sequences") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            if (state is DripSequencesUiState.Content || state is DripSequencesUiState.Empty) {
                FloatingActionButton(
                    onClick = { showCreate = true },
                    modifier = Modifier.testTag(DripSequencesTestTags.FAB_CREATE),
                ) { Icon(Icons.Filled.Add, contentDescription = "New sequence") }
            }
        },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when (state) {
                is DripSequencesUiState.Loading ->
                    CircularProgressIndicator(Modifier.align(Alignment.Center))

                is DripSequencesUiState.Unavailable ->
                    CenterMsg("Drip sequences aren't available.")

                is DripSequencesUiState.Empty ->
                    CenterMsg("No drip sequences yet. Tap + to create one.")

                is DripSequencesUiState.Error ->
                    CenterMsg(state.error.message)

                is DripSequencesUiState.Content -> LazyColumn(
                    modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(state.sequences, key = { it.sequenceId }) { seq -> SequenceRow(seq) }
                }
            }
        }
    }

    if (showCreate) {
        CreateDripDialog(
            onDismiss = { showCreate = false },
            onSubmit = { name, desc, stages -> onCreate(name, desc, stages) { showCreate = false } },
        )
    }
}

@Composable
private fun androidx.compose.foundation.layout.BoxScope.CenterMsg(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.align(Alignment.Center).padding(24.dp),
    )
}

@Composable
private fun SequenceRow(seq: DripSequence) {
    Card(modifier = Modifier.fillMaxWidth().testTag(DripSequencesTestTags.row(seq.sequenceId))) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(seq.name, style = MaterialTheme.typography.titleMedium)
            seq.description.takeIf { it.isNotBlank() }?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium)
            }
            Text("${seq.stageCount} stages", style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun CreateDripDialog(
    onDismiss: () -> Unit,
    onSubmit: (String, String, List<DripStage>) -> Unit,
) {
    var name by rememberSaveable { mutableStateOf("") }
    var description by rememberSaveable { mutableStateOf("") }
    var templateId by rememberSaveable { mutableStateOf("") }
    var toField by rememberSaveable { mutableStateOf("email") }
    var delayHoursText by rememberSaveable { mutableStateOf("24") }

    val delayHours = delayHoursText.toIntOrNull() ?: -1
    val stages = listOf(
        DripStage(stageNumber = 1, delayHours = delayHours, templateId = templateId, toField = toField),
    )
    val canSubmit = WorkflowRuleMath.canSubmitDrip(name, stages)

    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            Button(
                onClick = { onSubmit(name, description, stages) },
                enabled = canSubmit,
                modifier = Modifier.testTag(DripSequencesTestTags.CREATE_SUBMIT),
            ) { Text("Create") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
        title = { Text("New drip sequence") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = description,
                    onValueChange = { description = it },
                    label = { Text("Description") },
                    modifier = Modifier.fillMaxWidth(),
                )
                Text("First stage", style = MaterialTheme.typography.titleSmall)
                OutlinedTextField(
                    value = templateId,
                    onValueChange = { templateId = it },
                    label = { Text("Template id") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = toField,
                    onValueChange = { toField = it },
                    label = { Text("To field") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = delayHoursText,
                    onValueChange = { delayHoursText = it.filter(Char::isDigit) },
                    label = { Text("Delay (hours)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
    )
}
