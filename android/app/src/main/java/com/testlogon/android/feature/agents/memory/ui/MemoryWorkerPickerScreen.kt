@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agents.memory.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
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
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

object MemoryWorkerPickerTestTags {
    const val SCREEN = "agent_memory_picker_screen"
    const val EMPTY = "agent_memory_picker_empty"
    fun row(id: String) = "agent_memory_picker_row_$id"
}

@Composable
fun MemoryWorkerPickerRoute(
    onBack: () -> Unit,
    onOpenMemory: (String) -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: MemoryWorkerPickerViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is MemoryPickerEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }
    Scaffold(
        modifier = Modifier.testTag(MemoryWorkerPickerTestTags.SCREEN),
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
        when (val s = state) {
            is MemoryWorkerPickerUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is MemoryWorkerPickerUiState.Error ->
                ErrorState(modifier = Modifier.padding(padding), message = s.message, onRetry = viewModel::onRetry)
            is MemoryWorkerPickerUiState.Empty ->
                EmptyState(
                    modifier = Modifier.padding(padding).testTag(MemoryWorkerPickerTestTags.EMPTY),
                    title = "No workers yet",
                    body = "Provision a worker first, then manage its identity, project context and memory here.",
                    imageVector = Icons.Outlined.Memory,
                )
            is MemoryWorkerPickerUiState.Content ->
                LazyColumn(
                    modifier = Modifier.fillMaxSize().padding(padding),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    item { Text("Choose a worker to view and edit its agent memory.") }
                    items(items = s.workers, key = { it.id }) { worker ->
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag(MemoryWorkerPickerTestTags.row(worker.id))
                                .clickable { onOpenMemory(worker.id) },
                        ) {
                            ListItem(
                                headlineContent = { Text(worker.label.ifBlank { worker.id }) },
                                supportingContent = {
                                    Text(
                                        listOf(worker.agentType, worker.statusWire).filter { it.isNotBlank() }
                                            .joinToString(" · "),
                                    )
                                },
                                trailingContent = {
                                    Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null)
                                },
                            )
                        }
                    }
                }
        }
    }
}
