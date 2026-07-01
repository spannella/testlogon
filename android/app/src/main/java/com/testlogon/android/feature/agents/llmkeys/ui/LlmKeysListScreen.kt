@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agents.llmkeys.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.NetworkCheck
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.feature.agents.llmkeys.data.LlmKey

/** AGENTS-BASICS - stable testTags for the LLM keys list. */
object LlmKeysListTestTags {
    const val SCREEN = "llm_keys_list_screen"
    const val EMPTY = "llm_keys_empty"
    const val ERROR_RETRY = "llm_keys_error_retry"
    const val ADD_FAB = "llm_keys_add_fab"
    fun row(id: String) = "llm_key_row_$id"
    fun delete(id: String) = "llm_key_delete_$id"
}

@Composable
fun LlmKeysListRoute(
    onBack: () -> Unit,
    onAdd: () -> Unit,
    onNavigateToLogin: () -> Unit,
    added: Boolean = false,
    onAddedConsumed: () -> Unit = {},
    viewModel: LlmKeysListViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(added) {
        if (added) {
            viewModel.onAdded()
            onAddedConsumed()
        }
    }
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is LlmKeysEffect.NavigateToLogin -> onNavigateToLogin()
                else -> Unit
            }
        }
    }
    LlmKeysListScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onAdd = onAdd,
        onDelete = viewModel::delete,
        onTest = viewModel::test,
    )
}

@Composable
fun LlmKeysListScreen(
    state: LlmKeysListUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onAdd: () -> Unit,
    onDelete: (String) -> Unit,
    onTest: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(LlmKeysListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("LLM keys") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            if (state is LlmKeysListUiState.Content || state is LlmKeysListUiState.Empty) {
                FloatingActionButton(onClick = onAdd, modifier = Modifier.testTag(LlmKeysListTestTags.ADD_FAB)) {
                    Icon(Icons.Outlined.Add, contentDescription = "Add LLM key")
                }
            }
        },
    ) { padding ->
        val isRefreshing = (state as? LlmKeysListUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is LlmKeysListUiState.Loading -> com.testlogon.android.core.ui.state.LoadingState()
                is LlmKeysListUiState.Empty ->
                    com.testlogon.android.core.ui.state.EmptyState(
                        modifier = Modifier.testTag(LlmKeysListTestTags.EMPTY),
                        title = "No LLM keys",
                        body = "Add a provider API key (OpenAI, Anthropic…) to power your agent workers.",
                        imageVector = Icons.Outlined.Key,
                        actionLabel = "Add key",
                        onAction = onAdd,
                    )
                is LlmKeysListUiState.Error ->
                    com.testlogon.android.core.ui.state.ErrorState(
                        modifier = Modifier.testTag(LlmKeysListTestTags.ERROR_RETRY),
                        message = state.message,
                        onRetry = onRetry,
                    )
                is LlmKeysListUiState.Content ->
                    Column(Modifier.fillMaxSize()) {
                        state.testResult?.let {
                            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp))
                        }
                        state.actionError?.let {
                            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
                                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp))
                        }
                        LazyColumn(
                            modifier = Modifier.fillMaxSize(),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            items(items = state.items, key = { it.id }) { key ->
                                LlmKeyRow(
                                    key = key,
                                    busy = state.busyId == key.id,
                                    onTest = { onTest(key.id) },
                                    onDelete = { onDelete(key.id) },
                                )
                            }
                        }
                    }
            }
        }
    }
}

@Composable
private fun LlmKeyRow(
    key: LlmKey,
    busy: Boolean,
    onTest: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(LlmKeysListTestTags.row(key.id))) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    text = key.label.ifBlank { key.provider },
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = buildString {
                        append(key.provider)
                        if (key.keySuffix.isNotBlank()) append(" · …${key.keySuffix}")
                        append(" · ${key.status}")
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (key.assignedWorkerIds.isNotEmpty()) {
                    Text(
                        text = "${key.assignedWorkerIds.size} worker(s)",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            if (busy) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
            } else {
                IconButton(onClick = onTest) {
                    Icon(Icons.Outlined.NetworkCheck, contentDescription = "Test")
                }
                IconButton(onClick = onDelete, modifier = Modifier.testTag(LlmKeysListTestTags.delete(key.id))) {
                    Icon(Icons.Outlined.Delete, contentDescription = "Delete", tint = MaterialTheme.colorScheme.error)
                }
            }
        }
    }
}
