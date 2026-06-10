package com.testlogon.android.feature.messaging.search

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.text.highlightMatches
import com.testlogon.android.data.messaging.MessageSearchResultItem

/** AND-152 — stable testTags for the global search screen. */
object GlobalSearchTestTags {
    const val SCREEN = "global_search_screen"
    const val INPUT = "global_search_input"
    const val CLEAR = "global_search_clear"
    const val LIST = "global_search_list"
    const val ROW = "global_search_row"
    const val STATUS = "global_search_status"
}

/** AND-152 — route-level global search; reached from the conversation list search action. */
@Composable
fun GlobalSearchRoute(
    onOpenResult: (conversationId: String, messageId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: GlobalSearchViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    GlobalSearchScreen(
        state = state,
        onQueryChange = viewModel::onQueryChange,
        onClearQuery = { viewModel.onQueryChange("") },
        onRetry = viewModel::retry,
        onOpenResult = onOpenResult,
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GlobalSearchScreen(
    state: GlobalSearchUiState,
    onQueryChange: (String) -> Unit,
    onClearQuery: () -> Unit,
    onRetry: () -> Unit,
    onOpenResult: (conversationId: String, messageId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(GlobalSearchTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = {
                    TextField(
                        value = state.query,
                        onValueChange = onQueryChange,
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag(GlobalSearchTestTags.INPUT),
                        placeholder = { Text(stringResource(R.string.search_messages)) },
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                        keyboardActions = KeyboardActions(),
                        trailingIcon = {
                            if (state.query.isNotEmpty()) {
                                IconButton(
                                    onClick = onClearQuery,
                                    modifier = Modifier.testTag(GlobalSearchTestTags.CLEAR),
                                ) {
                                    Icon(
                                        Icons.Filled.Clear,
                                        contentDescription = stringResource(R.string.search_clear),
                                    )
                                }
                            }
                        },
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (val phase = state.phase) {
                GlobalSearchPhase.Idle ->
                    EmptyState(title = stringResource(R.string.search_prompt_title))
                GlobalSearchPhase.TooShort ->
                    EmptyState(title = stringResource(R.string.search_min_chars))
                GlobalSearchPhase.Searching -> LoadingState()
                GlobalSearchPhase.Empty ->
                    EmptyState(title = stringResource(R.string.search_no_messages))
                is GlobalSearchPhase.Error ->
                    ErrorState(message = phase.message, onRetry = onRetry)
                GlobalSearchPhase.Results ->
                    ResultsList(state = state, onOpenResult = onOpenResult)
            }
        }
    }
}

@Composable
private fun ResultsList(
    state: GlobalSearchUiState,
    onOpenResult: (conversationId: String, messageId: String) -> Unit,
) {
    val rows = remember(state.groups) { state.groups.flatMap { it.items } }
    LazyColumn(modifier = Modifier.fillMaxSize().testTag(GlobalSearchTestTags.LIST)) {
        // Status line (announced to screen readers).
        item {
            Text(
                text = stringResource(R.string.search_result_count, state.resultCount, state.groups.size),
                style = MaterialTheme.typography.labelMedium,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp)
                    .semantics { liveRegion = LiveRegionMode.Polite }
                    .testTag(GlobalSearchTestTags.STATUS),
            )
        }
        items(rows, key = { it.messageId }) { item ->
            SearchResultRow(item = item, query = state.query, onClick = { onOpenResult(item.conversationId, item.messageId) })
        }
    }
}

@Composable
private fun SearchResultRow(
    item: MessageSearchResultItem,
    query: String,
    onClick: () -> Unit,
) {
    val snippet = item.text.orEmpty()
    val highlighted = highlightMatches(
        body = snippet,
        query = query,
        matchBg = MaterialTheme.colorScheme.primaryContainer,
        activeBg = MaterialTheme.colorScheme.tertiaryContainer,
    )
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .semantics { role = Role.Button }
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(GlobalSearchTestTags.ROW),
    ) {
        Text(
            text = item.conversationId,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Text(
            text = highlighted,
            style = MaterialTheme.typography.bodyMedium,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
    }
}
