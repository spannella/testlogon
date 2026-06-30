@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.questionnaire.builder.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Assignment
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.questionnaire.builder.data.QnrDraft

/**
 * Route-level entry for the questionnaire-builder DRAFTS list. Collects the state, wires the one-shot
 * NavigateToLogin effect to the re-auth handoff, and the FAB / empty CTA / rows to nav callbacks. A
 * [refreshKey] (bumped after a return from create/builder) forces a refresh so a newly-created/edited
 * draft appears.
 */
@Composable
fun DraftsListRoute(
    onBack: () -> Unit,
    onCreate: () -> Unit,
    onOpenDraft: (String) -> Unit,
    onNavigateToLogin: () -> Unit,
    refreshKey: Int = 0,
    viewModel: DraftsListViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(refreshKey) {
        if (refreshKey > 0) viewModel.refresh()
    }

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is BuilderEffect.NavigateToLogin -> onNavigateToLogin()
                is BuilderEffect.DraftCreated -> Unit // not emitted by the list VM
            }
        }
    }

    DraftsListScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onCreate = onCreate,
        onOpenDraft = onOpenDraft,
    )
}

@Composable
fun DraftsListScreen(
    state: DraftsListUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onCreate: () -> Unit,
    onOpenDraft: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(QuestionnaireBuilderTestTags.LIST_SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Questionnaires") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            if (state is DraftsListUiState.Content || state is DraftsListUiState.Empty) {
                FloatingActionButton(
                    onClick = onCreate,
                    modifier = Modifier.testTag(QuestionnaireBuilderTestTags.CREATE_FAB),
                ) {
                    Icon(Icons.Outlined.Add, contentDescription = "New questionnaire")
                }
            }
        },
    ) { padding ->
        val isRefreshing = (state as? DraftsListUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is DraftsListUiState.Loading -> LoadingState()
                is DraftsListUiState.Empty ->
                    EmptyState(
                        modifier = Modifier.testTag(QuestionnaireBuilderTestTags.LIST_EMPTY),
                        title = "No questionnaires yet",
                        body = "Create your first questionnaire to start building sections and questions.",
                        imageVector = Icons.Outlined.Assignment,
                        actionLabel = "New questionnaire",
                        onAction = onCreate,
                    )
                is DraftsListUiState.Error ->
                    ErrorState(
                        modifier = Modifier.testTag(QuestionnaireBuilderTestTags.LIST_ERROR_RETRY),
                        message = state.message,
                        onRetry = onRetry,
                    )
                is DraftsListUiState.Content ->
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(items = state.items, key = { it.questionnaireId }) { draft ->
                            DraftRow(draft = draft, onOpen = { onOpenDraft(draft.questionnaireId) })
                        }
                    }
            }
        }
    }
}

@Composable
private fun DraftRow(draft: QnrDraft, onOpen: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(QuestionnaireBuilderTestTags.draftRow(draft.questionnaireId)),
        onClick = onOpen,
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = draft.title.ifBlank { "Untitled questionnaire" },
                style = MaterialTheme.typography.titleMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (draft.description.isNotBlank()) {
                Text(
                    text = draft.description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            StatusChip(draft = draft)
        }
    }
}

@Composable
private fun StatusChip(draft: QnrDraft) {
    val label = when {
        draft.isPublished -> "Published"
        else -> "Draft"
    }
    Surface(
        color = if (draft.isPublished) MaterialTheme.colorScheme.secondaryContainer
        else MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.small,
    ) {
        Text(
            text = "$label  ·  ${draft.visibility}",
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
        )
    }
}
